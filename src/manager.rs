use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use uuid::Uuid;

use crate::capability::{Capabilities, OwnershipIdentity};
use crate::config::{DnsConfig, DnsScope, validate_against};
use crate::error::{ConflictReason, Error, Result};
use crate::fault::{CrashSignal, FaultAction, FaultHook, TxPoint};
use crate::interface::InterfaceInfo;
use crate::journal::{JournalRecord, JournalStore, Phase};
use crate::lease::{Lease, LiveRecord, LiveState};
use crate::normalize::NormalizedConfig;
use crate::ownership::{ResourceId, ResourceLockManager};
use crate::platform::{
    Backend, MutationAttempt, OwnershipProof, PlatformSnapshot, ResourceIdentity, ResourceStatus,
    VerifiedMutation, select_default_backend,
};
use crate::reconciliation::Reconciler;
use crate::watch::SuppressionRegistry;
use crate::watch::{WatchCallback, WatchHandle};

/// How the manager reacts when an external actor changes DNS state that we
/// hold a lease over.
///
/// - [`ConflictPolicy::Cooperative`] (default): never overwrite; surface
///   conflicts to the lease owner.
/// - [`ConflictPolicy::Enforce`]: for active VPN/mesh/tunnel agents; the
///   manager keeps the native observation needed for reconciliation alive
///   while at least one lease is active, without requiring a public
///   [`DnsManager::watch`] subscription. See [`DnsManager::watch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConflictPolicy {
    /// Never overwrite externally changed state automatically.
    ///
    /// Applies, updates, restores, and recovery report
    /// [`Error::ExternalModification`](crate::Error) and mutate nothing when
    /// current state is no longer ours. This is the default and the right
    /// choice unless the application is an always-on network agent.
    #[default]
    Cooperative,
    /// Rebase on legitimate external changes and reapply the overlay.
    ///
    /// Enforce is self-contained: the first active lease starts the internal
    /// native watch and reconciliation worker, and the last lease ending
    /// stops them. The reconciliation worker waits for stable authoritative
    /// state, adopts the new external base in the journal, and reapplies the
    /// lease's desired overlay transactionally. Restoring a rebased lease
    /// returns to the new external base. [`DnsManager::watch`] remains a
    /// pure observability subscription and is never required for Enforce to
    /// work. Backends without watch support fail lease creation with
    /// [`Error::Unsupported`] rather than silently behaving cooperatively.
    Enforce,
}

/// The result of inspecting one journal record during stale recovery.
///
/// Returned per record by [`DnsManager::recover_stale`]. Terminal lifetime
/// outcomes remove obsolete records without touching a replacement target;
/// conflicts, ambiguity, busy resources, and failures retain the record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecoveryOutcome {
    /// A different application owner must recover or abandon this record.
    ForeignOwner {
        /// Resource still claimed by the journal.
        resource: ResourceId,
        /// Application ownership tag, not an OS authorization identity.
        owner: String,
    },
    /// The recorded transaction was still in effect; the original state was
    /// restored and verified, and the journal record was removed.
    Restored {
        /// The recovered resource.
        resource: ResourceId,
        /// The lease that left the record behind.
        lease_id: Uuid,
    },
    /// The transaction never became effective (or was already reverted), so
    /// only the journal record was removed. No mutation was needed.
    JournalCleared {
        /// The recovered resource.
        resource: ResourceId,
        /// The lease that left the record behind.
        lease_id: Uuid,
    },
    /// The recorded native resource ceased to exist; its journal was removed.
    Gone {
        /// Historical mutation target.
        resource: ResourceId,
        /// Lease that owned it.
        lease_id: Uuid,
    },
    /// The selector now names a different native incarnation; no DNS access occurred.
    Replaced {
        /// Selector that now names another incarnation.
        resource: ResourceId,
        /// Lease that owned the old incarnation.
        lease_id: Uuid,
    },
    /// Incarnation equality cannot be proved safely; nothing was mutated.
    IdentityMismatch {
        /// Resource whose incarnation is ambiguous.
        resource: ResourceId,
        /// Lease that recorded it.
        lease_id: Uuid,
    },
    /// This record failed, but recovery continued with unrelated records.
    Failed {
        /// Resource whose recovery failed.
        resource: ResourceId,
        /// Lease that recorded it.
        lease_id: Uuid,
        /// Failure detail.
        detail: String,
    },
    /// The current state matches neither the recorded applied state nor the
    /// original state: another actor changed it. Nothing was mutated and the
    /// journal record was kept.
    ExternalConflict {
        /// The contended resource.
        resource: ResourceId,
        /// The lease that left the record behind.
        lease_id: Uuid,
    },
    /// The resource is currently locked by an active lease, so it was not
    /// inspected.
    Busy {
        /// The locked resource.
        resource: ResourceId,
    },
}

/// Operational state of a manager's internal Enforce observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservationHealth {
    /// No active lease currently needs internal observation.
    Idle,
    /// Native subscriptions are operational.
    Operational,
    /// Observation was interrupted; scheduled resubscription and rescans continue.
    Degraded {
        /// Most recent subscription failure, when available.
        detail: String,
    },
}

pub(crate) struct Inner {
    pub(crate) owner: String,
    pub(crate) backend: Arc<dyn Backend>,
    pub(crate) locks: ResourceLockManager,
    pub(crate) journal: JournalStore,
    pub(crate) conflict_policy: ConflictPolicy,
    pub(crate) hook: Mutex<Option<Arc<dyn FaultHook>>>,
    pub(crate) suppressions: Arc<SuppressionRegistry>,
    pub(crate) active: Mutex<HashMap<ResourceId, Arc<Mutex<LiveRecord>>>>,
    pub(crate) lease_tokens: Mutex<HashMap<ResourceId, Arc<Mutex<()>>>>,
    #[allow(dead_code)]
    pub(crate) reconciler: Arc<Reconciler>,
    pub(crate) enforce: Mutex<EnforceState>,
}

/// Internal observation state for [`ConflictPolicy::Enforce`].
///
/// Independent of public [`DnsManager::watch`] subscriptions: the first
/// active lease starts one native watch feeding the shared reconciler, and
/// the last active lease ending stops it. `refs` counts live leases.
#[derive(Default)]
pub(crate) struct EnforceState {
    refs: usize,
    handle: Option<WatchHandle>,
    feed: Option<crate::reconciliation::ReconcileFeed>,
    parked: bool,
    recovery: Option<WatchRecovery>,
}

struct WatchRecovery {
    next_retry: std::time::Instant,
    failures: u32,
    error: String,
}

impl std::fmt::Debug for EnforceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnforceState")
            .field("refs", &self.refs)
            .field("watching", &self.handle.is_some())
            .finish()
    }
}

const COALESCE_WINDOW: Duration = Duration::from_millis(50);

impl Inner {
    /// Starts internal Enforce observation when the first lease becomes
    /// active. Fails honestly with [`Error::Unsupported`] when the backend
    /// cannot watch, instead of silently behaving cooperatively.
    pub(crate) fn ensure_enforce_watch(self: &Arc<Self>) -> Result<()> {
        if self.conflict_policy != ConflictPolicy::Enforce {
            return Ok(());
        }
        if !self.backend.capabilities().watch {
            return Err(Error::unsupported(
                self.backend.kind(),
                "ConflictPolicy::Enforce requires change notifications, which this backend does not support",
            ));
        }
        let mut enforce = self.enforce.lock();
        if enforce.refs == 0 {
            debug_assert!(enforce.handle.is_none() && enforce.feed.is_none());
            let feed = crate::reconciliation::spawn_reconciler(Arc::clone(self))?;
            let feed_clone = feed.clone();
            let callback: WatchCallback = Arc::new(move |event| {
                feed_clone.notify(event.resource().clone());
            });
            match self.backend.start_watch(callback) {
                Ok(handle) => {
                    enforce.handle = Some(handle);
                    enforce.feed = Some(feed);
                    enforce.parked = false;
                }
                Err(error) => {
                    drop(feed);
                    return Err(error);
                }
            }
        }
        enforce.refs += 1;
        Ok(())
    }

    /// Releases one Enforce lease reference, stopping internal observation
    /// when the last active lease ends.
    pub(crate) fn release_enforce_watch(&self) {
        if self.conflict_policy != ConflictPolicy::Enforce {
            return;
        }
        let mut enforce = self.enforce.lock();
        if enforce.refs == 0 {
            return;
        }
        enforce.refs -= 1;
        if enforce.refs == 0 {
            enforce.handle = None;
            enforce.feed = None;
            enforce.parked = false;
            enforce.recovery = None;
        }
    }

    pub(crate) fn refresh_enforce_watch(&self) {
        let mut enforce = self.enforce.lock();
        if enforce.refs == 0
            || enforce.parked
            || enforce.handle.as_ref().is_some_and(WatchHandle::is_active)
        {
            return;
        }
        let now = std::time::Instant::now();
        if enforce
            .recovery
            .as_ref()
            .is_some_and(|recovery| now < recovery.next_retry)
        {
            return;
        }
        enforce.handle = None;
        let Some(feed) = enforce.feed.clone() else {
            return;
        };
        let callback_feed = feed.clone();
        let callback: WatchCallback =
            Arc::new(move |event| callback_feed.notify(event.resource().clone()));
        match self.backend.start_watch(callback) {
            Ok(handle) => {
                enforce.handle = Some(handle);
                enforce.recovery = None;
            }
            Err(error) => {
                let failures = enforce
                    .recovery
                    .as_ref()
                    .map_or(1, |recovery| recovery.failures.saturating_add(1));
                enforce.recovery = Some(WatchRecovery {
                    next_retry: now + Duration::from_secs(1 << failures.saturating_sub(1).min(5)),
                    failures,
                    error: error.to_string(),
                });
            }
        }
        drop(enforce);
        for resource in self.active.lock().keys() {
            feed.notify(resource.clone());
        }
    }

    /// Clones the internal Enforce feed when one is running, so public
    /// watchers share the same reconciler instead of spawning duplicate
    /// worker threads.
    pub(crate) fn enforce_feed(&self) -> Option<crate::reconciliation::ReconcileFeed> {
        self.enforce.lock().feed.clone()
    }

    /// Number of live leases holding Enforce observation (testing only).
    #[cfg(feature = "test-util")]
    #[allow(dead_code)]
    pub(crate) fn enforce_refs(&self) -> usize {
        self.enforce.lock().refs
    }

    /// Drops the internal Enforce watch/feed without touching the refcount,
    /// so deterministic tests can drive reconciliation via `debug_reconcile`
    /// without racing a background worker. The lease-drop balance is kept:
    /// `release_enforce_watch` still runs once per lease.
    pub(crate) fn enforce_parked(&self) -> bool {
        self.enforce.lock().parked
    }

    #[cfg(feature = "test-util")]
    #[allow(dead_code)]
    pub(crate) fn suspend_enforce_watch(&self) {
        {
            let mut enforce = self.enforce.lock();
            enforce.handle = None;
            enforce.feed = None;
            enforce.parked = true;
        }
        let _reconcile_guard = self.reconciler.lock_gate();
        self.reconciler.clear();
    }

    /// Queues an authoritative reconciliation of every active resource.
    /// Called after native observation is installed so changes that arrived
    /// in the watcher-start window cannot be missed.
    pub(crate) fn rescan_enforce(&self) {
        let Some(feed) = self.enforce_feed() else {
            return;
        };
        let resources: Vec<ResourceId> = self.active.lock().keys().cloned().collect();
        for resource in resources {
            feed.notify(resource);
        }
    }

    /// Whether the internal Enforce watcher is currently running.
    #[cfg(feature = "test-util")]
    #[allow(dead_code)]
    pub(crate) fn enforce_watching(&self) -> bool {
        self.enforce.lock().handle.is_some()
    }
}

pub(crate) struct MutatePoints {
    apply: TxPoint,
    readback: TxPoint,
    verify: TxPoint,
    suppress_events: bool,
}

pub(crate) const INITIAL_POINTS: MutatePoints = MutatePoints {
    apply: TxPoint::AfterApply,
    readback: TxPoint::AfterReadback,
    verify: TxPoint::AfterVerify,
    suppress_events: true,
};

pub(crate) const RECONCILE_POINTS: MutatePoints = MutatePoints {
    suppress_events: false,
    ..INITIAL_POINTS
};

const UPDATE_POINTS: MutatePoints = MutatePoints {
    apply: TxPoint::AfterUpdateApply,
    readback: TxPoint::AfterUpdateReadback,
    verify: TxPoint::AfterUpdateVerify,
    suppress_events: true,
};

#[derive(Clone)]
pub(crate) struct PendingRollback {
    /// Backend-issued mutation evidence, or the previously committed snapshot
    /// interpreted under the backend's declared ownership contract.
    pub(crate) evidence: Option<PlatformSnapshot>,
    pub(crate) target: PlatformSnapshot,
}

pub(crate) enum MutationResidue {
    Unchanged,
    Restored(Option<PlatformSnapshot>),
    Pending(PendingRollback),
}

pub(crate) struct MutationFailure {
    pub(crate) error: Error,
    pub(crate) residue: MutationResidue,
}

pub(crate) struct PreparedLease {
    lease_id: Uuid,
    records: Vec<LiveRecord>,
    was_noop: bool,
}

enum RecoverBlock {
    Journal(Error),
    Conflict(String),
}

fn transaction_error(primary: Error, cleanup: Vec<Error>) -> Error {
    if cleanup.is_empty() {
        primary
    } else {
        Error::TransactionFailed {
            primary: Box::new(primary),
            cleanup,
        }
    }
}

impl Inner {
    pub(crate) fn fire(&self, point: TxPoint) -> Result<()> {
        let hook = self.hook.lock().clone();
        if let Some(hook) = hook {
            match hook.on_point(point) {
                FaultAction::Continue => {}
                FaultAction::Crash => std::panic::panic_any(CrashSignal),
                FaultAction::Fail(message) => {
                    return Err(Error::platform(
                        self.backend.kind(),
                        format_args!("injected transaction failure: {message}"),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Applies `plan` and verifies by read-back.
    ///
    /// `expected_current` is the caller's fresh ownership read. Backends with
    /// [`MutationGuard::CompareAndMutate`] refuse to overwrite a concurrent
    /// external change. A CAS rejection never rolls back. Rollback after a
    /// performed or proven-partial mutation uses the backend-issued proof,
    /// never a fresh post-failure read.
    pub(crate) fn mutate_and_verify(
        &self,
        identity: &ResourceIdentity,
        expected_current: &PlatformSnapshot,
        plan: &NormalizedConfig,
        points: MutatePoints,
    ) -> std::result::Result<VerifiedMutation, Box<MutationFailure>> {
        let resource = &identity.resource;
        match self.backend.apply_bound(identity, expected_current, plan) {
            MutationAttempt::Rejected { error } => Err(Box::new(MutationFailure {
                error,
                residue: MutationResidue::Unchanged,
            })),
            MutationAttempt::Indeterminate { error, produced } => Err(Box::new(MutationFailure {
                error,
                residue: self.rollback_proven(identity, produced, expected_current),
            })),
            MutationAttempt::Performed { produced } => {
                let fail = |this: &Self, produced: Option<PlatformSnapshot>, error: Error| {
                    Err(Box::new(MutationFailure {
                        error,
                        residue: this.rollback_proven(identity, produced, expected_current),
                    }))
                };
                if let Err(error) = self.fire(points.apply) {
                    return fail(self, produced, error);
                }
                match self.backend.resource_status(identity) {
                    Ok(ResourceStatus::Same) => {}
                    Ok(status) => {
                        return fail(
                            self,
                            produced,
                            Error::ResourceIdentity {
                                backend: self.backend.kind(),
                                resource: resource.clone(),
                                message: format!(
                                    "resource incarnation became {status:?} during mutation"
                                ),
                            },
                        );
                    }
                    Err(error) => return fail(self, produced, error),
                }
                match self.backend.readback(resource) {
                    Ok(actual) => {
                        if let Err(error) = self.fire(points.readback) {
                            return fail(self, produced, error);
                        }
                        if !self.backend.matches_desired(&actual, plan) {
                            return fail(
                                self,
                                produced,
                                Error::VerificationFailed {
                                    resource: resource.clone(),
                                    detail: "the state read back from the system does not match the desired configuration"
                                        .to_string(),
                                },
                            );
                        }
                        match self.backend.resource_status(identity) {
                            Ok(ResourceStatus::Same) => {}
                            Ok(status) => {
                                return fail(
                                    self,
                                    produced,
                                    Error::ResourceIdentity {
                                        backend: self.backend.kind(),
                                        resource: resource.clone(),
                                        message: format!(
                                            "resource incarnation became {status:?} during verification"
                                        ),
                                    },
                                );
                            }
                            Err(error) => return fail(self, produced, error),
                        }
                        if let Err(error) = self.fire(points.verify) {
                            return fail(self, produced, error);
                        }
                        match self.backend.ownership_identity() {
                            OwnershipIdentity::Durable => {
                                let Some(produced) = produced else {
                                    return fail(
                                        self,
                                        None,
                                        Error::VerificationFailed {
                                            resource: resource.clone(),
                                            detail: "the mutation issued no ownership proof"
                                                .to_string(),
                                        },
                                    );
                                };
                                if !self.backend.proves_current(&produced, &actual) {
                                    return fail(
                                        self,
                                        Some(produced),
                                        Error::ExternalModification {
                                            resource: resource.clone(),
                                            detail: "the state read back does not carry the identity of our mutation"
                                                .to_string(),
                                        },
                                    );
                                }
                                if points.suppress_events {
                                    self.suppressions.record(&produced);
                                }
                                Ok(VerifiedMutation {
                                    proof: Some(OwnershipProof::issued(produced)),
                                    observed: actual,
                                })
                            }
                            OwnershipIdentity::BestEffort => {
                                if points.suppress_events {
                                    self.suppressions.record(&actual);
                                }
                                Ok(VerifiedMutation {
                                    proof: produced.map(OwnershipProof::issued),
                                    observed: actual,
                                })
                            }
                        }
                    }
                    Err(error) => fail(self, produced, error),
                }
            }
        }
    }

    /// Compensation can issue a new identity even when it fails or read-back
    /// fails. Retain that identity rather than retrying with the superseded one.
    fn rollback_proven(
        &self,
        identity: &ResourceIdentity,
        proof: Option<PlatformSnapshot>,
        target: &PlatformSnapshot,
    ) -> MutationResidue {
        let mut pending = PendingRollback {
            evidence: proof,
            target: target.clone(),
        };
        match self.compensate(identity, &mut pending, None) {
            Ok(restored) => MutationResidue::Restored(restored),
            Err(_) => MutationResidue::Pending(pending),
        }
    }

    fn compensate(
        &self,
        identity: &ResourceIdentity,
        pending: &mut PendingRollback,
        after_restore: Option<TxPoint>,
    ) -> Result<Option<PlatformSnapshot>> {
        if self.backend.resource_status(identity)? != ResourceStatus::Same {
            return Err(Error::ResourceIdentity {
                backend: self.backend.kind(),
                resource: identity.resource.clone(),
                message: "cannot prove the compensation target incarnation".to_string(),
            });
        }
        let current = self.backend.readback(&identity.resource)?;
        // A target match needs no write and grants no new ownership identity.
        if self.backend.equivalent(&current, &pending.target) {
            let proof = pending
                .evidence
                .as_ref()
                .filter(|proof| self.backend.owns_current(proof, &current));
            return Ok(proof.cloned().or_else(|| {
                self.backend
                    .owns_current(&pending.target, &current)
                    .then(|| pending.target.clone())
            }));
        }
        let proof = pending
            .evidence
            .as_ref()
            .ok_or_else(|| Error::IndeterminateMutation {
                backend: self.backend.kind(),
                message: "compensation has no backend-issued ownership evidence".to_string(),
            })?;
        if !self.backend.owns_current(proof, &current) {
            return Err(Error::ExternalModification {
                resource: identity.resource.clone(),
                detail: "pending compensation evidence no longer names current state".to_string(),
            });
        }
        match self.backend.restore_bound(identity, proof, &pending.target) {
            MutationAttempt::Performed { produced } => {
                pending.evidence = produced;
            }
            MutationAttempt::Indeterminate { error, produced } => {
                if let Some(produced) = produced {
                    pending.evidence = Some(produced);
                }
                return Err(error);
            }
            MutationAttempt::Rejected { error } => return Err(error),
        }
        if let Some(point) = after_restore {
            self.fire(point)?;
        }
        let now = self.backend.readback(&identity.resource)?;
        if self.backend.resource_status(identity)? != ResourceStatus::Same
            || !self.backend.equivalent(&now, &pending.target)
        {
            return Err(Error::VerificationFailed {
                resource: identity.resource.clone(),
                detail: "compensation failed read-back verification".to_string(),
            });
        }
        self.suppressions.record(&now);
        Ok(pending
            .evidence
            .as_ref()
            .filter(|proof| self.backend.owns_current(proof, &now))
            .cloned()
            .or_else(|| {
                (pending.evidence.is_none()
                    && self.backend.ownership_identity() == OwnershipIdentity::BestEffort)
                    .then_some(now)
            }))
    }

    fn persist_unmutated(&self, records: &[JournalRecord]) -> Result<()> {
        for (index, record) in records.iter().enumerate() {
            if let Err(primary) = self.journal.write(record) {
                // Failed publication may already be visible, but no native mutation has begun.
                let cleanup = records[..=index]
                    .iter()
                    .filter_map(|record| {
                        self.journal
                            .remove(&record.lease_id, &record.resource)
                            .err()
                    })
                    .collect();
                return Err(transaction_error(primary, cleanup));
            }
        }
        Ok(())
    }

    /// Runs one apply transaction over already-locked resources.
    ///
    /// Returns the journal records plus whether the transaction was a
    /// semantic no-op (every `before` already expressed the plan). No-ops
    /// persist `Applied` records with `applied == before` and never touch
    /// the OS, but the returned lease is otherwise a fully owned,
    /// enforceable lease: it holds live records, active registration, and
    /// a lease id.
    pub(crate) fn transact_with_locks(
        &self,
        resources: Vec<ResourceId>,
        plan: &NormalizedConfig,
        befores: Vec<PlatformSnapshot>,
        identities: Vec<ResourceIdentity>,
    ) -> Result<PreparedLease> {
        let lease_id = Uuid::new_v4();
        let was_noop = befores
            .iter()
            .all(|before| self.backend.matches_desired(before, plan));
        let records: Vec<JournalRecord> = resources
            .into_iter()
            .zip(befores)
            .zip(identities)
            .map(|((resource, before), identity)| JournalRecord {
                owner: self.owner.clone(),
                lease_id,
                resource,
                backend: self.backend.kind(),
                identity,
                phase: if was_noop {
                    Phase::Applied
                } else {
                    Phase::Prepared
                },
                applied: was_noop.then(|| before.clone()),
                before,
                desired: plan.clone(),
            })
            .collect();
        self.persist_unmutated(&records)?;
        if was_noop {
            self.fire(TxPoint::AfterApplied)?;
            return Ok(PreparedLease {
                lease_id,
                records: records
                    .into_iter()
                    .map(|record| LiveRecord {
                        record,
                        state: LiveState::Committed,
                    })
                    .collect(),
                was_noop,
            });
        }
        self.fire(TxPoint::AfterPrepared)?;
        let mut mutations: Vec<VerifiedMutation> = Vec::new();
        for index in 0..records.len() {
            let expected = records[index].before.clone();
            match self.mutate_and_verify(&records[index].identity, &expected, plan, INITIAL_POINTS)
            {
                Ok(mutation) => mutations.push(mutation),
                Err(failure) => {
                    let MutationFailure { error, residue } = *failure;
                    let mut cleanup = Vec::new();
                    for (record, mutation) in records[..index].iter().zip(&mutations) {
                        match self.rollback_proven(
                            &record.identity,
                            Some(mutation.persist()),
                            &record.before,
                        ) {
                            MutationResidue::Restored(_) => {
                                if let Err(error) =
                                    self.journal.remove(&record.lease_id, &record.resource)
                                {
                                    cleanup.push(error);
                                }
                            }
                            MutationResidue::Pending(pending) => {
                                let mut retained = record.clone();
                                retained.applied = pending.evidence;
                                if let Err(error) = self.journal.write(&retained) {
                                    cleanup.push(error);
                                }
                                cleanup.push(Error::IndeterminateMutation {
                                    backend: self.backend.kind(),
                                    message: format!(
                                        "apply rollback could not restore {}",
                                        record.resource
                                    ),
                                });
                            }
                            MutationResidue::Unchanged => unreachable!(),
                        }
                    }
                    let failed = &records[index];
                    match residue {
                        MutationResidue::Pending(pending) => {
                            let mut retained = failed.clone();
                            retained.applied = pending.evidence;
                            if let Err(error) = self.journal.write(&retained) {
                                cleanup.push(error);
                            }
                        }
                        MutationResidue::Restored(_) | MutationResidue::Unchanged => {
                            if let Ok(now) = self.backend.readback(&failed.resource)
                                && self.backend.equivalent(&now, &failed.before)
                                && let Err(error) =
                                    self.journal.remove(&failed.lease_id, &failed.resource)
                            {
                                cleanup.push(error);
                            }
                        }
                    }
                    for record in &records[index + 1..] {
                        if let Err(error) = self.journal.remove(&record.lease_id, &record.resource)
                        {
                            cleanup.push(error);
                        }
                    }
                    return Err(transaction_error(error, cleanup));
                }
            }
        }
        let mut live: Vec<LiveRecord> = records
            .into_iter()
            .map(|record| LiveRecord {
                record,
                state: LiveState::Prepared,
            })
            .collect();
        let mut all_written = true;
        for (record, mutation) in live.iter_mut().zip(mutations) {
            if let Err(_error) = self.commit_verified(record, mutation) {
                osdns_warn!(resource = %record.record.resource, error = %_error,
                    "verified mutation remains pending until journal finalization succeeds");
                all_written = false;
            }
        }
        if all_written {
            self.fire(TxPoint::AfterApplied)?;
        }
        Ok(PreparedLease {
            lease_id,
            records: live,
            was_noop: false,
        })
    }

    /// Transactionally moves every owned resource to `plan` as one logical
    /// transaction: old complete configuration or new complete configuration,
    /// never a silently mixed configuration.
    ///
    /// Sequence: verify all resources still match their applied state, write
    /// all `Prepared` records, mutate+verify each resource, then write all
    /// `Applied` records. On any failure, previously updated resources are
    /// rolled back to their immediately previous applied state and every
    /// journal record is restored to its pre-update form.
    pub(crate) fn transact_update(
        &self,
        live: &[Arc<Mutex<LiveRecord>>],
        plan: &NormalizedConfig,
    ) -> Result<()> {
        self.fire(TxPoint::AfterUpdateResolve)?;
        // Snapshot the pre-update records and verify ownership first; no
        // mutation happens below until every resource is proven still ours.
        let mut olds: Vec<JournalRecord> = Vec::with_capacity(live.len());
        let mut applieds: Vec<PlatformSnapshot> = Vec::with_capacity(live.len());
        for record in live {
            let mut guard = record.lock();
            self.resolve_live(&mut guard, None)?;
            let applied = guard.applied().cloned().ok_or_else(|| {
                Error::ExternalModification {
                    resource: guard.record.resource.clone(),
                    detail: "the lease record carries no verified applied state; refusing to overwrite indeterminate state"
                        .to_string(),
                }
            })?;
            olds.push(guard.record.clone());
            applieds.push(applied);
        }
        for index in 0..live.len() {
            let resource = olds[index].resource.clone();
            let current = self.backend.readback(&resource)?;
            self.fire(TxPoint::AfterUpdateCapture)?;
            if !self.backend.owns_current(&applieds[index], &current) {
                return Err(Error::ExternalModification {
                    resource,
                    detail: "the current state no longer matches the state applied by this lease"
                        .to_string(),
                });
            }
        }
        if applieds
            .iter()
            .all(|applied| self.backend.matches_desired(applied, plan))
        {
            self.fire(TxPoint::AfterUpdateNoopCheck)?;
            return Ok(());
        }
        // Persist the prepared intent for every resource before mutating any.
        for record in live {
            let mut guard = record.lock();
            guard.record.desired = plan.clone();
            guard.record.phase = Phase::Prepared;
            guard.state = LiveState::Prepared;
            // `applied` still carries the previous applied state until the
            // mutation is verified; recovery therefore rolls back to it.
            if let Err(error) = self.journal.write(&guard.record) {
                // Restore any already-prepared journals to their old form so
                // the lease is never left half-prepared on a write failure.
                drop(guard);
                let mut cleanup = Vec::new();
                for (old, live_record) in olds.iter().zip(live.iter()) {
                    let mut guard = live_record.lock();
                    if let Err(error) = self.persist_live(&mut guard, old.clone()) {
                        cleanup.push(error);
                    }
                }
                return Err(transaction_error(error, cleanup));
            }
        }
        self.fire(TxPoint::AfterUpdatePrepared)?;
        // On failure every touched resource (including the failed one)
        // rolls back to its previous applied state; journals are then
        // restored to their pre-update form.
        let mut mutations: Vec<VerifiedMutation> = Vec::with_capacity(live.len());
        for index in 0..live.len() {
            let expected = applieds[index].clone();
            match self.mutate_and_verify(&olds[index].identity, &expected, plan, UPDATE_POINTS) {
                Ok(mutation) => mutations.push(mutation),
                Err(failure) => {
                    let MutationFailure { error, residue } = *failure;
                    let mut cleanup = Vec::new();
                    let mut residues: Vec<MutationResidue> = (0..live.len())
                        .map(|_| MutationResidue::Unchanged)
                        .collect();
                    for rollback_index in 0..index {
                        let mutation = &mutations[rollback_index];
                        residues[rollback_index] = self.rollback_proven(
                            &olds[rollback_index].identity,
                            Some(mutation.persist()),
                            &applieds[rollback_index],
                        );
                    }
                    residues[index] = residue;
                    self.fire(TxPoint::AfterUpdateVerify).ok();
                    for ((old, live_record), residue) in olds.iter().zip(live).zip(residues) {
                        let mut guard = live_record.lock();
                        match residue {
                            MutationResidue::Pending(pending) => {
                                if let Err(error) =
                                    self.retain_compensation(&mut guard, pending, old.clone())
                                {
                                    cleanup.push(error);
                                }
                                cleanup.push(Error::IndeterminateMutation {
                                    backend: self.backend.kind(),
                                    message: format!(
                                        "update rollback could not restore {}",
                                        old.resource
                                    ),
                                });
                            }
                            MutationResidue::Restored(identity) => {
                                let mut candidate = old.clone();
                                // Without new evidence, the old identity cannot authorize
                                // another mutation after a restore changed its generation.
                                candidate.applied = identity;
                                if candidate.applied.is_none() {
                                    candidate.phase = Phase::Prepared;
                                }
                                if let Err(error) = self.persist_live(&mut guard, candidate) {
                                    cleanup.push(error);
                                }
                            }
                            MutationResidue::Unchanged => {
                                if let Err(error) = self.persist_live(&mut guard, old.clone()) {
                                    cleanup.push(error);
                                }
                            }
                        }
                    }
                    return Err(transaction_error(error, cleanup));
                }
            }
        }
        let mut write_error = None;
        for (index, record) in live.iter().enumerate() {
            let mut guard = record.lock();
            let mutation = &mutations[index];
            if let Err(error) = self.commit_verified(&mut guard, mutation.clone())
                && write_error.is_none()
            {
                write_error = Some(error);
            }
        }
        if let Some(error) = write_error {
            return Err(error);
        }
        self.fire(TxPoint::AfterUpdateApplied)?;
        Ok(())
    }

    /// Publishes a known verified state or an unmutated journal intent.
    pub(crate) fn persist_live(
        &self,
        live: &mut LiveRecord,
        candidate: JournalRecord,
    ) -> Result<()> {
        let next = if candidate.phase == Phase::Applied {
            LiveState::Committed
        } else {
            LiveState::Prepared
        };
        match self.journal.write(&candidate) {
            Ok(()) => {
                live.record = candidate;
                live.state = next;
                Ok(())
            }
            Err(error) => {
                live.record = candidate;
                live.state = LiveState::Repair(Box::new(next));
                Err(error)
            }
        }
    }

    /// Every new native attempt first replaces the previous Applied record
    /// with durable Prepared intent. Failed publication restores the old intent
    /// or blocks mutation behind an explicit journal repair.
    pub(crate) fn prepare_live(
        &self,
        live: &mut LiveRecord,
        candidate: JournalRecord,
    ) -> Result<()> {
        let old = live.record.clone();
        let state = live.state.clone();
        if let Err(error) = self.journal.write(&candidate) {
            if self.journal.write(&old).is_err() {
                live.state = LiveState::Repair(Box::new(state));
            }
            return Err(error);
        }
        live.record = candidate;
        live.state = LiveState::Prepared;
        Ok(())
    }

    pub(crate) fn commit_verified(
        &self,
        live: &mut LiveRecord,
        mutation: VerifiedMutation,
    ) -> Result<()> {
        live.state = LiveState::Verified(mutation);
        self.resolve_live(live, None)
    }

    fn retain_compensation(
        &self,
        live: &mut LiveRecord,
        pending: PendingRollback,
        resume: JournalRecord,
    ) -> Result<()> {
        live.record.phase = Phase::Prepared;
        live.record.applied = pending.evidence.clone();
        live.record.desired = resume.desired.clone();
        live.state = LiveState::Compensating {
            pending,
            resume: Box::new(resume),
        };
        if let Err(error) = self.journal.write(&live.record) {
            live.state = LiveState::Repair(Box::new(live.state.clone()));
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn resolve_live(
        &self,
        live: &mut LiveRecord,
        current: Option<&PlatformSnapshot>,
    ) -> Result<()> {
        if let LiveState::Repair(next) = &live.state {
            self.journal.write(&live.record)?;
            live.state = *next.clone();
        }
        match live.state.clone() {
            LiveState::Committed => Ok(()),
            LiveState::Prepared => Err(Error::ExternalModification {
                resource: live.record.resource.clone(),
                detail: "prepared intent has no verified applied mutation".to_string(),
            }),
            LiveState::Verified(mutation) => {
                let owned;
                let current = match current {
                    Some(current) => current,
                    None => {
                        owned = self.backend.readback(&live.record.resource)?;
                        &owned
                    }
                };
                if self.backend.resource_status(&live.record.identity)? != ResourceStatus::Same
                    || !self.backend.owns_current(&mutation.persist(), current)
                {
                    return Err(Error::ExternalModification {
                        resource: live.record.resource.clone(),
                        detail: "verified mutation no longer names current native state"
                            .to_string(),
                    });
                }
                let mut candidate = live.record.clone();
                candidate.phase = Phase::Applied;
                candidate.applied = Some(mutation.persist());
                self.journal.write(&candidate)?;
                live.record = candidate;
                live.state = LiveState::Committed;
                Ok(())
            }
            LiveState::Compensating {
                mut pending,
                mut resume,
            } => {
                match self.compensate(&live.record.identity, &mut pending, None) {
                    Ok(identity) => {
                        if resume.phase == Phase::Applied {
                            resume.applied = identity;
                            if resume.applied.is_none() {
                                resume.phase = Phase::Prepared;
                            }
                        }
                        self.persist_live(live, *resume)
                    }
                    Err(error) => {
                        // A restoration attempt may have issued a newer identity.
                        // Publish it conservatively as Prepared recovery evidence.
                        let _ = self.retain_compensation(live, pending, *resume);
                        Err(error)
                    }
                }
            }
            LiveState::Repair(_) => unreachable!("journal repair is resolved first"),
        }
    }

    /// Restores one live-lease resource to its `before` snapshot, failing
    /// with [`Error::ExternalModification`] when the current state is no
    /// longer the verified applied state.
    pub(crate) fn restore_live_state(&self, live: &mut LiveRecord) -> Result<()> {
        let record = &live.record;
        let resource = &record.resource;
        match self.backend.resource_status(&record.identity)? {
            ResourceStatus::Gone | ResourceStatus::Replaced => {
                self.journal.remove(&record.lease_id, resource)?;
                return Ok(());
            }
            ResourceStatus::Ambiguous => {
                return Err(Error::ResourceIdentity {
                    backend: self.backend.kind(),
                    resource: resource.clone(),
                    message: "the backend cannot prove that the current target is the leased native resource incarnation".to_string(),
                });
            }
            ResourceStatus::Same => {}
        }
        let mut current = match self.backend.readback(resource) {
            Ok(current) => current,
            Err(Error::ResourceGone { .. }) => {
                self.journal.remove(&record.lease_id, resource)?;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        self.fire(TxPoint::AfterRestoreReadback)?;
        if self.backend.equivalent(&current, &record.before) {
            self.journal.remove(&record.lease_id, resource)?;
            self.fire(TxPoint::AfterRestoreJournal)?;
            return Ok(());
        }
        if !matches!(live.state, LiveState::Committed) {
            self.resolve_live(live, Some(&current))?;
            current = self.backend.readback(&live.record.resource)?;
            if self.backend.equivalent(&current, &live.record.before) {
                self.journal
                    .remove(&live.record.lease_id, &live.record.resource)?;
                self.fire(TxPoint::AfterRestoreJournal)?;
                return Ok(());
            }
        }
        let record = &live.record;
        let resource = &record.resource;
        let applied = live.applied().ok_or_else(|| Error::ExternalModification {
            resource: resource.clone(),
            detail: "the lease record carries no verified applied state; refusing to overwrite indeterminate state"
                .to_string(),
        })?;
        if !self.backend.owns_current(applied, &current) {
            return Err(Error::ExternalModification {
                resource: resource.clone(),
                detail: "the current state is neither the state applied by this lease nor the original state"
                    .to_string(),
            });
        }
        let mut pending = PendingRollback {
            evidence: Some(applied.clone()),
            target: record.before.clone(),
        };
        let mut resume = record.clone();
        resume.phase = Phase::Prepared;
        resume.applied = None;
        // Record the operation before calling the backend. Errors and failed
        // verification must keep the latest restoration identity for retry.
        live.state = LiveState::Compensating {
            pending: pending.clone(),
            resume: Box::new(resume.clone()),
        };
        let outcome = self.compensate(
            &live.record.identity,
            &mut pending,
            Some(TxPoint::AfterRestoreRestore),
        );
        if let Err(error) = outcome {
            let _ = self.retain_compensation(live, pending, resume);
            return Err(error);
        }
        live.state = LiveState::Compensating {
            pending,
            resume: Box::new(resume),
        };
        let record = &live.record;
        let resource = &record.resource;
        self.journal.remove(&record.lease_id, resource)?;
        self.fire(TxPoint::AfterRestoreJournal)?;
        Ok(())
    }

    /// Recovery uses only published evidence. Prepared may carry backend-issued
    /// residue that authorizes guarded restoration, without asserting that the
    /// desired state was verified. Desired-state equality alone and volatile
    /// live evidence never authorize crash recovery.
    fn recover_record(&self, record: JournalRecord) -> Result<RecoveryOutcome> {
        let resource = record.resource.clone();
        match self.backend.resource_status(&record.identity)? {
            ResourceStatus::Gone => {
                self.journal.remove(&record.lease_id, &resource)?;
                return Ok(RecoveryOutcome::Gone {
                    resource,
                    lease_id: record.lease_id,
                });
            }
            ResourceStatus::Replaced => {
                self.journal.remove(&record.lease_id, &resource)?;
                return Ok(RecoveryOutcome::Replaced {
                    resource,
                    lease_id: record.lease_id,
                });
            }
            ResourceStatus::Ambiguous => {
                return Ok(RecoveryOutcome::IdentityMismatch {
                    resource,
                    lease_id: record.lease_id,
                });
            }
            ResourceStatus::Same => {}
        }
        let current = match self.backend.capture(&resource) {
            Ok(current) => current,
            Err(Error::ResourceGone { .. }) => {
                self.journal.remove(&record.lease_id, &resource)?;
                return Ok(RecoveryOutcome::Gone {
                    resource,
                    lease_id: record.lease_id,
                });
            }
            Err(error) => return Err(error),
        };
        self.fire(TxPoint::AfterRecoveryReadback)?;
        if self.backend.equivalent(&current, &record.before) {
            self.journal.remove(&record.lease_id, &resource)?;
            self.fire(TxPoint::AfterRecoveryJournal)?;
            return Ok(RecoveryOutcome::JournalCleared {
                resource,
                lease_id: record.lease_id,
            });
        }
        let owned = record
            .applied
            .as_ref()
            .is_some_and(|applied| self.backend.owns_current(applied, &current));
        if owned {
            let mut pending = PendingRollback {
                evidence: record.applied.clone(),
                target: record.before.clone(),
            };
            if let Err(error) = self.compensate(
                &record.identity,
                &mut pending,
                Some(TxPoint::AfterRecoveryRestore),
            ) {
                let mut retained = record.clone();
                retained.phase = Phase::Prepared;
                retained.applied = pending.evidence;
                self.journal.write(&retained)?;
                if error.is_external_modification() {
                    return Ok(RecoveryOutcome::ExternalConflict {
                        resource,
                        lease_id: record.lease_id,
                    });
                }
                return Err(error);
            }
            self.journal.remove(&record.lease_id, &resource)?;
            self.fire(TxPoint::AfterRecoveryJournal)?;
            return Ok(RecoveryOutcome::Restored {
                resource,
                lease_id: record.lease_id,
            });
        }
        Ok(RecoveryOutcome::ExternalConflict {
            resource,
            lease_id: record.lease_id,
        })
    }

    fn recover_for_resource(&self, record: JournalRecord) -> std::result::Result<(), RecoverBlock> {
        if record.owner != self.owner {
            return Err(RecoverBlock::Conflict(format!(
                "journal belongs to application owner {}",
                record.owner
            )));
        }
        match self.recover_record(record) {
            Ok(RecoveryOutcome::ExternalConflict { .. }) => Err(RecoverBlock::Conflict(
                "the current state matches neither the journal's applied state nor its original state".to_string()
            )),
            Ok(RecoveryOutcome::IdentityMismatch { .. }) => Err(RecoverBlock::Conflict(
                "the recorded native resource incarnation cannot be recovered safely".to_string()
            )),
            Ok(_) => Ok(()),
            Err(error @ Error::JournalCorrupt(_)) => Err(RecoverBlock::Journal(error)),
            Err(error) => Err(RecoverBlock::Conflict(error.to_string())),
        }
    }

    pub(crate) fn recover_stale(&self) -> Result<Vec<RecoveryOutcome>> {
        let records = self.journal.records()?;
        let mut outcomes = Vec::new();
        for record in records {
            let resource = record.resource.clone();
            let lease_id = record.lease_id;
            if record.owner != self.owner {
                outcomes.push(RecoveryOutcome::ForeignOwner {
                    resource,
                    owner: record.owner,
                });
                continue;
            }
            match self.locks.try_acquire(&resource) {
                Ok(Some(lock)) => {
                    let outcome = self.recover_record(record).unwrap_or_else(|error| {
                        RecoveryOutcome::Failed {
                            resource: resource.clone(),
                            lease_id,
                            detail: error.to_string(),
                        }
                    });
                    drop(lock);
                    outcomes.push(outcome);
                }
                Ok(None) => outcomes.push(RecoveryOutcome::Busy { resource }),
                Err(Error::Conflict { .. }) => {
                    outcomes.push(RecoveryOutcome::Busy { resource });
                }
                Err(error) => outcomes.push(RecoveryOutcome::Failed {
                    resource,
                    lease_id,
                    detail: error.to_string(),
                }),
            }
        }
        Ok(outcomes)
    }

    pub(crate) fn abandon_journal(&self, resource: &ResourceId) -> Result<()> {
        let lock = self.locks.acquire(resource)?;
        let records = self.journal.records_for(resource)?;
        if records.iter().any(|record| record.owner != self.owner) {
            return Err(Error::Conflict {
                resource: resource.clone(),
                reason: ConflictReason::ResourceOccupied {
                    detail: "journal belongs to another application owner".to_string(),
                },
            });
        }
        let mut result = Ok(());
        for record in records {
            if let Err(error) = self.journal.remove(&record.lease_id, resource) {
                result = Err(error);
                break;
            }
        }
        drop(lock);
        result
    }
}

/// Entry point for reading, applying, watching, reconciling, and safely
/// restoring host OS DNS configuration.
///
/// Every mutation belongs to an explicit owner and [`Lease`], is journaled
/// before it happens, and is verified by read-back. Before later mutation or
/// restoration, osdns checks the strongest ownership and resource-incarnation
/// evidence exposed by the backend and fails closed when that evidence is
/// ambiguous. Exact guarantees are reported by [`Capabilities`]:
/// backends with [`OwnershipIdentity::BestEffort`](crate::OwnershipIdentity)
/// cannot prove every equivalent rewrite, while
/// [`ResourceBinding::PreflightOnly`](crate::ResourceBinding) means the native
/// API permits a final selector-reuse race after osdns's last identity check.
///
/// A manager is cheap to clone: clones share the same owner, backend, locks,
/// journal, and active-lease registry. It is `Send + Sync` and may be shared
/// across threads. Individual [`Lease`]s own their resources exclusively.
///
/// Mutations generally require elevated privileges (see [`Error::RequiresPrivilege`]);
/// `osdns` never escalates privileges on its own. Operations are synchronous
/// control-plane calls with no async runtime dependency.
///
/// After a process crash, journals left behind are recovered with
/// [`DnsManager::recover_stale`]; corrupt or unknown journal state fails
/// closed.
///
/// ```no_run
/// use osdns::{DnsConfig, DnsManager, DnsScope, InterfaceSelector};
///
/// # fn main() -> osdns::Result<()> {
/// let manager = DnsManager::builder()
///     .owner("io.example.agent")
///     .build()?;
/// let caps = manager.capabilities()?;
/// let current = manager.snapshot(&DnsScope::Interface(InterfaceSelector::Default))?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct DnsManager {
    inner: Arc<Inner>,
}

impl DnsManager {
    pub(crate) fn from_inner(inner: Arc<Inner>) -> Self {
        Self { inner }
    }

    /// Returns a builder for constructing a manager.
    ///
    /// See [`DnsManagerBuilder`] for the required `owner` identifier and the
    /// optional state directory, lock timeout, and conflict policy.
    pub fn builder() -> DnsManagerBuilder {
        DnsManagerBuilder::new()
    }

    /// The owner identifier every lease created by this manager carries.
    pub fn owner(&self) -> &str {
        &self.inner.owner
    }

    /// The configured conflict policy.
    pub fn conflict_policy(&self) -> ConflictPolicy {
        self.inner.conflict_policy
    }

    /// Inspects internal Enforce observation without reading or mutating DNS.
    pub fn observation_health(&self) -> ObservationHealth {
        let enforce = self.inner.enforce.lock();
        if enforce.refs == 0 {
            ObservationHealth::Idle
        } else if enforce.handle.as_ref().is_some_and(WatchHandle::is_active) {
            ObservationHealth::Operational
        } else {
            ObservationHealth::Degraded {
                detail: enforce.recovery.as_ref().map_or_else(
                    || "native observation stopped".to_string(),
                    |recovery| recovery.error.clone(),
                ),
            }
        }
    }

    /// Active resources awaiting an authoritative Enforce pass.
    pub fn pending_reconciliation(&self) -> Vec<ResourceId> {
        self.inner.reconciler.pending_resources()
    }

    /// What the active backend can actually guarantee.
    ///
    /// Never assumes uniformity across platforms: check fields such as
    /// `split_dns`, `per_interface_dns`, or `watch` before using the
    /// corresponding facility. Returns [`Error::BackendUnavailable`] only
    /// when no backend exists on this host.
    pub fn capabilities(&self) -> Result<Capabilities> {
        Ok(self.inner.backend.capabilities())
    }

    /// Lists network interfaces known to the backend.
    ///
    /// Read-only; requires no privileges beyond what the platform needs for
    /// enumeration. Names and indexes are selectors only; their lifetime and
    /// reuse semantics are backend-specific.
    pub fn interfaces(&self) -> Result<Vec<InterfaceInfo>> {
        self.inner.backend.list_interfaces()
    }

    /// Reads the current DNS configuration of `scope` from the system.
    ///
    /// Read-only and side-effect free. For multi-resource scopes this reports
    /// the primary resource (for example the network service backing the
    /// interface), not per-domain scoped state. For the Openresolv backend,
    /// `Global` reports the effective generated libc resolver state, including
    /// contributions from all Openresolv records; the owner-tagged source
    /// record remains private transaction state.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BackendUnavailable`] when the scope cannot be resolved
    /// on this backend and [`Error::Platform`] when the OS read fails.
    pub fn snapshot(&self, scope: &DnsScope) -> Result<DnsConfig> {
        let resources = self
            .inner
            .backend
            .resolve_resources(scope, &NormalizedConfig::default())?;
        let resource = resources.first().ok_or_else(|| {
            Error::invalid_config("the backend resolved the scope to no resources")
        })?;
        let snapshot = self.inner.backend.capture(resource)?;
        self.inner.backend.public_state(&snapshot, scope)
    }

    /// Validates a configuration against backend capabilities without
    /// touching the system.
    ///
    /// No locks are taken, no journal is written, and no OS state is read.
    /// Returns [`Error::InvalidConfig`] for malformed input and
    /// [`Error::Unsupported`] when the active backend cannot represent the
    /// request. [`DnsManager::apply`] performs the same check again before
    /// any mutation.
    pub fn validate(&self, config: &DnsConfig) -> Result<()> {
        let caps = self.inner.backend.capabilities();
        let plan = validate_against(config, &caps)?;
        self.inner.backend.validate_plan(config.scope(), &plan)?;
        Ok(())
    }

    /// Applies `config` transactionally and returns a [`Lease`] owning the
    /// resources.
    ///
    /// Every lease owns journal records and live reconciliation state, even
    /// when the desired state is already in effect: a no-op apply persists
    /// `Applied` records with `applied == before` instead of mutating, so
    /// an [`ConflictPolicy::Enforce`] lease over pre-existing desired state
    /// is still an enforceable ownership state with active reconciliation.
    ///
    /// The sequence is: resolve resources, acquire exclusive inter-process
    /// locks in sorted order (so multi-resource leases cannot deadlock),
    /// recover stale journals for those resources, capture current state,
    /// persist `Prepared` records (or `Applied` directly for the no-op
    /// fast path), mutate and verify each resource by read-back
    /// (attempting guarded rollback on failure), persist `Applied`
    /// records, and return the lease holding the locks.
    ///
    /// Native operations can partially mutate a resource. On failure, rollback
    /// uses backend-issued evidence where available; unresolved mutations retain
    /// journals for [`DnsManager::recover_stale`]. No atomicity across resources
    /// is promised.
    /// Requires elevated privileges on most platforms; see
    /// [`Error::RequiresPrivilege`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use osdns::{DnsConfig, DnsManager, DnsScope, InterfaceSelector};
    /// # fn main() -> osdns::Result<()> {
    /// # let manager = DnsManager::builder().owner("io.example.agent").build()?;
    /// let config = DnsConfig::builder(DnsScope::Interface(InterfaceSelector::Default))
    ///     .nameserver("127.0.0.1".parse().unwrap())
    ///     .build()?;
    /// let lease = manager.apply(&config)?;
    /// lease.restore()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn apply(&self, config: &DnsConfig) -> Result<Lease> {
        let caps = self.inner.backend.capabilities();
        let plan = validate_against(config, &caps)?;
        self.inner.backend.validate_plan(config.scope(), &plan)?;
        self.inner.fire(TxPoint::AfterValidate)?;
        let resources = self
            .inner
            .backend
            .resolve_resources(config.scope(), &plan)?;
        self.inner.fire(TxPoint::AfterResolve)?;
        let locks = self.inner.locks.acquire_all(&resources)?;
        self.inner.fire(TxPoint::AfterLock)?;
        let mut journals = self.inner.journal.records()?;
        for resource in &resources {
            if let Some(index) = journals
                .iter()
                .position(|record| &record.resource == resource)
            {
                match self.inner.recover_for_resource(journals.swap_remove(index)) {
                    Ok(()) => {}
                    Err(RecoverBlock::Journal(error)) => return Err(error),
                    Err(RecoverBlock::Conflict(detail)) => {
                        return Err(Error::Conflict {
                            resource: resource.clone(),
                            reason: ConflictReason::StaleJournalUnresolved { detail },
                        });
                    }
                }
            }
        }
        self.inner.fire(TxPoint::AfterRecovery)?;
        let mut befores = Vec::with_capacity(resources.len());
        let mut identities = Vec::with_capacity(resources.len());
        for resource in &resources {
            let observation = self.inner.backend.observe(resource)?;
            identities.push(observation.identity);
            befores.push(observation.snapshot);
            self.inner.fire(TxPoint::AfterCapture)?;
        }
        self.inner.fire(TxPoint::AfterNoopDecision)?;
        match self
            .inner
            .transact_with_locks(resources, &plan, befores, identities)
        {
            Ok(PreparedLease {
                lease_id,
                records,
                was_noop,
            }) => {
                let lease =
                    Lease::new_owned(self.inner.clone(), lease_id, records, locks, was_noop);
                if let Err(error) = self.inner.ensure_enforce_watch() {
                    return Err(match lease.restore() {
                        Ok(()) => error,
                        Err(failure) => transaction_error(error, vec![failure.error]),
                    });
                }
                self.inner.rescan_enforce();
                Ok(lease)
            }
            Err(error) => Err(error),
        }
    }

    /// Registers a callback for native DNS change notifications.
    ///
    /// This is a pure observability subscription: events are coalesced per
    /// resource within a small window, and events caused by this manager's
    /// own mutations are suppressed for the user-callback path. It is never
    /// required for [`ConflictPolicy::Enforce`] to work; Enforce keeps its
    /// own internal observation alive while leases are active.
    ///
    /// Suppression compares authoritative state with this manager's completed
    /// mutation snapshot on the coalescing worker. External changes remain visible
    /// even immediately after a mutation. Native delivery can be incomplete;
    /// check [`WatchHandle::is_active`] and resubscribe after interruption.
    /// Enforce manages its own resubscription and authoritative rescan.
    ///
    /// The callback must only publish or coalesce events; it must never
    /// perform expensive or mutating work. The returned [`WatchHandle`]
    /// cancels this subscription's native notification when stopped or
    /// dropped; dropping it never disables Enforce while an active lease
    /// still requires it.
    pub fn watch(&self, callback: WatchCallback) -> Result<WatchHandle> {
        let inner = Arc::clone(&self.inner);
        let verified: WatchCallback = Arc::new(move |event| {
            if matches!(event, crate::watch::DnsEvent::ResourceChanged { .. })
                && let Some(ours) = inner.suppressions.snapshot(event.resource())
                && let Ok(current) = inner.backend.readback(event.resource())
                && inner.backend.owns_current(&ours, &current)
            {
                return;
            }
            callback(event);
        });
        let coalescer =
            crate::watch::spawn_coalescer(self.inner.backend.kind(), verified, COALESCE_WINDOW)?;
        let coalesced = coalescer.callback();
        let native = self.inner.backend.start_watch(coalesced)?;
        let flag = native.flag();
        let delivery = Arc::clone(&coalescer.flag);
        let mut handle = WatchHandle::new(flag, move || {
            native.stop();
            coalescer.stop();
        });
        handle.delivery = Some(delivery);
        Ok(handle)
    }
    /// Flushes the OS DNS cache, when the backend supports it.
    ///
    /// Best-effort only; correctness never depends on cache state. Returns
    /// [`Error::Unsupported`] on backends without a flush facility. Check
    /// [`Capabilities::cache_flush`](crate::Capabilities) first.
    pub fn flush_cache(&self) -> Result<()> {
        self.inner.backend.flush_cache()
    }

    /// Scans the journal for records left behind by crashed or exited
    /// processes and recovers them where it is safe to do so.
    ///
    /// Resources locked by an active lease (in this or another process) are
    /// reported as [`RecoveryOutcome::Busy`] and left untouched. Records whose
    /// current state still matches published ownership evidence are
    /// restored to the original state. Prepared evidence may identify an
    /// incomplete mutation without proving successful application. Records already
    /// at the original state are simply cleared; anything else — including unverified `Prepared`
    /// records whose state merely matches the desired configuration — is
    /// reported as [`RecoveryOutcome::ExternalConflict`] and kept. Native
    /// resource lifetime is checked before any DNS read. Per-record failures
    /// are returned as [`RecoveryOutcome::Failed`] so unrelated records still
    /// make progress. Enumeration, parse, schema, and integrity failures are
    /// top-level errors and fail closed before recovery begins.
    pub fn recover_stale(&self) -> Result<Vec<RecoveryOutcome>> {
        self.inner.recover_stale()
    }

    /// Explicitly discards our ownership claim over `resource` without
    /// touching the system.
    ///
    /// Removes this manager's journal records for `resource` while holding
    /// the resource lock. Use this after an [`Error::ExternalModification`]
    /// conflict when the external state should win and the record should stop
    /// being reported by [`DnsManager::recover_stale`]. Same primitive as
    /// [`Lease::abandon`](crate::Lease::abandon), but usable without holding
    /// the lease.
    pub fn abandon_journal(&self, resource: &ResourceId) -> Result<()> {
        self.inner.abandon_journal(resource)
    }

    #[cfg(feature = "test-util")]
    /// Installs a fault injector for transaction-level failure and crash
    /// injection (testing only).
    pub fn install_fault_injector(&self, injector: Arc<crate::testing::FaultInjector>) {
        let hook: Arc<dyn FaultHook> = injector;
        *self.inner.hook.lock() = Some(hook);
    }

    /// Toggles injected journal write failures (testing only).
    #[cfg(feature = "test-util")]
    pub fn set_journal_fail_writes(&self, fail: bool) {
        self.inner.journal.set_fail_writes(fail);
    }

    /// Allows `skip` journal writes, then fails subsequent writes (testing
    /// only).
    #[cfg(feature = "test-util")]
    pub fn set_journal_fail_writes_after(&self, skip: u32) {
        self.inner.journal.set_fail_writes_after(skip);
    }

    /// Injects failures after journal publication or removal took effect (testing only).
    #[cfg(feature = "test-util")]
    pub fn set_journal_fail_after_io(&self, fail: bool) {
        self.inner.journal.set_fail_after_io(fail);
    }

    /// Toggles injected journal removal failures (testing only).
    #[cfg(feature = "test-util")]
    pub fn set_journal_fail_removes(&self, fail: bool) {
        self.inner.journal.set_fail_removes(fail);
    }

    /// Number of live leases holding internal Enforce observation (testing
    /// only). Cooperative managers always report zero.
    #[cfg(feature = "test-util")]
    pub fn debug_enforce_refs(&self) -> usize {
        self.inner.enforce_refs()
    }

    /// Whether the internal Enforce watcher is currently running (testing
    /// only).
    #[cfg(feature = "test-util")]
    pub fn debug_enforce_watching(&self) -> bool {
        self.inner.enforce_watching()
    }

    /// Stops the background Enforce worker without releasing the lease
    /// reference (testing only), so `debug_reconcile` drives reconciliation
    /// deterministically.
    #[cfg(feature = "test-util")]
    pub fn suspend_enforce_background(&self) {
        self.inner.suspend_enforce_watch();
    }

    /// Runs one synchronous reconciliation pass for `resource` (testing
    /// only), so Enforce semantics can be exercised deterministically
    /// without timing races against the worker thread.
    #[cfg(feature = "test-util")]
    pub fn debug_reconcile(&self, resource: &str) -> Result<crate::testing::DebugReconcile> {
        use crate::reconciliation::ReconcileOutcome;
        let resource: ResourceId = resource.parse().map_err(|e| {
            Error::invalid_config(format_args!("invalid resource id {resource:?}: {e}"))
        })?;
        let _reconcile_guard = self.inner.reconciler.lock_gate();
        Ok(
            match self
                .inner
                .reconcile_resource(&resource, &self.inner.reconciler)
            {
                ReconcileOutcome::NoActiveLease => crate::testing::DebugReconcile::NotOwned,
                ReconcileOutcome::IdentityAmbiguous => {
                    crate::testing::DebugReconcile::IdentityAmbiguous
                }
                ReconcileOutcome::StillOurs => crate::testing::DebugReconcile::StillOurs,
                ReconcileOutcome::Rebased => crate::testing::DebugReconcile::Rebased,
                ReconcileOutcome::Deferred => crate::testing::DebugReconcile::Deferred,
                ReconcileOutcome::Failed => crate::testing::DebugReconcile::Failed,
            },
        )
    }

    /// Whether Enforce still has `resource` scheduled for reconciliation.
    #[cfg(feature = "test-util")]
    pub fn debug_reconcile_pending(&self, resource: &str) -> Result<bool> {
        let resource: ResourceId = resource.parse().map_err(|e| {
            Error::invalid_config(format_args!("invalid resource id {resource:?}: {e}"))
        })?;
        Ok(self.inner.reconciler.is_pending(&resource))
    }
}

impl std::fmt::Debug for DnsManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsManager")
            .field("owner", &self.inner.owner)
            .field("conflict_policy", &self.inner.conflict_policy)
            .finish_non_exhaustive()
    }
}

/// Builder for [`DnsManager`].
///
/// The `owner` identifier is required and names every lease, journal record,
/// and ownership marker this manager creates. Optional settings have stable
/// defaults: a platform-appropriate state directory, a 30-second lock
/// timeout, and [`ConflictPolicy::Cooperative`].
///
/// ```no_run
/// # use osdns::DnsManager;
/// # fn main() -> osdns::Result<()> {
/// let manager = DnsManager::builder()
///     .owner("io.example.agent")
///     .conflict_policy(osdns::ConflictPolicy::Cooperative)
///     .build()?;
/// # Ok(())
/// # }
/// ```
pub struct DnsManagerBuilder {
    owner: Option<String>,
    state_dir: Option<PathBuf>,
    lock_timeout: Duration,
    conflict_policy: ConflictPolicy,
}

impl DnsManagerBuilder {
    pub(crate) fn new() -> Self {
        Self {
            owner: None,
            state_dir: None,
            lock_timeout: Duration::from_secs(30),
            conflict_policy: ConflictPolicy::default(),
        }
    }

    /// Sets the owner identifier (e.g. `io.example.agent`). Required.
    ///
    /// Owners are reverse-DNS style identifiers: 1–255 characters of ASCII
    /// letters, digits, dots, dashes, and underscores. The owner tags every
    /// journal record and platform ownership marker, so two applications never
    /// mistake each other's state for their own. Invalid identifiers fail at
    /// [`DnsManagerBuilder::build`] with [`Error::InvalidConfig`].
    pub fn owner(mut self, owner: impl Into<String>) -> Self {
        self.owner = Some(owner.into());
        self
    }

    /// Overrides the directory used for the durable journal.
    ///
    /// Defaults to a platform-appropriate system location (`/var/lib/osdns`
    /// on Linux and the BSDs, `PROGRAMDATA\osdns` on Windows, `/Library/Application
    /// Support/osdns` on macOS). The directory is created on
    /// [`DnsManagerBuilder::build`] and secured against unprivileged
    /// modification; failure surfaces as [`Error::RequiresPrivilege`] or
    /// [`Error::Io`].
    ///
    /// Journal storage never defines the ownership universe: inter-process
    /// resource locks live in a global system location independent of this
    /// setting, so two managers with different state directories still
    /// exclude each other on the same OS resource.
    pub fn state_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.state_dir = Some(dir.into());
        self
    }

    /// Sets how long acquiring a contended resource lock may block.
    /// Defaults to 30 seconds. Must be non-zero. When the deadline expires,
    /// lock acquisition fails with [`Error::Timeout`] and nothing is mutated.
    pub fn lock_timeout(mut self, timeout: Duration) -> Self {
        self.lock_timeout = timeout;
        self
    }

    /// Sets the conflict policy. Defaults to
    /// [`ConflictPolicy::Cooperative`].
    ///
    /// [`ConflictPolicy::Enforce`] is self-contained and fails at build
    /// time when the backend cannot watch; no public
    /// [`DnsManager::watch`] subscription is ever required for it to work.
    pub fn conflict_policy(mut self, policy: ConflictPolicy) -> Self {
        self.conflict_policy = policy;
        self
    }

    /// Builds the manager.
    ///
    /// Fails with [`Error::UnsupportedPlatform`] on targets that have no OS
    /// DNS backend or [`Error::BackendUnavailable`] when this host has no usable
    /// backend. State and lock directories are opened lazily by writable operations;
    /// capabilities, interfaces and snapshots do not initialize writable storage.
    pub fn build(self) -> Result<DnsManager> {
        let owner = self
            .owner
            .ok_or_else(|| Error::invalid_config("an owner identifier is required"))?;
        validate_owner(&owner)?;
        if self.lock_timeout.is_zero() {
            return Err(Error::invalid_config(
                "lock_timeout must be greater than zero",
            ));
        }
        let backend = select_default_backend(&owner)?;
        if self.conflict_policy == ConflictPolicy::Enforce && !backend.capabilities().watch {
            return Err(Error::unsupported(
                backend.kind(),
                "ConflictPolicy::Enforce requires change notifications, which this backend does not support",
            ));
        }
        let state_dir = match self.state_dir {
            Some(dir) => dir,
            None => default_state_dir()?,
        };
        // Locks are globally authoritative per OS resource, independent of
        // journal storage: a custom state_dir must never create a private
        // ownership universe. The directory is created lazily on first
        // lock acquisition so read-only flows never require its
        // privileges.
        let global_lock_dir = global_lock_root()?.join("locks");
        let locks = ResourceLockManager::new(global_lock_dir, self.lock_timeout);
        let journal = JournalStore::new(state_dir.join("journal"));
        Ok(DnsManager::from_inner(Arc::new(Inner {
            owner,
            backend,
            locks,
            journal,
            conflict_policy: self.conflict_policy,
            hook: Mutex::new(None),
            suppressions: Arc::new(SuppressionRegistry::new()),
            active: Mutex::new(HashMap::new()),
            lease_tokens: Mutex::new(HashMap::new()),
            reconciler: Arc::new(Reconciler::default()),
            enforce: Mutex::new(EnforceState::default()),
        })))
    }
}

impl Default for DnsManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn validate_owner(owner: &str) -> Result<()> {
    if owner.is_empty() || owner.len() > 255 {
        return Err(Error::invalid_config(
            "owner identifier must be 1-255 characters",
        ));
    }
    for c in owner.chars() {
        if !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')) {
            return Err(Error::invalid_config(format_args!(
                "owner identifier {owner:?} contains invalid character {c:?}"
            )));
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn default_state_dir() -> Result<PathBuf> {
    crate::platform::windows::programdata::program_data_dir().map(|dir| dir.join("osdns"))
}

#[cfg(target_os = "macos")]
fn default_state_dir() -> Result<PathBuf> {
    Ok(PathBuf::from("/Library/Application Support/osdns"))
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn default_state_dir() -> Result<PathBuf> {
    Ok(PathBuf::from("/var/lib/osdns"))
}

/// Machine-wide lock namespace. Independent of journal `state_dir` and of
/// process environment variables that can alias per-user directories.
pub(crate) fn global_lock_root() -> Result<PathBuf> {
    default_state_dir()
}

#[cfg(all(test, target_os = "windows"))]
mod windows_lock_dir_tests {
    use super::global_lock_root;

    #[test]
    fn global_lock_root_ignores_programdata_and_localappdata() {
        let original_programdata = std::env::var_os("PROGRAMDATA");
        let original_local = std::env::var_os("LOCALAPPDATA");
        // SAFETY: tests in this process serialize on this function; we restore
        // the previous values before returning.
        unsafe {
            std::env::set_var("PROGRAMDATA", r"C:\osdns-test-programdata-not-real");
            std::env::set_var("LOCALAPPDATA", r"C:\osdns-test-localappdata-not-real");
        }
        let resolved = global_lock_root();
        unsafe {
            match original_programdata {
                Some(value) => std::env::set_var("PROGRAMDATA", value),
                None => std::env::remove_var("PROGRAMDATA"),
            }
            match original_local {
                Some(value) => std::env::set_var("LOCALAPPDATA", value),
                None => std::env::remove_var("LOCALAPPDATA"),
            }
        }
        let path = resolved.expect("machine ProgramData must be resolvable");
        assert!(
            path.ends_with("osdns"),
            "lock root should be under ProgramData\\osdns: {}",
            path.display()
        );
        let text = path.to_string_lossy();
        assert!(
            !text.contains("osdns-test-programdata-not-real"),
            "lock root followed PROGRAMDATA: {text}"
        );
        assert!(
            !text.contains("osdns-test-localappdata-not-real"),
            "lock root followed LOCALAPPDATA: {text}"
        );
    }
}
