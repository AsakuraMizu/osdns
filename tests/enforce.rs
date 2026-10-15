//! Enforce-policy reconciliation tests: external base changes are rebased
//! and the desired overlay reapplied; restore then returns to the external
//! base. Cooperative policy must keep the old conflict behavior.
//!
//! Reconciliation is state-aware (our own mutation events are no-ops) and
//! event-safe (events inside suppression or defer windows are pending, never
//! dropped), so external changes are acted on no matter when they arrive.

#![cfg(feature = "test-util")]

use std::time::{Duration, Instant};

mod common;

use common::*;
use osdns::testing::{
    CrashOutcome, DebugReconcile, FakeDns, FaultInjector, TxPoint, manager_for_testing_with_policy,
};
use osdns::{ConflictPolicy, RecoveryOutcome};

fn enforce_manager(tag: &str) -> Fixture {
    let dir = temp_dir(tag);
    let fake = FakeDns::new();
    let manager = manager_for_testing_with_policy(
        "io.osdns.test",
        &dir,
        &fake,
        Duration::from_secs(30),
        ConflictPolicy::Enforce,
    )
    .unwrap();
    Fixture { manager, fake, dir }
}

fn wait_until(predicate: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("condition not reached within 5s");
}

#[rstest::rstest]
#[case(1)]
#[case(3)]
fn rejected_overlay_rebases_once_external_state_stabilizes(
    #[case] rejections: usize,
    #[values("none", "rejected", "ambiguous")] publication_failure: &str,
) {
    let fixture = enforce_manager("enforce-rejected-retry");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture.manager.suspend_enforce_background();
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    let mut external = state_with("9.9.9.9");
    for attempt in 0..rejections {
        external = state_with(if attempt % 2 == 0 {
            "8.8.8.8"
        } else {
            "4.4.4.4"
        });
        let generation = fixture.fake.generation(IFACE1).unwrap().unwrap();
        fixture
            .fake
            .inject_external_before_guarded(IFACE1, external.clone())
            .unwrap();
        assert_eq!(
            fixture.manager.debug_reconcile(IFACE1).unwrap(),
            DebugReconcile::Failed
        );
        assert_eq!(
            fixture.fake.current_state(IFACE1).unwrap(),
            Some(external.clone())
        );
        assert_eq!(
            fixture.fake.generation(IFACE1).unwrap(),
            Some(generation + 1),
            "a rejected attempt must neither apply nor compensate"
        );
        assert_eq!(journal_record_json(&fixture.dir)["phase"], "Prepared");
    }
    let generation = fixture.fake.generation(IFACE1).unwrap();
    if publication_failure != "none" {
        if publication_failure == "ambiguous" {
            fixture.manager.set_journal_fail_after_io(true);
        } else {
            fixture.manager.set_journal_fail_writes(true);
        }
        assert_eq!(
            fixture.manager.debug_reconcile(IFACE1).unwrap(),
            DebugReconcile::Failed
        );
        assert_eq!(fixture.fake.generation(IFACE1).unwrap(), generation);
        fixture.manager.set_journal_fail_after_io(false);
        fixture.manager.set_journal_fail_writes(true);
        assert_eq!(
            fixture.manager.debug_reconcile(IFACE1).unwrap(),
            DebugReconcile::Failed
        );
        assert_eq!(fixture.fake.generation(IFACE1).unwrap(), generation);
        assert_eq!(lease.pending_durability(), lease.resources());
        fixture.manager.set_journal_fail_writes(false);
    }
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::Rebased
    );
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1"))
    );
    assert!(lease.pending_durability().is_empty());
    lease.restore().unwrap();
    assert_eq!(fixture.fake.current_state(IFACE1).unwrap(), Some(external));
    assert!(journal_files(&fixture.dir).is_empty());
}

#[rstest::rstest]
#[case(false)]
#[case(true)]
fn rejected_overlay_does_not_grant_ownership(#[case] crash: bool) {
    let fixture = enforce_manager("enforce-rejected-ownership");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture.manager.suspend_enforce_background();
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    let external = state_with(if crash { "8.8.8.8" } else { "1.1.1.1" });
    fixture
        .fake
        .inject_external_before_guarded(IFACE1, external.clone())
        .unwrap();
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::Failed
    );
    let generation = fixture.fake.generation(IFACE1).unwrap();
    if crash {
        lease.debug_release_locks_keep_journal();
        assert!(matches!(
            &fixture.manager.recover_stale().unwrap()[..],
            [RecoveryOutcome::ExternalConflict { .. }]
        ));
        fixture
            .manager
            .abandon_journal(&resource_id(IFACE1))
            .unwrap();
    } else {
        assert_eq!(
            fixture.manager.debug_reconcile(IFACE1).unwrap(),
            DebugReconcile::Deferred
        );
        let failure = lease.restore().unwrap_err();
        assert!(failure.error.is_external_modification());
        failure.lease.abandon().unwrap();
    }
    assert_eq!(fixture.fake.generation(IFACE1).unwrap(), generation);
    assert_eq!(fixture.fake.current_state(IFACE1).unwrap(), Some(external));
    assert!(journal_files(&fixture.dir).is_empty());
}

#[rstest::rstest]
#[case(false)]
#[case(true)]
fn compensated_overlay_intent_can_be_superseded(#[case] deferred_compensation: bool) {
    use osdns::testing::FakeOp;
    let fixture = enforce_manager("enforce-compensated-retry");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture.manager.suspend_enforce_background();
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    fixture.fake.inject_partial_apply_failure(1);
    if deferred_compensation {
        fixture
            .fake
            .inject_backend_failure(FakeOp::Restore, 1, "compensation unavailable");
    }
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::Failed
    );
    if deferred_compensation {
        // Compensation succeeds, but its journal publication must be repaired
        // before the resolved intent can be replaced by another transaction.
        fixture.manager.set_journal_fail_writes(true);
        assert_eq!(
            fixture.manager.debug_reconcile(IFACE1).unwrap(),
            DebugReconcile::Failed
        );
    }
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9"))
    );
    fixture
        .fake
        .external_change(IFACE1, state_with("8.8.8.8"))
        .unwrap();
    fixture.manager.set_journal_fail_writes(false);
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::Rebased
    );
    lease.restore().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("8.8.8.8"))
    );
    assert!(journal_files(&fixture.dir).is_empty());
}

#[rstest::rstest]
#[case(false)]
#[case(true)]
fn indeterminate_overlay_cannot_be_superseded(#[case] produced_evidence: bool) {
    use osdns::testing::FakeOp;
    let fixture = enforce_manager("enforce-indeterminate-blocked");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture.manager.suspend_enforce_background();
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    if produced_evidence {
        fixture.fake.inject_partial_apply_failure(1);
        fixture
            .fake
            .inject_backend_failure(FakeOp::Restore, 1, "compensation unavailable");
    } else {
        // This seam changes native state before the backend returns an
        // indeterminate result with no produced evidence.
        fixture
            .fake
            .inject_external_before_nth_guarded(0, IFACE1, state_with("8.8.8.8"))
            .unwrap();
        fixture
            .fake
            .inject_backend_failure(FakeOp::Apply, 1, "outcome unknown");
    }
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::Failed
    );
    if produced_evidence {
        fixture
            .fake
            .external_change(IFACE1, state_with("8.8.8.8"))
            .unwrap();
    }
    let generation = fixture.fake.generation(IFACE1).unwrap();
    for _ in 0..3 {
        assert_eq!(
            fixture.manager.debug_reconcile(IFACE1).unwrap(),
            if produced_evidence {
                DebugReconcile::Deferred
            } else {
                DebugReconcile::Failed
            }
        );
        assert_eq!(fixture.fake.generation(IFACE1).unwrap(), generation);
        assert_eq!(lease.pending_durability(), lease.resources());
    }
    lease.debug_release_locks_keep_journal();
    assert!(matches!(
        &fixture.manager.recover_stale().unwrap()[..],
        [RecoveryOutcome::ExternalConflict { .. }]
    ));
    assert_eq!(fixture.fake.generation(IFACE1).unwrap(), generation);
    fixture
        .manager
        .abandon_journal(&resource_id(IFACE1))
        .unwrap();
}

#[rstest::rstest]
#[case(false)]
#[case(true)]
fn unresolved_overlay_blocks_new_mutation_until_compensated(
    #[case] rebase: bool,
    #[values(false, true)] verification_failure: bool,
) {
    use osdns::testing::FakeOp;
    let fixture = enforce_manager("enforce-overlay-residue");
    let original = fixture.fake.current_state(IFACE1).unwrap().unwrap();
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture.manager.suspend_enforce_background();
    let base = if rebase {
        state_with("9.9.9.9")
    } else {
        original
    };
    fixture.fake.external_change(IFACE1, base.clone()).unwrap();
    if verification_failure {
        fixture
            .fake
            .inject_backend_failure_after(FakeOp::Readback, 2, 1, "verification failed");
    } else {
        fixture.fake.inject_partial_apply_failure(1);
    }
    fixture
        .fake
        .inject_backend_failure(FakeOp::Restore, 2, "compensation unavailable");
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::Failed
    );
    assert_eq!(lease.pending_durability(), lease.resources());
    let record = journal_record_json(&fixture.dir);
    assert_eq!(record["phase"], "Prepared");
    assert!(
        record["applied"].is_null(),
        "newer evidence is still volatile"
    );
    let generation = fixture.fake.generation(IFACE1).unwrap();
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::Failed
    );
    assert_eq!(fixture.fake.generation(IFACE1).unwrap(), generation);
    assert_eq!(lease.pending_durability(), lease.resources());
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::Rebased
    );
    assert_eq!(
        fixture.fake.generation(IFACE1).unwrap(),
        generation.map(|n| n + 2),
        "resolution must compensate and verify before applying a new overlay"
    );
    assert!(lease.pending_durability().is_empty());
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1"))
    );
    lease.restore().unwrap();
    assert_eq!(fixture.fake.current_state(IFACE1).unwrap(), Some(base));
}

#[rstest::rstest]
#[case("restore")]
#[case("drop")]
#[case("abandon")]
#[case("crash")]
fn pending_compensation_respects_terminal_intent_and_external_ownership(
    #[case] finish: &str,
    #[values(false, true)] external: bool,
) {
    use osdns::testing::FakeOp;
    let fixture = enforce_manager("enforce-residue-terminal");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture.manager.suspend_enforce_background();
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    fixture.fake.inject_partial_apply_failure(1);
    fixture
        .fake
        .inject_backend_failure(FakeOp::Restore, 1, "compensation unavailable");
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::Failed
    );
    assert_eq!(lease.pending_durability(), lease.resources());
    if external {
        // Identical DNS content must not authorize compensation of another generation.
        fixture
            .fake
            .external_change(IFACE1, state_with("1.1.1.1"))
            .unwrap();
    }
    let generation = fixture.fake.generation(IFACE1).unwrap();
    match finish {
        "restore" if external => {
            let failure = lease.restore().unwrap_err();
            assert!(failure.error.is_external_modification());
            assert_eq!(
                fixture.manager.debug_reconcile(IFACE1).unwrap(),
                DebugReconcile::NotOwned
            );
            assert!(matches!(
                failure.lease.update(&iface_config(1, "8.8.8.8")),
                Err(osdns::Error::LeaseEnding)
            ));
            assert_eq!(
                failure.lease.pending_durability(),
                failure.lease.resources()
            );
            failure.lease.abandon().unwrap();
        }
        "restore" => lease.restore().unwrap(),
        "drop" => drop(lease),
        "abandon" => lease.abandon().unwrap(),
        "crash" => {
            assert!(journal_record_json(&fixture.dir)["applied"].is_null());
            lease.debug_release_locks_keep_journal();
            assert!(matches!(
                &fixture.manager.recover_stale().unwrap()[..],
                [RecoveryOutcome::ExternalConflict { .. }]
            ));
        }
        _ => unreachable!(),
    }
    if external || matches!(finish, "abandon" | "crash") {
        assert_eq!(fixture.fake.generation(IFACE1).unwrap(), generation);
        assert_eq!(
            fixture.fake.current_state(IFACE1).unwrap(),
            Some(state_with("1.1.1.1"))
        );
    } else {
        assert_eq!(
            fixture.fake.current_state(IFACE1).unwrap(),
            Some(state_with("9.9.9.9"))
        );
    }
    assert!(!fixture.manager.debug_enforce_watching());
    if finish == "crash" || (finish == "drop" && external) {
        assert_eq!(journal_files(&fixture.dir).len(), 1);
        fixture
            .manager
            .abandon_journal(&resource_id(IFACE1))
            .unwrap();
    } else {
        assert!(journal_files(&fixture.dir).is_empty());
    }
}

#[test]
fn pending_compensation_journal_repair_blocks_mutation() {
    use osdns::testing::FakeOp;
    let fixture = enforce_manager("enforce-residue-repair");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture.manager.suspend_enforce_background();
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    fixture.fake.inject_partial_apply_failure(1);
    fixture
        .fake
        .inject_backend_failure(FakeOp::Restore, 2, "compensation unavailable");
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::Failed
    );
    fixture.manager.set_journal_fail_after_io(true);
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::Failed
    );
    let generation = fixture.fake.generation(IFACE1).unwrap();
    let record = journal_record_json(&fixture.dir);
    assert_eq!(record["phase"], "Prepared");
    assert_eq!(record["applied"]["data"]["generation"].as_u64(), generation);
    fixture.manager.set_journal_fail_after_io(false);
    fixture.manager.set_journal_fail_writes(true);
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::Failed
    );
    assert!(lease.update(&iface_config(1, "8.8.8.8")).is_err());
    assert_eq!(fixture.fake.generation(IFACE1).unwrap(), generation);
    assert_eq!(lease.pending_durability(), lease.resources());
    fixture.manager.set_journal_fail_writes(false);
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::Rebased
    );
    lease.restore().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9"))
    );
}

#[test]
fn interrupted_observation_resubscribes_and_rescans_missed_changes() {
    let fixture = enforce_manager("enforce-watch-loss");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture.fake.inject_backend_failure(
        osdns::testing::FakeOp::Watch,
        1,
        "subscription unavailable",
    );
    fixture.fake.fail_watches();
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    wait_until(|| {
        matches!(
            fixture.manager.observation_health(),
            osdns::ObservationHealth::Degraded { .. }
        )
    });
    wait_until(|| {
        fixture.manager.observation_health() == osdns::ObservationHealth::Operational
            && fixture.fake.current_state(IFACE1).unwrap() == Some(state_with("1.1.1.1"))
    });
    lease.restore().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9"))
    );
}

#[rstest::rstest]
#[case(osdns::testing::FakeOp::Identity)]
#[case(osdns::testing::FakeOp::Readback)]
fn repeated_failures_remain_scheduled_and_recover(#[case] operation: osdns::testing::FakeOp) {
    let fixture = enforce_manager("enforce-repeated-error");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture.manager.suspend_enforce_background();
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    fixture
        .fake
        .inject_backend_failure(operation, 12, "temporary failure");
    for _ in 0..12 {
        assert_eq!(
            fixture.manager.debug_reconcile(IFACE1).unwrap(),
            DebugReconcile::Failed
        );
        assert!(fixture.manager.debug_reconcile_pending(IFACE1).unwrap());
    }
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::Rebased
    );
    assert!(!fixture.manager.debug_reconcile_pending(IFACE1).unwrap());
    lease.restore().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9"))
    );
}

#[test]
fn enforce_rebases_and_reapplies_on_external_change() {
    let fixture = enforce_manager("enforce-rebase");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    let _watch = fixture.manager.watch(std::sync::Arc::new(|_| {})).unwrap();

    // Arrives immediately after our apply - inside any suppression window -
    // but state-aware reconciliation must still act on it.
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();

    wait_until(|| fixture.fake.current_state(IFACE1).unwrap() == Some(state_with("1.1.1.1")));

    lease.restore().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9")),
        "restore must return to the rebased external base, not the pre-lease state"
    );
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn cooperative_still_reports_conflicts_without_reconciliation() {
    let fixture = new_fixture("enforce-coop");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let _watch = fixture
        .manager
        .watch(std::sync::Arc::new(move |event| {
            sender.send(event.clone()).unwrap();
        }))
        .unwrap();

    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    receiver.recv_timeout(Duration::from_secs(2)).unwrap();

    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9")),
        "cooperative must never reapply"
    );
    let failure = lease.restore().unwrap_err();
    assert!(failure.error.is_external_modification());
}

#[test]
fn enforce_works_without_user_watch() {
    let fixture = enforce_manager("enforce-nowatch");
    assert!(!fixture.manager.debug_enforce_watching());
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    // Enforce starts its own internal observation: no public watch needed.
    assert!(fixture.manager.debug_enforce_watching());
    assert_eq!(fixture.manager.debug_enforce_refs(), 1);
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    wait_until(|| fixture.fake.current_state(IFACE1).unwrap() == Some(state_with("1.1.1.1")));
    lease.restore().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9")),
        "restore must return to the rebased external base"
    );
    // Last lease ended: internal observation stops cleanly.
    assert!(!fixture.manager.debug_enforce_watching());
    assert_eq!(fixture.manager.debug_enforce_refs(), 0);
}

#[test]
fn public_watch_is_optional_and_does_not_own_enforce() {
    use std::sync::{Arc, Mutex};
    let fixture = enforce_manager("enforce-watch-optional");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    assert!(fixture.manager.debug_enforce_watching());
    wait_until(|| !fixture.manager.debug_reconcile_pending(IFACE1).unwrap());
    let seen: Arc<Mutex<Vec<osdns::DnsEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_clone = Arc::clone(&seen);
    let watch = fixture
        .manager
        .watch(Arc::new(move |event| {
            seen_clone.lock().unwrap().push(event.clone());
        }))
        .unwrap();
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    wait_until(|| fixture.fake.current_state(IFACE1).unwrap() == Some(state_with("1.1.1.1")));
    // Public watch still receives user-facing events for genuine changes.
    wait_until(|| !seen.lock().unwrap().is_empty());
    // Dropping the public watcher must not disable Enforce.
    watch.stop();
    assert!(
        fixture.manager.debug_enforce_watching(),
        "Enforce must survive public watcher teardown while a lease is active"
    );
    fixture
        .fake
        .external_change(IFACE1, state_with("8.8.8.8"))
        .unwrap();
    wait_until(|| fixture.fake.current_state(IFACE1).unwrap() == Some(state_with("1.1.1.1")));
    lease.restore().unwrap();
    assert!(!fixture.manager.debug_enforce_watching());
}

#[test]
fn enforce_fails_honestly_without_watch_capability() {
    use osdns::{BackendKind, Capabilities};
    let dir = temp_dir("enforce-no-watch-cap");
    let caps = Capabilities::new(BackendKind::Fake)
        .with_read(true)
        .with_global_dns(true)
        .with_per_interface_dns(true)
        .with_search_domains(true)
        .with_split_dns(true)
        .with_default_route(true)
        .with_watch(false)
        .with_cache_flush(true);
    let fake = FakeDns::with_capabilities(caps);
    let result = manager_for_testing_with_policy(
        "io.osdns.test",
        &dir,
        &fake,
        Duration::from_secs(30),
        ConflictPolicy::Enforce,
    );
    assert!(
        matches!(result, Err(osdns::Error::Unsupported { .. })),
        "Enforce construction without watch support must fail, not silently downgrade"
    );
}

#[rstest::rstest]
#[case(false)]
#[case(true)]
fn overlay_is_transactional_across_crash(#[case] rebase: bool) {
    let fixture = enforce_manager("enforce-crash");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    // Deterministic: drive reconciliation synchronously without racing the
    // background worker.
    fixture.manager.suspend_enforce_background();

    let injector = FaultInjector::new();
    injector.crash_at(TxPoint::AfterApply);
    fixture.manager.install_fault_injector(injector.clone());

    let base = if rebase {
        state_with("9.9.9.9")
    } else {
        osdns::testing::FakeState::Empty
    };
    fixture.fake.external_change(IFACE1, base.clone()).unwrap();

    // Synchronous reconcile: the crash lands after the overlay was applied
    // but before the `Applied` journal record was persisted. The journal
    // holds `Prepared` with the external base.
    let outcome =
        osdns::testing::catch_crash(|| fixture.manager.debug_reconcile("fake:interface:1"));
    injector.clear();
    assert!(matches!(outcome, CrashOutcome::Crashed));

    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1")),
        "the uncommitted overlay is on the OS"
    );
    let record = journal_record_json(&fixture.dir);
    assert_eq!(record["phase"], "Prepared");
    assert!(record["applied"].is_null());
    if rebase {
        assert_eq!(
            record["before"]["data"]["state"]["Configured"]["nameservers"][0],
            "9.9.9.9"
        );
    } else {
        assert_eq!(record["before"]["data"]["state"], "Empty");
    }

    // Recovery (as a fresh process would do) sees an unverified `Prepared`
    // record whose state merely matches `desired`: that never proves we
    // applied it (an external actor could have produced it), so recovery
    // reports a conflict and mutates nothing instead of rolling back to
    // the external base on unproven ownership. Read-back alone cannot
    // recover the missing backend-issued proof.
    lease.debug_release_locks_keep_journal();
    let outcomes = fixture.manager.recover_stale().unwrap();
    assert_eq!(outcomes.len(), 1, "{outcomes:?}");
    assert!(
        matches!(&outcomes[0], RecoveryOutcome::ExternalConflict { .. }),
        "{outcomes:?}"
    );
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1")),
        "ambiguous rebase state must be left untouched"
    );
    assert_eq!(journal_files(&fixture.dir).len(), 1);
    fixture
        .manager
        .abandon_journal(&resource_id(IFACE1))
        .unwrap();
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn rebase_journal_write_failure_defers_and_preserves_external_state() {
    let fixture = enforce_manager("enforce-journal-fail");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture.manager.suspend_enforce_background();

    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    fixture.manager.set_journal_fail_writes(true);

    let outcome = fixture.manager.debug_reconcile("fake:interface:1").unwrap();
    assert_eq!(outcome, DebugReconcile::Failed);
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9")),
        "a journal failure must leave the external state untouched"
    );

    // The journal on disk still describes the original lease: the failed
    // write must not have replaced the old `before`/`applied` state.
    let record = journal_record_json(&fixture.dir);
    assert_eq!(record["phase"], "Applied");
    assert_eq!(
        record["applied"]["data"]["state"]["Configured"]["nameservers"][0],
        "1.1.1.1"
    );

    fixture.manager.set_journal_fail_writes(false);
    let outcome = fixture.manager.debug_reconcile("fake:interface:1").unwrap();
    assert_eq!(outcome, DebugReconcile::Rebased);
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1"))
    );
    let record = journal_record_json(&fixture.dir);
    assert_eq!(
        record["before"]["data"]["state"]["Configured"]["nameservers"][0],
        "9.9.9.9"
    );
    lease.restore().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9"))
    );
}

#[rstest::rstest]
#[case(false)]
#[case(true)]
fn failed_rebase_rollback_preserves_external_base(#[case] finalize_live: bool) {
    use osdns::testing::FakeOp;
    let fixture = enforce_manager("enforce-rollback-fail");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture.manager.suspend_enforce_background();
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    // Allow both stability reads, then fail verification after apply.
    fixture
        .fake
        .inject_backend_failure_after(FakeOp::Readback, 2, 1, "verification read failed");
    fixture
        .fake
        .inject_backend_failure(FakeOp::Restore, 1, "rollback failed");
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::Failed
    );
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1"))
    );
    let record = journal_record_json(&fixture.dir);
    assert_eq!(record["phase"], "Prepared");
    assert_eq!(
        record["before"]["data"]["state"]["Configured"]["nameservers"][0],
        "9.9.9.9"
    );

    if finalize_live {
        assert_eq!(
            fixture.manager.debug_reconcile(IFACE1).unwrap(),
            DebugReconcile::Rebased
        );
        lease.restore().unwrap();
        assert_eq!(
            fixture.fake.current_state(IFACE1).unwrap(),
            Some(state_with("9.9.9.9")),
            "failed mutations must compensate before reapplying, and restore returns to the external base"
        );
        return;
    } else {
        lease.debug_release_locks_keep_journal();
        drop(fixture.manager);
        let recovered = manager_for_testing(
            "io.osdns.test",
            &fixture.dir,
            &fixture.fake,
            Duration::from_secs(30),
        )
        .unwrap();
        let outcomes = recovered.recover_stale().unwrap();
        assert!(
            matches!(&outcomes[..], [RecoveryOutcome::ExternalConflict { .. }]),
            "{outcomes:?}"
        );
        assert_eq!(
            fixture.fake.current_state(IFACE1).unwrap(),
            Some(state_with("1.1.1.1")),
            "orphaned ambiguous state must be left untouched"
        );
        recovered.abandon_journal(&resource_id(IFACE1)).unwrap();
    }
}

#[test]
fn vanished_enforce_resource_is_terminal_and_never_rebound() {
    let fixture = enforce_manager("enforce-defer");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture.manager.suspend_enforce_background();

    // Interface disappearance ends this incarnation. A later resource at the
    // same selector must not inherit the old lease.
    assert!(fixture.fake.external_remove(IFACE1).unwrap());
    let outcome = fixture.manager.debug_reconcile("fake:interface:1").unwrap();
    assert_eq!(outcome, DebugReconcile::NotOwned);

    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    let outcome = fixture.manager.debug_reconcile("fake:interface:1").unwrap();
    assert_eq!(outcome, DebugReconcile::NotOwned);
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9"))
    );

    lease.restore().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9"))
    );
}

#[test]
fn replacement_during_enforce_reapply_is_not_mutated() {
    let fixture = enforce_manager("enforce-replacement-race");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture.manager.suspend_enforce_background();
    fixture
        .fake
        .external_change(IFACE1, state_with("8.8.8.8"))
        .unwrap();
    fixture
        .fake
        .replace_before_next_apply(IFACE1, state_with("9.9.9.9"))
        .unwrap();

    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::Failed
    );
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9"))
    );
    lease.abandon().unwrap();
}

#[test]
fn ambiguous_identity_remains_owned_and_scheduled_without_mutation() {
    let fixture = enforce_manager("enforce-identity-ambiguous");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture.manager.suspend_enforce_background();
    let generation = fixture.fake.generation(IFACE1).unwrap();
    fixture.fake.set_identity_ambiguous(IFACE1, true).unwrap();

    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::IdentityAmbiguous
    );
    assert!(fixture.manager.debug_reconcile_pending(IFACE1).unwrap());
    assert_eq!(fixture.fake.generation(IFACE1).unwrap(), generation);
    assert!(journal_record_json(&fixture.dir).is_object());

    fixture.fake.set_identity_ambiguous(IFACE1, false).unwrap();
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::StillOurs
    );
    lease.restore().unwrap();
}

#[test]
fn enforce_reconciles_initial_noop_lease() {
    let fixture = enforce_manager("enforce-initial-noop");
    fixture
        .fake
        .external_change(IFACE1, state_with("1.1.1.1"))
        .unwrap();

    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    assert!(lease.is_noop());
    assert_eq!(
        journal_record_json(&fixture.dir)["lease_id"]
            .as_str()
            .unwrap(),
        lease.lease_id().to_string()
    );
    fixture.manager.suspend_enforce_background();

    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::Rebased
    );
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1"))
    );

    lease.restore().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9"))
    );
}

#[test]
fn enforce_observation_balances_noop_lifetime() {
    let fixture = enforce_manager("enforce-noop-refs");
    fixture
        .fake
        .external_change(IFACE1, state_with("1.1.1.1"))
        .unwrap();
    assert_eq!(fixture.manager.debug_enforce_refs(), 0);
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    assert!(lease.is_noop());
    assert_eq!(fixture.manager.debug_enforce_refs(), 1);
    assert!(fixture.manager.debug_enforce_watching());
    lease.restore().unwrap();
    assert_eq!(fixture.manager.debug_enforce_refs(), 0);
    assert!(!fixture.manager.debug_enforce_watching());

    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    assert_eq!(fixture.manager.debug_enforce_refs(), 1);
    lease.abandon().unwrap();
    assert_eq!(fixture.manager.debug_enforce_refs(), 0);
    assert!(!fixture.manager.debug_enforce_watching());
    assert!(journal_files(&fixture.dir).is_empty());
}

#[test]
fn prepared_desired_match_from_external_actor_is_not_ours() {
    let fixture = enforce_manager("enforce-prepared-desired");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture.manager.suspend_enforce_background();
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    fixture
        .fake
        .inject_backend_failure(osdns::testing::FakeOp::Apply, 2, "rebase apply refused");
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::Failed
    );
    assert_eq!(journal_record_json(&fixture.dir)["phase"], "Prepared");
    fixture
        .fake
        .external_change(IFACE1, state_with("1.1.1.1"))
        .unwrap();
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::Deferred
    );
    let record = journal_record_json(&fixture.dir);
    assert_eq!(record["phase"], "Prepared");
    assert!(record["applied"].is_null());
    lease.abandon().unwrap();
}

#[rstest::rstest]
fn verified_mutation_finalizes_only_from_retained_proof(#[values(false, true)] ambiguous: bool) {
    let fixture = enforce_manager("enforce-retained-proof");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture.manager.suspend_enforce_background();
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    fixture.manager.set_journal_fail_writes_after(1);
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::Failed
    );
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("1.1.1.1"))
    );
    let record = journal_record_json(&fixture.dir);
    assert_eq!(record["phase"], "Prepared");
    assert!(record["applied"].is_null());

    let generation = fixture.fake.generation(IFACE1).unwrap();
    if ambiguous {
        fixture.manager.set_journal_fail_writes(false);
        fixture.manager.set_journal_fail_after_io(true);
        assert_eq!(
            fixture.manager.debug_reconcile(IFACE1).unwrap(),
            DebugReconcile::Failed
        );
        assert_eq!(journal_record_json(&fixture.dir)["phase"], "Applied");
        assert_eq!(lease.pending_durability(), lease.resources());
        fixture.manager.set_journal_fail_after_io(false);
        fixture.manager.set_journal_fail_writes(true);
        assert_eq!(
            fixture.manager.debug_reconcile(IFACE1).unwrap(),
            DebugReconcile::Failed
        );
        assert_eq!(fixture.fake.generation(IFACE1).unwrap(), generation);
    }
    fixture.manager.set_journal_fail_writes(false);
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::StillOurs
    );
    let record = journal_record_json(&fixture.dir);
    assert_eq!(record["phase"], "Applied");
    lease.restore().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9"))
    );
}

#[rstest::rstest]
#[case(false)]
#[case(true)]
fn equivalent_rewrite_is_not_still_ours(#[case] after_update: bool) {
    let fixture = enforce_manager("enforce-same-dns-gen");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture.manager.suspend_enforce_background();
    let nameserver = if after_update {
        lease.update(&iface_config(1, "8.8.8.8")).unwrap();
        "8.8.8.8"
    } else {
        "1.1.1.1"
    };
    let ours = fixture.fake.generation(IFACE1).unwrap().unwrap();
    fixture
        .fake
        .external_change(IFACE1, state_with(nameserver))
        .unwrap();
    let external = fixture.fake.generation(IFACE1).unwrap().unwrap();
    assert!(external > ours);
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::Deferred
    );
    assert_eq!(
        journal_record_json(&fixture.dir)["applied"]["data"]["generation"],
        serde_json::json!(ours)
    );
    assert_eq!(fixture.fake.generation(IFACE1).unwrap(), Some(external));
    let failure = lease.restore().unwrap_err();
    assert!(failure.error.is_external_modification());
    assert_eq!(fixture.fake.generation(IFACE1).unwrap(), Some(external));
    failure.lease.abandon().unwrap();
}

#[test]
fn enforce_rescan_sees_change_during_watcher_start() {
    let fixture = enforce_manager("enforce-watch-gap");
    let (watch_started, release) = fixture.fake.block_next_start_watch();
    let manager = fixture.manager.clone();
    let fake = fixture.fake.clone();
    let apply = std::thread::spawn(move || manager.apply(&iface_config(1, "1.1.1.1")));
    watch_started
        .recv_timeout(Duration::from_secs(5))
        .expect("native watcher start");
    fake.external_change(IFACE1, state_with("9.9.9.9")).unwrap();
    release();
    let lease = apply.join().expect("apply thread").unwrap();
    wait_until(|| fixture.fake.current_state(IFACE1).unwrap() == Some(state_with("1.1.1.1")));
    lease.restore().unwrap();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9"))
    );
}

#[test]
fn failed_teardown_does_not_reintroduce_the_desired_overlay() {
    let fixture = enforce_manager("enforce-teardown");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture.manager.set_journal_fail_removes(true);
    let failure = lease.restore().unwrap_err();
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(osdns::testing::FakeState::Empty)
    );
    assert_eq!(
        fixture.manager.observation_health(),
        osdns::ObservationHealth::Idle
    );
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::NotOwned
    );
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(osdns::testing::FakeState::Empty)
    );
    fixture.manager.set_journal_fail_removes(false);
    failure.lease.restore().unwrap();
}

#[rstest::rstest]
#[case(false)]
#[case(true)]
fn ambiguous_rebase_journal_rollback_blocks_mutation_until_repaired(
    #[case] rollback_rejected: bool,
    #[values("enforce", "update", "restore", "drop", "abandon")] finish: &str,
) {
    let fixture = enforce_manager("enforce-ambiguous-journal");
    let lease = fixture.manager.apply(&iface_config(1, "1.1.1.1")).unwrap();
    fixture.manager.suspend_enforce_background();
    fixture
        .fake
        .external_change(IFACE1, state_with("9.9.9.9"))
        .unwrap();
    let before_generation = fixture.fake.generation(IFACE1).unwrap();
    fixture.manager.set_journal_fail_after_io(true);
    if rollback_rejected {
        fixture.manager.set_journal_fail_writes_after(1);
    }
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::Failed
    );
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(state_with("9.9.9.9"))
    );
    assert_eq!(fixture.fake.generation(IFACE1).unwrap(), before_generation);
    let durable = journal_record_json(&fixture.dir);
    if rollback_rejected {
        assert_eq!(
            durable["before"]["data"]["state"]["Configured"]["nameservers"][0],
            "9.9.9.9"
        );
    }
    assert_eq!(
        durable["phase"],
        if rollback_rejected {
            "Prepared"
        } else {
            "Applied"
        }
    );
    assert_eq!(lease.pending_durability(), lease.resources());
    fixture.manager.set_journal_fail_after_io(false);
    fixture.manager.set_journal_fail_writes(true);
    fixture
        .fake
        .external_change(IFACE1, osdns::testing::FakeState::Empty)
        .unwrap();
    let before_retry = fixture.fake.generation(IFACE1).unwrap();
    assert_eq!(
        fixture.manager.debug_reconcile(IFACE1).unwrap(),
        DebugReconcile::Failed
    );
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(osdns::testing::FakeState::Empty)
    );
    assert_eq!(fixture.fake.generation(IFACE1).unwrap(), before_retry);
    for _ in 0..2 {
        let error = lease.update(&iface_config(1, "8.8.8.8")).unwrap_err();
        assert!(matches!(error, osdns::Error::Platform { .. }), "{error:?}");
        assert_eq!(fixture.fake.generation(IFACE1).unwrap(), before_retry);
        assert_eq!(lease.pending_durability(), lease.resources());
    }
    fixture.manager.set_journal_fail_writes(false);
    match finish {
        "restore" => lease.restore().unwrap(),
        "drop" => drop(lease),
        "abandon" => lease.abandon().unwrap(),
        "enforce" | "update" => {
            if finish == "update" {
                assert!(
                    lease
                        .update(&iface_config(1, "8.8.8.8"))
                        .unwrap_err()
                        .is_external_modification()
                );
                assert!(lease.pending_durability().is_empty());
            }
            assert_eq!(
                fixture.manager.debug_reconcile(IFACE1).unwrap(),
                DebugReconcile::Rebased
            );
            assert!(lease.pending_durability().is_empty());
            lease.restore().unwrap();
        }
        _ => unreachable!(),
    }
    assert!(journal_files(&fixture.dir).is_empty());
    assert_eq!(
        fixture.fake.current_state(IFACE1).unwrap(),
        Some(osdns::testing::FakeState::Empty)
    );
}
