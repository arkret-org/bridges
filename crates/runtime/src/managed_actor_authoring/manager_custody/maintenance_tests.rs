use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

#[tokio::test]
async fn host_stop_aborts_shared_maintenance_without_waiting_for_last_reference() {
    let started = Arc::new(tokio::sync::Notify::new());
    let completed = Arc::new(AtomicUsize::new(0));
    let (release, pending) = tokio::sync::oneshot::channel::<()>();
    let task_started = started.clone();
    let task_completed = completed.clone();
    let task = tokio::spawn(async move {
        task_started.notify_one();
        if pending.await.is_ok() {
            task_completed.fetch_add(1, Ordering::SeqCst);
        }
    });
    let host_guard = Arc::new(ManagerArchiveMaintenance { task });
    let retained_router_guard = host_guard.clone();
    started.notified().await;
    assert_eq!(Arc::strong_count(&host_guard), 2);
    host_guard.stop();
    host_guard.stop();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !retained_router_guard.task.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the host stop must terminate the actual task while both guards remain alive");
    assert_eq!(Arc::strong_count(&host_guard), 2);
    assert!(release.send(()).is_err());
    assert_eq!(completed.load(Ordering::SeqCst), 0);
    drop(host_guard);
    assert!(retained_router_guard.task.is_finished());
}

#[test]
fn archive_wrapping_key_preflight_rejects_invalid_or_daily_service_key_material() {
    let edge = super::super::ghost_bundle_tests::edge(Arc::new(
        super::super::ghost_bundle_tests::RecordingAuthoringStore::default(),
    ));
    for length in [0, 31, 33] {
        assert!(
            ManagedActorManagerService::validate_archive_wrapping_key(
                &edge,
                &arkret::KeyBytes::new(vec![0x44; length]),
            )
            .is_err()
        );
    }
    for forbidden in [0x22, 0x33] {
        assert!(
            ManagedActorManagerService::validate_archive_wrapping_key(
                &edge,
                &arkret::KeyBytes::new(vec![forbidden; 32]),
            )
            .is_err()
        );
    }
    assert!(
        ManagedActorManagerService::validate_archive_wrapping_key(
            &edge,
            &arkret::KeyBytes::new(vec![0x44; 32]),
        )
        .is_ok()
    );
}
