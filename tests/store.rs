use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use a2a::{A2AError, ListTasksRequest, Task, TaskState, TaskStatus};
use a2a_server::TaskStore;
use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use smesh_a2a::BoundedTaskStore;

fn task(id: &str) -> Task {
    Task {
        id: id.into(),
        context_id: "context".into(),
        status: TaskStatus {
            state: TaskState::Submitted,
            message: None,
            timestamp: Some(chrono::Utc::now()),
        },
        artifacts: None,
        history: None,
        metadata: None,
    }
}

#[tokio::test]
async fn snapshot_expiry_uses_injected_monotonic_time_at_exact_boundary() {
    let now = Arc::new(AtomicU64::new(7));
    let clock = {
        let now = Arc::clone(&now);
        Arc::new(move || now.load(Ordering::SeqCst))
    };
    let store = BoundedTaskStore::new_with_clock(4, clock);
    for id in ["a", "b"] {
        store.create(task(id)).await.unwrap();
    }
    let request = ListTasksRequest {
        context_id: None,
        status: None,
        page_size: Some(1),
        page_token: None,
        history_length: None,
        status_timestamp_after: None,
        include_artifacts: Some(false),
        tenant: None,
    };
    let first = store.list(&request).await.unwrap();
    now.store(300_006, Ordering::SeqCst);
    assert!(
        store
            .list(&ListTasksRequest {
                page_token: Some(first.next_page_token.clone()),
                ..request.clone()
            })
            .await
            .is_ok()
    );
    now.store(0, Ordering::SeqCst);
    assert!(
        store
            .list(&ListTasksRequest {
                page_token: Some(first.next_page_token.clone()),
                ..request.clone()
            })
            .await
            .is_ok(),
        "clock rollback moved the observed monotonic deadline backward"
    );
    now.store(300_007, Ordering::SeqCst);
    assert!(
        store
            .list(&ListTasksRequest {
                page_token: Some(first.next_page_token),
                ..request
            })
            .await
            .is_err()
    );
}

#[tokio::test]
async fn page_size_one_snapshot_registry_byte_bound_recovers_after_expiry() {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let now = Arc::new(AtomicU64::new(0));
        let clock = {
            let now = Arc::clone(&now);
            Arc::new(move || now.load(Ordering::SeqCst))
        };
        let store = BoundedTaskStore::new_with_clock(8, clock);
        let payload = "雪".repeat(330_000);
        for id in ["a", "b", "c", "d"] {
            let mut value = task(id);
            value.metadata =
                Some(serde_json::from_value(serde_json::json!({"payload": payload})).unwrap());
            store.create(value).await.unwrap();
        }
        let request = ListTasksRequest {
            context_id: None,
            status: None,
            page_size: Some(1),
            page_token: None,
            history_length: None,
            status_timestamp_after: None,
            include_artifacts: Some(false),
            tenant: None,
        };
        let retry_token = store.list(&request).await.unwrap().next_page_token;
        for _ in 0..256 {
            assert_eq!(
                store.list(&request).await.unwrap().next_page_token,
                retry_token,
                "identical first-page retries must reuse one frozen snapshot"
            );
        }
        let mut admitted = 0;
        while admitted < 128 {
            let distinct = ListTasksRequest {
                history_length: Some(admitted % 101),
                include_artifacts: Some(admitted >= 101),
                ..request.clone()
            };
            if store.list(&distinct).await.is_err() {
                break;
            }
            admitted += 1;
        }
        assert!(
            admitted > 0 && admitted < 128,
            "registry byte bound was not enforced"
        );
        now.store(300_000, Ordering::SeqCst);
        assert!(
            store.list(&request).await.is_ok(),
            "expired registry bytes were not reclaimed"
        );
    })
    .await
    .expect("in-memory snapshot capacity watchdog expired");
}

#[tokio::test]
async fn deeply_nested_values_are_charged_as_frozen_canonical_bytes() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let store = BoundedTaskStore::new(2);
        let nested = vec![serde_json::Value::from(0); 200_000];
        for id in ["nested-a", "nested-b"] {
            let mut value = task(id);
            value.metadata =
                Some(serde_json::from_value(serde_json::json!({"millionZeros": nested})).unwrap());
            store.create(value).await.unwrap();
        }
        let request = ListTasksRequest {
            context_id: None,
            status: None,
            page_size: Some(1),
            page_token: None,
            history_length: None,
            status_timestamp_after: None,
            include_artifacts: Some(false),
            tenant: None,
        };
        let mut admitted = 0;
        while admitted < 128 {
            let distinct = ListTasksRequest {
                history_length: Some(admitted % 101),
                include_artifacts: Some(admitted >= 101),
                ..request.clone()
            };
            if store.list(&distinct).await.is_err() {
                break;
            }
            admitted += 1;
        }
        assert!(
            admitted > 4,
            "nested Value heap was retained instead of canonical bytes"
        );
        assert!(
            admitted < 128,
            "64 MiB canonical-byte bound was not enforced"
        );
    })
    .await
    .expect("million-zero snapshot regression watchdog expired");
}

#[tokio::test]
async fn store_rejects_new_tasks_at_capacity_without_losing_existing_tasks() {
    let store = BoundedTaskStore::new(1);
    store.create(task("one")).await.unwrap();

    let error: A2AError = store.create(task("two")).await.unwrap_err();

    assert!(error.message.contains("capacity"));
    assert!(store.get("one").await.unwrap().is_some());
    assert!(store.get("two").await.unwrap().is_none());
}

#[tokio::test]
async fn store_never_allows_a_terminal_task_to_regress() {
    let store = BoundedTaskStore::new(2);
    let mut completed = task("terminal");
    completed.status.state = TaskState::Completed;
    store.create(completed.clone()).await.unwrap();

    let mut stale = completed;
    stale.status.state = TaskState::Working;
    let error = store.update(stale).await.unwrap_err();

    assert_eq!(
        store.get("terminal").await.unwrap().unwrap().status.state,
        TaskState::Completed
    );
    assert!(error.message.contains("terminal"));
}

#[tokio::test]
async fn store_only_accepts_exact_terminal_idempotence() {
    let store = BoundedTaskStore::new(2);
    let mut completed = task("terminal-idempotent");
    completed.status.state = TaskState::Completed;
    store.create(completed.clone()).await.unwrap();
    assert!(store.update(completed.clone()).await.is_ok());

    completed.metadata =
        Some(serde_json::from_value(serde_json::json!({"different": true})).unwrap());
    assert!(store.update(completed).await.is_err());
    assert!(
        store
            .get("terminal-idempotent")
            .await
            .unwrap()
            .unwrap()
            .metadata
            .is_none()
    );
}

#[tokio::test]
async fn pagination_freezes_membership_total_order_and_projection() {
    let store = BoundedTaskStore::new(8);
    for (id, second) in [("雪-a", 3), ("雪-b", 2), ("雪-c", 1)] {
        let mut value = task(id);
        value.status.state = TaskState::Working;
        value.status.timestamp = Some(
            chrono::DateTime::parse_from_rfc3339(&format!("2026-01-01T00:00:0{second}Z"))
                .unwrap()
                .to_utc(),
        );
        value.metadata =
            Some(serde_json::from_value(serde_json::json!({"revision": "snapshot"})).unwrap());
        store.create(value).await.unwrap();
    }
    let request = ListTasksRequest {
        context_id: None,
        status: Some(TaskState::Working),
        page_size: Some(1),
        page_token: None,
        history_length: Some(0),
        status_timestamp_after: None,
        include_artifacts: Some(false),
        tenant: None,
    };
    let first = store.list(&request).await.unwrap();
    assert_eq!(first.tasks[0].id, "雪-a");

    let mut changed = store.get("雪-b").await.unwrap().unwrap();
    changed.status.state = TaskState::Completed;
    changed.status.timestamp = Some(
        chrono::DateTime::parse_from_rfc3339("2026-01-02T00:00:00Z")
            .unwrap()
            .to_utc(),
    );
    changed.metadata =
        Some(serde_json::from_value(serde_json::json!({"revision": "changed"})).unwrap());
    store.update(changed).await.unwrap();
    let mut inserted = task("雪-new");
    inserted.status.state = TaskState::Working;
    store.create(inserted).await.unwrap();

    let second_request = ListTasksRequest {
        page_token: Some(first.next_page_token.clone()),
        ..request.clone()
    };
    let second = store.list(&second_request).await.unwrap();
    let replay = store.list(&second_request).await.unwrap();
    assert_eq!(second, replay, "page-token replay must be deterministic");
    assert_eq!(second.total_size, 3);
    assert_eq!(second.tasks[0].id, "雪-b");
    assert_eq!(second.tasks[0].status.state, TaskState::Working);
    assert_eq!(
        second.tasks[0].metadata.as_ref().unwrap().get("revision"),
        Some(&serde_json::json!("snapshot"))
    );
    let third = store
        .list(&ListTasksRequest {
            page_token: Some(second.next_page_token),
            ..request
        })
        .await
        .unwrap();
    assert_eq!(third.total_size, 3);
    assert_eq!(third.tasks[0].id, "雪-c");
    assert!(third.next_page_token.is_empty());
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // The complete concurrent fixture remains explicit as its oracle.
async fn concurrent_first_and_later_page_mutations_match_explicit_order_oracle() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let store = BoundedTaskStore::new(16);
        for (id, timestamp) in [
            ("a", Some("2026-01-01T00:00:02Z")),
            ("雪", Some("2026-01-01T00:00:02Z")),
            ("c", Some("2026-01-01T00:00:01Z")),
            ("null", None),
        ] {
            let mut value = task(id);
            value.status.state = TaskState::Working;
            value.status.timestamp = timestamp.map(|value| {
                chrono::DateTime::parse_from_rfc3339(value)
                    .unwrap()
                    .to_utc()
            });
            store.create(value).await.unwrap();
        }
        let request = ListTasksRequest {
            context_id: Some("context".to_owned()),
            status: Some(TaskState::Working),
            page_size: Some(1),
            page_token: None,
            history_length: Some(0),
            status_timestamp_after: Some(
                chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:01Z")
                    .unwrap()
                    .to_utc(),
            ),
            include_artifacts: Some(false),
            tenant: None,
        };
        let start = Arc::new(tokio::sync::Barrier::new(2));
        let listing = {
            let store = store.clone();
            let request = request.clone();
            let start = Arc::clone(&start);
            tokio::spawn(async move {
                start.wait().await;
                store.list(&request).await
            })
        };
        let insertion = {
            let store = store.clone();
            let start = Arc::clone(&start);
            tokio::spawn(async move {
                let mut value = task("é-new");
                value.status.state = TaskState::Working;
                value.status.timestamp = Some(
                    chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:03Z")
                        .unwrap()
                        .to_utc(),
                );
                start.wait().await;
                store.create(value).await
            })
        };
        let first = listing.await.unwrap().unwrap();
        insertion.await.unwrap().unwrap();
        let expected: &[&str] = if first.tasks[0].id == "é-new" {
            &["é-new", "a", "雪", "c"]
        } else {
            &["a", "雪", "c"]
        };
        let mut ids = vec![first.tasks[0].id.clone()];
        let mut token = first.next_page_token;
        let later = Arc::new(tokio::sync::Barrier::new(2));
        let page = {
            let store = store.clone();
            let later = Arc::clone(&later);
            let request = ListTasksRequest {
                page_token: Some(token),
                ..request.clone()
            };
            tokio::spawn(async move {
                later.wait().await;
                store.list(&request).await
            })
        };
        let mutation = {
            let store = store.clone();
            let later = Arc::clone(&later);
            tokio::spawn(async move {
                later.wait().await;
                let mut changed = store.get("c").await.unwrap().unwrap();
                changed.status.state = TaskState::Completed;
                store.update(changed).await
            })
        };
        let second = page.await.unwrap().unwrap();
        mutation.await.unwrap().unwrap();
        ids.extend(second.tasks.into_iter().map(|task| task.id));
        token = second.next_page_token;
        while !token.is_empty() {
            let page = store
                .list(&ListTasksRequest {
                    page_token: Some(token),
                    ..request.clone()
                })
                .await
                .unwrap();
            ids.extend(page.tasks.into_iter().map(|task| task.id));
            token = page.next_page_token;
        }
        assert_eq!(ids, expected);
    })
    .await
    .expect("concurrent pagination watchdog expired");
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 24,
        rng_seed: RngSeed::Fixed(0x5A17_0010),
        ..ProptestConfig::default()
    })]

    #[test]
    fn frozen_pagination_matches_reference_under_mutation(
        count in 1_usize..13,
        page_size in 1_i32..6,
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async move {
            let store = BoundedTaskStore::new(64);
            let mut expected = Vec::new();
            for index in 0..count {
                let id = format!("任务-{index:02}-雪");
                let mut value = task(&id);
                value.status.state = TaskState::Working;
                value.status.timestamp = (index % 4 != 0).then(|| {
                    chrono::DateTime::parse_from_rfc3339(&format!(
                        "2026-01-01T00:00:0{}Z", index % 3
                    ))
                    .unwrap()
                    .to_utc()
                });
                value.metadata = Some(
                    serde_json::from_value(serde_json::json!({"frozen": index})).unwrap(),
                );
                expected.push(value.clone());
                store.create(value).await.unwrap();
            }
            expected.sort_by(|left, right| {
                right.status.timestamp.cmp(&left.status.timestamp)
                    .then_with(|| left.id.cmp(&right.id))
            });
            let base = ListTasksRequest {
                context_id: None,
                status: Some(TaskState::Working),
                page_size: Some(page_size),
                page_token: None,
                history_length: None,
                status_timestamp_after: None,
                include_artifacts: Some(true),
                tenant: None,
            };
            let mut token = None;
            let mut actual = Vec::new();
            let mut page_number = 0_usize;
            loop {
                let page = store.list(&ListTasksRequest {
                    page_token: token.clone(),
                    ..base.clone()
                }).await.unwrap();
                prop_assert_eq!(usize::try_from(page.total_size).unwrap(), expected.len());
                actual.extend(page.tasks);
                page_number += 1;
                prop_assert!(page_number <= count.div_ceil(usize::try_from(page_size).unwrap()) + 1);
                if page.next_page_token.is_empty() {
                    break;
                }
                let unseen = &expected[actual.len().min(expected.len() - 1)].id;
                let mut changed = store.get(unseen).await.unwrap().unwrap();
                changed.status.state = TaskState::Completed;
                changed.status.timestamp = Some(chrono::Utc::now());
                store.update(changed).await.unwrap();
                let mut inserted = task(&format!("post-snapshot-{page_number}"));
                inserted.status.state = TaskState::Working;
                store.create(inserted).await.unwrap();
                token = Some(page.next_page_token);
            }
            prop_assert_eq!(actual, expected);
            Ok(())
        })?;
    }
}
