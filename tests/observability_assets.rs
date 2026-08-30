use std::collections::BTreeSet;
use std::path::PathBuf;

#[test]
fn objectives_rules_dashboard_and_runbook_are_checked_in_and_consistent() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let objectives: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("observability/objectives.json")).unwrap())
            .unwrap();
    assert_eq!(objectives["classification"], "bootstrap-not-universal");
    assert!(objectives["reviewAfterDays"].as_u64().unwrap() <= 30);
    let rules = std::fs::read_to_string(root.join("observability/prometheus-rules.yml")).unwrap();
    assert!(rules.contains("SmeshA2AEdgeAvailability"));
    assert!(rules.contains("smesh_a2a_sli_event_total"));
    for unsupported in [
        "duplicate_effect",
        "stale_fence",
        "seal_failure",
        "smesh_a2a_durable_driver_up",
        "smesh_a2a_postgres_pool_in_use",
    ] {
        assert!(!rules.contains(unsupported));
    }
    assert!(rules.contains("smesh_a2a_audit_projection_failure_total"));
    assert!(rules.contains("smesh_a2a_audit_projection_lag_seconds"));
    assert!(rules.contains("smesh_result=\"eligible_bad\""));
    assert!(rules.contains("smesh_result=~\"eligible_good|eligible_bad\""));
    assert!(!rules.contains("smesh_result=\"bad\""));

    let dashboard: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("observability/grafana/smesh-a2a-overview.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(dashboard["schemaVersion"].as_u64().unwrap(), 39);
    let titles: BTreeSet<_> = dashboard["panels"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|panel| panel["title"].as_str())
        .collect();
    assert_eq!(
        titles,
        BTreeSet::from(["Edge availability", "Edge requests", "Audit projection"])
    );
    let runbook = std::fs::read_to_string(root.join("docs/OBSERVABILITY_RUNBOOK.md")).unwrap();
    assert!(runbook.contains("missing telemetry is not evidence of zero errors"));
    assert!(runbook.contains("#18"));
}
