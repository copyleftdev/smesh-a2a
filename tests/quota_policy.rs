use smesh_a2a::{
    QuotaAlgorithm, QuotaDimension, QuotaOperation, QuotaPolicy, QuotaReconciliationPlan,
    QuotaReconciliationTarget, QuotaScopeKind, QuotaSubject,
};

fn valid_policy() -> Vec<u8> {
    br#"{
      "schemaVersion":"smesh-quota-policy/v1",
      "policyId":"production-defaults",
      "revision":7,
      "requestWindowMillis":1000,
      "reconnectWindowMillis":60000,
      "limits":{
        "requestCount":{"tenant":200,"account":80,"principal":20},
        "concurrentActiveWork":{"tenant":32,"account":16,"principal":8},
        "inputBytes":{"tenant":67108864,"account":33554432,"principal":16777216},
        "outputBytes":{"tenant":67108864,"account":33554432,"principal":8388608},
        "eventCount":{"tenant":65536,"account":32768,"principal":8192},
        "concurrentStreams":{"tenant":64,"account":16,"principal":4},
        "concurrentSubscriptions":{"tenant":64,"account":16,"principal":4},
        "reconnectCount":{"tenant":120,"account":48,"principal":12},
        "retainedAuthorityBytes":{"tenant":67108864,"account":33554432,"principal":16777216}
      },
      "overrides":[]
    }"#
    .to_vec()
}

#[test]
fn lower_limit_reconciliation_is_digest_bound_typed_and_exact_scope() {
    let old = QuotaPolicy::from_json(&valid_policy()).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&valid_policy()).unwrap();
    value["revision"] = serde_json::json!(8);
    value["limits"]["concurrentStreams"]["principal"] = serde_json::json!(2);
    let new = QuotaPolicy::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(
        new.lowered_limits_from(&old),
        vec![(QuotaScopeKind::Principal, QuotaDimension::ConcurrentStreams)]
    );
    let plan = QuotaReconciliationPlan::drain(
        old.digest(),
        new.digest(),
        "operator-primary",
        "ticket-14 lower stream limit",
        1_700_000_000_000,
        vec![
            QuotaReconciliationTarget::new(
                "tenant-a",
                QuotaScopeKind::Principal,
                QuotaDimension::ConcurrentStreams,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    assert!(plan.authorizes(
        "tenant-a",
        old.digest(),
        new.digest(),
        QuotaScopeKind::Principal,
        QuotaDimension::ConcurrentStreams,
    ));
    assert!(!plan.authorizes(
        "tenant-b",
        old.digest(),
        new.digest(),
        QuotaScopeKind::Principal,
        QuotaDimension::ConcurrentStreams,
    ));
}

#[test]
fn strict_policy_has_closed_types_canonical_digest_and_hard_caps() {
    let policy = QuotaPolicy::from_json(&valid_policy()).expect("strict policy");
    assert_eq!(policy.policy_id(), "production-defaults");
    assert_eq!(policy.revision(), 7);
    assert!(policy.digest().starts_with("sha256:"));
    assert_eq!(policy.digest().len(), 71);
    assert_eq!(QuotaOperation::TaskCreate.as_str(), "taskCreate");
    assert_eq!(QuotaDimension::RequestCount.as_str(), "requestCount");
    assert_eq!(QuotaScopeKind::Principal.as_str(), "principal");
    assert_eq!(QuotaAlgorithm::FixedWindow.as_str(), "fixedWindow");

    let canonical = policy.canonical_json();
    assert_eq!(
        QuotaPolicy::from_json(canonical.as_bytes())
            .unwrap()
            .digest(),
        policy.digest()
    );

    let mut unknown: serde_json::Value = serde_json::from_slice(&valid_policy()).unwrap();
    unknown["callerLimit"] = serde_json::json!(999_999);
    assert!(QuotaPolicy::from_json(&serde_json::to_vec(&unknown).unwrap()).is_err());

    let mut zero: serde_json::Value = serde_json::from_slice(&valid_policy()).unwrap();
    zero["limits"]["requestCount"]["tenant"] = serde_json::json!(0);
    assert!(QuotaPolicy::from_json(&serde_json::to_vec(&zero).unwrap()).is_err());

    let mut fractional: serde_json::Value = serde_json::from_slice(&valid_policy()).unwrap();
    fractional["limits"]["requestCount"]["tenant"] = serde_json::json!(1.5);
    assert!(QuotaPolicy::from_json(&serde_json::to_vec(&fractional).unwrap()).is_err());

    let mut unsafe_cap: serde_json::Value = serde_json::from_slice(&valid_policy()).unwrap();
    unsafe_cap["limits"]["concurrentStreams"]["tenant"] = serde_json::json!(1_000_000);
    assert!(QuotaPolicy::from_json(&serde_json::to_vec(&unsafe_cap).unwrap()).is_err());
}

#[test]
fn audited_static_override_changes_only_named_scope_dimension_and_revision_window() {
    let mut document: serde_json::Value = serde_json::from_slice(&valid_policy()).unwrap();
    document["overrides"] = serde_json::json!([{
        "overrideId":"ops-incident-42","actor":"operator-primary","reason":"ticket-42",
        "scopeKind":"principal","scopeId":"principal-a","operation":"taskCreate",
        "dimension":"concurrentActiveWork","oldLimit":8,"newLimit":2,
        "effectiveAt":1_700_000_000_000_i64,"expiresAt":1_700_000_060_000_i64
    }]);
    let policy = QuotaPolicy::from_json(&serde_json::to_vec(&document).unwrap()).unwrap();
    assert_eq!(
        policy.limit_at(
            QuotaScopeKind::Principal,
            "principal-a",
            QuotaOperation::TaskCreate,
            QuotaDimension::ConcurrentActiveWork,
            1_700_000_000_000,
        ),
        2
    );
    assert_eq!(
        policy.limit_at(
            QuotaScopeKind::Principal,
            "principal-b",
            QuotaOperation::TaskCreate,
            QuotaDimension::ConcurrentActiveWork,
            1_700_000_000_000,
        ),
        8
    );
    assert_eq!(
        policy.limit_at(
            QuotaScopeKind::Principal,
            "principal-a",
            QuotaOperation::TaskCreate,
            QuotaDimension::RequestCount,
            1_700_000_000_000,
        ),
        20
    );
    assert_eq!(
        policy.limit_at(
            QuotaScopeKind::Principal,
            "principal-a",
            QuotaOperation::TaskCreate,
            QuotaDimension::ConcurrentActiveWork,
            1_700_006_000_000,
        ),
        8
    );
}

#[test]
fn policy_rejects_missing_account_limits_and_invalid_or_overlapping_overrides() {
    let mut missing: serde_json::Value = serde_json::from_slice(&valid_policy()).unwrap();
    missing["limits"]["requestCount"]
        .as_object_mut()
        .unwrap()
        .remove("account");
    assert!(QuotaPolicy::from_json(&serde_json::to_vec(&missing).unwrap()).is_err());

    for (field, value) in [
        ("oldLimit", serde_json::json!(79)),
        ("newLimit", serde_json::json!(1_000_001)),
        ("actor", serde_json::json!("operator\nprimary")),
        ("reason", serde_json::json!("ticket\t42")),
    ] {
        let mut invalid: serde_json::Value = serde_json::from_slice(&valid_policy()).unwrap();
        let mut override_value = serde_json::json!({
            "overrideId":"ops-1","actor":"operator-primary","reason":"ticket-42",
            "scopeKind":"account","scopeId":"account-a","operation":"taskCreate",
            "dimension":"requestCount","oldLimit":80,"newLimit":40,
            "effectiveAt":1000,"expiresAt":2000
        });
        override_value[field] = value;
        invalid["overrides"] = serde_json::json!([override_value]);
        assert!(
            QuotaPolicy::from_json(&serde_json::to_vec(&invalid).unwrap()).is_err(),
            "{field}"
        );
    }

    let mut overlapping: serde_json::Value = serde_json::from_slice(&valid_policy()).unwrap();
    overlapping["overrides"] = serde_json::json!([
      {"overrideId":"ops-1","actor":"operator-primary","reason":"ticket-42","scopeKind":"account","scopeId":"account-a","operation":"taskCreate","dimension":"requestCount","oldLimit":80,"newLimit":40,"effectiveAt":1000,"expiresAt":2000},
      {"overrideId":"ops-2","actor":"operator-primary","reason":"ticket-43","scopeKind":"account","scopeId":"account-a","operation":"taskCreate","dimension":"requestCount","oldLimit":80,"newLimit":30,"effectiveAt":1500,"expiresAt":2500}
    ]);
    assert!(QuotaPolicy::from_json(&serde_json::to_vec(&overlapping).unwrap()).is_err());
    overlapping["overrides"][1]["scopeId"] = serde_json::json!("account-b");
    assert!(QuotaPolicy::from_json(&serde_json::to_vec(&overlapping).unwrap()).is_ok());
}

#[test]
fn every_intent_charges_tenant_account_principal_in_canonical_order() {
    let policy = QuotaPolicy::from_json(&valid_policy()).unwrap();
    let subject = QuotaSubject::new("tenant-a", "account-a", "principal-a").unwrap();
    for intent in [
        policy
            .operation_intent(&subject, QuotaOperation::TaskList, "list", 0)
            .unwrap(),
        policy.egress_intent(&subject, "egress", 17, 1).unwrap(),
        policy
            .lease_intent(
                &subject,
                smesh_a2a::QuotaLeaseKind::TaskSubscription,
                "sub",
                false,
            )
            .unwrap(),
    ] {
        let scopes: Vec<_> = intent
            .charges()
            .iter()
            .map(smesh_a2a::QuotaCharge::scope_kind)
            .collect();
        assert!(scopes.contains(&QuotaScopeKind::Tenant));
        assert!(scopes.contains(&QuotaScopeKind::Account));
        assert!(scopes.contains(&QuotaScopeKind::Principal));
        assert!(scopes.windows(2).all(|pair| pair[0] <= pair[1]));
    }
}

#[test]
fn quota_exceeded_retry_after_is_bounded_and_stable_on_the_wire() {
    for (requested, expected) in [(0, 1), (17, 17), (9_999, 3_600)] {
        let exceeded = smesh_a2a::QuotaExceeded::new(requested);
        assert_eq!(u64::from(exceeded.retry_after_seconds()), expected);
        let error = exceeded.into_a2a_error();
        assert_eq!(error.code, -32_010);
        assert_eq!(error.http_status_code(), 429);
        let json = error.to_jsonrpc_error();
        assert_eq!(json.code, -32_010);
        let encoded = json.data.unwrap();
        assert!(
            encoded
                .as_array()
                .unwrap()
                .iter()
                .any(|detail| detail["retryAfterSeconds"] == expected)
        );
    }
}

#[test]
fn egress_intent_charges_canonical_bytes_and_events_at_all_scopes() {
    let policy = QuotaPolicy::from_json(&valid_policy()).unwrap();
    let subject = QuotaSubject::new("tenant-a", "account-a", "principal-a").unwrap();
    let intent = policy
        .egress_intent(&subject, "public-frame-1", 17, 1)
        .unwrap();
    assert_eq!(intent.operation(), QuotaOperation::PublicEgress);
    assert_eq!(
        intent
            .charges()
            .iter()
            .filter(|charge| charge.dimension() == QuotaDimension::OutputBytes)
            .count(),
        3
    );
    assert_eq!(
        intent
            .charges()
            .iter()
            .filter(|charge| charge.dimension() == QuotaDimension::EventCount)
            .count(),
        3
    );
}

#[test]
fn execution_admission_reserves_output_and_event_maxima_at_all_scopes() {
    let policy = QuotaPolicy::from_json(&valid_policy()).unwrap();
    let subject = QuotaSubject::new("tenant-a", "account-a", "principal-a").unwrap();
    let intent = policy
        .admission_intent(&subject, "execution-message", 17, false)
        .unwrap();

    assert_eq!(
        intent
            .charges()
            .iter()
            .filter(|charge| charge.dimension() == QuotaDimension::OutputBytes)
            .count(),
        3,
        "execution output must be reserved before dispatch"
    );
    assert_eq!(
        intent
            .charges()
            .iter()
            .filter(|charge| charge.dimension() == QuotaDimension::EventCount)
            .count(),
        3,
        "execution event capacity must be reserved before dispatch"
    );
}

#[test]
fn continuation_intent_is_bound_to_continuation_without_new_active_work() {
    let policy = QuotaPolicy::from_json(&valid_policy()).unwrap();
    let subject = QuotaSubject::new("tenant-a", "account-a", "principal-a").unwrap();
    let intent = policy
        .operation_intent(
            &subject,
            QuotaOperation::TaskContinue,
            "continuation-message",
            17,
        )
        .unwrap();

    assert_eq!(intent.operation(), QuotaOperation::TaskContinue);
    assert_eq!(
        intent
            .charges()
            .iter()
            .filter(|charge| charge.dimension() == QuotaDimension::RequestCount)
            .count(),
        3
    );
    assert_eq!(
        intent
            .charges()
            .iter()
            .filter(|charge| charge.dimension() == QuotaDimension::InputBytes)
            .count(),
        3
    );
    assert!(
        intent
            .charges()
            .iter()
            .all(|charge| charge.dimension() != QuotaDimension::ConcurrentActiveWork)
    );
}
