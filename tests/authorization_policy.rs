use smesh_a2a::auth::{Principal, PrincipalLimits};
use smesh_a2a::{AuthorizationPolicy, Operation, VisibilityScope};

fn complete_matrix_policy() -> AuthorizationPolicy {
    AuthorizationPolicy::from_json(
        br#"{
          "schemaVersion":"smesh-authz-policy/v1",
          "policyId":"complete-matrix",
          "revision":13,
          "tenants":[{"id":"tenant-a","enabled":true},{"id":"tenant-b","enabled":true}],
          "accounts":[
            {"id":"admin","kind":"human","memberships":[{"tenantId":"tenant-a","roles":["tenantAdmin"]}]},
            {"id":"operator","kind":"human","memberships":[{"tenantId":"tenant-a","roles":["taskOperator"]}]},
            {"id":"viewer","kind":"human","memberships":[{"tenantId":"tenant-a","roles":["taskViewer"]}]},
            {"id":"auditor","kind":"human","memberships":[{"tenantId":"tenant-a","roles":["auditor"]}]},
            {"id":"agent","kind":"serviceAccount","memberships":[{"tenantId":"tenant-a","roles":["taskAgent"]}]},
            {"id":"reader","kind":"serviceAccount","memberships":[{"tenantId":"tenant-a","roles":["serviceReader"]}]},
            {"id":"multi","kind":"human","memberships":[{"tenantId":"tenant-a","roles":["taskViewer"]},{"tenantId":"tenant-b","roles":["taskViewer"]}]}
          ],
          "principalBindings":[
            {"principal":{"issuer":"https://issuer.example","subject":"admin"},"accountId":"admin"},
            {"principal":{"issuer":"https://issuer.example","subject":"operator"},"accountId":"operator"},
            {"principal":{"issuer":"https://issuer.example","subject":"viewer"},"accountId":"viewer"},
            {"principal":{"issuer":"https://issuer.example","subject":"auditor"},"accountId":"auditor"},
            {"principal":{"issuer":"https://issuer.example","subject":"agent"},"accountId":"agent"},
            {"principal":{"issuer":"https://issuer.example","subject":"reader"},"accountId":"reader"},
            {"principal":{"issuer":"https://issuer.example","subject":"multi"},"accountId":"multi"}
          ]
        }"#,
    )
    .unwrap()
}

#[test]
#[allow(clippy::too_many_lines)]
fn every_role_and_operation_has_an_explicit_fixed_grant_or_deny() {
    use Operation::{
        ArtifactRead, AuditRead, AuthorizationAdmin, ExtendedCard, HistoryRead, PushCreate,
        PushDelete, PushGet, PushList, TaskCancel, TaskContinue, TaskCreate, TaskGet, TaskList,
        TaskSubscribe,
    };

    let policy = complete_matrix_policy();
    let all_operations = [
        TaskCreate,
        TaskContinue,
        TaskGet,
        TaskList,
        TaskSubscribe,
        TaskCancel,
        HistoryRead,
        ArtifactRead,
        AuditRead,
        AuthorizationAdmin,
        PushCreate,
        PushGet,
        PushList,
        PushDelete,
        ExtendedCard,
    ];
    let cases: [(&str, VisibilityScope, &[Operation]); 6] = [
        (
            "admin",
            VisibilityScope::Tenant,
            &[
                TaskCreate,
                TaskContinue,
                TaskGet,
                TaskList,
                TaskSubscribe,
                TaskCancel,
                HistoryRead,
                ArtifactRead,
                AuditRead,
                AuthorizationAdmin,
                ExtendedCard,
            ],
        ),
        (
            "operator",
            VisibilityScope::Tenant,
            &[
                TaskCreate,
                TaskContinue,
                TaskGet,
                TaskList,
                TaskSubscribe,
                TaskCancel,
                HistoryRead,
                ArtifactRead,
                ExtendedCard,
            ],
        ),
        (
            "viewer",
            VisibilityScope::Tenant,
            &[
                TaskGet,
                TaskList,
                TaskSubscribe,
                HistoryRead,
                ArtifactRead,
                ExtendedCard,
            ],
        ),
        (
            "auditor",
            VisibilityScope::Tenant,
            &[
                TaskGet,
                TaskList,
                HistoryRead,
                ArtifactRead,
                AuditRead,
                ExtendedCard,
            ],
        ),
        (
            "agent",
            VisibilityScope::Own,
            &[
                TaskCreate,
                TaskContinue,
                TaskGet,
                TaskList,
                TaskSubscribe,
                TaskCancel,
                HistoryRead,
                ArtifactRead,
                ExtendedCard,
            ],
        ),
        (
            "reader",
            VisibilityScope::Tenant,
            &[
                TaskGet,
                TaskList,
                TaskSubscribe,
                HistoryRead,
                ArtifactRead,
                ExtendedCard,
            ],
        ),
    ];

    for (subject, task_scope, grants) in cases {
        let principal = Principal::bearer_for_verifier(
            "https://issuer.example".into(),
            subject.into(),
            PrincipalLimits::default(),
        )
        .unwrap();
        let context = policy.resolve(&principal, None).unwrap();
        for operation in all_operations {
            let expected = grants
                .contains(&operation)
                .then_some(if operation == ExtendedCard {
                    VisibilityScope::Tenant
                } else {
                    task_scope
                });
            assert_eq!(
                context.visibility(operation).ok(),
                expected,
                "fixed matrix mismatch for {subject:?} / {operation:?}"
            );
        }
    }

    let multi = Principal::bearer_for_verifier(
        "https://issuer.example".into(),
        "multi".into(),
        PrincipalLimits::default(),
    )
    .unwrap();
    assert!(policy.resolve(&multi, None).is_err());
    assert_eq!(
        policy
            .resolve(&multi, Some("tenant-b"))
            .unwrap()
            .tenant_id(),
        "tenant-b"
    );
    let unenrolled = Principal::bearer_for_verifier(
        "https://issuer.example".into(),
        "unenrolled".into(),
        PrincipalLimits::default(),
    )
    .unwrap();
    assert!(policy.resolve(&unenrolled, Some("tenant-a")).is_err());
}

#[tokio::test]
async fn authorization_middleware_strips_selector_and_rejects_ambiguous_or_duplicate_selection() {
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        middleware,
        routing::get,
    };
    use http_body_util::BodyExt as _;
    use smesh_a2a::authorization::{
        AuthorizationMiddlewareState, authorize_request, current_authorization_context,
    };
    use std::sync::Arc;
    use tower::ServiceExt as _;

    async fn endpoint(request: Request<Body>) -> String {
        assert!(request.headers().get("x-smesh-tenant").is_none());
        let context = current_authorization_context().expect("context");
        format!("{}:{}", context.account_id(), context.tenant_id())
    }
    let principal = Arc::new(
        Principal::bearer_for_verifier(
            "https://issuer.example".into(),
            "operator".into(),
            PrincipalLimits::default(),
        )
        .unwrap(),
    );
    let policy = Arc::new(AuthorizationPolicy::from_json(&policy_json()).unwrap());
    let state = AuthorizationMiddlewareState::without_audit(policy);
    let app = Router::new()
        .route("/", get(endpoint))
        .layer(middleware::from_fn_with_state(state, authorize_request))
        .layer(axum::Extension(principal));

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header("x-smesh-tenant", "tenant-b")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "operator:tenant-b"
    );
    let ambiguous = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(ambiguous.status(), StatusCode::FORBIDDEN);
    let duplicate = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header("x-smesh-tenant", "tenant-a")
                .header("x-smesh-tenant", "tenant-b")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(duplicate.status(), StatusCode::FORBIDDEN);
}

fn policy_json() -> Vec<u8> {
    br#"{
      "schemaVersion":"smesh-authz-policy/v1",
      "policyId":"gateway-main",
      "revision":7,
      "tenants":[{"id":"tenant-a","enabled":true},{"id":"tenant-b","enabled":true}],
      "accounts":[
        {"id":"agent","kind":"serviceAccount","memberships":[{"tenantId":"tenant-a","roles":["taskAgent"]}]},
        {"id":"operator","kind":"human","memberships":[{"tenantId":"tenant-a","roles":["taskOperator"]},{"tenantId":"tenant-b","roles":["taskViewer"]}]}
      ],
      "principalBindings":[
        {"principal":{"issuer":"https://issuer.example","subject":"agent"},"accountId":"agent"},
        {"principal":{"issuer":"https://issuer.example","subject":"operator"},"accountId":"operator"}
      ]
    }"#.to_vec()
}

#[test]
fn policy_resolves_same_account_across_bearer_and_mtls() {
    let policy = AuthorizationPolicy::from_json(&policy_json()).unwrap();
    let bearer = Principal::bearer_for_verifier(
        "https://issuer.example".into(),
        "agent".into(),
        PrincipalLimits::default(),
    )
    .unwrap();
    let mtls = Principal::mutual_tls(
        "https://issuer.example".into(),
        "agent".into(),
        PrincipalLimits::default(),
    )
    .unwrap();

    let a = policy.resolve(&bearer, None).unwrap();
    let b = policy.resolve(&mtls, None).unwrap();
    assert_eq!(a.account_id(), "agent");
    assert_eq!(a, b);
    assert_eq!(
        a.visibility(Operation::TaskGet).unwrap(),
        VisibilityScope::Own
    );
}

#[test]
fn selector_selects_membership_but_never_grants_and_omission_is_ambiguous() {
    let policy = AuthorizationPolicy::from_json(&policy_json()).unwrap();
    let principal = Principal::bearer_for_verifier(
        "https://issuer.example".into(),
        "operator".into(),
        PrincipalLimits::default(),
    )
    .unwrap();

    assert!(policy.resolve(&principal, None).is_err());
    assert!(policy.resolve(&principal, Some("tenant-missing")).is_err());
    let tenant_b = policy.resolve(&principal, Some("tenant-b")).unwrap();
    assert_eq!(tenant_b.tenant_id(), "tenant-b");
    assert!(tenant_b.authorize(Operation::TaskGet).is_ok());
    assert!(tenant_b.authorize(Operation::TaskCancel).is_err());
    for operation in [
        Operation::PushCreate,
        Operation::PushGet,
        Operation::PushList,
        Operation::PushDelete,
    ] {
        assert!(tenant_b.authorize(operation).is_err());
    }
    assert!(tenant_b.authorize(Operation::ExtendedCard).is_ok());
}

#[tokio::test]
async fn selector_denials_append_digest_only_durable_audits() {
    use axum::{Router, body::Body, http::Request, middleware, routing::get};
    use smesh_a2a::{
        AuthorizationMiddlewareState, InjectedClock, SqliteTaskStore,
        authorization::authorize_request,
    };
    use std::sync::Arc;
    use tower::ServiceExt as _;

    let dir = std::env::temp_dir().join(format!(
        "smesh-selector-audit-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let db_path = dir.join("tasks.sqlite3");
    let store = SqliteTaskStore::open(&db_path, 8).await.unwrap();
    let policy = Arc::new(AuthorizationPolicy::from_json(&policy_json()).unwrap());
    let state =
        AuthorizationMiddlewareState::with_sqlite(policy, store.clone(), InjectedClock::new(100));
    let enrolled = Arc::new(
        Principal::bearer_for_verifier(
            "https://issuer.example".into(),
            "operator".into(),
            PrincipalLimits::default(),
        )
        .unwrap(),
    );
    let app = Router::new()
        .route("/", get(|| async { "unreachable" }))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            authorize_request,
        ))
        .layer(axum::Extension(enrolled));
    for request in [
        Request::builder()
            .uri("/")
            .header("x-smesh-tenant", "x".repeat(65))
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .uri("/")
            .header("x-smesh-tenant", "tenant-secret-canary")
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .uri("/")
            .header("x-smesh-tenant", "tenant-a")
            .header("x-smesh-tenant", "tenant-b")
            .body(Body::empty())
            .unwrap(),
    ] {
        assert_eq!(app.clone().oneshot(request).await.unwrap().status(), 403);
    }
    let unenrolled = Arc::new(
        Principal::bearer_for_verifier(
            "https://issuer.example".into(),
            "not-enrolled".into(),
            PrincipalLimits::default(),
        )
        .unwrap(),
    );
    let unenrolled_app = Router::new()
        .route("/", get(|| async { "unreachable" }))
        .layer(middleware::from_fn_with_state(state, authorize_request))
        .layer(axum::Extension(unenrolled));
    assert_eq!(
        unenrolled_app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(store.authorization_decision_count().await.unwrap(), 4);
    store.shutdown_shared().await.unwrap();
    let bytes = std::fs::read(&db_path).unwrap();
    assert!(
        !bytes
            .windows("tenant-secret-canary".len())
            .any(|window| { window == "tenant-secret-canary".as_bytes() })
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn policy_rejects_unknown_fields_duplicate_bindings_and_kind_role_confusion() {
    let mut value: serde_json::Value = serde_json::from_slice(&policy_json()).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("callerGrant".into(), true.into());
    assert!(AuthorizationPolicy::from_json(&serde_json::to_vec(&value).unwrap()).is_err());

    let mut value: serde_json::Value = serde_json::from_slice(&policy_json()).unwrap();
    let duplicate = value["principalBindings"][0].clone();
    value["principalBindings"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    assert!(AuthorizationPolicy::from_json(&serde_json::to_vec(&value).unwrap()).is_err());

    let mut value: serde_json::Value = serde_json::from_slice(&policy_json()).unwrap();
    value["accounts"][0]["memberships"][0]["roles"] = serde_json::json!(["taskOperator"]);
    assert!(AuthorizationPolicy::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
}
