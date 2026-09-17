#![cfg(debug_assertions)]

use std::{env, str::FromStr as _, sync::Arc, time::Duration};

use smesh_a2a::{
    AuthorityDiagnostics, AuthorityShutdown, AuthorizationAuditInput, AuthorizationAuditSink,
    AuthorizationDecisionEffect, AuthorizedMutation, AuthorizedTaskRead, CancellationAuthority,
    LeaseRenewalOutcome, OutboxAuthority, OwnedTaskScope, PostgresStoreConfig, PostgresTaskStore,
    QuotaLeaseAuthority, QuotaLeaseKind, QuotaPolicy, QuotaReconciliationPlan,
    QuotaReconciliationTarget, QuotaSubject, ReceiverAdmission, ReceiverAuthority,
    SendMessageAdmission, TaskAdmission, VisibilityScope,
};

fn admin_url() -> Option<String> {
    match env::var("SMESH_TEST_POSTGRES_ADMIN_URL") {
        Ok(url) => Some(url),
        Err(env::VarError::NotPresent)
            if env::var("SMESH_POSTGRES_TEST_REQUIRED").as_deref() == Ok("1") =>
        {
            panic!("SMESH_TEST_POSTGRES_ADMIN_URL is required")
        }
        Err(env::VarError::NotPresent) => {
            eprintln!("skipping PostgreSQL quota test: SMESH_TEST_POSTGRES_ADMIN_URL is absent");
            None
        }
        Err(env::VarError::NotUnicode(_)) => {
            panic!("SMESH_TEST_POSTGRES_ADMIN_URL must be valid Unicode")
        }
    }
}

fn superuser_url() -> String {
    env::var("SMESH_TEST_POSTGRES_SUPERUSER_URL")
        .expect("SMESH_TEST_POSTGRES_SUPERUSER_URL is required for RLS/corruption probes")
}

fn policy() -> Arc<QuotaPolicy> {
    Arc::new(
        QuotaPolicy::from_json(
            br#"{
      "schemaVersion":"smesh-quota-policy/v1","policyId":"race-policy","revision":1,
      "requestWindowMillis":1000,"reconnectWindowMillis":60000,
      "limits":{
        "requestCount":{"tenant":2,"account":2,"principal":2},
        "concurrentActiveWork":{"tenant":1,"account":1,"principal":1},
        "inputBytes":{"tenant":1048576,"account":1048576,"principal":1048576},
        "outputBytes":{"tenant":1048576,"account":1048576,"principal":1048576},
        "eventCount":{"tenant":1024,"account":1024,"principal":1024},
        "concurrentStreams":{"tenant":4,"account":4,"principal":4},
        "concurrentSubscriptions":{"tenant":4,"account":4,"principal":4},
        "reconnectCount":{"tenant":12,"account":12,"principal":12},
        "retainedAuthorityBytes":{"tenant":16777216,"account":16777216,"principal":16777216}
      },"overrides":[]
    }"#,
        )
        .unwrap(),
    )
}

fn same_revision_different_policy() -> Arc<QuotaPolicy> {
    let baseline = policy();
    let mut document: serde_json::Value = serde_json::from_str(baseline.canonical_json()).unwrap();
    document["limits"]["requestCount"]["principal"] = serde_json::json!(1);
    Arc::new(QuotaPolicy::from_json(&serde_json::to_vec(&document).unwrap()).unwrap())
}

fn lower_revision_policy() -> Arc<QuotaPolicy> {
    let baseline = policy();
    let mut document: serde_json::Value = serde_json::from_str(baseline.canonical_json()).unwrap();
    document["revision"] = serde_json::json!(2);
    document["limits"]["requestCount"]["principal"] = serde_json::json!(1);
    Arc::new(QuotaPolicy::from_json(&serde_json::to_vec(&document).unwrap()).unwrap())
}

fn revision_two_policy() -> Arc<QuotaPolicy> {
    let baseline = policy();
    let mut document: serde_json::Value = serde_json::from_str(baseline.canonical_json()).unwrap();
    document["revision"] = serde_json::json!(2);
    for scope in ["tenant", "account", "principal"] {
        document["limits"]["requestCount"][scope] = serde_json::json!(4);
        document["limits"]["concurrentActiveWork"][scope] = serde_json::json!(2);
    }
    Arc::new(QuotaPolicy::from_json(&serde_json::to_vec(&document).unwrap()).unwrap())
}

fn account_request_policy() -> Arc<QuotaPolicy> {
    let baseline = policy();
    let mut document: serde_json::Value = serde_json::from_str(baseline.canonical_json()).unwrap();
    document["limits"]["requestCount"]["tenant"] = serde_json::json!(4);
    document["limits"]["requestCount"]["account"] = serde_json::json!(1);
    document["limits"]["requestCount"]["principal"] = serde_json::json!(1);
    Arc::new(QuotaPolicy::from_json(&serde_json::to_vec(&document).unwrap()).unwrap())
}

fn one_stream_policy() -> Arc<QuotaPolicy> {
    let baseline = policy();
    let mut document: serde_json::Value = serde_json::from_str(baseline.canonical_json()).unwrap();
    document["limits"]["concurrentStreams"]["tenant"] = serde_json::json!(1);
    document["limits"]["concurrentStreams"]["account"] = serde_json::json!(1);
    document["limits"]["concurrentStreams"]["principal"] = serde_json::json!(1);
    Arc::new(QuotaPolicy::from_json(&serde_json::to_vec(&document).unwrap()).unwrap())
}

fn two_reconnect_policy() -> Arc<QuotaPolicy> {
    let baseline = one_stream_policy();
    let mut document: serde_json::Value = serde_json::from_str(baseline.canonical_json()).unwrap();
    for scope in ["tenant", "account", "principal"] {
        document["limits"]["reconnectCount"][scope] = serde_json::json!(2);
    }
    Arc::new(QuotaPolicy::from_json(&serde_json::to_vec(&document).unwrap()).unwrap())
}

fn execution_policy(output_bytes: u64, event_count: u64) -> Arc<QuotaPolicy> {
    let baseline = policy();
    let mut document: serde_json::Value = serde_json::from_str(baseline.canonical_json()).unwrap();
    for scope in ["tenant", "account", "principal"] {
        document["limits"]["outputBytes"][scope] = serde_json::json!(output_bytes);
        document["limits"]["eventCount"][scope] = serde_json::json!(event_count);
    }
    Arc::new(QuotaPolicy::from_json(&serde_json::to_vec(&document).unwrap()).unwrap())
}

fn exact_events() -> Vec<smesh_a2a::MeshEvent> {
    vec![
        smesh_a2a::MeshEvent::Progress("ascii progress".into()),
        smesh_a2a::MeshEvent::Artifact {
            name: "résultat.json".into(),
            media_type: "application/json".into(),
            content: "{\"multibyte\":\"🦀\"}".into(),
        },
        smesh_a2a::MeshEvent::Completed {
            summary: "done".into(),
        },
    ]
}

fn measured_event_bytes(events: &[smesh_a2a::MeshEvent]) -> u64 {
    events
        .iter()
        .map(|event| serde_json::to_vec(event).unwrap().len() as u64)
        .sum()
}

fn expiring_egress_override_policy() -> Arc<QuotaPolicy> {
    let baseline = policy();
    let mut document: serde_json::Value = serde_json::from_str(baseline.canonical_json()).unwrap();
    document["overrides"] = serde_json::json!([{
        "overrideId":"egress-incident","actor":"operator-primary","reason":"ticket-14",
        "scopeKind":"principal","scopeId":"principal-race","operation":"publicEgress",
        "dimension":"outputBytes","oldLimit":1_048_576,"newLimit":1,
        "effectiveAt":1_700_000_000_000_i64,"expiresAt":1_700_000_000_100_i64
    }]);
    Arc::new(QuotaPolicy::from_json(&serde_json::to_vec(&document).unwrap()).unwrap())
}

fn command(suffix: &str) -> SendMessageAdmission {
    let mut message = a2a::Message::new(a2a::Role::User, vec![a2a::Part::text("race")]);
    message.message_id = format!("message-{suffix}");
    let request = a2a::SendMessageRequest {
        message: message.clone(),
        configuration: None,
        metadata: None,
        tenant: None,
    };
    let task = a2a::Task {
        id: format!("task-{suffix}"),
        context_id: format!("context-{suffix}"),
        status: a2a::TaskStatus {
            state: a2a::TaskState::Submitted,
            message: None,
            timestamp: chrono::DateTime::from_timestamp_millis(1_700_000_000_000),
        },
        artifacts: None,
        history: Some(vec![message]),
        metadata: None,
    };
    SendMessageAdmission {
        request,
        streaming: false,
        task: task.clone(),
        original_result: a2a::SendMessageResponse::Task(task),
        input_limits: smesh_a2a::InputLimits::default(),
        now: 1_700_000_000_000,
        max_attempts: 2,
    }
}

async fn seed_fair_outbox(client: &tokio_postgres::Client, schema: &str, tenant: &str, n: usize) {
    let suffix = format!("fair-{tenant}-{n}");
    let admission = command(&suffix);
    let task_json = serde_json::to_string(&admission.task).unwrap();
    let state = serde_json::to_string(&admission.task.status.state).unwrap();
    let dispatch_payload = smesh_a2a::MeshRequest::from_a2a(
        admission.task.id.clone(),
        admission.task.context_id.clone(),
        &admission.request.message,
        smesh_a2a::InputLimits::default(),
    )
    .unwrap();
    let payload = serde_json::to_string(&dispatch_payload).unwrap();
    let dispatch = format!("dispatch-{suffix}");
    client.execute(&format!("INSERT INTO {schema}.tasks(tenant_scope,task_id,context_id,state,status_timestamp,revision,task_json,owner_account_id) VALUES($1,$2,$3,$4,NULL,1,$5,'fair-account')"), &[&tenant,&admission.task.id,&admission.task.context_id,&state,&task_json]).await.unwrap();
    client.execute(&format!("INSERT INTO {schema}.outbox(dispatch_id,tenant_scope,task_id,message_id,causative_revision,payload_json,payload_digest,state,attempt_count,max_attempts,available_at,created_at,updated_at,dispatch_identity_version) VALUES($1,$2,$3,$4,1,$5,$6,'pending',0,3,1,1,1,1)"), &[&dispatch,&tenant,&admission.task.id,&admission.request.message.message_id,&payload,&smesh_a2a::content_digest(payload.as_bytes())]).await.unwrap();
}

fn audit_for_policy(
    command: &SendMessageAdmission,
    suffix: &str,
    operation: &str,
    policy_id: &str,
    policy_revision: u64,
    policy_digest: &str,
) -> AuthorizationAuditInput {
    let request_digest = smesh_a2a::canonical_send_message_digest_v2(
        "tenant-race",
        "account-race",
        &command.request,
        command.streaming,
    )
    .unwrap();
    AuthorizationAuditInput::new(
        format!("audit-{suffix}"),
        "tenant-race",
        "account-race",
        policy_id,
        policy_revision,
        policy_digest,
        operation,
        AuthorizationDecisionEffect::Allow,
        "policy_grant",
        "send-message-request",
        request_digest,
        None,
        1_700_000_000_000,
    )
    .unwrap()
}

fn audit_for(
    command: &SendMessageAdmission,
    suffix: &str,
    operation: &str,
) -> AuthorizationAuditInput {
    audit_for_policy(
        command,
        suffix,
        operation,
        "authz-policy",
        1,
        "authz-digest",
    )
}

fn audit(suffix: &str) -> AuthorizationAuditInput {
    audit_for(&command(suffix), suffix, "TaskCreate")
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn runtime_authority_context_reloads_postgres_rows() {
    Box::pin(tokio::time::timeout(Duration::from_secs(30), async {
        let Some(admin) = admin_url() else {
            return;
        };
        let runtime = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let schema = format!("smesh_runtime_authority_{:016x}", rand::random::<u64>());
        let quota_policy = policy();
        let config = PostgresStoreConfig::new(&admin, &runtime, &schema)
            .unwrap()
            .with_test_only_insecure_loopback(true)
            .with_quota_policy(Arc::clone(&quota_policy));
        let store = Arc::new(PostgresTaskStore::open(config.clone()).await.unwrap());
        let scope = OwnedTaskScope::new_with_principal_and_authentication(
            "tenant-race",
            "account-race",
            "principal-race",
            VisibilityScope::Tenant,
            "bearer-jwt",
        )
        .unwrap();
        let subject = QuotaSubject::new("tenant-race", "account-race", "principal-race").unwrap();
        let mut admission = command("runtime-authority");
        admission.streaming = true;
        let bytes = serde_json::to_vec(&admission.request).unwrap().len() as u64;
        let intent = quota_policy
            .admission_intent(&subject, "runtime-authority", bytes, admission.streaming)
            .unwrap();
        store
            .authorize_and_admit_mutation(
                &scope,
                AuthorizedMutation::with_quota_intent(admission.clone(), intent.clone()),
                audit_for(&admission, "runtime-authority", "TaskCreate"),
            )
            .await
            .unwrap();
        let mut accounting_config = tokio_postgres::Config::from_str(&admin).unwrap();
        accounting_config.options(format!(
            "-c search_path={schema},pg_catalog -c smesh.tenant_scope=tenant-race -c smesh.internal_global=diag-v1"
        ));
        let (accounting_client, accounting_connection) =
            accounting_config.connect(tokio_postgres::NoTls).await.unwrap();
        tokio::spawn(async move {
            let _ = accounting_connection.await;
        });
        let principal_bytes: i64 = accounting_client
            .query_one(
                "SELECT retained_bytes FROM retained_authority_usage WHERE tenant_scope='tenant-race' AND scope_kind='principal' AND scope_id='principal-race'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert!(principal_bytes > 0);
        let attribution = accounting_client
            .query_one(
                "SELECT count(*),count(*) FILTER (WHERE retained_principal(to_jsonb(i))='principal-race') FROM idempotency_records i WHERE authorization_principal_scope='principal-race'",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(attribution.get::<_, i64>(0), 1);
        assert_eq!(attribution.get::<_, i64>(1), 1);
        let sender = store
            .claim_outbox("runtime-authority-sender", admission.now + 1, 60_000)
            .await
            .unwrap()
            .unwrap();
        let payload_digest =
            smesh_a2a::content_digest(&serde_json::to_vec(&sender.request).unwrap());
        let receiver = match store
            .begin_receive(
                smesh_a2a::DurableDispatchEnvelope {
                    tenant_scope: sender.tenant_scope.clone(),
                    dispatch_id: sender.dispatch_id.clone(),
                    payload_digest,
                    request: sender.request.clone(),
                    execution_reservation: sender.execution_reservation.clone(),
                },
                "runtime-authority-receiver",
                admission.now + 2,
                60_000,
            )
            .await
            .unwrap()
        {
            ReceiverAdmission::Execute(lease) => lease,
            other => panic!("expected receiver execution, got {other:?}"),
        };
        let authority_now = admission.now + 2;

        let context = store
            .load_runtime_authority_context(&sender, &receiver, authority_now)
            .await
            .unwrap();
        assert_eq!(context.request(), &sender.request);
        assert_eq!(context.transport_payload_digest(), receiver.payload_digest);
        assert_eq!(
            context.authorized_request_digest(),
            smesh_a2a::canonical_send_message_digest_v2(
                "tenant-race",
                "account-race",
                &admission.request,
                true,
            )
            .unwrap()
        );
        assert_ne!(
            context.transport_payload_digest(),
            context.authorized_request_digest()
        );
        assert_eq!(context.scope().tenant_scope(), "tenant-race");
        assert_eq!(context.scope().account_id(), "account-race");
        assert_eq!(context.scope().principal_scope(), "principal-race");
        assert_eq!(context.scope().authentication_method(), "bearer-jwt");
        assert_eq!(context.scope().visibility(), VisibilityScope::Tenant);
        assert_eq!(context.scope().authorization_policy_id(), "authz-policy");
        assert_eq!(context.scope().authorization_policy_revision(), 1);
        assert_eq!(
            context.scope().authorization_policy_digest(),
            "authz-digest"
        );
        assert_eq!(
            context.production_reservation(),
            sender.execution_reservation.as_ref()
        );
        assert_eq!(
            context.budget(),
            sender.execution_reservation.as_ref().unwrap().budget
        );
        assert!(
            receiver.lease_until > sender.lease_until,
            "receiver lease must remain live at sender expiry"
        );
        let error = store
            .load_runtime_authority_context(&sender, &receiver, sender.lease_until)
            .await
            .expect_err("expired sender must fail while receiver remains live");
        assert_eq!(error.code, -32603);
        assert_eq!(error.message, "durable runtime authority unavailable");
        assert!(error.details.is_none());
        let mut renewed_sender = sender.clone();
        renewed_sender.lease_until = receiver.lease_until + 60_000;
        let (renew_client, renew_connection) =
            tokio_postgres::connect(&admin, tokio_postgres::NoTls)
                .await
                .unwrap();
        let renew_driver = tokio::spawn(renew_connection);
        renew_client
            .query_one(
                "SELECT set_config('smesh.internal_global','diag-v1',false),
                        set_config('smesh.tenant_scope','tenant-race',false)",
                &[],
            )
            .await
            .unwrap();
        let initial_evidence = renew_client
            .query_one(
                &format!(
                    "SELECT d.decision_id,d.operation,d.resource_kind,d.resource_digest,
                            d.actor_account_id,d.policy_id,d.policy_revision,d.policy_digest,
                            i.authorization_principal_scope,i.authorization_authentication_method,
                            i.authorization_visibility
                     FROM {schema}.idempotency_records i
                     JOIN {schema}.authorization_decisions d
                       ON d.tenant_scope=i.tenant_scope
                      AND d.decision_id=i.authorization_decision_id
                     WHERE i.tenant_scope='tenant-race' AND i.task_id=$1"
                ),
                &[&admission.task.id],
            )
            .await
            .unwrap();
        assert_eq!(initial_evidence.get::<_, &str>(0), "audit-runtime-authority");
        assert_eq!(initial_evidence.get::<_, &str>(1), "TaskCreate");
        assert_eq!(initial_evidence.get::<_, &str>(2), "send-message-request");
        assert_eq!(initial_evidence.get::<_, &str>(3), context.authorized_request_digest());
        assert_eq!(initial_evidence.get::<_, &str>(4), "account-race");
        assert_eq!(initial_evidence.get::<_, &str>(5), "authz-policy");
        assert_eq!(initial_evidence.get::<_, i64>(6), 1);
        assert_eq!(initial_evidence.get::<_, &str>(7), "authz-digest");
        assert_eq!(initial_evidence.get::<_, &str>(8), "principal-race");
        assert_eq!(initial_evidence.get::<_, &str>(9), "bearer-jwt");
        assert_eq!(initial_evidence.get::<_, &str>(10), "tenant");
        renew_client
            .batch_execute(&format!(
                "ALTER TABLE {schema}.outbox DISABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.retained_authority_usage DISABLE ROW LEVEL SECURITY;"
            ))
            .await
            .unwrap();
        assert_eq!(
            renew_client
                .execute(
                    &format!("UPDATE {schema}.outbox SET lease_until=$1 WHERE tenant_scope='tenant-race' AND outbox_id=$2 AND lease_until=$3"),
                    &[&renewed_sender.lease_until, &sender.outbox_id, &sender.lease_until],
                )
                .await
                .unwrap(),
            1,
            "sender lease renewal must durably apply"
        );
        renew_client
            .batch_execute(&format!(
                "ALTER TABLE {schema}.retained_authority_usage ENABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.retained_authority_usage FORCE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.outbox ENABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.outbox FORCE ROW LEVEL SECURITY;"
            ))
            .await
            .unwrap();
        drop(renew_client);
        renew_driver.abort();
        assert!(
            renewed_sender.lease_until > receiver.lease_until,
            "sender lease must remain live at receiver expiry"
        );
        let error = store
            .load_runtime_authority_context(&renewed_sender, &receiver, receiver.lease_until)
            .await
            .expect_err("expired receiver must fail while sender remains live");
        assert_eq!(error.code, -32603);
        assert_eq!(error.message, "durable runtime authority unavailable");
        assert!(error.details.is_none());
        let sender = renewed_sender;

        let mut runtime_config = tokio_postgres::Config::from_str(&runtime).unwrap();
        runtime_config.options(format!(
            "-c role={schema}_runtime -c smesh.tenant_scope=tenant-race -c smesh.account_id=account-race"
        ));
        let (runtime_client, runtime_connection) = runtime_config.connect(tokio_postgres::NoTls).await.unwrap();
        let runtime_driver = tokio::spawn(runtime_connection);
        for mutation in [
            "principal_scope='forged-principal'",
            "authentication_method='forged-authentication'",
            "authorization_policy_id='forged-policy'",
            "authorization_policy_revision=2",
            "authorization_policy_digest='forged-digest'",
            "visibility='own'",
            "authorization_decision_id='forged-decision'",
        ] {
            let error = runtime_client
                .execute(
                    &format!("UPDATE {schema}.tasks SET {mutation} WHERE tenant_scope='tenant-race' AND task_id=$1"),
                    &[&admission.task.id],
                )
                .await
                .expect_err(mutation);
            assert_eq!(
                error.code(),
                Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE),
                "runtime must have no effective UPDATE privilege for {mutation}"
            );
        }
        drop(runtime_client);
        runtime_driver.abort();

        let context_json = serde_json::to_string(&context).unwrap();
        for token in [
            &sender.lease_token,
            &receiver.lease_token,
            &receiver.sender_lease_token,
        ] {
            assert!(!context_json.contains(token));
        }
        assert!(context_json.contains(context.transport_payload_digest()));
        assert!(context_json.contains(context.authorized_request_digest()));

        let mut sender_mutations = Vec::new();
        let mut changed = sender.clone();
        changed.lease_token.push_str("-stale");
        sender_mutations.push(("sender token", changed));
        let mut changed = sender.clone();
        changed.attempt_no += 1;
        sender_mutations.push(("sender attempt", changed));
        let mut changed = sender.clone();
        changed.lease_until -= 1;
        sender_mutations.push(("sender expiry", changed));
        let mut changed = sender.clone();
        changed.task_id.push_str("-other");
        sender_mutations.push(("sender identity", changed));
        let mut changed = sender.clone();
        changed.tenant_scope.push_str("-other");
        sender_mutations.push(("sender tenant", changed));
        let mut changed = sender.clone();
        changed.request.text.push_str("-other");
        sender_mutations.push(("sender request", changed));
        let mut changed = sender.clone();
        changed.ratification_required = !changed.ratification_required;
        sender_mutations.push(("sender policy fence", changed));
        let mut changed = sender.clone();
        changed
            .execution_reservation
            .as_mut()
            .unwrap()
            .binding_digest
            .push_str("-other");
        sender_mutations.push(("sender reservation binding", changed));
        let mut changed = sender.clone();
        changed
            .execution_reservation
            .as_mut()
            .unwrap()
            .policy_digest
            .push_str("-other");
        sender_mutations.push(("sender reservation policy", changed));
        for (label, changed) in sender_mutations {
            assert_ne!(changed, sender, "{label} mutation must differ");
            let error = store
                .load_runtime_authority_context(&changed, &receiver, authority_now)
                .await
                .expect_err(label);
            assert_eq!(error.code, -32603, "{label}");
            assert_eq!(
                error.message, "durable runtime authority unavailable",
                "{label}"
            );
            assert!(error.details.is_none(), "{label}");
        }

        let mut receiver_mutations = Vec::new();
        let mut changed = receiver.clone();
        changed.lease_token.push_str("-stale");
        receiver_mutations.push(("receiver token", changed));
        let mut changed = receiver.clone();
        changed.lease_epoch += 1;
        receiver_mutations.push(("receiver epoch", changed));
        let mut changed = receiver.clone();
        changed.sender_lease_token.push_str("-stale");
        receiver_mutations.push(("receiver sender binding", changed));
        let mut changed = receiver.clone();
        changed.sender_attempt_no += 1;
        receiver_mutations.push(("receiver sender attempt", changed));
        let mut changed = receiver.clone();
        changed.payload_digest.push_str("-other");
        receiver_mutations.push(("receiver digest", changed));
        let mut changed = receiver.clone();
        changed.tenant_scope.push_str("-other");
        receiver_mutations.push(("receiver scope", changed));
        let mut changed = receiver.clone();
        changed.task_id.push_str("-other");
        receiver_mutations.push(("receiver task identity", changed));
        let mut changed = receiver.clone();
        changed.dispatch_id.push_str("-other");
        receiver_mutations.push(("receiver dispatch identity", changed));
        let mut changed = receiver.clone();
        changed.lease_until -= 1;
        receiver_mutations.push(("receiver expiry", changed));
        let mut changed = receiver.clone();
        let reservation = changed.execution_reservation.as_mut().unwrap();
        reservation.budget = smesh_a2a::ExecutionBudget::new(
            reservation.budget.max_output_bytes() + 1,
            reservation.budget.max_event_count(),
        )
        .unwrap();
        receiver_mutations.push(("receiver reservation budget", changed));
        for (label, changed) in receiver_mutations {
            assert_ne!(changed, receiver, "{label} mutation must differ");
            let error = store
                .load_runtime_authority_context(&sender, &changed, authority_now)
                .await
                .expect_err(label);
            assert_eq!(error.code, -32603, "{label}");
            assert_eq!(
                error.message, "durable runtime authority unavailable",
                "{label}"
            );
            assert!(error.details.is_none(), "{label}");
        }

        let (admin_client, admin_connection) =
            tokio_postgres::connect(&admin, tokio_postgres::NoTls).await.unwrap();
        let admin_driver = tokio::spawn(admin_connection);
        let set_task_policy = |policy: &str| {
            format!(
                "ALTER TABLE {schema}.tasks DISABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.retained_authority_usage DISABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.tasks DISABLE TRIGGER tasks_runtime_authority_immutable;
                 UPDATE {schema}.tasks SET authorization_policy_id='{policy}'
                  WHERE tenant_scope='tenant-race' AND task_id='{}';
                 ALTER TABLE {schema}.tasks ENABLE TRIGGER tasks_runtime_authority_immutable;
                 ALTER TABLE {schema}.retained_authority_usage ENABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.retained_authority_usage FORCE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.tasks ENABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.tasks FORCE ROW LEVEL SECURITY;",
                admission.task.id
            )
        };
        admin_client
            .batch_execute(&set_task_policy("privileged-contradiction"))
            .await
            .unwrap();
        let still_causative = store
            .load_runtime_authority_context(&sender, &receiver, authority_now)
            .await
            .expect("runtime authority must not be sourced from copied task admission provenance");
        assert_eq!(still_causative.scope().authorization_policy_id(), "authz-policy");
        admin_client
            .batch_execute(&set_task_policy("authz-policy"))
            .await
            .unwrap();

        admin_client
            .batch_execute(&format!(
                "ALTER TABLE {schema}.idempotency_records DISABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.retained_authority_usage DISABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.idempotency_records DISABLE TRIGGER idempotency_runtime_authority_immutable;"
            ))
            .await
            .unwrap();
        let authorization_decision_id: String = admin_client
            .query_one(
                &format!("SELECT authorization_decision_id FROM {schema}.idempotency_records WHERE tenant_scope='tenant-race' AND task_id=$1"),
                &[&admission.task.id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(
            admin_client
                .execute(
                    &format!("UPDATE {schema}.idempotency_records SET authorization_decision_id=NULL WHERE tenant_scope='tenant-race' AND task_id=$1"),
                    &[&admission.task.id],
                )
                .await
                .unwrap(),
            1
        );
        admin_client
            .batch_execute(&format!(
                "ALTER TABLE {schema}.idempotency_records ENABLE TRIGGER idempotency_runtime_authority_immutable;
                 ALTER TABLE {schema}.retained_authority_usage ENABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.retained_authority_usage FORCE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.idempotency_records ENABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.idempotency_records FORCE ROW LEVEL SECURITY;"
            ))
            .await
            .unwrap();
        let null_store = Arc::clone(&store);
        let null_sender = sender.clone();
        let null_receiver = receiver.clone();
        let null_result = tokio::spawn(async move {
            null_store
                .load_runtime_authority_context(&null_sender, &null_receiver, authority_now)
                .await
        })
        .await
        .expect("legacy NULL authority load must not panic")
        .expect_err("legacy NULL causative authority must remain non-executable");
        assert_eq!(null_result.code, -32603);
        assert_eq!(null_result.message, "durable runtime authority unavailable");
        assert!(null_result.details.is_none());
        admin_client
            .batch_execute(&format!(
                "ALTER TABLE {schema}.idempotency_records DISABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.retained_authority_usage DISABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.idempotency_records DISABLE TRIGGER idempotency_runtime_authority_immutable;"
            ))
            .await
            .unwrap();
        assert_eq!(
            admin_client
                .execute(
                    &format!("UPDATE {schema}.idempotency_records SET authorization_decision_id=$1 WHERE tenant_scope='tenant-race' AND task_id=$2"),
                    &[&authorization_decision_id, &admission.task.id],
                )
                .await
                .unwrap(),
            1
        );
        admin_client
            .batch_execute(&format!(
                "ALTER TABLE {schema}.idempotency_records ENABLE TRIGGER idempotency_runtime_authority_immutable;
                 ALTER TABLE {schema}.retained_authority_usage ENABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.retained_authority_usage FORCE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.idempotency_records ENABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.idempotency_records FORCE ROW LEVEL SECURITY;"
            ))
            .await
            .unwrap();
        drop(admin_client);
        admin_driver.abort();

        let mut substituted_request = sender.request.clone();
        substituted_request.text = "coherently substituted executable text".to_owned();
        let substituted_json = serde_json::to_string(&substituted_request).unwrap();
        let substituted_digest = smesh_a2a::content_digest(substituted_json.as_bytes());
        let mut substituted_sender = sender.clone();
        let mut substituted_receiver = receiver.clone();
        let (tamper_client, tamper_connection) =
            tokio_postgres::connect(&admin, tokio_postgres::NoTls).await.unwrap();
        let tamper_driver = tokio::spawn(tamper_connection);
        tamper_client
            .batch_execute(&format!(
                "ALTER TABLE {schema}.outbox DISABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.receiver_inbox DISABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.retained_authority_usage DISABLE ROW LEVEL SECURITY;"
            ))
            .await
            .unwrap();
        assert_eq!(
            tamper_client
                .execute(
                    &format!("UPDATE {schema}.outbox SET payload_json=$1,payload_digest=$2 WHERE tenant_scope='tenant-race' AND task_id=$3 AND state='leased'"),
                    &[&substituted_json, &substituted_digest, &admission.task.id],
                )
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            tamper_client
                .execute(
                    &format!("UPDATE {schema}.receiver_inbox SET payload_json=$1,payload_digest=$2 WHERE tenant_scope='tenant-race' AND task_id=$3 AND state='processing'"),
                    &[&substituted_json, &substituted_digest, &admission.task.id],
                )
                .await
                .unwrap(),
            1
        );
        tamper_client
            .batch_execute(&format!(
                "ALTER TABLE {schema}.retained_authority_usage ENABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.retained_authority_usage FORCE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.receiver_inbox ENABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.receiver_inbox FORCE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.outbox ENABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.outbox FORCE ROW LEVEL SECURITY;"
            ))
            .await
            .unwrap();
        drop(tamper_client);
        tamper_driver.abort();
        substituted_sender.request = substituted_request;
        substituted_receiver.payload_digest = substituted_digest;
        let error = store
            .load_runtime_authority_context(
                &substituted_sender,
                &substituted_receiver,
                authority_now,
            )
            .await
            .expect_err("causative request must bind executable semantics");
        assert_eq!(error.code, -32603);
        assert_eq!(error.message, "durable runtime authority unavailable");
        assert!(error.details.is_none());

        let original_json = serde_json::to_string(&sender.request).unwrap();
        let original_digest = smesh_a2a::content_digest(original_json.as_bytes());
        let (mut lock_client, lock_connection) =
            tokio_postgres::connect(&superuser_url(), tokio_postgres::NoTls)
                .await
                .unwrap();
        let lock_driver = tokio::spawn(lock_connection);
        lock_client
            .batch_execute(&format!(
                "ALTER TABLE {schema}.outbox DISABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.receiver_inbox DISABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.retained_authority_usage DISABLE ROW LEVEL SECURITY;"
            ))
            .await
            .unwrap();
        lock_client
            .execute(
                &format!("UPDATE {schema}.outbox SET payload_json=$1,payload_digest=$2 WHERE tenant_scope='tenant-race' AND task_id=$3 AND state='leased'"),
                &[&original_json, &original_digest, &admission.task.id],
            )
            .await
            .unwrap();
        lock_client
            .execute(
                &format!("UPDATE {schema}.receiver_inbox SET payload_json=$1,payload_digest=$2 WHERE tenant_scope='tenant-race' AND task_id=$3 AND state='processing'"),
                &[&original_json, &original_digest, &admission.task.id],
            )
            .await
            .unwrap();
        lock_client
            .batch_execute(&format!(
                "ALTER TABLE {schema}.retained_authority_usage ENABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.retained_authority_usage FORCE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.receiver_inbox ENABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.receiver_inbox FORCE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.outbox ENABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.outbox FORCE ROW LEVEL SECURITY;"
            ))
            .await
            .unwrap();
        let lock_tx = lock_client.transaction().await.unwrap();
        lock_tx
            .query_one(
                &format!(
                    "SELECT 1 FROM {schema}.receiver_inbox WHERE tenant_scope=$1 AND dispatch_id=$2 FOR UPDATE"
                ),
                &[&receiver.tenant_scope, &receiver.dispatch_id],
            )
            .await
            .unwrap();

        let (mut cancel_client, cancel_connection) =
            tokio_postgres::connect(&superuser_url(), tokio_postgres::NoTls)
                .await
                .unwrap();
        let cancel_driver = tokio::spawn(cancel_connection);
        let cancel_schema = schema.clone();
        let cancel_receiver = receiver.clone();
        let cancellation = tokio::spawn(async move {
            let tx = cancel_client.transaction().await.unwrap();
            tx.query_one(
                &format!(
                    "SELECT 1 /* cancellation-first-regression */ FROM {cancel_schema}.receiver_inbox WHERE tenant_scope=$1 AND dispatch_id=$2 FOR UPDATE"
                ),
                &[&cancel_receiver.tenant_scope, &cancel_receiver.dispatch_id],
            )
            .await
            .unwrap();
            tx.execute(
                &format!(
                    "INSERT INTO {cancel_schema}.cancellation_intents(tenant_scope,dispatch_id,task_id,state,requested_at) VALUES($1,$2,$3,'requested',{cancel_schema}.db_millis())"
                ),
                &[
                    &cancel_receiver.tenant_scope,
                    &cancel_receiver.dispatch_id,
                    &cancel_receiver.task_id,
                ],
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
        });
        let (monitor, monitor_connection) =
            tokio_postgres::connect(&superuser_url(), tokio_postgres::NoTls)
                .await
                .unwrap();
        let monitor_driver = tokio::spawn(monitor_connection);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let waiting: bool = monitor
                    .query_one(
                        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE query LIKE '%cancellation-first-regression%' AND wait_event_type='Lock')",
                        &[],
                    )
                    .await
                    .unwrap()
                    .get(0);
                if waiting {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("cancellation did not queue on the receiver lock");
        let completion_store = Arc::clone(&store);
        let completion_receiver = receiver.clone();
        let completion = tokio::spawn(async move {
            completion_store
                .complete_loopback_receive(
                    &completion_receiver,
                    &[smesh_a2a::MeshEvent::Completed {
                        summary: "cancellation-first race".into(),
                    }],
                    authority_now + 1,
                )
                .await
        });
        lock_tx.commit().await.unwrap();
        cancellation.await.unwrap();
        let completion_error = completion
            .await
            .unwrap()
            .expect_err("cancellation queued first must defeat terminal completion");
        assert_eq!(completion_error.message, "receiver lease is stale");
        cancel_driver.abort();
        monitor_driver.abort();
        lock_driver.abort();

        drop(store);
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }))
    .await
    .unwrap();
}

#[tokio::test]
async fn admission_persists_immutable_pre_dispatch_output_and_event_budget() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let Some(admin) = admin_url() else {
            return;
        };
        let runtime = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let schema = format!("smesh_quota_execution_budget_{:016x}", rand::random::<u64>());
        let quota_policy = policy();
        let config = PostgresStoreConfig::new(&admin, &runtime, &schema)
            .unwrap()
            .with_test_only_insecure_loopback(true)
            .with_quota_policy(Arc::clone(&quota_policy));
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let scope = OwnedTaskScope::new("tenant-race", "account-race", VisibilityScope::Own).unwrap();
        let subject = QuotaSubject::new("tenant-race", "account-race", "principal-race").unwrap();
        let admission = command("execution-budget");
        let bytes = serde_json::to_vec(&admission.request).unwrap().len() as u64;
        let intent = quota_policy
            .admission_intent(&subject, "execution-budget", bytes, false)
            .unwrap();

        let admin_pg = tokio_postgres::Config::from_str(&admin).unwrap();
        let (admin_client, admin_connection) = admin_pg.connect(tokio_postgres::NoTls).await.unwrap();
        let admin_driver = tokio::spawn(async move { let _ = admin_connection.await; });
        admin_client.batch_execute(&format!("CREATE FUNCTION {schema}.fail_execution_reserve() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'reserve fault'; END $$; CREATE TRIGGER fail_execution_reserve BEFORE INSERT ON {schema}.quota_execution_reservations FOR EACH ROW EXECUTE FUNCTION {schema}.fail_execution_reserve()" )).await.unwrap();
        assert!(store.authorize_and_admit_mutation(
            &scope,
            AuthorizedMutation::with_quota_intent(admission.clone(), intent.clone()),
            audit("execution-budget-fault"),
        ).await.is_err());
        assert_eq!(store.atomic_record_counts().await.unwrap().tasks, 0);
        admin_client.batch_execute(&format!("DROP TRIGGER fail_execution_reserve ON {schema}.quota_execution_reservations; DROP FUNCTION {schema}.fail_execution_reserve()" )).await.unwrap();
        drop(admin_client);
        admin_driver.abort();

        store
            .authorize_and_admit_mutation(
                &scope,
                AuthorizedMutation::with_quota_intent(admission, intent.clone()),
                audit("execution-budget"),
            )
            .await
            .unwrap();

        let pg = tokio_postgres::Config::from_str(&runtime).unwrap();
        let (client, connection) = pg.connect(tokio_postgres::NoTls).await.unwrap();
        let driver = tokio::spawn(async move { let _ = connection.await; });
        client.batch_execute(&format!("SET ROLE {schema}_runtime")).await.unwrap();
        client.query_one(
            "SELECT set_config('smesh.tenant_scope','tenant-race',false), set_config('smesh.account_id','account-race',false)",
            &[],
        ).await.unwrap();
        let row = client.query_one(
            &format!("SELECT quota_binding_digest,quota_reservation_id,quota_reservation_version,reserved_output_bytes,reserved_event_count FROM {schema}.outbox WHERE tenant_scope='tenant-race'"),
            &[],
        ).await.unwrap();
        assert_eq!(row.get::<_, String>(0), intent.binding_digest());
        assert_eq!(row.get::<_, String>(1), smesh_a2a::content_digest(format!("execution-reservation-v1\0tenant-race\0{}", intent.binding_digest()).as_bytes()));
        assert_eq!(row.get::<_, i64>(2), 1);
        assert_eq!(row.get::<_, i64>(3), 1_048_576);
        assert_eq!(row.get::<_, i64>(4), 1024);

        drop(client);
        driver.abort();
        store.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }).await.expect("execution budget admission watchdog");
}

#[tokio::test]
async fn receiver_rejects_output_or_event_plus_one_before_any_effect_or_frame() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let Some(admin) = admin_url() else { return };
        let runtime = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let baseline = exact_events();
        let quota_policy = execution_policy(measured_event_bytes(&baseline), baseline.len() as u64);
        let schema = format!("smesh_quota_execution_over_{:016x}", rand::random::<u64>());
        let config = PostgresStoreConfig::new(&admin, &runtime, &schema).unwrap()
            .with_test_only_insecure_loopback(true)
            .with_quota_policy(Arc::clone(&quota_policy));
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let scope = OwnedTaskScope::new("tenant-race", "account-race", VisibilityScope::Own).unwrap();
        let subject = QuotaSubject::new("tenant-race", "account-race", "principal-race").unwrap();
        let admission = command("execution-over");
        let input = serde_json::to_vec(&admission.request).unwrap().len() as u64;
        let intent = quota_policy.admission_intent(&subject, "execution-over", input, false).unwrap();
        store.authorize_and_admit_mutation(&scope, AuthorizedMutation::with_quota_intent(admission, intent), audit("execution-over")).await.unwrap();
        let sender = store.claim_outbox("sender-over", 1_700_000_000_000, 10_000).await.unwrap().unwrap();
        let payload = serde_json::to_vec(&sender.request).unwrap();
        let envelope = smesh_a2a::DurableDispatchEnvelope {
            tenant_scope: sender.tenant_scope.clone(),
            dispatch_id: sender.dispatch_id.clone(),
            payload_digest: smesh_a2a::content_digest(&payload),
            request: sender.request.clone(),
            execution_reservation: sender.execution_reservation.clone(),
        };
        let ReceiverAdmission::Execute(receiver) = store.begin_receive(envelope, "receiver-over", 1_700_000_000_000, 10_000).await.unwrap() else { panic!("receiver lease") };

        let mut bytes_over = baseline.clone();
        let smesh_a2a::MeshEvent::Completed { summary } = bytes_over.last_mut().unwrap() else { unreachable!() };
        summary.push('x');
        assert!(store.complete_loopback_receive(&receiver, &bytes_over, 1_700_000_000_001).await.is_err());
        let mut events_over = baseline.clone();
        events_over.push(smesh_a2a::MeshEvent::Progress(String::new()));
        assert!(store.complete_loopback_receive(&receiver, &events_over, 1_700_000_000_001).await.is_err());

        let admin_pg = tokio_postgres::Config::from_str(&admin).unwrap();
        let (admin_client, admin_connection) = admin_pg.connect(tokio_postgres::NoTls).await.unwrap();
        let admin_driver = tokio::spawn(async move { let _ = admin_connection.await; });
        admin_client.batch_execute(&format!("CREATE FUNCTION {schema}.fail_receiver_measurement() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'measurement fault'; END $$; CREATE TRIGGER fail_receiver_measurement BEFORE UPDATE OF state ON {schema}.receiver_inbox FOR EACH ROW WHEN (NEW.state='completed') EXECUTE FUNCTION {schema}.fail_receiver_measurement()" )).await.unwrap();
        assert!(store.complete_loopback_receive(&receiver, &baseline, 1_700_000_000_001).await.is_err());
        admin_client.batch_execute(&format!("DROP TRIGGER fail_receiver_measurement ON {schema}.receiver_inbox; DROP FUNCTION {schema}.fail_receiver_measurement()" )).await.unwrap();
        drop(admin_client);
        admin_driver.abort();

        let pg = tokio_postgres::Config::from_str(&runtime).unwrap();
        let (client, connection) = pg.connect(tokio_postgres::NoTls).await.unwrap();
        let driver = tokio::spawn(async move { let _ = connection.await; });
        client.batch_execute(&format!("SET ROLE {schema}_runtime")).await.unwrap();
        client.query_one("SELECT set_config('smesh.tenant_scope','tenant-race',false),set_config('smesh.account_id','account-race',false)", &[]).await.unwrap();
        let row = client.query_one(&format!("SELECT (SELECT count(*) FROM {schema}.loopback_effects),(SELECT count(*) FROM {schema}.receiver_frames),r.state,q.state FROM {schema}.receiver_inbox r JOIN {schema}.quota_execution_reservations q ON q.tenant_scope=r.tenant_scope AND q.reservation_id=r.quota_reservation_id"), &[]).await.unwrap();
        assert_eq!((row.get::<_, i64>(0), row.get::<_, i64>(1)), (0, 0));
        assert_eq!(row.get::<_, String>(2), "processing");
        assert_eq!(row.get::<_, String>(3), "reserved");
        drop(client); driver.abort();
        store.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }).await.expect("receiver plus-one watchdog");
}

#[tokio::test]
async fn exact_multibyte_receiver_measurement_survives_sender_crash_and_settles_once() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let Some(admin) = admin_url() else { return };
        let runtime = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let events = exact_events();
        let actual_bytes = measured_event_bytes(&events);
        let quota_policy = execution_policy(actual_bytes + 17, events.len() as u64 + 2);
        let schema = format!("smesh_quota_execution_settle_{:016x}", rand::random::<u64>());
        let config = PostgresStoreConfig::new(&admin, &runtime, &schema).unwrap()
            .with_test_only_insecure_loopback(true)
            .with_quota_policy(Arc::clone(&quota_policy));
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let scope = OwnedTaskScope::new("tenant-race", "account-race", VisibilityScope::Own).unwrap();
        let subject = QuotaSubject::new("tenant-race", "account-race", "principal-race").unwrap();
        let admission = command("execution-settle");
        let input = serde_json::to_vec(&admission.request).unwrap().len() as u64;
        let intent = quota_policy.admission_intent(&subject, "execution-settle", input, false).unwrap();
        store.authorize_and_admit_mutation(&scope, AuthorizedMutation::with_quota_intent(admission, intent), audit("execution-settle")).await.unwrap();
        let sender = store.claim_outbox("sender-settle", 1_700_000_000_000, 10_000).await.unwrap().unwrap();
        let payload = serde_json::to_vec(&sender.request).unwrap();
        let envelope = smesh_a2a::DurableDispatchEnvelope {
            tenant_scope: sender.tenant_scope.clone(), dispatch_id: sender.dispatch_id.clone(),
            payload_digest: smesh_a2a::content_digest(&payload), request: sender.request.clone(),
            execution_reservation: sender.execution_reservation.clone(),
        };
        let ReceiverAdmission::Execute(receiver) = store.begin_receive(envelope, "receiver-settle", 1_700_000_000_000, 10_000).await.unwrap() else { panic!("receiver lease") };
        store.complete_loopback_receive(&receiver, &events, 1_700_000_000_001).await.unwrap();

        let mut terminal = store.task_for_outbox(&sender).await.unwrap().unwrap();
        let initial = terminal.clone();
        let mut status_message = a2a::Message::new(a2a::Role::Agent, vec![a2a::Part::text("done")]);
        status_message.task_id = Some(terminal.id.clone());
        status_message.context_id = Some(terminal.context_id.clone());
        terminal.status = a2a::TaskStatus {
            state: a2a::TaskState::Completed,
            message: Some(status_message),
            timestamp: chrono::DateTime::from_timestamp_millis(1_700_000_000_002),
        };
        let transcript = vec![
            a2a::StreamResponse::Task(initial),
            a2a::StreamResponse::StatusUpdate(a2a::TaskStatusUpdateEvent {
                task_id: terminal.id.clone(),
                context_id: terminal.context_id.clone(),
                status: terminal.status.clone(),
                metadata: None,
            }),
        ];
        let result = a2a::SendMessageResponse::Task(terminal.clone());

        let admin_pg = tokio_postgres::Config::from_str(&superuser_url()).unwrap();
        let (admin_client, admin_connection) = admin_pg.connect(tokio_postgres::NoTls).await.unwrap();
        let admin_driver = tokio::spawn(async move { let _ = admin_connection.await; });
        admin_client.batch_execute(&format!("CREATE FUNCTION {schema}.fail_execution_settlement() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'settlement fault'; END $$; CREATE TRIGGER fail_execution_settlement BEFORE UPDATE OF state ON {schema}.quota_execution_reservations FOR EACH ROW WHEN (NEW.state='settled') EXECUTE FUNCTION {schema}.fail_execution_settlement()" )).await.unwrap();
        assert!(store.commit_delivery(&sender, terminal.clone(), result.clone(), &transcript, 1_700_000_000_002).await.is_err());
        let unchanged = admin_client.query_one(&format!("SELECT q.state,o.state,t.state FROM {schema}.quota_execution_reservations q JOIN {schema}.outbox o ON o.quota_reservation_id=q.reservation_id JOIN {schema}.tasks t ON t.tenant_scope=q.tenant_scope AND t.task_id=q.task_id"), &[]).await.unwrap();
        assert_eq!(unchanged.get::<_, String>(0), "reserved");
        assert_eq!(unchanged.get::<_, String>(1), "leased");
        assert_eq!(unchanged.get::<_, String>(2), serde_json::to_string(&a2a::TaskState::Submitted).unwrap());
        admin_client.batch_execute(&format!("DROP TRIGGER fail_execution_settlement ON {schema}.quota_execution_reservations; DROP FUNCTION {schema}.fail_execution_settlement()" )).await.unwrap();
        drop(admin_client);
        admin_driver.abort();

        assert_eq!(store.commit_delivery(&sender, terminal.clone(), result.clone(), &transcript, 1_700_000_000_002).await.unwrap(), smesh_a2a::TransitionOutcome::Applied);
        assert_eq!(store.commit_delivery(&sender, terminal, result, &transcript, 1_700_000_000_003).await.unwrap(), smesh_a2a::TransitionOutcome::Stale);

        let pg = tokio_postgres::Config::from_str(&runtime).unwrap();
        let (client, connection) = pg.connect(tokio_postgres::NoTls).await.unwrap();
        let driver = tokio::spawn(async move { let _ = connection.await; });
        client.batch_execute(&format!("SET ROLE {schema}_runtime")).await.unwrap();
        client.query_one("SELECT set_config('smesh.tenant_scope','tenant-race',false),set_config('smesh.account_id','account-race',false)", &[]).await.unwrap();
        let row = client.query_one(&format!("SELECT state,actual_output_bytes,actual_event_count,(SELECT measured_output_bytes FROM {schema}.receiver_inbox),(SELECT measured_event_count FROM {schema}.receiver_inbox) FROM {schema}.quota_execution_reservations"), &[]).await.unwrap();
        assert_eq!(row.get::<_, String>(0), "settled");
        assert_eq!(
            row.get::<_, i64>(1),
            i64::try_from(actual_bytes).expect("test output bytes fit i64")
        );
        assert_eq!(
            row.get::<_, i64>(2),
            i64::try_from(events.len()).expect("test event count fits i64")
        );
        assert_eq!(
            row.get::<_, i64>(3),
            i64::try_from(actual_bytes).expect("test output bytes fit i64")
        );
        assert_eq!(
            row.get::<_, i64>(4),
            i64::try_from(events.len()).expect("test event count fits i64")
        );
        drop(client); driver.abort();
        store.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }).await.expect("receiver settlement watchdog");
}

#[tokio::test]
async fn list_quota_charge_rolls_back_when_the_atomic_audit_write_conflicts() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let Some(admin) = admin_url() else {
            return;
        };
        let runtime = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let schema = format!("smesh_quota_list_atomic_{:016x}", rand::random::<u64>());
        let quota_policy = policy();
        let config = PostgresStoreConfig::new(&admin, &runtime, &schema)
            .unwrap()
            .with_test_only_insecure_loopback(true)
            .with_quota_policy(Arc::clone(&quota_policy));
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let scope =
            OwnedTaskScope::new("tenant-race", "account-race", VisibilityScope::Own).unwrap();
        let subject = QuotaSubject::new("tenant-race", "account-race", "principal-race").unwrap();

        let conflicting_audit = audit("atomic-list-conflict");
        store
            .append_authorization_decision(conflicting_audit.clone())
            .await
            .unwrap();
        let intent = quota_policy
            .operation_intent(
                &subject,
                smesh_a2a::QuotaOperation::TaskList,
                conflicting_audit.decision_id(),
                0,
            )
            .unwrap();
        let result = store
            .list_authorized_with_quota(
                &scope,
                &a2a::ListTasksRequest {
                    context_id: None,
                    status: None,
                    page_size: Some(10),
                    page_token: None,
                    history_length: None,
                    status_timestamp_after: None,
                    include_artifacts: Some(false),
                    tenant: None,
                },
                conflicting_audit,
                "atomic-list-cursor",
                Some(&intent),
            )
            .await;
        assert!(result.is_err());
        assert_eq!(
            store
                .quota_used_units(
                    "tenant-race",
                    smesh_a2a::QuotaScopeKind::Principal,
                    "principal-race",
                    smesh_a2a::QuotaOperation::TaskList,
                    smesh_a2a::QuotaDimension::RequestCount,
                )
                .await
                .unwrap(),
            0,
            "list quota and its authorization audit must share one transaction",
        );

        store.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    })
    .await
    .expect("atomic list quota watchdog");
}

#[tokio::test]
async fn expired_override_is_ignored_on_a_live_database_time_decision() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let Some(admin) = admin_url() else {
            return;
        };
        let runtime = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let schema = format!("smesh_quota_override_expiry_{:016x}", rand::random::<u64>());
        let quota_policy = expiring_egress_override_policy();
        let config = PostgresStoreConfig::new(&admin, &runtime, &schema)
            .unwrap()
            .with_test_only_insecure_loopback(true)
            .with_quota_policy(Arc::clone(&quota_policy));
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let subject = QuotaSubject::new("tenant-race", "account-race", "principal-race").unwrap();

        let during = quota_policy
            .egress_intent(&subject, "override-during", 1, 1)
            .unwrap();
        store
            .charge_quota_egress(&during, 1_700_000_000_000)
            .await
            .unwrap();
        let exhausted = quota_policy
            .egress_intent(&subject, "override-exhausted", 1, 1)
            .unwrap();
        assert_eq!(
            store
                .charge_quota_egress(&exhausted, 1_700_000_000_001)
                .await
                .unwrap_err()
                .code,
            -32_010
        );
        let expired = quota_policy
            .egress_intent(&subject, "override-expired", 1, 1)
            .unwrap();
        store
            .charge_quota_egress(&expired, 1_700_000_000_100)
            .await
            .unwrap();
        assert_eq!(store.quota_denial_count("tenant-race").await.unwrap(), 1);

        store.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    })
    .await
    .expect("override expiry watchdog");
}

#[tokio::test]
async fn crash_expiry_reclaims_slot_and_stale_holder_cannot_renew_or_release() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let Some(admin) = admin_url() else {
            return;
        };
        let runtime = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let schema = format!("smesh_quota_stream_expiry_{:016x}", rand::random::<u64>());
        let quota_policy = one_stream_policy();
        let config = PostgresStoreConfig::new(&admin, &runtime, &schema)
            .unwrap()
            .with_test_only_insecure_loopback(true)
            .with_quota_policy(Arc::clone(&quota_policy));
        let a = PostgresTaskStore::open(config.clone()).await.unwrap();
        let b = PostgresTaskStore::open(config.clone()).await.unwrap();
        let subject = QuotaSubject::new("tenant-race", "account-race", "principal-race").unwrap();
        let first_intent = quota_policy
            .lease_intent(&subject, QuotaLeaseKind::MessageStream, "crashed", false)
            .unwrap();
        let first = a
            .acquire_quota_lease(
                &first_intent,
                QuotaLeaseKind::MessageStream,
                "resource-digest-crashed",
                1_700_000_000_000,
                1_000,
            )
            .await
            .unwrap();
        let replacement_intent = quota_policy
            .lease_intent(
                &subject,
                QuotaLeaseKind::MessageStream,
                "replacement",
                false,
            )
            .unwrap();
        let replacement = b
            .acquire_quota_lease(
                &replacement_intent,
                QuotaLeaseKind::MessageStream,
                "resource-digest-replacement",
                1_700_000_001_000,
                1_000,
            )
            .await
            .unwrap();
        assert_eq!(
            a.renew_quota_lease(&first, 1_700_000_001_000, 1_000)
                .await
                .unwrap(),
            LeaseRenewalOutcome::Stale
        );
        assert!(
            !a.release_quota_lease(&first, 1_700_000_001_000)
                .await
                .unwrap()
        );
        assert!(
            b.release_quota_lease(&replacement, 1_700_000_001_000)
                .await
                .unwrap()
        );

        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    })
    .await
    .expect("stream lease crash-expiry watchdog");
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn reconnect_token_bucket_refills_continuously_without_boundary_reset_or_clock_mint() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let Some(admin) = admin_url() else { return };
        let runtime = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let schema = format!("smesh_quota_token_refill_{:016x}", rand::random::<u64>());
        let quota_policy = two_reconnect_policy();
        let config = PostgresStoreConfig::new(&admin, &runtime, &schema)
            .unwrap()
            .with_test_only_insecure_loopback(true)
            .with_quota_policy(Arc::clone(&quota_policy));
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let subject = QuotaSubject::new("tenant-race", "account-race", "principal-race").unwrap();
        let base = 1_700_000_000_000_i64;
        for n in 0..2 {
            let intent = quota_policy
                .lease_intent(
                    &subject,
                    QuotaLeaseKind::MessageStream,
                    &format!("token-burst-{n}"),
                    true,
                )
                .unwrap();
            let lease = store
                .acquire_quota_lease(
                    &intent,
                    QuotaLeaseKind::MessageStream,
                    &format!("token-resource-{n}"),
                    base,
                    1_000,
                )
                .await
                .unwrap();
            assert!(store.release_quota_lease(&lease, base).await.unwrap());
        }
        for (suffix, now) in [("rollback", base - 1), ("partial", base + 29_999)] {
            let intent = quota_policy
                .lease_intent(&subject, QuotaLeaseKind::MessageStream, suffix, true)
                .unwrap();
            assert_eq!(
                store
                    .acquire_quota_lease(&intent, QuotaLeaseKind::MessageStream, suffix, now, 1_000)
                    .await
                    .unwrap_err()
                    .code,
                -32_010
            );
        }
        let intent = quota_policy
            .lease_intent(
                &subject,
                QuotaLeaseKind::MessageStream,
                "exact-refill",
                true,
            )
            .unwrap();
        let lease = store
            .acquire_quota_lease(
                &intent,
                QuotaLeaseKind::MessageStream,
                "exact-refill",
                base + 30_000,
                1_000,
            )
            .await
            .unwrap();
        assert!(
            store
                .release_quota_lease(&lease, base + 30_000)
                .await
                .unwrap()
        );
        let state = store
            .quota_used_units(
                "tenant-race",
                smesh_a2a::QuotaScopeKind::Principal,
                "principal-race",
                smesh_a2a::QuotaOperation::Reconnect,
                smesh_a2a::QuotaDimension::ReconnectCount,
            )
            .await
            .unwrap();
        assert_eq!(
            state, 2,
            "capacity minus available tokens remains durable across restart"
        );
        store.shutdown().await.unwrap();
        let reopened = PostgresTaskStore::open(config.clone()).await.unwrap();
        let denied = quota_policy
            .lease_intent(
                &subject,
                QuotaLeaseKind::MessageStream,
                "restart-no-mint",
                true,
            )
            .unwrap();
        assert_eq!(
            reopened
                .acquire_quota_lease(
                    &denied,
                    QuotaLeaseKind::MessageStream,
                    "restart-no-mint",
                    base + 30_000,
                    1_000
                )
                .await
                .unwrap_err()
                .code,
            -32_010
        );
        reopened.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    })
    .await
    .expect("continuous token bucket watchdog");
}

#[tokio::test]
async fn two_independent_stores_cannot_oversubscribe_one_stream_lease_and_release_is_fenced() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let Some(admin) = admin_url() else {
            return;
        };
        let runtime = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let schema = format!("smesh_quota_stream_lease_{:016x}", rand::random::<u64>());
        let quota_policy = one_stream_policy();
        let config = PostgresStoreConfig::new(&admin, &runtime, &schema)
            .unwrap()
            .with_test_only_insecure_loopback(true)
            .with_quota_policy(Arc::clone(&quota_policy));
        let a = Arc::new(PostgresTaskStore::open(config.clone()).await.unwrap());
        let b = Arc::new(PostgresTaskStore::open(config.clone()).await.unwrap());
        let subject = QuotaSubject::new("tenant-race", "account-race", "principal-race").unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let acquire = |store: Arc<PostgresTaskStore>, suffix: &'static str| {
            let barrier = Arc::clone(&barrier);
            let intent = quota_policy
                .lease_intent(&subject, QuotaLeaseKind::MessageStream, suffix, false)
                .unwrap();
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .acquire_quota_lease(
                        &intent,
                        QuotaLeaseKind::MessageStream,
                        &format!("resource-digest-{suffix}"),
                        1_700_000_000_000,
                        30_000,
                    )
                    .await
            })
        };
        let one = acquire(Arc::clone(&a), "one");
        let two = acquire(Arc::clone(&b), "two");
        barrier.wait().await;
        let (one, two) = tokio::join!(one, two);
        let mut outcomes = vec![one.unwrap(), two.unwrap()];
        assert_eq!(outcomes.iter().filter(|value| value.is_ok()).count(), 1);
        assert_eq!(outcomes.iter().filter(|value| value.is_err()).count(), 1);
        let lease = outcomes
            .drain(..)
            .find_map(Result::ok)
            .expect("one stream lease winner");

        let mut stale = lease.clone();
        stale.lease_token =
            "digest:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
        assert!(
            !a.release_quota_lease(&stale, 1_700_000_000_001)
                .await
                .unwrap()
        );
        assert!(
            a.release_quota_lease(&lease, 1_700_000_000_001)
                .await
                .unwrap()
        );
        assert!(
            !a.release_quota_lease(&lease, 1_700_000_000_001)
                .await
                .unwrap()
        );

        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    })
    .await
    .expect("stream lease race watchdog");
}

#[tokio::test]
async fn account_boundary_contends_across_principals_and_isolates_other_accounts() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let Some(admin) = admin_url() else { return };
        let runtime = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let schema = format!("smesh_quota_account_{:016x}", rand::random::<u64>());
        let quota_policy = account_request_policy();
        let config = PostgresStoreConfig::new(&admin, &runtime, &schema)
            .unwrap()
            .with_test_only_insecure_loopback(true)
            .with_quota_policy(Arc::clone(&quota_policy));
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let a1 = QuotaSubject::new("tenant-race", "account-a", "principal-a1").unwrap();
        let a2 = QuotaSubject::new("tenant-race", "account-a", "principal-a2").unwrap();
        let b1 = QuotaSubject::new("tenant-race", "account-b", "principal-b1").unwrap();
        let first = quota_policy
            .operation_intent(
                &a1,
                smesh_a2a::QuotaOperation::TaskCancel,
                "account-a-first",
                0,
            )
            .unwrap();
        let contender = quota_policy
            .operation_intent(
                &a2,
                smesh_a2a::QuotaOperation::TaskCancel,
                "account-a-second",
                0,
            )
            .unwrap();
        let independent = quota_policy
            .operation_intent(
                &b1,
                smesh_a2a::QuotaOperation::TaskCancel,
                "account-b-first",
                0,
            )
            .unwrap();
        store
            .charge_quota_request(&first, 1_700_000_000_000)
            .await
            .unwrap();
        assert_eq!(
            store
                .charge_quota_request(&contender, 1_700_000_000_000)
                .await
                .unwrap_err()
                .code,
            -32_010
        );
        store
            .charge_quota_request(&independent, 1_700_000_000_000)
            .await
            .unwrap();
        for account in ["account-a", "account-b"] {
            assert_eq!(
                store
                    .quota_used_units(
                        "tenant-race",
                        smesh_a2a::QuotaScopeKind::Account,
                        account,
                        smesh_a2a::QuotaOperation::TaskCancel,
                        smesh_a2a::QuotaDimension::RequestCount
                    )
                    .await
                    .unwrap(),
                1
            );
        }
        store.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    })
    .await
    .expect("account boundary watchdog");
}

#[tokio::test]
async fn two_independent_stores_cannot_oversubscribe_last_request_or_active_work_unit() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let Some(admin) = admin_url() else {
            return;
        };
        let runtime = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let schema = format!("smesh_quota_race_{:016x}", rand::random::<u64>());
        let quota_policy = policy();
        let config = PostgresStoreConfig::new(&admin, &runtime, &schema)
            .unwrap()
            .with_test_only_insecure_loopback(true)
            .with_test_only_trust_injected_time(false)
            .with_quota_policy(Arc::clone(&quota_policy));
        let a = Arc::new(PostgresTaskStore::open(config.clone()).await.unwrap());
        let b = Arc::new(PostgresTaskStore::open(config.clone()).await.unwrap());
        let scope = Arc::new(
            OwnedTaskScope::new("tenant-race", "account-race", VisibilityScope::Own).unwrap(),
        );
        let subject = QuotaSubject::new("tenant-race", "account-race", "principal-race").unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let run = |store: Arc<PostgresTaskStore>, suffix: &'static str| {
            let scope = Arc::clone(&scope);
            let barrier = Arc::clone(&barrier);
            let command = command(suffix);
            let input_bytes = serde_json::to_vec(&command.request).unwrap().len() as u64;
            let intent = quota_policy
                .admission_intent(&subject, suffix, input_bytes, false)
                .unwrap();
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .authorize_and_admit_mutation(
                        &scope,
                        AuthorizedMutation::with_quota_intent(command, intent),
                        audit(suffix),
                    )
                    .await
            })
        };
        let one = run(Arc::clone(&a), "one");
        let two = run(Arc::clone(&b), "two");
        barrier.wait().await;
        let (one, two) = tokio::join!(one, two);
        let outcomes = [one.unwrap(), two.unwrap()];
        assert_eq!(outcomes.iter().filter(|value| value.is_ok()).count(), 1);
        assert_eq!(outcomes.iter().filter(|value| value.is_err()).count(), 1);
        assert_eq!(a.quota_denial_count("tenant-race").await.unwrap(), 1);
        let counts = a.atomic_record_counts().await.unwrap();
        assert_eq!(counts.tasks, 1);
        let pg = tokio_postgres::Config::from_str(&superuser_url()).unwrap();
        let (client, connection) = pg.connect(tokio_postgres::NoTls).await.unwrap();
        let driver = tokio::spawn(async move { let _ = connection.await; });
        let exact = client.query_one(&format!("SELECT (SELECT count(*) FROM {schema}.quota_execution_reservations),(SELECT count(*) FROM {schema}.quota_receipts r WHERE r.dimension IN ('outputBytes','eventCount')),(SELECT count(DISTINCT binding_digest) FROM {schema}.quota_receipts r WHERE r.dimension IN ('outputBytes','eventCount')),(SELECT array_agg(scope_kind||':'||dimension ORDER BY scope_kind,dimension) FROM {schema}.quota_receipts r WHERE r.dimension IN ('outputBytes','eventCount')),(SELECT count(*) FROM {schema}.quota_denial_audits WHERE octet_length(content_digest)=71 AND octet_length(bucket_digest)=71 AND octet_length(reason_digest)=71)"), &[]).await.unwrap();
        assert_eq!(
            (exact.get::<_, i64>(0), exact.get::<_, i64>(1), exact.get::<_, i64>(2)),
            (1, 6, 1),
            "loser must leave no second execution reservation, binding, or partial receipts"
        );
        assert_eq!(
            exact.get::<_, Vec<String>>(3),
            vec![
                "account:eventCount", "account:outputBytes",
                "principal:eventCount", "principal:outputBytes",
                "tenant:eventCount", "tenant:outputBytes",
            ]
        );
        assert_eq!(exact.get::<_, i64>(4), 1, "loser emits one digest-only denial audit");
        drop(client);
        driver.abort();
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    })
    .await
    .expect("quota race watchdog");
}

#[tokio::test]
async fn terminal_release_is_exactly_once_and_replay_never_recharges_active_work() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let Some(admin) = admin_url() else { return };
        let runtime = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let schema = format!("smesh_quota_release_{:016x}", rand::random::<u64>());
        let quota_policy = policy();
        let config = PostgresStoreConfig::new(&admin, &runtime, &schema).unwrap()
            .with_test_only_insecure_loopback(true)
            .with_quota_policy(Arc::clone(&quota_policy));
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let scope = OwnedTaskScope::new("tenant-race", "account-race", VisibilityScope::Own).unwrap();
        let subject = QuotaSubject::new("tenant-race", "account-race", "principal-race").unwrap();
        let command = command("release-one");
        let bytes = serde_json::to_vec(&command.request).unwrap().len() as u64;
        let intent = quota_policy.admission_intent(&subject, "release-one", bytes, false).unwrap();
        store.authorize_and_admit_mutation(
            &scope,
            AuthorizedMutation::with_quota_intent(command.clone(), intent.clone()),
            audit("release-one"),
        ).await.unwrap();
        let replay = store.authorize_and_admit_mutation(
            &scope,
            AuthorizedMutation::with_quota_intent(command, intent),
            audit("release-replay"),
        ).await.unwrap();
        assert!(matches!(replay, smesh_a2a::AdmissionOutcome::Replay(_)));
        assert_eq!(store.quota_used_units(
            "tenant-race", smesh_a2a::QuotaScopeKind::Principal, "principal-race",
            smesh_a2a::QuotaOperation::TaskCreate,
            smesh_a2a::QuotaDimension::ConcurrentActiveWork,
        ).await.unwrap(), 1);
        assert_eq!(store.quota_used_units(
            "tenant-race", smesh_a2a::QuotaScopeKind::Principal, "principal-race",
            smesh_a2a::QuotaOperation::TaskCreate,
            smesh_a2a::QuotaDimension::RequestCount,
        ).await.unwrap(), 2, "exact replay consumes a fresh request charge");

        let pg = tokio_postgres::Config::from_str(&runtime).unwrap();
        let (client, connection) = pg.connect(tokio_postgres::NoTls).await.unwrap();
        let driver = tokio::spawn(async move { let _ = connection.await; });
        client.batch_execute(&format!("SET ROLE {schema}_runtime")).await.unwrap();
        client.query_one(
            "SELECT set_config('smesh.tenant_scope','tenant-race',false), set_config('smesh.account_id','account-race',false)",
            &[],
        ).await.unwrap();
        client.execute(
            &format!("UPDATE {schema}.tasks SET state='\"TASK_STATE_COMPLETED\"' WHERE tenant_scope='tenant-race' AND task_id='task-release-one'"),
            &[],
        ).await.unwrap();
        client.execute(
            &format!("UPDATE {schema}.tasks SET state='\"TASK_STATE_COMPLETED\"' WHERE tenant_scope='tenant-race' AND task_id='task-release-one'"),
            &[],
        ).await.unwrap();
        assert_eq!(store.quota_used_units(
            "tenant-race", smesh_a2a::QuotaScopeKind::Principal, "principal-race",
            smesh_a2a::QuotaOperation::TaskCreate,
            smesh_a2a::QuotaDimension::ConcurrentActiveWork,
        ).await.unwrap(), 0);
        drop(client);
        driver.abort();
        store.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }).await.expect("quota release watchdog");
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn continuation_charges_its_typed_operation_once_without_second_active_allocation() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let Some(admin) = admin_url() else {
            return;
        };
        let runtime = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let schema = format!("smesh_quota_continue_{:016x}", rand::random::<u64>());
        let quota_policy = policy();
        let config = PostgresStoreConfig::new(&admin, &runtime, &schema)
            .unwrap()
            .with_test_only_insecure_loopback(true)
            .with_quota_policy(Arc::clone(&quota_policy));
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let scope =
            OwnedTaskScope::new("tenant-race", "account-race", VisibilityScope::Own).unwrap();
        let subject =
            QuotaSubject::new("tenant-race", "account-race", "principal-race").unwrap();

        let mut first = command("continuation");
        first.streaming = true;
        let first_bytes = serde_json::to_vec(&first.request).unwrap().len() as u64;
        let first_intent = quota_policy
            .admission_intent(&subject, "continuation", first_bytes, first.streaming)
            .unwrap();
        store
            .authorize_and_admit_mutation(
                &scope,
                AuthorizedMutation::with_quota_intent(first.clone(), first_intent),
                audit_for_policy(
                    &first,
                    "continuation-create",
                    "TaskCreate",
                    "policy-p1",
                    1,
                    "digest-p1",
                ),
            )
            .await
            .unwrap();

        let mut paused = first.task.clone();
        paused.status.state = a2a::TaskState::InputRequired;
        paused.status.timestamp = chrono::DateTime::from_timestamp_millis(1_700_000_000_001);
        let paused_json = serde_json::to_string(&paused).unwrap();
        let pg = tokio_postgres::Config::from_str(&runtime).unwrap();
        let (client, connection) = pg.connect(tokio_postgres::NoTls).await.unwrap();
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        client
            .batch_execute(&format!("SET ROLE {schema}_runtime"))
            .await
            .unwrap();
        client
            .query_one(
                "SELECT set_config('smesh.tenant_scope','tenant-race',false), set_config('smesh.account_id','account-race',false)",
                &[],
            )
            .await
            .unwrap();
        client
            .execute(
                &format!("UPDATE {schema}.tasks SET state='\"TASK_STATE_INPUT_REQUIRED\"',task_json=$1 WHERE tenant_scope='tenant-race' AND task_id='task-continuation'"),
                &[&paused_json],
            )
            .await
            .unwrap();
        client
            .execute(
                &format!("UPDATE {schema}.outbox SET state='superseded',updated_at=$1 WHERE tenant_scope='tenant-race' AND task_id='task-continuation' AND state='pending'"),
                &[&first.now],
            )
            .await
            .unwrap();
        drop(client);
        driver.abort();

        let mut followup = command("followup");
        followup.streaming = true;
        followup.task = paused.clone();
        followup.original_result = a2a::SendMessageResponse::Task(paused.clone());
        followup.request.message.task_id = Some(paused.id.clone());
        followup.request.message.context_id = Some(paused.context_id.clone());
        let bytes = serde_json::to_vec(&followup.request).unwrap().len() as u64;
        let intent = quota_policy
            .operation_intent(
                &subject,
                smesh_a2a::QuotaOperation::TaskContinue,
                "message-followup",
                bytes,
            )
            .unwrap();
        let continuation_audit = audit_for_policy(
            &followup,
            "continuation-followup",
            "TaskContinue",
            "policy-p2",
            2,
            "digest-p2",
        );
        store
            .authorize_and_continue_mutation(
                &scope,
                AuthorizedMutation::with_quota_intent(followup.clone(), intent),
                continuation_audit.clone(),
            )
            .await
            .unwrap();

        let continuation_sender = store
            .claim_outbox("continuation-sender", followup.now + 2, 60_000)
            .await
            .unwrap()
            .expect("continuation dispatch must be claimable");
        let continuation_receiver = match store
            .begin_receive(
                smesh_a2a::DurableDispatchEnvelope {
                    tenant_scope: continuation_sender.tenant_scope.clone(),
                    dispatch_id: continuation_sender.dispatch_id.clone(),
                    payload_digest: smesh_a2a::content_digest(
                        &serde_json::to_vec(&continuation_sender.request).unwrap(),
                    ),
                    request: continuation_sender.request.clone(),
                    execution_reservation: continuation_sender.execution_reservation.clone(),
                },
                "continuation-receiver",
                followup.now + 3,
                60_000,
            )
            .await
            .unwrap()
        {
            ReceiverAdmission::Execute(lease) => lease,
            other => panic!("expected continuation receiver execution, got {other:?}"),
        };
        let continuation_context = store
            .load_runtime_authority_context(
                &continuation_sender,
                &continuation_receiver,
                followup.now + 3,
            )
            .await
            .expect("continuation must load its own causative P2 authority");
        assert_eq!(
            continuation_context.scope().authorization_policy_id(),
            "policy-p2"
        );
        assert_eq!(
            continuation_context.scope().authorization_policy_revision(),
            2
        );
        assert_eq!(
            continuation_context.scope().authorization_policy_digest(),
            "digest-p2"
        );
        assert_eq!(continuation_context.scope().principal_scope(), "account-race");
        assert_eq!(
            continuation_context.scope().authentication_method(),
            "trusted-local"
        );
        assert_eq!(continuation_context.scope().visibility(), VisibilityScope::Own);
        assert_eq!(
            continuation_context.authorized_request_digest(),
            smesh_a2a::canonical_send_message_digest_v2(
                "tenant-race",
                "account-race",
                &followup.request,
                followup.streaming,
            )
            .unwrap()
        );
        let unrelated = AuthorizationAuditInput::new(
            "audit-continuation-unrelated",
            "tenant-race",
            "account-race",
            "policy-p2",
            2,
            "digest-p2",
            "TaskGet",
            AuthorizationDecisionEffect::Allow,
            "unrelated allow",
            "send-message-request",
            continuation_context.authorized_request_digest(),
            Some(followup.task.id.clone()),
            followup.now,
        )
        .unwrap();
        store
            .append_authorization_decision(unrelated)
            .await
            .unwrap();
        let unary_digest = smesh_a2a::canonical_send_message_digest_v2(
            "tenant-race",
            "account-race",
            &followup.request,
            false,
        )
        .unwrap();
        assert_ne!(unary_digest, continuation_context.authorized_request_digest());
        let unary_substitute = AuthorizationAuditInput::new(
            "audit-continuation-unary-substitute",
            "tenant-race",
            "account-race",
            "policy-p2",
            2,
            "digest-p2",
            "TaskContinue",
            AuthorizationDecisionEffect::Allow,
            "unary substitution",
            "send-message-request",
            unary_digest,
            None,
            followup.now,
        )
        .unwrap();
        store
            .append_authorization_decision(unary_substitute)
            .await
            .unwrap();
        let (tamper_client, tamper_connection) =
            tokio_postgres::connect(&admin, tokio_postgres::NoTls)
                .await
                .unwrap();
        let tamper_driver = tokio::spawn(tamper_connection);
        tamper_client
            .query_one(
                "SELECT set_config('smesh.internal_global','diag-v1',false),
                        set_config('smesh.tenant_scope','tenant-race',false)",
                &[],
            )
            .await
            .unwrap();
        let continuation_evidence = tamper_client
            .query_one(
                &format!(
                    "SELECT d.decision_id,d.operation,d.resource_kind,d.resource_digest,
                            d.actor_account_id,d.policy_id,d.policy_revision,d.policy_digest,
                            i.authorization_principal_scope,i.authorization_authentication_method,
                            i.authorization_visibility
                     FROM {schema}.idempotency_records i
                     JOIN {schema}.authorization_decisions d
                       ON d.tenant_scope=i.tenant_scope
                      AND d.decision_id=i.authorization_decision_id
                     WHERE d.decision_id=$1"
                ),
                &[&continuation_audit.decision_id()],
            )
            .await
            .unwrap();
        assert_eq!(continuation_evidence.get::<_, &str>(0), continuation_audit.decision_id());
        assert_eq!(continuation_evidence.get::<_, &str>(1), "TaskContinue");
        assert_eq!(continuation_evidence.get::<_, &str>(2), "send-message-request");
        assert_eq!(
            continuation_evidence.get::<_, &str>(3),
            continuation_context.authorized_request_digest()
        );
        assert_eq!(continuation_evidence.get::<_, &str>(4), "account-race");
        assert_eq!(continuation_evidence.get::<_, &str>(5), "policy-p2");
        assert_eq!(continuation_evidence.get::<_, i64>(6), 2);
        assert_eq!(continuation_evidence.get::<_, &str>(7), "digest-p2");
        assert_eq!(continuation_evidence.get::<_, &str>(8), "account-race");
        assert_eq!(continuation_evidence.get::<_, &str>(9), "trusted-local");
        assert_eq!(continuation_evidence.get::<_, &str>(10), "own");
        tamper_client
            .batch_execute(&format!(
                "ALTER TABLE {schema}.idempotency_records DISABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.retained_authority_usage DISABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.idempotency_records DISABLE TRIGGER idempotency_runtime_authority_immutable;"
            ))
            .await
            .unwrap();
        let set_continuation_authority = |decision: &str, policy: &str, revision: i64, digest: &str| {
            format!(
                "UPDATE {schema}.idempotency_records SET authorization_decision_id='{decision}',authorization_policy_id='{policy}',authorization_policy_revision={revision},authorization_policy_digest='{digest}' WHERE tenant_scope='tenant-race' AND task_id='task-continuation' AND message_id<>'{}'",
                smesh_a2a::authorized_message_identity("tenant-race", "account-race", &first.request.message.message_id)
            )
        };
        tamper_client
            .batch_execute(&set_continuation_authority(
                "audit-continuation-create",
                "policy-p1",
                1,
                "digest-p1",
            ))
            .await
            .unwrap();
        let error = store
            .load_runtime_authority_context(
                &continuation_sender,
                &continuation_receiver,
                followup.now + 3,
            )
            .await
            .expect_err("coherent substitution of initial P1 must not authorize continuation");
        assert_eq!(
            (error.code, error.message.as_str(), error.details),
            (-32603, "durable runtime authority unavailable", None)
        );
        tamper_client
            .batch_execute(&set_continuation_authority(
                "audit-continuation-unary-substitute",
                "policy-p2",
                2,
                "digest-p2",
            ))
            .await
            .unwrap();
        let error = store
            .load_runtime_authority_context(
                &continuation_sender,
                &continuation_receiver,
                followup.now + 3,
            )
            .await
            .expect_err("unary decision digest must not authorize streaming continuation");
        assert_eq!(
            (error.code, error.message.as_str(), error.details),
            (-32603, "durable runtime authority unavailable", None)
        );
        tamper_client
            .batch_execute(&set_continuation_authority(
                "audit-continuation-unrelated",
                "policy-p2",
                2,
                "digest-p2",
            ))
            .await
            .unwrap();
        let error = store
            .load_runtime_authority_context(
                &continuation_sender,
                &continuation_receiver,
                followup.now + 3,
            )
            .await
            .expect_err("allow for another operation must not authorize continuation");
        assert_eq!((error.code, error.message.as_str(), error.details), (-32603, "durable runtime authority unavailable", None));
        tamper_client
            .batch_execute(&set_continuation_authority(
                continuation_audit.decision_id(),
                "policy-p2",
                2,
                "digest-p2",
            ))
            .await
            .unwrap();
        tamper_client
            .batch_execute(&format!(
                "ALTER TABLE {schema}.idempotency_records ENABLE TRIGGER idempotency_runtime_authority_immutable;
                 ALTER TABLE {schema}.retained_authority_usage ENABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.retained_authority_usage FORCE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.idempotency_records ENABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.idempotency_records FORCE ROW LEVEL SECURITY;"
            ))
            .await
            .unwrap();
        drop(tamper_client);
        tamper_driver.abort();

        assert_eq!(
            store
                .quota_used_units(
                    "tenant-race",
                    smesh_a2a::QuotaScopeKind::Principal,
                    "principal-race",
                    smesh_a2a::QuotaOperation::TaskContinue,
                    smesh_a2a::QuotaDimension::RequestCount,
                )
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .quota_used_units(
                    "tenant-race",
                    smesh_a2a::QuotaScopeKind::Principal,
                    "principal-race",
                    smesh_a2a::QuotaOperation::TaskContinue,
                    smesh_a2a::QuotaDimension::ConcurrentActiveWork,
                )
                .await
                .unwrap(),
            0
        );

        let cancel_intent = quota_policy
            .operation_intent(
                &subject,
                smesh_a2a::QuotaOperation::TaskCancel,
                "cancel-decision",
                0,
            )
            .unwrap();
        store
            .cancel_authorized_with_quota(
                &scope,
                "task-continuation",
                1_700_000_000_002,
                audit("continuation-cancel"),
                None,
                Some(&cancel_intent),
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .quota_used_units(
                    "tenant-race",
                    smesh_a2a::QuotaScopeKind::Principal,
                    "principal-race",
                    smesh_a2a::QuotaOperation::TaskCancel,
                    smesh_a2a::QuotaDimension::RequestCount,
                )
                .await
                .unwrap(),
            1
        );
        let pg = tokio_postgres::Config::from_str(&runtime).unwrap();
        let (client, connection) = pg.connect(tokio_postgres::NoTls).await.unwrap();
        let driver = tokio::spawn(async move { let _ = connection.await; });
        client.batch_execute(&format!("SET ROLE {schema}_runtime")).await.unwrap();
        client.query_one("SELECT set_config('smesh.tenant_scope','tenant-race',false),set_config('smesh.account_id','account-race',false)", &[]).await.unwrap();
        let states = client.query_one(&format!("SELECT count(*) FILTER (WHERE state='reserved'),count(*) FILTER (WHERE state='settled') FROM {schema}.quota_execution_reservations"), &[]).await.unwrap();
        assert_eq!(
            (states.get::<_, i64>(0), states.get::<_, i64>(1)),
            (1, 1),
            "receiver-admitted continuation stays reserved for reconciliation while cancellation settles only the non-admitted allocation"
        );
        drop(client);
        driver.abort();

        store.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    })
    .await
    .expect("continuation quota watchdog");
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn startup_rejects_same_revision_with_a_different_policy_digest() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let Some(admin) = admin_url() else {
            return;
        };
        let runtime = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let schema = format!("smesh_quota_policy_{:016x}", rand::random::<u64>());
        let baseline = policy();
        let config = PostgresStoreConfig::new(&admin, &runtime, &schema)
            .unwrap()
            .with_test_only_insecure_loopback(true)
            .with_quota_policy(Arc::clone(&baseline));
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let scope =
            OwnedTaskScope::new("tenant-race", "account-race", VisibilityScope::Own).unwrap();
        let subject = QuotaSubject::new("tenant-race", "account-race", "principal-race").unwrap();
        let admission = command("policy-snapshot");
        let bytes = serde_json::to_vec(&admission.request).unwrap().len() as u64;
        let intent = baseline
            .admission_intent(&subject, "policy-snapshot", bytes, false)
            .unwrap();
        store
            .authorize_and_admit_mutation(
                &scope,
                AuthorizedMutation::with_quota_intent(admission, intent),
                audit("policy-snapshot"),
            )
            .await
            .unwrap();

        let get_audit = audit("quota-get");
        let get_intent = baseline
            .operation_intent(
                &subject,
                smesh_a2a::QuotaOperation::TaskGet,
                get_audit.decision_id(),
                0,
            )
            .unwrap();
        assert!(
            store
                .get_authorized_with_quota(
                    &scope,
                    "task-policy-snapshot",
                    get_audit,
                    Some(&get_intent),
                )
                .await
                .unwrap()
                .is_some()
        );
        let list_audit = audit("quota-list");
        let list_intent = baseline
            .operation_intent(
                &subject,
                smesh_a2a::QuotaOperation::TaskList,
                list_audit.decision_id(),
                0,
            )
            .unwrap();
        store
            .list_authorized_with_quota(
                &scope,
                &a2a::ListTasksRequest {
                    context_id: None,
                    status: None,
                    page_size: Some(10),
                    page_token: None,
                    history_length: None,
                    status_timestamp_after: None,
                    include_artifacts: Some(false),
                    tenant: None,
                },
                list_audit,
                "quota-list-cursor",
                Some(&list_intent),
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .quota_used_units(
                    "tenant-race",
                    smesh_a2a::QuotaScopeKind::Principal,
                    "principal-race",
                    smesh_a2a::QuotaOperation::TaskGet,
                    smesh_a2a::QuotaDimension::RequestCount,
                )
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .quota_used_units(
                    "tenant-race",
                    smesh_a2a::QuotaScopeKind::Principal,
                    "principal-race",
                    smesh_a2a::QuotaOperation::TaskList,
                    smesh_a2a::QuotaDimension::RequestCount,
                )
                .await
                .unwrap(),
            1
        );
        store.shutdown().await.unwrap();

        let changed = PostgresStoreConfig::new(&admin, &runtime, &schema)
            .unwrap()
            .with_test_only_insecure_loopback(true)
            .with_test_only_parent_managed_cleanup()
            .with_quota_policy(same_revision_different_policy());
        assert!(PostgresTaskStore::open(changed).await.is_err());
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    })
    .await
    .expect("policy reconciliation watchdog");
}

#[tokio::test]
async fn lower_revision_requires_exact_audited_plan_then_migrates_once_without_reset() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let Some(admin) = admin_url() else { return };
        let runtime = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let schema = format!("smesh_quota_reconcile_{:016x}", rand::random::<u64>());
        let baseline = policy();
        let config = PostgresStoreConfig::new(&admin, &runtime, &schema).unwrap()
            .with_test_only_insecure_loopback(true)
            .with_quota_policy(Arc::clone(&baseline));
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let scope = OwnedTaskScope::new("tenant-race", "account-race", VisibilityScope::Own).unwrap();
        let subject = QuotaSubject::new("tenant-race", "account-race", "principal-race").unwrap();
        let admission = command("reconcile");
        let bytes = serde_json::to_vec(&admission.request).unwrap().len() as u64;
        let intent = baseline.admission_intent(&subject, "reconcile", bytes, false).unwrap();
        store.authorize_and_admit_mutation(&scope, AuthorizedMutation::with_quota_intent(admission.clone(), intent), audit("reconcile")).await.unwrap();
        store.shutdown().await.unwrap();

        let lower = lower_revision_policy();
        let refused = PostgresStoreConfig::new(&admin, &runtime, &schema).unwrap()
            .with_test_only_insecure_loopback(true)
            .with_test_only_parent_managed_cleanup()
            .with_quota_policy(Arc::clone(&lower));
        match PostgresTaskStore::open(refused).await {
            Err(smesh_a2a::PostgresStoreError::ReconciliationRequired) => {}
            Err(error) => panic!("unexpected lower-policy refusal: {error:?}"),
            Ok(opened) => {
                opened.shutdown().await.unwrap();
                panic!("lower policy unexpectedly opened without reconciliation")
            }
        }
        let plan = QuotaReconciliationPlan::drain(
            baseline.digest(), lower.digest(), "operator-primary", "ticket-14", 1_700_000_000_100,
            vec![QuotaReconciliationTarget::new("tenant-race", smesh_a2a::QuotaScopeKind::Principal, smesh_a2a::QuotaDimension::RequestCount).unwrap()],
        ).unwrap();
        let migrated = PostgresStoreConfig::new(&admin, &runtime, &schema).unwrap()
            .with_test_only_insecure_loopback(true)
            .with_test_only_parent_managed_cleanup()
            .with_quota_policy(Arc::clone(&lower))
            .with_quota_reconciliation_plan(plan);
        let reopened = PostgresTaskStore::open(migrated).await.unwrap();
        let replay_intent = lower
            .admission_intent(&subject, "reconcile", bytes, false)
            .unwrap();
        let replay = reopened
            .authorize_and_admit_mutation(
                &scope,
                AuthorizedMutation::with_quota_intent(admission, replay_intent),
                audit("reconcile-current-policy-replay"),
            )
            .await
            .expect("exact replay must use its retained policy snapshot");
        assert!(matches!(replay, smesh_a2a::AdmissionOutcome::Replay(_)));
        let pg = tokio_postgres::Config::from_str(&superuser_url()).unwrap();
        let (client, connection) = pg.connect(tokio_postgres::NoTls).await.unwrap();
        let driver = tokio::spawn(async move { let _ = connection.await; });
        let replay_receipts = client.query_one(
            &format!("SELECT count(*),count(*) FILTER (WHERE policy_digest=$1),count(*) FILTER (WHERE policy_digest=$2),count(DISTINCT mutation_binding_digest) FROM {schema}.quota_request_receipts WHERE tenant_scope='tenant-race'"),
            &[&baseline.digest(), &lower.digest()],
        ).await.unwrap();
        assert_eq!(replay_receipts.get::<_, i64>(0), 6, "request and input replay charges must retain exact tenant/account/principal row scope");
        assert_eq!(replay_receipts.get::<_, i64>(1), 6, "replay charges must target the retained old policy");
        assert_eq!(replay_receipts.get::<_, i64>(2), 0, "the current policy must not rewrite a durable replay binding");
        assert_eq!(replay_receipts.get::<_, i64>(3), 1);
        let row = client.query_one(&format!("SELECT count(*),min(new_policy_revision),max(new_policy_revision) FROM {schema}.quota_policy_reconciliation_audits"), &[]).await.unwrap();
        assert_eq!((row.get::<_, i64>(0), row.get::<_, i64>(1), row.get::<_, i64>(2)), (1,2,2));
        let versions = client.query(&format!("SELECT policy_digest,lifecycle FROM {schema}.quota_policy_versions WHERE tenant_scope='tenant-race' ORDER BY policy_revision"), &[]).await.unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].get::<_, String>(1), "draining");
        assert_eq!(versions[1].get::<_, String>(1), "active");
        assert_eq!(versions[0].get::<_, String>(0), baseline.digest());
        client.execute(&format!("UPDATE {schema}.outbox SET state='dead',last_error='policy-upgrade-settlement',updated_at=1700000000200 WHERE tenant_scope='tenant-race' AND task_id='task-reconcile'"), &[]).await.unwrap();
        let settled = client.query_one(&format!("SELECT (SELECT count(*) FROM {schema}.quota_execution_reservations WHERE tenant_scope='tenant-race' AND state='settled'),(SELECT count(*) FROM {schema}.quota_buckets WHERE tenant_scope='tenant-race' AND policy_digest=$1),(SELECT COALESCE(sum(used_units),0)::bigint FROM {schema}.quota_buckets WHERE tenant_scope='tenant-race' AND policy_digest=$1 AND dimension IN ('outputBytes','eventCount'))"), &[&baseline.digest()]).await.unwrap();
        assert_eq!(settled.get::<_, i64>(0), 1);
        assert!(settled.get::<_, i64>(1) > 0, "draining bucket identity must survive settlement");
        assert_eq!(settled.get::<_, i64>(2), 0, "completion refunds old-policy reserved capacity");
        drop(client); driver.abort();
        reopened.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }).await.expect("lower policy reconciliation watchdog");
}

#[tokio::test]
async fn policy_upgrade_does_not_copy_live_gauges_or_refundable_reservations() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let Some(admin) = admin_url() else { return };
        let runtime = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let schema = format!("smesh_quota_no_phantom_{:016x}", rand::random::<u64>());
        let baseline = policy();
        let config = PostgresStoreConfig::new(&admin, &runtime, &schema).unwrap()
            .with_test_only_insecure_loopback(true)
            .with_quota_policy(Arc::clone(&baseline));
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let scope = OwnedTaskScope::new("tenant-race", "account-race", VisibilityScope::Own).unwrap();
        let subject = QuotaSubject::new("tenant-race", "account-race", "principal-race").unwrap();
        let old = command("old-policy-live");
        let old_bytes = serde_json::to_vec(&old.request).unwrap().len() as u64;
        let old_intent = baseline.admission_intent(&subject, "old-policy-live", old_bytes, false).unwrap();
        store.authorize_and_admit_mutation(&scope, AuthorizedMutation::with_quota_intent(old, old_intent), audit("old-policy-live")).await.unwrap();
        store.shutdown().await.unwrap();

        let current = revision_two_policy();
        let upgraded = PostgresStoreConfig::new(&admin, &runtime, &schema).unwrap()
            .with_test_only_insecure_loopback(true)
            .with_test_only_parent_managed_cleanup()
            .with_quota_policy(Arc::clone(&current));
        let reopened = PostgresTaskStore::open(upgraded).await.unwrap();
        let pg = tokio_postgres::Config::from_str(&superuser_url()).unwrap();
        let (client, connection) = pg.connect(tokio_postgres::NoTls).await.unwrap();
        let driver = tokio::spawn(async move { let _ = connection.await; });
        let current_usage: i64 = client.query_one(
            &format!("SELECT COALESCE(sum(used_units),0)::bigint FROM {schema}.quota_buckets WHERE tenant_scope='tenant-race' AND policy_digest=$1 AND dimension IN ('concurrentActiveWork','outputBytes','eventCount')"),
            &[&current.digest()],
        ).await.unwrap().get(0);
        assert_eq!(current_usage, 0, "new policy must not contain copied live or refundable usage");

        let blocked = command("new-policy-blocked");
        let blocked_bytes = serde_json::to_vec(&blocked.request).unwrap().len() as u64;
        let blocked_intent = current.admission_intent(&subject, "new-policy-blocked", blocked_bytes, false).unwrap();
        assert_eq!(reopened.authorize_and_admit_mutation(&scope, AuthorizedMutation::with_quota_intent(blocked, blocked_intent), audit("new-policy-blocked")).await.unwrap_err().code, -32_010,
            "old refundable reservation must constrain current-policy projected capacity");

        client.execute(&format!("UPDATE {schema}.outbox SET state='dead',last_error='old-policy-terminal',updated_at=1700000000200 WHERE tenant_scope='tenant-race' AND task_id='task-old-policy-live'"), &[]).await.unwrap();
        client.execute(&format!("UPDATE {schema}.tasks SET state='\"TASK_STATE_COMPLETED\"' WHERE tenant_scope='tenant-race' AND task_id='task-old-policy-live'"), &[]).await.unwrap();
        let after_release: i64 = client.query_one(
            &format!("SELECT COALESCE(sum(used_units),0)::bigint FROM {schema}.quota_buckets WHERE tenant_scope='tenant-race' AND policy_digest=$1 AND dimension IN ('concurrentActiveWork','outputBytes','eventCount')"),
            &[&current.digest()],
        ).await.unwrap().get(0);
        assert_eq!(after_release, 0, "old settlement must not decrement or leave phantom current-policy buckets");

        let admitted = command("new-policy-admitted");
        let admitted_bytes = serde_json::to_vec(&admitted.request).unwrap().len() as u64;
        let admitted_intent = current.admission_intent(&subject, "new-policy-admitted", admitted_bytes, false).unwrap();
        reopened.authorize_and_admit_mutation(&scope, AuthorizedMutation::with_quota_intent(admitted, admitted_intent), audit("new-policy-admitted")).await.unwrap();
        drop(client); driver.abort();
        reopened.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }).await.expect("cross-policy canonical accounting watchdog");
}

#[tokio::test]
async fn retained_usage_is_materialized_exact_and_bounded_gc_releases_expired_rows() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let Some(admin) = admin_url() else { return };
        let runtime = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let schema = format!("smesh_quota_retained_{:016x}", rand::random::<u64>());
        let quota_policy = policy();
        let config = PostgresStoreConfig::new(&admin, &runtime, &schema).unwrap()
            .with_test_only_insecure_loopback(true)
            .with_quota_policy(Arc::clone(&quota_policy));
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let scope = OwnedTaskScope::new("tenant-race", "account-race", VisibilityScope::Own).unwrap();
        let subject = QuotaSubject::new("tenant-race", "account-race", "principal-race").unwrap();
        let admission = command("retained");
        let bytes = serde_json::to_vec(&admission.request).unwrap().len() as u64;
        let intent = quota_policy.admission_intent(&subject, "retained", bytes, false).unwrap();
        store.authorize_and_admit_mutation(
            &scope,
            AuthorizedMutation::with_quota_intent(admission, intent),
            audit("retained"),
        ).await.unwrap();

        let pg = tokio_postgres::Config::from_str(&superuser_url()).unwrap();
        let (client, connection) = pg.connect(tokio_postgres::NoTls).await.unwrap();
        let driver = tokio::spawn(async move { let _ = connection.await; });
        let denial_key = smesh_a2a::content_digest(b"gc-denial-key");
        let denial_content = smesh_a2a::content_digest(b"gc-denial-content");
        let denial_bucket = smesh_a2a::content_digest(b"gc-denial-bucket");
        let denial_reason = smesh_a2a::content_digest(b"gc-denial-reason");
        client.execute(
            &format!("INSERT INTO {schema}.quota_denial_audits(tenant_scope,decision_key,content_digest,policy_digest,bucket_digest,reason_digest,retry_after_seconds,denied_at) VALUES('tenant-race',$1,$2,$3,$4,$5,1,1)"),
            &[&denial_key,&denial_content,&quota_policy.digest(),&denial_bucket,&denial_reason],
        ).await.unwrap();
        let before = store.retained_authority_bytes("tenant-race", Some("principal-race")).await.unwrap();
        assert!(before.0 > 0);
        assert!(before.1 > 0);
        let oracle: i64 = client.query_one(
            &format!("SELECT {schema}.retained_authority_oracle('tenant-race',NULL)"), &[]
        ).await.unwrap().get(0);
        assert_eq!(before.0, u64::try_from(oracle).unwrap());
        client.execute(
            &format!("UPDATE {schema}.quota_denial_audits SET denied_at=1 WHERE tenant_scope='tenant-race'"), &[]
        ).await.unwrap();
        drop(client); driver.abort();

        let deleted = store.gc_quota_authority(1_700_000_000_000, 1).await.unwrap();
        assert_eq!(deleted, 1, "the deterministic fixture seeds exactly one expired denial row");
        let after = store.retained_authority_bytes("tenant-race", Some("principal-race")).await.unwrap();
        assert!(after.0 < before.0, "deleting the seeded row must strictly reduce retained tenant bytes");

        store.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }).await.expect("retained accounting and gc watchdog");
}

#[test]
fn runtime_membership_validation_is_recursive_and_option_exact() {
    let source = include_str!("../src/postgres_store.rs");
    let start = source.find("async fn validate_runtime_login").unwrap();
    let end = start + source[start..].find("async fn migrate").unwrap();
    let validation = &source[start..end];
    for fragment in [
        "WITH RECURSIVE membership_walk",
        "am.inherit_option",
        "am.set_option",
        "cycle",
        "depth",
        "admin_option",
        "rolbypassrls",
        "rolsuper",
    ] {
        assert!(
            validation.contains(fragment),
            "membership validation missing {fragment}"
        );
    }
}

#[test]
fn quota_lease_reclaim_is_explicitly_bounded_and_skip_locked() {
    let source = include_str!("../src/postgres_store.rs");
    let start = source
        .find("async fn reclaim_expired_quota_leases")
        .unwrap();
    let end = start
        + source[start..]
            .find("async fn append_quota_denial_audit")
            .unwrap();
    let reclaim = &source[start..end];
    for fragment in [
        "batch_size: u32",
        "if !(1..=1000).contains(&batch_size)",
        "ORDER BY lease_until,lease_id",
        "FOR UPDATE SKIP LOCKED LIMIT $3",
        "UPDATE __S__.quota_leases l",
    ] {
        assert!(
            reclaim.contains(fragment),
            "unbounded reclaim; missing {fragment}"
        );
    }
    assert!(!reclaim.contains("UPDATE __S__.quota_leases SET state='expired'"));
}

#[test]
fn postgres_quota_required_mode_cannot_silently_skip() {
    let source = include_str!("postgres_quota.rs");
    assert_eq!(
        source
            .matches("env::var(\"SMESH_TEST_POSTGRES_ADMIN_URL\")")
            .count(),
        1
    );
    assert!(source.contains("SMESH_TEST_POSTGRES_ADMIN_URL is required"));
    assert!(!source.contains("env::var(\"SMESH_TEST_POSTGRES_ADMIN_URL\").ok()"));
}

#[test]
fn quota_gc_declares_the_exact_evidence_horizon_and_dependency_order() {
    let migration = include_str!("../migrations/postgres/0004_distributed_quota_authority.sql");
    assert!(migration.contains("Quota evidence replay horizon: 86400000 ms"));
    let gc = &migration[migration
        .find("CREATE FUNCTION __SCHEMA__.gc_quota_authority_bounded")
        .unwrap()..];
    let allocation = gc.find("DELETE FROM __SCHEMA__.quota_allocations").unwrap();
    let receipt = gc.find("DELETE FROM __SCHEMA__.quota_receipts").unwrap();
    let intent = gc.find("DELETE FROM __SCHEMA__.quota_intents").unwrap();
    let bucket = gc.find("DELETE FROM __SCHEMA__.quota_buckets").unwrap();
    let policy = gc
        .find("DELETE FROM __SCHEMA__.quota_policy_versions")
        .unwrap();
    assert!(allocation < receipt && receipt < intent && intent < bucket && bucket < policy);
    assert!(gc.contains("FOR UPDATE SKIP LOCKED"));
    assert!(gc.contains("retention_until<=now_ms"));
    for reference in [
        "quota_intents i WHERE i.tenant_scope=p.tenant_scope AND i.policy_digest=p.policy_digest",
        "quota_buckets b WHERE b.tenant_scope=p.tenant_scope AND b.policy_digest=p.policy_digest",
        "quota_request_receipts r WHERE r.tenant_scope=p.tenant_scope AND r.policy_digest=p.policy_digest",
        "quota_execution_reservations e WHERE e.tenant_scope=p.tenant_scope AND e.policy_digest=p.policy_digest",
        "quota_override_audits o WHERE o.tenant_scope=p.tenant_scope AND o.policy_digest=p.policy_digest",
        "quota_policy_reconciliation_audits a WHERE a.tenant_scope=p.tenant_scope AND (a.old_policy_digest=p.policy_digest OR a.new_policy_digest=p.policy_digest)",
    ] {
        assert!(
            gc.contains(reference),
            "policy GC omits reference: {reference}"
        );
    }
}

#[test]
fn every_live_mutation_path_avoids_global_capacity_lock_and_full_oracle_scan() {
    let source = include_str!("../src/postgres_store.rs");
    let runner_start = source.find("async fn run_retryable_transaction").unwrap();
    let startup_start = source.find("async fn reconcile_quota_policy").unwrap();
    let live = &source[runner_start..startup_start];
    assert!(
        !live.contains("6001136200064"),
        "live call graph contains the global quota lock"
    );
    assert!(
        !live.contains("ensure_capacity("),
        "live call graph invokes the full retained oracle"
    );
    assert!(
        !live.contains("ensure_all_tenant_capacity("),
        "live call graph invokes the all-tenant oracle"
    );
    assert!(
        !live.contains("retained_authority_oracle("),
        "live call graph performs a full authority scan"
    );
}

#[tokio::test]
async fn long_tenant_a_counter_transaction_does_not_serialize_tenant_b() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let Some(admin) = admin_url() else { return };
        let runtime = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let schema = format!(
            "smesh_quota_tenant_isolation_{:016x}",
            rand::random::<u64>()
        );
        let quota_policy = policy();
        let config = PostgresStoreConfig::new(&admin, &runtime, &schema)
            .unwrap()
            .with_test_only_insecure_loopback(true)
            .with_quota_policy(Arc::clone(&quota_policy));
        let a = Arc::new(PostgresTaskStore::open(config.clone()).await.unwrap());
        let b = Arc::new(PostgresTaskStore::open(config.clone()).await.unwrap());
        let sa = QuotaSubject::new("tenant-a-isolated", "account-a", "principal-a").unwrap();
        let sb = QuotaSubject::new("tenant-b-isolated", "account-b", "principal-b").unwrap();
        let seed_a = quota_policy
            .operation_intent(&sa, smesh_a2a::QuotaOperation::TaskGet, "seed-a", 0)
            .unwrap();
        let seed_b = quota_policy
            .operation_intent(&sb, smesh_a2a::QuotaOperation::TaskGet, "seed-b", 0)
            .unwrap();
        a.charge_quota_request(&seed_a, 1_700_000_000_000)
            .await
            .unwrap();
        b.charge_quota_request(&seed_b, 1_700_000_000_000)
            .await
            .unwrap();
        let acquired = Arc::new(tokio::sync::Barrier::new(2));
        let release = Arc::new(tokio::sync::Barrier::new(2));
        let holder = {
            let a = Arc::clone(&a);
            let acquired = Arc::clone(&acquired);
            let release = Arc::clone(&release);
            tokio::spawn(async move {
                a.hold_test_tenant_counter_transaction(
                    "tenant-a-isolated",
                    "account-a",
                    acquired,
                    release,
                )
                .await
            })
        };
        acquired.wait().await;
        let independent = quota_policy
            .operation_intent(
                &sb,
                smesh_a2a::QuotaOperation::TaskCancel,
                "tenant-b-progress",
                0,
            )
            .unwrap();
        tokio::time::timeout(
            Duration::from_secs(2),
            b.charge_quota_request(&independent, 1_700_000_000_001),
        )
        .await
        .expect("tenant B must not wait for tenant A")
        .unwrap();
        release.wait().await;
        holder.await.unwrap().unwrap();
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    })
    .await
    .expect("two-tenant isolation watchdog");
}

#[test]
fn token_bucket_schema_has_continuous_integer_refill_state() {
    let migration = include_str!("../migrations/postgres/0004_distributed_quota_authority.sql");
    let bucket = &migration[migration
        .find("CREATE TABLE __SCHEMA__.quota_buckets")
        .unwrap()
        ..migration
            .find("CREATE TABLE __SCHEMA__.quota_receipts")
            .unwrap()];
    for required in [
        "available_tokens",
        "last_refill_at",
        "refill_numerator",
        "refill_period_millis",
    ] {
        assert!(
            bucket.contains(required),
            "missing token bucket field {required}"
        );
    }
    let source = include_str!("../src/postgres_store.rs");
    assert!(
        source.contains("::numeric*b.refill_numerator::numeric"),
        "refill must use exact overflow-safe database integer arithmetic"
    );
    assert!(
        source.contains("GREATEST($9-b.last_refill_at,0)"),
        "database-time refill must not mint on clock rollback"
    );
}

#[tokio::test]
async fn startup_rejects_missing_taskless_principal_counter() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let Some(admin) = admin_url() else { return };
        let runtime = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let schema = format!("smesh_quota_taskless_oracle_{:016x}", rand::random::<u64>());
        let quota_policy = policy();
        let config = PostgresStoreConfig::new(&admin, &runtime, &schema).unwrap()
            .with_test_only_insecure_loopback(true)
            .with_test_only_parent_managed_cleanup()
            .with_quota_policy(Arc::clone(&quota_policy));
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let subject = QuotaSubject::new("tenant-taskless", "account-taskless", "principal-taskless").unwrap();
        let intent = quota_policy.operation_intent(&subject, smesh_a2a::QuotaOperation::TaskGet, "taskless-get", 0).unwrap();
        store.charge_quota_request(&intent, 1_700_000_000_000).await.unwrap();
        store.shutdown().await.unwrap();
        let pg = tokio_postgres::Config::from_str(&superuser_url()).unwrap();
        let (client, connection) = pg.connect(tokio_postgres::NoTls).await.unwrap();
        let driver = tokio::spawn(async move { let _ = connection.await; });
        client.execute(&format!("DELETE FROM {schema}.retained_authority_usage WHERE tenant_scope='tenant-taskless' AND scope_kind='principal' AND scope_id='principal-taskless'"), &[]).await.unwrap();
        assert!(matches!(PostgresTaskStore::open(config.clone()).await, Err(smesh_a2a::PostgresStoreError::InvalidSchema)));
        drop(client); driver.abort();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }).await.expect("taskless retained oracle watchdog");
}

#[test]
fn startup_tenant_oracle_unions_every_tenant_bearing_authority_table() {
    let migration = include_str!("../migrations/postgres/0004_distributed_quota_authority.sql");
    let oracle = &migration[migration
        .find("CREATE OR REPLACE FUNCTION __SCHEMA__.authority_tenants_bounded")
        .unwrap()
        ..migration
            .find("CREATE INDEX quota_denial_audits_expiry")
            .unwrap()];
    for table in [
        "tasks",
        "task_events",
        "idempotency_records",
        "outbox",
        "outbox_attempts",
        "receiver_inbox",
        "receiver_frames",
        "loopback_effects",
        "stream_transcripts",
        "stream_frames",
        "cancellation_intents",
        "authorization_decisions",
        "list_snapshots",
        "list_snapshot_entries",
        "list_page_tokens",
        "quota_reservations",
        "quota_policy_versions",
        "quota_policy_reconciliation_audits",
        "quota_intents",
        "quota_buckets",
        "quota_receipts",
        "quota_request_receipts",
        "quota_execution_reservations",
        "quota_allocations",
        "quota_leases",
        "quota_denial_audits",
        "quota_override_audits",
        "retained_authority_usage",
    ] {
        assert!(
            oracle.contains(&format!("FROM __SCHEMA__.{table}")),
            "startup oracle omits {table}"
        );
    }
    assert!(oracle.contains("FROM __SCHEMA__.outbox_tenant_scheduler"));
    assert!(oracle.contains("SECURITY DEFINER SET search_path=pg_catalog"));
}

#[tokio::test]
async fn sustained_fair_scheduler_bounds_service_with_continuous_a_backlog() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let Some(admin) = admin_url() else { return };
        let runtime = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let schema = format!("smesh_quota_sustained_fair_{:016x}", rand::random::<u64>());
        let config = PostgresStoreConfig::new(&admin, &runtime, &schema).unwrap()
            .with_test_only_insecure_loopback(true);
        let a = PostgresTaskStore::open(config.clone()).await.unwrap();
        let b = PostgresTaskStore::open(config.clone()).await.unwrap();
        let pg = tokio_postgres::Config::from_str(&superuser_url()).unwrap();
        let (client, connection) = pg.connect(tokio_postgres::NoTls).await.unwrap();
        let driver = tokio::spawn(async move { let _ = connection.await; });
        for n in 0..100 { seed_fair_outbox(&client, &schema, "tenant-a", n).await; }
        seed_fair_outbox(&client, &schema, "tenant-b", 0).await;
        seed_fair_outbox(&client, &schema, "tenant-c", 0).await;
        let mut next = [1_usize, 1_usize];
        let mut arrivals = vec![("tenant-b".to_owned(),0_usize),("tenant-c".to_owned(),0_usize)];
        for claim_no in 0..120_usize {
            if claim_no > 0 && claim_no % 10 == 0 {
                for (idx, tenant) in ["tenant-b","tenant-c"].into_iter().enumerate() {
                    seed_fair_outbox(&client, &schema, tenant, next[idx]).await;
                    next[idx] += 1;
                    arrivals.push((tenant.to_owned(), claim_no));
                }
            }
            let store = if claim_no % 2 == 0 { &a } else { &b };
            let claim_offset = i64::try_from(claim_no).expect("bounded claim number");
            let lease = store.claim_outbox(&format!("fair-owner-{claim_no}"), 1_700_000_000_000 + claim_offset, 10_000).await.unwrap().expect("active tenant must be claimable");
            if lease.tenant_scope != "tenant-a" {
                let position = arrivals.iter().position(|(tenant,_)| tenant == &lease.tenant_scope).expect("arrival must be tracked");
                let (_, arrived) = arrivals.remove(position);
                assert!(claim_no - arrived <= 3, "{} waited {} claims", lease.tenant_scope, claim_no-arrived);
            }
            client.execute(&format!("UPDATE {schema}.outbox SET state='delivered',lease_owner=NULL,lease_token=NULL,lease_until=NULL,updated_at=$1 WHERE tenant_scope=$2 AND dispatch_id=$3"), &[&(1_700_000_100_000_i64+claim_offset),&lease.tenant_scope,&lease.dispatch_id]).await.unwrap();
            seed_fair_outbox(&client, &schema, "tenant-a", 100 + claim_no).await;
        }
        assert!(arrivals.is_empty(), "every B/C arrival must be selected within the bound");
        drop(client); driver.abort();
        a.shutdown().await.unwrap(); b.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }).await.expect("sustained fair scheduler watchdog");
}

#[tokio::test]
async fn concurrent_claimers_lock_different_tenant_scheduler_rows() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let Some(admin) = admin_url() else { return };
        let runtime = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let schema = format!("smesh_quota_parallel_fair_{:016x}", rand::random::<u64>());
        let config = PostgresStoreConfig::new(&admin, &runtime, &schema)
            .unwrap()
            .with_test_only_insecure_loopback(true);
        let a = Arc::new(PostgresTaskStore::open(config.clone()).await.unwrap());
        let b = Arc::new(PostgresTaskStore::open(config.clone()).await.unwrap());
        let pg = tokio_postgres::Config::from_str(&superuser_url()).unwrap();
        let (client, connection) = pg.connect(tokio_postgres::NoTls).await.unwrap();
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        seed_fair_outbox(&client, &schema, "tenant-a", 0).await;
        seed_fair_outbox(&client, &schema, "tenant-b", 0).await;
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let claim = |store: Arc<PostgresTaskStore>, owner: &'static str| {
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .claim_outbox(owner, 1_700_000_000_000, 10_000)
                    .await
                    .unwrap()
                    .unwrap()
            })
        };
        let one = claim(Arc::clone(&a), "parallel-a");
        let two = claim(Arc::clone(&b), "parallel-b");
        barrier.wait().await;
        let (one, two) = tokio::join!(one, two);
        let mut tenants = vec![one.unwrap().tenant_scope, two.unwrap().tenant_scope];
        tenants.sort();
        assert_eq!(tenants, vec!["tenant-a", "tenant-b"]);
        drop(client);
        driver.abort();
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    })
    .await
    .expect("parallel tenant scheduler watchdog");
}

#[test]
fn canonical_claim_function_has_only_per_tenant_scheduler_locks() {
    let migration = include_str!("../migrations/postgres/0004_distributed_quota_authority.sql");
    let start = migration
        .find("CREATE FUNCTION __SCHEMA__.claim_outbox_bounded")
        .unwrap();
    let end = start + migration[start..].find("END $$;").unwrap() + "END $$;".len();
    let claim = &migration[start..end];
    assert_eq!(
        smesh_a2a::content_digest(claim.as_bytes()),
        "sha256:d5ccf89ab192d316fbfb3f9706b3d98147fcbf266a2c718ddf162a8ecea0df6c",
        "reviewed PL/pgSQL internals changed; re-audit and update the canonical hash",
    );
    assert!(
        !claim.contains("singleton"),
        "singleton scheduler state is a global lock"
    );
    assert!(
        !claim.contains("pg_advisory"),
        "scheduler must not use a global advisory lock"
    );
    for fragment in [
        "FROM __SCHEMA__.outbox_tenant_scheduler s",
        "ORDER BY s.virtual_finish,s.served_sequence,s.tenant_scope",
        "FOR UPDATE OF s SKIP LOCKED LIMIT 1",
        "ORDER BY o.available_at,o.outbox_id FOR UPDATE OF o SKIP LOCKED LIMIT 1",
        "served_sequence=nextval('__SCHEMA__.outbox_served_sequence')",
    ] {
        assert!(
            claim.contains(fragment),
            "claim function lost canonical fragment: {fragment}"
        );
    }
}

#[tokio::test]
async fn populated_fair_scheduler_queries_use_scoped_due_indexes_without_global_sort() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let Some(admin) = admin_url() else { return };
        let runtime = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let schema = format!("smesh_quota_scheduler_plan_{:016x}", rand::random::<u64>());
        let quota_policy = policy();
        let config = PostgresStoreConfig::new(&admin, &runtime, &schema).unwrap()
            .with_test_only_insecure_loopback(true)
            .with_quota_policy(Arc::clone(&quota_policy));
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let scope = OwnedTaskScope::new("tenant-race", "account-race", VisibilityScope::Own).unwrap();
        let subject = QuotaSubject::new("tenant-race", "account-race", "principal-race").unwrap();
        let admission = command("scheduler-plan");
        let bytes = serde_json::to_vec(&admission.request).unwrap().len() as u64;
        let intent = quota_policy.admission_intent(&subject, "scheduler-plan", bytes, false).unwrap();
        store.authorize_and_admit_mutation(&scope, AuthorizedMutation::with_quota_intent(admission, intent), audit("scheduler-plan")).await.unwrap();

        let pg = tokio_postgres::Config::from_str(&superuser_url()).unwrap();
        let (client, connection) = pg.connect(tokio_postgres::NoTls).await.unwrap();
        let driver = tokio::spawn(async move { let _ = connection.await; });
        client.batch_execute(&format!("INSERT INTO {schema}.tasks(tenant_scope,task_id,context_id,state,status_timestamp,revision,task_json,owner_account_id) SELECT 'plan-'||g,'task-'||g,'context','\"TASK_STATE_SUBMITTED\"',NULL,1,'{{\"id\":\"fixture\"}}','account' FROM generate_series(1,3000) g; INSERT INTO {schema}.outbox(dispatch_id,tenant_scope,task_id,message_id,causative_revision,payload_json,payload_digest,state,attempt_count,max_attempts,available_at,created_at,updated_at,dispatch_identity_version) SELECT 'dispatch-'||g,'plan-'||g,'task-'||g,'message-'||g,1,'{{}}','digest','pending',0,3,1,1,1,1 FROM generate_series(1,3000) g; INSERT INTO {schema}.quota_intents(tenant_scope,binding_digest,account_id,principal_scope,operation,semantic_id,policy_id,policy_revision,policy_digest,created_at) SELECT 'tenant-race','sha256:'||md5(g::text)||md5(g::text),'account-race','plan-principal-'||g,'sendStream','plan-lease-'||g,'race-policy',1,'{}',1 FROM generate_series(1,2000) g; INSERT INTO {schema}.quota_leases(tenant_scope,lease_id,lease_token,lease_epoch,binding_digest,policy_digest,account_id,principal_scope,operation,lease_kind,resource_digest,lease_until,state,created_at,updated_at) SELECT 'tenant-race','sha256:'||md5(('lease'||g)::text)||md5(('lease'||g)::text),'sha256:'||md5(('token'||g)::text)||md5(('token'||g)::text),1,'sha256:'||md5(g::text)||md5(g::text),'{}','account-race','plan-principal-'||g,'sendStream','messageStream','resource-'||g,1,'active',1,1 FROM generate_series(1,2000) g; INSERT INTO {schema}.quota_buckets(tenant_scope,policy_digest,scope_kind,scope_id,operation,dimension,algorithm,window_start,window_millis,capacity,used_units,updated_at) SELECT 'tenant-race','{}','principal','plan-bucket-'||g,'taskGet','requestCount','fixedWindow',g,1000,10,0,1 FROM generate_series(1,3000) g; ANALYZE {schema}.outbox; ANALYZE {schema}.outbox_tenant_scheduler; ANALYZE {schema}.quota_buckets; ANALYZE {schema}.quota_leases; ANALYZE {schema}.retained_authority_usage;", quota_policy.digest(), quota_policy.digest(), quota_policy.digest())).await.unwrap();
        let explain = |rows: Vec<tokio_postgres::Row>| rows.into_iter().map(|row| row.get::<_,String>(0)).collect::<Vec<_>>().join("\n");
        let plans = [
            (format!("EXPLAIN (COSTS OFF) UPDATE {schema}.quota_buckets SET updated_at=updated_at WHERE tenant_scope='tenant-race' AND policy_digest='{}' AND scope_kind='tenant' AND scope_id='tenant-race' AND operation='taskCreate' AND dimension='requestCount' AND window_start=1700000000000", quota_policy.digest()), "quota_buckets_scope_lookup"),
            (format!("EXPLAIN (COSTS OFF) UPDATE {schema}.quota_buckets SET available_tokens=available_tokens WHERE tenant_scope='tenant-race' AND policy_digest='{}' AND scope_kind='principal' AND scope_id='principal-race' AND operation='reconnect' AND dimension='reconnectCount' AND window_start=0", quota_policy.digest()), "quota_buckets_scope_lookup"),
            (format!("EXPLAIN (COSTS OFF) SELECT lease_id FROM {schema}.quota_leases WHERE tenant_scope='tenant-race' AND lease_id='sha256:0000000000000000000000000000000000000000000000000000000000000000'"), "quota_leases_pkey"),
            (format!("EXPLAIN (COSTS OFF) SELECT tenant_scope,lease_id FROM {schema}.quota_leases WHERE tenant_scope='tenant-race' AND state='active' AND lease_until<=2 ORDER BY lease_until,lease_id FOR UPDATE SKIP LOCKED LIMIT 100"), "quota_leases_gc"),
            (format!("EXPLAIN (COSTS OFF) UPDATE {schema}.retained_authority_usage SET retained_bytes=retained_bytes+1 WHERE tenant_scope='tenant-race' AND scope_kind='principal' AND scope_id='principal-race'"), "retained_authority_usage_pkey"),
            (format!("EXPLAIN (COSTS OFF) SELECT s.tenant_scope FROM {schema}.outbox_tenant_scheduler s WHERE EXISTS (SELECT 1 FROM {schema}.outbox o WHERE o.tenant_scope=s.tenant_scope AND o.state='pending' AND o.available_at<=2 AND o.attempt_count<o.max_attempts) ORDER BY s.virtual_finish,s.served_sequence,s.tenant_scope LIMIT 1"), "outbox_tenant_scheduler_eligible"),
            (format!("EXPLAIN (COSTS OFF) SELECT outbox_id FROM {schema}.outbox WHERE tenant_scope='plan-1500' AND state='pending' AND available_at<=2 AND attempt_count<max_attempts ORDER BY available_at,outbox_id LIMIT 1"), "outbox_pending_tenant_due"),
        ];
        for (sql, expected_index) in plans {
            let plan = explain(client.query(&sql, &[]).await.unwrap());
            assert!(!plan.contains("Seq Scan"), "{sql}\n{plan}");
            assert!(plan.contains(expected_index), "expected {expected_index}\n{sql}\n{plan}");
        }
        drop(client); driver.abort();
        store.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }).await.expect("scheduler plan watchdog");
}
