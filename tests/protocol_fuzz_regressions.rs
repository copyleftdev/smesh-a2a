use a2a::{
    ListTasksRequest, Message, Part, Role, SendMessageResponse, Task, TaskState, TaskStatus,
};
use a2a_server::TaskStore;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac as _};
use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use sha2::Sha256;
use smesh_a2a::{
    AuthorizationPolicy, BoundedTaskStore, QuotaPolicy, RuntimeEventCapture, SqliteTaskStore,
    fuzz_decode_opaque_page_token, fuzz_parse_callback_page_token, push::PushPolicy,
    task_state_transition_allowed, transport::PrincipalMap,
};

fn task() -> Task {
    Task {
        id: "task-union".to_owned(),
        context_id: "context-union".to_owned(),
        status: TaskStatus {
            state: TaskState::Submitted,
            message: None,
            timestamp: None,
        },
        artifacts: None,
        history: None,
        metadata: None,
    }
}

fn stored_task(id: &str) -> Task {
    let mut task = task();
    id.clone_into(&mut task.id);
    task
}

#[tokio::test]
async fn memory_store_rejects_transitions_outside_shared_durable_matrix() {
    let store = BoundedTaskStore::new(4);
    let mut working = stored_task("memory-transition");
    working.status.state = TaskState::Working;
    store.create(working.clone()).await.unwrap();
    let mut submitted = working;
    submitted.status.state = TaskState::Submitted;
    assert!(store.update(submitted).await.is_err());
    assert_eq!(
        store
            .get("memory-transition")
            .await
            .unwrap()
            .unwrap()
            .status
            .state,
        TaskState::Working
    );
}

fn message() -> Message {
    let mut message = Message::new(Role::User, vec![Part::text("union")]);
    "message-union".clone_into(&mut message.message_id);
    message
}

fn callback_token(key: &[u8; 32], payload: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(b"smesh-callback-page-v1\0");
    mac.update(payload);
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(payload),
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

#[test]
fn send_message_response_rejects_ambiguous_or_unknown_union_members() {
    let task_value = serde_json::to_value(task()).unwrap();
    let message_value = serde_json::to_value(message()).unwrap();
    assert!(
        serde_json::from_value::<SendMessageResponse>(serde_json::json!({
            "task": task_value,
            "message": message_value,
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<SendMessageResponse>(serde_json::json!({
            "task": serde_json::to_value(task()).unwrap(),
            "unexpected": true,
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<SendMessageResponse>(serde_json::json!({
            "task": serde_json::to_value(task()).unwrap(),
        }))
        .is_ok()
    );
}

#[test]
fn every_a2a_field_presence_union_rejects_ambiguity_and_unknown_members() {
    assert!(
        serde_json::from_value::<Part>(serde_json::json!({"text":"a","url":"https://example.com"}))
            .is_err()
    );
    assert!(
        serde_json::from_value::<Part>(serde_json::json!({"text":"a","unknown":true})).is_err()
    );

    let task_value = serde_json::to_value(task()).unwrap();
    let message_value = serde_json::to_value(message()).unwrap();
    assert!(
        serde_json::from_value::<a2a::StreamResponse>(
            serde_json::json!({"task":task_value,"message":message_value})
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<a2a::StreamResponse>(
            serde_json::json!({"message":serde_json::to_value(message()).unwrap(),"unknown":true})
        )
        .is_err()
    );

    assert!(
        serde_json::from_value::<a2a::SecurityScheme>(serde_json::json!({
            "apiKeySecurityScheme":{"location":"header","name":"x-api-key"},
            "httpAuthSecurityScheme":{"scheme":"bearer"}
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<a2a::SecurityScheme>(serde_json::json!({
            "mtlsSecurityScheme":{},"unknown":true
        }))
        .is_err()
    );

    assert!(serde_json::from_value::<a2a::OAuthFlows>(serde_json::json!({
        "authorizationCode":{"authorizationUrl":"https://example.com/auth","tokenUrl":"https://example.com/token","scopes":{}},
        "clientCredentials":{"tokenUrl":"https://example.com/token","scopes":{}}
    })).is_err());
    assert!(
        serde_json::from_value::<a2a::OAuthFlows>(serde_json::json!({
            "password":{"tokenUrl":"https://example.com/token","scopes":{}},"unknown":true
        }))
        .is_err()
    );
    for duplicate in [
        r#"{"text":"a","text":"b"}"#,
        r#"{"task":{},"task":{}}"#,
        r#"{"message":{},"message":{}}"#,
        r#"{"mtlsSecurityScheme":{},"mtlsSecurityScheme":{}}"#,
        r#"{"password":{"tokenUrl":"x","scopes":{}},"password":{"tokenUrl":"y","scopes":{}}}"#,
    ] {
        assert!(serde_json::from_str::<serde_json::Value>(duplicate).is_ok());
    }
    assert!(serde_json::from_str::<Part>(r#"{"text":"a","text":"b"}"#).is_err());
    assert!(serde_json::from_str::<SendMessageResponse>(r#"{"task":{},"task":{}}"#).is_err());
    assert!(serde_json::from_str::<a2a::StreamResponse>(r#"{"message":{},"message":{}}"#).is_err());
    assert!(
        serde_json::from_str::<a2a::SecurityScheme>(
            r#"{"mtlsSecurityScheme":{},"mtlsSecurityScheme":{}}"#
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<a2a::OAuthFlows>(
            r#"{"password":{"tokenUrl":"x","scopes":{}},"password":{"tokenUrl":"y","scopes":{}}}"#
        )
        .is_err()
    );
}

#[test]
fn jsonrpc_envelopes_reject_unknown_and_ambiguous_members() {
    assert!(
        serde_json::from_value::<a2a::jsonrpc::JsonRpcRequest>(serde_json::json!({
            "jsonrpc":"2.0","id":1,"method":"GetTask","unknown":true
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<a2a::jsonrpc::JsonRpcResponse>(serde_json::json!({
            "jsonrpc":"2.0","id":1,"result":{},"error":{"code":-1,"message":"x"}
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<a2a::jsonrpc::JsonRpcResponse>(serde_json::json!({
            "jsonrpc":"2.0","id":1
        }))
        .is_err()
    );
    assert!(
        serde_json::from_str::<a2a::jsonrpc::JsonRpcRequest>(
            r#"{"jsonrpc":"2.0","id":1,"id":2,"method":"GetTask"}"#
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<a2a::jsonrpc::JsonRpcResponse>(serde_json::json!({
            "jsonrpc":"2.0","id":1,"result":null
        }))
        .is_ok()
    );
    assert!(
        serde_json::from_value::<a2a::jsonrpc::JsonRpcResponse>(serde_json::json!({
            "jsonrpc":"2.0","id":1,"result":{},"error":null
        }))
        .is_err()
    );
    assert!(serde_json::from_value::<Part>(serde_json::json!({"data":null})).is_ok());
    assert!(serde_json::from_value::<Part>(serde_json::json!({"text":"a","data":null})).is_err());
}

#[test]
fn minimized_page_token_mutation_corpus_fails_closed() {
    let key = [7_u8; 32];
    let valid = callback_token(&key, b"1\x1ftenant-a\x1ftask-a\x1f42\x1fconfig-a");
    assert!(fuzz_parse_callback_page_token(
        &key, &valid, "tenant-a", "task-a"
    ));
    assert!(!fuzz_parse_callback_page_token(
        &key, &valid, "tenant-b", "task-a"
    ));
    assert!(!fuzz_parse_callback_page_token(
        &key, &valid, "tenant-a", "task-b"
    ));
    for invalid in [
        format!("{valid}.extra"),
        format!("{}A", &valid[..valid.len() - 1]),
        callback_token(&key, b"1\x1ftenant-a\x1ftask-a\x1fnot-time\x1fconfig-a"),
        callback_token(&key, b"1\x1ftenant-a\x1ftask-a\x1f42\x1f"),
        callback_token(&key, b"1\x1ftenant-a\x1ftask-a\x1f42\x1fconfig-a\x1fextra"),
        callback_token(&key, &[0xff, 0xfe]),
        "A".repeat(4097),
    ] {
        assert!(!fuzz_parse_callback_page_token(
            &key, &invalid, "tenant-a", "task-a"
        ));
    }

    let opaque = URL_SAFE_NO_PAD.encode([9_u8; 32]);
    assert!(fuzz_decode_opaque_page_token(&opaque));
    for invalid in [
        String::new(),
        "!".to_owned(),
        URL_SAFE_NO_PAD.encode([0_u8; 31]),
        URL_SAFE_NO_PAD.encode([0_u8; 33]),
        "A".repeat(4097),
    ] {
        assert!(!fuzz_decode_opaque_page_token(&invalid));
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        max_shrink_iters: 2_048,
        rng_seed: RngSeed::Fixed(0x5A17_0074),
        ..ProptestConfig::default()
    })]

    #[test]
    fn arbitrary_bounded_bytes_never_escape_closed_parsers(input in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let _ = serde_json::from_slice::<a2a::SendMessageRequest>(&input);
        let _ = serde_json::from_slice::<a2a::ListTasksRequest>(&input);
        let _ = serde_json::from_slice::<a2a::SendMessageResponse>(&input);
        let _ = serde_json::from_slice::<a2a::StreamResponse>(&input);
        let _ = serde_json::from_slice::<a2a::Task>(&input);
        let _ = AuthorizationPolicy::from_json(&input);
        let _ = QuotaPolicy::from_json(&input);
        let _ = PushPolicy::parse_bytes(&input);
        let _ = PrincipalMap::from_json(&input, 8_192, 128);
        let _ = RuntimeEventCapture::replay(&input);
        if let Ok(text) = std::str::from_utf8(&input) {
            let _ = fuzz_decode_opaque_page_token(text);
            let _ = fuzz_parse_callback_page_token(&[11; 32], text, "tenant", "task");
        }
    }
}

#[test]
fn parser_errors_do_not_echo_secret_or_tenant_canaries() {
    const SECRET: &str = "FUZZ_SECRET_CANARY_NEVER_ECHO";
    const TENANT: &str = "tenant-canary-never-echo";
    let bytes = format!(r#"{{"schemaVersion":"{SECRET}","tenant":"{TENANT}"}}"#);
    for rendered in [
        format!(
            "{:?}",
            AuthorizationPolicy::from_json(bytes.as_bytes())
                .err()
                .unwrap()
        ),
        format!(
            "{:?}",
            QuotaPolicy::from_json(bytes.as_bytes()).unwrap_err()
        ),
        format!(
            "{:?}",
            PushPolicy::parse_bytes(bytes.as_bytes()).unwrap_err()
        ),
        format!(
            "{:?}",
            PrincipalMap::from_json(bytes.as_bytes(), 8_192, 128)
                .err()
                .unwrap()
        ),
    ] {
        assert!(!rendered.contains(SECRET));
        assert!(!rendered.contains(TENANT));
    }
}

#[test]
fn task_state_transition_matrix_is_closed_and_terminal_absorbing() {
    let states = [
        TaskState::Unspecified,
        TaskState::Submitted,
        TaskState::Working,
        TaskState::InputRequired,
        TaskState::AuthRequired,
        TaskState::Completed,
        TaskState::Failed,
        TaskState::Canceled,
        TaskState::Rejected,
    ];
    for from in &states {
        for to in &states {
            let allowed = task_state_transition_allowed(from, to);
            assert_eq!(allowed, task_state_transition_allowed(from, to));
            if from.is_terminal() {
                assert_eq!(allowed, from == to);
            }
        }
    }
}

#[tokio::test]
async fn task_page_token_mutations_never_cross_query_scope_or_mutate_authority() {
    let root = std::env::temp_dir().join(format!(
        "smesh-token-corpus-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let store = SqliteTaskStore::open(root.join("authority.db"), 8)
        .await
        .unwrap();
    store.create(stored_task("token-a")).await.unwrap();
    store.create(stored_task("token-b")).await.unwrap();
    let request = ListTasksRequest {
        context_id: None,
        status: None,
        page_size: Some(1),
        page_token: None,
        history_length: None,
        status_timestamp_after: None,
        include_artifacts: None,
        tenant: None,
    };
    let first = store.list(&request).await.unwrap();
    let token = first.next_page_token;
    let mutations = [
        String::new(),
        format!("{}A", &token[..token.len() - 1]),
        format!("{token}A"),
        token[..token.len() - 1].to_owned(),
        "!".repeat(token.len()),
        "A".repeat(4097),
    ];
    for mutation in mutations {
        let mut mutated = request.clone();
        mutated.page_token = Some(mutation);
        let error = store.list(&mutated).await.unwrap_err();
        assert_eq!(error.code, a2a::error_code::INVALID_PARAMS);
        assert_eq!(store.list(&request).await.unwrap().total_size, 2);
    }
    let mut cross_query = request.clone();
    cross_query.context_id = Some("other-context".to_owned());
    cross_query.page_token = Some(token.clone());
    assert_eq!(
        store.list(&cross_query).await.unwrap_err().code,
        a2a::error_code::INVALID_PARAMS
    );
    let mut valid = request;
    valid.page_token = Some(token);
    assert_eq!(store.list(&valid).await.unwrap().total_size, 2);
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}
