#[test]
fn amendment_claims_authenticate_before_any_lease_or_effect() {
    let sqlite = include_str!("../src/sqlite_store.rs");
    let sqlite_claim = &sqlite[sqlite.find("pub async fn claim_outbox(").unwrap()
        ..sqlite.find("pub async fn ack_outbox(").unwrap()];
    assert!(sqlite_claim.contains("ensure_integrated_ratification_integrity(&transaction"));
    assert!(
        sqlite_claim
            .find("ensure_integrated_ratification_integrity(&transaction")
            .unwrap()
            < sqlite_claim.find("dead_letter_task(&transaction").unwrap()
    );

    let postgres = include_str!("../src/postgres_store.rs");
    let claim_start = postgres
        .find("impl OutboxAuthority for PostgresTaskStore")
        .unwrap();
    let claim = &postgres[claim_start
        ..postgres[claim_start..]
            .find("async fn renew_outbox_lease(")
            .unwrap()
            + claim_start];
    assert!(claim.contains("validate_integrated_ratification_anchor(tx, &tenant, &task_id)"));
    assert!(
        claim
            .find("validate_integrated_ratification_anchor(tx, &tenant, &task_id)")
            .unwrap()
            < claim.find("materialize_postgres_dead_letter(").unwrap()
    );

    let sqlite_finish = &sqlite[sqlite.find("async fn finish_outbox_attempt(").unwrap()
        ..sqlite.find("async fn renew_receiver_lease(").unwrap()];
    assert!(sqlite_finish.contains("payload_digest, ratification_required FROM outbox"));
    assert!(
        sqlite_finish
            .find("SELECT attempt_count, max_attempts")
            .unwrap()
            < sqlite_finish
                .find("ensure_integrated_ratification_integrity(&transaction")
                .unwrap()
    );
    let sqlite_receive = &sqlite[sqlite.find("pub async fn begin_receive(").unwrap()
        ..sqlite.find("pub async fn complete_receive(").unwrap()];
    assert!(
        sqlite_receive
            .find("ensure_integrated_ratification_integrity(&tx")
            .unwrap()
            < sqlite_receive
                .find("#[allow(clippy::type_complexity)]")
                .unwrap()
    );

    let postgres_finish = &postgres[postgres.find("async fn finish_outbox_attempt(").unwrap()
        ..postgres.find("async fn renew_receiver_lease(").unwrap()];
    assert!(postgres_finish.contains("message_id,payload_digest,ratification_required"));
    assert!(
        postgres_finish
            .find("message_id,payload_digest,ratification_required")
            .unwrap()
            < postgres_finish
                .find("validate_integrated_ratification_anchor(tx")
                .unwrap()
    );
    let postgres_receive = &postgres[postgres
        .find("impl ReceiverAuthority for PostgresTaskStore")
        .unwrap()..];
    assert!(
        postgres_receive
            .find("validate_integrated_ratification_anchor(")
            .unwrap()
            < postgres_receive
                .find("let sender_reservation = match")
                .unwrap()
    );
}

#[test]
fn restore_pristine_check_is_locked_inside_journal_transaction() {
    let source = include_str!("../src/artifact_restore_executor.rs");
    let pre_journal = &source[..source.find("async fn commit_restore_journal(").unwrap()];
    assert!(
        !pre_journal.contains("assert_uninitialized_ratification_bootstrap(client, schema).await?")
    );
    let journal = &source[source.find("async fn commit_restore_journal(").unwrap()..];
    let locks = journal.find("ratification_ledger_anchor").unwrap();
    let check = journal
        .find("assert_uninitialized_ratification_bootstrap(&tx, schema).await?")
        .unwrap();
    assert!(locks < check);
}

#[test]
fn postgres_amendment_terminal_semantics_match_sqlite() {
    let source = include_str!("../src/postgres_store.rs");
    assert!(!source.contains("async fn validate_ratification_semantics"));
    let semantics = &source[source
        .find("async fn validate_ratification_target_semantics")
        .unwrap()
        ..source
            .find("async fn postgres_ratification_qualified_state")
            .unwrap()];
    assert!(semantics.contains("terminal_ratification_task_matches"));
    assert!(!semantics.contains("HumanDecision::Amend => a2a::TaskState::InputRequired"));
}

#[test]
fn postgres_startup_uses_anchors_without_lifetime_cap_or_n_plus_one_scan() {
    // Revision 11's immutable migration keeps its bounded first-initialization
    // qualification. Steady-state restart must authenticate the stored sealed
    // anchor instead of invoking that lifetime scan.
    let migration = include_str!("../migrations/postgres/0011_ratification_retained_authority.sql");
    assert!(migration.contains("LIMIT 100001"));
    assert!(migration.contains("startup qualification cap exceeded"));

    let source = include_str!("../src/postgres_store.rs");
    let anchor_start = source
        .find("async fn reconcile_postgres_ratification_anchor")
        .unwrap();
    let anchor = &source[anchor_start
        ..source[anchor_start + 1..]
            .find("\nasync fn ")
            .map_or(source.len(), |offset| anchor_start + 1 + offset)];
    let initialize = anchor.find("if !row.get::<_, bool>(0) {").unwrap();
    let initial_qualification = anchor
        .find("let state = postgres_ratification_qualified_state(client, schema).await?")
        .unwrap();
    let steady_state = anchor.find("let stored_state = (").unwrap();
    assert!(initialize < initial_qualification && initial_qualification < steady_state);
    assert!(!anchor[steady_state..].contains("postgres_ratification_qualified_state("));
    assert!(!anchor[steady_state..].contains("qualify_postgres_ratification_tenant_seals("));

    let startup = &source[source
        .find("let ratification_transaction = migration")
        .unwrap()
        ..source
            .find("if let Some(keyring) = artifact_keyring.as_ref()")
            .unwrap()];
    assert!(!startup.contains("validate_ratification_semantics("));
}

#[test]
fn runbook_probe_keeps_every_secret_and_response_private() {
    let runbook = include_str!("../docs/HUMAN_RATIFICATION_RUNBOOK.md");
    let probe = &runbook[runbook.find("With a running bearer deployment").unwrap()
        ..runbook.find("For mTLS,").unwrap()];
    for required in [
        "umask 077",
        "mktemp -d",
        "chmod 700",
        "trap cleanup EXIT",
        "header = \"Authorization: Bearer %s\"",
        "\"$TOKEN\" > \"$TMP_DIR/curl.conf\"",
        "curl --config \"$TMP_DIR/curl.conf\"",
        "chmod 600 \"$TMP_DIR/curl.conf\"",
        "rm -f \"$TMP_DIR/curl.conf\" \"$TMP_DIR/headers\" \"$TMP_DIR/view.json\"",
        "sensitive",
    ] {
        assert!(probe.contains(required), "missing {required}");
    }
    assert!(!probe.contains("Authorization: Bearer ***"));
    let curl = &probe[probe.find("curl --config").unwrap()..];
    assert!(!curl.contains("Authorization: Bearer $TOKEN"));
}
