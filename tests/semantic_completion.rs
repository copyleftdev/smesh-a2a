use base64::{Engine as _, engine::general_purpose::STANDARD};
use smesh_a2a::{
    AuthorizationPolicy, DurableGateway, DurableReceiverResult, DurableReceiverTermination,
    GatewayConfig, InjectedClock, MeshEvent, PolicyError, PostgresTaskStore,
    TEXT_CONCORDANCE_ARTIFACT_NAME_V1, TEXT_CONCORDANCE_MEDIA_TYPE, TextConcordanceIssuerSet,
    TextConcordanceLimits, build_authorized_postgres_text_concordance_runtime_gateway,
    process_text_concordance, validate_text_concordance_runtime_proposal,
};

type TextConcordanceBuilder = fn(
    GatewayConfig,
    PostgresTaskStore,
    std::sync::Arc<dyn smesh_a2a::DurableRuntimeAdapter>,
    TextConcordanceIssuerSet,
    std::time::Duration,
    InjectedClock,
    smesh_a2a::auth::AuthState,
    std::sync::Arc<AuthorizationPolicy>,
) -> Result<DurableGateway, PolicyError>;

#[test]
fn production_profile_has_a_distinct_closed_builder() {
    let _: TextConcordanceBuilder = build_authorized_postgres_text_concordance_runtime_gateway;
}

fn exact_proposal(input: &str) -> DurableReceiverResult {
    let output = process_text_concordance(input, TextConcordanceLimits::default()).unwrap();
    let content = format!(
        "smesh-internal-artifact/v1:{{\"kind\":\"binary\",\"bytes\":\"{}\"}}",
        STANDARD.encode(&output.artifact_bytes)
    );
    DurableReceiverResult {
        events: vec![
            MeshEvent::Progress("SMESH runtime retained the query".to_owned()),
            MeshEvent::Artifact {
                name: TEXT_CONCORDANCE_ARTIFACT_NAME_V1.to_owned(),
                media_type: TEXT_CONCORDANCE_MEDIA_TYPE.to_owned(),
                content,
            },
            MeshEvent::Completed {
                summary: "text-concordance/v1 candidate proposed".to_owned(),
            },
        ],
        termination: DurableReceiverTermination::Success,
    }
}

#[test]
fn runtime_proposal_accepts_only_the_exact_recomputed_candidate() {
    let bytes = validate_text_concordance_runtime_proposal("alpha\n", &exact_proposal("alpha\n"))
        .expect("exact processor proposal");
    assert_eq!(
        bytes,
        process_text_concordance("alpha\n", TextConcordanceLimits::default())
            .unwrap()
            .artifact_bytes
    );
}

#[test]
fn runtime_proposal_rejects_forged_candidate_bytes() {
    let mut proposal = exact_proposal("alpha\n");
    proposal.events[1] = MeshEvent::Artifact {
        name: TEXT_CONCORDANCE_ARTIFACT_NAME_V1.to_owned(),
        media_type: TEXT_CONCORDANCE_MEDIA_TYPE.to_owned(),
        content: format!(
            "smesh-internal-artifact/v1:{{\"kind\":\"binary\",\"bytes\":\"{}\"}}",
            STANDARD.encode(b"{}")
        ),
    };
    assert!(validate_text_concordance_runtime_proposal("alpha\n", &proposal).is_err());
}
