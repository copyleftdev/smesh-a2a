use std::collections::HashSet;
use std::path::{Path, PathBuf};

use futures::StreamExt as _;
use smesh_a2a::{
    ArtifactManifest, CompletionEvidence, LifelineDirectorManifest, LifelineResponseDirector,
    LifelineTeamManifest, LifelineTopologyManifest, MeshDispatcher, MeshRequest,
    artifact_set_digest, content_digest,
};

const MANIFEST: &str = include_str!("../deploy/lifeline-teams.json");
const TOPOLOGY: &str = include_str!("../deploy/lifeline-topology.json");
const DIRECTOR: &str = include_str!("../deploy/lifeline-director.json");

#[test]
fn checked_manifest_defines_five_isolated_teams_for_six_gateways() {
    let manifest = LifelineTeamManifest::from_json(MANIFEST).unwrap();

    assert!(manifest.is_fictional());
    assert_eq!(manifest.seed(), 47);
    assert_eq!(manifest.teams().len(), 5);

    let mut gateways = HashSet::new();
    for team in manifest.teams() {
        assert!(team.roles().len() >= 4);
        assert!(
            team.roles()
                .iter()
                .map(smesh_a2a::LifelineTeamRole::id)
                .all_unique()
        );
        assert!(
            team.roles()
                .iter()
                .map(smesh_a2a::LifelineTeamRole::concern)
                .all_unique()
        );
        assert!(
            team.gateways()
                .iter()
                .all(|gateway| gateways.insert(gateway.clone()))
        );
        assert!(team.tool().id().starts_with("local."));
        assert!(team.tool().record_count() > 0);
    }
    assert_eq!(
        gateways,
        [
            "meridian",
            "atlas-primary",
            "atlas-fallback",
            "helix",
            "harbor",
            "sentinel",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
}

trait AllUnique: Iterator + Sized {
    fn all_unique(self) -> bool
    where
        Self::Item: Eq + std::hash::Hash,
    {
        let mut seen = HashSet::new();
        self.into_iter().all(|item| seen.insert(item))
    }
}

impl<I: Iterator> AllUnique for I {}

#[test]
fn manifest_rejects_unreviewed_local_data_changes() {
    let mut manifest: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();
    manifest["teams"][0]["tool"]["records"][0] = serde_json::json!("unreviewed-record");
    let error =
        LifelineTeamManifest::from_json(&serde_json::to_string(&manifest).unwrap()).unwrap_err();
    assert!(error.to_string().contains("reviewed LIFELINE team catalog"));
}

#[tokio::test]
async fn directly_deserialized_manifest_is_revalidated_before_launch() {
    let root = TempDir::new("direct-deserialize");
    let mut input: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();
    input["teams"][0]["roles"] = serde_json::json!([]);
    input["teams"][0]["id"] = serde_json::json!("../escape");
    let manifest: LifelineTeamManifest = serde_json::from_value(input).unwrap();

    let error = match manifest.launch(root.path()).await {
        Ok(fleet) => {
            fleet.shutdown().await.unwrap();
            panic!("directly deserialized unreviewed manifest was accepted");
        }
        Err(error) => error,
    };

    assert!(error.to_string().contains("team id"));
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

#[cfg(unix)]
#[tokio::test]
async fn insecure_journal_root_is_rejected_before_workers_start() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = TempDir::new("insecure-root");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let result = LifelineTeamManifest::from_json(MANIFEST)
        .unwrap()
        .launch(root.path())
        .await;
    match result {
        Ok(fleet) => {
            fleet.shutdown().await.unwrap();
            panic!("insecure journal root was accepted");
        }
        Err(error) => assert!(error.to_string().contains("private")),
    }
}

#[tokio::test]
async fn journal_collision_fails_without_partial_team_startup() {
    let root = TempDir::new("journal-collision");
    let atlas_path = root.path().join("atlas.jsonl");
    std::fs::write(&atlas_path, "sentinel\n").unwrap();
    let result = LifelineTeamManifest::from_json(MANIFEST)
        .unwrap()
        .launch(root.path())
        .await;
    match result {
        Ok(fleet) => {
            fleet.shutdown().await.unwrap();
            panic!("journal collision was accepted");
        }
        Err(error) => assert!(error.to_string().contains("exists")),
    }
    assert_eq!(std::fs::read_to_string(atlas_path).unwrap(), "sentinel\n");
    assert!(!root.path().join("meridian.jsonl").exists());
}

#[tokio::test]
async fn dropping_fleet_stops_surviving_gateway_dispatcher() {
    let root = TempDir::new("fleet-drop");
    let fleet = LifelineTeamManifest::from_json(MANIFEST)
        .unwrap()
        .launch(root.path())
        .await
        .unwrap();
    let dispatcher = fleet.dispatcher_for_gateway("meridian").unwrap();

    drop(fleet);

    let events = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        dispatcher
            .dispatch(MeshRequest {
                protocol: "a2a-v1".to_owned(),
                task_id: "after-fleet-drop".to_owned(),
                context_id: "after-fleet-drop-context".to_owned(),
                text: "must not run after fleet ownership ends".to_owned(),
            })
            .collect::<Vec<_>>(),
    )
    .await
    .expect("surviving dispatcher remained open after fleet drop");
    assert!(events.iter().any(Result::is_err), "{events:?}");
}

#[tokio::test]
async fn meridian_delegation_enters_a_real_runtime_and_reinforces_a_claim() {
    let root = TempDir::new("meridian-runtime");
    let manifest = LifelineTeamManifest::from_json(MANIFEST).unwrap();
    let fleet = manifest.launch(root.path()).await.unwrap();
    let dispatcher = fleet.dispatcher_for_gateway("meridian").unwrap();

    let events = dispatcher
        .dispatch(MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "team-task-meridian".to_owned(),
            context_id: "team-context-0047".to_owned(),
            text: "Trace the bounded fictional lot genealogy.".to_owned(),
        })
        .collect::<Vec<_>>()
        .await;
    assert!(events.iter().all(Result::is_ok));

    let journal_path = fleet.journal_path("meridian").unwrap().to_owned();
    fleet.shutdown().await.unwrap();
    let journal = read_journal(&journal_path);
    assert!(journal.iter().any(|event| {
        event["kind"] == "query_retained"
            && event["data"]["signal_hash"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
            && event["data"]["task_id"] == "team-task-meridian"
    }));
    assert!(journal.iter().any(|event| {
        event["kind"] == "task_claimed" && event["data"]["organization"] == "Meridian Bio"
    }));
    assert!(journal.iter().any(|event| {
        event["kind"] == "signal_reinforced"
            && event["data"]["reinforcement_count"].as_u64().unwrap() >= 1
            && event["data"]["attesters"]
                .as_array()
                .is_some_and(|values| values.len() == 2 && values[0] != values[1])
    }));
}

#[tokio::test]
async fn meridian_candidate_is_bounded_and_derived_from_its_local_tool() {
    let root = TempDir::new("meridian-candidate");
    let fleet = LifelineTeamManifest::from_json(MANIFEST)
        .unwrap()
        .launch(root.path())
        .await
        .unwrap();
    let dispatcher = fleet.dispatcher_for_gateway("meridian").unwrap();
    let events = dispatcher
        .dispatch(MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "candidate-task-meridian".to_owned(),
            context_id: "candidate-context-0047".to_owned(),
            text: "Trace the bounded fictional lot genealogy.".to_owned(),
        })
        .collect::<Vec<_>>()
        .await;
    let mut artifact = None;
    let mut completed = false;
    for event in events {
        match event.unwrap() {
            smesh_a2a::MeshEvent::Artifact {
                name,
                media_type,
                content,
            } => artifact = Some((name, media_type, content)),
            smesh_a2a::MeshEvent::Completed { .. } => completed = true,
            _ => {}
        }
    }
    let (name, media_type, content) = artifact.expect("missing bounded candidate artifact");
    assert_eq!(name, "affected-lots.json");
    assert_eq!(media_type, "application/json");
    assert!(content.len() <= 8 * 1024);
    let candidate: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(candidate["schemaVersion"], "lifeline-team-candidate/1");
    assert_eq!(candidate["fictional"], true);
    assert_eq!(candidate["organization"], "Meridian Bio");
    assert_eq!(candidate["toolId"], "local.meridian-lot-ledger");
    assert_eq!(candidate["recordCount"], 4);
    assert!(
        candidate["datasetDigest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert!(candidate.get("records").is_none());
    assert!(completed);

    let journal_path = fleet.journal_path("meridian").unwrap().to_owned();
    fleet.shutdown().await.unwrap();
    let journal = read_journal(&journal_path);
    assert!(journal.iter().any(|event| event["kind"] == "tool_called"));
    assert!(
        journal
            .iter()
            .any(|event| event["kind"] == "tool_completed")
    );
}

#[tokio::test]
async fn lower_affinity_meridian_claim_backs_off_without_losing_reinforcement_work() {
    let root = TempDir::new("meridian-backoff");
    let fleet = LifelineTeamManifest::from_json(MANIFEST)
        .unwrap()
        .launch(root.path())
        .await
        .unwrap();
    let dispatcher = fleet.dispatcher_for_gateway("meridian").unwrap();
    let events = dispatcher
        .dispatch(MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "backoff-task-meridian".to_owned(),
            context_id: "backoff-context-0047".to_owned(),
            text: "Trace the bounded fictional lot genealogy.".to_owned(),
        })
        .collect::<Vec<_>>()
        .await;
    assert!(events.iter().all(Result::is_ok));
    let journal_path = fleet.journal_path("meridian").unwrap().to_owned();
    fleet.shutdown().await.unwrap();
    let journal = read_journal(&journal_path);
    let claims: Vec<_> = journal
        .iter()
        .filter(|event| event["kind"] == "task_claimed")
        .collect();
    assert_eq!(claims.len(), 2);
    let backoff = journal
        .iter()
        .find(|event| event["kind"] == "task_backed_off")
        .expect("missing deterministic backoff");
    assert!(
        backoff["data"]["winner_score"].as_u64().unwrap()
            > backoff["data"]["loser_score"].as_u64().unwrap()
    );
    assert!(journal.iter().any(|event| {
        event["kind"] == "signal_reinforced" && event["data"]["role"] == backoff["data"]["role"]
    }));
}

#[tokio::test]
async fn unsupported_meridian_hypothesis_is_contradicted_and_decays_from_the_runtime() {
    let root = TempDir::new("meridian-decay");
    let fleet = LifelineTeamManifest::from_json(MANIFEST)
        .unwrap()
        .launch(root.path())
        .await
        .unwrap();
    let dispatcher = fleet.dispatcher_for_gateway("meridian").unwrap();
    let events = dispatcher
        .dispatch(MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "decay-task-meridian".to_owned(),
            context_id: "decay-context-0047".to_owned(),
            text: "Reject unsupported fictional lot hypotheses.".to_owned(),
        })
        .collect::<Vec<_>>()
        .await;
    assert!(events.iter().all(Result::is_ok));
    let artifact_content = events
        .iter()
        .find_map(|event| match event.as_ref().unwrap() {
            smesh_a2a::MeshEvent::Artifact { content, .. } => Some(content.as_str()),
            _ => None,
        })
        .unwrap();
    assert!(!artifact_content.contains("all-lots-everywhere"));
    let journal_path = fleet.journal_path("meridian").unwrap().to_owned();
    let runtime_path = fleet.runtime_trace_path("meridian").unwrap().to_owned();
    fleet.shutdown().await.unwrap();
    let journal = read_journal(&journal_path);
    let contradiction = journal
        .iter()
        .find(|event| event["kind"] == "signal_contradicted")
        .expect("missing contradiction observation");
    let decay = journal
        .iter()
        .find(|event| event["kind"] == "signal_decayed")
        .expect("missing decay observation");
    assert_eq!(
        contradiction["data"]["hypothesis_hash"],
        decay["data"]["signal_hash"]
    );
    let contradiction_hash = contradiction["data"]["contradiction_hash"]
        .as_str()
        .expect("missing real contradiction signal hash");
    let trace = read_journal(&runtime_path);
    for hash in [
        contradiction["data"]["hypothesis_hash"].as_str().unwrap(),
        contradiction_hash,
    ] {
        assert!(
            trace.iter().any(|event| {
                event["kind"] == "signal_emitted" && event["data"]["hash"] == hash
            })
        );
    }
    assert!(trace.iter().any(|event| {
        event["kind"] == "tick_completed"
            && event["data"]["expired"]
                .as_u64()
                .is_some_and(|count| count >= 1)
    }));
    assert_eq!(decay["data"]["removed_from_active"], true);
    assert_eq!(decay["data"]["retained_in_history"], true);
}

#[tokio::test]
async fn fixed_seed_replays_identical_runtime_semantics_and_semantic_journals() {
    async fn run_once(label: &str) -> (Vec<u8>, Vec<u8>) {
        let root = TempDir::new(label);
        let fleet = LifelineTeamManifest::from_json(MANIFEST)
            .unwrap()
            .launch(root.path())
            .await
            .unwrap();
        let events = fleet
            .dispatcher_for_gateway("meridian")
            .unwrap()
            .dispatch(MeshRequest {
                protocol: "a2a-v1".to_owned(),
                task_id: "replay-task-meridian".to_owned(),
                context_id: "replay-context-0047".to_owned(),
                text: "Run the reviewed fictional replay operation.".to_owned(),
            })
            .collect::<Vec<_>>()
            .await;
        assert!(events.iter().all(Result::is_ok), "{events:?}");
        let path = fleet.journal_path("meridian").unwrap().to_owned();
        let runtime_path = fleet.runtime_trace_path("meridian").unwrap().to_owned();
        fleet.shutdown().await.unwrap();
        (
            std::fs::read(path).unwrap(),
            std::fs::read(runtime_path).unwrap(),
        )
    }

    let (first_semantic, first_runtime) = run_once("semantic-replay-a").await;
    let (second_semantic, second_runtime) = run_once("semantic-replay-b").await;
    assert_eq!(first_semantic, second_semantic);
    assert_eq!(
        canonical_runtime_semantics(&first_runtime),
        canonical_runtime_semantics(&second_runtime)
    );
    assert!(first_semantic.len() <= 256 * 1024);
    assert!(first_runtime.len() <= 256 * 1024);
    assert!(
        !String::from_utf8(first_semantic)
            .unwrap()
            .contains("Run the reviewed fictional replay operation.")
    );
    assert!(
        !String::from_utf8(first_runtime)
            .unwrap()
            .contains("Run the reviewed fictional replay operation.")
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One end-to-end evidence trace verifies every subject binding.
async fn reinforced_candidate_receives_subject_bound_team_evidence() {
    let root = TempDir::new("team-evidence");
    let fleet = LifelineTeamManifest::from_json(MANIFEST)
        .unwrap()
        .launch(root.path())
        .await
        .unwrap();
    let events = fleet
        .dispatcher_for_gateway("meridian")
        .unwrap()
        .dispatch(MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "evidence-task-meridian".to_owned(),
            context_id: "evidence-context-0047".to_owned(),
            text: "Build and cross-check the fictional lot candidate.".to_owned(),
        })
        .collect::<Vec<_>>()
        .await;
    assert!(events.iter().all(Result::is_ok), "{events:?}");
    let events: Vec<_> = events.into_iter().map(Result::unwrap).collect();
    let (name, media_type, content) = events
        .iter()
        .find_map(|event| match event {
            smesh_a2a::MeshEvent::Artifact {
                name,
                media_type,
                content,
            } => Some((name, media_type, content)),
            _ => None,
        })
        .unwrap();
    let subject_digest = artifact_set_digest(&[ArtifactManifest {
        name: name.clone(),
        media_type: media_type.clone(),
        digest: content_digest(content.as_bytes()),
    }])
    .unwrap();
    let evidence: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            smesh_a2a::MeshEvent::Evidence(evidence) => Some(evidence),
            _ => None,
        })
        .collect();
    assert_eq!(evidence.len(), 3);
    assert!(matches!(evidence[0], CompletionEvidence::Review { .. }));
    assert!(matches!(evidence[1], CompletionEvidence::Test { .. }));
    assert!(matches!(
        evidence[2],
        CompletionEvidence::Contradiction { .. }
    ));
    assert!(evidence.iter().all(|evidence| match evidence {
        CompletionEvidence::Review {
            subject_digest: value,
            ..
        }
        | CompletionEvidence::Test {
            subject_digest: value,
            ..
        }
        | CompletionEvidence::Contradiction {
            subject_digest: value,
            ..
        }
        | CompletionEvidence::Attestation {
            subject_digest: value,
            ..
        } => value == &subject_digest,
        CompletionEvidence::Ratification(_) => false,
    }));
    let signed_roles = ["lot-genealogy", "quality", "toxicology"];
    for (record, role) in evidence.iter().zip(signed_roles) {
        let bytes = match record {
            CompletionEvidence::Review { evidence, .. }
            | CompletionEvidence::Test { evidence, .. }
            | CompletionEvidence::Contradiction { evidence, .. } => evidence,
            CompletionEvidence::Attestation { .. } | CompletionEvidence::Ratification(_) => {
                unreachable!()
            }
        };
        let payload: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        assert_eq!(payload["subjectDigest"], subject_digest);
        assert_eq!(payload["role"], role);
        let runtime_hash = payload["runtimeSignalHash"].as_str().unwrap();
        let attestation: smesh_core::Attestation =
            serde_json::from_value(payload["runtimeAttestation"].clone()).unwrap();
        assert_eq!(attestation.node_id, format!("meridian-{role}"));
        assert!(attestation.verify(runtime_hash));
    }
    assert!(matches!(
        events.last(),
        Some(smesh_a2a::MeshEvent::Completed { .. })
    ));
    let journal_path = fleet.journal_path("meridian").unwrap().to_owned();
    let runtime_path = fleet.runtime_trace_path("meridian").unwrap().to_owned();
    fleet.shutdown().await.unwrap();
    let journal = read_journal(&journal_path);
    let claim_hash = journal
        .iter()
        .find(|event| event["kind"] == "signal_reinforced")
        .unwrap()["data"]["signal_hash"]
        .as_str()
        .unwrap();
    let hypothesis_hash = journal
        .iter()
        .find(|event| event["kind"] == "signal_decayed")
        .unwrap()["data"]["signal_hash"]
        .as_str()
        .unwrap();
    let payloads = evidence
        .iter()
        .map(|evidence| match evidence {
            CompletionEvidence::Review { evidence, .. }
            | CompletionEvidence::Test { evidence, .. }
            | CompletionEvidence::Contradiction { evidence, .. } => {
                serde_json::from_slice::<serde_json::Value>(evidence).unwrap()
            }
            CompletionEvidence::Attestation { .. } | CompletionEvidence::Ratification(_) => {
                unreachable!()
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(payloads[0]["assertion"]["claimHash"], claim_hash);
    assert_eq!(
        payloads[1]["assertion"]["toolId"],
        "local.meridian-lot-ledger"
    );
    assert_eq!(
        payloads[1]["assertion"]["candidateDigest"],
        content_digest(content.as_bytes())
    );
    assert_eq!(payloads[2]["assertion"]["hypothesisHash"], hypothesis_hash);
    assert_eq!(payloads[2]["assertion"]["decayed"], true);
    let trace = read_journal(&runtime_path);
    for payload in payloads {
        let hash = payload["runtimeSignalHash"].as_str().unwrap();
        assert!(
            trace.iter().any(|event| {
                event["kind"] == "signal_emitted" && event["data"]["hash"] == hash
            })
        );
    }
}

#[tokio::test]
async fn gateway_binding_keeps_local_data_in_the_owning_organization() {
    let root = TempDir::new("all-organizations");
    let fleet = LifelineTeamManifest::from_json(MANIFEST)
        .unwrap()
        .launch(root.path())
        .await
        .unwrap();
    let gateways = [
        ("meridian", "Meridian Bio", "local.meridian-"),
        ("atlas-primary", "Atlas Cold Chain", "local.atlas-"),
        ("atlas-fallback", "Atlas Cold Chain", "local.atlas-"),
        ("helix", "Helix Medicines Authority", "local.helix-"),
        ("harbor", "Harbor Health", "local.harbor-"),
        ("sentinel", "Sentinel Labs", "local.sentinel-"),
    ];
    for (gateway, organization, tool_prefix) in gateways {
        assert_eq!(fleet.organization_for_gateway(gateway), Some(organization));
        let events = fleet
            .dispatcher_for_gateway(gateway)
            .unwrap()
            .dispatch(MeshRequest {
                protocol: "a2a-v1".to_owned(),
                task_id: format!("isolation-task-{gateway}"),
                context_id: "isolation-context-0047".to_owned(),
                text: format!("Run the bounded fictional {gateway} operation."),
            })
            .collect::<Vec<_>>()
            .await;
        assert!(events.iter().all(Result::is_ok), "{gateway}: {events:?}");
        let candidate = events
            .iter()
            .find_map(|event| match event.as_ref().unwrap() {
                smesh_a2a::MeshEvent::Artifact { content, .. } => {
                    Some(serde_json::from_str::<serde_json::Value>(content).unwrap())
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(candidate["organization"], organization);
        assert!(
            candidate["toolId"]
                .as_str()
                .unwrap()
                .starts_with(tool_prefix)
        );
        assert!(!candidate.to_string().contains("records"));
    }
    let journals: Vec<_> = [
        ("meridian", "Meridian Bio"),
        ("atlas", "Atlas Cold Chain"),
        ("helix", "Helix Medicines Authority"),
        ("harbor", "Harbor Health"),
        ("sentinel", "Sentinel Labs"),
    ]
    .into_iter()
    .map(|(team, organization)| (organization, fleet.journal_path(team).unwrap().to_owned()))
    .collect();
    fleet.shutdown().await.unwrap();
    for (organization, path) in journals {
        let journal = read_journal(&path);
        for kind in [
            "task_claimed",
            "task_backed_off",
            "signal_reinforced",
            "signal_contradicted",
            "signal_decayed",
            "tool_completed",
            "candidate_built",
        ] {
            assert!(
                journal.iter().any(|event| {
                    event["kind"] == kind && event["data"]["organization"] == organization
                }),
                "{organization} missing {kind}"
            );
        }
    }
}

#[tokio::test]
async fn same_gateway_duplicate_does_not_replace_active_request_subject() {
    let root = TempDir::new("same-gateway-duplicate");
    let fleet = LifelineTeamManifest::from_json(MANIFEST)
        .unwrap()
        .launch(root.path())
        .await
        .unwrap();
    let dispatcher = fleet.dispatcher_for_gateway("meridian").unwrap();
    let first = dispatcher.dispatch(MeshRequest {
        protocol: "a2a-v1".to_owned(),
        task_id: "duplicate-task".to_owned(),
        context_id: "first-context".to_owned(),
        text: "Run the first bounded fictional operation.".to_owned(),
    });
    let duplicate = dispatcher
        .dispatch(MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "duplicate-task".to_owned(),
            context_id: "replacement-context".to_owned(),
            text: "Attempt a duplicate bounded fictional operation.".to_owned(),
        })
        .collect::<Vec<_>>()
        .await;
    assert_eq!(duplicate.len(), 1);
    assert!(
        duplicate[0]
            .as_ref()
            .unwrap_err()
            .to_string()
            .contains("already owns")
    );

    let first = first.collect::<Vec<_>>().await;
    assert!(first.iter().all(Result::is_ok), "{first:?}");
    let candidate = first
        .iter()
        .find_map(|event| match event.as_ref().unwrap() {
            smesh_a2a::MeshEvent::Artifact { content, .. } => {
                Some(serde_json::from_str::<serde_json::Value>(content).unwrap())
            }
            _ => None,
        })
        .unwrap();
    assert_eq!(candidate["contextId"], "first-context");
    fleet.shutdown().await.unwrap();
}

#[tokio::test]
async fn atlas_gateways_namespace_identical_task_ids() {
    let root = TempDir::new("atlas-gateway-task-namespace");
    let fleet = LifelineTeamManifest::from_json(MANIFEST)
        .unwrap()
        .launch(root.path())
        .await
        .unwrap();
    let request = MeshRequest {
        protocol: "a2a-v1".to_owned(),
        task_id: "shared-atlas-task".to_owned(),
        context_id: "shared-atlas-context".to_owned(),
        text: "Run the bounded fictional route operation.".to_owned(),
    };
    let primary = fleet
        .dispatcher_for_gateway("atlas-primary")
        .unwrap()
        .dispatch(request.clone())
        .collect::<Vec<_>>();
    let fallback = fleet
        .dispatcher_for_gateway("atlas-fallback")
        .unwrap()
        .dispatch(request)
        .collect::<Vec<_>>();
    let (primary, fallback) = tokio::join!(primary, fallback);
    for events in [&primary, &fallback] {
        assert!(events.iter().all(Result::is_ok), "{events:?}");
        let candidate = events
            .iter()
            .find_map(|event| match event.as_ref().unwrap() {
                smesh_a2a::MeshEvent::Artifact { content, .. } => {
                    Some(serde_json::from_str::<serde_json::Value>(content).unwrap())
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(candidate["taskId"], "shared-atlas-task");
        assert_eq!(candidate["contextId"], "shared-atlas-context");
    }
    fleet.shutdown().await.unwrap();
}

#[tokio::test]
async fn atlas_tasks_cannot_reinforce_each_other_across_task_identity() {
    let root = TempDir::new("atlas-task-isolation");
    let fleet = LifelineTeamManifest::from_json(MANIFEST)
        .unwrap()
        .launch(root.path())
        .await
        .unwrap();
    let mut hashes = Vec::new();
    for (gateway, task_id) in [
        ("atlas-primary", "atlas-primary-task"),
        ("atlas-fallback", "atlas-fallback-task"),
    ] {
        let events = fleet
            .dispatcher_for_gateway(gateway)
            .unwrap()
            .dispatch(MeshRequest {
                protocol: "a2a-v1".to_owned(),
                task_id: task_id.to_owned(),
                context_id: "atlas-context-0047".to_owned(),
                text: "Run the bounded fictional route operation.".to_owned(),
            })
            .collect::<Vec<_>>()
            .await;
        assert!(events.iter().all(Result::is_ok), "{events:?}");
        let candidate = events
            .iter()
            .find_map(|event| match event.as_ref().unwrap() {
                smesh_a2a::MeshEvent::Artifact { content, .. } => {
                    Some(serde_json::from_str::<serde_json::Value>(content).unwrap())
                }
                _ => None,
            })
            .unwrap();
        hashes.push(candidate["claimSignalHash"].as_str().unwrap().to_owned());
    }
    fleet.shutdown().await.unwrap();
    assert_ne!(hashes[0], hashes[1]);
}

#[tokio::test]
async fn official_a2a_director_reaches_each_organization_team() {
    let root = TempDir::new("official-team-topology");
    let topology = LifelineTopologyManifest::from_json(TOPOLOGY)
        .unwrap()
        .with_ephemeral_loopback_ports();
    let running = LifelineTeamManifest::from_json(MANIFEST)
        .unwrap()
        .launch_topology(topology, root.path())
        .await
        .unwrap();
    let mut director: serde_json::Value = serde_json::from_str(DIRECTOR).unwrap();
    for gateway in director["gateways"].as_array_mut().unwrap() {
        let gateway_id = gateway["id"].as_str().unwrap();
        let base_url = running
            .endpoints()
            .iter()
            .find(|endpoint| endpoint.gateway_id() == gateway_id)
            .unwrap()
            .base_url();
        gateway["discoveryUrl"] = serde_json::json!(base_url);
    }
    let run = LifelineResponseDirector::new(
        LifelineDirectorManifest::from_json(&director.to_string()).unwrap(),
    )
    .run()
    .await
    .unwrap();
    assert_eq!(run.initial_operations().len(), 4);
    assert!(run.review().is_some());
    assert!(run.fallback_operation().is_none());
    running.shutdown().await.unwrap();
}

#[test]
fn cli_runs_every_gateway_and_writes_private_journals() {
    use std::process::Command;

    let parent = TempDir::new("team-cli");
    let output = parent.path().join("run");
    let result = Command::new(env!("CARGO_BIN_EXE_lifeline-organization-teams"))
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/lifeline-teams.json"))
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let record: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(output.join("run.json")).unwrap()).unwrap();
    assert_eq!(record["schemaVersion"], "lifeline-team-run/1");
    assert_eq!(record["boundary"], "official-a2a");
    assert_eq!(record["fictional"], true);
    assert_eq!(record["seed"], 47);
    assert_eq!(record["initialOperationCount"], 4);
    assert_eq!(record["reviewCompleted"], true);
    assert_eq!(record["fallbackUsed"], false);
    let gateway_runs = record["gatewayRuns"].as_array().unwrap();
    assert_eq!(gateway_runs.len(), 5);
    assert!(gateway_runs.iter().all(|run| run["completed"] == true));
    assert_eq!(
        gateway_runs
            .iter()
            .map(|run| run["gatewayId"].as_str().unwrap())
            .collect::<HashSet<_>>(),
        HashSet::from(["meridian", "atlas-primary", "helix", "harbor", "sentinel"])
    );
    let journal_entries = std::fs::read_dir(output.join("journals"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(journal_entries.len(), 10);
    assert_eq!(
        journal_entries
            .iter()
            .filter(|entry| entry
                .file_name()
                .to_string_lossy()
                .ends_with(".runtime.jsonl"))
            .count(),
        5
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(output.join("run.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        for entry in std::fs::read_dir(output.join("journals")).unwrap() {
            assert_eq!(
                entry.unwrap().metadata().unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}

fn canonical_runtime_semantics(bytes: &[u8]) -> serde_json::Value {
    let events = String::from_utf8(bytes.to_vec()).unwrap();
    let events = events
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    let emitted_hashes = events
        .iter()
        .filter(|event| event["kind"] == "signal_emitted")
        .map(|event| event["data"]["hash"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let expired = events
        .iter()
        .filter(|event| event["kind"] == "tick_completed")
        .map(|event| event["data"]["expired"].as_u64().unwrap())
        .sum::<u64>();
    serde_json::json!({
        "emittedHashes": emitted_hashes,
        "expiredSignals": expired,
    })
}

fn read_journal(path: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "smesh-lifeline-teams-{label}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
