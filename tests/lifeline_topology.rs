use std::io::BufRead as _;
use std::process::{Command, Stdio};
use std::time::Duration;

use a2a::{AgentCard, TRANSPORT_PROTOCOL_HTTP_JSON, TRANSPORT_PROTOCOL_JSONRPC};
use a2a_client::agent_card::AgentCardResolver;
use smesh_a2a::{LIFELINE_DISCOVERY_DISCLAIMER, LifelineTopologyManifest};
use wait_timeout::ChildExt as _;

const MANIFEST: &str = include_str!("../deploy/lifeline-topology.json");

#[test]
fn checked_manifest_defines_six_distinct_fictional_gateways() {
    let manifest = LifelineTopologyManifest::from_json(MANIFEST).unwrap();

    assert_eq!(manifest.gateways().len(), 6);
    assert_eq!(manifest.listener_count(), 6);
    assert!(manifest.is_fictional());

    let ids: Vec<_> = manifest
        .gateways()
        .iter()
        .map(smesh_a2a::LifelineGateway::id)
        .collect();
    assert_eq!(
        ids,
        [
            "meridian",
            "atlas-primary",
            "helix",
            "harbor",
            "sentinel",
            "atlas-fallback"
        ]
    );

    let logistics = manifest.logistics();
    assert_eq!(logistics.primary_gateway_id(), "atlas-primary");
    assert_eq!(logistics.fallback_gateway_id(), "atlas-fallback");
}

#[test]
fn six_public_cards_are_a2a_v1_profiles_without_internal_topology_or_authority_claims() {
    let manifest = LifelineTopologyManifest::from_json(MANIFEST).unwrap();
    let forbidden_internal_roles = [
        "epidemiology",
        "pharmacy",
        "manufacturing specialist",
        "quality specialist",
        "routing specialist",
        "provenance auditor",
        "contradiction specialist",
    ];

    for gateway in manifest.gateways() {
        let card = manifest.agent_card(gateway.id()).unwrap();
        let wire = serde_json::to_string(&card).unwrap();
        let round_trip: AgentCard = serde_json::from_str(&wire).unwrap();
        assert_eq!(round_trip, card);
        assert!(card.description.contains(LIFELINE_DISCOVERY_DISCLAIMER));
        assert_eq!(card.skills.len(), 1);
        assert!(card.security_schemes.is_none());
        assert!(card.security_requirements.is_none());
        assert!(card.capabilities.streaming.unwrap());
        assert_eq!(card.capabilities.push_notifications, Some(false));
        assert!(card.supported_interfaces.iter().all(|interface| {
            interface.protocol_version == "1.0"
                && matches!(
                    interface.protocol_binding.as_str(),
                    TRANSPORT_PROTOCOL_JSONRPC | TRANSPORT_PROTOCOL_HTTP_JSON
                )
        }));
        let lower = wire.to_ascii_lowercase();
        for internal_role in forbidden_internal_roles {
            assert!(!lower.contains(internal_role));
        }
    }

    let atlas = manifest.agent_card("atlas-primary").unwrap();
    assert_eq!(atlas.supported_interfaces.len(), 2);
    assert_eq!(
        atlas
            .supported_interfaces
            .iter()
            .filter(|interface| interface.url.contains("43142"))
            .count(),
        2
    );
    let atlas_fallback = manifest.agent_card("atlas-fallback").unwrap();
    assert_eq!(atlas_fallback.supported_interfaces.len(), 2);
    assert!(
        atlas_fallback
            .supported_interfaces
            .iter()
            .all(|interface| interface.url.contains("43146"))
    );
    assert_eq!(atlas.provider, atlas_fallback.provider);
    assert_eq!(atlas.skills, atlas_fallback.skills);
}

#[tokio::test]
async fn official_director_resolves_six_remote_cards_including_logistics_fallback() {
    let manifest = LifelineTopologyManifest::from_json(MANIFEST)
        .unwrap()
        .with_ephemeral_loopback_ports();
    let topology = manifest.launch().await.unwrap();
    let resolver = AgentCardResolver::new(None);

    let primary: Vec<_> = topology
        .endpoints()
        .iter()
        .filter(|endpoint| !endpoint.is_fallback())
        .collect();
    assert_eq!(primary.len(), 5);
    assert_eq!(topology.endpoints().len(), 6);

    let expected = [
        (
            "meridian",
            "Meridian Bio",
            "Pharmacovigilance Agent",
            "lifeline.lot-genealogy",
        ),
        (
            "atlas-primary",
            "Atlas Cold Chain",
            "Logistics Agent",
            "lifeline.shipment-quarantine",
        ),
        (
            "helix",
            "Helix Medicines Authority",
            "Recall Criteria Agent",
            "lifeline.recall-criteria",
        ),
        (
            "harbor",
            "Harbor Health",
            "Member Safety Agent",
            "lifeline.exposure-cohort",
        ),
        (
            "sentinel",
            "Sentinel Labs",
            "Independent Evidence Agent",
            "lifeline.evidence-review",
        ),
        (
            "atlas-fallback",
            "Atlas Cold Chain",
            "Fallback Logistics Agent",
            "lifeline.shipment-quarantine",
        ),
    ];
    for (endpoint, (gateway_id, organization, agent_name, skill_id)) in
        topology.endpoints().iter().zip(expected)
    {
        assert_eq!(endpoint.gateway_id(), gateway_id);
        let card = resolver.resolve(endpoint.base_url()).await.unwrap();
        assert_eq!(card.name, agent_name);
        assert_eq!(card.provider.as_ref().unwrap().organization, organization);
        assert_eq!(card.skills[0].id, skill_id);
        assert!(card.security_schemes.is_none());
        assert!(card.security_requirements.is_none());
    }

    let primary_atlas = topology
        .endpoints()
        .iter()
        .find(|endpoint| endpoint.listener_id() == "singapore-primary")
        .unwrap();
    let fallback_atlas = topology
        .endpoints()
        .iter()
        .find(|endpoint| endpoint.listener_id() == "frankfurt-fallback")
        .unwrap();
    assert_ne!(primary_atlas.base_url(), fallback_atlas.base_url());
    let primary_card = resolver.resolve(primary_atlas.base_url()).await.unwrap();
    let fallback_card = resolver.resolve(fallback_atlas.base_url()).await.unwrap();
    assert_eq!(primary_card.provider, fallback_card.provider);
    assert_eq!(primary_card.skills, fallback_card.skills);

    topology.shutdown().await.unwrap();
}

#[test]
fn manifest_rejects_public_internal_roles_and_clinical_authority_claims() {
    for leaked_text in [
        "Manufacturing Specialist handles this task.",
        "Regulatory Specialist handles this task.",
        "Claims Specialist handles this task.",
        "This capability is clinically validated.",
        "This endpoint provides medical advice.",
    ] {
        let mut value: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();
        value["gateways"][0]["skill"]["description"] =
            serde_json::Value::String(leaked_text.to_owned());
        let encoded = serde_json::to_string(&value).unwrap();
        assert!(LifelineTopologyManifest::from_json(&encoded).is_err());
    }
}

#[test]
fn manifest_rejects_every_change_to_the_approved_public_profiles() {
    for (pointer, replacement) in [
        ("/gateways/0/agentName", "Clinician-approved Agent"),
        (
            "/gateways/0/skill/description",
            "Authorized to issue recalls.",
        ),
        ("/gateways/0/skill/tags/0", "Epidemiology Agent"),
        ("/gateways/0/geography/city", "Secret Ward"),
        ("/gateways/0/skill/outputModes/0", "not a media type"),
    ] {
        let mut value: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();
        *value.pointer_mut(pointer).unwrap() = replacement.into();
        assert!(
            LifelineTopologyManifest::from_json(&serde_json::to_string(&value).unwrap()).is_err(),
            "public profile mutation at {pointer} was accepted"
        );
    }
}

struct TempManifest(std::path::PathBuf);

impl Drop for TempManifest {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn ephemeral_manifest_file() -> TempManifest {
    let mut value: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();
    for gateway in value["gateways"].as_array_mut().unwrap() {
        for listener in gateway["listeners"].as_array_mut().unwrap() {
            listener["bind"] = serde_json::Value::String("127.0.0.1:0".to_owned());
        }
    }
    let path = std::env::temp_dir().join(format!(
        "smesh-lifeline-topology-{}-{}.json",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    TempManifest(path)
}

#[test]
fn one_command_launches_every_declared_listener() {
    let manifest = ephemeral_manifest_file();
    let mut child = Command::new(env!("CARGO_BIN_EXE_lifeline-topology"))
        .arg(&manifest.0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let lines: Vec<_> = std::io::BufReader::new(stdout)
            .lines()
            .take(6)
            .collect::<Result<_, _>>()
            .unwrap();
        let _ = sender.send(lines);
    });
    let lines = receiver
        .recv_timeout(Duration::from_secs(10))
        .unwrap_or_else(|error| {
            let _ = child.kill();
            panic!("topology readiness deadline failed: {error}");
        });
    assert_eq!(lines.len(), 6);
    assert!(lines.iter().all(|line| line.starts_with("ready gateway=")));
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.contains("fallback=true"))
            .count(),
        1
    );
    child.kill().unwrap();
    assert!(
        child
            .wait_timeout(Duration::from_secs(5))
            .unwrap()
            .is_some(),
        "topology process did not reap"
    );
}
