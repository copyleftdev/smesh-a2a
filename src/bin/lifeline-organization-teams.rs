use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;
use smesh_a2a::{
    LIFELINE_TEAM_DISCLAIMER, LifelineDirectorManifest, LifelineDirectorOperationReceipt,
    LifelineResponseDirector, LifelineTeamManifest, LifelineTopologyManifest,
};

const TOPOLOGY: &str = include_str!("../../deploy/lifeline-topology.json");
const DIRECTOR: &str = include_str!("../../deploy/lifeline-director.json");

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TeamRunRecord {
    schema_version: &'static str,
    boundary: &'static str,
    fictional: bool,
    disclaimer: &'static str,
    seed: u64,
    initial_operation_count: usize,
    review_completed: bool,
    fallback_used: bool,
    gateway_runs: Vec<GatewayRun>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GatewayRun {
    gateway_id: String,
    binding: String,
    task_id: String,
    context_id: String,
    completed: bool,
}

impl From<&LifelineDirectorOperationReceipt> for GatewayRun {
    fn from(receipt: &LifelineDirectorOperationReceipt) -> Self {
        Self {
            gateway_id: receipt.gateway_id().to_owned(),
            binding: receipt.binding().to_owned(),
            task_id: receipt.task_id().to_owned(),
            context_id: receipt.context_id().to_owned(),
            completed: receipt.is_completed(),
        }
    }
}

struct OwnedRunDirectory {
    path: PathBuf,
    committed: bool,
}

impl OwnedRunDirectory {
    fn create(path: PathBuf) -> Result<Self, std::io::Error> {
        std::fs::create_dir(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            path,
            committed: false,
        })
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for OwnedRunDirectory {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os();
    let binary = args
        .next()
        .unwrap_or_else(|| "lifeline-organization-teams".into());
    let manifest_path = args.next().ok_or_else(|| {
        format!(
            "usage: {} <team-manifest.json> <new-output-directory>",
            Path::new(&binary).display()
        )
    })?;
    let output_path = args.next().ok_or_else(|| {
        format!(
            "usage: {} <team-manifest.json> <new-output-directory>",
            Path::new(&binary).display()
        )
    })?;
    if args.next().is_some() {
        return Err("unexpected extra argument".into());
    }

    let manifest_text = std::fs::read_to_string(manifest_path)?;
    let manifest = LifelineTeamManifest::from_json(&manifest_text)?;
    let seed = manifest.seed();
    let mut output = OwnedRunDirectory::create(PathBuf::from(output_path))?;
    let topology = LifelineTopologyManifest::from_json(TOPOLOGY)?.with_ephemeral_loopback_ports();
    let running = manifest
        .launch_topology(topology, output.path.join("journals"))
        .await?;

    let endpoints = running
        .endpoints()
        .iter()
        .map(|endpoint| {
            (
                endpoint.gateway_id().to_owned(),
                endpoint.base_url().to_owned(),
            )
        })
        .collect::<HashMap<_, _>>();
    let director_manifest = rewrite_director_discovery(&endpoints)?;
    let run_result = LifelineResponseDirector::new(director_manifest).run().await;
    let shutdown_result = running.shutdown().await;
    let run = run_result?;
    shutdown_result?;

    let review = run.review().ok_or("the Sentinel review did not complete")?;
    let mut gateway_runs = run
        .initial_operations()
        .iter()
        .map(GatewayRun::from)
        .collect::<Vec<_>>();
    gateway_runs.push(GatewayRun::from(review));
    let record = TeamRunRecord {
        schema_version: "lifeline-team-run/1",
        boundary: "official-a2a",
        fictional: true,
        disclaimer: LIFELINE_TEAM_DISCLAIMER,
        seed,
        initial_operation_count: run.initial_operations().len(),
        review_completed: review.is_completed(),
        fallback_used: run.fallback_operation().is_some(),
        gateway_runs,
    };
    write_private_new(
        &output.path.join("run.json"),
        serde_json::to_vec_pretty(&record)?.as_slice(),
    )?;
    output.commit();
    println!("{}", output.path.join("run.json").display());
    Ok(())
}

fn rewrite_director_discovery(
    endpoints: &HashMap<String, String>,
) -> Result<LifelineDirectorManifest, Box<dyn Error>> {
    let mut director: Value = serde_json::from_str(DIRECTOR)?;
    for gateway in director["gateways"]
        .as_array_mut()
        .ok_or("director gateways are not an array")?
    {
        let id = gateway["id"]
            .as_str()
            .ok_or("director gateway ID is absent")?;
        let base_url = endpoints
            .get(id)
            .ok_or_else(|| format!("missing endpoint for {id}"))?;
        gateway["discoveryUrl"] = Value::String(base_url.clone());
    }
    Ok(LifelineDirectorManifest::from_json(&director.to_string())?)
}

fn write_private_new(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    use std::io::Write as _;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
