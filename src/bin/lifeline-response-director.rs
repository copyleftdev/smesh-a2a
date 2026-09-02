use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use smesh_a2a::{LifelineDirectorManifest, LifelineResponseDirector, LifelineTopologyManifest};

const MANIFEST_LIMIT_BYTES: u64 = 64 * 1024;

fn read_bounded(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > MANIFEST_LIMIT_BYTES {
        return Err(format!("manifest exceeds {MANIFEST_LIMIT_BYTES} bytes").into());
    }
    Ok(std::fs::read_to_string(path)?)
}

fn write_new_private(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1).map(PathBuf::from);
    let topology_path = args.next().ok_or(
        "usage: lifeline-response-director <topology.json> <director.json> <run-output.json>",
    )?;
    let director_path = args.next().ok_or(
        "usage: lifeline-response-director <topology.json> <director.json> <run-output.json>",
    )?;
    let output_path = args.next().ok_or(
        "usage: lifeline-response-director <topology.json> <director.json> <run-output.json>",
    )?;
    if args.next().is_some() {
        return Err("unexpected extra argument".into());
    }

    let topology = LifelineTopologyManifest::from_json(&read_bounded(&topology_path)?)?
        .launch()
        .await?;
    let director_manifest = LifelineDirectorManifest::from_json(&read_bounded(&director_path)?)?;
    let run_result = LifelineResponseDirector::new(director_manifest).run().await;
    let shutdown_result = topology.shutdown().await;
    let run = run_result?;
    shutdown_result?;

    let mut serialized = serde_json::to_vec_pretty(&run)?;
    serialized.push(b'\n');
    write_new_private(&output_path, &serialized)?;
    println!(
        "{{\"runManifest\":{},\"initialTasks\":{},\"idsComplete\":{}}}",
        serde_json::to_string(&output_path.display().to_string())?,
        run.initial_operations().len(),
        run.all_protocol_ids_are_captured()
    );
    Ok(())
}
