use std::io::Write as _;
use std::path::{Path, PathBuf};

use smesh_a2a::LifelineTopologyManifest;

const DEFAULT_MANIFEST: &str = "deploy/lifeline-topology.json";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

fn arguments() -> Result<(bool, PathBuf), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let first = args.next();
    let (check, path) = if first.as_deref() == Some(std::ffi::OsStr::new("--check")) {
        (
            true,
            args.next()
                .map_or_else(|| PathBuf::from(DEFAULT_MANIFEST), PathBuf::from),
        )
    } else {
        (
            false,
            first.map_or_else(|| PathBuf::from(DEFAULT_MANIFEST), PathBuf::from),
        )
    };
    if args.next().is_some() {
        return Err("usage: lifeline-topology [--check] [manifest.json]".into());
    }
    Ok((check, path))
}

fn read_manifest(path: &Path) -> Result<LifelineTopologyManifest, Box<dyn std::error::Error>> {
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        return Err(
            "LIFELINE topology manifest must be a regular file no larger than 64 KiB".into(),
        );
    }
    let input = std::fs::read_to_string(path)?;
    Ok(LifelineTopologyManifest::from_json(&input)?)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (check, path) = arguments()?;
    let manifest = read_manifest(&path)?;
    if check {
        println!(
            "validated {} gateways and {} listeners from {}",
            manifest.gateways().len(),
            manifest.listener_count(),
            path.display()
        );
        return Ok(());
    }

    let topology = manifest.launch().await?;
    for endpoint in topology.endpoints() {
        println!(
            "ready gateway={} listener={} url={} fallback={}",
            endpoint.gateway_id(),
            endpoint.listener_id(),
            endpoint.base_url(),
            endpoint.is_fallback()
        );
    }
    std::io::stdout().flush()?;
    tokio::signal::ctrl_c().await?;
    topology.shutdown().await?;
    Ok(())
}
