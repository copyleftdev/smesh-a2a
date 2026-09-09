use std::fs::OpenOptions;
use std::io::Write as _;

use smesh_a2a::{OperationalProjectionLimits, project_operational_observatory_with_source_facts};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() != 8 {
        return Err("usage: operational-observatory-project REPLAY RECEIPT RUN_SEAL ACTORS EDITORIAL SOURCE_FACTS OUTPUT_JSONL OUTPUT_RECEIPT".into());
    }
    let replay = std::fs::read(&arguments[0])?;
    let receipt = std::fs::read(&arguments[1])?;
    let run_seal = arguments[2].to_str().ok_or("run seal must be UTF-8")?;
    let actors = std::fs::read(&arguments[3])?;
    let editorial = std::fs::read(&arguments[4])?;
    let source_facts = std::fs::read(&arguments[5])?;
    let projection = project_operational_observatory_with_source_facts(
        &replay,
        &receipt,
        run_seal,
        &actors,
        &editorial,
        &source_facts,
        OperationalProjectionLimits::default(),
    )?;
    for (path, bytes) in [
        (&arguments[6], projection.package_jsonl()),
        (&arguments[7], projection.receipt_json()),
    ] {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("operational projection failed: {error}");
        std::process::exit(1);
    }
}
