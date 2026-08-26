use std::path::PathBuf;

use smesh_a2a::write_lifeline_trace;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::env::args_os()
        .nth(1)
        .map_or_else(|| PathBuf::from("demo/lifeline.trace.jsonl"), PathBuf::from);
    let events = write_lifeline_trace(&output)?;
    let final_hash = events
        .last()
        .map_or("none", |event| event.integrity.event_hash.as_str());
    println!(
        "wrote {} deterministic events to {}\nfinal hash: {}",
        events.len(),
        output.display(),
        final_hash
    );
    Ok(())
}
