#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use wait_timeout::ChildExt as _;

const WATCHDOG: Duration = Duration::from_secs(30);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "smesh-durable-api-boundary-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path).expect("create API-boundary fixture");
        Self(path)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.0.exists() {
            std::fs::remove_dir_all(&self.0).expect("remove API-boundary fixture");
        }
    }
}

fn current_library(deps: &Path) -> PathBuf {
    let mut candidates = std::fs::read_dir(deps)
        .expect("read Cargo dependency output")
        .map(|entry| entry.expect("read Cargo dependency entry").path())
        .filter(|path| {
            path.file_name().is_some_and(|name| {
                let name = name.to_string_lossy();
                name.starts_with("libsmesh_a2a-") && name.ends_with(".rlib")
            })
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|path| {
        std::fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .expect("read library modification time")
    });
    candidates.pop().expect("current smesh_a2a rlib")
}

#[test]
fn external_crate_cannot_stop_or_take_the_required_durable_driver() {
    let fixture = Fixture::new();
    let source = fixture.0.join("escape_hatch.rs");
    std::fs::write(
        &source,
        r"use smesh_a2a::DurableGateway;

fn escape(mut gateway: DurableGateway) {
    let _ = gateway.stop_driver_for_test();
    let _ = gateway.take_driver();
}
",
    )
    .expect("write external-crate compile fixture");

    let deps = std::env::current_exe()
        .expect("current test executable")
        .parent()
        .expect("Cargo dependency directory")
        .to_path_buf();
    let library = current_library(&deps);
    let mut child = Command::new("rustc")
        .arg("--edition=2024")
        .arg("--crate-type=lib")
        .arg("--emit=metadata")
        .arg("--out-dir")
        .arg(&fixture.0)
        .arg("--extern")
        .arg(format!("smesh_a2a={}", library.display()))
        .arg("-L")
        .arg(format!("dependency={}", deps.display()))
        .arg(&source)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rustc API-boundary fixture");
    if child
        .wait_timeout(WATCHDOG)
        .expect("wait for rustc API-boundary fixture")
        .is_none()
    {
        child
            .kill()
            .expect("kill timed-out rustc API-boundary fixture");
    }
    let output = child
        .wait_with_output()
        .expect("reap rustc API-boundary fixture");
    assert!(!output.status.success(), "driver escape hatch compiled");
    let stderr = String::from_utf8(output.stderr).expect("rustc diagnostics are UTF-8");
    for missing in ["stop_driver_for_test", "take_driver"] {
        assert!(
            stderr.contains(&format!("no method named `{missing}`")),
            "compile failure did not prove the intended missing-method boundary: {stderr}"
        );
    }

    std::fs::remove_file(&source).expect("remove external-crate compile fixture source");
    assert!(!source.exists(), "compile fixture source was not removed");
    let metadata = fixture.0.join("libescape_hatch.rmeta");
    assert!(
        !metadata.exists(),
        "compile-fail fixture unexpectedly produced metadata"
    );
}
