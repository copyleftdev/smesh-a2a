//! Debug-build, process-level artifact crash checkpoints.
//!
//! Production owners call this at durable/physical boundaries. The hook is a
//! release-build no-op and is armed only by an exact test environment value.

/// Block an armed debug/test process at a production-owned artifact boundary.
///
/// The parent observes `READY`, then either kills the process (a crash cut) or
/// writes the exact `GO <checkpoint>` line to stdin. No timing delay is used.
#[doc(hidden)]
pub fn artifact_production_checkpoint(checkpoint: &str) {
    #[cfg(debug_assertions)]
    {
        use std::io::{BufRead as _, Write as _};

        if std::env::var("SMESH_TEST_ARTIFACT_CHECKPOINT").as_deref() != Ok(checkpoint) {
            return;
        }
        println!("SMESH_ARTIFACT_CHECKPOINT READY {checkpoint}");
        std::io::stdout()
            .flush()
            .expect("artifact checkpoint READY flush");
        let mut release = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut release)
            .expect("artifact checkpoint GO read");
        assert_eq!(
            release.trim_end(),
            format!("GO {checkpoint}"),
            "artifact checkpoint parent sent an invalid release"
        );
    }

    #[cfg(not(debug_assertions))]
    let _ = checkpoint;
}
