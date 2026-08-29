#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// Test-owned trusted parent for artifact roots. Production correctly rejects
/// children of ambient world-writable temporary directories.
pub struct ArtifactTestRoot(PathBuf);

impl ArtifactTestRoot {
    pub fn new(label: &str) -> Self {
        let parent = std::env::var_os("SMESH_TEST_ARTIFACT_ROOT").map_or_else(
            || {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("target")
                    .join("artifact-tests")
            },
            PathBuf::from,
        );
        assert!(parent.is_absolute());
        std::fs::create_dir_all(&parent).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = parent.join(format!(
            "{label}-{}-{:016x}",
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
}

impl std::ops::Deref for ArtifactTestRoot {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<Path> for ArtifactTestRoot {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for ArtifactTestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
