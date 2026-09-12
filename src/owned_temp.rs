use std::io;
use std::path::{Path, PathBuf};

/// A private directory removed only by the process that created it atomically.
#[derive(Debug)]
pub struct OwnedTempDir {
    root: Option<PathBuf>,
}

impl OwnedTempDir {
    pub fn create(prefix: &str) -> io::Result<Self> {
        Self::create_in(&std::env::temp_dir(), prefix)
    }

    pub fn create_in(parent: &Path, prefix: &str) -> io::Result<Self> {
        Self::create_with_tokens(parent, prefix, || {
            format!("{:032x}", rand::random::<u128>())
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        self.root
            .as_deref()
            .expect("owned temporary directory active")
    }

    /// Remove this owned directory now and report any cleanup failure.
    pub fn close(mut self) -> io::Result<()> {
        let root = self.root.take().expect("owned temporary directory active");
        std::fs::remove_dir_all(root)
    }

    /// Transfer ownership after an atomic publication moved this directory.
    pub fn relinquish(mut self) {
        self.root = None;
    }

    fn create_with_tokens(
        parent: &Path,
        prefix: &str,
        mut next_token: impl FnMut() -> String,
    ) -> io::Result<Self> {
        for _ in 0..128 {
            let root = parent.join(format!("{prefix}{}", next_token()));
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            match builder.create(&root) {
                Ok(()) => return Ok(Self { root: Some(root) }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique private temporary directory",
        ))
    }
}

impl Drop for OwnedTempDir {
    fn drop(&mut self) {
        if let Some(root) = self.root.take() {
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::OwnedTempDir;

    #[test]
    fn collision_is_preserved_and_a_different_directory_is_owned() {
        let parent = OwnedTempDir::create("smesh-owned-temp-test-parent-").unwrap();
        let collision = parent.path().join("candidate-collision");
        std::fs::create_dir(&collision).unwrap();
        let sentinel = collision.join("sentinel");
        std::fs::write(&sentinel, b"unrelated").unwrap();
        let mut tokens = ["collision", "owned"].into_iter();

        let owned = OwnedTempDir::create_with_tokens(parent.path(), "candidate-", || {
            tokens.next().unwrap().to_owned()
        })
        .unwrap();

        assert_eq!(std::fs::read(&sentinel).unwrap(), b"unrelated");
        assert_eq!(owned.path(), parent.path().join("candidate-owned"));
        let owned_path = owned.path().to_owned();
        drop(owned);
        assert!(!owned_path.exists());
        assert_eq!(std::fs::read(sentinel).unwrap(), b"unrelated");
    }

    #[cfg(unix)]
    #[test]
    fn explicit_close_reports_cleanup_failure() {
        use std::os::unix::fs::PermissionsExt as _;

        let parent = OwnedTempDir::create("smesh-owned-temp-close-parent-").unwrap();
        let owned = OwnedTempDir::create_in(parent.path(), "owned-").unwrap();
        std::fs::write(owned.path().join("retained"), b"data").unwrap();
        std::fs::set_permissions(owned.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let path = owned.path().to_owned();
        let error = owned.close().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn relinquish_transfers_cleanup_ownership() {
        let owned = OwnedTempDir::create("smesh-owned-temp-relinquish-").unwrap();
        let path = owned.path().to_owned();
        owned.relinquish();
        assert!(path.exists());
        std::fs::remove_dir(path).unwrap();
    }
}
