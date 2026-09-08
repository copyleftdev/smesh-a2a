use std::fmt;
use std::io::Read as _;
use std::path::Path;

use zeroize::Zeroizing;

/// Redacted failure for owner-private secret files.
pub(crate) struct PrivateFileError;

impl fmt::Debug for PrivateFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateFileError")
    }
}

impl fmt::Display for PrivateFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("private file rejected")
    }
}

impl std::error::Error for PrivateFileError {}

/// Read exactly `N` raw bytes from one validated no-follow descriptor.
pub(crate) fn read_owner_private_exact<const N: usize>(
    path: &Path,
) -> Result<Zeroizing<[u8; N]>, PrivateFileError> {
    if !path.is_absolute() {
        return Err(PrivateFileError);
    }
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| PrivateFileError)?;
    let file = std::fs::File::from(descriptor);
    let metadata = file.metadata().map_err(|_| PrivateFileError)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if !metadata.is_file()
            || metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(PrivateFileError);
        }
    }
    let limit = N.checked_add(1).ok_or(PrivateFileError)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(limit));
    file.take(u64::try_from(limit).map_err(|_| PrivateFileError)?)
        .read_to_end(&mut bytes)
        .map_err(|_| PrivateFileError)?;
    let value: [u8; N] = bytes.as_slice().try_into().map_err(|_| PrivateFileError)?;
    Ok(Zeroizing::new(value))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::path::{Path, PathBuf};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "smesh-private-file-{}-{:016x}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::create_dir(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(root)
        }

        fn file(&self, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            path
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn rejected(path: &Path) {
        let error = super::read_owner_private_exact::<32>(path).unwrap_err();
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert_eq!(display, "private file rejected");
        assert_eq!(debug, "PrivateFileError");
        assert!(!display.contains(&path.to_string_lossy().to_string()));
    }

    #[test]
    fn accepts_exact_owner_private_raw_bytes() {
        let fixture = Fixture::new();
        let path = fixture.file("key", &[0xa5; 32], 0o600);
        assert_eq!(
            *super::read_owner_private_exact::<32>(&path).unwrap(),
            [0xa5; 32]
        );
    }

    #[test]
    fn rejects_non_absolute_symlink_directory_permissions_and_lengths() {
        let fixture = Fixture::new();
        rejected(Path::new("relative-key"));
        rejected(&fixture.0);
        rejected(&fixture.file("empty", &[], 0o600));
        rejected(&fixture.file("short", &[1; 31], 0o600));
        rejected(&fixture.file("long", &[2; 33], 0o600));
        rejected(&fixture.file(
            "newline",
            &[b'x'; 32].into_iter().chain(*b"\n").collect::<Vec<_>>(),
            0o600,
        ));
        rejected(&fixture.file("group", &[3; 32], 0o640));
        rejected(&fixture.file("world", &[4; 32], 0o604));
        let target = fixture.file("target", &[5; 32], 0o600);
        let link = fixture.0.join("link");
        symlink(target, &link).unwrap();
        rejected(&link);
    }

    #[test]
    fn errors_redact_path_and_secret_canaries() {
        let fixture = Fixture::new();
        let canary = b"RATIFICATION-CANARY-123456789012";
        assert_eq!(canary.len(), 32);
        let path = fixture.file("PATH-CANARY", canary, 0o640);
        let error = super::read_owner_private_exact::<32>(&path).unwrap_err();
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("PATH-CANARY"));
        assert!(!rendered.contains("RATIFICATION-CANARY"));
    }
}
