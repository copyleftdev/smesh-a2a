use std::collections::HashMap;
use std::error::Error;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use serde_json::Value;
use smesh_a2a::{
    LifelineDirectorManifest, LifelineFailureTrace, LifelineResponseDirector,
    LifelineTeamFailureMode, LifelineTeamManifest, LifelineTopologyManifest,
    verify_lifeline_failure_trace,
};

const TOPOLOGY: &str = include_str!("../../deploy/lifeline-topology.json");
const DIRECTOR: &str = include_str!("../../deploy/lifeline-director.json");
const STAGING_PREFIX: &str = ".lifeline-failure-staging-";

#[cfg(test)]
thread_local! {
    static FAIL_OUTPUT_PARENT_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

struct OwnedRunDirectory {
    path: PathBuf,
    final_path: PathBuf,
    staging_name: std::ffi::OsString,
    parent: std::fs::File,
    lease: std::fs::File,
    committed: bool,
}
impl OwnedRunDirectory {
    fn create(path: &Path) -> Result<Self, std::io::Error> {
        use std::os::fd::AsRawFd as _;
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt as _;

        let parent_path = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let final_name = path
            .file_name()
            .ok_or_else(|| std::io::Error::other("output directory name is absent"))?;
        let parent = open_directory_no_symlinks(parent_path)?;
        let parent_metadata = parent.metadata()?;
        #[cfg(unix)]
        {
            let mode = parent_metadata.mode();
            let owner = parent_metadata.uid();
            let current = rustix::process::geteuid().as_raw();
            if owner != current && owner != 0 {
                return Err(std::io::Error::other("output parent owner is not trusted"));
            }
            if mode & 0o022 != 0 && mode & 0o1000 == 0 {
                return Err(std::io::Error::other(
                    "writable output parent must use the sticky bit",
                ));
            }
        }
        rustix::fs::flock(
            &parent,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|error| {
            if error == rustix::io::Errno::WOULDBLOCK {
                std::io::Error::other("output parent is already owned by another run")
            } else {
                error.into()
            }
        })?;
        match rustix::fs::statat(&parent, final_name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "output directory already exists",
                ));
            }
            Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(error.into()),
        }
        let parent_path = std::fs::canonicalize(format!("/proc/self/fd/{}", parent.as_raw_fd()))?;
        reconcile_stale_staging(&parent_path, &parent)?;
        let staging_name = std::ffi::OsString::from(format!(
            "{STAGING_PREFIX}{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        rustix::fs::mkdirat(
            &parent,
            &staging_name,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR | rustix::fs::Mode::XUSR,
        )?;
        let lease = match open_and_lock_staging(&parent, &staging_name) {
            Ok(lease) => lease,
            Err(error) => {
                let _ =
                    rustix::fs::unlinkat(&parent, &staging_name, rustix::fs::AtFlags::REMOVEDIR);
                return Err(error);
            }
        };
        let path = PathBuf::from(format!("/proc/self/fd/{}", lease.as_raw_fd()));
        Ok(Self {
            path,
            final_path: parent_path.join(final_name),
            staging_name,
            parent,
            lease,
            committed: false,
        })
    }
    fn commit(&mut self) -> Result<(), std::io::Error> {
        self.lease.sync_all()?;
        let final_name = self
            .final_path
            .file_name()
            .ok_or_else(|| std::io::Error::other("output directory name is absent"))?;
        rustix::fs::renameat_with(
            &self.parent,
            &self.staging_name,
            &self.parent,
            final_name,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        self.committed = true;
        sync_output_parent(&self.parent)
    }
}

fn sync_output_parent(parent: &std::fs::File) -> Result<(), std::io::Error> {
    #[cfg(test)]
    if FAIL_OUTPUT_PARENT_SYNC.with(|fail| fail.replace(false)) {
        return Err(std::io::Error::other(
            "injected output parent synchronization failure",
        ));
    }
    parent.sync_all()
}

fn open_directory_no_symlinks(path: &Path) -> Result<std::fs::File, std::io::Error> {
    let start = if path.is_absolute() {
        Path::new("/")
    } else {
        Path::new(".")
    };
    let descriptor = rustix::fs::openat(
        rustix::fs::CWD,
        start,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let mut current = std::fs::File::from(descriptor);
    for component in path.components() {
        let name = match component {
            std::path::Component::RootDir | std::path::Component::CurDir => continue,
            std::path::Component::Normal(name) => name,
            std::path::Component::ParentDir | std::path::Component::Prefix(_) => {
                return Err(std::io::Error::other(
                    "output parent must not contain parent or platform-prefix components",
                ));
            }
        };
        let descriptor = rustix::fs::openat(
            &current,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        current = std::fs::File::from(descriptor);
    }
    Ok(current)
}

fn open_and_lock_staging(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
) -> Result<std::fs::File, std::io::Error> {
    let descriptor = rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let descriptor = std::fs::File::from(descriptor);
    rustix::fs::flock(&descriptor, rustix::fs::FlockOperation::LockExclusive)?;
    Ok(descriptor)
}

fn reconcile_stale_staging(
    parent_path: &Path,
    parent: &std::fs::File,
) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt as _;

    for entry in std::fs::read_dir(parent_path)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name_text) = name.to_str() else {
            continue;
        };
        if !name_text.starts_with(STAGING_PREFIX) {
            continue;
        }
        let descriptor = match rustix::fs::openat(
            parent,
            &name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Ok(descriptor) => std::fs::File::from(descriptor),
            Err(rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR) => continue,
            Err(error) => return Err(error.into()),
        };
        let metadata = descriptor.metadata()?;
        #[cfg(unix)]
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o777 != 0o700
        {
            continue;
        }
        match rustix::fs::flock(
            &descriptor,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        ) {
            Ok(()) => {}
            Err(rustix::io::Errno::WOULDBLOCK) => continue,
            Err(error) => return Err(error.into()),
        }
        let candidate = parent_path.join(&name);
        let current = match std::fs::symlink_metadata(&candidate) {
            Ok(current) => current,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        #[cfg(unix)]
        if current.dev() != metadata.dev() || current.ino() != metadata.ino() {
            continue;
        }
        clear_directory(&descriptor)?;
        rustix::fs::unlinkat(parent, &name, rustix::fs::AtFlags::REMOVEDIR)?;
        parent.sync_all()?;
    }
    Ok(())
}

fn clear_directory(directory: &std::fs::File) -> Result<(), std::io::Error> {
    use std::os::fd::AsRawFd as _;

    let path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            std::fs::remove_dir_all(entry.path())?;
        } else {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

impl Drop for OwnedRunDirectory {
    fn drop(&mut self) {
        if !self.committed {
            let _ = clear_directory(&self.lease);
            let _ = rustix::fs::unlinkat(
                &self.parent,
                &self.staging_name,
                rustix::fs::AtFlags::REMOVEDIR,
            );
            let _ = self.parent.sync_all();
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os();
    let binary = args
        .next()
        .unwrap_or_else(|| "lifeline-failure-scenario".into());
    let usage = || {
        format!(
            "usage: {} <team-manifest.json> <new-output-directory>\n       {} verify <run.json> <restricted-scenario.jsonl>",
            Path::new(&binary).display(),
            Path::new(&binary).display()
        )
    };
    let first = args.next().ok_or_else(usage)?;
    if first == "verify" {
        let run_path = args.next().ok_or_else(usage)?;
        let trace_path = args.next().ok_or_else(usage)?;
        if args.next().is_some() {
            return Err("unexpected extra argument".into());
        }
        let run: smesh_a2a::LifelineFailureScenarioRun =
            serde_json::from_str(&read_bounded_utf8(Path::new(&run_path), 256 * 1024)?)?;
        let events = verify_lifeline_failure_trace(Path::new(&trace_path))?;
        run.verify(&events)?;
        println!("{}", Path::new(&run_path).display());
        return Ok(());
    }
    let manifest_path = first;
    let output_path = args.next().ok_or_else(usage)?;
    if args.next().is_some() {
        return Err("unexpected extra argument".into());
    }

    let manifest = LifelineTeamManifest::from_json(&read_bounded_utf8(
        Path::new(&manifest_path),
        256 * 1024,
    )?)?;
    let output_path = PathBuf::from(output_path);
    let mut output = OwnedRunDirectory::create(&output_path)?;
    let trace_path = output.path.join("restricted-scenario.jsonl");
    let trace = LifelineFailureTrace::create(&trace_path)?;
    let failure = LifelineTeamFailureMode::new(trace.clone());
    let topology = LifelineTopologyManifest::from_json(TOPOLOGY)?.with_ephemeral_loopback_ports();
    let running = manifest
        .launch_failure_topology(topology, output.path.join("journals"), failure.clone())
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
    let director = LifelineResponseDirector::new(rewrite_director_discovery(&endpoints)?);
    let run_result = director.run_failure_scenario(failure).await;
    let shutdown_result = running.shutdown().await;
    let run = run_result?;
    shutdown_result?;
    trace.sync()?;
    let events = verify_lifeline_failure_trace(&trace_path)?;
    run.verify(&events)?;
    let mut bytes = serde_json::to_vec_pretty(&run)?;
    bytes.push(b'\n');
    let run_path = output.path.join("run.json");
    write_private_new(&run_path, &bytes)?;
    let persisted_run: smesh_a2a::LifelineFailureScenarioRun =
        serde_json::from_str(&read_bounded_utf8(&run_path, 256 * 1024)?)?;
    let persisted_events = verify_lifeline_failure_trace(&trace_path)?;
    persisted_run.verify(&persisted_events)?;
    output.commit()?;
    println!("{}", output.final_path.join("run.json").display());
    Ok(())
}

fn read_bounded_utf8(path: &Path, limit: usize) -> Result<String, Box<dyn Error>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > limit as u64 {
        return Err("manifest must be a bounded regular file".into());
    }
    let capacity = usize::try_from(metadata.len())?;
    let mut bytes = Vec::with_capacity(capacity);
    std::fs::File::open(path)?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("manifest exceeds the byte limit".into());
    }
    Ok(String::from_utf8(bytes)?)
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
        gateway["discoveryUrl"] = Value::String(
            endpoints
                .get(id)
                .ok_or_else(|| format!("missing endpoint for {id}"))?
                .clone(),
        );
    }
    Ok(LifelineDirectorManifest::from_json(&director.to_string())?)
}

fn write_private_new(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn final_output_is_not_visible_before_atomic_commit() {
        let parent = std::env::temp_dir().join(format!(
            "smesh-failure-publication-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&parent).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let final_path = parent.join("run");

        let output = OwnedRunDirectory::create(&final_path).unwrap();

        assert!(!final_path.exists());
        assert!(output.path.exists());
        drop(output);
        assert!(!final_path.exists());
        std::fs::remove_dir(parent).unwrap();
    }

    #[test]
    fn parent_sync_failure_after_rename_preserves_published_output() {
        let parent = std::env::temp_dir().join(format!(
            "smesh-failure-parent-sync-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&parent).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let final_path = parent.join("published");
        let mut output = OwnedRunDirectory::create(&final_path).unwrap();
        std::fs::write(output.path.join("run.json"), b"{}\n").unwrap();
        std::fs::write(output.path.join("restricted-scenario.jsonl"), b"{}\n").unwrap();

        FAIL_OUTPUT_PARENT_SYNC.with(|fail| fail.set(true));
        assert!(output.commit().is_err());
        drop(output);

        assert!(final_path.join("run.json").is_file());
        assert!(final_path.join("restricted-scenario.jsonl").is_file());
        assert!(std::fs::read_dir(&parent).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(STAGING_PREFIX)
        }));
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn stale_staging_is_reconciled_without_touching_live_staging() {
        let parent = std::env::temp_dir().join(format!(
            "smesh-failure-reconcile-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&parent).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let stale = parent.join(".lifeline-failure-staging-1-1");
        let live = parent.join(".lifeline-failure-staging-1-2");
        std::fs::create_dir(&stale).unwrap();
        std::fs::create_dir(&live).unwrap();
        #[cfg(unix)]
        {
            std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(&live, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let live_lease = std::fs::File::open(&live).unwrap();
        rustix::fs::flock(&live_lease, rustix::fs::FlockOperation::LockExclusive).unwrap();

        let final_path = parent.join("run");
        let output = OwnedRunDirectory::create(&final_path).unwrap();

        assert!(!stale.exists());
        assert!(live.exists());
        drop(output);
        drop(live_lease);
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlink_output_parent_is_rejected() {
        let root = std::env::temp_dir().join(format!(
            "smesh-failure-parent-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let real = root.join("real");
        let link = root.join("link");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let final_path = link.join("run");
        let result = OwnedRunDirectory::create(&final_path);

        assert!(result.is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn intermediate_symlink_in_output_parent_is_rejected() {
        let root = std::env::temp_dir().join(format!(
            "smesh-failure-ancestor-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let real = root.join("real");
        let nested = real.join("nested");
        let link = root.join("link");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&real).unwrap();
        std::fs::create_dir(&nested).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let result = OwnedRunDirectory::create(&link.join("nested/run"));

        assert!(result.is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrently_owned_output_parent_is_rejected() {
        let parent = std::env::temp_dir().join(format!(
            "smesh-failure-parent-lock-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&parent).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let owner = std::fs::File::open(&parent).unwrap();
        rustix::fs::flock(&owner, rustix::fs::FlockOperation::LockExclusive).unwrap();

        let result = OwnedRunDirectory::create(&parent.join("run"));

        assert!(result.is_err());
        drop(owner);
        std::fs::remove_dir(parent).unwrap();
    }
}
