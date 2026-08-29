mod support;

use std::fs;

use smesh_a2a::{ArtifactBackupPlanFile, ArtifactKeyRotationPlanFile, ArtifactRestorePlanFile};
use support::artifact_test_root::ArtifactTestRoot;

#[cfg(unix)]
fn private(path: &std::path::Path, json: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    fs::write(path, json).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(unix)]
#[test]
fn operator_plans_are_strict_private_no_follow_and_bounded() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let root = ArtifactTestRoot::new("artifact-operator-plans");
    let backup_root = root.join("backup");
    fs::create_dir(&backup_root).unwrap();
    fs::set_permissions(&backup_root, fs::Permissions::from_mode(0o700)).unwrap();
    let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    let backup = root.join("backup.json");
    private(
        &backup,
        &format!(
            r#"{{"schema":"smesh-artifact-backup-plan/v1","backupId":"backup-1","source":{{"schema":"smesh_source","storeId":"{digest}"}},"artifactPolicy":{{"id":"artifact-policy","revision":1,"digest":"{digest}"}},"actor":"operator","reason":"scheduled backup","destination":"{}","batchSize":1000,"leaseDurationMillis":60000,"signatureHook":{{"command":"/usr/bin/true","args":["--detached"]}}}}"#,
            backup_root.display()
        ),
    );
    let loaded = ArtifactBackupPlanFile::open(&backup).unwrap();
    assert_eq!(loaded.batch_size(), 1000);
    assert_eq!(loaded.signature_hook().unwrap().args(), &["--detached"]);
    assert!(format!("{loaded:?}").contains("<redacted>"));

    let link = root.join("backup-link.json");
    symlink(&backup, &link).unwrap();
    assert!(ArtifactBackupPlanFile::open(&link).is_err());
    fs::set_permissions(&backup, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(ArtifactBackupPlanFile::open(&backup).is_err());

    let restore = root.join("restore.json");
    private(
        &restore,
        &format!(
            r#"{{"schema":"smesh-artifact-restore-plan/v1","restoreId":"restore-1","source":{{"backupRoot":"{}","inventory":"{}/inventory.json","storeId":"{digest}"}},"target":{{"schema":"smesh_target","storeId":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","root":"{}"}},"artifactPolicyDigest":"{digest}","actor":"operator","reason":"disaster recovery","batchSize":100,"clonePolicy":false}}"#,
            backup_root.display(),
            backup_root.display(),
            backup_root.display()
        ),
    );
    assert!(
        !ArtifactRestorePlanFile::open(&restore)
            .unwrap()
            .clone_policy()
    );

    let rotation = root.join("rotation.json");
    private(
        &rotation,
        &format!(
            r#"{{"schema":"smesh-artifact-key-rotation-plan/v1","rotationId":"rotation-1","source":{{"schema":"smesh_source","storeId":"{digest}"}},"encryptionDomain":"tenant-a/confidential","oldGeneration":"key-old","newGeneration":"key-new","policy":{{"id":"rotation-policy","revision":1,"digest":"{digest}"}},"actor":"operator","reason":"scheduled rotation","effectiveAt":1,"batchSize":1000,"leaseDurationMillis":60000,"rollbackHorizonMillis":60000}}"#
        ),
    );
    let loaded = ArtifactKeyRotationPlanFile::open(&rotation).unwrap();
    assert_eq!(loaded.plan().batch_size(), 1000);
    assert_eq!(loaded.rollback_horizon_millis(), 60000);
}
