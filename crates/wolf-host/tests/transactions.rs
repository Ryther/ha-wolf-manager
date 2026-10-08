use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};
use tempfile::tempdir;
use wolf_manager_host::transactions::{Grant, TransactionStore};

#[test]
fn apply_and_restore_preserve_original_bytes() {
    let root = tempdir().unwrap();
    let backups = tempdir().unwrap();
    fs::set_permissions(backups.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(root.path().join("config.vdf"), b"original Steam data").unwrap();
    let grant = Grant::open(root.path()).unwrap();
    let store = TransactionStore::open(backups.path()).unwrap();
    let transaction = store
        .apply(&grant, "config.vdf", b"managed settings")
        .unwrap();
    assert_eq!(
        fs::read(root.path().join("config.vdf")).unwrap(),
        b"managed settings"
    );
    store.restore(&grant, &transaction).unwrap();
    assert_eq!(
        fs::read(root.path().join("config.vdf")).unwrap(),
        b"original Steam data"
    );
    assert_eq!(
        fs::metadata(root.path().join("config.vdf"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
}

#[test]
fn restore_drift_preserves_current_and_backup_bytes() {
    let root = tempdir().unwrap();
    let backups = tempdir().unwrap();
    fs::set_permissions(backups.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(root.path().join("config.vdf"), b"original").unwrap();
    let grant = Grant::open(root.path()).unwrap();
    let store = TransactionStore::open(backups.path()).unwrap();
    let transaction = store.apply(&grant, "config.vdf", b"managed").unwrap();
    fs::write(root.path().join("config.vdf"), b"legitimate later settings").unwrap();
    assert!(store.restore(&grant, &transaction).is_err());
    assert_eq!(
        fs::read(root.path().join("config.vdf")).unwrap(),
        b"legitimate later settings"
    );
    assert_eq!(store.preimage(&transaction).unwrap(), b"original");
    assert!(store.recovery_pending().unwrap());
}

#[test]
fn symlink_hardlink_and_traversal_refuse_without_writing() {
    let root = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let backups = tempdir().unwrap();
    fs::set_permissions(backups.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(outside.path().join("private"), b"outside state").unwrap();
    symlink(outside.path().join("private"), root.path().join("alias")).unwrap();
    fs::write(root.path().join("regular"), b"inside state").unwrap();
    fs::hard_link(root.path().join("regular"), root.path().join("linked")).unwrap();
    let grant = Grant::open(root.path()).unwrap();
    let store = TransactionStore::open(backups.path()).unwrap();
    for path in ["alias", "linked", "../private", "/etc/passwd"] {
        assert!(
            store.apply(&grant, path, b"new").is_err(),
            "accepted {path}"
        );
    }
    assert_eq!(
        fs::read(outside.path().join("private")).unwrap(),
        b"outside state"
    );
    assert_eq!(
        fs::read(root.path().join("regular")).unwrap(),
        b"inside state"
    );
}

#[test]
fn backup_corruption_refuses_restore_without_overwriting() {
    let root = tempdir().unwrap();
    let backups = tempdir().unwrap();
    fs::set_permissions(backups.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(root.path().join("config.vdf"), b"original").unwrap();
    let grant = Grant::open(root.path()).unwrap();
    let store = TransactionStore::open(backups.path()).unwrap();
    let transaction = store.apply(&grant, "config.vdf", b"managed").unwrap();
    fs::write(
        backups
            .path()
            .join(transaction.to_string())
            .join("preimage"),
        b"corrupt",
    )
    .unwrap();
    assert!(store.restore(&grant, &transaction).is_err());
    assert_eq!(
        fs::read(root.path().join("config.vdf")).unwrap(),
        b"managed"
    );
}

#[test]
fn refuses_public_backup_directory_and_missing_target() {
    let root = tempdir().unwrap();
    let backups = tempdir().unwrap();
    fs::set_permissions(backups.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(TransactionStore::open(backups.path()).is_err());
    fs::set_permissions(backups.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let store = TransactionStore::open(backups.path()).unwrap();
    let grant = Grant::open(root.path()).unwrap();
    assert!(store.apply(&grant, "missing", b"new").is_err());
    assert!(!root.path().join("missing").exists());
}

#[test]
fn reopened_store_preserves_active_backup_and_blocks_duplicate_application() {
    let root = tempdir().unwrap();
    let backups = tempdir().unwrap();
    fs::set_permissions(backups.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(root.path().join("config"), b"original").unwrap();
    let grant = Grant::open(root.path()).unwrap();
    let id = TransactionStore::open(backups.path())
        .unwrap()
        .apply(&grant, "config", b"managed")
        .unwrap();
    let reopened = TransactionStore::open(backups.path()).unwrap();
    assert!(
        reopened
            .apply(&grant, "config", b"second overwrite")
            .is_err()
    );
    assert_eq!(fs::read(root.path().join("config")).unwrap(), b"managed");
    reopened.restore(&grant, &id).unwrap();
    reopened.restore(&grant, &id).unwrap();
    assert_eq!(fs::read(root.path().join("config")).unwrap(), b"original");
}

#[test]
fn nested_directory_alias_is_refused_and_disappeared_target_is_preserved() {
    let root = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let backups = tempdir().unwrap();
    fs::set_permissions(backups.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(outside.path().join("config"), b"outside").unwrap();
    symlink(outside.path(), root.path().join("folder")).unwrap();
    let store = TransactionStore::open(backups.path()).unwrap();
    let grant = Grant::open(root.path()).unwrap();
    assert!(store.apply(&grant, "folder/config", b"escape").is_err());
    fs::write(root.path().join("config"), b"original").unwrap();
    let id = store.apply(&grant, "config", b"managed").unwrap();
    fs::remove_file(root.path().join("config")).unwrap();
    assert!(store.restore(&grant, &id).is_err());
    assert!(!root.path().join("config").exists());
    assert_eq!(store.preimage(&id).unwrap(), b"original");
}

#[test]
fn replaced_nested_parent_is_refused_without_changing_either_directory() {
    let root = tempdir().unwrap();
    let backups = tempdir().unwrap();
    fs::set_permissions(backups.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(root.path().join("folder")).unwrap();
    fs::write(root.path().join("folder/config"), b"original").unwrap();
    let grant = Grant::open(root.path()).unwrap();
    let store = TransactionStore::open(backups.path()).unwrap();
    let id = store.apply(&grant, "folder/config", b"managed").unwrap();
    fs::rename(root.path().join("folder"), root.path().join("folder-old")).unwrap();
    fs::create_dir(root.path().join("folder")).unwrap();
    fs::write(root.path().join("folder/config"), b"managed").unwrap();
    assert!(store.restore(&grant, &id).is_err());
    assert_eq!(
        fs::read(root.path().join("folder/config")).unwrap(),
        b"managed"
    );
    assert_eq!(
        fs::read(root.path().join("folder-old/config")).unwrap(),
        b"managed"
    );
    assert_eq!(store.preimage(&id).unwrap(), b"original");
    assert!(store.recovery_pending().unwrap());
}

#[test]
fn extended_attributes_survive_apply_and_restore() {
    use rustix::fs::{XattrFlags, fgetxattr, fsetxattr};
    let root = tempdir().unwrap();
    let backups = tempdir().unwrap();
    fs::set_permissions(backups.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.path().join("config");
    fs::write(&path, b"original").unwrap();
    fsetxattr(
        fs::File::open(&path).unwrap(),
        "user.wolf-test",
        b"preserved metadata",
        XattrFlags::empty(),
    )
    .unwrap();
    let grant = Grant::open(root.path()).unwrap();
    let store = TransactionStore::open(backups.path()).unwrap();
    let id = store.apply(&grant, "config", b"managed").unwrap();
    let mut buffer = [0u8; 128];
    let length = fgetxattr(
        fs::File::open(&path).unwrap(),
        "user.wolf-test",
        &mut buffer[..],
    )
    .unwrap();
    assert_eq!(&buffer[..length], b"preserved metadata");
    store.restore(&grant, &id).unwrap();
    let length = fgetxattr(
        fs::File::open(&path).unwrap(),
        "user.wolf-test",
        &mut buffer[..],
    )
    .unwrap();
    assert_eq!(&buffer[..length], b"preserved metadata");
}

#[test]
fn posix_access_acl_is_preserved() {
    use rustix::fs::{XattrFlags, fgetxattr, fsetxattr};
    let root = tempdir().unwrap();
    let backups = tempdir().unwrap();
    fs::set_permissions(backups.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.path().join("config");
    fs::write(&path, b"original").unwrap();
    let mut acl = 2u32.to_le_bytes().to_vec();
    for (tag, permission, id) in [
        (1u16, 6u16, u32::MAX),
        (2, 4, 1001),
        (4, 4, u32::MAX),
        (16, 4, u32::MAX),
        (32, 4, u32::MAX),
    ] {
        acl.extend(tag.to_le_bytes());
        acl.extend(permission.to_le_bytes());
        acl.extend(id.to_le_bytes());
    }
    fsetxattr(
        fs::File::open(&path).unwrap(),
        "system.posix_acl_access",
        &acl,
        XattrFlags::empty(),
    )
    .unwrap();
    let grant = Grant::open(root.path()).unwrap();
    let store = TransactionStore::open(backups.path()).unwrap();
    let id = store.apply(&grant, "config", b"managed").unwrap();
    for restore in [false, true] {
        if restore {
            store.restore(&grant, &id).unwrap();
        }
        let mut buffer = [0u8; 128];
        let length = fgetxattr(
            fs::File::open(&path).unwrap(),
            "system.posix_acl_access",
            &mut buffer[..],
        )
        .unwrap();
        assert_eq!(&buffer[..length], acl);
    }
}
#[test]
fn interrupted_quarantine_recovers_from_verified_preimage() {
    use sha2::{Digest, Sha256};
    let root = tempdir().unwrap();
    let backups = tempdir().unwrap();
    fs::set_permissions(backups.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.path().join("config");
    fs::write(&path, b"original").unwrap();
    let grant = Grant::open(root.path()).unwrap();
    let store = TransactionStore::open(backups.path()).unwrap();
    let id = store.apply(&grant, "config", b"managed").unwrap();
    // Reconstruct a crash snapshot after quarantine, before staged-file rename.
    fs::remove_file(&path).unwrap();
    let manifest_path = backups.path().join(id.to_string()).join("manifest.json");
    // Struct serialization uses field order, so reconstruct it from the original bytes order.
    let original = fs::read_to_string(&manifest_path).unwrap();
    let mut typed_manifest = original
        .split("\"manifest\":")
        .nth(1)
        .unwrap()
        .split(",\"checksum\":")
        .next()
        .unwrap()
        .to_owned();
    typed_manifest = typed_manifest.replace("\"phase\":\"applied\"", "\"phase\":\"quarantined\"");
    let ordered_checksum: String = Sha256::digest(typed_manifest.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    fs::write(
        &manifest_path,
        format!("{{\"manifest\":{typed_manifest},\"checksum\":\"{ordered_checksum}\"}}"),
    )
    .unwrap();
    let reopened = TransactionStore::open(backups.path()).unwrap();
    assert!(reopened.recovery_pending().unwrap());
    reopened.restore(&grant, &id).unwrap();
    assert_eq!(fs::read(path).unwrap(), b"original");
    assert!(!reopened.recovery_pending().unwrap());
}

#[test]
fn parent_symlink_after_apply_is_durable_recovery_conflict() {
    let root = tempdir().unwrap();
    let backups = tempdir().unwrap();
    fs::set_permissions(backups.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(root.path().join("folder")).unwrap();
    fs::write(root.path().join("folder/config"), b"original").unwrap();
    let grant = Grant::open(root.path()).unwrap();
    let store = TransactionStore::open(backups.path()).unwrap();
    let id = store.apply(&grant, "folder/config", b"managed").unwrap();
    fs::rename(root.path().join("folder"), root.path().join("moved")).unwrap();
    symlink(root.path().join("moved"), root.path().join("folder")).unwrap();
    assert!(store.restore(&grant, &id).is_err());
    assert!(store.recovery_pending().unwrap());
    assert_eq!(
        fs::read(root.path().join("moved/config")).unwrap(),
        b"managed"
    );
}
