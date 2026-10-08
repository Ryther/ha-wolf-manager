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
