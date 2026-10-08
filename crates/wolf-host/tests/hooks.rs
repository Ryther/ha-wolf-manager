use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
};
use tempfile::tempdir;
use wolf_manager_host::{
    hooks::{self, Overlay},
    transactions::{Grant, TransactionStore},
};
#[test]
fn multi_file_overlay_survives_restart_and_restores_all_originals() {
    let root = tempdir().unwrap();
    let backup = tempdir().unwrap();
    fs::set_permissions(backup.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(root.path().join("first"), b"first original").unwrap();
    fs::write(root.path().join("second"), b"second original").unwrap();
    let grant = Grant::open(root.path()).unwrap();
    let store = TransactionStore::open(backup.path()).unwrap();
    hooks::apply(
        &store,
        &[
            Overlay {
                grant: &grant,
                relative: "first",
                bytes: b"first overlay".to_vec(),
            },
            Overlay {
                grant: &grant,
                relative: "second",
                bytes: b"second overlay".to_vec(),
            },
        ],
        || Ok(()),
    )
    .unwrap();
    assert_eq!(grant.read("first").unwrap(), b"first overlay");
    drop(store);
    let store = TransactionStore::open(backup.path()).unwrap();
    let meta = fs::metadata(root.path()).unwrap();
    hooks::restore(&store, &[(root.path(), meta.uid(), meta.gid())], || Ok(())).unwrap();
    assert_eq!(grant.read("first").unwrap(), b"first original");
    assert_eq!(grant.read("second").unwrap(), b"second original");
    assert!(store.active().unwrap().is_empty());
}
#[test]
fn stopped_writer_proof_is_required_before_any_overlay() {
    let root = tempdir().unwrap();
    let backup = tempdir().unwrap();
    fs::set_permissions(backup.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(root.path().join("config"), b"original").unwrap();
    let grant = Grant::open(root.path()).unwrap();
    let store = TransactionStore::open(backup.path()).unwrap();
    assert!(
        hooks::apply(
            &store,
            &[Overlay {
                grant: &grant,
                relative: "config",
                bytes: b"changed".to_vec()
            }],
            || Err(std::io::Error::other("Steam running"))
        )
        .is_err()
    );
    assert_eq!(grant.read("config").unwrap(), b"original");
    assert!(store.active().unwrap().is_empty());
}
