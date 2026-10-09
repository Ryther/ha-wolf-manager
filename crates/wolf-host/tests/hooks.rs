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
fn newer_preimages_refuse_without_losing_other_files() {
    let root = tempdir().unwrap();
    let backup = tempdir().unwrap();
    fs::set_permissions(backup.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(root.path().join("first"), b"first original").unwrap();
    fs::write(root.path().join("second"), b"second original").unwrap();
    let grant = Grant::open(root.path()).unwrap();
    let store = TransactionStore::open(backup.path()).unwrap();
    let expected = vec![grant.read("first").unwrap(), grant.read("second").unwrap()];
    let overlays = [
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
    ];
    let calls = std::cell::Cell::new(0);
    assert!(
        hooks::apply_expected(&store, &overlays, &expected, || {
            let call = calls.get();
            calls.set(call + 1);
            if call == 1 {
                fs::write(root.path().join("second"), b"legitimate newer settings")?;
            }
            Ok(())
        })
        .is_err()
    );
    assert_eq!(grant.read("first").unwrap(), b"first original");
    assert_eq!(grant.read("second").unwrap(), b"legitimate newer settings");
    assert!(store.active().unwrap().is_empty());
}
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

#[test]
fn preimage_shape_mismatch_and_pending_overlay_refuse_without_overwriting_data() {
    let root = tempdir().unwrap();
    let backup = tempdir().unwrap();
    fs::set_permissions(backup.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(root.path().join("config"), b"original").unwrap();
    let grant = Grant::open(root.path()).unwrap();
    let store = TransactionStore::open(backup.path()).unwrap();
    let overlays = [Overlay {
        grant: &grant,
        relative: "config",
        bytes: b"overlay".to_vec(),
    }];
    assert!(
        hooks::apply_expected(&store, &overlays, &[], || panic!(
            "invalid shape reached writer check"
        ))
        .is_err()
    );
    assert_eq!(grant.read("config").unwrap(), b"original");
    hooks::apply(&store, &overlays, || Ok(())).unwrap();
    let before = store.active().unwrap();
    assert!(
        hooks::apply(
            &store,
            &[Overlay {
                grant: &grant,
                relative: "config",
                bytes: b"second overlay".to_vec()
            }],
            || Ok(())
        )
        .is_err()
    );
    assert_eq!(grant.read("config").unwrap(), b"overlay");
    assert_eq!(store.active().unwrap().len(), before.len());
    let meta = fs::metadata(root.path()).unwrap();
    assert!(hooks::restore(&store, &[], || Ok(())).is_err());
    assert_eq!(grant.read("config").unwrap(), b"overlay");
    assert_eq!(store.active().unwrap().len(), 1);
    hooks::restore(&store, &[(root.path(), meta.uid(), meta.gid())], || Ok(())).unwrap();
    assert_eq!(grant.read("config").unwrap(), b"original");
    assert!(store.active().unwrap().is_empty());
}

#[test]
fn writer_appearing_during_apply_preserves_overlay_and_recovery_until_quiescent() {
    let root = tempdir().unwrap();
    let backup = tempdir().unwrap();
    fs::set_permissions(backup.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(root.path().join("first"), b"original one").unwrap();
    fs::write(root.path().join("second"), b"original two").unwrap();
    let grant = Grant::open(root.path()).unwrap();
    let store = TransactionStore::open(backup.path()).unwrap();
    let calls = std::cell::Cell::new(0);
    assert!(
        hooks::apply(
            &store,
            &[
                Overlay {
                    grant: &grant,
                    relative: "first",
                    bytes: b"overlay one".to_vec()
                },
                Overlay {
                    grant: &grant,
                    relative: "second",
                    bytes: b"overlay two".to_vec()
                },
            ],
            || {
                let count = calls.get();
                calls.set(count + 1);
                if count >= 2 {
                    Err(std::io::Error::other("writer appeared"))
                } else {
                    Ok(())
                }
            }
        )
        .is_err()
    );
    assert_eq!(grant.read("first").unwrap(), b"overlay one");
    assert_eq!(grant.read("second").unwrap(), b"original two");
    assert_eq!(store.active().unwrap().len(), 1);
    let meta = fs::metadata(root.path()).unwrap();
    hooks::restore(&store, &[(root.path(), meta.uid(), meta.gid())], || Ok(())).unwrap();
    assert_eq!(grant.read("first").unwrap(), b"original one");
    assert!(store.active().unwrap().is_empty());
}
