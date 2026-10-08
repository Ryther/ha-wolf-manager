use ha_wolf_manager::{bundle, domain::PcInput, recovery::Recovery, ssh, store::Store};
use std::{fs, os::unix::fs::PermissionsExt};
use tempfile::tempdir;
use wolf_core::PcId;
fn populate(root: &std::path::Path) -> Vec<u8> {
    let mut store = Store::open(root, 1).unwrap();
    let pc = PcId::new("fixture").unwrap();
    store
        .add_pc(
            PcInput {
                pc_id: pc.clone(),
                display_name: "Fixture".into(),
                ssh_host: "localhost".into(),
                ssh_port: 22,
                ssh_user: "wolf-manager".into(),
            },
            2,
        )
        .unwrap();
    let public = ssh::ensure_identity(root, &pc).unwrap();
    let key = russh::keys::PublicKey::from_openssh(&public).unwrap();
    let connection = rusqlite::Connection::open(root.join("manager.sqlite3")).unwrap();
    connection.execute("UPDATE pcs SET enrolled_public_key=?1,host_key_algorithm=?2,host_key_public=?1,host_key_fingerprint=?3",rusqlite::params![public,key.algorithm().to_string(),key.fingerprint(russh::keys::HashAlg::Sha256).to_string()]).unwrap();
    drop(connection);
    drop(store);
    Recovery::open(root, 3)
        .unwrap()
        .reset_password("SyntheticPassword!42", 4)
        .unwrap();
    fs::read(root.join("keys/fixture/id_ed25519")).unwrap()
}
#[test]
fn matched_bundle_restores_account_state_and_exact_key_without_touching_source() {
    let temp = tempdir().unwrap();
    let data = temp.path().join("data");
    let key = populate(&data);
    let before = fs::read(data.join("manager.sqlite3")).unwrap();
    let trust_before = account_and_trust(&data);
    let backup = temp.path().join("bundle");
    bundle::backup(&data, &backup).unwrap();
    assert_eq!(before, fs::read(data.join("manager.sqlite3")).unwrap());
    bundle::preview(&backup).unwrap();
    let target = temp.path().join("restored");
    assert!(bundle::restore(&backup, &target).unwrap().is_none());
    assert_eq!(
        key,
        fs::read(target.join("keys/fixture/id_ed25519")).unwrap()
    );
    assert_eq!(
        b"initialized-v1\n",
        fs::read(target.join("initialized")).unwrap().as_slice()
    );
    assert_eq!(trust_before, account_and_trust(&target));
    assert_eq!(1, Store::open(&target, 5).unwrap().pcs().unwrap().len());
}
#[test]
fn tamper_alias_and_mode_refuse_before_destination_changes() {
    let temp = tempdir().unwrap();
    let data = temp.path().join("data");
    populate(&data);
    let backup = temp.path().join("bundle");
    bundle::backup(&data, &backup).unwrap();
    fs::write(backup.join("keys/fixture/id_ed25519"), b"tampered").unwrap();
    assert!(bundle::preview(&backup).is_err());
    let target = temp.path().join("new");
    assert!(bundle::restore(&backup, &target).is_err());
    assert!(!target.exists());
    let alias = temp.path().join("alias");
    std::os::unix::fs::symlink(&data, &alias).unwrap();
    assert!(bundle::backup(&alias, &temp.path().join("bad")).is_err());
    fs::set_permissions(&backup, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(bundle::preview(&backup).is_err());
}
#[test]
fn whole_directory_restore_preserves_old_target_as_verified_rollback() {
    let temp = tempdir().unwrap();
    let source = temp.path().join("source");
    let original = populate(&source);
    let backup = temp.path().join("bundle");
    bundle::backup(&source, &backup).unwrap();
    let target = temp.path().join("target");
    let old = populate(&target);
    assert_ne!(old, original);
    let rollback = bundle::restore(&backup, &target).unwrap().unwrap();
    assert_eq!(
        original,
        fs::read(target.join("keys/fixture/id_ed25519")).unwrap()
    );
    assert_eq!(
        old,
        fs::read(rollback.join("keys/fixture/id_ed25519")).unwrap()
    );
    assert_eq!(1, Store::open(&rollback, 6).unwrap().pcs().unwrap().len());
}

#[test]
fn readonly_preview_and_backup_refuse_missing_roots_without_creating_them() {
    let temp = tempdir().unwrap();
    let missing = temp.path().join("missing");
    assert!(bundle::preview(&missing).is_err());
    assert!(!missing.exists());
    assert!(bundle::backup(&missing, &temp.path().join("out")).is_err());
    assert!(!missing.exists());
    assert!(!temp.path().join("out").exists());
}
#[test]
fn offline_lock_and_invalid_target_preserve_bytes() {
    let temp = tempdir().unwrap();
    let source = temp.path().join("source");
    populate(&source);
    let store = Store::open(&source, 5).unwrap();
    assert!(bundle::backup(&source, &temp.path().join("blocked")).is_err());
    assert!(!temp.path().join("blocked").exists());
    drop(store);
    let backup = temp.path().join("bundle");
    bundle::backup(&source, &backup).unwrap();
    let target = temp.path().join("target");
    populate(&target);
    fs::write(target.join("manager.sqlite3"), b"corrupt-preserve").unwrap();
    assert!(bundle::restore(&backup, &target).is_err());
    assert_eq!(
        b"corrupt-preserve",
        fs::read(target.join("manager.sqlite3")).unwrap().as_slice()
    );
}

fn account_and_trust(root: &std::path::Path) -> (String, String, String, String) {
    let conn = rusqlite::Connection::open_with_flags(
        root.join("manager.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    conn.query_row("SELECT password_hash,enrolled_public_key,host_key_public,host_key_fingerprint FROM administrator,pcs",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap()
}
#[test]
fn restore_rejects_missing_or_mismatched_required_private_identity() {
    let temp = tempdir().unwrap();
    let source = temp.path().join("source");
    populate(&source);
    fs::remove_file(source.join("keys/fixture/id_ed25519")).unwrap();
    assert!(bundle::backup(&source, &temp.path().join("bundle")).is_err());
    assert!(!temp.path().join("bundle").exists());
}
#[test]
fn pending_sqlite_sidecars_refuse_readonly_and_preserve_exact_bytes() {
    let temp = tempdir().unwrap();
    let source = temp.path().join("source");
    populate(&source);
    fs::write(source.join("manager.sqlite3-wal"), b"preserve-journal").unwrap();
    let before = fs::read(source.join("manager.sqlite3")).unwrap();
    assert!(bundle::backup(&source, &temp.path().join("bundle")).is_err());
    assert_eq!(before, fs::read(source.join("manager.sqlite3")).unwrap());
    assert_eq!(
        b"preserve-journal",
        fs::read(source.join("manager.sqlite3-wal"))
            .unwrap()
            .as_slice()
    );
}

#[test]
fn backup_and_restore_refuse_overlapping_roots_without_source_changes() {
    let temp = tempdir().unwrap();
    let source = temp.path().join("source");
    populate(&source);
    assert!(bundle::backup(&source, &source.join("nested")).is_err());
    assert!(!source.join("nested").exists());
    let backup = temp.path().join("bundle");
    bundle::backup(&source, &backup).unwrap();
    assert!(bundle::restore(&backup, &backup.join("nested")).is_err());
    assert!(!backup.join("nested").exists());
    bundle::preview(&backup).unwrap();
}
#[test]
fn restored_inflight_child_remains_uncertain_and_cannot_be_dispatched_again() {
    use wolf_core::{EmptyPayload, OperationKind, RpcOperation, RpcRequest};
    let temp = tempdir().unwrap();
    let source = temp.path().join("source");
    populate(&source);
    let mut store = Store::open(&source, 5).unwrap();
    let pc = PcId::new("fixture").unwrap();
    let request = RpcRequest {
        version: 1,
        request_id: uuid::Uuid::new_v4(),
        pc_id: pc.clone(),
        operation: RpcOperation::Stop(EmptyPayload {}),
    };
    store
        .enqueue_operation(
            &pc,
            OperationKind::Stop,
            None,
            std::slice::from_ref(&request),
            6,
        )
        .unwrap();
    store.begin_dispatch(request.request_id, 7).unwrap();
    drop(store);
    let backup = temp.path().join("bundle");
    bundle::backup(&source, &backup).unwrap();
    let target = temp.path().join("target");
    bundle::restore(&backup, &target).unwrap();
    let mut restored = Store::open(&target, 8).unwrap();
    assert!(restored.begin_dispatch(request.request_id, 9).is_err());
    assert!(restored.active_mutation(&pc).unwrap().is_some());
}
