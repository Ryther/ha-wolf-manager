use ha_wolf_manager::{domain::PcInput, imports, store::Store};
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;
use wolf_core::*;
fn pc(store: &mut Store, name: &str) -> PcId {
    let id = PcId::new(name).unwrap();
    store
        .add_pc(
            PcInput {
                pc_id: id.clone(),
                display_name: name.into(),
                ssh_host: "example.test".into(),
                ssh_port: 22,
                ssh_user: "wolf-manager".into(),
            },
            1,
        )
        .unwrap();
    id
}
const SOURCE: &[u8]=br#"{"games":{"42":{"direct_launch":true,"parameters":["fsr4_indicator","fsr4"],"proton_cachyos":true}},"debug":{"test_ball":true}}"#;
#[test]
fn reviewed_import_preserves_valid_prototype_definition_changes() {
    let t = tempdir().unwrap();
    std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut store = Store::open(t.path(), 0).unwrap();
    let id = pc(&mut store, "fixture");
    let expected = store.settings(&id).unwrap().revision().unwrap();
    let value = serde_json::json!({"parameters":{"fsr4":{"label":"L".repeat(3000),"description":"D".repeat(5000),"launch_options":"PROTON_FSR4_UPGRADE=1 %command%"}},"games":{"42":{"parameters":["fsr4"]}}});
    let bytes = serde_json::to_vec(&value).unwrap();
    let settings = imports::preview(1, &bytes).unwrap();
    store
        .import_legacy_settings(&id, &expected, 1, &bytes, 2)
        .unwrap();
    assert_eq!(store.settings(&id).unwrap(), settings);
}
#[test]
fn explicit_import_retains_source_and_backup_and_stages_no_host_operation() {
    let t = tempdir().unwrap();
    std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut store = Store::open(t.path(), 0).unwrap();
    let id = pc(&mut store, "fixture");
    let before = store.global_settings().unwrap().revision().unwrap();
    let original_files: std::collections::BTreeSet<_> = std::fs::read_dir(t.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    let preview = imports::preview(1, SOURCE).unwrap();
    assert!(imports::preview(2, SOURCE).is_err());
    assert!(
        store
            .import_legacy_settings(&id, &Revision::new("a".repeat(64)).unwrap(), 1, SOURCE, 2)
            .is_err()
    );
    let revision = store
        .import_legacy_settings(&id, &before, 1, SOURCE, 2)
        .unwrap();
    assert_eq!(revision, preview.revision().unwrap());
    assert_eq!(store.settings(&id).unwrap(), preview);
    assert!(store.active_mutation(&id).unwrap().is_none());
    let mut retained_source = false;
    let mut backup = false;
    for entry in std::fs::read_dir(t.path()).unwrap() {
        let path = entry.unwrap().path();
        if path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("legacy-source-")
        {
            assert_eq!(std::fs::read(&path).unwrap(), SOURCE);
            retained_source = true;
        }
        if path
            .extension()
            .is_some_and(|extension| extension == "sqlite3")
            && path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("backup-")
            && !original_files.contains(path.file_name().unwrap())
        {
            let connection = rusqlite::Connection::open_with_flags(
                &path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .unwrap();
            let rows: i64 = connection
                .query_row("SELECT count(*) FROM settings", [], |row| row.get(0))
                .unwrap();
            assert_eq!(rows, 0, "backup must contain the state before import");
            backup = true;
        }
    }
    assert!(retained_source && backup);
}
#[test]
fn import_refuses_shared_global_changes_and_keeps_existing_settings() {
    let t = tempdir().unwrap();
    std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut store = Store::open(t.path(), 0).unwrap();
    let id = pc(&mut store, "first");
    pc(&mut store, "second");
    let before = store.global_settings().unwrap();
    assert!(
        store
            .import_legacy_settings(&id, &before.revision().unwrap(), 1, SOURCE, 2)
            .is_err()
    );
    assert_eq!(before, store.global_settings().unwrap());
    assert!(!std::fs::read_dir(t.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("legacy-source-")
    }));
}
