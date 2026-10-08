use std::fs;
use wolf_core::PcId;
use wolf_manager_host::catalog::{CatalogConfig, Library, scan};
fn fixture() -> (tempfile::TempDir, CatalogConfig) {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("steamapps");
    fs::create_dir_all(root.join("common/Game")).unwrap();
    let state = t.path().join("state");
    fs::create_dir(&state).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let config = CatalogConfig {
        pc_id: PcId::new("pc-one").unwrap(),
        libraries: vec![Library {
            library_id: "main".into(),
            canonical_path: root,
        }],
        state_directory: state,
    };
    (t, config)
}
fn manifest(c: &CatalogConfig, id: &str, name: &str, flags: &str) {
    fs::write(c.libraries[0].canonical_path.join(format!("appmanifest_{id}.acf")),format!(r#""AppState" {{ "appid" "{id}" "name" "{name}" "installdir" "Game" "StateFlags" "{flags}" }}"#)).unwrap();
}
#[test]
fn complete_scan_monotonic_across_reopen() {
    let (_t, c) = fixture();
    manifest(&c, "12", "My™ Game", "4");
    let a = scan(&c, 1).unwrap();
    let b = scan(&c, 2).unwrap();
    assert_eq!(a.attributes[0].name, "My Game");
    assert_eq!(
        b.manifest.catalog_generation,
        a.manifest.catalog_generation + 1
    );
    assert_eq!(a.manifest.app_ids.len(), 1);
}
#[test]
fn exclusions_and_uninstalled_are_not_games() {
    let (_t, c) = fixture();
    manifest(&c, "12", "Proton Experimental", "4");
    manifest(&c, "13", "Half downloaded", "2");
    let s = scan(&c, 1).unwrap();
    assert!(s.attributes.is_empty());
}
#[test]
fn corrupt_scan_does_not_replace_accepted_state() {
    let (_t, c) = fixture();
    manifest(&c, "12", "Game", "4");
    scan(&c, 1).unwrap();
    let before = fs::read(c.state_directory.join("accepted.json")).unwrap();
    fs::write(
        c.libraries[0].canonical_path.join("appmanifest_13.acf"),
        "broken {",
    )
    .unwrap();
    assert!(scan(&c, 2).is_err());
    assert_eq!(
        before,
        fs::read(c.state_directory.join("accepted.json")).unwrap()
    );
}
#[test]
fn aliases_refused() {
    use std::os::unix::fs::symlink;
    let (t, c) = fixture();
    fs::write(t.path().join("outside"), "AppState {}").unwrap();
    symlink(
        t.path().join("outside"),
        c.libraries[0].canonical_path.join("appmanifest_12.acf"),
    )
    .unwrap();
    assert!(scan(&c, 1).is_err());
}
#[test]
fn published_checkpoint_survives_restart_and_is_pc_bound() {
    use wolf_manager_host::catalog::{load_published, record_published};
    let (_t, c) = fixture();
    manifest(&c, "12", "Game", "4");
    let snap = scan(&c, 1).unwrap();
    assert!(load_published(&c).unwrap().is_none());
    record_published(&c, &snap).unwrap();
    assert_eq!(load_published(&c).unwrap().unwrap().manifest, snap.manifest);
    let mut other = c.clone();
    other.pc_id = PcId::new("other-pc").unwrap();
    assert!(load_published(&other).is_err());
}
#[test]
fn hardlinked_manifests_and_missing_counter_fail_closed() {
    let (t, c) = fixture();
    manifest(&c, "12", "Game", "4");
    let file = c.libraries[0].canonical_path.join("appmanifest_12.acf");
    fs::hard_link(&file, t.path().join("alias")).unwrap();
    assert!(scan(&c, 1).is_err());
    fs::remove_file(t.path().join("alias")).unwrap();
    scan(&c, 1).unwrap();
    fs::remove_file(c.state_directory.join("generation")).unwrap();
    assert!(scan(&c, 2).is_err());
}
#[test]
fn names_match_unicode_cleanup() {
    use wolf_manager_host::catalog::clean_game_name;
    assert_eq!(
        clean_game_name("  Ｆｏｏ™\u{200b}\u{e000} \n Bar®©"),
        "Foo Bar"
    );
}
#[test]
fn rolled_back_counter_refuses_new_generation() {
    let (_t, c) = fixture();
    manifest(&c, "12", "Game", "4");
    scan(&c, 1).unwrap();
    fs::write(c.state_directory.join("generation"), "0").unwrap();
    assert!(scan(&c, 2).is_err());
}

#[test]
fn lifecycle_inventory_is_read_only_and_needs_no_catalog_state_access() {
    let (_t, mut c) = fixture();
    manifest(&c, "12", "Game", "4");
    let snapshot = scan(&c, 1).unwrap();
    let before = fs::read(c.state_directory.join("accepted.json")).unwrap();
    let inventory = wolf_manager_host::catalog::inventory(&c, 2).unwrap();
    assert_eq!(inventory.len(), 1);
    assert_eq!(
        fs::read(c.state_directory.join("accepted.json")).unwrap(),
        before
    );
    assert_eq!(
        scan(&c, 3).unwrap().manifest.catalog_generation,
        snapshot.manifest.catalog_generation + 1
    );
    c.state_directory = "/nonexistent/private/catalog".into();
    assert_eq!(
        wolf_manager_host::catalog::inventory(&c, 4).unwrap().len(),
        1
    );
}
