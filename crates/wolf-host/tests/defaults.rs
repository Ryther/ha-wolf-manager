use wolf_manager_host::{defaults, policy::RootPolicy};
fn policy() -> RootPolicy {
    serde_json::from_value(serde_json::json!({"version":1,"pc_id":"desktop","steam_uid":1000,"steam_gid":1000,"libraries":[{"library_id":"primary","steamapps_path":"/home/gamer/Steam/steamapps","container_paths":["/home/steam/Steam/steamapps"]}],"steam_profiles":[{"root":"/home/gamer/Steam","config_vdf":"config/config.vdf","libraryfolders_vdf":["steamapps/libraryfolders.vdf"],"userdata_directory":"userdata","container_userdata_paths":["/home/steam/Steam/userdata"]}],"wolf_config":{"root":"/etc/wolf","relative_path":"config.toml","uid":0,"gid":0},"compose_file":"/etc/wolf/compose.yaml","service_unit":"wolf.service","container_name":"wolf","image_ref":"ghcr.io/games-on-whales/wolf:stable","backup_root":"/var/lib/wolf-manager/backups","state_root":"/var/lib/wolf-manager/state","catalog_state_directory":"/home/gamer/.local/state/wolf-manager","broker_secret_file":null,"pull_on_start":true,"pull_timeout_seconds":60,"proton":null,"steam_executables":["/usr/bin/steam"],"steam_runner":{"type":"docker","image":"trusted.example/steam:stable"}})).unwrap()
}
#[test]
fn initial_defaults_are_explicit_absent_only_and_preserve_existing_pairings() {
    let temp = tempfile::tempdir().unwrap();
    let mut p = policy();
    p.wolf_config.root = temp.path().to_owned();
    p.compose_file = temp.path().join("compose.json");
    let files = defaults::initial_files(&p).unwrap();
    assert_eq!(files.len(), 2);
    let config = files
        .iter()
        .find(|f| f.path.ends_with("config.toml"))
        .unwrap();
    let parsed: toml::Table = toml::from_str(std::str::from_utf8(&config.bytes).unwrap()).unwrap();
    assert_eq!(parsed["config_version"].as_integer(), Some(7));
    let compose = files
        .iter()
        .find(|f| f.path.ends_with("compose.json"))
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&compose.bytes).unwrap();
    assert_eq!(json["services"]["wolf"]["pull_policy"], "never");
    std::fs::write(
        temp.path().join("config.toml"),
        b"uuid='existing'\npaired_clients=['keep']\n",
    )
    .unwrap();
    let second = defaults::initial_files(&p).unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(
        std::fs::read(temp.path().join("config.toml")).unwrap(),
        b"uuid='existing'\npaired_clients=['keep']\n"
    );
    assert!(!p.compose_file.exists());
}
