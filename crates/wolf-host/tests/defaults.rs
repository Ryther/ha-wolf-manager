use wolf_manager_host::{defaults, policy::RootPolicy};
fn policy() -> RootPolicy {
    serde_json::from_value(serde_json::json!({"version":1,"pc_id":"desktop","steam_uid":1000,"steam_gid":1000,"libraries":[{"library_id":"primary","steamapps_path":"/home/gamer/Steam/steamapps","container_paths":["/home/steam/Steam/steamapps"]}],"steam_profiles":[{"root":"/home/gamer/Steam","config_vdf":"config/config.vdf","libraryfolders_vdf":["steamapps/libraryfolders.vdf"],"userdata_directory":"userdata","container_userdata_paths":["/home/steam/Steam/userdata"]}],"wolf_config":{"root":"/etc/wolf","relative_path":"config.toml","uid":0,"gid":0},"compose_file":"/etc/wolf/compose.yaml","service_unit":"wolf.service","container_name":"wolf","image_ref":"ghcr.io/games-on-whales/wolf:stable","backup_root":"/var/lib/wolf-manager/backups","state_root":"/var/lib/wolf-manager/state","catalog_state_directory":"/home/gamer/.local/state/wolf-manager","broker_secret_file":null,"pull_on_start":true,"pull_timeout_seconds":60,"proton":null,"steam_executables":["/usr/bin/steam"],"steam_runner":{"type":"docker","image":"trusted.example/steam:stable"}})).unwrap()
}
#[test]
fn initial_defaults_are_explicit_absent_only_and_preserve_existing_pairings() {
    let temp = tempfile::tempdir().unwrap();
    let mut p = policy();
    p.wolf_config.root = temp.path().to_owned();
    p.wolf_config.relative_path = "cfg/config.toml".into();
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
        {
            std::fs::create_dir(temp.path().join("cfg")).unwrap();
            temp.path().join("cfg/config.toml")
        },
        b"uuid='existing'\npaired_clients=['keep']\n",
    )
    .unwrap();
    let second = defaults::initial_files(&p).unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(
        std::fs::read(temp.path().join("cfg/config.toml")).unwrap(),
        b"uuid='existing'\npaired_clients=['keep']\n"
    );
    assert!(!p.compose_file.exists());
}

#[test]
fn generated_directory_mapping_matches_upstream_startup_config_and_certificate_paths() {
    let temp = tempfile::tempdir().unwrap();
    let mut p = policy();
    p.wolf_config.root = temp.path().join("custom-wolf-state");
    p.wolf_config.relative_path = "cfg/config.toml".into();
    p.compose_file = temp.path().join("compose.json");
    let files = defaults::initial_files(&p).unwrap();
    let config = files
        .iter()
        .find(|f| f.path.ends_with("config.toml"))
        .unwrap();
    let compose = files.iter().find(|f| f.path == p.compose_file).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&compose.bytes).unwrap();
    let service = &json["services"]["wolf"];
    // Immutable upstream startup.sh derives and overwrites these paths from
    // HOST_APPS_STATE_FOLDER, regardless of a supplied WOLF_CFG_FILE.
    let state = service["environment"]["HOST_APPS_STATE_FOLDER"]
        .as_str()
        .unwrap_or("/etc/wolf");
    assert_eq!(state, p.wolf_config.root.to_str().unwrap());
    let map = |suffix: &str| {
        let container = std::path::Path::new(state).join("cfg").join(suffix);
        service["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .find_map(|volume| {
                let parts: Vec<_> = volume.as_str().unwrap().split(':').collect();
                container
                    .strip_prefix(parts[1])
                    .ok()
                    .map(|relative| std::path::Path::new(parts[0]).join(relative))
            })
            .expect("upstream path must be on a persistent directory bind")
    };
    assert_eq!(map("config.toml"), config.path);
    assert_eq!(
        map("config.toml"),
        p.wolf_config.root.join(&p.wolf_config.relative_path)
    );
    assert_eq!(map("key.pem"), p.wolf_config.root.join("cfg/key.pem"));
    assert_eq!(map("cert.pem"), p.wolf_config.root.join("cfg/cert.pem"));
    assert!(service["environment"].get("WOLF_CFG_FILE").is_none());
    assert!(!p.wolf_config.root.exists());
}

#[test]
fn fresh_defaults_refuse_incompatible_config_layout_without_effects() {
    let temp = tempfile::tempdir().unwrap();
    let mut p = policy();
    p.wolf_config.root = temp.path().join("wolf");
    p.compose_file = temp.path().join("compose.json");
    for incompatible in ["config.toml", "cfg/custom.toml", "nested/cfg/config.toml"] {
        p.wolf_config.relative_path = incompatible.into();
        assert!(
            defaults::initial_files(&p).is_err(),
            "accepted {incompatible}"
        );
    }
    assert!(!p.wolf_config.root.exists());
    assert!(!p.compose_file.exists());
}
