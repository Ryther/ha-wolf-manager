use std::os::unix::fs::PermissionsExt;
use wolf_manager_host::{
    host_steam::clear_current,
    transactions::{Grant, TransactionStore},
};
#[test]
fn stop_edits_current_toml_and_keeps_pairings_created_during_session() {
    let dir = tempfile::tempdir().unwrap();
    let wolf = dir.path().join("wolf");
    let backups = dir.path().join("backups");
    std::fs::create_dir(&wolf).unwrap();
    std::fs::create_dir(&backups).unwrap();
    std::fs::set_permissions(&backups, std::fs::Permissions::from_mode(0o700)).unwrap();
    let current=b"config_version=7\nuuid='keep'\npaired_clients=['new-session-pairing']\n[[profiles]]\nid='moonlight-profile-id'\n# BEGIN HA-WOLF-MANAGER GENERATED MOONLIGHT APPS\n[[profiles.apps]]\ntitle='temporary-debug'\n# END HA-WOLF-MANAGER GENERATED MOONLIGHT APPS\n[[profiles]]\nid='user'\n# BEGIN HA-WOLF-MANAGER GENERATED USER APPS\n[[profiles.apps]]\ntitle='generated-game'\n# END HA-WOLF-MANAGER GENERATED USER APPS\n[[profiles.apps]]\ntitle='custom-app'\n";
    std::fs::write(wolf.join("config.toml"), current).unwrap();
    let grant = Grant::open(&wolf).unwrap();
    let store = TransactionStore::open(&backups).unwrap();
    clear_current(&store, &grant, "config.toml").unwrap();
    let result = std::fs::read_to_string(wolf.join("config.toml")).unwrap();
    assert!(result.contains("new-session-pairing"));
    assert!(result.contains("uuid='keep'"));
    assert!(result.contains("custom-app"));
    assert!(!result.contains("generated-game"));
    assert!(!result.contains("temporary-debug"));
    assert!(store.active().unwrap().is_empty());
    assert_eq!(store.transactions().unwrap().len(), 1);
    let before = result.clone();
    clear_current(&store, &grant, "config.toml").unwrap();
    assert_eq!(
        std::fs::read_to_string(wolf.join("config.toml")).unwrap(),
        before
    );
    assert_eq!(store.transactions().unwrap().len(), 1);
}
#[test]
fn root_runner_labels_preserve_baseline_and_refuse_other_host_authority() {
    use wolf_manager_host::host_steam::labelled_runner;
    let pc = wolf_core::PcId::new("fixture").unwrap();
    let template:toml::Table=toml::from_str("type='docker'\nimage='root-owned:stable'\nbase_create_json='{\"Labels\":{\"keep\":\"custom\"},\"HostConfig\":{\"Privileged\":false}}'\n").unwrap();
    let labelled = labelled_runner(&template, &pc).unwrap();
    let json: serde_json::Value =
        serde_json::from_str(labelled["base_create_json"].as_str().unwrap()).unwrap();
    assert_eq!(json["Labels"]["keep"], "custom");
    assert_eq!(json["HostConfig"]["Privileged"], false);
    assert_eq!(json["Labels"]["io.ha-wolf-manager.pc"], "fixture");
    assert_eq!(
        json["Labels"]["io.ha-wolf-manager.owner"],
        "managed-steam-v1"
    );
    let mut conflict = template;
    conflict.insert(
        "base_create_json".into(),
        toml::Value::String("{\"Labels\":{\"io.ha-wolf-manager.pc\":\"another-host\"}}".into()),
    );
    assert!(labelled_runner(&conflict, &pc).is_err());
}
#[test]
#[ignore = "requires disposable root container; never household Steam data"]
fn policy_adapter_overlays_userdata_and_library_aliases_then_restores_pairing_safely() {
    use std::{fs, path::Path};
    use wolf_manager_host::{
        host_steam::{prepare_with, restore_with, runner},
        policy::RootPolicy,
    };
    assert_eq!(rustix::process::geteuid().as_raw(), 0);
    let temporary = tempfile::Builder::new()
        .prefix("wolf-adapter-")
        .tempdir_in("/root")
        .unwrap();
    let root = temporary.path();
    for directory in [
        "profile/config",
        "profile/steamapps/common/Fixture",
        "profile/userdata/123/config",
        "proton",
        "wolf",
        "backups",
        "state",
        "catalog",
        "bin",
    ] {
        fs::create_dir_all(root.join(directory)).unwrap();
    }
    for directory in ["backups", "state", "catalog"] {
        fs::set_permissions(root.join(directory), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let config = b"\"InstallConfigStore\" { \"unrelated\" \"keep\" }\n";
    let local = b"\"UserLocalConfigStore\" { \"unrelated\" \"keep\" }\n";
    let folders = format!(
        "\"libraryfolders\" {{ \"0\" {{ \"path\" \"{}\" }} }}\n",
        root.join("profile").display()
    );
    for (path, bytes) in [
        ("profile/config/config.vdf", config.as_slice()),
        (
            "profile/userdata/123/config/localconfig.vdf",
            local.as_slice(),
        ),
        ("profile/steamapps/libraryfolders.vdf", folders.as_bytes()),
    ] {
        fs::write(root.join(path), bytes).unwrap();
        rustix::fs::chown(
            root.join(path),
            Some(rustix::fs::Uid::from_raw(1000)),
            Some(rustix::fs::Gid::from_raw(1000)),
        )
        .unwrap();
    }
    fs::write(
        root.join("profile/steamapps/appmanifest_10.acf"),
        b"\"AppState\" {\"appid\" \"10\" \"name\" \"Fixture game\" \"installdir\" \"Fixture\"}",
    )
    .unwrap();
    fs::write(root.join("bin/steam"), b"fixture executable identity").unwrap();
    fs::write(root.join("wolf/compose.json"), b"{}").unwrap();
    fs::write(root.join("wolf/config.toml"),b"config_version=7\nuuid='identity'\npaired_clients=['original']\n[[profiles]]\nid='moonlight-profile-id'\n[[profiles]]\nid='user'\n[[profiles.apps]]\ntitle='custom-app'\n").unwrap();
    let policy:RootPolicy=serde_json::from_value(serde_json::json!({"version":1,"pc_id":"fixture","steam_uid":1000,"steam_gid":1000,"libraries":[{"library_id":"primary","steamapps_path":root.join("profile/steamapps"),"container_paths":["/home/steam/Steam/steamapps","/home/steam/.steam/steam/steamapps"]}],"steam_profiles":[{"root":root.join("profile"),"config_vdf":"config/config.vdf","libraryfolders_vdf":["steamapps/libraryfolders.vdf"],"userdata_directory":"userdata","container_userdata_paths":["/home/steam/Steam/userdata","/home/steam/.steam/steam/userdata"]}],"wolf_config":{"root":root.join("wolf"),"relative_path":"config.toml","uid":0,"gid":0},"compose_file":root.join("wolf/compose.json"),"service_unit":"wolf.service","container_name":"wolf","image_ref":"ghcr.io/games-on-whales/wolf:stable","backup_root":root.join("backups"),"state_root":root.join("state"),"catalog_state_directory":root.join("catalog"),"broker_secret_file":null,"pull_on_start":true,"pull_timeout_seconds":60,"proton":{"name":"proton-cachyos","host_path":root.join("proton"),"container_paths":["/home/steam/.steam/root/compatibilitytools.d/proton-cachyos"]},"steam_executables":[root.join("bin/steam")],"steam_runner":{"type":"docker","image":"example.invalid/steam:stable","mounts":["/var/run/wolf/wolf.sock:/var/run/wolf/wolf.sock"]}})).unwrap();
    let mut settings = wolf_core::Settings::default();
    settings.debug.test_ball = true;
    settings.games.insert(
        wolf_core::AppId::new("10").unwrap(),
        wolf_core::GameSettings {
            direct_launch: true,
            proton_cachyos: true,
            parameters: vec![wolf_core::ParameterId::new("fsr4").unwrap()],
        },
    );
    prepare_with(&policy, &settings, || Ok(())).unwrap();
    assert!(
        fs::read_to_string(root.join("profile/config/config.vdf"))
            .unwrap()
            .contains("proton-cachyos")
    );
    assert!(
        fs::read_to_string(root.join("profile/userdata/123/config/localconfig.vdf"))
            .unwrap()
            .contains("PROTON_FSR4_UPGRADE=1")
    );
    assert!(
        fs::read_to_string(root.join("profile/steamapps/libraryfolders.vdf"))
            .unwrap()
            .contains("/home/steam/Steam")
    );
    let trusted = runner(&policy).unwrap();
    let mounts = trusted["mounts"].as_array().unwrap();
    assert!(mounts.iter().any(|mount| {
        mount
            .as_str()
            .unwrap()
            .contains("/home/steam/.steam/steam/steamapps:rw")
    }));
    assert!(mounts.iter().any(|mount| {
        mount
            .as_str()
            .unwrap()
            .contains("/home/steam/.steam/steam/userdata:rw")
    }));
    let wolf = root.join("wolf/config.toml");
    let generated = fs::read_to_string(&wolf).unwrap();
    assert!(generated.contains("Fixture game"));
    assert!(generated.contains("Test ball"));
    fs::write(
        &wolf,
        generated.replace(
            "paired_clients=['original']",
            "paired_clients=['original','during-session']",
        ),
    )
    .unwrap();
    restore_with(&policy, || Ok(())).unwrap();
    assert_eq!(
        fs::read(root.join("profile/config/config.vdf")).unwrap(),
        config
    );
    assert_eq!(
        fs::read(root.join("profile/userdata/123/config/localconfig.vdf")).unwrap(),
        local
    );
    assert_eq!(
        fs::read(root.join("profile/steamapps/libraryfolders.vdf")).unwrap(),
        folders.as_bytes()
    );
    let stopped = fs::read_to_string(&wolf).unwrap();
    assert!(stopped.contains("during-session"));
    assert!(stopped.contains("custom-app"));
    assert!(!stopped.contains("Fixture game"));
    assert!(root.join("backups").read_dir().unwrap().count() > 3);
    assert!(root.join("catalog").read_dir().unwrap().next().is_none());
    assert!(
        Path::new(&policy.libraries[0].steamapps_path)
            .join("common/Fixture")
            .is_dir()
    );
    let local_path = root.join("profile/userdata/123/config/localconfig.vdf");
    fs::rename(&local_path, root.join("saved-localconfig")).unwrap();
    let before_no_local = fs::read(&wolf).unwrap();
    let backups_no_local = root.join("backups").read_dir().unwrap().count();
    assert!(prepare_with(&policy, &settings, || Ok(())).is_err());
    assert_eq!(fs::read(&wolf).unwrap(), before_no_local);
    assert_eq!(
        root.join("backups").read_dir().unwrap().count(),
        backups_no_local
    );
    fs::rename(root.join("saved-localconfig"), &local_path).unwrap();
    let before = fs::read(&wolf).unwrap();
    let before_backups = root.join("backups").read_dir().unwrap().count();
    let mut duplicate = policy.clone();
    let duplicate_path = duplicate.steam_profiles[0].libraryfolders_vdf[0].clone();
    duplicate.steam_profiles[0]
        .libraryfolders_vdf
        .push(duplicate_path);
    assert!(prepare_with(&duplicate, &settings, || Ok(())).is_err());
    assert_eq!(fs::read(&wolf).unwrap(), before);
    assert_eq!(
        fs::read(root.join("profile/config/config.vdf")).unwrap(),
        config
    );
    assert_eq!(
        root.join("backups").read_dir().unwrap().count(),
        before_backups
    );
}
