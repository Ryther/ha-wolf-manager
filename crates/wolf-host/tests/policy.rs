use wolf_manager_host::policy::RootPolicy;
fn policy() -> RootPolicy {
    serde_json::from_value(serde_json::json!({"version":1,"pc_id":"desktop","steam_uid":1000,"steam_gid":1000,"libraries":[{"library_id":"primary","steamapps_path":"/home/gamer/Steam/steamapps","container_paths":["/home/steam/Steam/steamapps"]}],"steam_profiles":[{"root":"/home/gamer/Steam","config_vdf":"config/config.vdf","libraryfolders_vdf":["steamapps/libraryfolders.vdf"],"userdata_directory":"userdata","container_userdata_paths":["/home/steam/Steam/userdata"]}],"wolf_config":{"root":"/etc/wolf","relative_path":"config.toml","uid":0,"gid":0},"compose_file":"/etc/wolf/compose.yaml","service_unit":"wolf.service","container_name":"wolf","image_ref":"ghcr.io/games-on-whales/wolf:stable","backup_root":"/var/lib/wolf-manager/backups","state_root":"/var/lib/wolf-manager/state","catalog_state_directory":"/home/gamer/.local/state/wolf-manager","broker_secret_file":null,"pull_on_start":true,"pull_timeout_seconds":60,"proton":null,"steam_executables":["/usr/bin/steam"],"steam_runner":{"type":"docker","image":"trusted.example/steam:stable"}})).unwrap()
}
#[test]
fn closed_policy_rejects_unknown_fields_and_missing_authority() {
    let mut value = serde_json::to_value(policy()).unwrap();
    value["shell"] = serde_json::json!("sh -c anything");
    assert!(serde_json::from_value::<RootPolicy>(value).is_err());
}
#[test]
fn valid_structure_and_bad_privileged_argv_are_distinct() {
    let mut p = policy();
    p.validate_structure().unwrap();
    p.service_unit = "wolf.service; reboot".into();
    assert!(p.validate_structure().is_err());
    p = policy();
    p.image_ref = "/malformed/image".into();
    assert!(p.validate_structure().is_err());
}
#[test]
fn duplicated_profiles_are_refused() {
    let mut p = policy();
    p.steam_profiles.push(p.steam_profiles[0].clone());
    assert!(p.validate_structure().is_err());
}
#[test]
fn mutable_escape_and_duplicate_grant_refuse() {
    let mut p = policy();
    p.wolf_config.relative_path = "../config.toml".into();
    assert!(p.validate_structure().is_err());
    p = policy();
    p.libraries.push(p.libraries[0].clone());
    assert!(p.validate_structure().is_err());
}
#[test]
fn untrusted_policy_path_is_rejected_without_write() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("policy.json");
    let bytes = serde_json::to_vec(&policy()).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    assert!(RootPolicy::load(&path).is_err());
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}
