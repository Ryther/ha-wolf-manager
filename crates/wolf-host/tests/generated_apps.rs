use std::collections::BTreeMap;
use wolf_core::*;
use wolf_manager_host::{generated_apps, steam};
fn fixture() -> (Settings, BTreeMap<AppId, CatalogAttributes>, toml::Table) {
    let id = AppId::new("42").unwrap();
    let mut settings = Settings::default();
    settings.debug.test_ball = true;
    settings.games.insert(
        id.clone(),
        GameSettings {
            direct_launch: true,
            proton_cachyos: false,
            parameters: vec![],
        },
    );
    let entry = CatalogAttributes {
        version: 1,
        pc_id: PcId::new("office").unwrap(),
        app_id: id.clone(),
        name: "Game ' \"\n[malicious]\n".into(),
        cover_url: steam_cover_url(&id),
        library_id: "main".into(),
        catalog_generation: 1,
        observed_at_ms: 1,
    };
    let runner:toml::Table=toml::from_str("type='docker'\nimage='trusted-steam-image'\nname='Steam'\nenv=['RUN_SWAY=true','STEAM_STARTUP_FLAGS=-silent']\nmounts=['/trusted:/data:rw']\n").unwrap();
    (settings, BTreeMap::from([(id, entry)]), runner)
}
#[test]
fn generated_catalogue_text_cannot_inject_runner_and_flags_are_owned() {
    let (settings, catalog, runner) = fixture();
    let (diagnostics, games) = generated_apps::generate(&settings, &catalog, &runner).unwrap();
    let original = "config_version=7\nuuid='preserved'\n[[profiles]]\nid='moonlight-profile-id'\n[[profiles]]\nid='user'\n";
    let text = steam::generated_sections(original, &diagnostics, &games).unwrap();
    let doc: toml::Table = toml::from_str(&text).unwrap();
    assert_eq!(doc["uuid"].as_str(), Some("preserved"));
    assert!(doc.get("malicious").is_none());
    let profiles = doc["profiles"].as_array().unwrap();
    let app = &profiles[1]["apps"].as_array().unwrap()[0];
    assert_eq!(
        app["title"].as_str(),
        Some(catalog.values().next().unwrap().name.as_str())
    );
    assert_eq!(app["runner"]["image"].as_str(), Some("trusted-steam-image"));
    let env = app["runner"]["env"].as_array().unwrap();
    assert_eq!(
        env.iter()
            .filter(|e| e.as_str().unwrap().starts_with("STEAM_STARTUP_FLAGS="))
            .count(),
        1
    );
    assert!(
        env.iter()
            .any(|e| e.as_str() == Some("STEAM_STARTUP_FLAGS=steam://rungameid/42"))
    );
    assert_eq!(
        profiles[0]["apps"].as_array().unwrap()[0]["title"].as_str(),
        Some("Test ball")
    );
}
#[test]
fn missing_games_preserve_settings_but_generate_no_apps() {
    let (mut settings, _, runner) = fixture();
    settings.debug.test_ball = false;
    assert_eq!(
        generated_apps::generate(&settings, &BTreeMap::new(), &runner).unwrap(),
        (String::new(), String::new())
    );
    assert_eq!(settings.games.len(), 1);
}
