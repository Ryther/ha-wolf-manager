use wolf_core::*;
use wolf_manager_host::{steam, vdf::Document};
fn settings() -> Settings {
    let mut settings = Settings::default();
    settings.games.insert(
        AppId::new("42").unwrap(),
        GameSettings {
            direct_launch: true,
            proton_cachyos: true,
            parameters: vec![
                ParameterId::new("fsr4").unwrap(),
                ParameterId::new("fsr4_indicator").unwrap(),
            ],
        },
    );
    settings
}
#[test]
fn ordered_launch_parameters_preserve_custom_game_fields() {
    let settings = settings();
    let game = settings.games.values().next().unwrap();
    assert_eq!(
        steam::launch_options(game, &settings).unwrap(),
        "PROTON_FSR4_UPGRADE=1 PROTON_FSR4_INDICATOR=1 %command%"
    );
    let original = "// keep this comment\n\"UserLocalConfigStore\" { \"Software\" { \"Valve\" { \"Steam\" { \"apps\" { \"42\" { \"Other\" \"preserve\" } } } } } }\n";
    let result = steam::localconfig(original, &settings).unwrap();
    assert!(result.starts_with("// keep this comment"));
    let doc = Document::parse(&result).unwrap();
    assert_eq!(
        doc.get(&[
            "UserLocalConfigStore",
            "Software",
            "Valve",
            "Steam",
            "apps",
            "42",
            "Other"
        ])
        .unwrap(),
        Some("preserve".into())
    );
    assert_eq!(
        doc.get(&[
            "UserLocalConfigStore",
            "Software",
            "Valve",
            "Steam",
            "apps",
            "42",
            "LaunchOptions"
        ])
        .unwrap(),
        Some(steam::launch_options(game, &settings).unwrap())
    );
}
#[test]
fn compatibility_preserves_unmanaged_mappings() {
    let original = "\"InstallConfigStore\" { \"Software\" { \"Valve\" { \"Steam\" { \"CompatToolMapping\" { \"99\" { \"name\" \"custom proton\" } } } } } }";
    let result = steam::compatibility(original, &settings(), "proton-cachyos").unwrap();
    let doc = Document::parse(&result).unwrap();
    assert_eq!(
        doc.get(&[
            "InstallConfigStore",
            "Software",
            "Valve",
            "Steam",
            "CompatToolMapping",
            "99",
            "name"
        ])
        .unwrap(),
        Some("custom proton".into())
    );
    assert_eq!(
        doc.get(&[
            "InstallConfigStore",
            "Software",
            "Valve",
            "Steam",
            "CompatToolMapping",
            "42",
            "name"
        ])
        .unwrap(),
        Some("proton-cachyos".into())
    );
}
#[test]
fn generated_sections_preserve_uuid_pairing_and_custom_apps_and_converge() {
    let original = "config_version = 7\nuuid = 'existing-uuid'\n[[profiles]]\nid='user'\nname='custom-profile'\n[[profiles.apps]]\ntitle='Custom app'\n[profiles.apps.runner]\ntype='process'\nrun_cmd='true'\n";
    let generated = "[[profiles.apps]]\ntitle='Managed game'\n[profiles.apps.runner]\ntype='process'\nrun_cmd='true'";
    let once = steam::generated_sections(original, "", generated).unwrap();
    assert!(once.starts_with(original));
    assert_eq!(
        steam::generated_sections(&once, "", generated).unwrap(),
        once
    );
    assert!(
        steam::generated_sections(
            "# BEGIN MACHINE-SETUP GENERATED USER APPS\nbroken",
            "",
            generated
        )
        .is_err()
    );
}

#[test]
fn marker_text_inside_multiline_user_string_is_preserved() {
    let original = "config_version=7\nnote='''\n# BEGIN HA-WOLF-MANAGER GENERATED USER APPS\ncustom text\n# END HA-WOLF-MANAGER GENERATED USER APPS\n'''\n[[profiles]]\nname='custom'\n";
    let result = steam::generated_sections(original, "", "").unwrap();
    assert!(result.starts_with(original));
    assert_eq!(steam::generated_sections(&result, "", "").unwrap(), result);
}

#[test]
fn legacy_generated_sections_are_adopted_without_duplicate_apps() {
    let original = "config_version=7\nuuid='keep-identity'\n[[profiles]]\nname='custom'\n# BEGIN MACHINE-SETUP GENERATED USER APPS\n[[profiles.apps]]\ntitle='Old generated'\n# END MACHINE-SETUP GENERATED USER APPS\n";
    let result =
        steam::generated_sections(original, "", "[[profiles.apps]]\ntitle='New generated'")
            .unwrap();
    assert!(!result.contains("Old generated"));
    assert!(result.contains("uuid='keep-identity'"));
    assert_eq!(result.matches("title='New generated'").count(), 1);
    assert!(!result.contains("MACHINE-SETUP"));
}

#[test]
fn absent_markers_place_apps_in_their_correct_existing_profiles() {
    let original = "config_version=7\nuuid='preserved'\n[[profiles]]\nid='moonlight-profile-id'\n[[profiles.apps]]\ntitle='Wolf UI'\n[[profiles]]\nid='user'\nname='User'\n[[profiles.apps]]\ntitle='Custom game'\n";
    let result = steam::generated_sections(
        original,
        "[[profiles.apps]]\ntitle='Diagnostic'",
        "[[profiles.apps]]\ntitle='Managed game'",
    )
    .unwrap();
    let parsed: toml::Table = toml::from_str(&result).unwrap();
    let profiles = parsed["profiles"].as_array().unwrap();
    assert_eq!(profiles.len(), 2);
    let titles = |index: usize| {
        profiles[index]["apps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|app| app["title"].as_str().unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(titles(0), vec!["Wolf UI", "Diagnostic"]);
    assert_eq!(titles(1), vec!["Custom game", "Managed game"]);
}

#[test]
fn library_mapping_merges_apps_without_losing_unmanaged_libraries() {
    let original = "// operator metadata\n\"libraryfolders\" { \"0\" { \"path\" \"/host/main\" \"label\" \"Keep\" \"apps\" { \"99\" \"old-build\" } } \"7\" { \"path\" \"/unrelated\" \"custom\" \"keep\" } }";
    let mapping = vec![(
        "/host/main".into(),
        "/container/main".into(),
        vec![AppId::new("42").unwrap()],
    )];
    let updated = steam::libraryfolders(original, &mapping).unwrap();
    let doc = Document::parse(&updated).unwrap();
    assert!(updated.starts_with("// operator metadata"));
    assert_eq!(
        doc.get(&["libraryfolders", "0", "path"]).unwrap(),
        Some("/container/main".into())
    );
    assert_eq!(
        doc.get(&["libraryfolders", "0", "apps", "99"]).unwrap(),
        Some("old-build".into())
    );
    assert_eq!(
        doc.get(&["libraryfolders", "0", "apps", "42"]).unwrap(),
        Some("0".into())
    );
    assert_eq!(
        doc.get(&["libraryfolders", "7", "custom"]).unwrap(),
        Some("keep".into())
    );
    assert_eq!(steam::libraryfolders(&updated, &mapping).unwrap(), updated);
}
