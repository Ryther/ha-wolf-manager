use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};
use tempfile::tempdir;
use wolf_core::*;
use wolf_manager_host::state::State;
#[test]
fn initial_defaults_are_atomic_and_never_replace_existing_or_corrupt_state() {
    let root = tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let state = State::open(root.path(), &PcId::new("office").unwrap()).unwrap();
    let defaults = Settings::default();
    assert_eq!(
        state.staged_or_default(&defaults).unwrap(),
        (defaults.clone(), defaults.revision().unwrap())
    );
    let mut chosen = defaults.clone();
    chosen.debug.test_ball = true;
    let revision = state.stage(&chosen).unwrap();
    let before = fs::read(root.path().join("staged.json")).unwrap();
    assert_eq!(
        state.staged_or_default(&defaults).unwrap(),
        (chosen, revision)
    );
    assert_eq!(fs::read(root.path().join("staged.json")).unwrap(), before);
    fs::write(root.path().join("staged.json"), b"broken").unwrap();
    assert!(state.staged_or_default(&defaults).is_err());
    assert_eq!(
        fs::read(root.path().join("staged.json")).unwrap(),
        b"broken"
    );
}
#[test]
fn full_desired_state_is_durable_and_running_revision_is_independent() {
    let root = tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let pc = PcId::new("office").unwrap();
    let state = State::open(root.path(), &pc).unwrap();
    let mut settings = Settings::default();
    settings.games.insert(
        AppId::new("42").unwrap(),
        GameSettings {
            direct_launch: true,
            proton_cachyos: false,
            parameters: vec![],
        },
    );
    let first = state.stage(&settings).unwrap();
    state.set_running(Some(&first)).unwrap();
    settings.debug.test_ball = true;
    let second = state.stage(&settings).unwrap();
    assert_ne!(first, second);
    drop(state);
    let reopened = State::open(root.path(), &pc).unwrap();
    assert_eq!(reopened.staged().unwrap(), Some((settings, second)));
    assert_eq!(reopened.running().unwrap(), Some(first));
}
#[test]
fn private_state_rejects_aliases_corruption_and_wrong_pc_without_rewrite() {
    let root = tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let pc = PcId::new("office").unwrap();
    let state = State::open(root.path(), &pc).unwrap();
    state.stage(&Settings::default()).unwrap();
    let bytes = fs::read(root.path().join("staged.json")).unwrap();
    assert!(
        State::open(root.path(), &PcId::new("other").unwrap())
            .unwrap()
            .staged()
            .is_err()
    );
    assert_eq!(fs::read(root.path().join("staged.json")).unwrap(), bytes);
    fs::write(root.path().join("staged.json"), b"broken").unwrap();
    assert!(state.stage(&Settings::default()).is_err());
    assert_eq!(
        fs::read(root.path().join("staged.json")).unwrap(),
        b"broken"
    );
    fs::remove_file(root.path().join("staged.json")).unwrap();
    symlink("elsewhere", root.path().join("staged.json")).unwrap();
    assert!(state.stage(&Settings::default()).is_err());
}
