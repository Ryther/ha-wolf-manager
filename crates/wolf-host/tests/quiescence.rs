use std::{path::PathBuf, process::Command, sync::Mutex};
static PROCESS_FIXTURES: Mutex<()> = Mutex::new(());
use wolf_manager_host::quiescence;
#[test]
fn executable_identity_detects_running_writer_and_permits_after_exit() {
    let _guard = PROCESS_FIXTURES.lock().unwrap();
    let fixture = tempfile::tempdir().unwrap();
    let executable = fixture.path().join("declared-writer");
    std::fs::copy("/bin/sleep", &executable).unwrap();
    let mut child = Command::new(&executable).arg("30").spawn().unwrap();
    let uid = rustix::process::geteuid().as_raw();
    let executables = vec![executable];
    let running = quiescence::require_stopped(uid, &executables);
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(running.is_err());
    quiescence::require_stopped(uid, &executables).unwrap();
}
#[test]
fn missing_or_empty_executable_authority_refuses() {
    let uid = rustix::process::geteuid().as_raw();
    assert!(quiescence::require_stopped(uid, &[]).is_err());
    assert!(quiescence::require_stopped(uid, &[PathBuf::from("/nonexistent/writer")]).is_err());
}

#[test]
fn undeclared_native_steam_name_refuses_until_process_exits() {
    let _guard = PROCESS_FIXTURES.lock().unwrap();
    for name in ["steam", "SteamHelper"] {
        let fixture = tempfile::tempdir().unwrap();
        let executable = fixture.path().join(name);
        std::fs::copy("/bin/sleep", &executable).unwrap();
        let mut child = Command::new(&executable).arg("30").spawn().unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let executables = vec![PathBuf::from("/bin/echo")];
        let running = quiescence::require_stopped(uid, &executables);
        let other_uid = quiescence::require_stopped(uid + 1, &executables);
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(
            other_uid.is_ok(),
            "other UID processes must not broaden authority"
        );
        assert!(
            running.is_err(),
            "an undeclared native Steam writer must refuse"
        );
        quiescence::require_stopped(uid, &executables).unwrap();
    }
}
