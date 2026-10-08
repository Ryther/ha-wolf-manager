use std::{path::PathBuf, process::Command};
use wolf_manager_host::quiescence;
#[test]
fn executable_identity_detects_running_writer_and_permits_after_exit() {
    let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let uid = rustix::process::geteuid().as_raw();
    let executables = vec![PathBuf::from("/bin/sleep")];
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
