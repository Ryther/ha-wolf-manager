use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::Duration,
};
use wolf_manager_host::quiescence;
static PROCESS_FIXTURES: Mutex<()> = Mutex::new(());

struct WriterChild(Option<Child>);
impl WriterChild {
    fn is_alive(&mut self) -> bool {
        self.0.as_mut().unwrap().try_wait().unwrap().is_none()
    }
    fn stop(&mut self) {
        let child = self.0.as_mut().unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        self.0 = None;
    }
}
impl Drop for WriterChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// A copied native test executable works on GNU and BusyBox distributions alike.
// Copying an applet binary under a different name does not reliably run sleep.
fn native_writer(name: &str) -> (tempfile::TempDir, PathBuf, WriterChild) {
    let fixture = tempfile::tempdir().unwrap();
    let executable = fixture.path().join(name);
    std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    let child = Command::new(&executable)
        .args(["--exact", "native_process_fixture", "--ignored"])
        .env("WOLF_QUIESCENCE_NATIVE_FIXTURE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let child = WriterChild(Some(child));
    let comm =
        std::fs::read_to_string(format!("/proc/{}/comm", child.0.as_ref().unwrap().id())).unwrap();
    assert_eq!(
        comm.trim_end(),
        name,
        "fixture must use the actual kernel process name"
    );
    (fixture, executable, child)
}

#[test]
#[ignore = "subprocess fixture selected explicitly by native_writer"]
fn native_process_fixture() {
    assert_eq!(
        std::env::var("WOLF_QUIESCENCE_NATIVE_FIXTURE").as_deref(),
        Ok("1")
    );
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
fn executable_identity_detects_running_writer_and_permits_after_exit() {
    let _guard = PROCESS_FIXTURES.lock().unwrap();
    let (_fixture, executable, mut child) = native_writer("declared-writer");
    let uid = rustix::process::geteuid().as_raw();
    let executables = vec![executable];
    let running = quiescence::require_stopped(uid, &executables);
    let alive = child.is_alive();
    child.stop();
    assert!(alive, "native writer fixture must remain running");
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
        let (fixture, _executable, mut child) = native_writer(name);
        // The configured executable has a distinct inode and is never started.
        // /bin/echo can alias an already-running BusyBox /bin/sleep process.
        let authority = fixture.path().join("unstarted-authority");
        std::fs::copy(std::env::current_exe().unwrap(), &authority).unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let executables = vec![authority];
        let running = quiescence::require_stopped(uid, &executables);
        let other_uid = quiescence::require_stopped(uid + 1, &executables);
        let alive = child.is_alive();
        child.stop();
        assert!(alive, "native writer fixture must remain running");
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
