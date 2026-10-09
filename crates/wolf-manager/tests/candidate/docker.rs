//! Disposable Docker orchestration; candidate binaries are never rebuilt here.
use std::{
    path::Path,
    process::{Command, Output},
    time::Duration,
};
pub fn output(args: &[&str]) -> Output {
    Command::new("docker")
        .args(args)
        .output()
        .expect("Docker fixture command")
}
pub fn checked(args: &[&str]) -> String {
    let result = output(args);
    assert!(
        result.status.success(),
        "Docker fixture failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap().trim().to_owned()
}
pub struct Container(pub String);
impl Drop for Container {
    fn drop(&mut self) {
        let _ = output(&["rm", "-f", &self.0]);
    }
}
pub fn mount(path: &Path, target: &str, readonly: bool) -> String {
    format!(
        "{}:{target}{}",
        path.display(),
        if readonly { ":ro" } else { "" }
    )
}
pub async fn wait_exit(container: &Container) {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if checked(&["inspect", "--format", "{{.State.Running}}", &container.0]) == "false" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("SIGTERM must exit without SIGKILL");
    assert_eq!(
        checked(&["inspect", "--format", "{{.State.ExitCode}}", &container.0]),
        "0"
    );
}
