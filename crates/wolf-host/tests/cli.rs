use std::process::Command;

#[test]
fn native_host_cli_reports_the_coordinated_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_wolf-manager-host"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        concat!("wolf-manager-host ", env!("CARGO_PKG_VERSION"), "\n")
    );
}
#[test]
fn native_host_cli_refuses_unknown_commands() {
    let output = Command::new(env!("CARGO_BIN_EXE_wolf-manager-host"))
        .arg("arbitrary-shell-command")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}
#[test]
fn invalid_ssh_command_is_refused_before_dispatch() {
    let output = Command::new(env!("CARGO_BIN_EXE_wolf-manager-host"))
        .arg("dispatch-rpc")
        .env("SSH_ORIGINAL_COMMAND", "sh -c malicious")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}
