use clap::Parser;
use ha_wolf_manager::{init, runtime::Cli};
#[test]
fn already_unprivileged_startup_keeps_explicit_private_directory() {
    if rustix::process::geteuid().is_root() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let mut cli = Cli::parse_from([
        "manager",
        "--data",
        temp.path().to_str().unwrap(),
        "healthcheck",
    ]);
    init::prepare(&mut cli).unwrap();
    assert!(!rustix::process::geteuid().is_root());
}
