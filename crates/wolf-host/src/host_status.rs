//! Fixed-command observations, separate from lifecycle mutations.
use std::{io, time::Duration};
use wolf_core::{HostStatus, Revision};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tool {
    Docker,
    Systemctl,
}
pub struct Output {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
}
pub trait Tools {
    fn run(&mut self, tool: Tool, args: &[&str], timeout: Duration) -> io::Result<Output>;
}
pub struct FixedTools;
impl Tools for FixedTools {
    fn run(&mut self, tool: Tool, args: &[&str], timeout: Duration) -> io::Result<Output> {
        let output = crate::commands::run(
            match tool {
                Tool::Docker => crate::commands::Tool::Docker,
                Tool::Systemctl => crate::commands::Tool::Systemctl,
            },
            args,
            timeout,
        )?;
        Ok(Output {
            code: output.code,
            stdout: output.stdout,
        })
    }
}
pub fn observed(
    systemd: &str,
    docker: &[u8],
    staged: Option<Revision>,
    running: Option<Revision>,
    overlays: bool,
    uncertain: bool,
) -> io::Result<HostStatus> {
    if ![
        "active",
        "inactive",
        "failed",
        "activating",
        "deactivating",
        "reloading",
    ]
    .contains(&systemd)
    {
        return Err(io::Error::other("invalid systemd observation"));
    }
    let (container_state, restart_count, exit_code) = if docker.is_empty() {
        ("missing".to_owned(), 0, None)
    } else {
        let value: serde_json::Value = serde_json::from_slice(docker)?;
        let state = value
            .get("State")
            .ok_or_else(|| io::Error::other("missing Docker state"))?;
        let status = state
            .get("Status")
            .and_then(serde_json::Value::as_str)
            .filter(|s| {
                [
                    "created",
                    "running",
                    "paused",
                    "restarting",
                    "removing",
                    "exited",
                    "dead",
                ]
                .contains(s)
            })
            .ok_or_else(|| io::Error::other("invalid Docker state"))?;
        let exit = state
            .get("ExitCode")
            .and_then(serde_json::Value::as_i64)
            .and_then(|i| i32::try_from(i).ok())
            .ok_or_else(|| io::Error::other("invalid Docker exit code"))?;
        let restarts = value
            .get("RestartCount")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| io::Error::other("invalid Docker restart count"))?;
        (status.to_owned(), restarts, Some(exit))
    };
    let recovery_pending =
        uncertain || (overlays && !(systemd == "active" && container_state == "running"));
    Ok(HostStatus {
        systemd_state: systemd.into(),
        container_state,
        restart_count,
        exit_code,
        staged_revision: staged,
        running_revision: running,
        recovery_pending,
    })
}
pub(crate) fn checked(output: Output) -> io::Result<Vec<u8>> {
    if output.code != Some(0) {
        return Err(io::Error::other("fixed host tool failed"));
    }
    Ok(output.stdout)
}
pub fn container(
    policy: &crate::policy::RootPolicy,
    tools: &mut impl Tools,
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    let filter = format!("name={}", policy.container_name);
    let names = checked(tools.run(
        Tool::Docker,
        &[
            "container",
            "ls",
            "--all",
            "--filter",
            &filter,
            "--format",
            "{{.Names}}",
        ],
        timeout,
    )?)?;
    let names =
        std::str::from_utf8(&names).map_err(|_| io::Error::other("invalid Docker names"))?;
    if !names.lines().any(|name| name == policy.container_name) {
        return Ok(Vec::new());
    }
    checked(tools.run(
        Tool::Docker,
        &[
            "container",
            "inspect",
            "--format",
            "{{json .}}",
            &policy.container_name,
        ],
        timeout,
    )?)
}
pub fn read(policy: &crate::policy::RootPolicy) -> io::Result<HostStatus> {
    read_with(policy, &mut FixedTools)
}
pub fn read_with(
    policy: &crate::policy::RootPolicy,
    tools: &mut impl Tools,
) -> io::Result<HostStatus> {
    policy.validate()?;
    let state = crate::state::State::open(&policy.state_root, &policy.pc_id)?;
    let store = crate::transactions::TransactionStore::open(&policy.backup_root)?;
    let systemd = checked(tools.run(
        Tool::Systemctl,
        &[
            "show",
            "--property=ActiveState",
            "--value",
            &policy.service_unit,
        ],
        Duration::from_secs(5),
    )?)?;
    let systemd = std::str::from_utf8(&systemd)
        .map_err(|_| io::Error::other("invalid systemd output"))?
        .trim();
    let docker = container(policy, tools, Duration::from_secs(5))?;
    observed(
        systemd,
        &docker,
        state.staged()?.map(|(_, r)| r),
        state.running()?,
        !store.active()?.is_empty(),
        store.recovery_pending()?,
    )
}
