//! Local administrator commands and the closed SSH entrypoint.
use crate::{
    install::{self, InstallMode, InstallPlan, InstallRequest},
    policy::RootPolicy,
};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};
use wolf_core::*;

#[derive(Parser)]
#[command(
    name = "wolf-manager-host",
    version,
    about = "Guarded Wolf host toolkit"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Clone, ValueEnum)]
enum Mode {
    Install,
    Adopt,
}
#[derive(Subcommand)]
enum Command {
    DispatchRpc,
    PrivilegedRpc,
    LifecycleStart,
    LifecycleStop,
    ApplySteam,
    RestoreSteam,
    CatalogDaemon,
    InstallPreview {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        host_binary: PathBuf,
        #[arg(long, required = true)]
        authorized_key: Vec<PathBuf>,
        #[arg(long)]
        broker_config: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "install")]
        mode: Mode,
        #[arg(long)]
        output: PathBuf,
    },
    InstallApply {
        #[arg(long)]
        plan: PathBuf,
    },
    InstallActivate {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        start_wolf: bool,
        #[arg(long)]
        start_catalog: bool,
        #[arg(long)]
        enable_on_boot: bool,
    },
    InstallRollback {
        #[arg(long)]
        plan: PathBuf,
    },
}
fn invalid() -> io::Error {
    io::Error::other("host authority or operation invalid")
}
fn require_root() -> io::Result<()> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(invalid());
    }
    Ok(())
}
fn read_admin(path: &Path) -> io::Result<Vec<u8>> {
    require_root()?;
    crate::policy::trusted_path(path, 0, false)?;
    let file = File::from(rustix::fs::openat2(
        rustix::fs::CWD,
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    )?);
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || metadata.len() > 2 * 1024 * 1024
    {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    file.take(2 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(invalid());
    }
    Ok(bytes)
}
fn public_key_input(bytes: Vec<u8>) -> io::Result<String> {
    let mut value = String::from_utf8(bytes).map_err(|_| invalid())?;
    // ssh-keygen writes one terminal line ending; retain all other bytes for validation.
    if value.ends_with("\r\n") {
        value.truncate(value.len() - 2);
    } else if value.ends_with('\n') {
        value.truncate(value.len() - 1);
    }
    Ok(value)
}
fn read_json<T: DeserializeOwned>(path: &Path) -> io::Result<T> {
    serde_json::from_slice(&read_admin(path)?).map_err(|_| invalid())
}
fn print_json(value: &impl Serialize) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| invalid())?;
    io::stdout().lock().write_all(&bytes)?;
    io::stdout().lock().write_all(b"\n")
}
fn write_plan(path: &Path, value: &InstallPlan) -> io::Result<()> {
    let parent = path.parent().ok_or_else(invalid)?;
    crate::policy::trusted_path(parent, 0, true)?;
    let name = path.file_name().ok_or_else(invalid)?;
    let directory = File::from(rustix::fs::openat2(
        rustix::fs::CWD,
        parent,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    )?);
    let metadata = directory.metadata()?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(invalid());
    }
    let mut file = File::from(rustix::fs::openat(
        &directory,
        name,
        rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_raw_mode(0o600),
    )?);
    file.write_all(&serde_json::to_vec_pretty(value).map_err(|_| invalid())?)?;
    file.sync_all()?;
    directory.sync_all()
}
pub fn run(cli: Cli) -> io::Result<()> {
    match cli.command {
        Command::DispatchRpc => {
            let original = std::env::var("SSH_ORIGINAL_COMMAND").map_err(|_| invalid())?;
            let bytes = crate::dispatcher::dispatch(&original, io::stdin().lock(), |bytes| {
                crate::dispatcher::fixed_helper(bytes, Duration::from_secs(800))
            })?;
            // Every verified response, including ok:false, is an SSH transport success.
            io::stdout().lock().write_all(&bytes)
        }
        Command::PrivilegedRpc => privileged_rpc(),
        Command::LifecycleStart => crate::host_runtime::lifecycle_start(&RootPolicy::load_fixed()?),
        Command::LifecycleStop => crate::host_runtime::lifecycle_stop(&RootPolicy::load_fixed()?),
        Command::ApplySteam => {
            let policy = RootPolicy::load_fixed()?;
            let state = crate::state::State::open(&policy.state_root, &policy.pc_id)?;
            let (settings, _) = state.staged()?.ok_or_else(invalid)?;
            crate::host_steam::prepare(&policy, &settings)
        }
        Command::RestoreSteam => crate::host_steam::restore(&RootPolicy::load_fixed()?),
        Command::CatalogDaemon => crate::catalog_daemon::run(),
        Command::InstallPreview {
            policy,
            host_binary,
            authorized_key,
            broker_config,
            mode,
            output,
        } => {
            require_root()?;
            let policy: RootPolicy = read_json(&policy)?;
            let authorized_public_keys = authorized_key
                .iter()
                .map(|p| public_key_input(read_admin(p)?))
                .collect::<io::Result<Vec<_>>>()?;
            let initial_files = match mode {
                Mode::Install => crate::defaults::initial_files(&policy)?,
                Mode::Adopt => Vec::new(),
            };
            let plan = install::preflight(&InstallRequest {
                mode: match mode {
                    Mode::Install => InstallMode::Install,
                    Mode::Adopt => InstallMode::Adopt,
                },
                policy,
                authorized_public_keys,
                source_binary: host_binary,
                broker_config_source: broker_config,
                initial_files,
            })?;
            write_plan(&output, &plan)?;
            print_json(&plan)
        }
        Command::InstallApply { plan } => print_json(&install::apply(&read_json(&plan)?)?),
        Command::InstallActivate {
            plan,
            start_wolf,
            start_catalog,
            enable_on_boot,
        } => print_json(&install::activate(
            &read_json(&plan)?,
            install::ActivationOptions {
                start_wolf,
                start_catalog,
                enable_on_boot,
            },
        )?),
        Command::InstallRollback { plan } => print_json(&install::rollback(&read_json(&plan)?)?),
    }
}
fn safe_io(error: io::Error) -> SafeError {
    SafeError::new(if error.kind() == io::ErrorKind::TimedOut {
        "unknown_interrupted"
    } else {
        "recovery_pending"
    })
}
fn privileged_rpc() -> io::Result<()> {
    require_root()?;
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take((RPC_MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    let request = RpcRequest::parse(&bytes).map_err(|_| invalid())?;
    let policy = RootPolicy::load_fixed()?;
    let journal = crate::journal::Journal::open(&policy.backup_root.join("requests"))?;
    let response = crate::rpc::serve(&journal, &policy.pc_id, &request, |operation| {
        match operation {
            RpcOperation::Preflight(_) => {
                let status = crate::host_status::read(&policy).map_err(safe_io)?;
                Ok(RpcResult::Preflight(HostCapabilities {
                    version: 1,
                    pc_id: policy.pc_id.clone(),
                    ready: !status.recovery_pending,
                    proton_cachyos: policy.proton.is_some(),
                    reasons: if status.recovery_pending {
                        vec!["recovery_pending".into()]
                    } else {
                        vec![]
                    },
                }))
            }
            RpcOperation::Status(_) => crate::host_status::read(&policy)
                .map(RpcResult::Status)
                .map_err(safe_io),
            RpcOperation::ApplySettings(payload) => {
                payload.settings.validate_capabilities(&HostCapabilities {
                    version: 1,
                    pc_id: policy.pc_id.clone(),
                    ready: true,
                    proton_cachyos: policy.proton.is_some(),
                    reasons: vec![],
                })?;
                if crate::host_status::read(&policy)
                    .map_err(safe_io)?
                    .recovery_pending
                {
                    return Err(SafeError::new("recovery_pending"));
                }
                let state = crate::state::State::open(&policy.state_root, &policy.pc_id)
                    .map_err(safe_io)?;
                // A late write/fsync error cannot certify that staging had no effect.
                let revision = state
                    .stage(&payload.settings)
                    .map_err(|_| SafeError::new("unknown_interrupted"))?;
                Ok(RpcResult::Applied {
                    staged_revision: revision,
                })
            }
            RpcOperation::Start(payload) => {
                let mut backend =
                    crate::host_runtime::SystemBackend::new(&policy).map_err(safe_io)?;
                crate::lifecycle::start(&mut backend, &payload.expected_staged_revision)
                    .map(RpcResult::Lifecycle)
            }
            RpcOperation::Restart(payload) => {
                let mut backend =
                    crate::host_runtime::SystemBackend::new(&policy).map_err(safe_io)?;
                crate::lifecycle::restart(&mut backend, &payload.expected_staged_revision)
                    .map(RpcResult::Lifecycle)
            }
            RpcOperation::Stop(_) => {
                let mut backend =
                    crate::host_runtime::SystemBackend::new(&policy).map_err(safe_io)?;
                crate::lifecycle::stop(&mut backend).map(RpcResult::Lifecycle)
            }
            RpcOperation::BoundedLogs(payload) => {
                bounded_logs(&policy, payload.lines).map_err(safe_io)
            }
            RpcOperation::RequestStatus(_) => Err(SafeError::validation()),
        }
    })?;
    print_json(&response)
}
fn bounded_logs(policy: &RootPolicy, count: u16) -> io::Result<RpcResult> {
    let requested = count;
    let count = count.to_string();
    let output = crate::commands::run(
        crate::commands::Tool::Journalctl,
        &[
            "--no-pager",
            "--output=cat",
            "--unit",
            &policy.service_unit,
            "--lines",
            &count,
        ],
        Duration::from_secs(10),
    )?;
    if output.code != Some(0) {
        return Err(invalid());
    }
    let text = String::from_utf8(output.stdout).map_err(|_| invalid())?;
    let mut lines = Vec::new();
    let mut total = 0;
    let mut truncated = false;
    for line in text.lines() {
        let clean = sanitize_log(line);
        if lines.len() >= usize::from(requested) || total + clean.len() > 64 * 1024 {
            truncated = true;
            break;
        }
        truncated |= line.chars().count() > 4096;
        total += clean.len();
        lines.push(clean);
    }
    Ok(RpcResult::Logs { lines, truncated })
}
fn sanitize_log(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    if [
        "password",
        "authorization",
        "private key",
        "token",
        "cookie",
        "secret",
    ]
    .iter()
    .any(|word| lower.contains(word))
    {
        return "[redacted sensitive log line]".into();
    }
    line.chars()
        .filter(|c| !c.is_control())
        .take(4096)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::public_key_input;
    use crate::install::{render_privilege_templates, validate_public_key};

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA operator";

    #[test]
    fn ssh_public_key_file_accepts_one_optional_terminal_line_ending() {
        let expected = render_privilege_templates(&[KEY.into()]).unwrap();
        for ending in ["", "\n", "\r\n"] {
            let decoded = public_key_input(format!("{KEY}{ending}").into_bytes()).unwrap();
            assert_eq!(render_privilege_templates(&[decoded]).unwrap(), expected);
        }
    }

    #[test]
    fn public_key_file_preserves_refusal_of_multiline_blank_and_control_input() {
        for input in [
            format!("{KEY}\n{KEY}\n"),
            format!("{KEY}\n\n"),
            format!("{KEY}\r"),
            format!("{KEY}\t\n"),
            format!("{KEY}\0\n"),
            "\n".into(),
            "\r\n".into(),
        ] {
            let decoded = public_key_input(input.into_bytes()).unwrap();
            assert!(validate_public_key(&decoded).is_err());
        }
        assert!(public_key_input(vec![0xff]).is_err());
    }
}
