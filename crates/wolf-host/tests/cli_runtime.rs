//! Native entrypoint fixtures require a separate disposable root PID namespace.
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use wolf_core::*;

struct ChildGuard {
    child: std::process::Child,
    stdout: std::sync::mpsc::Receiver<std::io::Result<Vec<u8>>>,
    stderr: std::sync::mpsc::Receiver<std::io::Result<Vec<u8>>>,
    deadline: std::time::Instant,
    completed: bool,
}
fn capture(
    reader: Option<impl Read + Send + 'static>,
    limit: usize,
) -> std::sync::mpsc::Receiver<std::io::Result<Vec<u8>>> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = (|| {
            let mut bytes = Vec::new();
            if let Some(reader) = reader {
                reader.take((limit + 1) as u64).read_to_end(&mut bytes)?;
            }
            if bytes.len() > limit {
                return Err(std::io::Error::other("fixture output exceeds bound"));
            }
            Ok(bytes)
        })();
        let _ = sender.send(result);
    });
    receiver
}
impl ChildGuard {
    fn spawn(command: &mut Command) -> Self {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap();
        Self {
            stdout: capture(child.stdout.take(), 1024 * 1024),
            stderr: capture(child.stderr.take(), 65536),
            child,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(10),
            completed: false,
        }
    }
    fn write(&mut self, bytes: Vec<u8>) {
        let mut pipe = self.child.stdin.take().unwrap();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let _ = sender.send(pipe.write_all(&bytes));
        });
        receiver
            .recv_timeout(
                self.deadline
                    .saturating_duration_since(std::time::Instant::now()),
            )
            .expect("fixture stdin deadline")
            .expect("fixture stdin closed");
    }
    fn output(mut self) -> std::process::Output {
        drop(self.child.stdin.take());
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(
                std::time::Instant::now() < self.deadline,
                "fixture process deadline"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        let read = |receiver: &std::sync::mpsc::Receiver<std::io::Result<Vec<u8>>>| {
            receiver
                .recv_timeout(
                    self.deadline
                        .saturating_duration_since(std::time::Instant::now()),
                )
                .expect("fixture pipe deadline")
                .expect("fixture pipe refused")
        };
        let output = std::process::Output {
            status,
            stdout: read(&self.stdout),
            stderr: read(&self.stderr),
        };
        self.completed = true;
        output
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.completed
            && let Some(pid) = rustix::process::Pid::from_raw(self.child.id() as i32)
        {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
        let _ = self.child.wait();
    }
}

#[test]
fn unprivileged_cli_refuses_admin_commands_without_touching_inputs() {
    assert_ne!(
        rustix::process::geteuid().as_raw(),
        0,
        "run default tests as the development user"
    );
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("plan.json");
    fs::write(&input, b"private unrelated bytes").unwrap();
    for command in ["install-apply", "install-activate", "install-rollback"] {
        let output = ChildGuard::spawn(
            Command::new(env!("CARGO_BIN_EXE_wolf-manager-host"))
                .args([command, "--plan"])
                .arg(&input),
        )
        .output();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("private unrelated"));
        assert_eq!(fs::read(&input).unwrap(), b"private unrelated bytes");
    }
}

#[test]
#[ignore = "requires isolated root container, native-validator sentinel and WOLF_TEST_CLI_RUNTIME=1"]
fn native_catalog_daemon_terminates_during_unacknowledged_connect_without_publishing() {
    assert_eq!(rustix::process::geteuid().as_raw(), 0);
    assert_eq!(std::env::var("WOLF_TEST_CLI_RUNTIME").as_deref(), Ok("1"));
    assert_eq!(
        fs::read("/run/wolf-native-validator-fixture").unwrap(),
        b"disposable-container"
    );
    assert!(!Path::new("/var/run/docker.sock").exists());
    let temp = tempfile::Builder::new()
        .prefix("wolf-catalog-cli-")
        .tempdir_in("/var/lib")
        .unwrap();
    let base = temp.path();
    fs::set_permissions(base, fs::Permissions::from_mode(0o755)).unwrap();
    for path in ["profile/steamapps", "catalog"] {
        fs::create_dir_all(base.join(path)).unwrap();
    }
    fs::set_permissions(base.join("catalog"), fs::Permissions::from_mode(0o700)).unwrap();
    rustix::fs::fchown(
        fs::File::open(base.join("catalog")).unwrap(),
        Some(rustix::fs::Uid::from_raw(1000)),
        Some(rustix::fs::Gid::from_raw(1000)),
    )
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let broker = base.join("broker.json");
    fs::write(&broker,serde_json::to_vec(&serde_json::json!({"host":"127.0.0.1","port":listener.local_addr().unwrap().port(),"client_id":uuid::Uuid::new_v4().to_string(),"username_file":null,"password_file":null,"tls":false,"pc_name":"Fixture","topic_base":"wolf-manager/native-catalog-fixture","discovery_prefix":"native-catalog-fixture"})).unwrap()).unwrap();
    fs::set_permissions(&broker, fs::Permissions::from_mode(0o600)).unwrap();
    rustix::fs::fchown(
        fs::File::open(&broker).unwrap(),
        Some(rustix::fs::Uid::from_raw(1000)),
        Some(rustix::fs::Gid::from_raw(1000)),
    )
    .unwrap();
    let policy = serde_json::json!({"version":1,"pc_id":"catalog-native","steam_uid":1000,"steam_gid":1000,"libraries":[{"library_id":"primary","steamapps_path":base.join("profile/steamapps"),"container_paths":["/home/steam/Steam/steamapps"]}],"steam_profiles":[{"root":base.join("profile"),"config_vdf":"config/config.vdf","libraryfolders_vdf":["steamapps/libraryfolders.vdf"],"userdata_directory":"userdata","container_userdata_paths":["/home/steam/Steam/userdata"]}],"wolf_config":{"root":"/etc/wolf","relative_path":"config.toml","uid":0,"gid":0},"compose_file":"/etc/wolf/compose.json","service_unit":"wolf.service","container_name":"wolf","image_ref":"ghcr.io/games-on-whales/wolf:stable","backup_root":"/var/lib/wolf-manager/backups","state_root":"/var/lib/wolf-manager/state","catalog_state_directory":base.join("catalog"),"broker_secret_file":broker,"pull_on_start":true,"pull_timeout_seconds":60,"proton":null,"steam_executables":["/usr/bin/steam"],"steam_runner":{"type":"docker","image":"example.invalid/steam:stable"}});
    let mut fixed = FixedFiles(vec![]);
    fixed.replace(
        "/etc/wolf-manager/host-policy.json",
        &serde_json::to_vec(&policy).unwrap(),
        0o644,
    );
    let bytes = fs::read(&broker).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_wolf-manager-host"));
    command
        .arg("catalog-daemon")
        .uid(1000)
        .gid(1000)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
        // Root/nonroot processes can share a PID across disposable containers.
        // A separate filename avoids existing root-owned LLVM pool files.
        let path = PathBuf::from(profile);
        command.env(
            "LLVM_PROFILE_FILE",
            path.parent().unwrap().join(format!(
                "ha-wolf-manager-catalog-{}-%p-%32m.profraw",
                uuid::Uuid::new_v4()
            )),
        );
    }
    let mut process = ChildGuard::spawn(&mut command);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    process.child.try_wait().unwrap().is_none(),
                    "daemon exited before native connect"
                );
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => panic!("fixture accept: {error}"),
        }
    };
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).unwrap();
    assert_eq!(first, [0x10]);
    // Signal handlers are installed before CONNECT. No broker acknowledgement is sent.
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(process.child.id() as i32).unwrap(),
        rustix::process::Signal::TERM,
    )
    .unwrap();
    while process.child.try_wait().unwrap().is_none() {
        assert!(
            std::time::Instant::now() < deadline,
            "shutdown blocked on unacknowledged broker"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let result = process.output();
    assert!(
        result.status.success(),
        "native daemon did not shut down gracefully"
    );
    assert!(!base.join("catalog/owned.json").exists());
    assert!(!base.join("catalog/published.json").exists());
    assert_eq!(fs::read(broker).unwrap(), bytes);
}

struct Preimage {
    path: PathBuf,
    retained: Option<(Vec<u8>, u32)>,
}
struct FixedFiles(Vec<Preimage>);
impl FixedFiles {
    fn replace(&mut self, path: &str, bytes: &[u8], mode: u32) {
        let path = PathBuf::from(path);
        let before = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                assert!(metadata.is_file() && metadata.nlink() == 1);
                Some((fs::read(&path).unwrap(), metadata.mode() & 0o7777))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("fixture preimage refused: {error}"),
        };
        self.0.push(Preimage {
            path: path.clone(),
            retained: before,
        });
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
}
impl Drop for FixedFiles {
    fn drop(&mut self) {
        for preimage in self.0.iter().rev() {
            if let Some((bytes, mode)) = &preimage.retained {
                fs::write(&preimage.path, bytes).unwrap();
                fs::set_permissions(&preimage.path, fs::Permissions::from_mode(*mode)).unwrap();
            } else {
                fs::remove_file(&preimage.path).unwrap();
            }
        }
    }
}

fn native(command: &str, request: Option<&RpcRequest>) -> std::process::Output {
    let mut process =
        ChildGuard::spawn(Command::new(env!("CARGO_BIN_EXE_wolf-manager-host")).arg(command));
    if let Some(request) = request {
        process.write(serde_json::to_vec(request).unwrap());
    }
    process.output()
}

#[test]
#[ignore = "requires isolated root container, native-validator sentinel and WOLF_TEST_CLI_RUNTIME=1"]
fn native_rpc_and_lifecycle_preserve_pairing_and_reconcile_without_replay() {
    assert_eq!(rustix::process::geteuid().as_raw(), 0);
    assert_eq!(std::env::var("WOLF_TEST_CLI_RUNTIME").as_deref(), Ok("1"));
    assert_eq!(
        fs::read("/run/wolf-native-validator-fixture").unwrap(),
        b"disposable-container"
    );
    assert!(
        !Path::new("/var/run/docker.sock").exists(),
        "fixture must never have a Docker authority socket"
    );
    let temp = tempfile::Builder::new()
        .prefix("wolf-native-cli-")
        .tempdir_in("/root")
        .unwrap();
    let base = temp.path();
    for directory in [
        "profile/config",
        "profile/steamapps/common",
        "profile/userdata",
        "wolf",
        "backups/requests",
        "state",
        "catalog",
        "bin",
    ] {
        fs::create_dir_all(base.join(directory)).unwrap();
    }
    for directory in ["backups", "backups/requests", "state"] {
        fs::set_permissions(base.join(directory), fs::Permissions::from_mode(0o700)).unwrap();
    }
    for name in [
        "profile/config/config.vdf",
        "profile/steamapps/libraryfolders.vdf",
    ] {
        let path = base.join(name);
        fs::write(&path, b"\"Steam\" {}\n").unwrap();
        let file = fs::File::open(path).unwrap();
        rustix::fs::fchown(
            &file,
            Some(rustix::fs::Uid::from_raw(1000)),
            Some(rustix::fs::Gid::from_raw(1000)),
        )
        .unwrap();
    }
    let original_wolf = b"config_version=7\nuuid=\"retained-fixture-identity\"\npaired_clients=[{client_id=\"retained-pairing\"}]\napps=[]\n";
    fs::write(base.join("wolf/config.toml"), original_wolf).unwrap();
    fs::write(base.join("wolf/compose.json"), b"{}\n").unwrap();
    fs::write(base.join("bin/steam"), b"not an executing Steam process").unwrap();
    let policy: wolf_manager_host::policy::RootPolicy = serde_json::from_value(serde_json::json!({
        "version":1,"pc_id":"native-cli","steam_uid":1000,"steam_gid":1000,
        "libraries":[{"library_id":"primary","steamapps_path":base.join("profile/steamapps"),"container_paths":["/home/steam/Steam/steamapps"]}],
        "steam_profiles":[{"root":base.join("profile"),"config_vdf":"config/config.vdf","libraryfolders_vdf":["steamapps/libraryfolders.vdf"],"userdata_directory":"userdata","container_userdata_paths":["/home/steam/Steam/userdata"]}],
        "wolf_config":{"root":base.join("wolf"),"relative_path":"config.toml","uid":0,"gid":0},
        "compose_file":base.join("wolf/compose.json"),"service_unit":"wolf.service","container_name":"wolf",
        "image_ref":"ghcr.io/games-on-whales/wolf:stable","backup_root":base.join("backups"),"state_root":base.join("state"),
        "catalog_state_directory":base.join("catalog"),"broker_secret_file":null,"pull_on_start":true,"pull_timeout_seconds":60,
        "proton":null,"steam_executables":[base.join("bin/steam")],"steam_runner":{"type":"docker","image":"example.invalid/steam:stable"}
    })).unwrap();
    policy.validate().unwrap();
    let mut fixed = FixedFiles(vec![]);
    fixed.replace(
        "/etc/wolf-manager/host-policy.json",
        &serde_json::to_vec(&policy).unwrap(),
        0o644,
    );
    fixed.replace("/run/wolf-cli-runtime-state", b"inactive", 0o600);
    fixed.replace("/run/wolf-cli-runtime-actions", b"", 0o600);
    let binary = serde_json::to_string(env!("CARGO_BIN_EXE_wolf-manager-host")).unwrap();
    let profile = serde_json::to_string(
        &std::env::var("LLVM_PROFILE_FILE").unwrap_or_else(|_| "/tmp/wolf-cli-%p.profraw".into()),
    )
    .unwrap();
    fixed.replace("/usr/bin/systemctl", format!(r#"#!/usr/bin/python3
import pathlib,sys,subprocess
state=pathlib.Path('/run/wolf-cli-runtime-state')
with open('/run/wolf-cli-runtime-actions','a') as log: log.write('systemctl '+repr(sys.argv[1:])+'\n')
if sys.argv[1]=='show': print('loaded' if '--property=LoadState' in sys.argv else state.read_text())
elif sys.argv[1]=='is-active': raise SystemExit(1)
elif sys.argv[1]=='is-enabled': print('disabled'); raise SystemExit(1)
elif sys.argv[1] in ('start','stop'):
 raise SystemExit(subprocess.run([{binary},'lifecycle-'+sys.argv[1]],env={{'LLVM_PROFILE_FILE':{profile}}}).returncode)
else: raise SystemExit(2)
"#).as_bytes(), 0o755);
    fixed.replace("/usr/bin/docker", br#"#!/usr/bin/python3
import json,pathlib,sys
a=sys.argv[1:];state=pathlib.Path('/run/wolf-cli-runtime-state')
with open('/run/wolf-cli-runtime-actions','a') as log: log.write('docker '+repr(a)+'\n')
if a[0]=='pull': raise SystemExit(1)
elif a[:2]==['image','inspect']:
 import platform
 print(json.dumps({'Architecture':{'x86_64':'amd64','aarch64':'arm64'}[platform.machine()],'Os':'linux'}))
elif a[0]=='compose':
 if 'up' in a: state.write_text('active')
 elif 'down' in a: state.write_text('inactive')
 else: raise SystemExit(2)
elif a[:2]==['container','ls']:
 if '{{.Names}}' in a: print('wolf')
elif a[:2]==['container','inspect']: print(json.dumps({'State':{'Status':'running' if state.read_text()=='active' else 'exited','ExitCode':0},'RestartCount':0}))
else: raise SystemExit(2)
"#, 0o755);
    let sensitive = uuid::Uuid::new_v4().to_string();
    fixed.replace("/usr/bin/journalctl", format!("#!/usr/bin/python3\nprint('ordinary status\\x01')\nprint('authorization: {sensitive}')\nprint('x'*4100)\nprint('extra')\n").as_bytes(), 0o755);
    let mut request = RpcRequest {
        version: 1,
        request_id: uuid::Uuid::new_v4(),
        pc_id: policy.pc_id.clone(),
        operation: RpcOperation::Preflight(EmptyPayload {}),
    };
    fixed.replace("/usr/bin/sudo", format!(r#"#!/usr/bin/python3
import subprocess,sys
assert sys.argv[1:]==['-n','/usr/libexec/wolf-manager/wolf-host-root']
raise SystemExit(subprocess.run([{binary},'privileged-rpc'],env={{'LLVM_PROFILE_FILE':{profile}}}).returncode)
"#).as_bytes(), 0o755);
    let call = |request: &RpcRequest| {
        let output = native("privileged-rpc", Some(request));
        assert!(
            output.status.success(),
            "native RPC refused: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let response: RpcResponse = serde_json::from_slice(&output.stdout).unwrap();
        response.validate_for(request).unwrap();
        response
    };
    assert!(call(&request).ok);
    let mut dispatcher = ChildGuard::spawn(
        Command::new(env!("CARGO_BIN_EXE_wolf-manager-host"))
            .arg("dispatch-rpc")
            .env("SSH_ORIGINAL_COMMAND", "wolf-manager-rpc-v1"),
    );
    dispatcher.write(serde_json::to_vec(&request).unwrap());
    let dispatched = dispatcher.output();
    assert!(dispatched.status.success());
    let dispatched: RpcResponse = serde_json::from_slice(&dispatched.stdout).unwrap();
    dispatched.validate_for(&request).unwrap();
    assert!(dispatched.ok);
    request.request_id = uuid::Uuid::new_v4();
    request.operation = RpcOperation::ApplySettings(ApplySettingsPayload {
        settings: Settings::default(),
        revision: Settings::default().revision().unwrap(),
    });
    let applied = call(&request);
    assert!(applied.ok);
    let original = request.clone();
    let before = fs::read("/run/wolf-cli-runtime-actions").unwrap();
    assert_eq!(call(&request), applied);
    assert_eq!(fs::read("/run/wolf-cli-runtime-actions").unwrap(), before);
    request.request_id = uuid::Uuid::new_v4();
    request.operation = RpcOperation::RequestStatus(RequestStatusPayload {
        original_request_id: original.request_id,
    });
    let Some(RpcResult::RequestStatus(observed)) = call(&request).result else {
        panic!("missing reconciliation")
    };
    assert_eq!(observed.phase, Some(JournalPhase::Succeeded));
    assert!(native("lifecycle-start", None).status.success());
    let running = wolf_manager_host::state::State::open(&policy.state_root, &policy.pc_id)
        .unwrap()
        .running()
        .unwrap();
    assert_eq!(running, Some(Settings::default().revision().unwrap()));
    request.request_id = uuid::Uuid::new_v4();
    request.operation = RpcOperation::Status(EmptyPayload {});
    let Some(RpcResult::Status(status)) = call(&request).result else {
        panic!("missing status")
    };
    assert_eq!(status.container_state, "running");
    request.request_id = uuid::Uuid::new_v4();
    request.operation = RpcOperation::BoundedLogs(LogsPayload { lines: 3 });
    let Some(RpcResult::Logs { lines, truncated }) = call(&request).result else {
        panic!("missing logs")
    };
    assert!(truncated);
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0], "ordinary status");
    assert_eq!(lines[1], "[redacted sensitive log line]");
    assert_eq!(lines[2].len(), 4096);
    assert!(!lines.join("").contains(&sensitive));
    assert!(native("lifecycle-stop", None).status.success());
    assert!(
        wolf_manager_host::state::State::open(&policy.state_root, &policy.pc_id)
            .unwrap()
            .running()
            .unwrap()
            .is_none()
    );
    for operation in [
        RpcOperation::Start(StartPayload {
            expected_staged_revision: Settings::default().revision().unwrap(),
        }),
        RpcOperation::Restart(StartPayload {
            expected_staged_revision: Settings::default().revision().unwrap(),
        }),
        RpcOperation::Stop(EmptyPayload {}),
    ] {
        request.request_id = uuid::Uuid::new_v4();
        request.operation = operation;
        let response = call(&request);
        assert!(response.ok);
        let actions = fs::read("/run/wolf-cli-runtime-actions").unwrap();
        assert_eq!(call(&request), response);
        assert_eq!(fs::read("/run/wolf-cli-runtime-actions").unwrap(), actions);
    }
    let document: toml::Value =
        toml::from_str(&fs::read_to_string(base.join("wolf/config.toml")).unwrap()).unwrap();
    assert_eq!(document["uuid"].as_str(), Some("retained-fixture-identity"));
    assert_eq!(
        document["paired_clients"][0]["client_id"].as_str(),
        Some("retained-pairing")
    );
    assert_eq!(
        fs::read(base.join("profile/config/config.vdf")).unwrap(),
        b"\"Steam\" {}\n"
    );

    let compose = serde_json::json!({"services":{"wolf":{"container_name":"wolf","volumes":[format!("{}:/mapped/wolf:rw",policy.wolf_config.root.display())]}}});
    fs::write(&policy.compose_file, serde_json::to_vec(&compose).unwrap()).unwrap();
    let apps = [AppId::new("12").unwrap()];
    let icons = wolf_manager_host::icons::prepare(&policy, &apps, false).unwrap();
    assert_eq!(
        icons[&apps[0]],
        "/mapped/wolf/.ha-wolf-manager-icons/12.png"
    );
    let cache = policy
        .wolf_config
        .root
        .join(".ha-wolf-manager-icons/12.png");
    let png = fs::read(&cache).unwrap();
    assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));
    assert_eq!(
        wolf_manager_host::icons::prepare(&policy, &apps, false).unwrap(),
        icons
    );
    assert_eq!(fs::read(&cache).unwrap(), png);
    fs::write(&cache, b"operator replacement").unwrap();
    assert!(wolf_manager_host::icons::prepare(&policy, &apps, false).is_err());
    assert_eq!(fs::read(&cache).unwrap(), b"operator replacement");

    // Preview is a native administrator read/plan operation, never service activation.
    fixed.replace(
        "/etc/ssh/sshd_config",
        b"# disposable preview authority\n",
        0o600,
    );
    let mut install_policy = policy.clone();
    install_policy.wolf_config.relative_path = "cfg/config.toml".into();
    fs::create_dir(base.join("wolf/cfg")).unwrap();
    fs::write(base.join("wolf/cfg/config.toml"), original_wolf).unwrap();
    fs::remove_file(&policy.compose_file).unwrap();
    fs::set_permissions(
        &policy.catalog_state_directory,
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    rustix::fs::fchown(
        fs::File::open(&policy.catalog_state_directory).unwrap(),
        Some(rustix::fs::Uid::from_raw(1000)),
        Some(rustix::fs::Gid::from_raw(1000)),
    )
    .unwrap();
    let policy_input = base.join("install-policy.json");
    fs::write(&policy_input, serde_json::to_vec(&install_policy).unwrap()).unwrap();
    let key_input = base.join("manager-key.pub");
    let key =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA fixture";
    fs::write(&key_input, format!("{key}\r\n")).unwrap();
    let source_binary = base.join("candidate-binary");
    // Minimal reviewed ELF descriptor fixture; applying/executing this candidate is forbidden.
    let mut elf = vec![0u8; 128];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16..18].copy_from_slice(&2u16.to_le_bytes());
    elf[18..20].copy_from_slice(&62u16.to_le_bytes());
    elf[32..40].copy_from_slice(&64u64.to_le_bytes());
    elf[54..56].copy_from_slice(&56u16.to_le_bytes());
    elf[56..58].copy_from_slice(&1u16.to_le_bytes());
    elf[64..68].copy_from_slice(&1u32.to_le_bytes());
    fs::write(&source_binary, &elf).unwrap();
    let plan_path = base.join("reviewed-plan.json");
    let preview_request = wolf_manager_host::install::InstallRequest {
        mode: wolf_manager_host::install::InstallMode::Install,
        policy: install_policy.clone(),
        authorized_public_keys: vec![key.into()],
        source_binary: source_binary.clone(),
        broker_config_source: None,
        initial_files: wolf_manager_host::defaults::initial_files(&install_policy).unwrap(),
    };
    assert!(
        wolf_manager_host::install::preflight(&preview_request).is_err(),
        "changed storage authority must require explicit migration"
    );
    assert_eq!(
        fs::read("/etc/wolf-manager/host-policy.json").unwrap(),
        serde_json::to_vec(&policy).unwrap()
    );
    fixed.replace(
        "/etc/wolf-manager/host-policy.json",
        &serde_json::to_vec_pretty(&install_policy).unwrap(),
        0o644,
    );
    wolf_manager_host::install::preflight(&preview_request)
        .expect("native fixture installer preconditions");
    let preview = || {
        ChildGuard::spawn(
            Command::new(env!("CARGO_BIN_EXE_wolf-manager-host"))
                .arg("install-preview")
                .arg("--policy")
                .arg(&policy_input)
                .arg("--host-binary")
                .arg(&source_binary)
                .arg("--authorized-key")
                .arg(&key_input)
                .arg("--output")
                .arg(&plan_path),
        )
        .output()
    };
    let output = preview();
    assert!(
        output.status.success(),
        "native preview refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let plan: wolf_manager_host::install::InstallPlan =
        serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan.authorized_public_keys, [key]);
    assert_eq!(plan.policy.pc_id, policy.pc_id);
    assert!(!plan.service_snapshot.wolf.active);
    let before = fs::read(&plan_path).unwrap();
    assert_eq!(fs::metadata(&plan_path).unwrap().mode() & 0o7777, 0o600);
    assert!(
        !preview().status.success(),
        "preview must not replace an existing reviewed plan"
    );
    assert_eq!(fs::read(&plan_path).unwrap(), before);
    assert!(
        !policy.compose_file.exists(),
        "preview materialized proposed defaults"
    );
    assert_eq!(
        fs::read(base.join("wolf/cfg/config.toml")).unwrap(),
        original_wolf
    );
}
