//! Opt-in per-native-architecture verification of the exact built scratch image.
//! No household services, rebuilds inside the DUT, or emulated execution.
#[path = "candidate/docker.rs"]
mod docker;
#[path = "candidate/http.rs"]
mod http;
#[path = "candidate/mqtt.rs"]
mod mqtt;
#[path = "candidate/ssh.rs"]
mod ssh;
use reqwest::StatusCode;
use serde_json::json;
use std::{
    fs,
    net::TcpListener,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    time::Duration,
};
const BROKER: &str =
    "eclipse-mosquitto@sha256:38c0da4f2ef84284d47b3b3eeea1cb3bdeabe81ee10caf0cd5c5ff61ee3ea408";
fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn write(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}
struct Files(tempfile::TempDir);
impl Drop for Files {
    fn drop(&mut self) {
        // Only this fresh, uniquely named disposable fixture tree is mounted.
        let mount = docker::mount(self.0.path(), "/fixture", false);
        let _ = docker::output(&[
            "run",
            "--rm",
            "--network",
            "none",
            "--user",
            "0:0",
            "--entrypoint",
            "sh",
            "-v",
            &mount,
            BROKER,
            "-c",
            "rm -rf /fixture/data /fixture/secrets",
        ]);
    }
}
fn start_dut(image: &str, root: &Path, listen: u16, broker: u16, base: &str) -> docker::Container {
    let name = format!("wolf-candidate-runtime-{}", uuid::Uuid::new_v4());
    let data = docker::mount(&root.join("data"), "/data", false);
    let secrets = docker::mount(&root.join("secrets"), "/secrets", true);
    docker::checked(&[
        "run",
        "-d",
        "--name",
        &name,
        "--network",
        "host",
        "--user",
        "1000:1000",
        "-e",
        "WOLF_MODE=standalone",
        "-v",
        &data,
        "-v",
        &secrets,
        image,
        "--mode",
        "standalone",
        "--listen",
        &format!("0.0.0.0:{listen}"),
        "--public-origin",
        &format!("https://localhost:{listen}"),
        "--bootstrap-token-file",
        "/secrets/bootstrap",
        "--tls-cert-file",
        "/secrets/tls-cert.pem",
        "--tls-key-file",
        "/secrets/tls-key.pem",
        "--mqtt-host",
        "localhost",
        "--mqtt-port",
        &broker.to_string(),
        "--mqtt-tls",
        "--mqtt-ca-file",
        "/secrets/tls-cert.pem",
        "--topic-base",
        base,
    ]);
    docker::Container(name)
}
async fn health(dut: &docker::Container) {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if docker::output(&[
                "exec",
                "--user",
                "1000:1000",
                &dut.0,
                "/ha-wolf-manager",
                "healthcheck",
            ])
            .status
            .success()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("native exec health marker must become ready");
}
fn protected_state(root: &Path) -> String {
    let mount = docker::mount(&root.join("data"), "/data", true);
    docker::checked(&[
        "run",
        "--rm",
        "--network",
        "none",
        "--user",
        "0:0",
        "--entrypoint",
        "sh",
        "-v",
        &mount,
        BROKER,
        "-c",
        "test \"$(stat -c '%u:%g:%a' /data)\" = '1000:1000:700' && test \"$(stat -c '%u:%g:%a' /data/keys/candidate-pc/id_ed25519)\" = '1000:1000:600' && test \"$(stat -c '%u:%g:%a' /data/manager.sqlite3)\" = '1000:1000:600' && sha256sum /data/keys/candidate-pc/id_ed25519 /data/instance-id",
    ])
}
async fn stop(dut: &docker::Container, observer: &mqtt::Observer, gate: Option<&ssh::Gate>) {
    observer.messages.lock().unwrap().clear();
    docker::checked(&["kill", "--signal", "TERM", &dut.0]);
    observer.wait("/availability", b"offline").await;
    if let Some(gate) = gate {
        assert_eq!(
            docker::checked(&["inspect", "--format", "{{.State.Running}}", &dut.0]),
            "true",
            "SIGTERM must drain the already admitted SSH operation"
        );
        gate.hold.store(false, std::sync::atomic::Ordering::Release);
        gate.release.notify_waiters();
    }
    docker::wait_exit(dut).await;
    let log_output = docker::output(&["logs", &dut.0]);
    assert!(log_output.status.success());
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&log_output.stdout),
        String::from_utf8_lossy(&log_output.stderr)
    );
    assert!(
        logs.contains("MQTT offline acknowledgements drained and disconnect sent"),
        "offline LWT alone does not prove graceful MQTT acknowledgment drain"
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires exact disposable native image via WOLF_TEST_SCRATCH_IMAGE and Docker"]
async fn exact_scratch_native_tls_ssh_mqtt_state_health_and_sigterm() {
    let reference =
        std::env::var("WOLF_TEST_SCRATCH_IMAGE").expect("explicit exact candidate image required");
    let image = docker::checked(&["image", "inspect", "--format", "{{.Id}}", &reference]);
    let arch = docker::checked(&["image", "inspect", "--format", "{{.Architecture}}", &image]);
    let expected = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => panic!("unsupported native fixture architecture {other}"),
    };
    assert_eq!(
        arch, expected,
        "emulated candidate execution is not native evidence"
    );
    let temp = match std::env::var("WOLF_TEST_SCRATCH_ROOT") {
        Ok(path) => {
            fs::create_dir_all(&path).unwrap();
            tempfile::Builder::new()
                .prefix("scratch-runtime-")
                .tempdir_in(path)
                .unwrap()
        }
        Err(_) => tempfile::Builder::new()
            .prefix("scratch-runtime-")
            .tempdir()
            .unwrap(),
    };
    let files = Files(temp);
    let root = files.0.path();
    fs::set_permissions(root, fs::Permissions::from_mode(0o711)).unwrap();
    fs::create_dir(root.join("data")).unwrap();
    fs::create_dir(root.join("secrets")).unwrap();
    fs::set_permissions(root.join("secrets"), fs::Permissions::from_mode(0o755)).unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let cert = fixture.join("tls-cert.pem");
    write(
        &root.join("secrets/tls-cert.pem"),
        &fs::read(&cert).unwrap(),
        0o444,
    );
    write(
        &root.join("secrets/tls-key.pem"),
        &fs::read(fixture.join("tls-key.pem")).unwrap(),
        0o400,
    );
    let bootstrap_token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let password = uuid::Uuid::new_v4().to_string();
    write(
        &root.join("secrets/bootstrap"),
        bootstrap_token.as_bytes(),
        0o400,
    );
    let broker_port = port();
    let listen = port();
    assert_ne!(broker_port, listen);
    let config = format!(
        "listener {broker_port} 127.0.0.1\nallow_anonymous true\npersistence false\ncertfile /secrets/tls-cert.pem\nkeyfile /secrets/tls-key.pem\nlog_dest stdout\nlog_type all\n"
    );
    write(&root.join("mosquitto.conf"), config.as_bytes(), 0o444);
    let tree = docker::mount(root, "/fixture", false);
    docker::checked(&[
        "run",
        "--rm",
        "--network",
        "none",
        "--user",
        "0:0",
        "--entrypoint",
        "sh",
        "-v",
        &tree,
        BROKER,
        "-c",
        "chown -R 1000:1000 /fixture/data /fixture/secrets && chmod 700 /fixture/data",
    ]);
    let broker_name = format!("wolf-candidate-broker-{}", uuid::Uuid::new_v4());
    let secrets = docker::mount(&root.join("secrets"), "/secrets", true);
    let config_mount = docker::mount(
        &root.join("mosquitto.conf"),
        "/mosquitto/config/mosquitto.conf",
        true,
    );
    docker::checked(&[
        "run",
        "-d",
        "--name",
        &broker_name,
        "--network",
        "host",
        "--user",
        "1000:1000",
        "-v",
        &secrets,
        "-v",
        &config_mount,
        BROKER,
    ]);
    let _broker = docker::Container(broker_name);
    let base = format!("candidate/{}", uuid::Uuid::new_v4());
    let observer_ca = root.join("observer-ca.pem");
    write(&observer_ca, &fs::read(&cert).unwrap(), 0o444);
    let observer = mqtt::start(broker_port, &observer_ca, &base).await;
    let ssh = ssh::start().await;
    let dut = start_dut(&image, root, listen, broker_port, &base);
    let mut api = http::Api::new(listen, &cert);
    api.ready().await;
    api.bootstrap(&bootstrap_token, &password).await;
    health(&dut).await;
    assert!(
        reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap()
            .get(format!("{}/api/v1/system/ready", api.origin))
            .send()
            .await
            .is_err(),
        "self-signed fixture is accepted only with explicit verified trust"
    );
    let processes = docker::checked(&["top", &dut.0, "-eo", "pid,uid,gid"]);
    let identities: Vec<_> = processes
        .lines()
        .skip(1)
        .map(|line| line.split_whitespace().skip(1).collect::<Vec<_>>())
        .collect();
    assert_eq!(
        identities,
        vec![vec!["1000", "1000"]],
        "actual scratch process runs without root"
    );
    api.post("/api/v1/pcs",json!({"pc_id":"candidate-pc","display_name":"Candidate PC","ssh_host":"127.0.0.1","ssh_port":ssh.port,"ssh_user":"wolf-manager"}),StatusCode::CREATED).await;
    let public = api.get("/api/v1/pcs/candidate-pc/ssh/public-key").await["public_key"]
        .as_str()
        .unwrap()
        .to_owned();
    ssh.seen.lock().unwrap().authorized =
        Some(russh::keys::PublicKey::from_openssh(&public).unwrap());
    // Probe must return this fixture's independently generated host fingerprint.
    let probe = api
        .post(
            "/api/v1/pcs/candidate-pc/ssh/probe",
            json!({}),
            StatusCode::OK,
        )
        .await;
    assert_eq!(probe["fingerprint"], ssh.fingerprint);
    assert!(
        ssh.seen.lock().unwrap().commands.is_empty(),
        "probe cannot execute RPC"
    );
    api.post(
        "/api/v1/pcs/candidate-pc/ssh/enroll",
        json!({"probe_id":probe["probe_id"],"fingerprint":probe["fingerprint"]}),
        StatusCode::OK,
    )
    .await;
    let operation = api
        .post(
            "/api/v1/pcs/candidate-pc/ssh/test",
            json!({}),
            StatusCode::ACCEPTED,
        )
        .await;
    let operation_path = format!(
        "/api/v1/operations/{}",
        operation["operation_id"].as_str().unwrap()
    );
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if api.get(&operation_path).await["state"] == "succeeded" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    {
        let seen = ssh.seen.lock().unwrap();
        assert!(!seen.requests.is_empty());
        assert_eq!(seen.pty, 0);
        assert!(
            seen.commands
                .iter()
                .all(|command| command == b"wolf-manager-rpc-v1")
        );
    }
    observer.wait("/availability", b"online").await;
    let identity = protected_state(root);
    ssh.gate
        .hold
        .store(true, std::sync::atomic::Ordering::Release);
    let drain_operation = api
        .post(
            "/api/v1/pcs/candidate-pc/ssh/test",
            json!({}),
            StatusCode::ACCEPTED,
        )
        .await;
    let drain_path = format!(
        "/api/v1/operations/{}",
        drain_operation["operation_id"].as_str().unwrap()
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if ssh.gate.entered.load(std::sync::atomic::Ordering::Acquire) > 0
                && api.get(&drain_path).await["state"] == "running"
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("admitted SSH work did not reach held native RPC");
    stop(&dut, &observer, Some(&ssh.gate)).await;
    let data = docker::mount(&root.join("data"), "/data", false);
    assert!(
        !docker::output(&[
            "run",
            "--rm",
            "--network",
            "none",
            "--user",
            "1000:1000",
            "-v",
            &data,
            &image,
            "healthcheck"
        ])
        .status
        .success(),
        "stopped runtime must fail native healthcheck"
    );
    let restarted = start_dut(&image, root, listen, broker_port, &base);
    api.ready().await;
    health(&restarted).await;
    assert_eq!(
        api.get("/api/v1/bootstrap/status").await["initialized"],
        true
    );
    assert_eq!(
        api.get("/api/v1/auth/session").await["authenticated"],
        true,
        "session/account retained on restart"
    );
    assert_eq!(
        api.get("/api/v1/pcs").await["pcs"][0]["pc_id"],
        "candidate-pc"
    );
    assert_eq!(
        api.get("/api/v1/pcs/candidate-pc/ssh/public-key").await["public_key"],
        public
    );
    assert_eq!(
        protected_state(root),
        identity,
        "native SSH key and instance identity retained byte-for-byte"
    );
    assert_eq!(
        api.get(&drain_path).await["state"],
        "succeeded",
        "SIGTERM drained and durably completed admitted work"
    );
    stop(&restarted, &observer, None).await;
    // Driver itself does not require elevated ownership of retained runtime data.
    assert_eq!(fs::metadata(root).unwrap().mode() & 0o777, 0o711);
}
