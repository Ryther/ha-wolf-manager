//! Real process tests over private HTTP sockets and protected temporary state.
use ha_wolf_manager::{api::now, domain::PcInput, store::Store};
use reqwest::{Client, Method, StatusCode};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};
use tempfile::{TempDir, tempdir};
use wolf_core::PcId;

const ORIGIN: &str = "https://example.test";
fn protected(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn command(data: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_ha-wolf-manager"));
    for (name, _) in
        std::env::vars().filter(|(name, _)| name.starts_with("WOLF_") || name == "SUPERVISOR_TOKEN")
    {
        c.env_remove(name);
    }
    c.args(["--data"]).arg(data);
    c
}
trait BoundedCommand {
    fn bounded_status(&mut self) -> ExitStatus;
}
impl BoundedCommand for Command {
    fn bounded_status(&mut self) -> ExitStatus {
        struct Guard(Child);
        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut guard = Guard(self.spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = guard.0.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "CLI fixture exceeded its process deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
struct Process {
    child: Child,
    fixture: TempDir,
    base: String,
    client: Client,
    topic: String,
    token: String,
    password: String,
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Process {
    async fn start(mqtt: Option<(&str, u16)>) -> Self {
        assert!(
            !rustix::process::geteuid().is_root(),
            "run process fixtures as the disposable development user"
        );
        let _ = rustls::crypto::ring::default_provider().install_default();
        let fixture = tempdir().unwrap();
        let token = format!("fixture-{}-{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let password = uuid::Uuid::new_v4().to_string();
        protected(&fixture.path().join("token"), token.as_bytes());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let mut c = command(&fixture.path().join("data"));
        let topic = format!("fixture-{}", uuid::Uuid::new_v4());
        c.args([
            "--mode",
            "standalone",
            "--listen",
            &address.to_string(),
            "--public-origin",
            ORIGIN,
            "--trusted-proxy",
            "127.0.0.1",
            "--bootstrap-token-file",
        ])
        .arg(fixture.path().join("token"));
        if let Some((host, port)) = mqtt {
            c.args([
                "--mqtt-host",
                host,
                "--mqtt-port",
                &port.to_string(),
                "--topic-base",
                &topic,
            ]);
        } else {
            c.arg("--mqtt-disabled");
        }
        c.stdout(Stdio::from(
            fs::File::create(fixture.path().join("stdout")).unwrap(),
        ));
        c.stderr(Stdio::from(
            fs::File::create(fixture.path().join("stderr")).unwrap(),
        ));
        let child = c.spawn().unwrap();
        let client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let mut process = Self {
            child,
            fixture,
            base: format!("http://{address}"),
            client,
            topic,
            token,
            password,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if process
                .client
                .get(format!("{}/api/v1/system/health", process.base))
                .send()
                .await
                .is_ok()
            {
                break;
            }
            assert!(
                process.child.try_wait().unwrap().is_none(),
                "manager exited before HTTP admission"
            );
            assert!(
                Instant::now() < deadline,
                "manager startup exceeded fixture deadline"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        process
    }
    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Value,
        cookie: &str,
        csrf: &str,
    ) -> reqwest::Response {
        self.client
            .request(method, format!("{}/api/v1/{path}", self.base))
            .header("origin", ORIGIN)
            .header("cookie", cookie)
            .header("x-wolf-csrf", csrf)
            .json(&body)
            .send()
            .await
            .unwrap()
    }
    async fn bootstrap(&self) -> (String, String) {
        let challenge: Value = self
            .client
            .get(format!(
                "{}/api/v1/auth/login-challenge?purpose=bootstrap",
                self.base
            ))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let token = challenge["challenge"].as_str().unwrap();
        let response = self
            .client
            .post(format!("{}/api/v1/bootstrap", self.base))
            .header("origin", ORIGIN)
            .header("x-wolf-csrf", token)
            .bearer_auth(&self.token)
            .json(&json!({"password":self.password,"challenge":token}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let body: Value = response.json().await.unwrap();
        (cookie, body["csrf_token"].as_str().unwrap().to_owned())
    }
    async fn stop(&mut self) {
        assert!(
            Command::new("kill")
                .args(["-TERM", &self.child.id().to_string()])
                .bounded_status()
                .success()
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "graceful shutdown failed");
                break;
            }
            assert!(
                Instant::now() < deadline,
                "shutdown exceeded fixture deadline"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

#[tokio::test]
async fn live_process_authenticated_configuration_archive_and_offline_recovery() {
    let mut process = Process::start(None).await;
    assert_eq!(
        process
            .request(Method::GET, "pcs", json!({}), "", "")
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let (cookie, csrf) = process.bootstrap().await;
    let pc = json!({"pc_id":"fixture-pc","display_name":"Fixture PC","ssh_host":"127.0.0.1","ssh_port":9,"ssh_user":"wolf-manager"});
    assert_eq!(
        process
            .request(Method::POST, "pcs", pc.clone(), &cookie, "wrong-csrf")
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        process
            .request(Method::POST, "pcs", pc, &cookie, &csrf)
            .await
            .status(),
        StatusCode::CREATED
    );
    let pcs: Value = process
        .request(Method::GET, "pcs", json!({}), &cookie, &csrf)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(pcs["pcs"].as_array().unwrap().len(), 1);
    let def = json!({"label":"Fixture option","launch_options":"FIXTURE=1 %command%","description":"Synthetic process fixture"});
    assert_eq!(
        process
            .request(Method::PUT, "parameters/fixture", def, &cookie, &csrf)
            .await
            .status(),
        StatusCode::OK
    );
    let params: Value = process
        .request(Method::GET, "parameters", json!({}), &cookie, &csrf)
        .await
        .json()
        .await
        .unwrap();
    assert!(params["parameters"].get("fixture").is_some());
    assert_eq!(
        process
            .request(
                Method::PUT,
                "settings/debug",
                json!({"test_ball":true}),
                &cookie,
                &csrf
            )
            .await
            .status(),
        StatusCode::OK
    );
    let settings: Value = process
        .request(
            Method::GET,
            "pcs/fixture-pc/settings",
            json!({}),
            &cookie,
            &csrf,
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(settings["settings"]["debug"]["test_ball"], true);
    for path in ["pcs/fixture-pc/status", "pcs/fixture-pc/games"] {
        assert_eq!(
            process
                .request(Method::GET, path, json!({}), &cookie, &csrf)
                .await
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    let history: Value = process
        .request(
            Method::GET,
            "pcs/fixture-pc/operations?limit=1",
            json!({}),
            &cookie,
            &csrf,
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(history["operations"], json!([]));
    for path in [
        "pcs/fixture-pc/operations?bad=1",
        "pcs/fixture-pc/operations?limit=no",
        "pcs/fixture-pc/operations?cursor=bad",
        "pcs/fixture-pc/logs?bad=1",
        "pcs/fixture-pc/logs?lines=no",
    ] {
        assert!(
            !process
                .request(Method::GET, path, json!({}), &cookie, &csrf)
                .await
                .status()
                .is_success()
        );
    }
    assert_eq!(
        process
            .request(
                Method::GET,
                "pcs/fixture-pc/ssh/public-key",
                json!({}),
                &cookie,
                &csrf
            )
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        process
            .request(
                Method::POST,
                "pcs/fixture-pc/ssh/probe",
                json!({}),
                &cookie,
                &csrf
            )
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert!(
        !process
            .request(
                Method::POST,
                "pcs/fixture-pc/ssh/enroll",
                json!({"probe_id":uuid::Uuid::new_v4(),"fingerprint":"SHA256:untrusted"}),
                &cookie,
                &csrf
            )
            .await
            .status()
            .is_success()
    );
    for (path, body) in [
        (
            "pcs/fixture-pc/service/start",
            json!({"expected_desired_revision":settings["desired_revision"]}),
        ),
        (
            "pcs/fixture-pc/service/restart",
            json!({"expected_desired_revision":settings["desired_revision"]}),
        ),
        (
            "pcs/fixture-pc/apply",
            json!({"expected_desired_revision":settings["desired_revision"]}),
        ),
        ("pcs/fixture-pc/service/stop", json!({})),
        ("pcs/fixture-pc/ssh/test", json!({})),
    ] {
        let response = process
            .request(Method::POST, path, body, &cookie, &csrf)
            .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let admitted: Value = response.json().await.unwrap();
        let id = admitted["operation_id"].as_str().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let observed: Value = process
                .request(
                    Method::GET,
                    &format!("operations/{id}"),
                    json!({}),
                    &cookie,
                    &csrf,
                )
                .await
                .json()
                .await
                .unwrap();
            if observed["state"] == "rejected" {
                assert_eq!(observed["sanitized_result"]["code"], "not_dispatched");
                break;
            }
            assert!(
                Instant::now() < deadline,
                "unenrolled local operation failed to reach a durable refusal: {observed}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            !process
                .request(
                    Method::POST,
                    &format!("operations/{id}/reconcile"),
                    json!({}),
                    &cookie,
                    &csrf
                )
                .await
                .status()
                .is_success()
        );
    }
    assert_eq!(process.request(Method::PATCH,"pcs/fixture-pc",json!({"display_name":"Renamed fixture","ssh_host":"127.0.0.1","ssh_port":10,"ssh_user":"wolf-manager"}),&cookie,&csrf).await.status(),StatusCode::OK);
    assert_eq!(
        process
            .request(
                Method::DELETE,
                "parameters/fixture",
                json!({}),
                &cookie,
                &csrf
            )
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        process
            .request(Method::DELETE, "pcs/fixture-pc", json!({}), &cookie, &csrf)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    let pcs: Value = process
        .request(Method::GET, "pcs", json!({}), &cookie, &csrf)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(pcs["pcs"], json!([]));
    process.stop().await;
    let data = process.fixture.path().join("data");
    let archive = process.fixture.path().join("backup");
    assert!(
        command(&data)
            .arg("backup")
            .arg("--destination")
            .arg(&archive)
            .bounded_status()
            .success()
    );
    assert!(
        command(&data)
            .arg("restore-preview")
            .arg("--bundle")
            .arg(&archive)
            .bounded_status()
            .success()
    );
    let restore = process.fixture.path().join("restored");
    assert!(
        command(&restore)
            .arg("restore")
            .arg("--bundle")
            .arg(&archive)
            .bounded_status()
            .success()
    );
    assert!(restore.join("manager.sqlite3").is_file());
    let password = process.fixture.path().join("password");
    protected(&password, uuid::Uuid::new_v4().to_string().as_bytes());
    assert!(
        command(&data)
            .arg("reset-password")
            .arg("--password-file")
            .arg(password)
            .bounded_status()
            .success()
    );
    assert!(!command(&data).arg("healthcheck").bounded_status().success());
}

#[tokio::test]
#[ignore = "requires the documented disposable loopback broker on port18889"]
async fn live_broker_runtime_becomes_ready_and_drains_on_sigterm() {
    let host = std::env::var("WOLF_TEST_MQTT_HOST").expect("use disposable broker opt-in");
    assert_eq!(host, "127.0.0.1");
    let port = std::env::var("WOLF_TEST_MQTT_PORT")
        .unwrap()
        .parse::<u16>()
        .unwrap();
    assert_eq!(port, 18889);
    let mut process = Process::start(Some((&host, port))).await;
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        let response = process
            .request(Method::GET, "system/ready", json!({}), "", "")
            .await;
        if response.status() == StatusCode::OK {
            let body: Value = response.json().await.unwrap();
            assert_eq!(body["mqtt_enabled"], true);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "private broker runtime failed to become ready"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (cookie, csrf) = process.bootstrap().await;
    assert_eq!(process.request(Method::POST,"pcs",json!({"pc_id":"broker-pc","display_name":"Broker fixture","ssh_host":"127.0.0.1","ssh_port":9,"ssh_user":"wolf-manager"}),&cookie,&csrf).await.status(),StatusCode::CREATED);
    use rumqttc::v5::{AsyncClient, MqttOptions, mqttbytes::QoS};
    use wolf_core::{AppId, CatalogAttributes, CatalogManifest, Topics, steam_cover_url};
    let options = MqttOptions::new(
        format!("process-observer-{}", uuid::Uuid::new_v4()),
        &host,
        port,
    );
    let (publisher, mut events) = AsyncClient::new(options, 32);
    let peer = tokio::spawn(async move { while events.poll().await.is_ok() {} });
    let topics = Topics::new(&process.topic, "homeassistant").unwrap();
    let pc = PcId::new("broker-pc").unwrap();
    // Registration is reconciled by the runtime's five-second snapshot, without restart.
    tokio::time::sleep(Duration::from_secs(6)).await;
    let app = AppId::new("480").unwrap();
    let observed = now();
    let attributes = CatalogAttributes {
        version: 1,
        pc_id: pc.clone(),
        app_id: app.clone(),
        name: "Synthetic game".into(),
        cover_url: steam_cover_url(&app),
        library_id: "fixture-library".into(),
        catalog_generation: 1,
        observed_at_ms: observed,
    };
    let manifest = CatalogManifest {
        version: 1,
        pc_id: pc.clone(),
        catalog_generation: 1,
        app_ids: vec![app.clone()],
        observed_at_ms: observed,
        complete: true,
    };
    publisher
        .publish(
            topics.host_availability(&pc),
            QoS::AtLeastOnce,
            false,
            "online",
        )
        .await
        .unwrap();
    publisher
        .publish(
            topics.catalog_manifest(&pc),
            QoS::AtLeastOnce,
            false,
            serde_json::to_vec(&manifest).unwrap(),
        )
        .await
        .unwrap();
    publisher
        .publish(
            topics.catalog_attributes(&pc, &app),
            QoS::AtLeastOnce,
            false,
            serde_json::to_vec(&attributes).unwrap(),
        )
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let response = process
            .request(
                Method::GET,
                "pcs/broker-pc/games",
                json!({}),
                &cookie,
                &csrf,
            )
            .await;
        if response.status() == StatusCode::OK {
            let body: Value = response.json().await.unwrap();
            assert_eq!(body["games"][0]["app_id"], "480");
            assert_eq!(body["availability"], "online");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "runtime did not commit complete live catalog"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    for command in ["ON", "OFF"] {
        publisher
            .publish(
                topics.service_command(&pc),
                QoS::AtLeastOnce,
                false,
                command,
            )
            .await
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let body: Value = process
                .request(
                    Method::GET,
                    "pcs/broker-pc/operations",
                    json!({}),
                    &cookie,
                    &csrf,
                )
                .await
                .json()
                .await
                .unwrap();
            let expected = if command == "ON" { "start" } else { "stop" };
            if body["operations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|o| o["kind"] == expected && o["state"] == "rejected")
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "broker command failed to record controlled refusal"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
    publisher
        .publish(topics.ha_birth(), QoS::AtLeastOnce, false, "online")
        .await
        .unwrap();
    publisher
        .publish(
            topics.host_availability(&pc),
            QoS::AtLeastOnce,
            false,
            "offline",
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(6)).await;
    let body: Value = process
        .request(
            Method::GET,
            "pcs/broker-pc/games",
            json!({}),
            &cookie,
            &csrf,
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(body["availability"], "offline");
    assert_eq!(body["games"].as_array().unwrap().len(), 1);
    assert_eq!(
        process
            .request(Method::DELETE, "pcs/broker-pc", json!({}), &cookie, &csrf)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    tokio::time::sleep(Duration::from_secs(6)).await;
    peer.abort();
    let _ = peer.await;
    process.stop().await;
    assert!(
        !command(&process.fixture.path().join("data"))
            .arg("healthcheck")
            .bounded_status()
            .success()
    );
}

#[test]
fn offline_import_cli_preserves_input_and_refuses_stale_revision() {
    assert!(!rustix::process::geteuid().is_root());
    let fixture = tempdir().unwrap();
    let data = fixture.path().join("data");
    let pc = PcId::new("import-pc").unwrap();
    let revision;
    {
        let mut store = Store::open(&data, now()).unwrap();
        store
            .add_pc(
                PcInput {
                    pc_id: pc.clone(),
                    display_name: "Import fixture".into(),
                    ssh_host: "127.0.0.1".into(),
                    ssh_port: 9,
                    ssh_user: "wolf-manager".into(),
                },
                now(),
            )
            .unwrap();
        revision = store.settings(&pc).unwrap().revision().unwrap();
    }
    let source = fixture.path().join("legacy.json");
    let bytes = br#"{"debug":{"test_ball":true}}"#;
    protected(&source, bytes);
    assert!(
        command(&data)
            .arg("import-preview")
            .arg("--source")
            .arg(&source)
            .args(["--format-version", "1"])
            .bounded_status()
            .success()
    );
    assert!(
        command(&data)
            .arg("import-legacy")
            .arg("--source")
            .arg(&source)
            .args([
                "--format-version",
                "1",
                "--pc",
                "import-pc",
                "--expected-revision",
                revision.as_str()
            ])
            .bounded_status()
            .success()
    );
    assert!(
        !command(&data)
            .arg("import-legacy")
            .arg("--source")
            .arg(&source)
            .args([
                "--format-version",
                "1",
                "--pc",
                "import-pc",
                "--expected-revision",
                revision.as_str()
            ])
            .bounded_status()
            .success()
    );
    assert_eq!(fs::read(source).unwrap(), bytes);
    assert!(
        Store::open(&data, now())
            .unwrap()
            .settings(&pc)
            .unwrap()
            .debug
            .test_ball
    );
}

#[tokio::test]
#[ignore = "requires a fresh disposable root container with the native-validator sentinel and no /data mount"]
async fn root_addon_startup_preserves_existing_state_and_admits_only_fresh_options() {
    use std::os::unix::fs::MetadataExt;
    assert!(rustix::process::geteuid().is_root());
    assert_eq!(
        fs::read("/run/wolf-native-validator-fixture").unwrap(),
        b"disposable-container"
    );
    let data = Path::new("/data");
    assert!(
        !data.exists(),
        "fixture requires an empty container-owned /data path"
    );
    fs::create_dir(data).unwrap();
    fs::set_permissions(data, fs::Permissions::from_mode(0o700)).unwrap();
    protected(&data.join("options.json"), b"{}");
    let retained = data.join("manager.sqlite3");
    fs::write(&retained, b"retained synthetic state").unwrap();
    let mut refused = command(data);
    refused.args(["--listen", "127.0.0.1:0"]);
    // Existing state must not be admitted or recursively reassigned by startup.
    assert!(!refused.bounded_status().success());
    assert_eq!(fs::read(&retained).unwrap(), b"retained synthetic state");
    assert_eq!(fs::metadata(data).unwrap().uid(), 0);
    fs::remove_file(retained).unwrap();
    let options = data.join("options.json");
    protected(&options, b"{}");
    let fixture = tempdir().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut admitted = command(data);
    admitted.args(["--listen", &address.to_string()]);
    admitted.stdout(Stdio::from(
        fs::File::create(fixture.path().join("stdout")).unwrap(),
    ));
    admitted.stderr(Stdio::from(
        fs::File::create(fixture.path().join("stderr")).unwrap(),
    ));
    let child = admitted.spawn().unwrap();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let mut process = Process {
        child,
        fixture,
        base: format!("http://{address}"),
        client,
        topic: String::new(),
        token: uuid::Uuid::new_v4().to_string(),
        password: uuid::Uuid::new_v4().to_string(),
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if data.join("manager.sqlite3").is_file() {
            break;
        }
        assert!(
            process.child.try_wait().unwrap().is_none(),
            "root startup failed after fresh volume admission"
        );
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let metadata = fs::metadata(data).unwrap();
    assert_eq!(
        (metadata.uid(), metadata.gid(), metadata.mode() & 0o777),
        (1000, 1000, 0o700)
    );
    assert_eq!(fs::metadata(&options).unwrap().uid(), 0);
    assert_eq!(fs::read(&options).unwrap(), b"{}");
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if tokio::net::TcpStream::connect(address).await.is_ok() {
            break;
        }
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        process
            .client
            .get(format!("{}/api/v1/system/health", process.base))
            .send()
            .await
            .is_err(),
        "loopback must not bypass the actual ingress connection boundary"
    );
    process.stop().await;
    // Only this sentinel-guarded disposable container's fixture was created above.
    fs::remove_dir_all(data).unwrap();
}
