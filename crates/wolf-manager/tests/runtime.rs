use ha_wolf_manager::{api::now, health::healthcheck, store::Store};
use tempfile::tempdir;
#[test]
fn private_exec_healthcheck_requires_live_identity_and_fresh_marker() {
    let t = tempdir().unwrap();
    let root = t.path().join("data");
    let store = Store::open(&root, 0).unwrap();
    assert!(healthcheck(&root).is_err());
    store.heartbeat(now()).unwrap();
    assert!(healthcheck(&root).is_ok());
    store.heartbeat(now() - 60_000).unwrap();
    assert!(healthcheck(&root).is_err());
}
#[test]
fn configuration_refuses_http_credentials_or_implicit_proxy() {
    use clap::Parser;
    use ha_wolf_manager::runtime::Cli;
    for args in [
        vec![
            "ha-wolf-manager",
            "--mode",
            "standalone",
            "--public-origin",
            "http://example.test",
            "--bootstrap-token-file",
            "/data/token",
        ],
        vec![
            "ha-wolf-manager",
            "--mode",
            "standalone",
            "--public-origin",
            "https://example.test",
            "--bootstrap-token-file",
            "/data/token",
        ],
        vec![
            "ha-wolf-manager",
            "--mode",
            "ingress",
            "--trusted-proxy",
            "127.0.0.1",
        ],
    ] {
        assert!(Cli::try_parse_from(args).unwrap().validate().is_err());
    }
}
#[tokio::test]
async fn native_tls_serves_embedded_assets_and_refuses_plaintext() {
    use ha_wolf_manager::{
        api::{AppState, Deployment, router},
        auth::{BootstrapSecret, TransportPolicy},
        runtime::{client_tls, server_tls},
    };
    use std::{fs, os::unix::fs::PermissionsExt, sync::Arc};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let t = tempdir().unwrap();
    let root = t.path().join("data");
    let key = t.path().join("tls-key.pem");
    let cert = t.path().join("tls-cert.pem");
    fs::write(&key, include_bytes!("fixtures/tls-key.pem")).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&cert, include_bytes!("fixtures/tls-cert.pem")).unwrap();
    let secret = t.path().join("token");
    fs::write(&secret, b"synthetic-bootstrap-token-256bits!").unwrap();
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o400)).unwrap();
    let state = AppState::new(
        Store::open(&root, 0).unwrap(),
        root,
        Deployment::Standalone {
            origin: "https://localhost".into(),
            bootstrap: BootstrapSecret::read(&secret).unwrap(),
        },
        TransportPolicy::NativeTls,
    );
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls(&cert, &key).unwrap()));
    let task = tokio::spawn(async move {
        for _ in 0..2 {
            let (stream, peer) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let app = app.clone();
            tokio::spawn(async move {
                ha_wolf_manager::runtime::serve_connection(app, stream, peer, Some(acceptor)).await;
            });
        }
    });
    let mut plain = tokio::net::TcpStream::connect(address).await.unwrap();
    plain
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut bytes = Vec::new();
    let _ = plain.read_to_end(&mut bytes).await;
    assert!(!bytes.windows(7).any(|v| v == b"HTTP/1."));
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls(Some(&cert)).unwrap()));
    let stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let mut tls = connector
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            stream,
        )
        .await
        .unwrap();
    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    let html = String::from_utf8(response).unwrap();
    assert!(html.starts_with("HTTP/1.1 200"));
    assert!(html.contains("content=\"standalone\""));
    task.await.unwrap();
}
#[tokio::test]
async fn real_startup_bootstrap_required_passes_exec_healthcheck() {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let t = tempdir().unwrap();
    let root = t.path().join("data");
    let secret = t.path().join("token");
    fs::write(&secret, b"synthetic-bootstrap-token-256bits!").unwrap();
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o400)).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let binary = env!("CARGO_BIN_EXE_ha-wolf-manager");
    let mut child = Command::new(binary)
        .args([
            "--mode",
            "standalone",
            "--mqtt-disabled",
            "--public-origin",
            "https://localhost",
            "--trusted-proxy",
            "127.0.0.1",
            "--listen",
            &address.to_string(),
            "--data",
            root.to_str().unwrap(),
            "--bootstrap-token-file",
            secret.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(ha_wolf_manager::runtime::client_tls(None).unwrap())
        .no_proxy()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut ready = false;
    while Instant::now() < deadline {
        if let Ok(response) = client
            .get(format!("http://{address}/api/v1/system/ready"))
            .send()
            .await
            && response.status().is_success()
        {
            let body = response.json::<serde_json::Value>().await.unwrap();
            assert_eq!(body["bootstrap_required"], true);
            if Command::new(binary)
                .args(["--data", root.to_str().unwrap(), "healthcheck"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
            {
                ready = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(ready);
    assert!(healthcheck(&root).is_err());
}
