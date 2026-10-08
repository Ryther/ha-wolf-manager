use ha_wolf_manager::{
    api::{AppState, Deployment, router},
    auth::{BootstrapSecret, TransportPolicy},
    runtime::{client_tls, serve_connection, server_tls},
    store::Store,
};
use std::{fs, os::unix::fs::PermissionsExt, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn native_tls_withheld_unauthenticated_body_is_bounded_and_next_request_works() {
    let fixture = tempfile::tempdir().unwrap();
    let data = fixture.path().join("data");
    let key = fixture.path().join("key.pem");
    let cert = fixture.path().join("cert.pem");
    let token = fixture.path().join("bootstrap-token");
    fs::write(&key, include_bytes!("fixtures/tls-key.pem")).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&cert, include_bytes!("fixtures/tls-cert.pem")).unwrap();
    fs::write(&token, b"synthetic-bootstrap-token-256bits!").unwrap();
    fs::set_permissions(&token, fs::Permissions::from_mode(0o400)).unwrap();
    let state = AppState::new(
        Store::open(&data, 0).unwrap(),
        data,
        Deployment::Standalone {
            origin: "https://localhost".into(),
            bootstrap: BootstrapSecret::read(&token).unwrap(),
        },
        TransportPolicy::NativeTls,
    );
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls(&cert, &key).unwrap()));
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (stream, peer) = listener.accept().await.unwrap();
            let app = app.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(serve_connection(app, stream, peer, Some(acceptor)));
        }
    });
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls(Some(&cert)).unwrap()));
    let connect = || async {
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        connector
            .connect(
                rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                stream,
            )
            .await
            .unwrap()
    };
    let mut stalled = connect().await;
    stalled.write_all(b"POST /api/v1/auth/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 64\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(11), stalled.read_to_end(&mut response))
        .await
        .expect("unauthenticated body collection must have a deadline")
        .unwrap();
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 503"), "{response}");
    assert!(response.contains("\"code\":\"host_unavailable\""));
    let mut normal = connect().await;
    normal
        .write_all(
            b"GET /api/v1/system/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), normal.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    server.await.unwrap();
}
