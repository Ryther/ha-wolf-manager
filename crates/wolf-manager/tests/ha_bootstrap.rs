use ha_bootstrap::*;
use ha_wolf_manager::ha_bootstrap;
#[test]
fn supported_options_are_closed_validated_and_defaulted() {
    let options = parse_options(b"{}").unwrap();
    assert_eq!(options.topic_base, "wolf-manager/v1");
    assert_eq!(options.discovery_prefix, "homeassistant");
    assert!(parse_options(br#"{"topic_base":"unsafe/#"}"#).is_err());
    assert!(parse_options(br#"{"mqtt_password":"secret"}"#).is_err());
}
#[test]
fn conflicting_or_unreadable_secrets_are_refused() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("missing");
    assert!(secret_value(Some("value"), Some(&missing)).is_err());
    assert!(secret_value(None, Some(&missing)).is_err());
    assert_eq!(
        secret_value(Some("value"), None).unwrap().as_deref(),
        Some("value")
    );
}
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    time::Duration,
};
#[test]
fn protected_secret_files_trim_one_newline_and_reject_aliases() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("mqtt-password");
    fs::write(&path, b"fixture-password\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        secret_value(None, Some(&path)).unwrap().as_deref(),
        Some("fixture-password")
    );
    let alias = root.path().join("alias");
    symlink(&path, &alias).unwrap();
    assert!(secret_value(None, Some(&alias)).is_err());
    fs::hard_link(&path, root.path().join("hardlink")).unwrap();
    assert!(secret_value(None, Some(&path)).is_err());
}
#[tokio::test]
#[ignore = "uses port80 inside isolated container; fixed Supervisor URL resolver"]
async fn native_supervisor_get_only_bearer_bounded_response_and_failure() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 80))
        .await
        .unwrap();
    let task = tokio::spawn(async move {
        for body in [r#"{"result":"ok","data":{"addon":"core_mosquitto","host":"172.30.33.4","port":"1883","ssl":false,"username":"fixture-user","password":"fixture-password","protocol":"3.1.1"}}"#.to_string(),r#"{"result":"error","data":null}"#.to_string(),"x".repeat(65537)]{
   let (mut socket,_)=listener.accept().await.unwrap();let mut bytes=Vec::new();loop{let mut block=[0u8;1024];let n=socket.read(&mut block).await.unwrap();assert!(n>0);bytes.extend_from_slice(&block[..n]);assert!(bytes.len()<16384);if bytes.windows(4).any(|w|w==b"\r\n\r\n"){break;}}
   let request=String::from_utf8(bytes).unwrap();assert!(request.starts_with("GET /services/mqtt HTTP/1.1\r\n"));assert!(request.to_ascii_lowercase().contains("authorization: bearer fixture-token-only\r\n"));
   let response=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body);socket.write_all(response.as_bytes()).await.unwrap();
  }
    });
    let client = SupervisorClient::client_builder()
        .unwrap()
        .timeout(Duration::from_secs(3))
        .resolve("supervisor", (std::net::Ipv4Addr::LOCALHOST, 80).into())
        .build()
        .unwrap();
    let supervisor = SupervisorClient::with_client(client, "fixture-token-only".into()).unwrap();
    let service = supervisor.mqtt().await.unwrap();
    assert_eq!(service.host, "172.30.33.4");
    assert_eq!(service.port, 1883);
    assert_eq!(service.username.as_deref(), Some("fixture-user"));
    assert!(!service.tls);
    assert!(supervisor.mqtt().await.is_err());
    assert!(supervisor.mqtt().await.is_err());
    task.await.unwrap();
}
