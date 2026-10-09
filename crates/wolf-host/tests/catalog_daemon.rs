use std::{fs, os::unix::fs::PermissionsExt};
use wolf_manager_host::catalog_daemon::load_broker;
#[test]
fn broker_config_is_closed_private_and_component_aliases_are_refused() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("private");
    fs::create_dir(&dir).unwrap();
    let path = dir.join("broker.json");
    fs::write(&path,r#"{"host":"localhost","port":1883,"client_id":"fixture","username_file":null,"password_file":null,"tls":false,"pc_name":"Fixture","topic_base":"wolf-manager/v1","discovery_prefix":"homeassistant"}"#).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let uid = rustix::process::geteuid().as_raw();
    assert!(load_broker(&path, uid).is_ok());
    let alias = temp.path().join("alias");
    std::os::unix::fs::symlink(&dir, &alias).unwrap();
    assert!(load_broker(&alias.join("broker.json"), uid).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load_broker(&path, uid).is_err());
}
fn policy(temp: &tempfile::TempDir) -> wolf_manager_host::policy::RootPolicy {
    let steam = temp.path().join("Steam");
    fs::create_dir_all(steam.join("steamapps/common/Game")).unwrap();
    let state = temp.path().join("state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let broker = temp.path().join("broker.json");
    fs::write(&broker,r#"{"host":"127.0.0.1","port":18889,"client_id":"daemon-fixture","username_file":null,"password_file":null,"tls":false,"pc_name":"Fixture","topic_base":"wolf-manager/daemon-test","discovery_prefix":"ha-daemon-test"}"#).unwrap();
    fs::set_permissions(&broker, fs::Permissions::from_mode(0o600)).unwrap();
    serde_json::from_value(serde_json::json!({"version":1,"pc_id":"daemon-test","steam_uid":rustix::process::geteuid().as_raw(),"steam_gid":rustix::process::getegid().as_raw(),"libraries":[{"library_id":"primary","steamapps_path":steam.join("steamapps"),"container_paths":["/home/steam/Steam/steamapps"]}],"steam_profiles":[{"root":steam,"config_vdf":"config/config.vdf","libraryfolders_vdf":["steamapps/libraryfolders.vdf"],"userdata_directory":"userdata","container_userdata_paths":["/home/steam/Steam/userdata"]}],"wolf_config":{"root":"/etc/wolf","relative_path":"config.toml","uid":0,"gid":0},"compose_file":"/etc/wolf/compose.yaml","service_unit":"wolf.service","container_name":"wolf","image_ref":"ghcr.io/games-on-whales/wolf:stable","backup_root":"/var/lib/wolf-manager/backups","state_root":"/var/lib/wolf-manager/state","catalog_state_directory":state,"broker_secret_file":broker,"pull_on_start":true,"pull_timeout_seconds":60,"proton":null,"steam_executables":["/usr/bin/steam"],"steam_runner":{"type":"docker","image":"trusted.example/steam:stable"}})).unwrap()
}
#[test]
fn daemon_admission_binds_granted_uid_libraries_and_private_broker() {
    let temp = tempfile::tempdir().unwrap();
    let mut policy = policy(&temp);
    assert!(wolf_manager_host::catalog_daemon::Daemon::from_policy(&policy).is_ok());
    policy.steam_uid += 1;
    assert!(wolf_manager_host::catalog_daemon::Daemon::from_policy(&policy).is_err());
}

#[test]
fn malformed_broker_authority_is_refused_without_modifying_secret_bytes() {
    for (field, value) in [
        ("host", serde_json::json!("")),
        ("host", serde_json::json!("reserved.invalid\nother")),
        ("port", serde_json::json!(0)),
        ("client_id", serde_json::json!("")),
        ("client_id", serde_json::json!("bad\u{0}id")),
        ("pc_name", serde_json::json!("   ")),
        ("pc_name", serde_json::json!("bad\nname")),
        ("topic_base", serde_json::json!("bad/#")),
        ("username_file", serde_json::json!("/tmp/unpaired-user")),
        ("ca_file", serde_json::json!("/tmp/unencrypted-ca")),
        ("unknown", serde_json::json!(true)),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let p = policy(&temp);
        let path = p.broker_secret_file.as_ref().unwrap();
        let mut config: serde_json::Value =
            serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        config[field] = value;
        let bytes = serde_json::to_vec(&config).unwrap();
        fs::write(path, &bytes).unwrap();
        assert!(
            load_broker(path, rustix::process::geteuid().as_raw()).is_err(),
            "accepted {field}"
        );
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}

#[test]
fn corrupt_owned_scope_or_unsafe_lock_never_replaces_recovery_evidence() {
    for malformed in [
        serde_json::json!({"version":2,"pc_id":"daemon-test","app_ids":[]}),
        serde_json::json!({"version":1,"pc_id":"other","app_ids":[]}),
        serde_json::json!({"version":1,"pc_id":"daemon-test","app_ids":["12","12"]}),
        serde_json::json!({"version":1,"pc_id":"daemon-test","app_ids":["13","12"]}),
        serde_json::json!({"version":1,"pc_id":"daemon-test","app_ids":[],"unexpected":true}),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let p = policy(&temp);
        let path = p.catalog_state_directory.join("owned.json");
        let bytes = serde_json::to_vec(&malformed).unwrap();
        fs::write(&path, &bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(wolf_manager_host::catalog_daemon::Daemon::from_policy(&p).is_err());
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
    let temp = tempfile::tempdir().unwrap();
    let p = policy(&temp);
    let lock = p.catalog_state_directory.join("daemon.lock");
    fs::write(&lock, b"retained lock bytes").unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(wolf_manager_host::catalog_daemon::Daemon::from_policy(&p).is_err());
    assert_eq!(fs::read(&lock).unwrap(), b"retained lock bytes");
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&lock, temp.path().join("alias-lock")).unwrap();
    assert!(wolf_manager_host::catalog_daemon::Daemon::from_policy(&p).is_err());
    assert_eq!(fs::read(&lock).unwrap(), b"retained lock bytes");
    fs::remove_file(temp.path().join("alias-lock")).unwrap();
    let daemon = wolf_manager_host::catalog_daemon::Daemon::from_policy(&p).unwrap();
    assert!(
        wolf_manager_host::catalog_daemon::Daemon::from_policy(&p).is_err(),
        "admitted concurrent writer"
    );
    drop(daemon);
    assert!(wolf_manager_host::catalog_daemon::Daemon::from_policy(&p).is_ok());
}

#[tokio::test]
async fn invalid_scan_intervals_refuse_and_shutdown_interrupts_connect_without_publication() {
    use std::time::Duration;
    use wolf_manager_host::catalog_daemon::Daemon;
    let temp = tempfile::tempdir().unwrap();
    let p = policy(&temp);
    for interval in [Duration::ZERO, Duration::from_secs(3601)] {
        assert!(
            Daemon::from_policy(&p)
                .unwrap()
                .serve(interval, std::future::pending())
                .await
                .is_err()
        );
        assert!(!p.catalog_state_directory.join("owned.json").exists());
        assert!(!p.catalog_state_directory.join("published.json").exists());
    }
    Daemon::from_policy(&p)
        .unwrap()
        .serve(Duration::from_secs(30), async {})
        .await
        .unwrap();
    assert!(!p.catalog_state_directory.join("owned.json").exists());
    assert!(!p.catalog_state_directory.join("published.json").exists());
}
async fn packet(stream: &mut tokio::net::TcpStream) -> std::io::Result<(u8, Vec<u8>)> {
    use tokio::io::AsyncReadExt;
    let h = stream.read_u8().await?;
    let mut len = 0usize;
    let mut scale = 1;
    loop {
        let b = stream.read_u8().await?;
        len += (b as usize & 127) * scale;
        if b & 128 == 0 {
            break;
        }
        scale *= 128;
        if scale > 128 * 128 * 128 {
            return Err(std::io::Error::other("length"));
        }
    }
    let mut body = vec![0; len];
    stream.read_exact(&mut body).await?;
    Ok((h, body))
}
#[tokio::test]
async fn crash_before_puback_preserves_owned_scope_for_restart_cleanup() {
    use tokio::{
        io::AsyncWriteExt,
        net::TcpListener,
        sync::oneshot,
        time::{Duration, timeout},
    };
    use wolf_manager_host::{catalog::load_published, catalog_daemon::Daemon};
    let temp = tempfile::tempdir().unwrap();
    let p = policy(&temp);
    let path = p.libraries[0].steamapps_path.join("appmanifest_12.acf");
    fs::write(
        &path,
        r#""AppState" { "appid" "12" "name" "Game" "installdir" "Game" "StateFlags" "4" }"#,
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let broker_file = p.broker_secret_file.as_ref().unwrap();
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(broker_file).unwrap()).unwrap();
    value["port"] = port.into();
    fs::write(broker_file, serde_json::to_vec(&value).unwrap()).unwrap();
    let (introduced_tx, introduced_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut introduced = Some(introduced_tx);
        while let Ok((header, body)) = packet(&mut stream).await {
            match header >> 4 {
                1 => stream.write_all(&[0x20, 2, 0, 0]).await.unwrap(),
                8 => stream
                    .write_all(&[0x90, 3, body[0], body[1], 0])
                    .await
                    .unwrap(),
                3 => {
                    let n = u16::from_be_bytes([body[0], body[1]]) as usize;
                    let topic = std::str::from_utf8(&body[2..2 + n]).unwrap();
                    if topic.ends_with("game_12/config") {
                        introduced.take().unwrap().send(()).unwrap();
                        break;
                    }
                    stream
                        .write_all(&[0x40, 2, body[2 + n], body[3 + n]])
                        .await
                        .unwrap();
                }
                _ => {}
            }
        }
    });
    let daemon = Daemon::from_policy(&p).unwrap();
    let (stop_tx, stop_rx) = oneshot::channel();
    let actor = tokio::spawn(daemon.serve(Duration::from_millis(100), async move {
        let _ = stop_rx.await;
    }));
    timeout(Duration::from_secs(5), introduced_rx)
        .await
        .unwrap()
        .unwrap();
    let journal: serde_json::Value =
        serde_json::from_slice(&fs::read(p.catalog_state_directory.join("owned.json")).unwrap())
            .unwrap();
    assert_eq!(journal["app_ids"], serde_json::json!(["12"]));
    assert!(!p.catalog_state_directory.join("published.json").exists());
    stop_tx.send(()).unwrap();
    timeout(Duration::from_secs(6), actor)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    server.await.unwrap();
    fs::remove_file(path).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    value["port"] = listener.local_addr().unwrap().port().into();
    fs::write(broker_file, serde_json::to_vec(&value).unwrap()).unwrap();
    let state = p.catalog_state_directory.clone();
    let (tomb_tx, tomb_rx) = oneshot::channel();
    let broker = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut tomb = Some(tomb_tx);
        while let Ok((header, body)) = packet(&mut stream).await {
            match header >> 4 {
                1 => stream.write_all(&[0x20, 2, 0, 0]).await.unwrap(),
                8 => stream
                    .write_all(&[0x90, 3, body[0], body[1], 0])
                    .await
                    .unwrap(),
                3 => {
                    let n = u16::from_be_bytes([body[0], body[1]]) as usize;
                    let topic = std::str::from_utf8(&body[2..2 + n]).unwrap();
                    if topic.ends_with("game_12/config") && body[4 + n..].is_empty() {
                        let published: serde_json::Value = serde_json::from_slice(
                            &fs::read(state.join("published.json")).unwrap(),
                        )
                        .unwrap();
                        assert_eq!(published["manifest"]["app_ids"], serde_json::json!([]));
                        if let Some(tx) = tomb.take() {
                            tx.send(()).unwrap();
                        }
                    }
                    stream
                        .write_all(&[0x40, 2, body[2 + n], body[3 + n]])
                        .await
                        .unwrap();
                }
                14 => break,
                _ => {}
            }
        }
    });
    let daemon = Daemon::from_policy(&p).unwrap();
    let (stop_tx, stop_rx) = oneshot::channel();
    let actor = tokio::spawn(daemon.serve(Duration::from_secs(30), async move {
        let _ = stop_rx.await;
    }));
    timeout(Duration::from_secs(5), tomb_rx)
        .await
        .unwrap()
        .unwrap();
    stop_tx.send(()).unwrap();
    timeout(Duration::from_secs(6), actor)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    broker.await.unwrap();
    let config = wolf_manager_host::catalog::CatalogConfig {
        pc_id: p.pc_id.clone(),
        libraries: vec![],
        state_directory: p.catalog_state_directory,
    };
    assert!(
        load_published(&config)
            .unwrap()
            .unwrap()
            .manifest
            .app_ids
            .is_empty()
    );
}
#[tokio::test]
#[ignore = "requires isolated MQTT broker on localhost18889, never a household broker"]
async fn actual_broker_birth_scan_concurrency_and_graceful_offline() {
    use fs2::FileExt;
    use rumqttc::{AsyncClient, Event, Incoming, MqttOptions, QoS};
    use tokio::{
        sync::oneshot,
        time::{Duration, timeout},
    };
    use wolf_core::{AppId, PcId, Topics};
    use wolf_manager_host::catalog_daemon::Daemon;
    let temp = tempfile::tempdir().unwrap();
    let p = policy(&temp);
    let file = p.broker_secret_file.as_ref().unwrap();
    let mut cfg: serde_json::Value = serde_json::from_slice(&fs::read(file).unwrap()).unwrap();
    let namespace = uuid::Uuid::new_v4().simple().to_string();
    cfg["client_id"] = format!("host-{namespace}").into();
    cfg["topic_base"] = format!("wolf-test/{namespace}").into();
    cfg["discovery_prefix"] = format!("ha-test-{namespace}").into();
    fs::write(file, serde_json::to_vec(&cfg).unwrap()).unwrap();
    let topics = Topics::new(
        cfg["topic_base"].as_str().unwrap(),
        cfg["discovery_prefix"].as_str().unwrap(),
    )
    .unwrap();
    let app = AppId::new("12").unwrap();
    let discovery = topics.game_discovery(&p.pc_id, &app);
    let availability = topics.host_availability(&p.pc_id);
    let manifest = topics.catalog_manifest(&p.pc_id);
    fs::write(
        p.libraries[0].steamapps_path.join("appmanifest_12.acf"),
        r#""AppState" { "appid" "12" "name" "Game" "installdir" "Game" "StateFlags" "4" }"#,
    )
    .unwrap();
    let mut options = MqttOptions::new(format!("observer-{namespace}"), "127.0.0.1", 18889);
    options.set_keep_alive(Duration::from_secs(5));
    let (client, mut events) = AsyncClient::new(options, 8);
    client
        .try_subscribe(
            format!("{}/#", cfg["topic_base"].as_str().unwrap()),
            QoS::AtLeastOnce,
        )
        .unwrap();
    client
        .try_subscribe(
            format!("{}/#", cfg["discovery_prefix"].as_str().unwrap()),
            QoS::AtLeastOnce,
        )
        .unwrap();
    timeout(Duration::from_secs(5), async {
        let mut ack = 0;
        while ack < 2 {
            if matches!(
                events.poll().await.unwrap(),
                Event::Incoming(Incoming::SubAck(_))
            ) {
                ack += 1;
            }
        }
    })
    .await
    .unwrap();
    let other = topics.game_discovery(&PcId::new("other-pc").unwrap(), &AppId::new("13").unwrap());
    client
        .try_publish(
            &other,
            QoS::AtLeastOnce,
            true,
            b"unrelated-sentinel".to_vec(),
        )
        .unwrap();
    timeout(Duration::from_secs(5), async {
        loop {
            if let Event::Incoming(Incoming::Publish(message)) = events.poll().await.unwrap()
                && message.topic == other
            {
                break;
            }
        }
    })
    .await
    .unwrap();
    let daemon = Daemon::from_policy(&p).unwrap();
    let (stop_tx, stop_rx) = oneshot::channel();
    let actor = tokio::spawn(daemon.serve(Duration::from_millis(200), async move {
        let _ = stop_rx.await;
    }));
    timeout(Duration::from_secs(5), async {
        loop {
            if let Event::Incoming(Incoming::Publish(message)) = events.poll().await.unwrap()
                && message.topic == discovery
            {
                break;
            }
        }
    })
    .await
    .unwrap();
    timeout(Duration::from_secs(5), async {
        while !p.catalog_state_directory.join("published.json").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(p.catalog_state_directory.join("catalog.lock"))
        .unwrap();
    lock.lock_exclusive().unwrap();
    // Allow the next scan worker to block on the held lock, then require HA replay.
    tokio::time::sleep(Duration::from_millis(250)).await;
    client
        .try_publish(
            topics.ha_birth(),
            QoS::AtMostOnce,
            false,
            b"online".to_vec(),
        )
        .unwrap();
    timeout(Duration::from_secs(3), async {
        loop {
            if let Event::Incoming(Incoming::Publish(message)) = events.poll().await.unwrap()
                && message.topic == discovery
            {
                break;
            }
        }
    })
    .await
    .unwrap();
    lock.unlock().unwrap();
    drop(lock);
    timeout(Duration::from_secs(5), async {
        loop {
            if let Event::Incoming(Incoming::Publish(message)) = events.poll().await.unwrap()
                && message.topic == manifest
            {
                let value: serde_json::Value = serde_json::from_slice(&message.payload).unwrap();
                if value["catalog_generation"].as_u64().unwrap() > 1 {
                    break;
                }
            }
        }
    })
    .await
    .unwrap();
    stop_tx.send(()).unwrap();
    timeout(Duration::from_secs(6), async {
        loop {
            if let Event::Incoming(Incoming::Publish(message)) = events.poll().await.unwrap()
                && message.topic == availability
                && message.payload.as_ref() == b"offline"
            {
                break;
            }
        }
    })
    .await
    .unwrap();
    timeout(Duration::from_secs(6), actor)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    client
        .try_subscribe(other.clone(), QoS::AtLeastOnce)
        .unwrap();
    timeout(Duration::from_secs(5), async {
        loop {
            if let Event::Incoming(Incoming::Publish(message)) = events.poll().await.unwrap()
                && message.topic == other
            {
                assert_eq!(message.payload.as_ref(), b"unrelated-sentinel");
                assert!(message.retain);
                break;
            }
        }
    })
    .await
    .unwrap();
}
