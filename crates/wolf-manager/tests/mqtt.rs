use ha_wolf_manager::mqtt;
use mqtt::CatalogBuffer;
use wolf_core::*;
fn pc() -> PcId {
    PcId::new("gaming-pc").unwrap()
}
fn attribute(id: &str, generation: u64) -> CatalogAttributes {
    let app = AppId::new(id).unwrap();
    CatalogAttributes {
        version: 1,
        pc_id: pc(),
        app_id: app.clone(),
        name: format!("Game {id}"),
        cover_url: steam_cover_url(&app),
        library_id: "library-main".into(),
        catalog_generation: generation,
        observed_at_ms: 100,
    }
}
fn manifest(ids: &[&str], generation: u64) -> CatalogManifest {
    CatalogManifest {
        version: 1,
        pc_id: pc(),
        catalog_generation: generation,
        app_ids: ids.iter().map(|id| AppId::new(*id).unwrap()).collect(),
        observed_at_ms: 100,
        complete: true,
    }
}
#[test]
fn arbitrary_retained_order_requires_every_attribute_before_projection() {
    let mut buffer = CatalogBuffer::new(vec![pc()]);
    assert!(
        buffer
            .manifest(manifest(&["1", "2"], 1), 0)
            .unwrap()
            .is_none()
    );
    assert!(buffer.attributes(attribute("2", 1), 1).unwrap().is_none());
    let complete = buffer.attributes(attribute("1", 1), 2).unwrap().unwrap();
    assert_eq!(complete.1.len(), 2);
    assert_eq!(complete.1[0].app_id.as_str(), "1");
}
#[test]
fn lower_and_conflicting_equal_generations_are_refused() {
    let mut buffer = CatalogBuffer::new(vec![pc()]);
    buffer.attributes(attribute("1", 2), 0).unwrap();
    assert!(buffer.manifest(manifest(&["1"], 2), 1).unwrap().is_some());
    assert!(buffer.manifest(manifest(&[], 1), 2).is_err());
    assert!(buffer.manifest(manifest(&[], 2), 3).is_err());
}
#[test]
fn unknown_pc_and_inconsistent_catalog_identity_are_refused() {
    let mut buffer = CatalogBuffer::new(vec![pc()]);
    let mut other = attribute("1", 1);
    other.pc_id = PcId::new("foreign-pc").unwrap();
    assert!(buffer.attributes(other, 0).is_err());
    let mut bad = attribute("1", 1);
    bad.cover_url = "https://example.invalid/unsafe".into();
    assert!(buffer.attributes(bad, 0).is_err());
}

#[test]
fn expiry_preserves_committed_generation_and_complete_empty_is_explicit() {
    let mut buffer = CatalogBuffer::new(vec![pc()]);
    buffer.attributes(attribute("1", 1), 0).unwrap();
    buffer.manifest(manifest(&["1"], 1), 1).unwrap();
    buffer.manifest(manifest(&["1", "2"], 2), 2).unwrap();
    buffer.attributes(attribute("1", 2), 3).unwrap();
    buffer.expire_incomplete(70000);
    assert!(
        buffer
            .attributes(attribute("2", 2), 70001)
            .unwrap()
            .is_none()
    );
    assert!(buffer.manifest(manifest(&[], 1), 70002).is_err());
    let complete = buffer.manifest(manifest(&[], 3), 70003).unwrap().unwrap();
    assert!(complete.1.is_empty());
}
#[test]
fn seeded_projection_rejects_stale_and_changed_equal_generation() {
    let mut buffer = CatalogBuffer::new(vec![pc()]);
    buffer
        .seed(manifest(&["1"], 2), vec![attribute("1", 2)])
        .unwrap();
    assert!(buffer.manifest(manifest(&[], 1), 0).is_err());
    let mut changed = attribute("1", 2);
    changed.name = "Changed".into();
    buffer.attributes(changed, 1).unwrap();
    assert!(buffer.manifest(manifest(&["1"], 2), 2).is_err());
}
use ha_wolf_manager::mqtt::{BrokerConfig, ManagerEvent, ManagerMqtt, Registration};
use rumqttc::v5::{
    AsyncClient, Event, MqttOptions,
    mqttbytes::{QoS, v5::Packet},
};
use std::time::Duration;
struct Peer {
    client: AsyncClient,
    events: tokio::sync::mpsc::Receiver<Event>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn peer(host: &str, port: u16, base: &str) -> Peer {
    let mut options = MqttOptions::new(format!("wolf-test-{}", uuid::Uuid::new_v4()), host, port);
    options
        .set_clean_start(true)
        .set_session_expiry_interval(Some(0));
    let (client, mut eventloop) = AsyncClient::new(options, 32);
    client
        .subscribe(format!("{base}/#"), QoS::AtLeastOnce)
        .await
        .unwrap();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1024);
    let task = tokio::spawn(async move {
        while let Ok(event) = eventloop.poll().await {
            if sender.try_send(event).is_err() {
                break;
            }
        }
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(event) = receiver.recv().await {
            if matches!(event, Event::Incoming(Packet::SubAck(_))) {
                break;
            }
        }
    })
    .await
    .unwrap();
    Peer {
        client,
        events: receiver,
        task,
    }
}
async fn publish(peer: &mut Peer, topic: String, payload: Vec<u8>, retain: bool) {
    peer.client
        .publish(topic, QoS::AtLeastOnce, retain, payload)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(event) = peer.events.recv().await {
            if matches!(event, Event::Incoming(Packet::PubAck(_))) {
                return;
            }
        }
        panic!("publisher stopped before acknowledgement");
    })
    .await
    .unwrap();
}
async fn ready(manager: &mut ManagerMqtt) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if matches!(manager.poll().await.unwrap(), Some(ManagerEvent::Connected)) {
                break;
            }
        }
    })
    .await
    .unwrap();
    assert!(manager.controls_ready());
}
#[tokio::test]
#[ignore = "requires disposable MQTT5 broker via WOLF_TEST_MQTT_HOST/PORT"]
async fn broker_v5_retained_rejection_complete_catalog_registration_and_shutdown() {
    let host = std::env::var("WOLF_TEST_MQTT_HOST").expect("explicit disposable broker host");
    let port = std::env::var("WOLF_TEST_MQTT_PORT")
        .unwrap()
        .parse()
        .unwrap();
    let base = format!("wolf-test/{}", uuid::Uuid::new_v4());
    let topics = Topics::new(&base, &format!("{base}/discovery")).unwrap();
    let instance = uuid::Uuid::new_v4();
    let mut observer = peer(&host, port, &base).await;
    publish(
        &mut observer,
        topics.service_command(&pc()),
        b"ON".to_vec(),
        true,
    )
    .await;
    let config = BrokerConfig {
        host,
        port,
        username: None,
        password: None,
        tls: false,
    };
    let mut manager = ManagerMqtt::new(
        config.clone(),
        topics.clone(),
        instance,
        vec![Registration {
            pc_id: pc(),
            display_name: "Gaming PC".into(),
        }],
    )
    .unwrap();
    ready(&mut manager).await;
    // Both retained initial delivery and live retained publish must be refused.
    publish(
        &mut observer,
        topics.service_command(&pc()),
        b"ON".to_vec(),
        true,
    )
    .await;
    publish(
        &mut observer,
        topics.service_command(&pc()),
        b"RESTART".to_vec(),
        false,
    )
    .await;
    publish(
        &mut observer,
        topics.service_command(&pc()),
        b" OFF".to_vec(),
        false,
    )
    .await;
    publish(
        &mut observer,
        topics.service_command(&pc()),
        b"OFF".to_vec(),
        false,
    )
    .await;
    let mut commands = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(ManagerEvent::Command { pc_id, command }) = manager.poll().await.unwrap() {
                assert_eq!(pc_id, pc());
                commands.push(command);
                if command == ServiceCommand::Off {
                    break;
                }
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(commands, vec![ServiceCommand::Off]);
    publish(
        &mut observer,
        topics.catalog_manifest(&pc()),
        serde_json::to_vec(&manifest(&["1", "2"], 1)).unwrap(),
        true,
    )
    .await;
    publish(
        &mut observer,
        topics.catalog_attributes(&pc(), &AppId::new("2").unwrap()),
        serde_json::to_vec(&attribute("2", 1)).unwrap(),
        true,
    )
    .await;
    publish(
        &mut observer,
        topics.catalog_attributes(&pc(), &AppId::new("1").unwrap()),
        serde_json::to_vec(&attribute("1", 1)).unwrap(),
        true,
    )
    .await;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(ManagerEvent::CatalogReady {
                manifest,
                attributes,
            }) = manager.poll().await.unwrap()
            {
                assert_eq!(manifest.catalog_generation, 1);
                assert_eq!(attributes.len(), 2);
                break;
            }
        }
    })
    .await
    .unwrap();
    // Add a PC without restarting transport; its exact command scope becomes available after SUBACK.
    let added = PcId::new("second-pc").unwrap();
    manager
        .sync_registrations(vec![
            Registration {
                pc_id: pc(),
                display_name: "Gaming PC".into(),
            },
            Registration {
                pc_id: added.clone(),
                display_name: "Second PC".into(),
            },
        ])
        .unwrap();
    ready(&mut manager).await;
    publish(
        &mut observer,
        topics.service_command(&added),
        b"ON".to_vec(),
        false,
    )
    .await;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(ManagerEvent::Command { pc_id, command }) = manager.poll().await.unwrap() {
                assert_eq!(pc_id, added);
                assert_eq!(command, ServiceCommand::On);
                break;
            }
        }
    })
    .await
    .unwrap();
    manager
        .sync_registrations(vec![Registration {
            pc_id: pc(),
            display_name: "Gaming PC".into(),
        }])
        .unwrap();
    ready(&mut manager).await;
    manager.shutdown().await.unwrap();
    assert!(!manager.controls_ready());
    let offline = topics.manager_availability(instance);
    tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(event) = observer.events.recv().await {
            if let Event::Incoming(Packet::Publish(p)) = event
                && p.topic.as_ref() == offline.as_bytes()
                && p.payload.as_ref() == b"offline"
            {
                return;
            }
        }
        panic!("missing offline projection");
    })
    .await
    .unwrap();
    // Same durable manager identity gets clean session; retained ON cannot replay after restart.
    let mut restarted = ManagerMqtt::new(
        config,
        topics.clone(),
        instance,
        vec![Registration {
            pc_id: pc(),
            display_name: "Gaming PC".into(),
        }],
    )
    .unwrap();
    ready(&mut restarted).await;
    publish(
        &mut observer,
        topics.service_command(&pc()),
        b"OFF".to_vec(),
        false,
    )
    .await;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(ManagerEvent::Command { command, .. }) = restarted.poll().await.unwrap() {
                assert_eq!(command, ServiceCommand::Off);
                break;
            }
        }
    })
    .await
    .unwrap();
    restarted.shutdown().await.unwrap();
}
#[test]
fn full_catalog_can_advance_and_pending_entry_limit_is_enforced() {
    let attributes: Vec<_> = (1..=10000)
        .map(|id| attribute(&id.to_string(), 1))
        .collect();
    let mut ids: Vec<_> = attributes.iter().map(|a| a.app_id.clone()).collect();
    ids.sort();
    let mut full = manifest(&[], 1);
    full.app_ids = ids;
    let mut buffer = CatalogBuffer::new(vec![pc()]);
    buffer.seed(full.clone(), attributes).unwrap();
    for id in 1..=10000 {
        assert!(
            buffer
                .attributes(attribute(&id.to_string(), 2), id)
                .unwrap()
                .is_none()
        );
    }
    assert!(buffer.attributes(attribute("10001", 2), 10001).is_err());
    full.catalog_generation = 2;
    assert_eq!(
        buffer.manifest(full, 10002).unwrap().unwrap().1.len(),
        10000
    );
}
#[tokio::test]
#[ignore = "requires disposable MQTT5 broker via WOLF_TEST_MQTT_HOST/PORT"]
async fn broker_shutdown_flushes_archived_discovery_under_queue_backpressure() {
    let host = std::env::var("WOLF_TEST_MQTT_HOST").unwrap();
    let port = std::env::var("WOLF_TEST_MQTT_PORT")
        .unwrap()
        .parse()
        .unwrap();
    let base = format!("wolf-test/{}", uuid::Uuid::new_v4());
    let topics = Topics::new(&base, &format!("{base}/discovery")).unwrap();
    let mut observer = peer(&host, port, &base).await;
    let registrations: Vec<_> = (1..=80)
        .map(|id| Registration {
            pc_id: PcId::new(format!("pc-{id}")).unwrap(),
            display_name: format!("PC {id}"),
        })
        .collect();
    let archived = registrations.last().unwrap().pc_id.clone();
    let mut manager = ManagerMqtt::new(
        BrokerConfig {
            host,
            port,
            username: None,
            password: None,
            tls: false,
        },
        topics.clone(),
        uuid::Uuid::new_v4(),
        registrations.clone(),
    )
    .unwrap();
    ready(&mut manager).await;
    manager
        .sync_registrations(registrations[..79].to_vec())
        .unwrap();
    ready(&mut manager).await;
    manager.shutdown().await.unwrap();
    let tombstone = topics.switch_discovery(&archived);
    tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(event) = observer.events.recv().await {
            if let Event::Incoming(Packet::Publish(p)) = event
                && p.topic.as_ref() == tombstone.as_bytes()
                && p.payload.is_empty()
            {
                return;
            }
        }
        panic!("observer stopped before archive tombstone");
    })
    .await
    .expect("shutdown dropped archive cleanup queued behind discovery replay");
}
#[test]
fn durable_seed_accepts_valid_arbitrary_entry_order() {
    let mut buffer = CatalogBuffer::new(vec![pc()]);
    buffer
        .seed(
            manifest(&["1", "2"], 1),
            vec![attribute("2", 1), attribute("1", 1)],
        )
        .unwrap();
    buffer.attributes(attribute("1", 1), 0).unwrap();
    buffer.attributes(attribute("2", 1), 1).unwrap();
    assert!(
        buffer
            .manifest(manifest(&["1", "2"], 1), 2)
            .unwrap()
            .is_none()
    );
}
#[tokio::test]
#[ignore = "requires disposable MQTT5 broker via WOLF_TEST_MQTT_HOST/PORT"]
async fn broker_restart_replays_durable_archived_scope_cleanup() {
    let host = std::env::var("WOLF_TEST_MQTT_HOST").unwrap();
    let port = std::env::var("WOLF_TEST_MQTT_PORT")
        .unwrap()
        .parse()
        .unwrap();
    let base = format!("wolf-test/{}", uuid::Uuid::new_v4());
    let topics = Topics::new(&base, &format!("{base}/discovery")).unwrap();
    let mut observer = peer(&host, port, &base).await;
    let archived = PcId::new("archived-pc").unwrap();
    publish(
        &mut observer,
        topics.switch_discovery(&archived),
        b"obsolete discovery".to_vec(),
        true,
    )
    .await;
    publish(
        &mut observer,
        topics.service_availability(&archived),
        b"online".to_vec(),
        true,
    )
    .await;
    let mut manager = ManagerMqtt::new(
        BrokerConfig {
            host,
            port,
            username: None,
            password: None,
            tls: false,
        },
        topics.clone(),
        uuid::Uuid::new_v4(),
        vec![Registration {
            pc_id: pc(),
            display_name: "Gaming PC".into(),
        }],
    )
    .unwrap();
    manager.seed_archived_pcs(vec![archived.clone()]).unwrap();
    ready(&mut manager).await;
    manager.shutdown().await.unwrap();
    let tombstone = topics.switch_discovery(&archived);
    let offline = topics.service_availability(&archived);
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut saw_config = false;
        let mut saw_offline = false;
        while let Some(event) = observer.events.recv().await {
            if let Event::Incoming(Packet::Publish(p)) = event {
                saw_config |= p.topic.as_ref() == tombstone.as_bytes() && p.payload.is_empty();
                saw_offline |=
                    p.topic.as_ref() == offline.as_bytes() && p.payload.as_ref() == b"offline";
                if saw_config && saw_offline {
                    return;
                }
            }
        }
        panic!("observer stopped before archive replay");
    })
    .await
    .expect("restart forgot durable archive cleanup");
}

#[tokio::test]
#[ignore = "requires disposable MQTT5 broker via WOLF_TEST_MQTT_HOST/PORT"]
async fn broker_retains_confirmed_compose_down_off_state_and_control_availability() {
    let host = std::env::var("WOLF_TEST_MQTT_HOST").expect("explicit disposable broker host");
    let port = std::env::var("WOLF_TEST_MQTT_PORT")
        .unwrap()
        .parse()
        .unwrap();
    let base = format!("wolf-test/{}", uuid::Uuid::new_v4());
    let topics = Topics::new(&base, &format!("{base}/discovery")).unwrap();
    let mut observer = peer(&host, port, &base).await;
    let mut manager = ManagerMqtt::new(
        BrokerConfig {
            host: host.clone(),
            port,
            username: None,
            password: None,
            tls: false,
        },
        topics.clone(),
        uuid::Uuid::new_v4(),
        vec![Registration {
            pc_id: pc(),
            display_name: "Stopped PC".into(),
        }],
    )
    .unwrap();
    ready(&mut manager).await;
    manager
        .observe_service(
            &pc(),
            &HostStatus {
                systemd_state: "inactive".into(),
                container_state: "missing".into(),
                restart_count: 0,
                exit_code: None,
                staged_revision: None,
                running_revision: None,
                recovery_pending: false,
            },
            100,
            None,
        )
        .unwrap();
    let state_topic = topics.service_state(&pc());
    let availability_topic = topics.service_availability(&pc());
    tokio::time::timeout(Duration::from_secs(3),async {
        let (mut off,mut available)=(false,false);
        while !(off && available) {
            tokio::select! {
                event=manager.poll()=>{event.unwrap();},
                event=observer.events.recv()=>{
                    if let Some(Event::Incoming(Packet::Publish(p)))=event {
                        off|=p.topic.as_ref()==state_topic.as_bytes() && p.payload.as_ref()==b"OFF";
                        available|=p.topic.as_ref()==availability_topic.as_bytes() && p.payload.as_ref()==b"online";
                    }
                }
            }
        }
    }).await.unwrap();
    // A fresh HA subscription must recover both values from broker retention,
    // without a new host command or a new service observation.
    let mut restarted_ha = peer(&host, port, &base).await;
    tokio::time::timeout(Duration::from_secs(3), async {
        let (mut off, mut available) = (false, false);
        while !(off && available) {
            match restarted_ha.events.recv().await {
                Some(Event::Incoming(Packet::Publish(p)))
                    if p.topic.as_ref() == state_topic.as_bytes() =>
                {
                    assert!(p.retain);
                    assert_eq!(p.payload.as_ref(), b"OFF");
                    off = true;
                }
                Some(Event::Incoming(Packet::Publish(p)))
                    if p.topic.as_ref() == availability_topic.as_bytes() =>
                {
                    assert!(p.retain);
                    assert_eq!(p.payload.as_ref(), b"online");
                    available = true;
                }
                Some(_) => {}
                None => panic!("fresh observer disconnected"),
            }
        }
    })
    .await
    .unwrap();
}
