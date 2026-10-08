use wolf_core::{AppId, CatalogAttributes, CatalogManifest, PcId, Topics, steam_cover_url};
use wolf_manager_host::{catalog::Snapshot, catalog_mqtt::plan};
#[test]
fn owned_publication_manifest_precedes_tombstones() {
    let pc = PcId::new("pc-one").unwrap();
    let app = AppId::new("12").unwrap();
    let old = AppId::new("13").unwrap();
    let topics = Topics::new("wolf-manager/v1", "homeassistant").unwrap();
    let snap = Snapshot {
        manifest: CatalogManifest {
            version: 1,
            pc_id: pc.clone(),
            catalog_generation: 1,
            app_ids: vec![app.clone()],
            observed_at_ms: 1,
            complete: true,
        },
        attributes: vec![CatalogAttributes {
            version: 1,
            pc_id: pc.clone(),
            app_id: app.clone(),
            name: "Game".into(),
            cover_url: steam_cover_url(&app),
            library_id: "main".into(),
            catalog_generation: 1,
            observed_at_ms: 1,
        }],
    };
    let plan = plan(&topics, "My PC", &snap, std::slice::from_ref(&old)).unwrap();
    let manifest = plan
        .iter()
        .position(|p| p.topic == topics.catalog_manifest(&pc))
        .unwrap();
    assert!(
        plan[..manifest]
            .iter()
            .any(|p| p.topic == topics.catalog_attributes(&pc, &app))
    );
    assert!(
        plan[manifest + 1..]
            .iter()
            .any(|p| p.topic == topics.game_discovery(&pc, &old) && p.payload.is_empty())
    );
    assert!(
        plan.iter()
            .all(|p| !p.topic.contains("/service/") && !p.topic.contains("/manager/"))
    );
}
#[tokio::test]
async fn actual_wire_acknowledgements_gate_completion() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use wolf_manager_host::catalog_mqtt::{BrokerConfig, Publisher};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let broker = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut seen = Vec::new();
        loop {
            let mut header = [0u8; 1];
            if stream.read_exact(&mut header).await.is_err() {
                break;
            }
            let mut len = 0;
            let mut scale = 1;
            loop {
                let b = stream.read_u8().await.unwrap();
                len += (b as usize & 127) * scale;
                if b & 128 == 0 {
                    break;
                }
                scale *= 128;
            }
            let mut payload = vec![0; len];
            stream.read_exact(&mut payload).await.unwrap();
            match header[0] >> 4 {
                1 => stream.write_all(&[0x20, 2, 0, 0]).await.unwrap(),
                3 => {
                    assert_eq!(header[0] & 7, 3);
                    let size = u16::from_be_bytes([payload[0], payload[1]]) as usize;
                    let topic = String::from_utf8(payload[2..2 + size].to_vec()).unwrap();
                    seen.push(topic);
                    let id = &payload[2 + size..4 + size];
                    stream.write_all(&[0x40, 2, id[0], id[1]]).await.unwrap();
                }
                12 => stream.write_all(&[0xd0, 0]).await.unwrap(),
                _ => {}
            }
        }
        seen
    });
    let config = BrokerConfig {
        host: "127.0.0.1".into(),
        port,
        client_id: "test-host".into(),
        username_file: None,
        password_file: None,
        tls: false,
        pc_name: "PC".into(),
        topic_base: "wolf-manager/v1".into(),
        discovery_prefix: "homeassistant".into(),
    };
    let pc = PcId::new("pc-one").unwrap();
    let snap = Snapshot {
        manifest: CatalogManifest {
            version: 1,
            pc_id: pc.clone(),
            catalog_generation: 1,
            app_ids: vec![],
            observed_at_ms: 1,
            complete: true,
        },
        attributes: vec![],
    };
    let mut publisher = Publisher::connect(&config, &pc).await.unwrap();
    publisher
        .publish_snapshot(&snap, &[AppId::new("13").unwrap()])
        .await
        .unwrap();
    drop(publisher);
    let seen = broker.await.unwrap();
    let manifest = seen
        .iter()
        .position(|t| t.ends_with("catalog/manifest"))
        .unwrap();
    assert!(
        seen[manifest + 1..]
            .iter()
            .any(|t| t.ends_with("game_13/config"))
    );
}
#[tokio::test]
async fn missing_ack_never_advances_to_manifest() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use wolf_manager_host::catalog_mqtt::{BrokerConfig, Publisher};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut header = [0; 1];
        s.read_exact(&mut header).await.unwrap();
        let mut len = 0;
        let mut scale = 1;
        loop {
            let b = s.read_u8().await.unwrap();
            len += (b as usize & 127) * scale;
            if b & 128 == 0 {
                break;
            }
            scale *= 128;
        }
        let mut bytes = vec![0; len];
        s.read_exact(&mut bytes).await.unwrap();
        s.write_all(&[0x20, 2, 0, 0]).await.unwrap();
        s.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 0x33);
        let len = s.read_u8().await.unwrap() as usize;
        let mut packet = vec![0; len];
        s.read_exact(&mut packet).await.unwrap();
        let n = u16::from_be_bytes([packet[0], packet[1]]) as usize;
        assert!(
            std::str::from_utf8(&packet[2..2 + n])
                .unwrap()
                .ends_with("host/availability")
        );
        drop(s);
    });
    let config = BrokerConfig {
        host: "127.0.0.1".into(),
        port,
        client_id: "test-refuse".into(),
        username_file: None,
        password_file: None,
        tls: false,
        pc_name: "PC".into(),
        topic_base: "wolf-manager/v1".into(),
        discovery_prefix: "homeassistant".into(),
    };
    assert!(
        Publisher::connect(&config, &PcId::new("pc-one").unwrap())
            .await
            .is_err()
    );
    server.await.unwrap();
}
