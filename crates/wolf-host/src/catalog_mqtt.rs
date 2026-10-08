//! Host-only MQTT v3 catalog publication. Every retained QoS1 packet is acknowledged
//! before the next packet; complete manifest precedes owned-entity tombstones.
use crate::catalog::Snapshot;
use rumqttc::{
    AsyncClient, Event, EventLoop, Incoming, LastWill, MqttOptions, Outgoing, QoS, Transport,
};
use std::{io, path::PathBuf, time::Duration};
use wolf_core::{AppId, PcId, Topics};
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerConfig {
    pub host: String,
    pub port: u16,
    pub client_id: String,
    pub username_file: Option<PathBuf>,
    pub password_file: Option<PathBuf>,
    pub tls: bool,
    pub pc_name: String,
    pub topic_base: String,
    pub discovery_prefix: String,
}
#[derive(Clone, Debug)]
pub struct Publication {
    pub topic: String,
    pub payload: Vec<u8>,
}
fn invalid() -> io::Error {
    io::Error::other("catalog broker or publication invalid")
}
pub fn plan(
    topics: &Topics,
    pc_name: &str,
    snapshot: &Snapshot,
    previous: &[AppId],
) -> io::Result<Vec<Publication>> {
    wolf_core::validate_catalog_generation(
        &snapshot.manifest.pc_id,
        &snapshot.manifest,
        &snapshot.attributes,
        None,
    )
    .map_err(|_| invalid())?;
    if previous.len() > 10000 || pc_name.is_empty() || pc_name.len() > 256 {
        return Err(invalid());
    }
    let pc = &snapshot.manifest.pc_id;
    let mut publications = Vec::new();
    for a in &snapshot.attributes {
        publications.push(Publication {
            topic: topics.catalog_state(pc, &a.app_id),
            payload: b"installed".to_vec(),
        });
        publications.push(Publication {
            topic: topics.catalog_attributes(pc, &a.app_id),
            payload: serde_json::to_vec(a)?,
        });
        publications.push(Publication {
            topic: topics.game_discovery(pc, &a.app_id),
            payload: serde_json::to_vec(
                &topics.game_discovery_payload(pc, &a.app_id, pc_name, &a.name),
            )?,
        });
    }
    publications.push(Publication {
        topic: topics.catalog_manifest(pc),
        payload: serde_json::to_vec(&snapshot.manifest)?,
    });
    let current: std::collections::BTreeSet<_> = snapshot.manifest.app_ids.iter().collect();
    let previous: std::collections::BTreeSet<_> = previous.iter().collect();
    for app in previous {
        if !current.contains(app) {
            for topic in [
                topics.game_discovery(pc, app),
                topics.catalog_state(pc, app),
                topics.catalog_attributes(pc, app),
            ] {
                publications.push(Publication {
                    topic,
                    payload: vec![],
                });
            }
        }
    }
    Ok(publications)
}
fn secret(path: &std::path::Path) -> io::Result<String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || m.mode() & 0o777 != 0o600
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.len() > 4096
    {
        return Err(invalid());
    }
    let mut value = String::new();
    Read::by_ref(&mut f).take(4097).read_to_string(&mut value)?;
    let value = value.trim_end_matches(['\r', '\n']);
    if value.is_empty() || value.len() > 4096 || value.contains('\0') {
        return Err(invalid());
    }
    Ok(value.into())
}
pub struct Publisher {
    client: AsyncClient,
    event_loop: EventLoop,
    topics: Topics,
    pc: PcId,
    pc_name: String,
}
impl Publisher {
    pub async fn connect(config: &BrokerConfig, pc: &PcId) -> io::Result<Self> {
        if config.host.is_empty()
            || config.port == 0
            || config.client_id.is_empty()
            || config.client_id.len() > 128
            || config.pc_name.is_empty()
            || config.pc_name.len() > 256
        {
            return Err(invalid());
        }
        let topics =
            Topics::new(&config.topic_base, &config.discovery_prefix).map_err(|_| invalid())?;
        let mut options = MqttOptions::new(&config.client_id, &config.host, config.port);
        options
            .set_clean_session(true)
            .set_keep_alive(Duration::from_secs(20))
            .set_max_packet_size(2 * 1024 * 1024, 2 * 1024 * 1024)
            .set_last_will(LastWill::new(
                topics.host_availability(pc),
                "offline",
                QoS::AtLeastOnce,
                true,
            ));
        if config.tls {
            let _ = rustls::crypto::ring::default_provider().install_default();
            options.set_transport(Transport::tls_with_default_config());
        }
        match (&config.username_file, &config.password_file) {
            (Some(u), Some(p)) => {
                options.set_credentials(secret(u)?, secret(p)?);
            }
            (None, None) => {}
            _ => return Err(invalid()),
        }
        let (client, event_loop) = AsyncClient::new(options, 4);
        let mut publisher = Self {
            client,
            event_loop,
            topics,
            pc: pc.clone(),
            pc_name: config.pc_name.clone(),
        };
        publisher
            .publish_ack(Publication {
                topic: publisher.topics.host_availability(pc),
                payload: b"online".to_vec(),
            })
            .await?;
        Ok(publisher)
    }
    async fn publish_ack(&mut self, message: Publication) -> io::Result<()> {
        self.client
            .try_publish(message.topic, QoS::AtLeastOnce, true, message.payload)
            .map_err(|_| invalid())?;
        tokio::time::timeout(Duration::from_secs(15), async {
            let mut packet = None;
            loop {
                match self.event_loop.poll().await.map_err(|_| invalid())? {
                    Event::Outgoing(Outgoing::Publish(id)) => {
                        if packet.is_some() {
                            return Err(invalid());
                        }
                        packet = Some(id)
                    }
                    Event::Incoming(Incoming::PubAck(ack)) => {
                        if Some(ack.pkid) != packet {
                            return Err(invalid());
                        }
                        return Ok(());
                    }
                    Event::Incoming(Incoming::ConnAck(ack))
                        if ack.code != rumqttc::ConnectReturnCode::Success =>
                    {
                        return Err(invalid());
                    }
                    _ => {}
                }
            }
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "catalog broker acknowledgment timeout",
            )
        })?
    }
    pub async fn publish_snapshot(
        &mut self,
        snapshot: &Snapshot,
        previous: &[AppId],
    ) -> io::Result<()> {
        if snapshot.manifest.pc_id != self.pc {
            return Err(invalid());
        }
        for message in plan(&self.topics, &self.pc_name, snapshot, previous)? {
            self.publish_ack(message).await?
        }
        Ok(())
    }
    /// Keep the event loop moving between scans. Errors must cause a fresh connection
    /// and full snapshot replay, never continued use of uncertain in-flight packets.
    pub async fn idle(&mut self, duration: Duration) -> io::Result<()> {
        let end = tokio::time::Instant::now() + duration;
        loop {
            match tokio::time::timeout_at(end, self.event_loop.poll()).await {
                Ok(Ok(_)) => {}
                Ok(Err(_)) => return Err(invalid()),
                Err(_) => return Ok(()),
            }
        }
    }
}
