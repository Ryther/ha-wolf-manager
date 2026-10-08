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
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
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
    if previous.len() > 20000 || pc_name.is_empty() || pc_name.len() > 256 {
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
pub(crate) fn protected_file(
    path: &std::path::Path,
    uid: u32,
    modes: &[u32],
    max: u64,
) -> io::Result<std::fs::File> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(invalid());
    }
    let mut ancestor = PathBuf::from("/");
    for component in path.parent().ok_or_else(invalid)?.components() {
        if let std::path::Component::Normal(part) = component {
            ancestor.push(part);
        }
        let fd = rustix::fs::openat2(
            rustix::fs::CWD,
            &ancestor,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        )?;
        let m = std::fs::File::from(fd).metadata()?;
        let sticky_root = m.uid() == 0 && m.mode() & 0o1000 != 0;
        if ![0, uid].contains(&m.uid()) || (m.mode() & 0o022 != 0 && !sticky_root) {
            return Err(invalid());
        }
    }
    let f = std::fs::File::from(rustix::fs::openat2(
        rustix::fs::CWD,
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    )?);
    let m = f.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || ![0, uid].contains(&m.uid())
        || !modes.contains(&(m.mode() & 0o7777))
        || m.len() > max
    {
        return Err(invalid());
    }
    Ok(f)
}
fn secret(path: &std::path::Path) -> io::Result<String> {
    use std::{io::Read, os::unix::fs::MetadataExt};
    let file = protected_file(path, rustix::process::geteuid().as_raw(), &[0o600], 4096)?;
    if file.metadata()?.uid() != rustix::process::geteuid().as_raw() {
        return Err(invalid());
    }
    let mut value = String::new();
    file.take(4097).read_to_string(&mut value)?;
    let value = value.strip_suffix('\n').unwrap_or(&value);
    if value.is_empty() || value.len() > 4096 || value.contains(['\0', '\r', '\n']) {
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
    birth: bool,
    pending: bool,
    packet: Option<u16>,
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
            options.set_transport(Transport::tls_with_config(tls_config(config)?.into()));
        } else if config.ca_file.is_some() {
            return Err(invalid());
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
            birth: false,
            pending: false,
            packet: None,
        };
        publisher
            .publish_ack(Publication {
                topic: publisher.topics.host_availability(pc),
                payload: b"online".to_vec(),
            })
            .await?;
        publisher.subscribe_birth().await?;
        Ok(publisher)
    }
    fn observe(&mut self, event: &Event) {
        if let Event::Incoming(Incoming::Publish(p)) = event
            && p.topic == self.topics.ha_birth()
            && p.payload.as_ref() == b"online"
        {
            self.birth = true;
        }
    }
    pub fn take_birth(&mut self) -> bool {
        std::mem::take(&mut self.birth)
    }
    async fn subscribe_birth(&mut self) -> io::Result<()> {
        self.client
            .try_subscribe(self.topics.ha_birth(), QoS::AtMostOnce)
            .map_err(|_| invalid())?;
        tokio::time::timeout(Duration::from_secs(15), async {
            let mut packet = None;
            loop {
                let event = self.event_loop.poll().await.map_err(|_| invalid())?;
                self.observe(&event);
                match event {
                    Event::Outgoing(Outgoing::Subscribe(id)) => packet = Some(id),
                    Event::Incoming(Incoming::SubAck(ack)) => {
                        if Some(ack.pkid) != packet
                            || ack.return_codes
                                != vec![rumqttc::SubscribeReasonCode::Success(QoS::AtMostOnce)]
                        {
                            return Err(invalid());
                        }
                        return Ok(());
                    }
                    _ => {}
                }
            }
        })
        .await
        .map_err(|_| invalid())?
    }
    async fn publish_ack(&mut self, message: Publication) -> io::Result<()> {
        self.client
            .try_publish(message.topic, QoS::AtLeastOnce, true, message.payload)
            .map_err(|_| invalid())?;
        self.pending = true;
        self.drain_ack().await
    }
    async fn drain_ack(&mut self) -> io::Result<()> {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let event = self.event_loop.poll().await.map_err(|_| invalid())?;
                self.observe(&event);
                match event {
                    Event::Outgoing(Outgoing::Publish(id)) => {
                        if self.packet.is_some() {
                            return Err(invalid());
                        }
                        self.packet = Some(id)
                    }
                    Event::Incoming(Incoming::PubAck(ack)) => {
                        if Some(ack.pkid) != self.packet {
                            return Err(invalid());
                        }
                        self.pending = false;
                        self.packet = None;
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
                Ok(Ok(event)) => {
                    self.observe(&event);
                    if self.birth {
                        return Ok(());
                    }
                }
                Ok(Err(_)) => return Err(invalid()),
                Err(_) => return Ok(()),
            }
        }
    }
}

pub fn tls_config(config: &BrokerConfig) -> io::Result<rustls::ClientConfig> {
    use std::io::{BufReader, Read};
    let mut roots =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = &config.ca_file {
        let file = protected_file(
            path,
            rustix::process::geteuid().as_raw(),
            &[0o400, 0o600, 0o644],
            1024 * 1024,
        )?;
        let mut bytes = Vec::new();
        file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 1024 * 1024 {
            return Err(invalid());
        }
        let certs = rustls_pemfile::certs(&mut BufReader::new(bytes.as_slice()))
            .collect::<Result<Vec<_>, _>>()?;
        if certs.is_empty() {
            return Err(invalid());
        }
        for cert in certs {
            roots.add(cert).map_err(|_| invalid())?;
        }
    }
    Ok(
        rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| invalid())?
        .with_root_certificates(roots)
        .with_no_client_auth(),
    )
}

impl Publisher {
    pub async fn publish_catalog(&mut self, snapshot: &Snapshot) -> io::Result<()> {
        self.publish_snapshot(snapshot, &[]).await
    }
    pub async fn tombstones(&mut self, snapshot: &Snapshot, owned: &[AppId]) -> io::Result<()> {
        if snapshot.manifest.pc_id != self.pc {
            return Err(invalid());
        }
        for message in plan(&self.topics, &self.pc_name, snapshot, owned)?
            .into_iter()
            .filter(|p| p.payload.is_empty())
        {
            self.publish_ack(message).await?;
        }
        Ok(())
    }
    pub async fn shutdown(&mut self) -> io::Result<()> {
        tokio::time::timeout(Duration::from_secs(5), async {
            if self.pending {
                self.drain_ack().await?;
            }
            self.publish_ack(Publication {
                topic: self.topics.host_availability(&self.pc),
                payload: b"offline".to_vec(),
            })
            .await?;
            self.client.try_disconnect().map_err(|_| invalid())?;
            loop {
                if matches!(
                    self.event_loop.poll().await.map_err(|_| invalid())?,
                    Event::Outgoing(Outgoing::Disconnect)
                ) {
                    return Ok(());
                }
            }
        })
        .await
        .map_err(|_| invalid())?
    }
}
