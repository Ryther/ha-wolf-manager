//! Native MQTT5 transport and bounded complete catalog buffering.
use rumqttc::v5::{
    AsyncClient, Event, EventLoop, MqttOptions,
    mqttbytes::{
        QoS,
        v5::{
            ConnectReturnCode, Filter, LastWill, Packet, Publish, RetainForwardRule,
            SubscribeReasonCode,
        },
    },
};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};
use wolf_core::*;
const BUFFER_BYTES: usize = 16 * 1024 * 1024;
const BUFFER_ENTRIES: usize = 10000;
const BUFFER_TTL_MS: u64 = 60000;
fn internal<T>(_: T) -> SafeError {
    SafeError::new("internal_error")
}
type Projection = (CatalogManifest, Vec<CatalogAttributes>);
fn catalog_digest(attributes: &[CatalogAttributes]) -> Result<Revision, SafeError> {
    use sha2::Digest;
    Revision::new(
        sha2::Sha256::digest(canonical_json(&attributes)?)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
}
#[derive(Default)]
struct Candidate {
    manifest: Option<CatalogManifest>,
    attributes: BTreeMap<AppId, CatalogAttributes>,
    bytes: usize,
    created_ms: u64,
}
struct Committed {
    manifest: CatalogManifest,
    digest: Revision,
    bytes: usize,
}
pub struct CatalogBuffer {
    pcs: BTreeSet<PcId>,
    pending: BTreeMap<(PcId, u64), Candidate>,
    committed: BTreeMap<PcId, Committed>,
}
impl CatalogBuffer {
    pub fn new(pcs: Vec<PcId>) -> Self {
        Self {
            pcs: pcs.into_iter().collect(),
            pending: BTreeMap::new(),
            committed: BTreeMap::new(),
        }
    }
    pub fn expire_incomplete(&mut self, now_ms: u64) {
        let _ = self.expire_with_replay(now_ms);
    }
    fn expire_with_replay(&mut self, now_ms: u64) -> Vec<PcId> {
        let expired: BTreeSet<_> = self
            .pending
            .iter()
            .filter(|(_, candidate)| now_ms.saturating_sub(candidate.created_ms) > BUFFER_TTL_MS)
            .map(|((pc, _), _)| pc.clone())
            .collect();
        self.pending
            .retain(|_, candidate| now_ms.saturating_sub(candidate.created_ms) <= BUFFER_TTL_MS);
        expired.into_iter().collect()
    }
    fn usage(&self) -> (usize, usize) {
        self.pending
            .values()
            .map(|c| (c.bytes, c.attributes.len()))
            .chain(self.committed.values().map(|c| (c.bytes, 0)))
            .fold((0, 0), |(a, b), (c, d)| {
                (a.saturating_add(c), b.saturating_add(d))
            })
    }
    fn admit(&mut self, pc: &PcId, generation: u64, now_ms: u64) -> Result<(), SafeError> {
        self.expire_incomplete(now_ms);
        if !self.pcs.contains(pc) {
            return Err(SafeError::validation());
        }
        if self
            .committed
            .get(pc)
            .is_some_and(|old| generation < old.manifest.catalog_generation)
        {
            return Err(SafeError::new("catalog_generation_conflict"));
        }
        let key = (pc.clone(), generation);
        if !self.pending.contains_key(&key)
            && self.pending.keys().filter(|(id, _)| id == pc).count() >= 4
        {
            return Err(SafeError::new("payload_too_large"));
        }
        Ok(())
    }
    /// Seed durable state before subscribing; prevents old retained generations after restart.
    pub fn seed(
        &mut self,
        manifest: CatalogManifest,
        attributes: Vec<CatalogAttributes>,
    ) -> Result<(), SafeError> {
        if !self.pcs.contains(&manifest.pc_id) {
            return Err(SafeError::validation());
        }
        let entries = validate_catalog_generation(&manifest.pc_id, &manifest, &attributes, None)?;
        let digest = catalog_digest(&entries.into_values().collect::<Vec<_>>())?;
        let bytes = canonical_json(&manifest)?.len() + 64;
        let usage = self.usage();
        if usage.0.saturating_add(bytes) > BUFFER_BYTES
            || self.committed.contains_key(&manifest.pc_id)
        {
            return Err(SafeError::new("payload_too_large"));
        }
        self.committed.insert(
            manifest.pc_id.clone(),
            Committed {
                manifest,
                digest,
                bytes,
            },
        );
        Ok(())
    }
    pub fn attributes(
        &mut self,
        attribute: CatalogAttributes,
        now_ms: u64,
    ) -> Result<Option<Projection>, SafeError> {
        attribute.validate()?;
        self.admit(&attribute.pc_id, attribute.catalog_generation, now_ms)?;
        let key = (attribute.pc_id.clone(), attribute.catalog_generation);
        let bytes = canonical_json(&attribute)?.len();
        if let Some(existing) = self
            .pending
            .get(&key)
            .and_then(|c| c.attributes.get(&attribute.app_id))
        {
            if existing != &attribute {
                return Err(SafeError::new("catalog_generation_conflict"));
            }
            return self.complete(&key);
        }
        let usage = self.usage();
        if usage.0.saturating_add(bytes) > BUFFER_BYTES || usage.1 >= BUFFER_ENTRIES {
            return Err(SafeError::new("payload_too_large"));
        }
        let candidate = self
            .pending
            .entry(key.clone())
            .or_insert_with(|| Candidate {
                created_ms: now_ms,
                ..Default::default()
            });
        candidate.bytes += bytes;
        candidate
            .attributes
            .insert(attribute.app_id.clone(), attribute);
        self.complete(&key)
    }
    pub fn manifest(
        &mut self,
        manifest: CatalogManifest,
        now_ms: u64,
    ) -> Result<Option<Projection>, SafeError> {
        manifest.validate()?;
        self.admit(&manifest.pc_id, manifest.catalog_generation, now_ms)?;
        let key = (manifest.pc_id.clone(), manifest.catalog_generation);
        if let Some(old) = self.committed.get(&manifest.pc_id)
            && old.manifest.catalog_generation == manifest.catalog_generation
            && old.manifest != manifest
        {
            return Err(SafeError::new("catalog_generation_conflict"));
        }
        if let Some(existing) = self.pending.get(&key).and_then(|c| c.manifest.as_ref()) {
            if existing != &manifest {
                return Err(SafeError::new("catalog_generation_conflict"));
            }
            return self.complete(&key);
        }
        let bytes = canonical_json(&manifest)?.len();
        if self.usage().0.saturating_add(bytes) > BUFFER_BYTES {
            return Err(SafeError::new("payload_too_large"));
        }
        let candidate = self
            .pending
            .entry(key.clone())
            .or_insert_with(|| Candidate {
                created_ms: now_ms,
                ..Default::default()
            });
        candidate.bytes += bytes;
        candidate.manifest = Some(manifest);
        self.complete(&key)
    }
    fn complete(&mut self, key: &(PcId, u64)) -> Result<Option<Projection>, SafeError> {
        let Some(candidate) = self.pending.get(key) else {
            return Ok(None);
        };
        let Some(manifest) = candidate.manifest.as_ref() else {
            return Ok(None);
        };
        if manifest
            .app_ids
            .iter()
            .any(|id| !candidate.attributes.contains_key(id))
        {
            return Ok(None);
        }
        // Extras from arbitrary retained ordering do not belong to this manifest.
        let attributes: Vec<_> = manifest
            .app_ids
            .iter()
            .filter_map(|id| candidate.attributes.get(id).cloned())
            .collect();
        validate_catalog_generation(&key.0, manifest, &attributes, None)?;
        let digest = catalog_digest(&attributes)?;
        if let Some(old) = self.committed.get(&key.0)
            && manifest.catalog_generation == old.manifest.catalog_generation
        {
            if old.manifest != *manifest || old.digest != digest {
                return Err(SafeError::new("catalog_generation_conflict"));
            }
            self.pending.remove(key);
            return Ok(None);
        }
        let manifest = manifest.clone();
        let bytes = canonical_json(&manifest)?.len() + 64;
        self.pending
            .retain(|(pc, generation), _| pc != &key.0 || generation > &key.1);
        self.committed.insert(
            key.0.clone(),
            Committed {
                manifest: manifest.clone(),
                digest,
                bytes,
            },
        );
        Ok(Some((manifest, attributes)))
    }
}
#[derive(Clone)]
pub struct BrokerConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub tls: bool,
}
impl BrokerConfig {
    pub fn validate(&self) -> Result<(), SafeError> {
        if self.host.is_empty()
            || self.host.len() > 253
            || self
                .host
                .bytes()
                .any(|c| c.is_ascii_control() || c.is_ascii_whitespace())
            || self.port == 0
            || self.username.is_some() != self.password.is_some()
            || self
                .username
                .as_ref()
                .is_some_and(|u| u.is_empty() || u.len() > 512)
            || self
                .password
                .as_ref()
                .is_some_and(|p| p.is_empty() || p.len() > 65536)
        {
            return Err(SafeError::validation());
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct Registration {
    pub pc_id: PcId,
    pub display_name: String,
}
pub enum ManagerEvent {
    Connected,
    Birth,
    Command {
        pc_id: PcId,
        command: ServiceCommand,
    },
    CatalogReady {
        manifest: CatalogManifest,
        attributes: Vec<CatalogAttributes>,
    },
    HostAvailability {
        pc_id: PcId,
        online: bool,
    },
}
struct Publication {
    topic: String,
    payload: Vec<u8>,
    retain: bool,
}
enum ControlRequest {
    Subscribe(Vec<Filter>, bool),
    Unsubscribe(String),
}
struct Observation {
    publication: Vec<(String, Vec<u8>)>,
    updated: Instant,
    available: bool,
}
pub struct ManagerMqtt {
    client: AsyncClient,
    eventloop: EventLoop,
    topics: Topics,
    instance: uuid::Uuid,
    pcs: BTreeMap<PcId, String>,
    retired_pcs: BTreeSet<PcId>,
    catalog: CatalogBuffer,
    outbox: VecDeque<Publication>,
    control_outbox: VecDeque<ControlRequest>,
    outbox_bytes: usize,
    queued_q1: u64,
    acked_q1: u64,
    closing: bool,
    connected: bool,
    controls_ready: bool,
    subscription_plan: VecDeque<(Vec<QoS>, bool)>,
    pending_subscriptions: BTreeMap<u16, (Vec<QoS>, bool)>,
    last_rejection: Option<Instant>,
    observations: BTreeMap<PcId, Observation>,
    started: Instant,
}
impl ManagerMqtt {
    pub fn new(
        config: BrokerConfig,
        topics: Topics,
        instance: uuid::Uuid,
        pcs: Vec<Registration>,
    ) -> Result<Self, SafeError> {
        Self::new_with_tls(config, topics, instance, pcs, None)
    }
    pub fn new_with_tls(
        config: BrokerConfig,
        topics: Topics,
        instance: uuid::Uuid,
        pcs: Vec<Registration>,
        custom_tls: Option<rustls::ClientConfig>,
    ) -> Result<Self, SafeError> {
        config.validate()?;
        if custom_tls.is_some() && !config.tls {
            return Err(SafeError::validation());
        }
        if instance.is_nil() || pcs.len() > 1000 {
            return Err(SafeError::validation());
        }
        let mut registered = BTreeMap::new();
        for pc in pcs {
            if pc.display_name.is_empty()
                || pc.display_name.len() > 256
                || registered.insert(pc.pc_id, pc.display_name).is_some()
            {
                return Err(SafeError::validation());
            }
        }
        let mut options = MqttOptions::new(
            format!("wolf-manager-manager-{instance}"),
            config.host,
            config.port,
        );
        options
            .set_clean_start(true)
            .set_session_expiry_interval(Some(0))
            .set_keep_alive(Duration::from_secs(10))
            .set_max_packet_size(Some(2 * 1024 * 1024 + 4096))
            .set_outgoing_inflight_upper_limit(32)
            .set_connection_timeout(10);
        options.set_last_will(LastWill::new(
            topics.manager_availability(instance),
            b"offline".to_vec(),
            QoS::AtLeastOnce,
            true,
            None,
        ));
        if let (Some(user), Some(password)) = (config.username, config.password) {
            options.set_credentials(user, password);
        }
        if config.tls {
            let roots =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let tls = if let Some(tls) = custom_tls {
                tls
            } else {
                rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .map_err(internal)?
                .with_root_certificates(roots)
                .with_no_client_auth()
            };
            options.set_transport(rumqttc::Transport::tls_with_config(tls.into()));
        }
        let (client, eventloop) = AsyncClient::new(options, 32);
        let catalog = CatalogBuffer::new(registered.keys().cloned().collect());
        Ok(Self {
            client,
            eventloop,
            topics,
            instance,
            pcs: registered,
            retired_pcs: BTreeSet::new(),
            catalog,
            outbox: VecDeque::new(),
            control_outbox: VecDeque::new(),
            outbox_bytes: 0,
            queued_q1: 0,
            acked_q1: 0,
            closing: false,
            connected: false,
            controls_ready: false,
            subscription_plan: VecDeque::new(),
            pending_subscriptions: BTreeMap::new(),
            last_rejection: None,
            observations: BTreeMap::new(),
            started: Instant::now(),
        })
    }
    /// Update exact registered scopes after onboarding/archive; no host-owned cleanup.
    pub fn sync_registrations(&mut self, pcs: Vec<Registration>) -> Result<(), SafeError> {
        if pcs.len() > 1000 || self.closing {
            return Err(SafeError::validation());
        }
        let mut registered = BTreeMap::new();
        for pc in pcs {
            if pc.display_name.is_empty()
                || pc.display_name.len() > 256
                || registered.insert(pc.pc_id, pc.display_name).is_some()
            {
                return Err(SafeError::validation());
            }
        }
        if registered == self.pcs {
            return Ok(());
        }
        if !self.controls_ready {
            return Err(SafeError::new("operation_in_progress"));
        }
        let removed: Vec<_> = self
            .pcs
            .keys()
            .filter(|pc| !registered.contains_key(*pc))
            .cloned()
            .collect();
        if self.control_outbox.len() + removed.len() * 4 + 1 > 4001
            || self.outbox.len() + registered.len() * 4 + removed.len() * 2 + 1 > 10000
        {
            return Err(SafeError::new("payload_too_large"));
        }
        if self
            .retired_pcs
            .union(&removed.iter().cloned().collect())
            .count()
            > 1000
        {
            return Err(SafeError::new("payload_too_large"));
        }
        for pc in removed {
            self.retired_pcs.insert(pc.clone());
            let attr = self.topics.catalog_attributes(&pc, &AppId::new("1")?);
            for topic in [
                self.topics.service_command(&pc),
                format!(
                    "{}+/attributes",
                    attr.strip_suffix("1/attributes")
                        .ok_or_else(SafeError::validation)?
                ),
                self.topics.catalog_manifest(&pc),
                self.topics.host_availability(&pc),
            ] {
                self.control_outbox
                    .push_back(ControlRequest::Unsubscribe(topic));
            }
            self.enqueue(
                self.topics.service_availability(&pc),
                b"offline".to_vec(),
                true,
            )?;
            self.enqueue(self.topics.switch_discovery(&pc), Vec::new(), true)?;
            self.observations.remove(&pc);
        }
        self.retired_pcs.retain(|pc| !registered.contains_key(pc));
        self.pcs = registered;
        self.catalog.pcs = self.pcs.keys().cloned().collect();
        self.catalog
            .pending
            .retain(|(pc, _), _| self.pcs.contains_key(pc));
        self.catalog
            .committed
            .retain(|pc, _| self.pcs.contains_key(pc));
        self.controls_ready = false;
        let filters = self.filters();
        self.control_outbox
            .push_back(ControlRequest::Subscribe(filters, true));
        self.replay(false)
    }
    /// Flush QoS1 offline publications and their broker acknowledgements before DISCONNECT.
    pub async fn shutdown(&mut self) -> Result<(), SafeError> {
        if !self.connected {
            return Err(SafeError::new("internal_error"));
        }
        self.closing = true;
        self.controls_ready = false;
        // Archive tombstones and prior publications must drain before final offline.
        self.control_outbox.clear();
        let pcs: Vec<_> = self.pcs.keys().cloned().collect();
        for pc in pcs {
            self.enqueue(
                self.topics.service_availability(&pc),
                b"offline".to_vec(),
                true,
            )?;
        }
        self.enqueue(
            self.topics.manager_availability(self.instance),
            b"offline".to_vec(),
            true,
        )?;
        let target = self.queued_q1.saturating_add(self.outbox.len() as u64);
        tokio::time::timeout(Duration::from_secs(5), async {
            while self.acked_q1 < target {
                self.poll().await?;
            }
            self.client.try_disconnect().map_err(internal)?;
            loop {
                match self.eventloop.poll().await {
                    Ok(Event::Outgoing(rumqttc::Outgoing::Disconnect)) => return Ok(()),
                    Ok(_) => {}
                    Err(e) => return Err(internal(e)),
                }
            }
        })
        .await
        .map_err(internal)?
    }
    /// Load all durable archived IDs before connect; excessive scopes refuse, never drop.
    pub fn seed_archived_pcs(&mut self, pcs: Vec<PcId>) -> Result<(), SafeError> {
        if self.connected || pcs.len() > 1000 || pcs.iter().any(|pc| self.pcs.contains_key(pc)) {
            return Err(SafeError::new("payload_too_large"));
        }
        self.retired_pcs = pcs.into_iter().collect();
        Ok(())
    }
    pub fn seed_catalog(
        &mut self,
        manifest: CatalogManifest,
        attributes: Vec<CatalogAttributes>,
    ) -> Result<(), SafeError> {
        self.catalog.seed(manifest, attributes)
    }
    pub fn controls_ready(&self) -> bool {
        self.controls_ready
    }
    fn filters(&self) -> Vec<Filter> {
        let mut filters = vec![Filter::new(self.topics.ha_birth(), QoS::AtLeastOnce)];
        for pc in self.pcs.keys() {
            filters.push(Filter {
                path: self.topics.service_command(pc),
                qos: QoS::AtMostOnce,
                nolocal: false,
                preserve_retain: true,
                retain_forward_rule: RetainForwardRule::Never,
            });
            let attr = self
                .topics
                .catalog_attributes(pc, &AppId::new("1").expect("fixed valid app ID"));
            filters.push(Filter::new(
                format!(
                    "{}+/attributes",
                    attr.strip_suffix("1/attributes").expect("topic format")
                ),
                QoS::AtLeastOnce,
            ));
            filters.push(Filter::new(
                self.topics.catalog_manifest(pc),
                QoS::AtLeastOnce,
            ));
            filters.push(Filter::new(
                self.topics.host_availability(pc),
                QoS::AtLeastOnce,
            ));
        }
        filters
    }
    fn enqueue(&mut self, topic: String, payload: Vec<u8>, retain: bool) -> Result<(), SafeError> {
        if payload.len() > 65536
            || self.outbox.len() >= 10000
            || self
                .outbox_bytes
                .saturating_add(topic.len() + payload.len())
                > BUFFER_BYTES
        {
            return Err(SafeError::new("payload_too_large"));
        }
        self.outbox_bytes += topic.len() + payload.len();
        self.outbox.push_back(Publication {
            topic,
            payload,
            retain,
        });
        Ok(())
    }
    fn drain_outbox(&mut self) {
        for _ in 0..8 {
            let Some(request) = self.control_outbox.front() else {
                break;
            };
            let result = match request {
                ControlRequest::Subscribe(filters, _) => {
                    self.client.try_subscribe_many(filters.clone())
                }
                ControlRequest::Unsubscribe(topic) => self.client.try_unsubscribe(topic.clone()),
            };
            if result.is_err() {
                break;
            }
            if let Some(ControlRequest::Subscribe(filters, controls)) =
                self.control_outbox.pop_front()
            {
                self.subscription_plan
                    .push_back((filters.iter().map(|f| f.qos).collect(), controls));
            }
        }
        for _ in 0..8 {
            let Some(item) = self.outbox.front() else {
                break;
            };
            if self
                .client
                .try_publish(
                    item.topic.clone(),
                    QoS::AtLeastOnce,
                    item.retain,
                    item.payload.clone(),
                )
                .is_err()
            {
                break;
            }
            let item = self.outbox.pop_front().expect("front was present");
            self.outbox_bytes -= item.topic.len() + item.payload.len();
            self.queued_q1 = self.queued_q1.saturating_add(1);
        }
    }
    fn replay(&mut self, connected: bool) -> Result<(), SafeError> {
        for pc in self.retired_pcs.iter().cloned().collect::<Vec<_>>() {
            self.enqueue(
                self.topics.service_availability(&pc),
                b"offline".to_vec(),
                true,
            )?;
            self.enqueue(self.topics.switch_discovery(&pc), Vec::new(), true)?;
        }
        let pcs: Vec<_> = self
            .pcs
            .iter()
            .map(|(id, name)| (id.clone(), name.clone()))
            .collect();
        for (pc, name) in pcs {
            self.enqueue(
                self.topics.switch_discovery(&pc),
                canonical_json(
                    &self
                        .topics
                        .switch_discovery_payload(&pc, &name, self.instance),
                )?,
                true,
            )?;
            if connected {
                self.enqueue(
                    self.topics.service_availability(&pc),
                    b"offline".to_vec(),
                    true,
                )?;
            } else if let Some(observation) = self.observations.get(&pc) {
                let entries = observation.publication.clone();
                let available = observation.available
                    && observation.updated.elapsed() < Duration::from_secs(60);
                for (topic, bytes) in entries {
                    self.enqueue(topic, bytes, true)?;
                }
                self.enqueue(
                    self.topics.service_availability(&pc),
                    if available {
                        b"online".to_vec()
                    } else {
                        b"offline".to_vec()
                    },
                    true,
                )?;
            } else {
                self.enqueue(
                    self.topics.service_availability(&pc),
                    b"offline".to_vec(),
                    true,
                )?;
            }
        }
        self.enqueue(
            self.topics.manager_availability(self.instance),
            b"online".to_vec(),
            true,
        )
    }
    /// Publish availability/state only from a confirmed SSH observation, never a command.
    pub fn observe_service(
        &mut self,
        pc: &PcId,
        status: &HostStatus,
        observed_at_ms: i64,
        last_operation_id: Option<uuid::Uuid>,
    ) -> Result<(), SafeError> {
        if !self.pcs.contains_key(pc) || observed_at_ms < 0 {
            return Err(SafeError::validation());
        }
        let state = match (
            status.systemd_state.as_str(),
            status.container_state.as_str(),
        ) {
            ("active", "running") => Some("ON"),
            ("inactive", "stopped" | "exited" | "absent" | "not_found") => Some("OFF"),
            _ => None,
        };
        let attributes = canonical_json(
            &json!({"version":1,"pc_id":pc,"observed_at_ms":observed_at_ms,"systemd_state":status.systemd_state,"container_state":status.container_state,"restart_count":status.restart_count,"staged_revision":status.staged_revision,"running_revision":status.running_revision,"recovery_pending":status.recovery_pending,"last_operation_id":last_operation_id}),
        )?;
        let mut entries = vec![(self.topics.service_attributes(pc), attributes)];
        if let Some(state) = state {
            entries.push((self.topics.service_state(pc), state.as_bytes().to_vec()));
        }
        for (topic, bytes) in &entries {
            self.enqueue(topic.clone(), bytes.clone(), true)?;
        }
        self.enqueue(
            self.topics.service_availability(pc),
            if state.is_some() {
                b"online".to_vec()
            } else {
                b"offline".to_vec()
            },
            true,
        )?;
        self.observations.insert(
            pc.clone(),
            Observation {
                publication: entries,
                updated: Instant::now(),
                available: state.is_some(),
            },
        );
        Ok(())
    }
    pub fn unavailable(&mut self, pc: &PcId) -> Result<(), SafeError> {
        if !self.pcs.contains_key(pc) {
            return Err(SafeError::validation());
        }
        if let Some(value) = self.observations.get_mut(pc) {
            value.available = false;
        }
        self.enqueue(
            self.topics.service_availability(pc),
            b"offline".to_vec(),
            true,
        )
    }
    /// A pre-admission refusal has no durable operation and therefore no UUID.
    pub fn command_refused(
        &mut self,
        pc: &PcId,
        code: &str,
        observed_at_ms: i64,
    ) -> Result<(), SafeError> {
        if !self.pcs.contains_key(pc) || observed_at_ms < 0 {
            return Err(SafeError::validation());
        }
        let error = SafeError::new(code);
        self.enqueue(self.topics.service_result(pc),canonical_json(&json!({"version":1,"pc_id":pc,"operation_id":null,"state":"rejected","code":error.code(),"observed_at_ms":observed_at_ms}))?,false)
    }
    pub fn operation_result(
        &mut self,
        pc: &PcId,
        operation_id: uuid::Uuid,
        state: OperationState,
        code: Option<&str>,
        observed_at_ms: i64,
    ) -> Result<(), SafeError> {
        if !self.pcs.contains_key(pc) || operation_id.is_nil() || observed_at_ms < 0 {
            return Err(SafeError::validation());
        }
        let safe = code.map(SafeError::new);
        self.enqueue(self.topics.service_result(pc),canonical_json(&json!({"version":1,"pc_id":pc,"operation_id":operation_id,"state":state,"code":safe.as_ref().map(SafeError::code),"observed_at_ms":observed_at_ms}))?,false)
    }
    fn publication(&mut self, publish: Publish) -> Result<Option<ManagerEvent>, SafeError> {
        let topic = std::str::from_utf8(&publish.topic).map_err(internal)?;
        if topic == self.topics.ha_birth() {
            return Ok((publish.payload.as_ref() == b"online").then_some(ManagerEvent::Birth));
        }
        let pcs: Vec<_> = self.pcs.keys().cloned().collect();
        for pc in pcs {
            if topic == self.topics.service_command(&pc) {
                if !self.controls_ready {
                    return Ok(None);
                }
                let command = match validate_command(&publish.payload, publish.retain) {
                    Ok(c) => c,
                    Err(error) => {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map_err(internal)?
                            .as_millis()
                            .try_into()
                            .map_err(internal)?;
                        self.command_refused(&pc, error.code().as_str(), now)?;
                        return Ok(None);
                    }
                };
                return Ok(Some(ManagerEvent::Command { pc_id: pc, command }));
            }
            if topic == self.topics.host_availability(&pc) {
                return match publish.payload.as_ref() {
                    b"online" => Ok(Some(ManagerEvent::HostAvailability {
                        pc_id: pc,
                        online: true,
                    })),
                    b"offline" => Ok(Some(ManagerEvent::HostAvailability {
                        pc_id: pc,
                        online: false,
                    })),
                    _ => Err(SafeError::validation()),
                };
            }
            let now = self
                .started
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX);
            if topic == self.topics.catalog_manifest(&pc) {
                if publish.payload.len() > 2 * 1024 * 1024 {
                    return Err(SafeError::new("payload_too_large"));
                }
                let manifest: CatalogManifest = serde_json::from_slice(&publish.payload)
                    .map_err(|_| SafeError::validation())?;
                if manifest.pc_id != pc {
                    return Err(SafeError::validation());
                }
                return Ok(self
                    .catalog
                    .manifest(manifest, now)?
                    .map(|(manifest, attributes)| ManagerEvent::CatalogReady {
                        manifest,
                        attributes,
                    }));
            }
            let base = self
                .topics
                .catalog_attributes(&pc, &AppId::new("1").expect("fixed valid app ID"));
            let prefix = base.strip_suffix("1/attributes").expect("topic format");
            if let Some(id) = topic
                .strip_prefix(prefix)
                .and_then(|rest| rest.strip_suffix("/attributes"))
            {
                let app = AppId::new(id)?;
                if publish.payload.is_empty() {
                    return Ok(None);
                }
                if publish.payload.len() > 16384 {
                    return Err(SafeError::new("payload_too_large"));
                }
                let attr: CatalogAttributes = serde_json::from_slice(&publish.payload)
                    .map_err(|_| SafeError::validation())?;
                if attr.pc_id != pc || attr.app_id != app {
                    return Err(SafeError::validation());
                }
                return Ok(self
                    .catalog
                    .attributes(attr, now)?
                    .map(|(manifest, attributes)| ManagerEvent::CatalogReady {
                        manifest,
                        attributes,
                    }));
            }
        }
        Ok(None)
    }
    /// Keep this future polled while draining events. Queueing never awaits behind poll.
    /// On error, stop controls and rebuild from durable state; never replay commands.
    pub async fn poll(&mut self) -> Result<Option<ManagerEvent>, SafeError> {
        let expired = self.catalog.expire_with_replay(
            self.started
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
        );
        for pc in expired {
            if !self.closing {
                let attr = self.topics.catalog_attributes(&pc, &AppId::new("1")?);
                let filters = vec![
                    Filter::new(
                        format!(
                            "{}+/attributes",
                            attr.strip_suffix("1/attributes")
                                .ok_or_else(SafeError::validation)?
                        ),
                        QoS::AtLeastOnce,
                    ),
                    Filter::new(self.topics.catalog_manifest(&pc), QoS::AtLeastOnce),
                ];
                if self.control_outbox.len() >= 4001 {
                    return Err(SafeError::new("payload_too_large"));
                }
                self.control_outbox
                    .push_back(ControlRequest::Subscribe(filters, false));
            }
        }
        let stale: Vec<_> = self
            .observations
            .iter()
            .filter(|(_, v)| v.available && v.updated.elapsed() >= Duration::from_secs(60))
            .map(|(pc, _)| pc.clone())
            .collect();
        for pc in stale {
            self.unavailable(&pc)?;
        }
        self.drain_outbox();
        let event = match self.eventloop.poll().await {
            Ok(e) => e,
            Err(e) => {
                self.controls_ready = false;
                self.connected = false;
                return Err(internal(e));
            }
        };
        match event {
            Event::Incoming(Packet::ConnAck(ack)) => {
                if self.closing {
                    return Err(SafeError::new("internal_error"));
                }
                self.connected = true;
                self.controls_ready = false;
                self.pending_subscriptions.clear();
                self.subscription_plan.clear();
                if ack.code != ConnectReturnCode::Success
                    || ack.session_present
                    || ack.properties.as_ref().is_some_and(|p| {
                        p.session_expiry_interval.is_some_and(|expiry| expiry != 0)
                            || p.max_qos.is_some_and(|q| q < 1)
                            || p.retain_available == Some(0)
                    })
                {
                    return Err(SafeError::new("forbidden"));
                }
                self.outbox.clear();
                self.control_outbox.clear();
                self.outbox_bytes = 0;
                for observation in self.observations.values_mut() {
                    observation.available = false;
                }
                let filters = self.filters();
                self.control_outbox
                    .push_back(ControlRequest::Subscribe(filters, true));
                self.replay(true)?;
                Ok(None)
            }
            Event::Outgoing(rumqttc::Outgoing::Subscribe(pkid)) => {
                let plan = self
                    .subscription_plan
                    .pop_front()
                    .ok_or_else(|| SafeError::new("internal_error"))?;
                self.pending_subscriptions.insert(pkid, plan);
                Ok(None)
            }
            Event::Incoming(Packet::SubAck(ack)) => {
                let (qos, controls) = self
                    .pending_subscriptions
                    .remove(&ack.pkid)
                    .ok_or_else(|| SafeError::new("forbidden"))?;
                if ack.return_codes.len()!=qos.len()||ack.return_codes.iter().zip(&qos).any(|(actual,expected)|!matches!(actual,SubscribeReasonCode::Success(qos) if qos==expected)){return Err(SafeError::new("forbidden"));}
                if controls {
                    self.controls_ready = !self.closing;
                    Ok(Some(ManagerEvent::Connected))
                } else {
                    Ok(None)
                }
            }
            Event::Incoming(Packet::Publish(publish)) => {
                let result = match self.publication(publish) {
                    Ok(result) => result,
                    Err(error) => {
                        if self
                            .last_rejection
                            .is_none_or(|last| last.elapsed() >= Duration::from_secs(30))
                        {
                            tracing::warn!(code=?error.code(),"MQTT projection message refused");
                            self.last_rejection = Some(Instant::now());
                        }
                        return Ok(None);
                    }
                };
                if matches!(result, Some(ManagerEvent::Birth)) && !self.closing {
                    self.replay(false)?;
                }
                Ok(result)
            }
            Event::Incoming(Packet::PubAck(_)) => {
                self.acked_q1 = self.acked_q1.saturating_add(1);
                Ok(None)
            }
            _ => Ok(None),
        }
    }
}
