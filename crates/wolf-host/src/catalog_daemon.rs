//! Non-root policy-bound catalog actor with durable owned scopes and acknowledged cleanup.
use crate::{
    catalog::{self, CatalogConfig, Library, Snapshot},
    catalog_mqtt::{BrokerConfig, Publisher, protected_file},
    policy::RootPolicy,
};
use fs2::FileExt;
use rustix::fs::{Mode, OFlags, ResolveFlags};
use std::{
    collections::BTreeSet,
    fs::File,
    future::Future,
    io::{self, Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use wolf_core::{AppId, PcId, Topics};
fn invalid() -> io::Error {
    io::Error::other("catalog daemon state or authority invalid")
}
pub fn load_broker(path: &Path, uid: u32) -> io::Result<BrokerConfig> {
    let file = protected_file(path, uid, &[0o600], 65536)?;
    if file.metadata()?.uid() != uid {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(invalid());
    }
    let config: BrokerConfig = serde_json::from_slice(&bytes)?;
    Topics::new(&config.topic_base, &config.discovery_prefix).map_err(|_| invalid())?;
    if config.host.is_empty()
        || config.host.len() > 253
        || config
            .host
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
        || config.port == 0
        || config.client_id.is_empty()
        || config.client_id.len() > 128
        || config.client_id.chars().any(char::is_control)
        || config.pc_name.trim().is_empty()
        || config.pc_name.len() > 256
        || config.pc_name.chars().any(char::is_control)
        || config.username_file.is_some() != config.password_file.is_some()
        || !config.tls && config.ca_file.is_some()
    {
        return Err(invalid());
    }
    Ok(config)
}
fn directory(path: &Path, uid: u32, private: bool) -> io::Result<File> {
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
    for component in path.components() {
        if let std::path::Component::Normal(part) = component {
            ancestor.push(part);
        }
        let file = File::from(rustix::fs::openat2(
            rustix::fs::CWD,
            &ancestor,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?);
        let m = file.metadata()?;
        let sticky_root = m.uid() == 0 && m.mode() & 0o1000 != 0;
        if ![0, uid].contains(&m.uid()) || m.mode() & 0o022 != 0 && !sticky_root {
            return Err(invalid());
        }
        if ancestor == path {
            if private && (m.uid() != uid || m.mode() & 0o7777 != 0o700) {
                return Err(invalid());
            }
            return Ok(file);
        }
    }
    Err(invalid())
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Owned {
    version: u8,
    pc_id: PcId,
    app_ids: Vec<AppId>,
}
struct Journal {
    _lock: Arc<File>,
    root: File,
    path: PathBuf,
    pc: PcId,
    uid: u32,
    device: u64,
    inode: u64,
}
impl Journal {
    fn verify(&self) -> io::Result<()> {
        let m = directory(&self.path, self.uid, true)?.metadata()?;
        if m.dev() != self.device || m.ino() != self.inode {
            return Err(invalid());
        }
        Ok(())
    }
    fn read(&self) -> io::Result<BTreeSet<AppId>> {
        self.verify()?;
        if let Err(e) = std::fs::symlink_metadata(self.path.join("owned.json")) {
            if e.kind() == io::ErrorKind::NotFound {
                return Ok(BTreeSet::new());
            }
            return Err(e);
        }
        let file = protected_file(
            &self.path.join("owned.json"),
            self.uid,
            &[0o600],
            1024 * 1024,
        )?;
        if file.metadata()?.uid() != self.uid {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
        let owned: Owned = serde_json::from_slice(&bytes)?;
        if owned.version != 1
            || owned.pc_id != self.pc
            || owned.app_ids.len() > 20000
            || owned.app_ids.windows(2).any(|w| w[0] >= w[1])
        {
            return Err(invalid());
        }
        Ok(owned.app_ids.into_iter().collect())
    }
    fn write(&self, ids: &BTreeSet<AppId>) -> io::Result<()> {
        self.verify()?;
        self.read()?;
        if ids.len() > 20000 {
            return Err(invalid());
        }
        let bytes = serde_json::to_vec(&Owned {
            version: 1,
            pc_id: self.pc.clone(),
            app_ids: ids.iter().cloned().collect(),
        })?;
        if bytes.len() > 1024 * 1024 {
            return Err(invalid());
        }
        let name = format!(".owned-{}", uuid::Uuid::new_v4());
        let mut out = File::from(rustix::fs::openat2(
            &self.root,
            &name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?);
        out.write_all(&bytes)?;
        out.sync_all()?;
        self.verify()?;
        rustix::fs::renameat(&self.root, &name, &self.root, "owned.json")?;
        self.root.sync_all()
    }
}
pub struct Daemon {
    catalog: CatalogConfig,
    broker: BrokerConfig,
    journal: Arc<Journal>,
    owned: BTreeSet<AppId>,
    cached: Option<Snapshot>,
}
impl Daemon {
    pub fn from_policy(policy: &RootPolicy) -> io::Result<Self> {
        policy.validate_structure()?;
        let uid = rustix::process::geteuid().as_raw();
        if uid == 0
            || rustix::process::getuid().as_raw() != uid
            || rustix::process::getgid().as_raw() != policy.steam_gid
            || uid != policy.steam_uid
            || rustix::process::getegid().as_raw() != policy.steam_gid
            || policy.libraries.len() > 64
        {
            return Err(invalid());
        }
        let broker = load_broker(policy.broker_secret_file.as_ref().ok_or_else(invalid)?, uid)?;
        let root = directory(&policy.catalog_state_directory, uid, true)?;
        let lock = File::from(rustix::fs::openat2(
            &root,
            "daemon.lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?);
        let m = lock.metadata()?;
        if !m.is_file() || m.nlink() != 1 || m.uid() != uid || m.mode() & 0o7777 != 0o600 {
            return Err(invalid());
        }
        lock.try_lock_exclusive()?;
        for library in &policy.libraries {
            directory(&library.steamapps_path, uid, false)?;
        }
        let catalog = CatalogConfig {
            pc_id: policy.pc_id.clone(),
            libraries: policy
                .libraries
                .iter()
                .map(|l| Library {
                    library_id: l.library_id.clone(),
                    canonical_path: l.steamapps_path.clone(),
                })
                .collect(),
            state_directory: policy.catalog_state_directory.clone(),
        };
        let m = root.metadata()?;
        let journal = Arc::new(Journal {
            _lock: Arc::new(lock),
            root,
            path: policy.catalog_state_directory.clone(),
            pc: policy.pc_id.clone(),
            uid,
            device: m.dev(),
            inode: m.ino(),
        });
        let mut owned = journal.read()?;
        let cached = catalog::load_published(&catalog)?;
        if let Some(snapshot) = &cached {
            owned.extend(snapshot.manifest.app_ids.iter().cloned());
        }
        if owned.len() > 20000 {
            return Err(invalid());
        }
        Ok(Self {
            catalog,
            broker,
            journal,
            owned,
            cached,
        })
    }
    /// One blocking scan at a time; MQTT polling continues while it runs. A shutdown
    /// cancels publication safely because owned intents precede all broker effects.
    pub async fn serve(
        mut self,
        interval: Duration,
        shutdown: impl Future<Output = ()>,
    ) -> io::Result<()> {
        if interval.is_zero() || interval > Duration::from_secs(3600) {
            return Err(invalid());
        }
        tokio::pin!(shutdown);
        let mut backoff = Duration::from_secs(1);
        let mut scan: Option<tokio::task::JoinHandle<io::Result<Snapshot>>> = None;
        loop {
            let connect = Publisher::connect(&self.broker, &self.catalog.pc_id);
            let mut publisher = tokio::select! { _=&mut shutdown=>return Ok(()),result=connect=>match result{Ok(p)=>p,Err(_)=>{tokio::select!{_=&mut shutdown=>return Ok(()),_=tokio::time::sleep(backoff)=>{}}backoff=(backoff*2).min(Duration::from_secs(30));continue;}}};
            backoff = Duration::from_secs(1);
            let result = {
                let session = async {
                    if let Some(snapshot) = self.cached.clone() {
                        self.replay(&mut publisher, &snapshot).await?;
                    }
                    let mut ticks = tokio::time::interval(interval);
                    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    loop {
                        tokio::select! {
                            _=ticks.tick(),if scan.is_none()=>{
                                let config=self.catalog.clone();let guard=self.journal.clone();scan=Some(tokio::task::spawn_blocking(move||{let _guard=guard;catalog::scan(&config,now()?)}));
                            },
                            result=async {scan.as_mut().expect("guarded scan").await},if scan.is_some()=>{
                                scan=None;
                                if let Ok(Ok(snapshot))=result {self.commit(&mut publisher,snapshot).await?;}
                            },
                            result=publisher.idle(Duration::from_secs(1))=>{
                                result?;
                                if publisher.take_birth() && let Some(snapshot)=self.cached.clone(){self.replay(&mut publisher,&snapshot).await?;}
                            },
                        }
                    }
                    #[allow(unreachable_code)]
                    Ok::<(), io::Error>(())
                };
                tokio::pin!(session);
                tokio::select! {_=&mut shutdown=>None,result=&mut session=>Some(result)}
            };
            if result.is_none() {
                let _ = publisher.shutdown().await;
                return Ok(());
            }
            drop(publisher);
            tokio::select! {_=&mut shutdown=>return Ok(()),_=tokio::time::sleep(backoff)=>{}}
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    }
    async fn replay(&mut self, publisher: &mut Publisher, snapshot: &Snapshot) -> io::Result<()> {
        let journal = self.journal.clone();
        let owned = self.owned.clone();
        disk(
            publisher,
            tokio::task::spawn_blocking(move || journal.write(&owned)),
        )
        .await?;
        publisher.publish_catalog(snapshot).await
    }
    async fn commit(&mut self, publisher: &mut Publisher, snapshot: Snapshot) -> io::Result<()> {
        let mut union = self.owned.clone();
        union.extend(snapshot.manifest.app_ids.iter().cloned());
        if union.len() > 20000 {
            return Err(invalid());
        }
        self.owned = union;
        let journal = self.journal.clone();
        let owned = self.owned.clone();
        disk(
            publisher,
            tokio::task::spawn_blocking(move || journal.write(&owned)),
        )
        .await?;
        publisher.publish_catalog(&snapshot).await?;
        let config = self.catalog.clone();
        let acknowledged = snapshot.clone();
        let guard = self.journal.clone();
        disk(
            publisher,
            tokio::task::spawn_blocking(move || {
                let _guard = guard;
                catalog::record_published(&config, &acknowledged)
            }),
        )
        .await?;
        self.cached = Some(snapshot.clone());
        publisher
            .tombstones(&snapshot, &self.owned.iter().cloned().collect::<Vec<_>>())
            .await?;
        let current: BTreeSet<_> = snapshot.manifest.app_ids.iter().cloned().collect();
        let journal = self.journal.clone();
        let ids = current.clone();
        disk(
            publisher,
            tokio::task::spawn_blocking(move || journal.write(&ids)),
        )
        .await?;
        self.owned = current;
        Ok(())
    }
}
async fn disk<T: Send + 'static>(
    publisher: &mut Publisher,
    mut work: tokio::task::JoinHandle<io::Result<T>>,
) -> io::Result<T> {
    loop {
        tokio::select! {result=&mut work=>return result.map_err(|_|invalid())?,result=publisher.idle(Duration::from_secs(1))=>result?}
    }
}
fn now() -> io::Result<i64> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid())?
            .as_millis(),
    )
    .map_err(|_| invalid())
}
pub fn run() -> io::Result<()> {
    if rustix::process::geteuid().is_root() {
        return Err(invalid());
    }
    let daemon = Daemon::from_policy(&RootPolicy::load_catalog_fixed()?)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    let result = runtime.block_on(async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        daemon
            .serve(Duration::from_secs(30), async move {
                tokio::select! {_=term.recv()=>{},_=interrupt.recv()=>{}}
            })
            .await
    });
    runtime.shutdown_timeout(Duration::from_secs(5));
    result
}
