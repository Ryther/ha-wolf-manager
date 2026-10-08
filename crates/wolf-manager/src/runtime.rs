//! Explicit deployment configuration and native HTTPS server.
use crate::{
    api::{AppState, Deployment, now, router},
    auth::{BootstrapSecret, TransportPolicy, normalize_origin},
    protected::internal,
    store::Store,
};
use axum::extract::ConnectInfo;
use clap::{Parser, Subcommand, ValueEnum};
use std::{
    io::BufReader,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tower::ServiceBuilder;
use wolf_core::*;
#[derive(Clone, Debug, ValueEnum)]
pub enum Mode {
    Ingress,
    Standalone,
}
#[derive(Parser, Debug)]
#[command(name = "ha-wolf-manager", version)]
pub struct Cli {
    #[arg(skip)]
    pub startup_options: Option<crate::ha_bootstrap::AddonOptions>,
    #[command(subcommand)]
    pub command: Option<Command>,
    #[arg(long, env = "WOLF_DATA_DIR", default_value = "/data")]
    pub data: PathBuf,
    #[arg(long, env = "WOLF_MODE", default_value = "ingress")]
    pub mode: Mode,
    #[arg(long, env = "WOLF_LISTEN", default_value = "0.0.0.0:8099")]
    pub listen: SocketAddr,
    #[arg(long, env = "WOLF_PUBLIC_ORIGIN")]
    pub public_origin: Option<String>,
    #[arg(long, env = "WOLF_BOOTSTRAP_TOKEN_FILE")]
    pub bootstrap_token_file: Option<PathBuf>,
    #[arg(long, env = "WOLF_TLS_CERT_FILE")]
    pub tls_cert_file: Option<PathBuf>,
    #[arg(long, env = "WOLF_TLS_KEY_FILE")]
    pub tls_key_file: Option<PathBuf>,
    #[arg(long, env = "WOLF_TRUSTED_PROXY", value_delimiter = ',')]
    pub trusted_proxy: Vec<IpAddr>,
    #[arg(long, env = "WOLF_MQTT_DISABLED")]
    pub mqtt_disabled: bool,
    #[arg(long, env = "WOLF_MQTT_HOST")]
    pub mqtt_host: Option<String>,
    #[arg(long, env = "WOLF_MQTT_PORT", default_value = "1883")]
    pub mqtt_port: u16,
    #[arg(long, env = "WOLF_MQTT_USERNAME")]
    pub mqtt_username: Option<String>,
    #[arg(long, env = "WOLF_MQTT_PASSWORD_FILE")]
    pub mqtt_password_file: Option<PathBuf>,
    #[arg(long, env = "WOLF_MQTT_TLS")]
    pub mqtt_tls: bool,
    #[arg(long, env = "WOLF_MQTT_CA_FILE")]
    pub mqtt_ca_file: Option<PathBuf>,
    #[arg(long, env = "WOLF_OPTIONS_FILE", default_value = "/data/options.json")]
    pub options_file: PathBuf,
    #[arg(long, env = "WOLF_TOPIC_BASE", default_value = "wolf-manager/v1")]
    pub topic_base: String,
    #[arg(long, env = "WOLF_DISCOVERY_PREFIX", default_value = "homeassistant")]
    pub discovery_prefix: String,
}
#[derive(Subcommand, Debug)]
pub enum Command {
    Healthcheck,
    Backup {
        #[arg(long)]
        destination: PathBuf,
    },
    RestorePreview {
        #[arg(long)]
        bundle: PathBuf,
    },
    Restore {
        #[arg(long)]
        bundle: PathBuf,
    },
    ResetPassword {
        #[arg(long)]
        password_file: PathBuf,
    },
    ImportPreview {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        format_version: u8,
    },
    ImportLegacy {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        format_version: u8,
        #[arg(long)]
        pc: String,
        #[arg(long)]
        expected_revision: String,
    },
}
impl Cli {
    pub fn validate(&self) -> Result<(), SafeError> {
        if !self.data.is_absolute() {
            return Err(SafeError::validation());
        }
        Topics::new(&self.topic_base, &self.discovery_prefix)?;
        if self.mqtt_disabled
            && (self.mqtt_host.is_some()
                || self.mqtt_username.is_some()
                || self.mqtt_password_file.is_some()
                || self.mqtt_tls
                || self.mqtt_ca_file.is_some())
        {
            return Err(SafeError::validation());
        }
        if self.mqtt_username.is_some() != self.mqtt_password_file.is_some()
            || self.mqtt_port == 0
            || self.mqtt_ca_file.is_some() && !self.mqtt_tls
        {
            return Err(SafeError::validation());
        }
        match self.mode {
            Mode::Ingress => self.validate_ingress()?,
            Mode::Standalone => self.validate_standalone()?,
        }
        Ok(())
    }
    fn validate_ingress(&self) -> Result<(), SafeError> {
        if self.mqtt_disabled
            || self.mqtt_host.is_some()
            || self.mqtt_username.is_some()
            || self.mqtt_password_file.is_some()
        {
            return Err(SafeError::validation());
        }
        if self.public_origin.is_some()
            || self.bootstrap_token_file.is_some()
            || self.tls_cert_file.is_some()
            || self.tls_key_file.is_some()
            || !self.trusted_proxy.is_empty()
        {
            return Err(SafeError::validation());
        }
        Ok(())
    }
    fn validate_standalone(&self) -> Result<(), SafeError> {
        if !self.mqtt_disabled && self.mqtt_host.is_none() {
            return Err(SafeError::validation());
        }
        let origin = normalize_origin(
            self.public_origin
                .as_deref()
                .ok_or_else(SafeError::validation)?,
        )?;
        if !origin.starts_with("https://") || self.bootstrap_token_file.is_none() {
            return Err(SafeError::validation());
        }
        let native = self.tls_cert_file.is_some() && self.tls_key_file.is_some();
        if self.tls_cert_file.is_some() != self.tls_key_file.is_some()
            || native == !self.trusted_proxy.is_empty()
        {
            return Err(SafeError::validation());
        }
        Ok(())
    }
}
fn certificates(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, SafeError> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};
    use std::{fs::File, io::Read, os::unix::fs::MetadataExt};
    let file = File::from(
        rustix::fs::openat2(
            rustix::fs::CWD,
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(internal)?,
    );
    let metadata = file.metadata().map_err(internal)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || ![0, rustix::process::geteuid().as_raw()].contains(&metadata.uid())
        || metadata.mode() & 0o022 != 0
    {
        return Err(SafeError::new("forbidden"));
    }
    if metadata.len() > 1024 * 1024 {
        return Err(SafeError::new("payload_too_large"));
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(internal)?;
    if bytes.len() > 1024 * 1024 {
        return Err(SafeError::new("payload_too_large"));
    }
    let certs = rustls_pemfile::certs(&mut BufReader::new(bytes.as_slice()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(internal)?;
    if certs.is_empty() {
        return Err(SafeError::validation());
    }
    Ok(certs)
}
pub fn client_tls(private_ca: Option<&Path>) -> Result<rustls::ClientConfig, SafeError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = private_ca {
        for cert in certificates(path)? {
            roots.add(cert).map_err(internal)?;
        }
    }
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(internal)?
    .with_root_certificates(roots)
    .with_no_client_auth())
}
pub fn server_tls(cert: &Path, key: &Path) -> Result<rustls::ServerConfig, SafeError> {
    let certificates = certificates(cert)?;
    let bytes = read_secret(key, 16384)?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(bytes.as_slice()))
        .map_err(internal)?
        .ok_or_else(SafeError::validation)?;
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(internal)?
    .with_no_client_auth()
    .with_single_cert(certificates, key)
    .map_err(internal)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(cfg)
}
pub fn read_secret(path: &Path, limit: u64) -> Result<Vec<u8>, SafeError> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};
    use std::{fs::File, io::Read, os::unix::fs::MetadataExt};
    let file = File::from(
        rustix::fs::openat2(
            rustix::fs::CWD,
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(internal)?,
    );
    let m = file.metadata().map_err(internal)?;
    if !m.is_file()
        || m.nlink() != 1
        || ![0, rustix::process::geteuid().as_raw()].contains(&m.uid())
        || m.mode() & 0o077 != 0
        || m.len() > limit
    {
        return Err(SafeError::new("forbidden"));
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(internal)?;
    if bytes.len() as u64 > limit {
        return Err(SafeError::new("payload_too_large"));
    }
    Ok(bytes)
}
pub async fn serve(cli: Cli) -> Result<(), SafeError> {
    cli.validate()?;
    if rustix::process::geteuid().is_root() {
        return Err(SafeError::new("forbidden"));
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (mode, transport, tls) = match cli.mode {
        Mode::Ingress => (Deployment::Ingress, TransportPolicy::Ingress, None),
        Mode::Standalone => {
            let origin = cli.public_origin.clone().unwrap();
            let path = cli.bootstrap_token_file.clone().unwrap();
            let secret = tokio::task::spawn_blocking(move || BootstrapSecret::read(&path))
                .await
                .map_err(internal)??;
            let tls = match (cli.tls_cert_file.clone(), cli.tls_key_file.clone()) {
                (Some(cert), Some(key)) => Some(
                    tokio::task::spawn_blocking(move || server_tls(&cert, &key))
                        .await
                        .map_err(internal)??,
                ),
                _ => None,
            };
            let transport = if tls.is_some() {
                TransportPolicy::NativeTls
            } else {
                TransportPolicy::TrustedProxy(cli.trusted_proxy.clone())
            };
            (
                Deployment::Standalone {
                    origin,
                    bootstrap: secret,
                },
                transport,
                tls,
            )
        }
    };
    let data = cli.data.clone();
    let store = tokio::task::spawn_blocking(move || Store::open(&data, now()))
        .await
        .map_err(internal)??;
    let state = AppState::new(store, cli.data.clone(), mode, transport);
    state
        .mqtt_required
        .store(!cli.mqtt_disabled, std::sync::atomic::Ordering::Release);
    let listener = tokio::net::TcpListener::bind(cli.listen)
        .await
        .map_err(internal)?;
    let acceptor = tls.map(|cfg| tokio_rustls::TlsAcceptor::from(Arc::new(cfg)));
    let app = router(state.clone());
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let background = tokio::spawn(background(state.clone(), stop_rx.clone()));
    let polling = tokio::spawn(polling(state.clone(), stop_rx.clone()));
    let mqtt = if cli.mqtt_disabled {
        None
    } else {
        let state = state.clone();
        Some(tokio::spawn(crate::mqtt_runtime::run(state, cli, stop_rx)))
    };
    let connection_limit = Arc::new(tokio::sync::Semaphore::new(256));
    let mut connections = tokio::task::JoinSet::new();
    let mut shutdown = std::pin::pin!(shutdown_signal());
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            connection = listener.accept() => {
                let (stream, peer) = connection.map_err(internal)?;
                if state.transport.admit(peer.ip()).is_err() { continue; }
                let Ok(permit) = connection_limit.clone().try_acquire_owned() else { continue };
                let app = app.clone();
                let acceptor = acceptor.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    serve_connection(app, stream, peer, acceptor).await;
                });
            },
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    state
        .accepting
        .store(false, std::sync::atomic::Ordering::Release);
    drop(listener);
    let _ = stop_tx.send(true);
    let _ = background.await;
    if let Some(mqtt) = mqtt {
        let _ = tokio::time::timeout(Duration::from_secs(7), mqtt).await;
    }
    polling.abort();
    let _ = polling.await;
    state.blocking(|s| s.stop_heartbeat()).await?;
    let _ = tokio::time::timeout(
        Duration::from_secs(130),
        state.tasks.clone().acquire_many_owned(64),
    )
    .await;
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}
/// Shared production connection adapter, exercised by native TLS socket tests.
pub async fn serve_connection(
    app: axum::Router,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    acceptor: Option<tokio_rustls::TlsAcceptor>,
) {
    let app = ServiceBuilder::new()
        .layer(axum::Extension(ConnectInfo(peer)))
        .service(app);
    let service = hyper_util::service::TowerToHyperService::new(app);
    let mut builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    builder
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .max_buf_size(32768);
    builder
        .http2()
        .max_concurrent_streams(32)
        .max_header_list_size(16384);
    if let Some(acceptor) = acceptor {
        if let Ok(Ok(tls)) =
            tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await
        {
            let _ = tokio::time::timeout(
                Duration::from_secs(60),
                builder.serve_connection(hyper_util::rt::TokioIo::new(tls), service),
            )
            .await;
        }
    } else {
        let _ = tokio::time::timeout(
            Duration::from_secs(60),
            builder.serve_connection(hyper_util::rt::TokioIo::new(stream), service),
        )
        .await;
    }
}
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
async fn background(state: AppState, mut stop: tokio::sync::watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    loop {
        tokio::select! {_=stop.changed()=>break,_=tick.tick()=>{let ready=state.ready().await.unwrap_or(false);if state.blocking(move|s|{if ready{s.heartbeat(now())?;}else{s.stop_heartbeat()?;}s.prune_terminal_operations(now())?;Ok(())}).await.is_err(){state.accepting.store(false,std::sync::atomic::Ordering::Release);break;}}}
    }
}
async fn polling(state: AppState, mut stop: tokio::sync::watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(Duration::from_secs(15));
    let mut jobs = tokio::task::JoinSet::new();
    let limit = Arc::new(tokio::sync::Semaphore::new(8));
    loop {
        tokio::select! {_=stop.changed()=>{jobs.abort_all();break;},Some(_)=jobs.join_next(),if !jobs.is_empty()=>{},_=tick.tick()=>{if !jobs.is_empty(){continue;}let pcs=state.blocking(|s|s.pcs()).await.unwrap_or_default();for pc in pcs{let limit=limit.clone();let state=state.clone();jobs.spawn(async move{let Ok(_permit)=limit.acquire_owned().await else{return};let pc=pc.pc_id;let capabilities=state.read_rpc(&pc,RpcOperation::Preflight(EmptyPayload{})).await;let status=state.read_rpc(&pc,RpcOperation::Status(EmptyPayload{})).await;if capabilities.is_err()||status.is_err(){let _=state.mark_service_unavailable(&pc);}});}}}
    }
}
