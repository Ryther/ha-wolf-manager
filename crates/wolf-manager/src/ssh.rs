//! Native restricted SSH transport and protected per-PC identities.
use russh::{
    ChannelMsg, client,
    keys::{
        Algorithm, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate,
    },
};
use rustix::fs::{Mode, OFlags, ResolveFlags};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use wolf_core::{PcId, RPC_MAX_BYTES, RpcRequest, RpcResponse, SafeError};
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(810);
fn request_timeout(operation: &wolf_core::RpcOperation) -> Duration {
    use wolf_core::RpcOperation::*;
    match operation {
        Start(_) | Stop(_) | Restart(_) => REQUEST_TIMEOUT,
        ApplySettings(_) => Duration::from_secs(60),
        Preflight(_) | Status(_) | BoundedLogs(_) | RequestStatus(_) => Duration::from_secs(30),
    }
}
const OUTPUT_LIMIT: usize = 1024 * 1024;
const STDERR_LIMIT: usize = 16 * 1024;
const COMMAND: &str = "wolf-manager-rpc-v1";
fn internal<T>(_: T) -> SafeError {
    SafeError::new("internal_error")
}
fn forbidden<T>(_: T) -> SafeError {
    SafeError::new("forbidden")
}

#[derive(Clone, Debug)]
pub struct Endpoint {
    pub pc_id: PcId,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub host_key_algorithm: Option<String>,
    pub host_key_public: Option<String>,
    pub host_key_fingerprint: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    pub algorithm: String,
    pub public_key: String,
    pub fingerprint: String,
}
impl Endpoint {
    fn validate(&self) -> Result<(), SafeError> {
        if self.host.is_empty()
            || self.host.len() > 253
            || self
                .host
                .bytes()
                .any(|c| c.is_ascii_whitespace() || c.is_ascii_control())
            || self.port == 0
            || self.user != "wolf-manager"
        {
            return Err(SafeError::validation());
        }
        Ok(())
    }
    fn enrolled(&self) -> Result<PublicKey, SafeError> {
        self.validate()?;
        let key = PublicKey::from_openssh(
            self.host_key_public
                .as_deref()
                .ok_or_else(SafeError::validation)?,
        )
        .map_err(forbidden)?;
        let details = describe(&key)?;
        if self.host_key_algorithm.as_deref() != Some(details.algorithm.as_str())
            || self.host_key_fingerprint.as_deref() != Some(details.fingerprint.as_str())
        {
            return Err(SafeError::new("forbidden"));
        }
        Ok(key)
    }
}
fn describe(key: &PublicKey) -> Result<Probe, SafeError> {
    Ok(Probe {
        algorithm: key.algorithm().to_string(),
        public_key: key.to_openssh().map_err(internal)?,
        fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
    })
}
fn private_directory(file: File) -> Result<File, SafeError> {
    let m = file.metadata().map_err(internal)?;
    if !m.is_dir() || m.uid() != rustix::process::geteuid().as_raw() || m.mode() & 0o7777 != 0o700 {
        return Err(SafeError::new("forbidden"));
    }
    Ok(file)
}
fn child_directory(parent: &File, name: &str) -> Result<File, SafeError> {
    match rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
        Ok(()) => parent.sync_all().map_err(internal)?,
        Err(rustix::io::Errno::EXIST) => {}
        Err(e) => return Err(internal(e)),
    }
    let fd = rustix::fs::openat2(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(forbidden)?;
    private_directory(File::from(fd))
}
fn key_directory(data: &Path, pc: &PcId) -> Result<File, SafeError> {
    if !data.is_absolute()
        || data
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(SafeError::validation());
    }
    let mut ancestor = PathBuf::from("/");
    for component in data.components() {
        if let Component::Normal(part) = component {
            ancestor.push(part);
        }
        let fd = rustix::fs::openat2(
            rustix::fs::CWD,
            &ancestor,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(forbidden)?;
        let m = File::from(fd).metadata().map_err(internal)?;
        let sticky_root = m.uid() == 0 && m.mode() & 0o1000 != 0;
        if ![0, rustix::process::geteuid().as_raw()].contains(&m.uid())
            || (m.mode() & 0o022 != 0 && !sticky_root)
        {
            return Err(SafeError::new("forbidden"));
        }
    }
    let root = private_directory(File::from(
        rustix::fs::openat2(
            rustix::fs::CWD,
            data,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(forbidden)?,
    ))?;
    child_directory(&child_directory(&root, "keys")?, pc.as_str())
}
fn read_identity(directory: &File) -> Result<PrivateKey, SafeError> {
    let fd = rustix::fs::openat2(
        directory,
        "id_ed25519",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(forbidden)?;
    let file = File::from(fd);
    let m = file.metadata().map_err(internal)?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.mode() & 0o7777 != 0o600
        || m.len() > 16 * 1024
    {
        return Err(SafeError::new("forbidden"));
    }
    let mut bytes = Vec::new();
    file.take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(internal)?;
    let result = PrivateKey::from_openssh(&bytes).map_err(forbidden);
    bytes.fill(0);
    let key = result?;
    if key.algorithm() != Algorithm::Ed25519 || key.is_encrypted() {
        return Err(SafeError::new("forbidden"));
    }
    Ok(key)
}
/// Generate or validate the fixed protected identity; return public material only.
pub fn ensure_identity(data: &Path, pc: &PcId) -> Result<String, SafeError> {
    let directory = key_directory(data, pc)?;
    match rustix::fs::openat2(
        &directory,
        "id_ed25519",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    ) {
        Ok(fd) => {
            let key = PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519)
                .map_err(internal)?;
            let encoded = key
                .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                .map_err(internal)?;
            let mut file = File::from(fd);
            file.write_all(encoded.as_bytes()).map_err(internal)?;
            file.sync_all().map_err(internal)?;
            directory.sync_all().map_err(internal)?;
        }
        Err(rustix::io::Errno::EXIST) => {}
        Err(e) => return Err(forbidden(e)),
    }
    read_identity(&directory)?
        .public_key()
        .to_openssh()
        .map_err(internal)
}
struct Verifier {
    expected: Option<PublicKey>,
    observed: Arc<Mutex<Option<Probe>>>,
}
impl client::Handler for Verifier {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        server: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        if server.certificate().is_some() {
            return Ok(false);
        }
        let key = server.public_key();
        if let Ok(details) = describe(&key)
            && let Ok(mut observed) = self.observed.lock()
        {
            *observed = Some(details);
        }
        // Probes finish key exchange but never authenticate or open channels.
        Ok(self
            .expected
            .as_ref()
            .is_none_or(|expected| expected.key_data() == key.key_data()))
    }
}
fn config() -> Arc<client::Config> {
    Arc::new(client::Config {
        inactivity_timeout: Some(REQUEST_TIMEOUT),
        ..Default::default()
    })
}
/// Obtain the unauthenticated presented host key for explicit enrollment.
pub async fn probe(endpoint: &Endpoint) -> Result<Probe, SafeError> {
    endpoint.validate()?;
    let observed = Arc::new(Mutex::new(None));
    let handle = tokio::time::timeout(
        CONNECT_TIMEOUT,
        client::connect(
            config(),
            (endpoint.host.as_str(), endpoint.port),
            Verifier {
                expected: None,
                observed: observed.clone(),
            },
        ),
    )
    .await
    .map_err(internal)?
    .map_err(internal)?;
    let details = observed
        .lock()
        .map_err(internal)?
        .clone()
        .ok_or_else(|| SafeError::new("forbidden"))?;
    let _ = tokio::time::timeout(
        Duration::from_secs(1),
        handle.disconnect(russh::Disconnect::ByApplication, "probe complete", "en"),
    )
    .await;
    Ok(details)
}
pub struct ReadyClient {
    handle: client::Handle<Verifier>,
    pc_id: PcId,
}
/// Verify the enrolled key before authenticating with the protected identity.
pub async fn connect(endpoint: &Endpoint, data: &Path) -> Result<ReadyClient, SafeError> {
    let expected = endpoint.enrolled()?;
    let directory = key_directory(data, &endpoint.pc_id)?;
    let key = Arc::new(read_identity(&directory)?);
    let endpoint = endpoint.clone();
    tokio::time::timeout(CONNECT_TIMEOUT, async move {
        let mut handle = client::connect(
            config(),
            (endpoint.host.as_str(), endpoint.port),
            Verifier {
                expected: Some(expected),
                observed: Arc::new(Mutex::new(None)),
            },
        )
        .await
        .map_err(forbidden)?;
        let result = handle
            .authenticate_publickey(&endpoint.user, PrivateKeyWithHashAlg::new(key, None))
            .await
            .map_err(forbidden)?;
        if !result.success() {
            return Err(SafeError::new("forbidden"));
        }
        Ok(ReadyClient {
            handle,
            pc_id: endpoint.pc_id,
        })
    })
    .await
    .map_err(internal)?
}
// Informational SSH messages are distinct from explicit exec acceptance.
// The surrounding request timeout bounds the entire acknowledgement exchange.
const EXEC_ACK_INFORMATIONAL_LIMIT: usize = 64;
fn exec_acknowledged(
    message: Option<ChannelMsg>,
    informational: &mut usize,
) -> Result<bool, SafeError> {
    match message {
        Some(ChannelMsg::Success) => Ok(true),
        Some(ChannelMsg::WindowAdjusted { .. }) => {
            *informational += 1;
            if *informational > EXEC_ACK_INFORMATIONAL_LIMIT {
                return Err(SafeError::validation());
            }
            Ok(false)
        }
        Some(ChannelMsg::Failure | ChannelMsg::Close | ChannelMsg::Eof) | None => {
            Err(SafeError::new("forbidden"))
        }
        _ => Err(SafeError::validation()),
    }
}

impl ReadyClient {
    /// Submit once after the coordinator durably records the child as sending.
    /// Failure after this call starts is uncertain and must never trigger replay.
    pub async fn execute(&mut self, request: &RpcRequest) -> Result<RpcResponse, SafeError> {
        request.validate_pc(&self.pc_id)?;
        let input = serde_json::to_vec(request).map_err(internal)?;
        if input.len() > RPC_MAX_BYTES {
            return Err(SafeError::new("payload_too_large"));
        }
        tokio::time::timeout(request_timeout(&request.operation), async {
            let mut channel = self.handle.channel_open_session().await.map_err(internal)?;
            channel.exec(true, COMMAND).await.map_err(internal)?;
            // Wait for exec acceptance before submitting the typed stdin payload.
            let mut informational = 0;
            while !exec_acknowledged(channel.wait().await, &mut informational)? {}
            channel.data(input.as_slice()).await.map_err(internal)?;
            channel.eof().await.map_err(internal)?;
            let mut output = Vec::new();
            let mut stderr_bytes = 0usize;
            let mut exit = None;
            while let Some(message) = channel.wait().await {
                match message {
                    ChannelMsg::Data { data } => {
                        if output.len().saturating_add(data.len()) > OUTPUT_LIMIT {
                            return Err(SafeError::new("payload_too_large"));
                        }
                        output.extend_from_slice(&data);
                    }
                    ChannelMsg::ExtendedData { data, .. } => {
                        stderr_bytes = stderr_bytes.saturating_add(data.len());
                        if stderr_bytes > STDERR_LIMIT {
                            return Err(SafeError::new("payload_too_large"));
                        }
                    }
                    ChannelMsg::ExitStatus { exit_status } => {
                        if exit.replace(exit_status).is_some() {
                            return Err(SafeError::validation());
                        }
                    }
                    ChannelMsg::Close => break,
                    ChannelMsg::ExitSignal { .. } | ChannelMsg::Failure => {
                        return Err(SafeError::new("internal_error"));
                    }
                    ChannelMsg::Eof | ChannelMsg::WindowAdjusted { .. } => {}
                    _ => return Err(SafeError::validation()),
                }
            }
            if exit != Some(0) {
                return Err(SafeError::new("internal_error"));
            }
            let response: RpcResponse =
                serde_json::from_slice(&output).map_err(|_| SafeError::validation())?;
            response.validate_for(request)?;
            Ok(response)
        })
        .await
        .map_err(internal)?
    }
}

#[cfg(test)]
mod timeout_tests {
    use super::*;
    use wolf_core::{EmptyPayload, RpcOperation};
    #[test]
    fn lifecycle_budget_exceeds_fixed_host_ceiling() {
        for operation in [
            RpcOperation::Start(wolf_core::StartPayload {
                expected_staged_revision: wolf_core::Settings::default().revision().unwrap(),
            }),
            RpcOperation::Stop(EmptyPayload {}),
            RpcOperation::Restart(wolf_core::StartPayload {
                expected_staged_revision: wolf_core::Settings::default().revision().unwrap(),
            }),
        ] {
            assert_eq!(request_timeout(&operation), Duration::from_secs(810));
        }
        assert!(config().inactivity_timeout.unwrap() >= Duration::from_secs(810));
    }
    #[test]
    fn readonly_budget_is_shorter_than_lifecycle() {
        let settings = wolf_core::Settings::default();
        assert_eq!(
            request_timeout(&RpcOperation::ApplySettings(
                wolf_core::ApplySettingsPayload {
                    revision: settings.revision().unwrap(),
                    settings
                }
            )),
            Duration::from_secs(60)
        );
        assert_eq!(
            request_timeout(&RpcOperation::Status(EmptyPayload {})),
            Duration::from_secs(30)
        );
        assert_eq!(
            request_timeout(&RpcOperation::Preflight(EmptyPayload {})),
            Duration::from_secs(30)
        );
    }
}

#[cfg(test)]
mod exec_acknowledgement_tests {
    use super::*;
    #[test]
    fn window_updates_never_authorize_stdin_before_explicit_success() {
        let mut informational = 0;
        for new_size in [65536, 131072] {
            assert!(
                !exec_acknowledged(
                    Some(ChannelMsg::WindowAdjusted { new_size }),
                    &mut informational
                )
                .unwrap()
            );
        }
        assert!(exec_acknowledged(Some(ChannelMsg::Success), &mut informational).unwrap());
    }
    #[test]
    fn denied_closed_eof_or_unexpected_acknowledgements_never_authorize_stdin() {
        for message in [
            Some(ChannelMsg::Failure),
            Some(ChannelMsg::Close),
            Some(ChannelMsg::Eof),
            Some(ChannelMsg::ExitStatus { exit_status: 0 }),
            None,
        ] {
            assert!(exec_acknowledged(message, &mut 0).is_err());
        }
    }
    #[test]
    fn unbounded_window_updates_are_refused_even_before_request_timeout() {
        let mut informational = 0;
        for _ in 0..EXEC_ACK_INFORMATIONAL_LIMIT {
            assert!(
                !exec_acknowledged(
                    Some(ChannelMsg::WindowAdjusted { new_size: 65536 }),
                    &mut informational
                )
                .unwrap()
            );
        }
        assert!(
            exec_acknowledged(
                Some(ChannelMsg::WindowAdjusted { new_size: 65536 }),
                &mut informational
            )
            .is_err()
        );
    }
}
