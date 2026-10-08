use ha_wolf_manager::ssh::{self, Endpoint, ensure_identity};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};
use wolf_core::PcId;
fn fixture() -> (tempfile::TempDir, PcId) {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    (root, PcId::new("gaming-pc").unwrap())
}
#[test]
fn identity_is_native_stable_and_private() {
    let (root, pc) = fixture();
    let public = ensure_identity(root.path(), &pc).unwrap();
    assert!(public.starts_with("ssh-ed25519 "));
    assert_eq!(public, ensure_identity(root.path(), &pc).unwrap());
    let key = root.path().join("keys/gaming-pc/id_ed25519");
    assert_eq!(
        fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(key.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}
#[test]
fn weak_permissions_and_aliases_are_refused() {
    let (root, pc) = fixture();
    ensure_identity(root.path(), &pc).unwrap();
    let key = root.path().join("keys/gaming-pc/id_ed25519");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(ensure_identity(root.path(), &pc).is_err());
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&key, root.path().join("alias")).unwrap();
    assert!(ensure_identity(root.path(), &pc).is_err());
}
#[test]
fn key_directory_symlink_cannot_escape_data_root() {
    let (root, pc) = fixture();
    let elsewhere = tempfile::tempdir().unwrap();
    symlink(elsewhere.path(), root.path().join("keys")).unwrap();
    assert!(ensure_identity(root.path(), &pc).is_err());
    assert!(fs::read_dir(elsewhere.path()).unwrap().next().is_none());
}

use russh::{
    Channel, ChannelId,
    keys::{Algorithm, HashAlg, PrivateKey, PublicKey},
    server::{self, Msg, Session},
};
use std::sync::{Arc, Mutex};
use wolf_core::{EmptyPayload, HostStatus, RpcOperation, RpcRequest, RpcResponse, RpcResult};
#[derive(Clone, Copy)]
enum Reply {
    Valid,
    WrongId,
    ExtraField,
    Oversized,
}
#[derive(Default)]
struct Observations {
    auth: usize,
    commands: Vec<Vec<u8>>,
    input: Vec<Vec<u8>>,
    pty: usize,
}
struct FixtureHandler {
    seen: Arc<Mutex<Observations>>,
    authorized: PublicKey,
    input: Vec<u8>,
    reply: Reply,
}
impl server::Handler for FixtureHandler {
    type Error = russh::Error;
    async fn auth_none(&mut self, _: &str) -> Result<server::Auth, Self::Error> {
        self.seen.lock().unwrap().auth += 1;
        Ok(server::Auth::reject())
    }
    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        key: &PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        self.seen.lock().unwrap().auth += 1;
        Ok(
            if user == "wolf-manager" && key.key_data() == self.authorized.key_data() {
                server::Auth::Accept
            } else {
                server::Auth::reject()
            },
        )
    }
    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        self.seen.lock().unwrap().auth += 1;
        Ok(
            if user == "wolf-manager" && key.key_data() == self.authorized.key_data() {
                server::Auth::Accept
            } else {
                server::Auth::reject()
            },
        )
    }
    async fn channel_open_session(
        &mut self,
        _: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }
    async fn pty_request(
        &mut self,
        _: ChannelId,
        _: &str,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: &[(russh::Pty, u32)],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.seen.lock().unwrap().pty += 1;
        Ok(())
    }
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        command: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.seen.lock().unwrap().commands.push(command.to_vec());
        session.channel_success(channel)?;
        Ok(())
    }
    async fn data(
        &mut self,
        _: ChannelId,
        bytes: &[u8],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.input.extend_from_slice(bytes);
        Ok(())
    }
    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.seen.lock().unwrap().input.push(self.input.clone());
        let request = RpcRequest::parse(&self.input).unwrap();
        let response = RpcResponse {
            version: 1,
            request_id: if matches!(self.reply, Reply::WrongId) {
                uuid::Uuid::new_v4()
            } else {
                request.request_id
            },
            pc_id: request.pc_id,
            ok: true,
            result: Some(RpcResult::Status(HostStatus {
                systemd_state: "active".into(),
                container_state: "running".into(),
                restart_count: 0,
                exit_code: None,
                staged_revision: None,
                running_revision: None,
                recovery_pending: false,
            })),
            error: None,
        };
        let mut value = serde_json::to_value(response).unwrap();
        if matches!(self.reply, Reply::ExtraField) {
            value["private_path"] = serde_json::json!("untrusted");
        }
        let bytes = if matches!(self.reply, Reply::Oversized) {
            vec![b'x'; 1024 * 1024 + 1]
        } else {
            serde_json::to_vec(&value).unwrap()
        };
        session.data(channel, bytes)?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}
struct ServerFixture {
    endpoint: Endpoint,
    seen: Arc<Mutex<Observations>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for ServerFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn server_fixture(pc: PcId, authorized: PublicKey, reply: Reply) -> ServerFixture {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let host = PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
    let endpoint = Endpoint {
        pc_id: pc,
        host: "127.0.0.1".into(),
        port: listener.local_addr().unwrap().port(),
        user: "wolf-manager".into(),
        host_key_algorithm: Some(host.algorithm().to_string()),
        host_key_public: Some(host.public_key().to_openssh().unwrap()),
        host_key_fingerprint: Some(host.public_key().fingerprint(HashAlg::Sha256).to_string()),
    };
    let config = Arc::new(server::Config {
        keys: vec![host],
        auth_rejection_time: std::time::Duration::ZERO,
        inactivity_timeout: Some(std::time::Duration::from_secs(5)),
        ..Default::default()
    });
    let seen = Arc::new(Mutex::new(Observations::default()));
    let shared = seen.clone();
    let task = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let handler = FixtureHandler {
                seen: shared.clone(),
                authorized: authorized.clone(),
                input: Vec::new(),
                reply,
            };
            let config = config.clone();
            tokio::spawn(async move {
                if let Ok(session) = server::run_stream(config, socket, handler).await {
                    let _ = session.await;
                }
            });
        }
    });
    ServerFixture {
        endpoint,
        seen,
        task,
    }
}
fn status_request(pc: PcId) -> RpcRequest {
    RpcRequest {
        version: 1,
        request_id: uuid::Uuid::new_v4(),
        pc_id: pc,
        operation: RpcOperation::Status(EmptyPayload {}),
    }
}
#[tokio::test]
async fn probe_and_mismatched_host_key_never_authenticate_or_execute() {
    let (root, pc) = fixture();
    let public = PublicKey::from_openssh(&ensure_identity(root.path(), &pc).unwrap()).unwrap();
    let server = server_fixture(pc, public, Reply::Valid).await;
    let observed = ssh::probe(&server.endpoint).await.unwrap();
    assert_eq!(
        Some(&observed.fingerprint),
        server.endpoint.host_key_fingerprint.as_ref()
    );
    assert_eq!(server.seen.lock().unwrap().auth, 0);
    let wrong = PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
    let mut endpoint = server.endpoint.clone();
    endpoint.host_key_public = Some(wrong.public_key().to_openssh().unwrap());
    endpoint.host_key_fingerprint =
        Some(wrong.public_key().fingerprint(HashAlg::Sha256).to_string());
    assert!(ssh::connect(&endpoint, root.path()).await.is_err());
    let seen = server.seen.lock().unwrap();
    assert_eq!(seen.auth, 0);
    assert!(seen.commands.is_empty());
}
#[tokio::test]
async fn rpc_uses_exact_forced_command_stdin_eof_and_no_pty() {
    let (root, pc) = fixture();
    let public = PublicKey::from_openssh(&ensure_identity(root.path(), &pc).unwrap()).unwrap();
    let server = server_fixture(pc.clone(), public, Reply::Valid).await;
    let mut ready = ssh::connect(&server.endpoint, root.path()).await.unwrap();
    let request = status_request(pc);
    let response = ready.execute(&request).await.unwrap();
    response.validate_for(&request).unwrap();
    let seen = server.seen.lock().unwrap();
    assert!(seen.auth > 0);
    assert_eq!(seen.commands, vec![b"wolf-manager-rpc-v1".to_vec()]);
    assert_eq!(seen.input, vec![serde_json::to_vec(&request).unwrap()]);
    assert_eq!(seen.pty, 0);
}
#[tokio::test]
async fn wrong_identity_extra_fields_and_large_output_are_refused_without_retry() {
    for reply in [Reply::WrongId, Reply::ExtraField, Reply::Oversized] {
        let (root, pc) = fixture();
        let public = PublicKey::from_openssh(&ensure_identity(root.path(), &pc).unwrap()).unwrap();
        let server = server_fixture(pc.clone(), public, reply).await;
        let mut ready = ssh::connect(&server.endpoint, root.path()).await.unwrap();
        assert!(ready.execute(&status_request(pc)).await.is_err());
        assert_eq!(server.seen.lock().unwrap().commands.len(), 1);
    }
}
#[tokio::test]
async fn missing_or_inconsistent_enrollment_and_cross_pc_requests_are_refused() {
    let (root, pc) = fixture();
    let public = PublicKey::from_openssh(&ensure_identity(root.path(), &pc).unwrap()).unwrap();
    let server = server_fixture(pc, public, Reply::Valid).await;
    let mut missing = server.endpoint.clone();
    missing.host_key_fingerprint = None;
    assert!(ssh::connect(&missing, root.path()).await.is_err());
    let mut inconsistent = server.endpoint.clone();
    inconsistent.host_key_algorithm = Some("ssh-rsa".into());
    assert!(ssh::connect(&inconsistent, root.path()).await.is_err());
    assert_eq!(server.seen.lock().unwrap().auth, 0);
    let mut ready = ssh::connect(&server.endpoint, root.path()).await.unwrap();
    assert!(
        ready
            .execute(&status_request(PcId::new("another-pc").unwrap()))
            .await
            .is_err()
    );
    assert!(server.seen.lock().unwrap().commands.is_empty());
}
#[test]
fn malformed_existing_identity_is_preserved_and_refused() {
    let (root, pc) = fixture();
    ensure_identity(root.path(), &pc).unwrap();
    let key = root.path().join("keys/gaming-pc/id_ed25519");
    fs::write(&key, b"damaged identity requiring operator recovery").unwrap();
    assert!(ensure_identity(root.path(), &pc).is_err());
    assert_eq!(
        fs::read(&key).unwrap(),
        b"damaged identity requiring operator recovery"
    );
}
