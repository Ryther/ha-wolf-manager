//! Native SSH fixture adapted from the existing wire-contract tests.
use russh::{
    Channel, ChannelId,
    keys::{Algorithm, HashAlg, PrivateKey, PublicKey},
    server::{self, Msg, Session},
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
#[derive(Default)]
pub struct Gate {
    pub hold: AtomicBool,
    pub entered: AtomicUsize,
    pub release: tokio::sync::Notify,
}
use wolf_core::{HostCapabilities, HostStatus, RpcOperation, RpcRequest, RpcResponse, RpcResult};
#[derive(Default)]
pub struct Observations {
    pub authorized: Option<PublicKey>,
    pub commands: Vec<Vec<u8>>,
    pub requests: Vec<RpcRequest>,
    pub pty: usize,
}
pub struct Fixture {
    pub port: u16,
    pub fingerprint: String,
    pub seen: Arc<Mutex<Observations>>,
    pub gate: Arc<Gate>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
struct Handler {
    seen: Arc<Mutex<Observations>>,
    input: Vec<u8>,
    accepted: bool,
    gate: Arc<Gate>,
}
impl server::Handler for Handler {
    type Error = russh::Error;
    async fn auth_none(&mut self, _: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::reject())
    }
    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        key: &PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        self.auth_publickey(user, key).await
    }
    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        Ok(
            if user == "wolf-manager"
                && self
                    .seen
                    .lock()
                    .unwrap()
                    .authorized
                    .as_ref()
                    .is_some_and(|allowed| allowed.key_data() == key.key_data())
            {
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
        assert_eq!(command, b"wolf-manager-rpc-v1");
        self.accepted = true;
        session.channel_success(channel)?;
        Ok(())
    }
    async fn data(
        &mut self,
        _: ChannelId,
        bytes: &[u8],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        assert!(self.accepted);
        assert!(self.input.len() + bytes.len() <= 65536);
        self.input.extend_from_slice(bytes);
        Ok(())
    }
    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let request = RpcRequest::parse(&self.input).unwrap();
        if matches!(request.operation, RpcOperation::Preflight(_))
            && self.gate.hold.load(Ordering::Acquire)
        {
            let released = self.gate.release.notified();
            self.gate.entered.fetch_add(1, Ordering::Release);
            released.await;
        }
        let result = match request.operation {
            RpcOperation::Preflight(_) => RpcResult::Preflight(HostCapabilities {
                version: 1,
                pc_id: request.pc_id.clone(),
                ready: true,
                proton_cachyos: false,
                reasons: vec![],
            }),
            RpcOperation::Status(_) => RpcResult::Status(HostStatus {
                systemd_state: "inactive".into(),
                container_state: "missing".into(),
                restart_count: 0,
                exit_code: None,
                staged_revision: None,
                running_revision: None,
                recovery_pending: false,
            }),
            _ => panic!("fixture accepts only read-only preflight/status"),
        };
        let response = RpcResponse {
            version: 1,
            request_id: request.request_id,
            pc_id: request.pc_id.clone(),
            ok: true,
            result: Some(result),
            error: None,
        };
        self.seen.lock().unwrap().requests.push(request);
        session.data(channel, serde_json::to_vec(&response).unwrap())?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}
pub async fn start() -> Fixture {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let key = PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
    let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();
    let config = Arc::new(server::Config {
        keys: vec![key],
        auth_rejection_time: std::time::Duration::ZERO,
        ..Default::default()
    });
    let seen = Arc::new(Mutex::new(Observations::default()));
    let shared = seen.clone();
    let gate = Arc::new(Gate::default());
    let shared_gate = gate.clone();
    let task = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let handler = Handler {
                seen: shared.clone(),
                input: vec![],
                accepted: false,
                gate: shared_gate.clone(),
            };
            let config = config.clone();
            tokio::spawn(async move {
                if let Ok(session) = server::run_stream(config, socket, handler).await {
                    let _ = session.await;
                }
            });
        }
    });
    Fixture {
        port,
        fingerprint,
        seen,
        gate,
        task,
    }
}
