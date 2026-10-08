//! Disposable native SSH evidence; no household host is contacted.
use ha_wolf_manager::{
    api::{AppState, Deployment},
    auth::TransportPolicy,
    domain::PcInput,
    store::Store,
};
use russh::{
    Channel, ChannelId,
    keys::{Algorithm, PrivateKey, PublicKey},
    server::{self, Msg, Session},
};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use wolf_core::*;
#[derive(Clone)]
struct Handler {
    authorized: PublicKey,
    input: Vec<u8>,
    database: PathBuf,
    submitted: Arc<AtomicUsize>,
    error: Option<ErrorCode>,
}
impl server::Handler for Handler {
    type Error = russh::Error;
    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        key: &PublicKey,
    ) -> Result<server::Auth, Self::Error> {
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
        self.auth_publickey_offered(user, key).await
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
    async fn exec_request(
        &mut self,
        c: ChannelId,
        command: &[u8],
        s: &mut Session,
    ) -> Result<(), Self::Error> {
        assert_eq!(command, b"wolf-manager-rpc-v1");
        s.channel_success(c)?;
        Ok(())
    }
    async fn data(
        &mut self,
        _: ChannelId,
        data: &[u8],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.input.extend_from_slice(data);
        Ok(())
    }
    async fn channel_eof(&mut self, c: ChannelId, s: &mut Session) -> Result<(), Self::Error> {
        let request = RpcRequest::parse(&self.input).unwrap();
        let db = rusqlite::Connection::open(&self.database).unwrap();
        let phase: String = db
            .query_row(
                "SELECT dispatch_phase FROM operation_rpc_requests WHERE request_id=?1",
                [request.request_id.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(phase, "sending");
        self.submitted.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = self.error {
            let response = RpcResponse {
                version: 1,
                request_id: request.request_id,
                pc_id: request.pc_id,
                ok: false,
                result: None,
                error: Some(SafeError::from_code(error)),
            };
            s.data(c, serde_json::to_vec(&response).unwrap())?;
            s.exit_status_request(c, 0)?;
            s.eof(c)?;
        }
        s.close(c)?;
        Ok(())
    }
}
async fn exercise(error: Option<ErrorCode>, expected: OperationState) {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("data");
    let mut store = Store::open(&root, 0).unwrap();
    let pc = PcId::new("pc").unwrap();
    store
        .add_pc(
            PcInput {
                pc_id: pc.clone(),
                display_name: "PC".into(),
                ssh_host: "127.0.0.1".into(),
                ssh_port: 1,
                ssh_user: "wolf-manager".into(),
            },
            0,
        )
        .unwrap();
    let state = AppState::new(
        store,
        root.clone(),
        Deployment::Ingress,
        TransportPolicy::Ingress,
    );
    let authorized = PublicKey::from_openssh(&state.public_key(&pc).await.unwrap()).unwrap();
    let host = PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let shared = count.clone();
    let database = root.join("manager.sqlite3");
    let config = Arc::new(server::Config {
        keys: vec![host],
        auth_rejection_time: std::time::Duration::ZERO,
        inactivity_timeout: Some(std::time::Duration::from_secs(5)),
        ..Default::default()
    });
    let server = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let handler = Handler {
                authorized: authorized.clone(),
                input: Vec::new(),
                database: database.clone(),
                submitted: shared.clone(),
                error,
            };
            let config = config.clone();
            tokio::spawn(async move {
                if let Ok(session) = server::run_stream(config, socket, handler).await {
                    let _ = session.await;
                }
            });
        }
    });
    let id = pc.clone();
    state
        .blocking(move |s| {
            s.update_pc(
                PcInput {
                    pc_id: id,
                    display_name: "PC".into(),
                    ssh_host: "127.0.0.1".into(),
                    ssh_port: port,
                    ssh_user: "wolf-manager".into(),
                },
                1,
            )
        })
        .await
        .unwrap();
    let probe = state.probe_host(&pc).await.unwrap();
    state
        .enroll(
            &pc,
            serde_json::from_value(probe["probe_id"].clone()).unwrap(),
            probe["fingerprint"].as_str().unwrap().into(),
        )
        .await
        .unwrap();
    let request = RpcRequest {
        version: 1,
        request_id: uuid::Uuid::new_v4(),
        pc_id: pc.clone(),
        operation: RpcOperation::Stop(EmptyPayload {}),
    };
    let operation = state
        .blocking(move |s| s.enqueue_operation(&pc, OperationKind::Stop, None, &[request], 2))
        .await
        .unwrap();
    let outcome = state.run_operation(operation).await;
    assert_eq!(outcome.is_ok(), expected == OperationState::Failed);
    assert_eq!(
        state
            .blocking(move |s| s.operation_state(operation))
            .await
            .unwrap(),
        expected
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert!(state.run_operation(operation).await.is_err());
    assert_eq!(count.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn native_submission_is_durable_and_uncertainty_never_replays() {
    exercise(None, OperationState::UnknownInterrupted).await;
}
#[tokio::test]
async fn explicit_unknown_response_never_unblocks_a_mutation() {
    exercise(
        Some(ErrorCode::UnknownInterrupted),
        OperationState::UnknownInterrupted,
    )
    .await;
}

#[tokio::test]
async fn ordinary_terminal_safe_error_resolves_failed_without_replay() {
    exercise(Some(ErrorCode::RecoveryPending), OperationState::Failed).await;
}
