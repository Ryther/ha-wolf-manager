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
        Arc, Mutex,
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
    script: Option<Script>,
    calls: Arc<Mutex<Vec<RpcRequest>>>,
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
        let request = RpcRequest::parse(&std::mem::take(&mut self.input)).unwrap();
        if let Some(script) = self.script {
            return scripted_reply(script, &request, &self.calls, &self.database, c, s);
        }
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
                script: None,
                calls: Arc::new(Mutex::new(Vec::new())),
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

#[derive(Clone, Copy)]
enum JournalReply {
    Succeeded,
    Failed,
    Missing,
    WrongDigest,
}
#[derive(Clone, Copy)]
enum Script {
    Success,
    WrongStage,
    FailedStage,
    CrashLifecycle(JournalReply),
}
fn lifecycle_result(request: &RpcRequest) -> RpcResult {
    let revision = match &request.operation {
        RpcOperation::Start(p) | RpcOperation::Restart(p) => {
            Some(p.expected_staged_revision.clone())
        }
        _ => None,
    };
    RpcResult::Lifecycle(HostStatus {
        systemd_state: "active".into(),
        container_state: "running".into(),
        restart_count: 0,
        exit_code: None,
        staged_revision: revision.clone(),
        running_revision: revision,
        recovery_pending: false,
    })
}
fn scripted_reply(
    script: Script,
    request: &RpcRequest,
    calls: &Mutex<Vec<RpcRequest>>,
    database: &std::path::Path,
    channel: ChannelId,
    session: &mut Session,
) -> Result<(), russh::Error> {
    let mut ledger = calls.lock().unwrap();
    // The remote effect must never precede the manager's durable dispatch record.
    if !matches!(request.operation, RpcOperation::RequestStatus(_)) {
        let db = rusqlite::Connection::open(database).unwrap();
        let phase: String = db
            .query_row(
                "SELECT dispatch_phase FROM operation_rpc_requests WHERE request_id=?1",
                [request.request_id.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(phase, "sending");
    }
    ledger.push(request.clone());
    let result = match &request.operation {
        RpcOperation::ApplySettings(payload) => {
            if matches!(script, Script::FailedStage) {
                let response = RpcResponse {
                    version: 1,
                    request_id: request.request_id,
                    pc_id: request.pc_id.clone(),
                    ok: false,
                    result: None,
                    error: Some(SafeError::new("recovery_pending")),
                };
                session.data(channel, serde_json::to_vec(&response).unwrap())?;
                session.exit_status_request(channel, 0)?;
                session.eof(channel)?;
                session.close(channel)?;
                return Ok(());
            }
            RpcResult::Applied {
                staged_revision: if matches!(script, Script::WrongStage) {
                    Revision::new("0".repeat(64)).unwrap()
                } else {
                    payload.revision.clone()
                },
            }
        }
        RpcOperation::Start(_) | RpcOperation::Restart(_) | RpcOperation::Stop(_) => {
            if matches!(script, Script::CrashLifecycle(_)) {
                // Model a committed remote effect followed by lost completion bytes.
                session.close(channel)?;
                return Ok(());
            }
            lifecycle_result(request)
        }
        RpcOperation::RequestStatus(payload) => {
            let original = ledger
                .iter()
                .find(|r| r.request_id == payload.original_request_id)
                .unwrap();
            let mode = match script {
                Script::CrashLifecycle(mode) => mode,
                _ => panic!("unexpected reconciliation"),
            };
            // The stage was acknowledged before the later lifecycle crash;
            // preserve that truthful terminal evidence in every recovery case.
            let mode = if matches!(original.operation, RpcOperation::ApplySettings(_)) {
                JournalReply::Succeeded
            } else {
                mode
            };
            let found = !matches!(mode, JournalReply::Missing);
            RpcResult::RequestStatus(JournalObservation {
                found,
                request_id: original.request_id,
                pc_id: original.pc_id.clone(),
                canonical_request_sha256: if found {
                    Some(if matches!(mode, JournalReply::WrongDigest) {
                        Revision::new("0".repeat(64)).unwrap()
                    } else {
                        original.digest().unwrap()
                    })
                } else {
                    None
                },
                phase: if found {
                    Some(if matches!(mode, JournalReply::Failed) {
                        JournalPhase::Failed
                    } else {
                        JournalPhase::Succeeded
                    })
                } else {
                    None
                },
                observed_at_ms: 100,
                result: if found && !matches!(mode, JournalReply::Failed) {
                    Some(Box::new(match &original.operation {
                        RpcOperation::ApplySettings(p) => RpcResult::Applied {
                            staged_revision: p.revision.clone(),
                        },
                        _ => lifecycle_result(original),
                    }))
                } else {
                    None
                },
                error: if matches!(mode, JournalReply::Failed) {
                    Some(SafeError::new("recovery_pending"))
                } else {
                    None
                },
            })
        }
        _ => panic!("unexpected request in lifecycle fixture"),
    };
    drop(ledger);
    let response = RpcResponse {
        version: 1,
        request_id: request.request_id,
        pc_id: request.pc_id.clone(),
        ok: true,
        result: Some(result),
        error: None,
    };
    session.data(channel, serde_json::to_vec(&response).unwrap())?;
    session.exit_status_request(channel, 0)?;
    session.eof(channel)?;
    session.close(channel)?;
    Ok(())
}

struct NativeFixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    pc: PcId,
    state: AppState,
    calls: Arc<Mutex<Vec<RpcRequest>>>,
    server: tokio::task::JoinHandle<()>,
    port: u16,
}
impl Drop for NativeFixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl NativeFixture {
    async fn new(script: Script) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("data");
        let pc = PcId::new("pc").unwrap();
        let mut store = Store::open(&root, 0).unwrap();
        store
            .add_pc(
                PcInput {
                    pc_id: pc.clone(),
                    display_name: "Test PC".into(),
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
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let host =
            PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
        let config = Arc::new(server::Config {
            keys: vec![host],
            auth_rejection_time: std::time::Duration::ZERO,
            inactivity_timeout: Some(std::time::Duration::from_secs(5)),
            ..Default::default()
        });
        let calls = Arc::new(Mutex::new(Vec::new()));
        let database = root.join("manager.sqlite3");
        let shared = calls.clone();
        let server = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let handler = Handler {
                    authorized: authorized.clone(),
                    input: Vec::new(),
                    database: database.clone(),
                    submitted: Arc::new(AtomicUsize::new(0)),
                    error: None,
                    script: Some(script),
                    calls: shared.clone(),
                };
                let config = config.clone();
                tokio::spawn(async move {
                    if let Ok(session) = server::run_stream(config, socket, handler).await {
                        let _ = session.await;
                    }
                });
            }
        });
        let mut fixture = Self {
            _directory: directory,
            root,
            pc,
            state,
            calls,
            server,
            port,
        };
        fixture.change_port(port).await;
        let probe = fixture.state.probe_host(&fixture.pc).await.unwrap();
        fixture
            .state
            .enroll(
                &fixture.pc,
                serde_json::from_value(probe["probe_id"].clone()).unwrap(),
                probe["fingerprint"].as_str().unwrap().into(),
            )
            .await
            .unwrap();
        fixture
    }
    async fn change_port(&mut self, port: u16) {
        let pc = self.pc.clone();
        self.state
            .blocking(move |s| {
                s.update_pc(
                    PcInput {
                        pc_id: pc,
                        display_name: "Test PC".into(),
                        ssh_host: "127.0.0.1".into(),
                        ssh_port: port,
                        ssh_user: "wolf-manager".into(),
                    },
                    1,
                )
            })
            .await
            .unwrap();
    }
    async fn submit(&self, kind: OperationKind) -> uuid::Uuid {
        let pc = self.pc.clone();
        let revision = self
            .state
            .blocking(move |s| s.settings(&pc)?.revision())
            .await
            .unwrap();
        self.state
            .submit(self.pc.clone(), kind, Some(revision))
            .await
            .unwrap()
    }
    async fn wait(&self, id: uuid::Uuid) -> OperationState {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let outcome = self
                    .state
                    .blocking(move |s| s.operation_state(id))
                    .await
                    .unwrap();
                if !matches!(outcome, OperationState::Queued | OperationState::Running) {
                    return outcome;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("operation must finish or become explicitly uncertain")
    }
    fn requests(&self) -> Vec<RpcRequest> {
        self.calls.lock().unwrap().clone()
    }
    async fn reopen(&mut self) {
        // Drop the old runtime before opening the same protected state directory.
        // Its spawned admission task may still be releasing its final Arc.
        let placeholder = self.root.with_file_name("closed-runtime-placeholder");
        let old = std::mem::replace(
            &mut self.state,
            AppState::new(
                Store::open(&placeholder, 200).unwrap(),
                placeholder,
                Deployment::Ingress,
                TransportPolicy::Ingress,
            ),
        );
        drop(old);
        let store = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match Store::open(&self.root, 200) {
                    Ok(store) => break store,
                    Err(error) if error.code() == ErrorCode::OperationInProgress => {
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await
                    }
                    Err(error) => panic!("cannot reopen fixture: {error:?}"),
                }
            }
        })
        .await
        .expect("previous runtime must release its state lock");
        self.state = AppState::new(
            store,
            self.root.clone(),
            Deployment::Ingress,
            TransportPolicy::Ingress,
        );
    }
}

#[tokio::test]
async fn native_start_and_restart_stage_before_lifecycle_and_never_repeat_effects() {
    for kind in [OperationKind::Start, OperationKind::Restart] {
        let fixture = NativeFixture::new(Script::Success).await;
        let operation = fixture.submit(kind).await;
        assert_eq!(fixture.wait(operation).await, OperationState::Succeeded);
        let calls = fixture.requests();
        assert_eq!(calls.len(), 2);
        let staged = match &calls[0].operation {
            RpcOperation::ApplySettings(p) => p.revision.clone(),
            _ => panic!("stage must precede lifecycle"),
        };
        match &calls[1].operation {
            RpcOperation::Start(p) | RpcOperation::Restart(p) => {
                assert_eq!(p.expected_staged_revision, staged)
            }
            _ => panic!("expected lifecycle"),
        }
        assert!(fixture.state.run_operation(operation).await.is_err());
        assert_eq!(fixture.requests(), calls);
    }
}

#[tokio::test]
async fn incorrect_or_failed_stage_ack_never_sends_lifecycle() {
    for (script, expected) in [
        (Script::WrongStage, OperationState::UnknownInterrupted),
        (Script::FailedStage, OperationState::Failed),
    ] {
        let fixture = NativeFixture::new(script).await;
        let operation = fixture.submit(OperationKind::Start).await;
        assert_eq!(fixture.wait(operation).await, expected);
        assert_eq!(fixture.requests().len(), 1);
        assert!(matches!(
            fixture.requests()[0].operation,
            RpcOperation::ApplySettings(_)
        ));
        assert!(fixture.state.run_operation(operation).await.is_err());
        assert_eq!(fixture.requests().len(), 1);
    }
}

#[tokio::test]
async fn native_reconciliation_after_restart_reads_exact_journal_without_replaying_mutations() {
    for (mode, expected) in [
        (JournalReply::Succeeded, OperationState::Succeeded),
        (JournalReply::Failed, OperationState::Failed),
    ] {
        let mut fixture = NativeFixture::new(Script::CrashLifecycle(mode)).await;
        let operation = fixture.submit(OperationKind::Start).await;
        assert_eq!(
            fixture.wait(operation).await,
            OperationState::UnknownInterrupted
        );
        let submitted = fixture.requests();
        assert_eq!(submitted.len(), 2);
        fixture.reopen().await;
        let resolution = fixture.state.reconcile(operation).await.unwrap();
        assert_eq!(resolution.state, expected);
        assert!(resolution.stage_succeeded);
        let calls = fixture.requests();
        assert_eq!(&calls[..2], submitted.as_slice());
        assert_eq!(calls.len(), 4);
        for (read, original) in calls[2..].iter().zip(&submitted) {
            match &read.operation {
                RpcOperation::RequestStatus(p) => {
                    assert_eq!(p.original_request_id, original.request_id)
                }
                _ => panic!("recovery may only query journals"),
            }
        }
        let subsequent = fixture
            .state
            .submit(fixture.pc.clone(), OperationKind::Stop, None)
            .await;
        assert!(
            subsequent.is_ok(),
            "verified terminal outcome must unblock admission"
        );
        assert_eq!(
            fixture.wait(subsequent.unwrap()).await,
            OperationState::UnknownInterrupted
        );
    }
}

#[tokio::test]
async fn missing_or_mismatched_journal_keeps_interrupted_pc_blocked_without_replay() {
    for mode in [JournalReply::Missing, JournalReply::WrongDigest] {
        let mut fixture = NativeFixture::new(Script::CrashLifecycle(mode)).await;
        let operation = fixture.submit(OperationKind::Start).await;
        assert_eq!(
            fixture.wait(operation).await,
            OperationState::UnknownInterrupted
        );
        fixture.reopen().await;
        let _ = fixture.state.reconcile(operation).await;
        assert_eq!(
            fixture.wait(operation).await,
            OperationState::UnknownInterrupted
        );
        let before = fixture.requests();
        assert_eq!(
            before
                .iter()
                .filter(|r| !matches!(r.operation, RpcOperation::RequestStatus(_)))
                .count(),
            2
        );
        assert!(
            fixture
                .state
                .submit(fixture.pc.clone(), OperationKind::Stop, None)
                .await
                .is_err()
        );
        assert_eq!(fixture.requests(), before);
    }
}

#[tokio::test]
async fn unreachable_host_is_rejected_before_dispatch_and_later_admission_is_allowed() {
    let mut fixture = NativeFixture::new(Script::Success).await;
    let unused = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed = unused.local_addr().unwrap().port();
    drop(unused);
    fixture.change_port(closed).await;
    let operation = fixture.submit(OperationKind::Start).await;
    assert_eq!(fixture.wait(operation).await, OperationState::Rejected);
    assert!(fixture.requests().is_empty());
    let children = fixture
        .state
        .blocking(move |s| s.operation_children(operation))
        .await
        .unwrap();
    assert!(
        children
            .iter()
            .all(|c| c.dispatch_phase == DispatchPhase::NotDispatched)
    );
    fixture.change_port(fixture.port).await;
    // Endpoint changes require fresh explicit host-key enrollment.
    let probe = fixture.state.probe_host(&fixture.pc).await.unwrap();
    fixture
        .state
        .enroll(
            &fixture.pc,
            serde_json::from_value(probe["probe_id"].clone()).unwrap(),
            probe["fingerprint"].as_str().unwrap().into(),
        )
        .await
        .unwrap();
    let next = fixture.submit(OperationKind::Start).await;
    assert_eq!(fixture.wait(next).await, OperationState::Succeeded);
    assert_eq!(fixture.requests().len(), 2);
}

#[tokio::test]
async fn stale_revision_and_mutating_read_rpc_are_rejected_without_durable_work_or_remote_effects()
{
    let fixture = NativeFixture::new(Script::Success).await;
    let error = fixture
        .state
        .submit(
            fixture.pc.clone(),
            OperationKind::Start,
            Some(Revision::new("0".repeat(64)).unwrap()),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::StaleRevision);
    let error = fixture
        .state
        .read_rpc(&fixture.pc, RpcOperation::Stop(EmptyPayload {}))
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::ValidationFailed);
    let pc = fixture.pc.clone();
    let page = fixture
        .state
        .blocking(move |s| s.operation_page(&pc, 20, None))
        .await
        .unwrap();
    assert!(page.operations.is_empty());
    assert!(fixture.requests().is_empty());
}
