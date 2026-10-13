//! One-shot SSH coordinator. Authenticate before marking a child sending; never retry.
use crate::{
    api::{AppState, now},
    domain::ensure_pc,
    protected::internal,
    ssh::{self, Endpoint, Probe},
};
use rusqlite::params;
use std::time::Instant;
use uuid::Uuid;
use wolf_core::*;
#[derive(Clone)]
pub(crate) struct PendingProbe {
    pub endpoint: Endpoint,
    pub probe: Probe,
    pub expires_at: i64,
}
fn recorded_identity(
    s: &crate::store::Store,
    data: &std::path::Path,
    pc: &PcId,
) -> Result<Option<String>, SafeError> {
    ensure_pc(&s.conn, pc)?;
    let (expected, host_enrolled): (Option<String>, bool) = s.conn.query_row(
        "SELECT enrolled_public_key,host_key_algorithm IS NOT NULL OR host_key_public IS NOT NULL OR host_key_fingerprint IS NOT NULL FROM pcs WHERE pc_id=?1",
        [pc.as_str()], |row| Ok((row.get(0)?, row.get(1)?))).map_err(internal)?;
    let actual = ssh::identity_public_key(data, pc)?;
    if actual.is_none() && (expected.is_some() || host_enrolled) {
        return Err(SafeError::new("forbidden"));
    }
    if let (Some(expected), Some(actual)) = (expected, actual.as_deref()) {
        let expected = russh::keys::PublicKey::from_openssh(&expected)
            .map_err(|_| SafeError::new("forbidden"))?;
        let actual = russh::keys::PublicKey::from_openssh(actual)
            .map_err(|_| SafeError::new("forbidden"))?;
        if expected.key_data() != actual.key_data() {
            return Err(SafeError::new("forbidden"));
        }
    }
    Ok(actual)
}
impl AppState {
    pub async fn endpoint(&self, pc: &PcId) -> Result<Endpoint, SafeError> {
        let pc = pc.clone();
        self.blocking(move|s|{s.root.verify()?;ensure_pc(&s.conn,&pc)?;s.conn.query_row("SELECT ssh_host,ssh_port,ssh_user,host_key_algorithm,host_key_public,host_key_fingerprint FROM pcs WHERE pc_id=?1",[pc.as_str()],|r|Ok(Endpoint{pc_id:pc.clone(),host:r.get(0)?,port:r.get(1)?,user:r.get(2)?,host_key_algorithm:r.get(3)?,host_key_public:r.get(4)?,host_key_fingerprint:r.get(5)?})).map_err(internal)}).await
    }
    async fn observe_verified(
        &self,
        endpoint: &Endpoint,
        result: RpcResult,
    ) -> Result<bool, SafeError> {
        let endpoint = endpoint.clone();
        let state = self.clone();
        self.blocking(move|s|{
            s.root.verify()?;ensure_pc(&s.conn,&endpoint.pc_id)?;
            let current:(String,u16,String,Option<String>,Option<String>,Option<String>)=s.conn.query_row("SELECT ssh_host,ssh_port,ssh_user,host_key_algorithm,host_key_public,host_key_fingerprint FROM pcs WHERE pc_id=?1",[endpoint.pc_id.as_str()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).map_err(internal)?;
            if current!=(endpoint.host,endpoint.port,endpoint.user,endpoint.host_key_algorithm,endpoint.host_key_public,endpoint.host_key_fingerprint){return Ok(false);}
            state.observe_result(&endpoint.pc_id,&result)?;Ok(true)
        }).await
    }
    pub async fn public_key(&self, pc: &PcId) -> Result<String, SafeError> {
        self.endpoint(pc).await?;
        let data = self.data.clone();
        let pc = pc.clone();
        self.blocking(move |s| {
            s.root.verify()?;
            let key = match recorded_identity(s, &data, &pc)? {
                Some(public) => public,
                None => ssh::ensure_identity(&data, &pc)?,
            };
            s.conn
                .execute(
                    "UPDATE pcs SET enrolled_public_key=?1 WHERE pc_id=?2",
                    params![key, pc.as_str()],
                )
                .map_err(internal)?;
            Ok(key)
        })
        .await
    }
    pub async fn identity_public_key(&self, pc: &PcId) -> Result<Option<String>, SafeError> {
        let data = self.data.clone();
        let pc = pc.clone();
        self.blocking(move |s| {
            s.root.verify()?;
            ensure_pc(&s.conn, &pc)?;
            recorded_identity(s, &data, &pc)
        })
        .await
    }
    pub async fn import_identity(
        &self,
        pc: &PcId,
        private: String,
        public: Option<String>,
    ) -> Result<String, SafeError> {
        let data = self.data.clone();
        let pc = pc.clone();
        let mut private = private.into_bytes();
        self.blocking(move |s| {
            let result = (|| {
                s.root.verify()?;
                ensure_pc(&s.conn, &pc)?;
                let active: i64 = s.conn.query_row("SELECT count(*) FROM operations WHERE pc_id=?1 AND state IN ('queued','running','unknown_interrupted')", [pc.as_str()], |r| r.get(0)).map_err(internal)?;
                if active != 0 { return Err(SafeError::new("operation_in_progress")); }
                let enrolled: bool = s.conn.query_row("SELECT host_key_public IS NOT NULL FROM pcs WHERE pc_id=?1", [pc.as_str()], |r| r.get(0)).map_err(internal)?;
                if enrolled { return Err(SafeError::new("forbidden")); }
                recorded_identity(s, &data, &pc)?;
                let key = ssh::import_identity(&data, &pc, std::str::from_utf8(&private).map_err(|_| SafeError::validation())?, public.as_deref())?;
                s.conn.execute("UPDATE pcs SET enrolled_public_key=?1 WHERE pc_id=?2", params![key, pc.as_str()]).map_err(internal)?;
                Ok(key)
            })();
            // Erase the request buffer once parsing/storage finishes; never expose it in errors.
            private.fill(0);
            result
        }).await
    }
    pub async fn probe_host(&self, pc: &PcId) -> Result<serde_json::Value, SafeError> {
        let endpoint = self.endpoint(pc).await?;
        let probe = ssh::probe(&endpoint)
            .await
            .map_err(|_| SafeError::new("host_unavailable"))?;
        let id = Uuid::new_v4();
        let expires_at = now() + 5 * 60 * 1000;
        let mut map = self.probes.lock().map_err(internal)?;
        map.retain(|_, p| p.expires_at > now());
        if map.len() >= 1024 {
            return Err(SafeError::new("busy"));
        }
        map.insert(
            id,
            PendingProbe {
                endpoint,
                probe: probe.clone(),
                expires_at,
            },
        );
        Ok(
            serde_json::json!({"probe_id":id,"algorithm":probe.algorithm,"fingerprint":probe.fingerprint,"expires_at":expires_at}),
        )
    }
    pub async fn enroll(&self, pc: &PcId, id: Uuid, fingerprint: String) -> Result<(), SafeError> {
        let pending = self
            .probes
            .lock()
            .map_err(internal)?
            .remove(&id)
            .ok_or_else(|| SafeError::new("host_key_mismatch"))?;
        if pending.expires_at <= now()
            || pending.endpoint.pc_id != *pc
            || pending.probe.fingerprint != fingerprint
        {
            return Err(SafeError::new("host_key_mismatch"));
        }
        let current = self.endpoint(pc).await?;
        if !same_endpoint(&current, &pending.endpoint) {
            return Err(SafeError::new("host_key_mismatch"));
        }
        let pc = pc.clone();
        let data = self.data.clone();
        self.blocking(move|s|{s.root.verify()?;s.ensure_no_mutation(&pc)?;recorded_identity(s, &data, &pc)?.ok_or_else(SafeError::validation)?;if pending.expires_at<=now(){return Err(SafeError::new("host_key_mismatch"));}let changed=s.conn.execute("UPDATE pcs SET host_key_algorithm=?1,host_key_public=?2,host_key_fingerprint=?3,updated_at_ms=?4 WHERE pc_id=?5 AND ssh_host=?6 AND ssh_port=?7 AND ssh_user=?8 AND archived_at_ms IS NULL",params![pending.probe.algorithm,pending.probe.public_key,pending.probe.fingerprint,now(),pc.as_str(),pending.endpoint.host,pending.endpoint.port,pending.endpoint.user]).map_err(internal)?;if changed!=1{return Err(SafeError::new("host_key_mismatch"));}Ok(())}).await
    }
    pub async fn submit(
        &self,
        pc: PcId,
        kind: OperationKind,
        revision: Option<Revision>,
    ) -> Result<Uuid, SafeError> {
        if !self.accepting.load(std::sync::atomic::Ordering::Acquire) {
            return Err(SafeError::new("host_unavailable"));
        }
        let permit = self
            .tasks
            .clone()
            .try_acquire_owned()
            .map_err(|_| SafeError::new("busy"))?;
        self.endpoint(&pc).await?;
        let plan_pc = pc.clone();
        let id = self
            .blocking(move |s| {
                let request = |operation| RpcRequest {
                    version: 1,
                    request_id: Uuid::new_v4(),
                    pc_id: plan_pc.clone(),
                    operation,
                };
                let requests = match kind {
                    OperationKind::ApplySettings
                    | OperationKind::Start
                    | OperationKind::Restart => {
                        let settings = s.settings(&plan_pc)?;
                        let r = revision.clone().ok_or_else(SafeError::validation)?;
                        if settings.revision()? != r {
                            return Err(SafeError::new("stale_revision"));
                        }
                        let mut p =
                            vec![request(RpcOperation::ApplySettings(ApplySettingsPayload {
                                settings,
                                revision: r.clone(),
                            }))];
                        if kind == OperationKind::Start {
                            p.push(request(RpcOperation::Start(StartPayload {
                                expected_staged_revision: r,
                            })));
                        } else if kind == OperationKind::Restart {
                            p.push(request(RpcOperation::Restart(StartPayload {
                                expected_staged_revision: r,
                            })));
                        }
                        p
                    }
                    OperationKind::Stop => vec![request(RpcOperation::Stop(EmptyPayload {}))],
                    OperationKind::Preflight => {
                        vec![request(RpcOperation::Preflight(EmptyPayload {}))]
                    }
                    _ => return Err(SafeError::validation()),
                };
                s.enqueue_operation(&plan_pc, kind, revision.as_ref(), &requests, now())
            })
            .await?;
        tracing::info!(code="operation_admitted",kind=?kind,"Durable operation admitted");
        let state = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = state.run_operation(id).await {
                let _ = state.blocking(move |s| s.mark_interrupted(id, now())).await;
                tracing::warn!(code=%error.code(),kind=?kind,"Operation execution ended without normal completion");
            }
        });
        Ok(id)
    }
    pub async fn run_operation(&self, id: Uuid) -> Result<(), SafeError> {
        let started = Instant::now();
        let children = self.blocking(move |s| s.operation_children(id)).await?;
        let child_count = children.len();
        let pc = children
            .first()
            .ok_or_else(SafeError::validation)?
            .pc_id
            .clone();
        let endpoint = self.endpoint(&pc).await?;
        // Connection/authentication failures happen before sending; prove rejection rather than replay.
        let mut client = match ssh::connect(&endpoint, &self.data).await {
            Ok(c) => c,
            Err(_) => {
                self.blocking(move |s| {
                    s.mark_interrupted(id, now())?;
                    s.reconcile_operation(id, &[], now())?;
                    Ok(())
                })
                .await?;
                tracing::info!(
                    code = "operation_not_dispatched",
                    count = child_count,
                    duration_ms = started.elapsed().as_millis() as u64,
                    "Connection failure reconciled before dispatch"
                );
                return Ok(());
            }
        };
        for child in children {
            let request_id = child.request_id;
            let request = self
                .blocking(move |s| s.begin_dispatch(request_id, now()))
                .await?;
            let response = match client.execute(&request).await {
                Ok(r) => r,
                Err(_) => {
                    self.blocking(move |s| s.mark_interrupted(id, now()))
                        .await?;
                    tracing::warn!(
                        code = "unknown_interrupted",
                        count = child_count,
                        duration_ms = started.elapsed().as_millis() as u64,
                        "Dispatched RPC completion unavailable"
                    );
                    return Err(SafeError::new("unknown_interrupted"));
                }
            };
            if response
                .error
                .as_ref()
                .is_some_and(|e| e.code() == ErrorCode::UnknownInterrupted)
            {
                self.blocking(move |s| s.mark_interrupted(id, now()))
                    .await?;
                tracing::warn!(
                    code = "unknown_interrupted",
                    count = child_count,
                    duration_ms = started.elapsed().as_millis() as u64,
                    "Host reported an uncertain dispatched outcome"
                );
                return Err(SafeError::new("unknown_interrupted"));
            }
            if let Some(result) = &response.result {
                self.observe_verified(&endpoint, result.clone()).await?;
            }
            let failed = !response.ok;
            self.blocking(move |s| s.record_response(request_id, &response, now()))
                .await?;
            if failed {
                break;
            }
        }
        let resolution = self
            .blocking(move |s| s.finish_recorded_operation(id, now()))
            .await?;
        let code = match resolution.state {
            OperationState::Succeeded => "operation_succeeded",
            OperationState::Failed => "operation_failed",
            OperationState::Rejected => "operation_rejected",
            _ => "unknown_interrupted",
        };
        tracing::info!(
            code,
            count = child_count,
            duration_ms = started.elapsed().as_millis() as u64,
            "Durable operation completion recorded"
        );
        Ok(())
    }
    pub async fn read_rpc(
        &self,
        pc: &PcId,
        operation: RpcOperation,
    ) -> Result<RpcResult, SafeError> {
        if !matches!(
            operation,
            RpcOperation::Preflight(_)
                | RpcOperation::Status(_)
                | RpcOperation::BoundedLogs(_)
                | RpcOperation::RequestStatus(_)
        ) {
            return Err(SafeError::validation());
        }
        let _permit = self
            .tasks
            .clone()
            .try_acquire_owned()
            .map_err(|_| SafeError::new("busy"))?;
        let request = RpcRequest {
            version: 1,
            request_id: Uuid::new_v4(),
            pc_id: pc.clone(),
            operation,
        };
        request.validate_pc(pc)?;
        let endpoint = self.endpoint(pc).await?;
        let mut client = ssh::connect(&endpoint, &self.data)
            .await
            .map_err(|_| SafeError::new("host_unavailable"))?;
        let response = client
            .execute(&request)
            .await
            .map_err(|_| SafeError::new("host_unavailable"))?;
        if !response.ok {
            return Err(response
                .error
                .unwrap_or_else(|| SafeError::new("internal_error")));
        }
        let result = response
            .result
            .ok_or_else(|| SafeError::new("internal_error"))?;
        if !self.observe_verified(&endpoint, result.clone()).await? {
            return Err(SafeError::new("host_key_mismatch"));
        }
        Ok(result)
    }
    pub async fn reconcile(&self, id: Uuid) -> Result<Reconciliation, SafeError> {
        let started = Instant::now();
        let children = self
            .blocking(move |s| {
                let state = s.operation_state(id)?;
                if matches!(state, OperationState::Queued | OperationState::Running) {
                    return Err(SafeError::new("operation_in_progress"));
                }
                s.operation_children(id)
            })
            .await?;
        let child_count = children.len();
        let mut observations = Vec::new();
        for child in children {
            if child.dispatch_phase == DispatchPhase::NotDispatched {
                continue;
            }
            let result = self
                .read_rpc(
                    &child.pc_id,
                    RpcOperation::RequestStatus(RequestStatusPayload {
                        original_request_id: child.request_id,
                    }),
                )
                .await?;
            match result {
                RpcResult::RequestStatus(j) => {
                    if j.error
                        .as_ref()
                        .is_some_and(|e| e.code() == ErrorCode::UnknownInterrupted)
                    {
                        return Err(SafeError::new("unknown_interrupted"));
                    }
                    observations.push(j)
                }
                _ => return Err(SafeError::validation()),
            }
        }
        let resolution = self
            .blocking(move |s| s.reconcile_operation(id, &observations, now()))
            .await?;
        let code = match resolution.state {
            OperationState::Succeeded => "reconciled_succeeded",
            OperationState::Failed => "reconciled_failed",
            OperationState::Rejected => "reconciled_rejected",
            _ => "unknown_interrupted",
        };
        tracing::info!(
            code,
            count = child_count,
            duration_ms = started.elapsed().as_millis() as u64,
            "Durable reconciliation recorded without replay"
        );
        Ok(resolution)
    }
}
fn same_endpoint(a: &Endpoint, b: &Endpoint) -> bool {
    a.pc_id == b.pc_id && a.host == b.host && a.port == b.port && a.user == b.user
}
#[cfg(test)]
mod enrollment_tests {
    use super::*;
    #[tokio::test]
    async fn expired_or_changed_endpoint_probe_cannot_enroll() {
        let t = tempfile::tempdir().unwrap();
        let data = t.path().join("data");
        let mut store = crate::store::Store::open(&data, 0).unwrap();
        let pc = PcId::new("pc").unwrap();
        store
            .add_pc(
                crate::domain::PcInput {
                    pc_id: pc.clone(),
                    display_name: "PC".into(),
                    ssh_host: "127.0.0.1".into(),
                    ssh_port: 22,
                    ssh_user: "wolf-manager".into(),
                },
                0,
            )
            .unwrap();
        let state = AppState::new(
            store,
            data,
            crate::api::Deployment::Ingress,
            crate::auth::TransportPolicy::Ingress,
        );
        let endpoint = state.endpoint(&pc).await.unwrap();
        let probe = Probe {
            algorithm: "ssh-ed25519".into(),
            public_key: "synthetic".into(),
            fingerprint: "SHA256:synthetic".into(),
        };
        let expired = Uuid::new_v4();
        state.probes.lock().unwrap().insert(
            expired,
            PendingProbe {
                endpoint: endpoint.clone(),
                probe: probe.clone(),
                expires_at: now() - 1,
            },
        );
        assert!(
            state
                .enroll(&pc, expired, probe.fingerprint.clone())
                .await
                .is_err()
        );
        assert!(
            state
                .endpoint(&pc)
                .await
                .unwrap()
                .host_key_fingerprint
                .is_none()
        );
        let pending = Uuid::new_v4();
        state.probes.lock().unwrap().insert(
            pending,
            PendingProbe {
                endpoint,
                probe: probe.clone(),
                expires_at: now() + 60000,
            },
        );
        let id = pc.clone();
        state
            .blocking(move |s| {
                s.update_pc(
                    crate::domain::PcInput {
                        pc_id: id,
                        display_name: "PC".into(),
                        ssh_host: "127.0.0.2".into(),
                        ssh_port: 22,
                        ssh_user: "wolf-manager".into(),
                    },
                    1,
                )
            })
            .await
            .unwrap();
        assert!(state.enroll(&pc, pending, probe.fingerprint).await.is_err());
        assert!(
            state
                .endpoint(&pc)
                .await
                .unwrap()
                .host_key_fingerprint
                .is_none()
        );
    }
    #[tokio::test]
    async fn identity_import_refuses_enrollment_and_unresolved_operations_without_writes() {
        let t = tempfile::tempdir().unwrap();
        let data = t.path().join("data");
        let mut store = crate::store::Store::open(&data, 0).unwrap();
        let pc = PcId::new("import-pc").unwrap();
        store
            .add_pc(
                crate::domain::PcInput {
                    pc_id: pc.clone(),
                    display_name: "PC".into(),
                    ssh_host: "127.0.0.1".into(),
                    ssh_port: 22,
                    ssh_user: "wolf-manager".into(),
                },
                0,
            )
            .unwrap();
        let state = AppState::new(
            store,
            data.clone(),
            crate::api::Deployment::Ingress,
            crate::auth::TransportPolicy::Ingress,
        );
        let key = russh::keys::PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            russh::keys::Algorithm::Ed25519,
        )
        .unwrap();
        let private = key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap()
            .to_string();
        let public = key.public_key().to_openssh().unwrap();
        assert_eq!(state.identity_public_key(&pc).await.unwrap(), None);
        assert_eq!(
            state
                .import_identity(&pc, private.clone(), Some(public.clone()))
                .await
                .unwrap(),
            public
        );
        let path = data.join("keys/import-pc/id_ed25519");
        let original = std::fs::read(&path).unwrap();
        let id = pc.clone();
        state
            .blocking(move |s| {
                s.conn
                    .execute(
                        "UPDATE pcs SET host_key_public='enrolled' WHERE pc_id=?1",
                        [id.as_str()],
                    )
                    .map_err(internal)?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(
            state
                .import_identity(&pc, private.clone(), None)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
        let id = pc.clone();
        state
            .blocking(move |s| {
                s.conn
                    .execute(
                        "UPDATE pcs SET host_key_public=NULL WHERE pc_id=?1",
                        [id.as_str()],
                    )
                    .map_err(internal)?;
                let request = RpcRequest {
                    version: 1,
                    request_id: Uuid::new_v4(),
                    pc_id: id.clone(),
                    operation: RpcOperation::Preflight(EmptyPayload {}),
                };
                let operation =
                    s.enqueue_operation(&id, OperationKind::Preflight, None, &[request], 1)?;
                s.conn
                    .execute(
                        "UPDATE operations SET state='unknown_interrupted' WHERE operation_id=?1",
                        [operation.to_string()],
                    )
                    .map_err(internal)?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(state.import_identity(&pc, private, None).await.is_err());
        assert_eq!(std::fs::read(path).unwrap(), original);
    }
    #[tokio::test]
    async fn missing_recorded_identity_never_generates_a_replacement() {
        let t = tempfile::tempdir().unwrap();
        let data = t.path().join("data");
        let mut store = crate::store::Store::open(&data, 0).unwrap();
        let pc = PcId::new("preserve-key").unwrap();
        store
            .add_pc(
                crate::domain::PcInput {
                    pc_id: pc.clone(),
                    display_name: "PC".into(),
                    ssh_host: "127.0.0.1".into(),
                    ssh_port: 22,
                    ssh_user: "wolf-manager".into(),
                },
                0,
            )
            .unwrap();
        let state = AppState::new(
            store,
            data.clone(),
            crate::api::Deployment::Ingress,
            crate::auth::TransportPolicy::Ingress,
        );
        let public = state.public_key(&pc).await.unwrap();
        let path = data.join("keys/preserve-key/id_ed25519");
        let original = std::fs::read(&path).unwrap();
        let id = pc.clone();
        let commented = format!("{public} optional existing comment");
        state
            .blocking(move |s| {
                s.conn
                    .execute(
                        "UPDATE pcs SET enrolled_public_key=?1 WHERE pc_id=?2",
                        params![commented, id.as_str()],
                    )
                    .map_err(internal)?;
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(
            state.identity_public_key(&pc).await.unwrap(),
            Some(public.clone())
        );
        assert_eq!(state.public_key(&pc).await.unwrap(), public);
        let replacement = russh::keys::PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            russh::keys::Algorithm::Ed25519,
        )
        .unwrap()
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .unwrap();
        std::fs::write(&path, replacement.as_bytes()).unwrap();
        assert!(state.identity_public_key(&pc).await.is_err());
        assert!(state.public_key(&pc).await.is_err());
        assert!(
            state
                .import_identity(&pc, replacement.to_string(), None)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), replacement.as_bytes());
        std::fs::write(&path, &original).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(state.identity_public_key(&pc).await.is_err());
        assert!(state.public_key(&pc).await.is_err());
        assert!(
            state
                .import_identity(&pc, String::from_utf8(original).unwrap(), None)
                .await
                .is_err()
        );
        assert!(!path.exists());
        let id = pc.clone();
        let retained: String = state
            .blocking(move |s| {
                s.conn
                    .query_row(
                        "SELECT enrolled_public_key FROM pcs WHERE pc_id=?1",
                        [id.as_str()],
                        |r| r.get(0),
                    )
                    .map_err(internal)
            })
            .await
            .unwrap();
        assert_eq!(retained, public);
        let id = pc.clone();
        state.blocking(move |s| { s.conn.execute("UPDATE pcs SET enrolled_public_key=NULL,host_key_public='recorded-host' WHERE pc_id=?1", [id.as_str()]).map_err(internal)?; Ok(()) }).await.unwrap();
        assert!(state.identity_public_key(&pc).await.is_err());
        assert!(state.public_key(&pc).await.is_err());
        assert!(!path.exists());
    }
    #[tokio::test]
    async fn host_enrollment_requires_explicit_identity_choice_without_an_onboarding_dead_end() {
        for imported in [false, true] {
            let t = tempfile::tempdir().unwrap();
            let data = t.path().join("data");
            let mut store = crate::store::Store::open(&data, 0).unwrap();
            let pc = PcId::new("onboarding-pc").unwrap();
            store
                .add_pc(
                    crate::domain::PcInput {
                        pc_id: pc.clone(),
                        display_name: "PC".into(),
                        ssh_host: "127.0.0.1".into(),
                        ssh_port: 22,
                        ssh_user: "wolf-manager".into(),
                    },
                    0,
                )
                .unwrap();
            let state = AppState::new(
                store,
                data.clone(),
                crate::api::Deployment::Ingress,
                crate::auth::TransportPolicy::Ingress,
            );
            let endpoint = state.endpoint(&pc).await.unwrap();
            let host = russh::keys::PrivateKey::random(
                &mut russh::keys::key::safe_rng(),
                russh::keys::Algorithm::Ed25519,
            )
            .unwrap();
            let probe = Probe {
                algorithm: host.algorithm().to_string(),
                public_key: host.public_key().to_openssh().unwrap(),
                fingerprint: host
                    .public_key()
                    .fingerprint(russh::keys::HashAlg::Sha256)
                    .to_string(),
            };
            let initial = Uuid::new_v4();
            state.probes.lock().unwrap().insert(
                initial,
                PendingProbe {
                    endpoint: endpoint.clone(),
                    probe: probe.clone(),
                    expires_at: now() + 60000,
                },
            );
            assert!(
                state
                    .enroll(&pc, initial, probe.fingerprint.clone())
                    .await
                    .is_err()
            );
            let unconfigured = state.endpoint(&pc).await.unwrap();
            assert!(unconfigured.host_key_algorithm.is_none());
            assert!(unconfigured.host_key_public.is_none());
            assert!(unconfigured.host_key_fingerprint.is_none());
            assert!(!data.join("keys").exists());
            if imported {
                let key = russh::keys::PrivateKey::random(
                    &mut russh::keys::key::safe_rng(),
                    russh::keys::Algorithm::Ed25519,
                )
                .unwrap();
                state
                    .import_identity(
                        &pc,
                        key.to_openssh(russh::keys::ssh_key::LineEnding::LF)
                            .unwrap()
                            .to_string(),
                        None,
                    )
                    .await
                    .unwrap();
            } else {
                state.public_key(&pc).await.unwrap();
            }
            let original = std::fs::read(data.join("keys/onboarding-pc/id_ed25519")).unwrap();
            let ready = Uuid::new_v4();
            state.probes.lock().unwrap().insert(
                ready,
                PendingProbe {
                    endpoint,
                    probe: probe.clone(),
                    expires_at: now() + 60000,
                },
            );
            state
                .enroll(&pc, ready, probe.fingerprint.clone())
                .await
                .unwrap();
            assert_eq!(
                state.endpoint(&pc).await.unwrap().host_key_fingerprint,
                Some(probe.fingerprint)
            );
            assert_eq!(
                std::fs::read(data.join("keys/onboarding-pc/id_ed25519")).unwrap(),
                original
            );
            let host = russh::keys::PrivateKey::random(
                &mut russh::keys::key::safe_rng(),
                russh::keys::Algorithm::Ed25519,
            )
            .unwrap();
            let rotated = Probe {
                algorithm: host.algorithm().to_string(),
                public_key: host.public_key().to_openssh().unwrap(),
                fingerprint: host
                    .public_key()
                    .fingerprint(russh::keys::HashAlg::Sha256)
                    .to_string(),
            };
            let rotation = Uuid::new_v4();
            let endpoint = state.endpoint(&pc).await.unwrap();
            state.probes.lock().unwrap().insert(
                rotation,
                PendingProbe {
                    endpoint,
                    probe: rotated.clone(),
                    expires_at: now() + 60000,
                },
            );
            state
                .enroll(&pc, rotation, rotated.fingerprint.clone())
                .await
                .unwrap();
            assert_eq!(
                state.endpoint(&pc).await.unwrap().host_key_fingerprint,
                Some(rotated.fingerprint)
            );
            assert_eq!(
                std::fs::read(data.join("keys/onboarding-pc/id_ed25519")).unwrap(),
                original
            );
        }
    }
}
