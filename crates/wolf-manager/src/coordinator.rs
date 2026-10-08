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
            let key = ssh::ensure_identity(&data, &pc)?;
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
        self.blocking(move|s|{s.ensure_no_mutation(&pc)?;if pending.expires_at<=now(){return Err(SafeError::new("host_key_mismatch"));}let changed=s.conn.execute("UPDATE pcs SET host_key_algorithm=?1,host_key_public=?2,host_key_fingerprint=?3,updated_at_ms=?4 WHERE pc_id=?5 AND ssh_host=?6 AND ssh_port=?7 AND ssh_user=?8 AND archived_at_ms IS NULL",params![pending.probe.algorithm,pending.probe.public_key,pending.probe.fingerprint,now(),pc.as_str(),pending.endpoint.host,pending.endpoint.port,pending.endpoint.user]).map_err(internal)?;if changed!=1{return Err(SafeError::new("host_key_mismatch"));}Ok(())}).await
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
}
