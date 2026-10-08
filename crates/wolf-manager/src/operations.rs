//! Durable immutable child plans: sending is committed before transport gets bytes.
use crate::{
    domain::{ensure_pc, load_settings, time},
    protected::internal,
    store::{Store, encode, hash},
};
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;
use wolf_core::*;
pub fn operation_kind(operation: &RpcOperation) -> OperationKind {
    match operation {
        RpcOperation::Preflight(_) => OperationKind::Preflight,
        RpcOperation::Status(_) => OperationKind::Status,
        RpcOperation::ApplySettings(_) => OperationKind::ApplySettings,
        RpcOperation::Start(_) => OperationKind::Start,
        RpcOperation::Stop(_) => OperationKind::Stop,
        RpcOperation::Restart(_) => OperationKind::Restart,
        RpcOperation::BoundedLogs(_) => OperationKind::BoundedLogs,
        RpcOperation::RequestStatus(_) => OperationKind::RequestStatus,
    }
}
fn enum_name<T: serde::Serialize>(value: T) -> Result<String, SafeError> {
    serde_json::to_value(value)
        .map_err(internal)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(SafeError::validation)
}
fn enum_decode<T: serde::de::DeserializeOwned>(value: String) -> Result<T, SafeError> {
    serde_json::from_value(serde_json::Value::String(value)).map_err(internal)
}
fn mutation(kind: OperationKind) -> bool {
    matches!(
        kind,
        OperationKind::ApplySettings
            | OperationKind::Start
            | OperationKind::Stop
            | OperationKind::Restart
    )
}
impl Store {
    pub(crate) fn ensure_no_mutation(&self, pc: &PcId) -> Result<(), SafeError> {
        let unresolved: i64 = self
            .conn
            .query_row(
                "SELECT count(*) FROM operations WHERE pc_id=?1 AND state='unknown_interrupted'",
                [pc.as_str()],
                |r| r.get(0),
            )
            .map_err(internal)?;
        if unresolved >= 100 {
            return Err(SafeError::new("unknown_interrupted"));
        }
        let active:Option<String>=self.conn.query_row("SELECT state FROM operations WHERE pc_id=?1 AND state IN ('queued','running','unknown_interrupted') AND kind IN ('apply_settings','start','stop','restart') ORDER BY submitted_at_ms LIMIT 1",[pc.as_str()],|r|r.get(0)).optional().map_err(internal)?;
        match active.as_deref() {
            Some("unknown_interrupted") => Err(SafeError::new("unknown_interrupted")),
            Some(_) => Err(SafeError::new("operation_in_progress")),
            None => Ok(()),
        }
    }
    pub fn enqueue_operation(
        &mut self,
        pc: &PcId,
        kind: OperationKind,
        desired: Option<&Revision>,
        requests: &[RpcRequest],
        now: i64,
    ) -> Result<Uuid, SafeError> {
        self.root.verify()?;
        time(now)?;
        ensure_pc(&self.conn, pc)?;
        if mutation(kind) {
            self.ensure_no_mutation(pc)?;
        }
        let valid = if matches!(kind, OperationKind::Start | OperationKind::Restart) {
            requests.len() == 2
                && operation_kind(&requests[0].operation) == OperationKind::ApplySettings
                && operation_kind(&requests[1].operation) == kind
        } else {
            requests.len() == 1
                && operation_kind(&requests[0].operation) == kind
                && kind != OperationKind::RequestStatus
        };
        if !valid {
            return Err(SafeError::validation());
        }
        let mut ids = std::collections::BTreeSet::new();
        for request in requests {
            request.validate_pc(pc)?;
            if !ids.insert(request.request_id) || canonical_json(request)?.len() > RPC_MAX_BYTES {
                return Err(SafeError::validation());
            }
        }
        if matches!(
            kind,
            OperationKind::ApplySettings | OperationKind::Start | OperationKind::Restart
        ) {
            let desired = desired.ok_or_else(SafeError::validation)?;
            if load_settings(&self.conn, pc)?.revision()? != *desired {
                return Err(SafeError::new("stale_revision"));
            }
            for req in requests {
                match &req.operation {
                    RpcOperation::ApplySettings(p) if p.revision != *desired => {
                        return Err(SafeError::new("stale_revision"));
                    }
                    RpcOperation::Start(p) | RpcOperation::Restart(p)
                        if p.expected_staged_revision != *desired =>
                    {
                        return Err(SafeError::new("stale_revision"));
                    }
                    _ => {}
                }
            }
        } else if desired.is_some() {
            return Err(SafeError::validation());
        }
        let operation = Uuid::new_v4();
        if ids.contains(&operation) {
            return Err(SafeError::new("internal_error"));
        }
        let tx = self.conn.transaction().map_err(internal)?;
        let revision = desired.map(|v| hex_digest(v.as_str()));
        tx.execute("INSERT INTO operations(operation_id,pc_id,kind,desired_revision,state,submitted_at_ms,request_digest) VALUES(?1,?2,?3,?4,'queued',?5,?6)",params![operation.to_string(),pc.as_str(),enum_name(kind)?,revision,now,hash(&canonical_json(&requests)?)]).map_err(internal)?;
        for (ordinal, req) in requests.iter().enumerate() {
            tx.execute("INSERT INTO operation_rpc_requests(request_id,operation_id,pc_id,kind,ordinal,canonical_request_sha256,request_json,dispatch_phase,created_at_ms,updated_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,'not_dispatched',?8,?8)",params![req.request_id.to_string(),operation.to_string(),pc.as_str(),enum_name(operation_kind(&req.operation))?,ordinal as i64,hash(&canonical_json(req)?),encode(req)?,now]).map_err(internal)?;
        }
        tx.commit().map_err(internal)?;
        Ok(operation)
    }
    pub fn operation_state(&self, id: Uuid) -> Result<OperationState, SafeError> {
        self.root.verify()?;
        let state: Option<String> = self
            .conn
            .query_row(
                "SELECT state FROM operations WHERE operation_id=?1",
                [id.to_string()],
                |r| r.get(0),
            )
            .optional()
            .map_err(internal)?;
        enum_decode(state.ok_or_else(|| SafeError::new("not_found"))?)
    }
    pub fn operation_children(&self, id: Uuid) -> Result<Vec<ChildRequest>, SafeError> {
        self.root.verify()?;
        self.operation_state(id)?;
        let mut query=self.conn.prepare("SELECT request_id,pc_id,kind,ordinal,canonical_request_sha256,dispatch_phase FROM operation_rpc_requests WHERE operation_id=?1 ORDER BY ordinal").map_err(internal)?;
        query
            .query_map([id.to_string()], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, u32>(3)?,
                    r.get::<_, Vec<u8>>(4)?,
                    r.get::<_, String>(5)?,
                ))
            })
            .map_err(internal)?
            .map(|row| {
                let (request, pc, kind, ordinal, digest, phase) = row.map_err(internal)?;
                Ok(ChildRequest {
                    request_id: Uuid::parse_str(&request).map_err(internal)?,
                    pc_id: PcId::new(pc)?,
                    kind: enum_decode(kind)?,
                    ordinal,
                    canonical_request_sha256: Revision::new(
                        digest
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>(),
                    )?,
                    dispatch_phase: enum_decode(phase)?,
                })
            })
            .collect()
    }
    /// Never returns a mutation after sending/uncertainty was persisted.
    pub fn begin_dispatch(&mut self, id: Uuid, now: i64) -> Result<RpcRequest, SafeError> {
        self.root.verify()?;
        time(now)?;
        let tx = self.conn.transaction().map_err(internal)?;
        let row:Option<(String,String,i64,String,Vec<u8>)>=tx.query_row("SELECT c.operation_id,c.request_json,c.ordinal,c.dispatch_phase,c.canonical_request_sha256 FROM operation_rpc_requests c JOIN operations o USING(operation_id) WHERE c.request_id=?1 AND o.state IN ('queued','running')",[id.to_string()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional().map_err(internal)?;
        let (operation, json, ordinal, phase, digest) =
            row.ok_or_else(|| SafeError::new("unknown_interrupted"))?;
        if phase != "not_dispatched" {
            return Err(SafeError::new("unknown_interrupted"));
        }
        let predecessor:i64=tx.query_row("SELECT count(*) FROM operation_rpc_requests WHERE operation_id=?1 AND ordinal<?2 AND (observed_phase IS NULL OR observed_phase!='succeeded')",params![operation,ordinal],|r|r.get(0)).map_err(internal)?;
        if predecessor != 0 {
            return Err(SafeError::new("operation_in_progress"));
        }
        let request = RpcRequest::parse(json.as_bytes())?;
        if request.request_id != id || hash(&canonical_json(&request)?) != digest {
            return Err(SafeError::new("internal_error"));
        }
        tx.execute("UPDATE operation_rpc_requests SET dispatch_phase='sending',updated_at_ms=?1 WHERE request_id=?2",params![now,id.to_string()]).map_err(internal)?;
        tx.execute("UPDATE operations SET state='running',started_at_ms=COALESCE(started_at_ms,?1),dispatch_phase='sending' WHERE operation_id=?2",params![now,operation]).map_err(internal)?;
        tx.commit().map_err(internal)?;
        Ok(request)
    }
    pub fn record_response(
        &mut self,
        id: Uuid,
        response: &RpcResponse,
        now: i64,
    ) -> Result<(), SafeError> {
        self.root.verify()?;
        time(now)?;
        let json:Option<String>=self.conn.query_row("SELECT request_json FROM operation_rpc_requests WHERE request_id=?1 AND dispatch_phase='sending'",[id.to_string()],|r|r.get(0)).optional().map_err(internal)?;
        let request = RpcRequest::parse(
            json.ok_or_else(|| SafeError::new("unknown_interrupted"))?
                .as_bytes(),
        )?;
        response.validate_for(&request)?;
        let mut result = response.result.clone();
        if canonical_json(response)?.len() > 65536 {
            if matches!(result, Some(RpcResult::Logs { .. })) {
                result = Some(RpcResult::Logs {
                    lines: vec![],
                    truncated: true,
                });
            } else {
                return Err(SafeError::new("payload_too_large"));
            }
        }
        let observation = JournalObservation {
            found: true,
            request_id: id,
            pc_id: request.pc_id.clone(),
            canonical_request_sha256: Some(request.digest()?),
            phase: Some(if response.ok {
                JournalPhase::Succeeded
            } else {
                JournalPhase::Failed
            }),
            observed_at_ms: now,
            result: result.clone().map(Box::new),
            error: response.error.clone(),
        };
        observation.validate()?;
        self.conn.execute("UPDATE operation_rpc_requests SET dispatch_phase='sent',observed_phase=?1,safe_result=?2,resolution_json=?3,updated_at_ms=?4 WHERE request_id=?5",params![if response.ok{"succeeded"}else{"failed"},encode(&result)?,encode(&observation)?,now,id.to_string()]).map_err(internal)?;
        Ok(())
    }
    /// Reconciliation is read-only remotely and only admitted for interrupted work.
    pub fn reconcile_operation(
        &mut self,
        id: Uuid,
        observations: &[JournalObservation],
        now: i64,
    ) -> Result<Reconciliation, SafeError> {
        if self.operation_state(id)? != OperationState::UnknownInterrupted {
            return Err(SafeError::new("operation_in_progress"));
        }
        self.resolve_operation(id, observations, now)
    }
    pub fn finish_recorded_operation(
        &mut self,
        id: Uuid,
        now: i64,
    ) -> Result<Reconciliation, SafeError> {
        if self.operation_state(id)? != OperationState::Running {
            return Err(SafeError::new("unknown_interrupted"));
        }
        let records:Vec<String>=self.conn.prepare("SELECT resolution_json FROM operation_rpc_requests WHERE operation_id=?1 AND resolution_json IS NOT NULL ORDER BY ordinal").map_err(internal)?.query_map([id.to_string()],|r|r.get(0)).map_err(internal)?.collect::<Result<_,_>>().map_err(internal)?;
        let observations = records
            .iter()
            .map(|value| crate::store::decode(value))
            .collect::<Result<Vec<JournalObservation>, _>>()?;
        self.resolve_operation(id, &observations, now)
    }
    pub fn mark_interrupted(&mut self, id: Uuid, now: i64) -> Result<(), SafeError> {
        self.root.verify()?;
        time(now)?;
        let changed=self.conn.execute("UPDATE operations SET state='unknown_interrupted' WHERE operation_id=?1 AND state IN ('queued','running')",[id.to_string()]).map_err(internal)?;
        if changed != 1 {
            return Err(SafeError::validation());
        }
        Ok(())
    }
    fn resolve_operation(
        &mut self,
        id: Uuid,
        observations: &[JournalObservation],
        now: i64,
    ) -> Result<Reconciliation, SafeError> {
        self.root.verify()?;
        time(now)?;
        let children = self.operation_children(id)?;
        let resolution = reconcile_children(&children, observations);
        if !matches!(
            self.operation_state(id)?,
            OperationState::Queued | OperationState::Running | OperationState::UnknownInterrupted
        ) {
            return Err(SafeError::validation());
        }
        let encoded = encode(observations)?;
        if encoded.len() > 65536 {
            return Err(SafeError::new("payload_too_large"));
        }
        let tx = self.conn.transaction().map_err(internal)?;
        for observation in observations {
            if observation.validate().is_ok()
                && children.iter().any(|c| {
                    c.request_id == observation.request_id
                        && c.pc_id == observation.pc_id
                        && observation.canonical_request_sha256.as_ref()
                            == Some(&c.canonical_request_sha256)
                })
            {
                tx.execute("UPDATE operation_rpc_requests SET resolution_json=?1,observed_phase=?2,updated_at_ms=?3 WHERE request_id=?4",params![encode(observation)?,observation.phase.map(enum_name).transpose()?,now,observation.request_id.to_string()]).map_err(internal)?;
            }
        }
        tx.execute("UPDATE operations SET state=?1,completed_at_ms=CASE WHEN ?1='unknown_interrupted' THEN NULL ELSE ?2 END,resolution_json=?3,sanitized_result=?5 WHERE operation_id=?4",params![enum_name(resolution.state)?,now,encoded,id.to_string(),encode(&serde_json::json!({"code":resolution.code,"stage_succeeded":resolution.stage_succeeded}))?]).map_err(internal)?;
        tx.commit().map_err(internal)?;
        Ok(resolution)
    }
}
fn hex_digest(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|v| {
            ((v[0] as char).to_digit(16).unwrap_or(0) * 16
                + (v[1] as char).to_digit(16).unwrap_or(0)) as u8
        })
        .collect()
}
