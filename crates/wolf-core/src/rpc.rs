use crate::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
pub const RPC_MAX_BYTES: usize = 65536;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyPayload {}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplySettingsPayload {
    pub settings: Settings,
    pub revision: Revision,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartPayload {
    pub expected_staged_revision: Revision,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogsPayload {
    pub lines: u16,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestStatusPayload {
    pub original_request_id: Uuid,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum RpcOperation {
    Preflight(EmptyPayload),
    Status(EmptyPayload),
    ApplySettings(ApplySettingsPayload),
    Start(StartPayload),
    Stop(EmptyPayload),
    Restart(StartPayload),
    BoundedLogs(LogsPayload),
    RequestStatus(RequestStatusPayload),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RpcRequest {
    pub version: u8,
    pub request_id: Uuid,
    pub pc_id: PcId,
    #[serde(flatten)]
    pub operation: RpcOperation,
}
impl<'de> Deserialize<'de> for RpcRequest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Envelope {
            version: u8,
            request_id: Uuid,
            pc_id: PcId,
            operation: String,
            payload: serde_json::Value,
        }
        let raw = Envelope::deserialize(d)?;
        let op = serde_json::from_value(
            serde_json::json!({"operation":raw.operation,"payload":raw.payload}),
        )
        .map_err(serde::de::Error::custom)?;
        let result = Self {
            version: raw.version,
            request_id: raw.request_id,
            pc_id: raw.pc_id,
            operation: op,
        };
        result.validate().map_err(serde::de::Error::custom)?;
        Ok(result)
    }
}
impl RpcRequest {
    pub fn parse(bytes: &[u8]) -> Result<Self, SafeError> {
        if bytes.len() > RPC_MAX_BYTES {
            return Err(SafeError::new("payload_too_large"));
        }
        serde_json::from_slice(bytes).map_err(|_| SafeError::validation())
    }
    pub fn validate(&self) -> Result<(), SafeError> {
        if self.version != 1 || self.request_id.is_nil() {
            return Err(SafeError::validation());
        }
        match &self.operation {
            RpcOperation::ApplySettings(p) => {
                p.settings.validate()?;
                if p.settings.revision()? != p.revision {
                    return Err(SafeError::new("revision_mismatch"));
                }
            }
            RpcOperation::BoundedLogs(p) if !(1..=500).contains(&p.lines) => {
                return Err(SafeError::validation());
            }
            RpcOperation::RequestStatus(p) if p.original_request_id.is_nil() => {
                return Err(SafeError::validation());
            }
            _ => {}
        }
        Ok(())
    }
    pub fn validate_pc(&self, expected: &PcId) -> Result<(), SafeError> {
        self.validate()?;
        if &self.pc_id != expected {
            return Err(SafeError::new("pc_id_mismatch"));
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<Revision, SafeError> {
        self.validate()?;
        revision_of(self)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum RpcResult {
    Preflight(HostCapabilities),
    Status(HostStatus),
    Applied { staged_revision: Revision },
    Lifecycle(HostStatus),
    Logs { lines: Vec<String>, truncated: bool },
    RequestStatus(JournalObservation),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcResponse {
    pub version: u8,
    pub request_id: Uuid,
    pub pc_id: PcId,
    pub ok: bool,
    pub result: Option<RpcResult>,
    pub error: Option<SafeError>,
}
impl RpcResponse {
    pub fn validate_for(&self, request: &RpcRequest) -> Result<(), SafeError> {
        request.validate()?;
        if canonical_json(self)?.len() > 1024 * 1024 {
            return Err(SafeError::new("payload_too_large"));
        }
        if let Some(RpcResult::Logs { lines, .. }) = &self.result {
            let RpcOperation::BoundedLogs(payload) = &request.operation else {
                return Err(SafeError::validation());
            };
            if lines.len() > usize::from(payload.lines)
                || lines.iter().any(|line| line.contains(['\0', '\r', '\n']))
            {
                return Err(SafeError::validation());
            }
        }
        if self.version != 1
            || self.request_id != request.request_id
            || self.pc_id != request.pc_id
            || self.ok != self.result.is_some()
            || self.ok == self.error.is_some()
        {
            return Err(SafeError::validation());
        }
        if let Some(result) = &self.result {
            match (&request.operation, result) {
                (RpcOperation::ApplySettings(payload), RpcResult::Applied { staged_revision })
                    if staged_revision != &payload.revision =>
                {
                    return Err(SafeError::new("revision_mismatch"));
                }
                (RpcOperation::RequestStatus(payload), RpcResult::RequestStatus(journal))
                    if journal.request_id != payload.original_request_id
                        || journal.pc_id != request.pc_id =>
                {
                    return Err(SafeError::validation());
                }
                (RpcOperation::Preflight(_), RpcResult::Preflight(capabilities))
                    if capabilities.version != 1 || capabilities.pc_id != request.pc_id =>
                {
                    return Err(SafeError::validation());
                }
                _ => {}
            }

            let matches = matches!(
                (&request.operation, result),
                (RpcOperation::Preflight(_), RpcResult::Preflight(_))
                    | (RpcOperation::Status(_), RpcResult::Status(_))
                    | (RpcOperation::ApplySettings(_), RpcResult::Applied { .. })
                    | (
                        RpcOperation::Start(_) | RpcOperation::Stop(_) | RpcOperation::Restart(_),
                        RpcResult::Lifecycle(_)
                    )
                    | (RpcOperation::BoundedLogs(_), RpcResult::Logs { .. })
                    | (RpcOperation::RequestStatus(_), RpcResult::RequestStatus(_))
            );
            if !matches {
                return Err(SafeError::validation());
            }
        }
        Ok(())
    }
}
