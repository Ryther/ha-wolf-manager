use crate::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Preflight,
    Status,
    ApplySettings,
    Start,
    Stop,
    Restart,
    BoundedLogs,
    RequestStatus,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Queued,
    Running,
    Succeeded,
    Failed,
    Rejected,
    UnknownInterrupted,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchPhase {
    NotDispatched,
    Sending,
    Sent,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalPhase {
    Accepted,
    Running,
    Succeeded,
    Failed,
    UnknownInterrupted,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JournalObservation {
    pub found: bool,
    pub request_id: Uuid,
    pub pc_id: PcId,
    pub canonical_request_sha256: Option<Revision>,
    pub phase: Option<JournalPhase>,
    pub observed_at_ms: i64,
    pub result: Option<Box<RpcResult>>,
    pub error: Option<SafeError>,
}
impl JournalObservation {
    /// Validate complete journal evidence; nonterminal states never carry final outcomes.
    pub fn validate(&self) -> Result<(), SafeError> {
        self.validate_at_depth(0)?;
        if canonical_json(self)?.len() > 1024 * 1024 {
            return Err(SafeError::new("payload_too_large"));
        }
        Ok(())
    }
    pub(crate) fn validate_at_depth(&self, depth: usize) -> Result<(), SafeError> {
        if depth > 8 || self.request_id.is_nil() || self.observed_at_ms < 0 {
            return Err(SafeError::validation());
        }
        if !self.found {
            if self.canonical_request_sha256.is_some()
                || self.phase.is_some()
                || self.result.is_some()
                || self.error.is_some()
            {
                return Err(SafeError::validation());
            }
            return Ok(());
        }
        if self.canonical_request_sha256.is_none() {
            return Err(SafeError::validation());
        }
        self.validate_phase(depth)
    }
    fn validate_phase(&self, depth: usize) -> Result<(), SafeError> {
        match self.phase {
            Some(JournalPhase::Succeeded) => {
                let result = self.result.as_ref().ok_or_else(SafeError::validation)?;
                if self.error.is_some() {
                    return Err(SafeError::validation());
                }
                result.validate_at_depth(&self.pc_id, depth + 1)?;
            }
            Some(JournalPhase::Failed) => {
                if self.result.is_some() || self.error.is_none() {
                    return Err(SafeError::validation());
                }
            }
            Some(
                JournalPhase::Accepted | JournalPhase::Running | JournalPhase::UnknownInterrupted,
            ) => {
                if self.result.is_some() || self.error.is_some() {
                    return Err(SafeError::validation());
                }
            }
            None => return Err(SafeError::validation()),
        }
        Ok(())
    }
}
impl<'de> Deserialize<'de> for JournalObservation {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Received {
            found: bool,
            request_id: Uuid,
            pc_id: PcId,
            canonical_request_sha256: Option<Revision>,
            phase: Option<JournalPhase>,
            observed_at_ms: i64,
            result: Option<Box<RpcResult>>,
            error: Option<SafeError>,
        }
        let raw = Received::deserialize(d)?;
        let journal = Self {
            found: raw.found,
            request_id: raw.request_id,
            pc_id: raw.pc_id,
            canonical_request_sha256: raw.canonical_request_sha256,
            phase: raw.phase,
            observed_at_ms: raw.observed_at_ms,
            result: raw.result,
            error: raw.error,
        };
        journal.validate().map_err(serde::de::Error::custom)?;
        Ok(journal)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildRequest {
    pub request_id: Uuid,
    pub pc_id: PcId,
    pub kind: OperationKind,
    pub ordinal: u32,
    pub canonical_request_sha256: Revision,
    pub dispatch_phase: DispatchPhase,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reconciliation {
    pub state: OperationState,
    pub code: Option<&'static str>,
    pub stage_succeeded: bool,
}
pub fn reconcile_children(
    children: &[ChildRequest],
    observations: &[JournalObservation],
) -> Reconciliation {
    let unknown = || Reconciliation {
        state: OperationState::UnknownInterrupted,
        code: Some("unknown_interrupted"),
        stage_succeeded: false,
    };
    if !valid_children(children) || !observations_belong_to_children(children, observations) {
        return unknown();
    }
    let valid_stage_plan = children.len() == 2;
    let mut failed = false;
    let mut undispatched = false;
    let mut stage_succeeded = false;
    for child in children {
        if child.dispatch_phase == DispatchPhase::NotDispatched {
            undispatched = true;
            continue;
        }
        let Some(phase) = terminal_child_phase(child, observations) else {
            return unknown();
        };
        match phase {
            JournalPhase::Succeeded => {
                stage_succeeded |= child.kind == OperationKind::ApplySettings
            }
            JournalPhase::Failed => failed = true,
            _ => return unknown(),
        }
    }
    if children
        .iter()
        .all(|c| c.dispatch_phase == DispatchPhase::NotDispatched)
    {
        return Reconciliation {
            state: OperationState::Rejected,
            code: Some("not_dispatched"),
            stage_succeeded: false,
        };
    }
    if failed || undispatched {
        return Reconciliation {
            state: OperationState::Failed,
            code: Some(if stage_succeeded && !failed && valid_stage_plan {
                "primary_not_dispatched"
            } else {
                "child_failed"
            }),
            stage_succeeded,
        };
    }
    Reconciliation {
        state: OperationState::Succeeded,
        code: None,
        stage_succeeded,
    }
}
fn valid_children(children: &[ChildRequest]) -> bool {
    let Some(first) = children.first() else {
        return false;
    };
    let valid_plan = children.len() == 1
        || (children.len() == 2
            && first.kind == OperationKind::ApplySettings
            && matches!(
                children[1].kind,
                OperationKind::Start | OperationKind::Restart
            ));
    if !valid_plan {
        return false;
    }
    let mut ids = std::collections::BTreeSet::new();
    children.iter().enumerate().all(|(i, child)| {
        child.ordinal as usize == i && child.pc_id == first.pc_id && ids.insert(child.request_id)
    })
}

fn observations_belong_to_children(
    children: &[ChildRequest],
    observations: &[JournalObservation],
) -> bool {
    observations.iter().all(|observation| {
        children.iter().any(|child| {
            child.request_id == observation.request_id
                && child.dispatch_phase != DispatchPhase::NotDispatched
        })
    })
}

fn terminal_child_phase(
    child: &ChildRequest,
    observations: &[JournalObservation],
) -> Option<JournalPhase> {
    let mut matching = observations
        .iter()
        .filter(|o| o.request_id == child.request_id);
    let observation = matching.next()?;
    if matching.next().is_some()
        || observation.validate().is_err()
        || !observation.found
        || observation.pc_id != child.pc_id
        || observation.canonical_request_sha256.as_ref() != Some(&child.canonical_request_sha256)
    {
        return None;
    }
    let phase = observation.phase?;
    if phase == JournalPhase::Succeeded
        && observation
            .result
            .as_ref()
            .is_none_or(|result| result.validate_for_kind(child.kind, &child.pc_id).is_err())
    {
        return None;
    }
    Some(phase)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostCapabilities {
    pub version: u8,
    pub pc_id: PcId,
    pub ready: bool,
    pub proton_cachyos: bool,
    pub reasons: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostStatus {
    pub systemd_state: String,
    pub container_state: String,
    pub restart_count: u64,
    pub exit_code: Option<i32>,
    pub staged_revision: Option<Revision>,
    pub running_revision: Option<Revision>,
    pub recovery_pending: bool,
}
