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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    if children.is_empty()
        || children
            .iter()
            .enumerate()
            .any(|(i, c)| c.ordinal as usize != i)
    {
        return unknown();
    }
    let valid_stage_plan = children.len() == 2
        && children[0].kind == OperationKind::ApplySettings
        && matches!(
            children[1].kind,
            OperationKind::Start | OperationKind::Restart
        );
    if children.len() != 1 && !valid_stage_plan {
        return unknown();
    }
    if observations.iter().any(|o| {
        !children.iter().any(|child| {
            child.request_id == o.request_id && child.dispatch_phase != DispatchPhase::NotDispatched
        })
    }) {
        return unknown();
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut ordinals = std::collections::BTreeSet::new();
    let mut failed = false;
    let mut undispatched = false;
    let mut stage_succeeded = false;
    for child in children {
        if !ids.insert(child.request_id)
            || !ordinals.insert(child.ordinal)
            || child.pc_id != children[0].pc_id
        {
            return unknown();
        }
        if child.dispatch_phase == DispatchPhase::NotDispatched {
            undispatched = true;
            continue;
        }
        let matching: Vec<_> = observations
            .iter()
            .filter(|o| o.request_id == child.request_id)
            .collect();
        if matching.len() != 1 {
            return unknown();
        }
        let o = matching[0];
        if !o.found
            || o.pc_id != child.pc_id
            || o.canonical_request_sha256.as_ref() != Some(&child.canonical_request_sha256)
        {
            return unknown();
        }
        match o.phase {
            Some(JournalPhase::Succeeded) => {
                if child.kind == OperationKind::ApplySettings {
                    stage_succeeded = true;
                }
            }
            Some(JournalPhase::Failed) => failed = true,
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
