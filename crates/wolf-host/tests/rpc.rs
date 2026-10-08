use std::{fs, os::unix::fs::PermissionsExt};
use tempfile::tempdir;
use uuid::Uuid;
use wolf_core::*;
use wolf_manager_host::{journal::Journal, rpc};
fn request() -> RpcRequest {
    RpcRequest {
        version: 1,
        request_id: Uuid::new_v4(),
        pc_id: PcId::new("office").unwrap(),
        operation: RpcOperation::ApplySettings(ApplySettingsPayload {
            settings: Settings::default(),
            revision: Settings::default().revision().unwrap(),
        }),
    }
}
#[test]
fn completed_identical_rpc_is_cached_and_conflicting_id_never_executes() {
    let temp = tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let journal = Journal::open(temp.path()).unwrap();
    let mut request = request();
    let revision = Settings::default().revision().unwrap();
    let first = rpc::serve(&journal, &request.pc_id, &request, |_| {
        Ok(RpcResult::Applied {
            staged_revision: revision,
        })
    })
    .unwrap();
    assert_eq!(
        rpc::serve(&journal, &request.pc_id, &request, |_| panic!("replayed")).unwrap(),
        first
    );
    request.operation = RpcOperation::Stop(EmptyPayload {});
    assert!(
        rpc::serve(&journal, &request.pc_id, &request, |_| panic!(
            "conflicting execution"
        ))
        .is_err()
    );
}
#[test]
fn timeout_keeps_incomplete_evidence_and_a_duplicate_never_reexecutes() {
    let temp = tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let journal = Journal::open(temp.path()).unwrap();
    let request = request();
    assert!(
        rpc::serve(&journal, &request.pc_id, &request, |_| Err(SafeError::new(
            "unknown_interrupted"
        )))
        .is_err()
    );
    let observed = journal.lookup(request.request_id, &request.pc_id).unwrap();
    assert!(observed.found);
    assert_eq!(observed.phase, Some(JournalPhase::Running));
    assert!(observed.result.is_none());
    assert!(
        rpc::serve(&journal, &request.pc_id, &request, |_| panic!(
            "replayed unknown"
        ))
        .is_err()
    );
}
#[test]
fn wrong_pc_is_refused_before_journal_or_action() {
    let temp = tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let journal = Journal::open(temp.path()).unwrap();
    let request = request();
    assert!(
        rpc::serve(
            &journal,
            &PcId::new("other").unwrap(),
            &request,
            |_| panic!("wrong PC reached action")
        )
        .is_err()
    );
    assert!(
        !journal
            .lookup(request.request_id, &request.pc_id)
            .unwrap()
            .found
    );
}
