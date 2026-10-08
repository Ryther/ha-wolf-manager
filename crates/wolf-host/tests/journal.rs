use std::{fs, os::unix::fs::PermissionsExt};
use tempfile::tempdir;
use uuid::Uuid;
use wolf_core::*;
use wolf_manager_host::journal::*;
fn request() -> RpcRequest {
    RpcRequest {
        version: 1,
        request_id: Uuid::new_v4(),
        pc_id: PcId::new("office").unwrap(),
        operation: RpcOperation::Stop(EmptyPayload {}),
    }
}
#[test]
fn completed_request_is_cached_only_for_identical_payload() {
    let root = tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let journal = Journal::open(root.path()).unwrap();
    let request = request();
    let Admission::Execute(mut ticket) = journal.begin(&request).unwrap() else {
        panic!("new request not admitted")
    };
    ticket.running().unwrap();
    let response = RpcResponse {
        version: 1,
        request_id: request.request_id,
        pc_id: request.pc_id.clone(),
        ok: false,
        result: None,
        error: Some(SafeError::new("host_unavailable")),
    };
    ticket.finish(response.clone()).unwrap();
    let Admission::Cached(cached) = journal.begin(&request).unwrap() else {
        panic!("completed request not cached")
    };
    assert_eq!(cached, response);
    let mut conflict = request.clone();
    conflict.operation = RpcOperation::Status(EmptyPayload {});
    assert!(journal.begin(&conflict).is_err());
}
#[test]
fn interrupted_request_never_reexecutes_and_reports_identity() {
    let root = tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let request = request();
    {
        let journal = Journal::open(root.path()).unwrap();
        let Admission::Execute(mut ticket) = journal.begin(&request).unwrap() else {
            panic!()
        };
        ticket.running().unwrap();
    }
    let reopened = Journal::open(root.path()).unwrap();
    let Admission::Uncertain(observation) = reopened.begin(&request).unwrap() else {
        panic!("interrupted request was executable")
    };
    assert_eq!(observation.request_id, request.request_id);
    assert_eq!(
        observation.canonical_request_sha256,
        Some(request.digest().unwrap())
    );
    assert_eq!(observation.phase, Some(JournalPhase::Running));
    assert_eq!(reopened.status(&request).unwrap(), observation);
}
#[test]
fn journal_refuses_unsafe_storage_and_inconsistent_completion() {
    let root = tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Journal::open(root.path()).is_err());
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let journal = Journal::open(root.path()).unwrap();
    let request = request();
    let Admission::Execute(ticket) = journal.begin(&request).unwrap() else {
        panic!()
    };
    let response = RpcResponse {
        version: 1,
        request_id: Uuid::new_v4(),
        pc_id: request.pc_id.clone(),
        ok: false,
        result: None,
        error: Some(SafeError::validation()),
    };
    assert!(ticket.finish(response).is_err());
    assert!(matches!(
        journal.begin(&request).unwrap(),
        Admission::Uncertain(_)
    ));
}

#[test]
fn admission_is_exclusive_and_unknown_lookup_has_no_outcome() {
    let root = tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let first = Journal::open(root.path()).unwrap();
    let second = Journal::open(root.path()).unwrap();
    let request = request();
    let Admission::Execute(ticket) = first.begin(&request).unwrap() else {
        panic!()
    };
    assert!(second.begin(&crate::request()).is_err());
    drop(ticket);
    let missing = second.lookup(Uuid::new_v4(), &request.pc_id).unwrap();
    assert!(!missing.found);
    assert_eq!(missing.phase, None);
    assert_eq!(missing.result, None);
    assert_eq!(missing.canonical_request_sha256, None);
}
#[test]
fn corrupt_or_aliased_journal_is_refused_without_reexecution() {
    use std::os::unix::fs::symlink;
    let root = tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let journal = Journal::open(root.path()).unwrap();
    let request = request();
    let Admission::Execute(ticket) = journal.begin(&request).unwrap() else {
        panic!()
    };
    drop(ticket);
    let path = root.path().join(format!("{}.json", request.request_id));
    fs::write(&path, b"corrupt").unwrap();
    assert!(journal.begin(&request).is_err());
    fs::remove_file(&path).unwrap();
    let outside = tempdir().unwrap();
    let preserved = outside.path().join("record");
    fs::write(&preserved, b"outside bytes").unwrap();
    symlink(&preserved, &path).unwrap();
    assert!(journal.begin(&request).is_err());
    assert_eq!(fs::read(&preserved).unwrap(), b"outside bytes");
}
