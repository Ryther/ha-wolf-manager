use ha_wolf_manager::{auth::*, store::Store};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;
use wolf_core::*;
#[test]
fn new_store_is_seeded_exclusively_locked_and_protected() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("data");
    let store = Store::open(&root, 1).unwrap();
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(root.join("manager.sqlite3"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        store.global_settings().unwrap().parameters,
        Settings::default().parameters
    );
    assert!(store.global_settings().unwrap().games.is_empty());
    assert!(Store::open(&root, 2).is_err());
    drop(store);
    assert!(Store::open(&root, 3).is_ok());
}
#[test]
fn ingress_checks_transport_peer_and_refuses_origin_paths() {
    assert!(admit_ingress("192.0.2.8".parse().unwrap()).is_err());
    assert!(admit_ingress("172.30.32.2".parse().unwrap()).is_ok());
    assert!(admit_ingress("::ffff:172.30.32.2".parse().unwrap()).is_ok());
    assert!(normalize_origin("https://example.test/path").is_err());
    assert!(normalize_origin("https://user:password@example.test").is_err());
    assert_eq!(
        normalize_origin("https://EXAMPLE.test:443").unwrap(),
        "https://example.test"
    );
}
fn secret(path: &std::path::Path) -> BootstrapSecret {
    fs::write(path, b"synthetic-bootstrap-token-256bits!").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
    BootstrapSecret::read(path).unwrap()
}
fn attempt<'a>(challenge: &'a Challenge, password: &'a str) -> LoginAttempt<'a> {
    LoginAttempt {
        peer: "192.0.2.9".parse().unwrap(),
        origin: "https://example.test",
        challenge: &challenge.token,
        csrf_header: &challenge.token,
        password,
    }
}
#[test]
fn bootstrap_consumes_challenge_and_requires_session_bound_csrf() {
    let temp = tempdir().unwrap();
    let mut store = Store::open(&temp.path().join("data"), 0).unwrap();
    let mut auth = AuthService::standalone(
        &mut store,
        "https://example.test",
        secret(&temp.path().join("secret")),
    )
    .unwrap();
    let challenge = auth
        .issue_challenge("192.0.2.9".parse().unwrap(), Purpose::Bootstrap, 1)
        .unwrap();
    assert!(
        auth.bootstrap(attempt(&challenge, "SyntheticPassword!42"), "wrong", 2)
            .is_err()
    );
    let challenge = auth
        .issue_challenge("192.0.2.9".parse().unwrap(), Purpose::Bootstrap, 3)
        .unwrap();
    let credentials = auth
        .bootstrap(
            attempt(&challenge, "SyntheticPassword!42"),
            "synthetic-bootstrap-token-256bits!",
            4,
        )
        .unwrap();
    assert!(
        auth.bootstrap(
            attempt(&challenge, "SyntheticPassword!42"),
            "synthetic-bootstrap-token-256bits!",
            5
        )
        .is_err()
    );
    assert!(
        auth.require_mutation(
            &credentials.session_token,
            "wrong",
            "https://example.test",
            5
        )
        .is_err()
    );
    assert!(
        auth.require_mutation(
            &credentials.session_token,
            &credentials.csrf_token,
            "https://foreign.test",
            5
        )
        .is_err()
    );
    assert!(
        auth.require_mutation(
            &credentials.session_token,
            &credentials.csrf_token,
            "https://example.test",
            5
        )
        .is_ok()
    );
    assert!(
        auth.require_mutation(
            &credentials.session_token,
            &credentials.csrf_token,
            "https://example.test",
            8 * 24 * 60 * 60 * 1000
        )
        .is_err()
    );
}
#[test]
fn ingress_nonce_is_peer_and_origin_bound_without_standalone_fallback() {
    let temp = tempdir().unwrap();
    let mut store = Store::open(&temp.path().join("data"), 0).unwrap();
    let mut auth = AuthService::ingress(&mut store);
    assert!(
        auth.issue_ingress_csrf("192.0.2.9".parse().unwrap(), "https://example.test", 1)
            .is_err()
    );
    let peer = "172.30.32.2".parse().unwrap();
    let csrf = auth
        .issue_ingress_csrf(peer, "https://example.test", 2)
        .unwrap();
    assert!(
        auth.require_ingress_mutation(peer, &csrf.token, "https://foreign.test", 3)
            .is_err()
    );
    assert!(
        auth.require_ingress_mutation(peer, &csrf.token, "https://example.test", 3)
            .is_ok()
    );
    assert!(auth.issue_challenge(peer, Purpose::Login, 3).is_err());
    assert!(
        auth.require_mutation("fake", "fake", "https://example.test", 3)
            .is_err()
    );
}
use ha_wolf_manager::domain::PcInput;
fn pc(id: &str) -> PcInput {
    PcInput {
        pc_id: PcId::new(id).unwrap(),
        display_name: "Synthetic PC".into(),
        ssh_host: "192.0.2.20".into(),
        ssh_port: 22,
        ssh_user: "wolf-manager".into(),
    }
}
#[test]
fn domain_settings_revision_and_complete_catalog_are_pc_scoped() {
    let temp = tempdir().unwrap();
    let mut store = Store::open(&temp.path().join("data"), 0).unwrap();
    store.add_pc(pc("pc_a"), 1).unwrap();
    store.add_pc(pc("pc_b"), 1).unwrap();
    assert_eq!(store.pcs().unwrap().len(), 2);
    let a = PcId::new("pc_a").unwrap();
    let b = PcId::new("pc_b").unwrap();
    let app = AppId::new("42").unwrap();
    let prior = store.settings(&a).unwrap().revision().unwrap();
    let cap = HostCapabilities {
        version: 1,
        pc_id: a.clone(),
        ready: true,
        proton_cachyos: true,
        reasons: vec![],
    };
    let next = store
        .save_game(
            &a,
            &app,
            GameSettings {
                direct_launch: true,
                proton_cachyos: false,
                parameters: vec![
                    ParameterId::new("fsr4_indicator").unwrap(),
                    ParameterId::new("fsr4").unwrap(),
                ],
            },
            &prior,
            &cap,
            2,
        )
        .unwrap();
    assert_ne!(prior, next);
    assert!(
        store
            .save_game(&a, &app, GameSettings::default(), &prior, &cap, 3)
            .is_err()
    );
    assert!(store.settings(&b).unwrap().games.is_empty());
    let manifest = CatalogManifest {
        version: 1,
        pc_id: a.clone(),
        catalog_generation: 1,
        app_ids: vec![app.clone()],
        observed_at_ms: 3,
        complete: true,
    };
    let attrs = CatalogAttributes {
        version: 1,
        pc_id: a.clone(),
        app_id: app.clone(),
        name: "Synthetic game".into(),
        cover_url: steam_cover_url(&app),
        library_id: "one".into(),
        catalog_generation: 1,
        observed_at_ms: 3,
    };
    assert!(store.commit_catalog(&manifest, &[]).is_err());
    store.commit_catalog(&manifest, &[attrs]).unwrap();
    assert_eq!(store.catalog(&a).unwrap().unwrap().1.len(), 1);
    assert!(store.catalog(&b).unwrap().is_none());
}
#[test]
fn durable_child_plan_survives_restart_without_replay() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("data");
    let mut store = Store::open(&root, 0).unwrap();
    store.add_pc(pc("pc"), 1).unwrap();
    let pc = PcId::new("pc").unwrap();
    let settings = store.settings(&pc).unwrap();
    let revision = settings.revision().unwrap();
    let stage = RpcRequest {
        version: 1,
        request_id: uuid::Uuid::new_v4(),
        pc_id: pc.clone(),
        operation: RpcOperation::ApplySettings(ApplySettingsPayload {
            settings,
            revision: revision.clone(),
        }),
    };
    let primary = RpcRequest {
        version: 1,
        request_id: uuid::Uuid::new_v4(),
        pc_id: pc.clone(),
        operation: RpcOperation::Restart(StartPayload {
            expected_staged_revision: revision.clone(),
        }),
    };
    let op = store
        .enqueue_operation(
            &pc,
            OperationKind::Restart,
            Some(&revision),
            &[stage.clone(), primary.clone()],
            2,
        )
        .unwrap();
    assert_eq!(store.operation_children(op).unwrap().len(), 2);
    assert!(store.begin_dispatch(primary.request_id, 3).is_err());
    assert_eq!(store.begin_dispatch(stage.request_id, 3).unwrap(), stage);
    drop(store);
    let mut store = Store::open(&root, 4).unwrap();
    assert_eq!(
        store.operation_state(op).unwrap(),
        OperationState::UnknownInterrupted
    );
    assert!(store.begin_dispatch(stage.request_id, 5).is_err());
    assert_eq!(
        store.operation_children(op).unwrap()[0].dispatch_phase,
        DispatchPhase::Sending
    );
}
#[test]
fn writable_parent_and_data_alias_refuse_without_database_creation() {
    let temp = tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o777)).unwrap();
    let root = temp.path().join("data");
    assert!(Store::open(&root, 0).is_err());
    assert!(!root.exists());
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let actual = temp.path().join("actual");
    fs::create_dir(&actual).unwrap();
    fs::set_permissions(&actual, fs::Permissions::from_mode(0o700)).unwrap();
    let alias = temp.path().join("alias");
    std::os::unix::fs::symlink(&actual, &alias).unwrap();
    assert!(Store::open(&alias, 0).is_err());
    assert!(!actual.join("manager.sqlite3").exists());
}
#[test]
fn schema_version_checksum_corruption_refuses_without_byte_changes() {
    for alteration in [
        "UPDATE schema_migrations SET version=2",
        "UPDATE schema_migrations SET checksum=zeroblob(32)",
    ] {
        let temp = tempdir().unwrap();
        let root = temp.path().join("data");
        drop(Store::open(&root, 0).unwrap());
        let conn = rusqlite::Connection::open(root.join("manager.sqlite3")).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        conn.execute_batch(alteration).unwrap();
        let bytes = fs::read(root.join("manager.sqlite3")).unwrap();
        let wal = fs::read(root.join("manager.sqlite3-wal")).unwrap();
        assert!(Store::open(&root, 1).is_err());
        assert_eq!(fs::read(root.join("manager.sqlite3")).unwrap(), bytes);
        assert_eq!(fs::read(root.join("manager.sqlite3-wal")).unwrap(), wal);
    }
    let temp = tempdir().unwrap();
    let root = temp.path().join("data");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(root.join("manager.sqlite3"), b"corrupt synthetic database").unwrap();
    fs::set_permissions(
        root.join("manager.sqlite3"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(Store::open(&root, 0).is_err());
    assert_eq!(
        fs::read(root.join("manager.sqlite3")).unwrap(),
        b"corrupt synthetic database"
    );
}
#[test]
fn offline_reset_is_exclusive_and_preserves_domain_rows() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("data");
    let mut store = Store::open(&root, 0).unwrap();
    store.add_pc(pc("pc"), 1).unwrap();
    assert!(ha_wolf_manager::recovery::Recovery::open(&root, 2).is_err());
    drop(store);
    let mut recovery = ha_wolf_manager::recovery::Recovery::open(&root, 3).unwrap();
    recovery
        .reset_password("SyntheticNewPassword!42", 4)
        .unwrap();
    drop(recovery);
    let mut store = Store::open(&root, 5).unwrap();
    assert_eq!(store.pcs().unwrap().len(), 1);
    let mut auth = AuthService::standalone(
        &mut store,
        "https://example.test",
        secret(&temp.path().join("secret")),
    )
    .unwrap();
    assert!(auth.initialized().unwrap());
    let challenge = auth
        .issue_challenge("192.0.2.9".parse().unwrap(), Purpose::Login, 6)
        .unwrap();
    assert!(
        auth.login(attempt(&challenge, "SyntheticNewPassword!42"), 7)
            .is_ok()
    );
}
#[test]
fn trusted_proxy_and_ingress_prefix_refuse_spoofed_transport_input() {
    let policy = TransportPolicy::TrustedProxy(vec!["192.0.2.1".parse().unwrap()]);
    assert!(policy.admit("192.0.2.2".parse().unwrap()).is_err());
    assert!(policy.admit("192.0.2.1".parse().unwrap()).is_ok());
    for prefix in [
        "relative/",
        "//double/",
        "/a/../b/",
        "/a/%2e%2e/b/",
        "/a?x=1",
        "/a#fragment",
    ] {
        assert!(normalize_ingress_prefix(prefix).is_err());
    }
    assert_eq!(
        normalize_ingress_prefix("/api/hassio_ingress/synthetic").unwrap(),
        "/api/hassio_ingress/synthetic/"
    );
}
#[test]
fn login_challenge_replay_peer_binding_logout_and_rate_limit() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("data");
    let mut recovery = ha_wolf_manager::recovery::Recovery::open(&root, 0).unwrap();
    recovery.reset_password("SyntheticPassword!42", 1).unwrap();
    drop(recovery);
    let mut store = Store::open(&root, 2).unwrap();
    let mut auth = AuthService::standalone(
        &mut store,
        "https://example.test",
        secret(&temp.path().join("secret")),
    )
    .unwrap();
    let challenge = auth
        .issue_challenge("192.0.2.9".parse().unwrap(), Purpose::Login, 3)
        .unwrap();
    let mut wrong = attempt(&challenge, "SyntheticPassword!42");
    wrong.peer = "192.0.2.10".parse().unwrap();
    assert!(auth.login(wrong, 4).is_err());
    let credentials = auth
        .login(attempt(&challenge, "SyntheticPassword!42"), 5)
        .unwrap();
    assert!(
        auth.login(attempt(&challenge, "SyntheticPassword!42"), 6)
            .is_err()
    );
    assert!(
        credentials
            .cookie()
            .contains("Secure; HttpOnly; SameSite=Strict; Path=/")
    );
    auth.logout(
        &credentials.session_token,
        &credentials.csrf_token,
        "https://example.test",
        7,
    )
    .unwrap();
    assert!(auth.authenticate(&credentials.session_token, 8).is_err());
    for i in 0..5 {
        let challenge = auth
            .issue_challenge("192.0.2.9".parse().unwrap(), Purpose::Login, 10 + i)
            .unwrap();
        assert_eq!(
            auth.login(attempt(&challenge, "WrongPassword!42"), 10 + i)
                .err()
                .unwrap()
                .code(),
            ErrorCode::LoginFailed
        );
    }
    let challenge = auth
        .issue_challenge("192.0.2.9".parse().unwrap(), Purpose::Login, 20)
        .unwrap();
    assert_eq!(
        auth.login(attempt(&challenge, "SyntheticPassword!42"), 21)
            .err()
            .unwrap()
            .code(),
        ErrorCode::LoginRateLimited
    );
}
#[test]
fn initialized_marker_blocks_missing_or_prebootstrap_database() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("data");
    let store = Store::open(&root, 0).unwrap();
    drop(store);
    let prebootstrap = fs::read(root.join("manager.sqlite3")).unwrap();
    let mut recovery = ha_wolf_manager::recovery::Recovery::open(&root, 1).unwrap();
    recovery.reset_password("SyntheticPassword!42", 2).unwrap();
    drop(recovery);
    fs::write(root.join("manager.sqlite3"), &prebootstrap).unwrap();
    assert!(Store::open(&root, 3).is_err());
    assert_eq!(
        fs::read(root.join("manager.sqlite3")).unwrap(),
        prebootstrap
    );
    fs::rename(root.join("manager.sqlite3"), root.join("held.sqlite3")).unwrap();
    assert!(Store::open(&root, 4).is_err());
    assert!(!root.join("manager.sqlite3").exists());
}
#[test]
fn verified_backup_and_empty_database_migration_have_durable_manifests() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("data");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(root.join("manager.sqlite3"), b"").unwrap();
    fs::set_permissions(
        root.join("manager.sqlite3"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let store = Store::open(&root, 0).unwrap();
    let name = store.verified_backup().unwrap();
    let path = root.join(&name);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join(name.replace(".sqlite3", ".json"))).unwrap())
            .unwrap();
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(fs::read(path).unwrap())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(manifest["sha256"], digest);
}
#[test]
fn verified_stage_ack_gates_primary_and_partial_reconciliation_is_explicit() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("data");
    let mut store = Store::open(&root, 0).unwrap();
    store.add_pc(pc("pc"), 1).unwrap();
    let pc = PcId::new("pc").unwrap();
    let settings = store.settings(&pc).unwrap();
    let revision = settings.revision().unwrap();
    let stage = RpcRequest {
        version: 1,
        request_id: uuid::Uuid::new_v4(),
        pc_id: pc.clone(),
        operation: RpcOperation::ApplySettings(ApplySettingsPayload {
            settings,
            revision: revision.clone(),
        }),
    };
    let primary = RpcRequest {
        version: 1,
        request_id: uuid::Uuid::new_v4(),
        pc_id: pc.clone(),
        operation: RpcOperation::Start(StartPayload {
            expected_staged_revision: revision.clone(),
        }),
    };
    let operation = store
        .enqueue_operation(
            &pc,
            OperationKind::Start,
            Some(&revision),
            &[stage.clone(), primary.clone()],
            2,
        )
        .unwrap();
    assert!(store.reconcile_operation(operation, &[], 3).is_err());
    store.begin_dispatch(stage.request_id, 3).unwrap();
    let bad = RpcResponse {
        version: 1,
        request_id: stage.request_id,
        pc_id: pc.clone(),
        ok: true,
        result: Some(RpcResult::Applied {
            staged_revision: Revision::new("0".repeat(64)).unwrap(),
        }),
        error: None,
    };
    assert!(store.record_response(stage.request_id, &bad, 4).is_err());
    assert!(store.begin_dispatch(primary.request_id, 5).is_err());
    let response = RpcResponse {
        result: Some(RpcResult::Applied {
            staged_revision: revision.clone(),
        }),
        ..bad
    };
    store
        .record_response(stage.request_id, &response, 6)
        .unwrap();
    drop(store);
    let mut store = Store::open(&root, 7).unwrap();
    let journal = JournalObservation {
        found: true,
        request_id: stage.request_id,
        pc_id: pc.clone(),
        canonical_request_sha256: Some(stage.digest().unwrap()),
        phase: Some(JournalPhase::Succeeded),
        observed_at_ms: 8,
        result: response.result.map(Box::new),
        error: None,
    };
    let resolution = store.reconcile_operation(operation, &[journal], 8).unwrap();
    assert_eq!(resolution.state, OperationState::Failed);
    assert_eq!(resolution.code, Some("primary_not_dispatched"));
    assert!(resolution.stage_succeeded);
    assert!(store.begin_dispatch(primary.request_id, 9).is_err());
    assert_eq!(store.settings(&pc).unwrap().revision().unwrap(), revision);
}
#[test]
fn backup_manifest_corruption_is_refused() {
    let temp = tempdir().unwrap();
    let store = Store::open(&temp.path().join("data"), 0).unwrap();
    let name = store.verified_backup().unwrap();
    assert!(store.verify_backup(&name).is_ok());
    let path = temp
        .path()
        .join("data")
        .join(name.replace(".sqlite3", ".json"));
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    manifest["sha256"] = serde_json::json!("0".repeat(64));
    fs::write(path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    assert!(store.verify_backup(&name).is_err());
}
#[test]
fn operation_history_is_bounded_and_retains_unresolved_work() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("data");
    let mut store = Store::open(&root, 0).unwrap();
    store.add_pc(pc("pc"), 1).unwrap();
    let pc = PcId::new("pc").unwrap();
    let request = RpcRequest {
        version: 1,
        request_id: uuid::Uuid::new_v4(),
        pc_id: pc.clone(),
        operation: RpcOperation::Status(EmptyPayload {}),
    };
    let unresolved = store
        .enqueue_operation(&pc, OperationKind::Status, None, &[request], 2)
        .unwrap();
    store.mark_interrupted(unresolved, 3).unwrap();
    let expired = uuid::Uuid::new_v4();
    let conn = rusqlite::Connection::open(root.join("manager.sqlite3")).unwrap();
    conn.execute("INSERT INTO operations(operation_id,pc_id,kind,state,submitted_at_ms,completed_at_ms) VALUES(?1,'pc','status','succeeded',1,2)",[expired.to_string()]).unwrap();
    drop(conn);
    let page = store.operation_page(&pc, 1, None).unwrap();
    assert_eq!(page.operations[0].operation_id, unresolved);
    let cursor =
        ha_wolf_manager::history::OperationCursor::parse(&page.next_cursor.unwrap()).unwrap();
    assert_eq!(
        store
            .operation_page(&pc, 1, Some(&cursor))
            .unwrap()
            .operations[0]
            .operation_id,
        expired
    );
    assert!(store.operation_page(&pc, 0, None).is_err());
    assert_eq!(
        store
            .prune_terminal_operations(31 * 24 * 60 * 60 * 1000)
            .unwrap(),
        1
    );
    assert!(store.operation(expired).is_err());
    assert_eq!(
        store.operation(unresolved).unwrap().state,
        OperationState::UnknownInterrupted
    );
    assert_eq!(store.pcs().unwrap().len(), 1);
}

#[test]
fn history_terminal_cap_preserves_recent_thousand_and_unknown() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("data");
    let mut store = Store::open(&root, 0).unwrap();
    store.add_pc(pc("pc"), 1).unwrap();
    let mut conn = rusqlite::Connection::open(root.join("manager.sqlite3")).unwrap();
    let tx = conn.transaction().unwrap();
    for value in 1u128..=1001 {
        tx.execute("INSERT INTO operations(operation_id,pc_id,kind,state,submitted_at_ms,completed_at_ms) VALUES(?1,'pc','status','succeeded',?2,?2)",rusqlite::params![uuid::Uuid::from_u128(value).to_string(),value as i64]).unwrap();
    }
    let unknown = uuid::Uuid::new_v4();
    tx.execute("INSERT INTO operations(operation_id,pc_id,kind,state,submitted_at_ms) VALUES(?1,'pc','status','unknown_interrupted',0)",[unknown.to_string()]).unwrap();
    tx.commit().unwrap();
    drop(conn);
    assert_eq!(store.prune_terminal_operations(2000).unwrap(), 1);
    assert!(store.operation(uuid::Uuid::from_u128(1)).is_err());
    assert!(store.operation(uuid::Uuid::from_u128(2)).is_ok());
    assert_eq!(
        store.operation(unknown).unwrap().state,
        OperationState::UnknownInterrupted
    );
}
