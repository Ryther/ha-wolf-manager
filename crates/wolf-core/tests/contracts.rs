use serde_json::json;
use wolf_core::*;
#[test]
fn closed_ids_and_revision() {
    for id in ["", "UPPER", "a/b", "a+", "-pc"] {
        assert!(PcId::new(id).is_err());
    }
    assert_eq!(PcId::new("pc_one").unwrap().as_str(), "pc_one");
    assert!(AppId::new("1234567890123").is_err());
    assert!(serde_json::from_str::<AppId>("\"abc\"").is_err());
    assert!(ParameterId::new("with space").is_err());
    assert!(Revision::new("A".repeat(64)).is_err());
}
#[test]
fn settings_legacy_and_hash_are_canonical() {
    let settings = Settings::import_legacy(&json!({"games":{"42":{"parameters":["fsr4_indicator","fsr4_indicator","missing"],"fsr4":true}},"debug":{"test_ball":true}})).unwrap();
    assert_eq!(
        settings.games[&AppId::new("42").unwrap()]
            .parameters
            .iter()
            .map(ParameterId::as_str)
            .collect::<Vec<_>>(),
        vec!["fsr4_indicator", "fsr4"]
    );
    assert_eq!(
        settings.parameters[&ParameterId::new("fsr4").unwrap()].launch_options,
        "PROTON_FSR4_UPGRADE=1 %command%"
    );
    let a: Settings =
        serde_json::from_value(json!({"debug":{"test_ball":false},"parameters":{},"games":{}}))
            .unwrap();
    let b: Settings =
        serde_json::from_str(r#"{"games":{},"parameters":{},"debug":{"test_ball":false}}"#)
            .unwrap();
    assert_eq!(a.revision().unwrap(), b.revision().unwrap());
    assert_ne!(a.revision().unwrap(), settings.revision().unwrap());
}
#[test]
fn strict_settings_refuse_legacy_and_unknown_assignments() {
    assert!(
        serde_json::from_value::<Settings>(
            json!({"debug":{"test_ball":false,"other":1},"parameters":{},"games":{}})
        )
        .is_err()
    );
    assert!(serde_json::from_value::<Settings>(json!({"debug":{"test_ball":false},"parameters":{},"games":{"42":{"direct_launch":false,"proton_cachyos":false,"parameters":["unknown"]}}})).unwrap().validate().is_err());
}
#[test]
fn rpc_is_closed_bounded_and_hash_checked() {
    let req = json!({"version":1,"request_id":"00000000-0000-4000-8000-000000000001","pc_id":"pc_one","operation":"status","payload":{}});
    let encoded = serde_json::to_vec(&req).unwrap();
    assert!(RpcRequest::parse(&encoded).is_ok());
    let mut bad = req.clone();
    bad["payload"] = json!({"unit":"arbitrary"});
    assert!(RpcRequest::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
    bad = req.clone();
    bad["version"] = json!(2);
    assert!(RpcRequest::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
    bad = req;
    bad["extra"] = json!(true);
    assert!(RpcRequest::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
    assert!(RpcRequest::parse(&vec![b' '; 65537]).is_err());
}
#[test]
fn mqtt_topics_scope_identity_and_commands_refuse_retained() {
    let topics = Topics::new("wolf-manager/v1", "homeassistant").unwrap();
    let a = PcId::new("pc_a").unwrap();
    let b = PcId::new("pc_b").unwrap();
    let app = AppId::new("42").unwrap();
    assert_ne!(
        topics.catalog_attributes(&a, &app),
        topics.catalog_attributes(&b, &app)
    );
    assert_eq!(
        topics.catalog_attributes(&a, &app),
        "wolf-manager/v1/pc_a/catalog/42/attributes"
    );
    assert!(Topics::new("bad/+", "homeassistant").is_err());
    assert_eq!(validate_command(b"ON", false).unwrap(), ServiceCommand::On);
    for p in [b" ON".as_slice(), b"OFF\n", b"RESTART", b"on"] {
        assert!(validate_command(p, false).is_err());
    }
    assert!(validate_command(b"ON", true).is_err());
}
fn child(ordinal: u32, kind: OperationKind, dispatch_phase: DispatchPhase) -> ChildRequest {
    ChildRequest {
        request_id: uuid::Uuid::from_u128(ordinal as u128 + 1),
        pc_id: PcId::new("pc").unwrap(),
        kind,
        ordinal,
        canonical_request_sha256: Revision::new("0".repeat(64)).unwrap(),
        dispatch_phase,
    }
}
fn success(child: &ChildRequest) -> JournalObservation {
    JournalObservation {
        found: true,
        request_id: child.request_id,
        pc_id: child.pc_id.clone(),
        canonical_request_sha256: Some(child.canonical_request_sha256.clone()),
        phase: Some(JournalPhase::Succeeded),
        observed_at_ms: 1,
        result: None,
        error: None,
    }
}
#[test]
fn reconciliation_requires_all_child_evidence() {
    let stage = child(0, OperationKind::ApplySettings, DispatchPhase::Sent);
    let primary = child(1, OperationKind::Restart, DispatchPhase::NotDispatched);
    assert_eq!(
        reconcile_children(&[stage.clone(), primary.clone()], &[]).state,
        OperationState::UnknownInterrupted
    );
    let result = reconcile_children(&[stage.clone(), primary], &[success(&stage)]);
    assert_eq!(result.state, OperationState::Failed);
    assert_eq!(result.code, Some("primary_not_dispatched"));
    assert!(result.stage_succeeded);
    let primary = child(1, OperationKind::Restart, DispatchPhase::Sent);
    assert_eq!(
        reconcile_children(&[stage.clone(), primary.clone()], &[success(&stage)]).state,
        OperationState::UnknownInterrupted
    );
    assert_eq!(
        reconcile_children(
            &[stage.clone(), primary.clone()],
            &[success(&stage), success(&primary)]
        )
        .state,
        OperationState::Succeeded
    );
    let mut wrong = success(&stage);
    wrong.pc_id = PcId::new("other").unwrap();
    assert_eq!(
        reconcile_children(&[stage], &[wrong]).state,
        OperationState::UnknownInterrupted
    );
}
#[test]
fn catalog_manifest_refuses_unsorted_duplicate_or_incomplete_data() {
    let mut manifest = CatalogManifest {
        version: 1,
        pc_id: PcId::new("pc").unwrap(),
        catalog_generation: 1,
        app_ids: vec![AppId::new("42").unwrap(), AppId::new("42").unwrap()],
        observed_at_ms: 1,
        complete: true,
    };
    assert!(manifest.validate().is_err());
    manifest.app_ids.clear();
    assert!(manifest.validate().is_ok());
    manifest.complete = false;
    assert!(manifest.validate().is_err());
}
#[test]
fn catalog_requires_complete_matching_generation_before_replacing_projection() {
    let pc = PcId::new("pc").unwrap();
    let app = AppId::new("42").unwrap();
    let manifest = CatalogManifest {
        version: 1,
        pc_id: pc.clone(),
        catalog_generation: 2,
        app_ids: vec![app.clone()],
        observed_at_ms: 1,
        complete: true,
    };
    let attrs=CatalogAttributes{version:1,pc_id:pc.clone(),app_id:app,name:"Synthetic game".into(),cover_url:"https://shared.fastly.steamstatic.com/store_item_assets/steam/apps/42/library_600x900.jpg".into(),library_id:"library_one".into(),catalog_generation:2,observed_at_ms:1};
    assert!(validate_catalog_generation(&pc, &manifest, &[], None).is_err());
    let valid =
        validate_catalog_generation(&pc, &manifest, std::slice::from_ref(&attrs), None).unwrap();
    assert_eq!(valid.len(), 1);
    let mut wrong = attrs.clone();
    wrong.catalog_generation = 1;
    assert!(validate_catalog_generation(&pc, &manifest, &[wrong], None).is_err());
    let mut wrong = attrs.clone();
    wrong.pc_id = PcId::new("other").unwrap();
    assert!(validate_catalog_generation(&pc, &manifest, &[wrong], None).is_err());
    let mut conflict = attrs.clone();
    conflict.name = "Conflicting".into();
    assert!(
        validate_catalog_generation(&pc, &manifest, &[conflict], Some((&manifest, &valid)))
            .is_err()
    );
    let mut older = manifest.clone();
    older.catalog_generation = 1;
    assert!(validate_catalog_generation(&pc, &older, &[attrs], Some((&manifest, &valid))).is_err());
}
#[test]
fn reconciliation_rejects_incomplete_or_conflicting_plan() {
    let a = child(0, OperationKind::ApplySettings, DispatchPhase::Sent);
    let b = child(2, OperationKind::Restart, DispatchPhase::Sent);
    assert_eq!(
        reconcile_children(&[a.clone(), b.clone()], &[success(&a), success(&b)]).state,
        OperationState::UnknownInterrupted
    );
}
#[test]
fn settings_launch_options_and_duplicate_assignments_are_refused() {
    let mut settings = Settings::default();
    let id = ParameterId::new("fsr4").unwrap();
    settings.games.insert(
        AppId::new("42").unwrap(),
        GameSettings {
            direct_launch: false,
            proton_cachyos: false,
            parameters: vec![id.clone(), id.clone()],
        },
    );
    assert!(settings.validate().is_err());
    settings.games.clear();
    settings.parameters.get_mut(&id).unwrap().launch_options = "x\ny".into();
    assert!(settings.validate().is_err());
}
#[test]
fn overrides_drop_inactive_games_without_changing_desired_revision() {
    let mut settings = Settings::default();
    settings
        .games
        .insert(AppId::new("42").unwrap(), GameSettings::default());
    assert!(settings.build_overrides().unwrap().games.is_empty());
    assert_eq!(settings.games.len(), 1);
}
#[test]
fn rpc_settings_wrong_hash_and_result_kind_are_refused() {
    let settings = Settings::default();
    let req = RpcRequest {
        version: 1,
        request_id: uuid::Uuid::from_u128(1),
        pc_id: PcId::new("pc").unwrap(),
        operation: RpcOperation::ApplySettings(ApplySettingsPayload {
            settings,
            revision: Revision::new("0".repeat(64)).unwrap(),
        }),
    };
    assert!(req.validate().is_err());
    let req = RpcRequest {
        operation: RpcOperation::Status(EmptyPayload {}),
        ..req
    };
    let response = RpcResponse {
        version: 1,
        request_id: req.request_id,
        pc_id: req.pc_id.clone(),
        ok: true,
        result: Some(RpcResult::Logs {
            lines: vec![],
            truncated: false,
        }),
        error: None,
    };
    assert!(response.validate_for(&req).is_err());
}
#[test]
fn discovery_switch_has_both_availability_sources() {
    let topics = Topics::new("wolf-manager/v1", "homeassistant").unwrap();
    let pc = PcId::new("pc").unwrap();
    let discovery = topics.switch_discovery_payload(&pc, "Synthetic PC", uuid::Uuid::from_u128(1));
    assert_eq!(discovery["availability_mode"], "all");
    assert_eq!(discovery["availability"].as_array().unwrap().len(), 2);
    assert_eq!(discovery["optimistic"], false);
    assert_eq!(discovery["retain"], false);
}
#[test]
fn rpc_response_logs_obey_output_bounds() {
    let req = RpcRequest {
        version: 1,
        request_id: uuid::Uuid::from_u128(1),
        pc_id: PcId::new("pc").unwrap(),
        operation: RpcOperation::BoundedLogs(LogsPayload { lines: 10 }),
    };
    let response = RpcResponse {
        version: 1,
        request_id: req.request_id,
        pc_id: req.pc_id.clone(),
        ok: true,
        result: Some(RpcResult::Logs {
            lines: vec!["x".repeat(1024 * 1024)],
            truncated: false,
        }),
        error: None,
    };
    assert!(response.validate_for(&req).is_err());
}
#[test]
fn legacy_import_refuses_an_unknown_versioned_format() {
    assert!(Settings::import_legacy(&json!({"version":2,"games":{}})).is_err());
}
#[test]
fn canonical_json_has_a_known_sha256_and_recursively_orders_keys() {
    let input = json!({"z":{"b":2,"a":1},"a":[{"d":4,"c":3}]});
    assert_eq!(
        canonical_json(&input).unwrap(),
        br#"{"a":[{"c":3,"d":4}],"z":{"a":1,"b":2}}"#
    );
    assert_eq!(
        revision_of(&json!({})).unwrap().as_str(),
        "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    );
}
#[test]
fn unsupported_proton_selection_refuses_before_dispatch() {
    let capabilities = HostCapabilities {
        version: 1,
        pc_id: PcId::new("pc").unwrap(),
        ready: true,
        proton_cachyos: false,
        reasons: vec![],
    };
    let mut settings = Settings::default();
    settings.games.insert(
        AppId::new("42").unwrap(),
        GameSettings {
            direct_launch: false,
            proton_cachyos: true,
            parameters: vec![],
        },
    );
    assert!(settings.validate_capabilities(&capabilities).is_err());
}
#[test]
fn contradictory_and_unowned_journal_evidence_remains_unknown() {
    let stage = child(0, OperationKind::ApplySettings, DispatchPhase::Sent);
    let primary = child(1, OperationKind::Restart, DispatchPhase::NotDispatched);
    assert_eq!(
        reconcile_children(
            &[stage.clone(), primary.clone()],
            &[success(&stage), success(&primary)]
        )
        .state,
        OperationState::UnknownInterrupted
    );
    let stranger = child(2, OperationKind::Stop, DispatchPhase::Sent);
    assert_eq!(
        reconcile_children(
            &[stage.clone(), primary],
            &[success(&stage), success(&stranger)]
        )
        .state,
        OperationState::UnknownInterrupted
    );
}
#[test]
fn primary_not_dispatched_is_only_a_stage_then_lifecycle_plan() {
    let stage = child(0, OperationKind::ApplySettings, DispatchPhase::Sent);
    let unrelated = child(1, OperationKind::Status, DispatchPhase::NotDispatched);
    assert_eq!(
        reconcile_children(&[stage.clone(), unrelated], &[success(&stage)]).state,
        OperationState::UnknownInterrupted
    );
}
fn request(operation: RpcOperation) -> RpcRequest {
    RpcRequest {
        version: 1,
        request_id: uuid::Uuid::from_u128(5),
        pc_id: PcId::new("pc").unwrap(),
        operation,
    }
}
fn response(request: &RpcRequest, result: RpcResult) -> RpcResponse {
    RpcResponse {
        version: 1,
        request_id: request.request_id,
        pc_id: request.pc_id.clone(),
        ok: true,
        result: Some(result),
        error: None,
    }
}
#[test]
fn rpc_reply_data_is_bound_to_request_identity_and_revision() {
    let settings = Settings::default();
    let revision = settings.revision().unwrap();
    let req = request(RpcOperation::ApplySettings(ApplySettingsPayload {
        settings,
        revision,
    }));
    assert!(
        response(
            &req,
            RpcResult::Applied {
                staged_revision: Revision::new("0".repeat(64)).unwrap()
            }
        )
        .validate_for(&req)
        .is_err()
    );
    let original = child(0, OperationKind::Stop, DispatchPhase::Sent);
    let req = request(RpcOperation::RequestStatus(RequestStatusPayload {
        original_request_id: original.request_id,
    }));
    let mut journal = success(&original);
    journal.request_id = uuid::Uuid::from_u128(99);
    assert!(
        response(&req, RpcResult::RequestStatus(journal))
            .validate_for(&req)
            .is_err()
    );
    let mut journal = success(&original);
    journal.pc_id = PcId::new("other").unwrap();
    assert!(
        response(&req, RpcResult::RequestStatus(journal))
            .validate_for(&req)
            .is_err()
    );
    let req = request(RpcOperation::Preflight(EmptyPayload {}));
    let capabilities = HostCapabilities {
        version: 2,
        pc_id: req.pc_id.clone(),
        ready: true,
        proton_cachyos: true,
        reasons: vec![],
    };
    assert!(
        response(&req, RpcResult::Preflight(capabilities))
            .validate_for(&req)
            .is_err()
    );
    let capabilities = HostCapabilities {
        version: 1,
        pc_id: PcId::new("other").unwrap(),
        ready: true,
        proton_cachyos: true,
        reasons: vec![],
    };
    assert!(
        response(&req, RpcResult::Preflight(capabilities))
            .validate_for(&req)
            .is_err()
    );
}
#[test]
fn error_decode_refuses_arbitrary_external_codes_and_messages() {
    assert!(
        serde_json::from_value::<SafeError>(json!({"code":"external","message":"secret token"}))
            .is_err()
    );
    assert!(
        serde_json::from_value::<SafeError>(
            json!({"code":"validation_failed","message":"secret token"})
        )
        .is_err()
    );
    let error = SafeError::validation();
    assert_eq!(
        serde_json::from_slice::<SafeError>(&serde_json::to_vec(&error).unwrap()).unwrap(),
        error
    );
    assert_eq!(
        serde_json::to_value(SafeError::new("untrusted_code")).unwrap()["code"],
        "internal_error"
    );
}
#[test]
fn explicit_legacy_import_preserves_long_valid_definitions_and_assignments() {
    let label = "L".repeat(300);
    let description = "D".repeat(5000);
    let settings=Settings::import_legacy(&json!({"parameters":{"custom":{"label":label,"description":description,"launch_options":"SYNTHETIC=1 %command%"}},"games":{"42":{"parameters":["custom"]}}})).unwrap();
    let custom = ParameterId::new("custom").unwrap();
    assert_eq!(settings.parameters.get(&custom).unwrap().label.len(), 300);
    assert_eq!(settings.parameters[&custom].description.len(), 5000);
    assert_eq!(
        settings.games[&AppId::new("42").unwrap()].parameters,
        vec![custom]
    );
    assert!(settings.validate().is_ok());
    assert!(settings.revision().is_ok());
}
