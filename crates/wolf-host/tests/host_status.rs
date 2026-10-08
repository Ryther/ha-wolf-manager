use wolf_manager_host::host_status::observed;
#[test]
fn live_session_overlay_is_not_recovery_but_stopped_overlay_is() {
    let docker = br#"{"State":{"Status":"running","ExitCode":0},"RestartCount":3}"#;
    let live = observed("active", docker, None, None, true, false).unwrap();
    assert!(!live.recovery_pending);
    assert_eq!(live.restart_count, 3);
    let stopped = observed("inactive", docker, None, None, true, false).unwrap();
    assert!(stopped.recovery_pending);
    assert!(
        observed("active", docker, None, None, true, true)
            .unwrap()
            .recovery_pending
    );
}
#[test]
fn malformed_observation_fails_instead_of_reporting_stopped() {
    assert!(
        observed(
            "active",
            br#"{"State":{"Status":"unknown"}}"#,
            None,
            None,
            false,
            false
        )
        .is_err()
    );
    assert!(observed("nonsense", b"", None, None, false, false).is_err());
}
