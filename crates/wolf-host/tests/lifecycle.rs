use wolf_core::*;
use wolf_manager_host::lifecycle::{self, Backend, Startup};
struct Fake {
    status: HostStatus,
    events: Vec<&'static str>,
    cache: bool,
    fail_stop: bool,
    fail_up: bool,
}
impl Backend for Fake {
    fn status(&mut self) -> Result<HostStatus, SafeError> {
        Ok(self.status.clone())
    }
    fn start(&mut self) -> Result<(), SafeError> {
        self.events.push("start");
        self.status.systemd_state = "active".into();
        self.status.container_state = "running".into();
        self.status.running_revision = self.status.staged_revision.clone();
        Ok(())
    }
    fn stop(&mut self) -> Result<(), SafeError> {
        self.events.push("stop");
        if self.fail_stop {
            return Err(SafeError::new("recovery_pending"));
        }
        self.status.systemd_state = "inactive".into();
        self.status.container_state = "exited".into();
        self.status.running_revision = None;
        Ok(())
    }
}
impl Startup for Fake {
    fn refresh(&mut self) -> Result<(), SafeError> {
        self.events.push("pull");
        Err(SafeError::new("host_unavailable"))
    }
    fn cached_image(&mut self) -> Result<bool, SafeError> {
        self.events.push("inspect");
        Ok(self.cache)
    }
    fn cleanup(&mut self) -> Result<(), SafeError> {
        self.events.push("cleanup");
        Ok(())
    }
    fn prepare(&mut self) -> Result<(), SafeError> {
        self.events.push("prepare");
        Ok(())
    }
    fn up(&mut self) -> Result<(), SafeError> {
        self.events.push("up");
        if self.fail_up {
            Err(SafeError::new("host_unavailable"))
        } else {
            Ok(())
        }
    }
    fn down_restore(&mut self) -> Result<(), SafeError> {
        self.events.push("restore");
        Ok(())
    }
}
fn fake() -> Fake {
    Fake {
        status: HostStatus {
            systemd_state: "inactive".into(),
            container_state: "exited".into(),
            restart_count: 0,
            exit_code: Some(0),
            staged_revision: Some(Settings::default().revision().unwrap()),
            running_revision: None,
            recovery_pending: false,
        },
        events: vec![],
        cache: true,
        fail_stop: false,
        fail_up: false,
    }
}
struct UncertainBackend {
    inner: Fake,
    post_observation: bool,
    effects: bool,
}
impl Backend for UncertainBackend {
    fn status(&mut self) -> Result<HostStatus, SafeError> {
        if self.effects && self.post_observation {
            Err(SafeError::new("host_unavailable"))
        } else {
            self.inner.status()
        }
    }
    fn start(&mut self) -> Result<(), SafeError> {
        self.effects = true;
        self.inner.start()?;
        if self.post_observation {
            Ok(())
        } else {
            Err(SafeError::new("recovery_pending"))
        }
    }
    fn stop(&mut self) -> Result<(), SafeError> {
        self.effects = true;
        self.inner.stop()?;
        if self.post_observation {
            Ok(())
        } else {
            Err(SafeError::new("recovery_pending"))
        }
    }
}
#[test]
fn errors_after_lifecycle_submission_never_become_terminal_journal_proof() {
    use std::{fs, os::unix::fs::PermissionsExt};
    use wolf_manager_host::{journal::Journal, rpc};
    for post_observation in [false, true] {
        for kind in ["start", "stop", "restart"] {
            let temporary = tempfile::tempdir().unwrap();
            fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let journal = Journal::open(temporary.path()).unwrap();
            let mut backend = UncertainBackend {
                inner: fake(),
                post_observation,
                effects: false,
            };
            let revision = backend.inner.status.staged_revision.clone().unwrap();
            let payload = StartPayload {
                expected_staged_revision: revision.clone(),
            };
            let request = RpcRequest {
                version: 1,
                request_id: uuid::Uuid::new_v4(),
                pc_id: PcId::new("fixture").unwrap(),
                operation: match kind {
                    "start" => RpcOperation::Start(payload),
                    "stop" => RpcOperation::Stop(EmptyPayload {}),
                    _ => RpcOperation::Restart(payload),
                },
            };
            let outcome = rpc::serve(&journal, &request.pc_id, &request, |_| {
                match kind {
                    "start" => lifecycle::start(&mut backend, &revision),
                    "stop" => lifecycle::stop(&mut backend),
                    _ => lifecycle::restart(&mut backend, &revision),
                }
                .map(RpcResult::Lifecycle)
            });
            assert!(backend.effects);
            assert!(outcome.is_err(), "{kind} incorrectly issued terminal proof");
            let evidence = journal.lookup(request.request_id, &request.pc_id).unwrap();
            assert_eq!(evidence.phase, Some(JournalPhase::Running));
            assert!(evidence.result.is_none());
            assert!(
                rpc::serve(&journal, &request.pc_id, &request, |_| panic!("replayed")).is_err()
            );
        }
    }
}
#[test]
fn registry_failure_uses_cache_and_missing_cache_refuses_before_cleanup() {
    let mut f = fake();
    lifecycle::startup(&mut f, true).unwrap();
    assert_eq!(
        f.events,
        vec!["pull", "inspect", "cleanup", "prepare", "up"]
    );
    let mut f = fake();
    f.cache = false;
    assert!(lifecycle::startup(&mut f, true).is_err());
    assert_eq!(f.events, vec!["pull", "inspect"]);
}
#[test]
fn revision_mismatch_never_stops_running_service_and_restore_failure_never_starts() {
    let mut f = fake();
    f.status.systemd_state = "active".into();
    f.status.container_state = "running".into();
    assert!(lifecycle::restart(&mut f, &Revision::new("a".repeat(64)).unwrap()).is_err());
    assert!(f.events.is_empty());
    let expected = f.status.staged_revision.clone().unwrap();
    f.fail_stop = true;
    assert!(lifecycle::restart(&mut f, &expected).is_err());
    assert_eq!(f.events, vec!["stop"]);
}
#[test]
fn already_active_start_has_no_effect_and_failed_up_runs_guarded_restore() {
    let mut f = fake();
    f.status.systemd_state = "active".into();
    f.status.container_state = "running".into();
    f.status.running_revision = f.status.staged_revision.clone();
    let expected = f.status.staged_revision.clone().unwrap();
    lifecycle::start(&mut f, &expected).unwrap();
    assert!(f.events.is_empty());
    let mut f = fake();
    f.fail_up = true;
    assert!(lifecycle::startup(&mut f, false).is_err());
    assert_eq!(
        f.events,
        vec!["inspect", "cleanup", "prepare", "up", "restore"]
    );
}
#[test]
fn active_start_still_requires_the_requested_stage_and_consistent_observations() {
    let mut f = fake();
    f.status.systemd_state = "active".into();
    f.status.container_state = "running".into();
    f.status.running_revision = f.status.staged_revision.clone();
    let expected = f.status.staged_revision.clone().unwrap();
    assert!(lifecycle::start(&mut f, &Revision::new("a".repeat(64)).unwrap()).is_err());
    f.status.container_state = "exited".into();
    assert!(lifecycle::start(&mut f, &expected).is_err());
    f.status.container_state = "running".into();
    f.status.recovery_pending = true;
    assert!(lifecycle::start(&mut f, &expected).is_err());
    assert!(f.events.is_empty());
}

struct Observations {
    statuses: std::collections::VecDeque<HostStatus>,
    events: Vec<&'static str>,
}
impl Backend for Observations {
    fn status(&mut self) -> Result<HostStatus, SafeError> {
        Ok(self.statuses.pop_front().expect("unexpected observation"))
    }
    fn start(&mut self) -> Result<(), SafeError> {
        self.events.push("start");
        Ok(())
    }
    fn stop(&mut self) -> Result<(), SafeError> {
        self.events.push("stop");
        Ok(())
    }
}

#[test]
fn restart_requires_stopped_observation_and_unchanged_stage_before_start() {
    let original = fake().status;
    let revision = original.staged_revision.clone().unwrap();
    for failure in [
        "recovery",
        "active",
        "running",
        "changed-stage",
        "recovery-after-stop",
    ] {
        let mut stopped = original.clone();
        match failure {
            "recovery" => stopped.recovery_pending = true,
            "active" => stopped.systemd_state = "active".into(),
            "running" => stopped.container_state = "running".into(),
            _ => {}
        }
        let mut rechecked = original.clone();
        if failure == "changed-stage" {
            rechecked.staged_revision = Some(Revision::new("b".repeat(64)).unwrap());
        }
        if failure == "recovery-after-stop" {
            rechecked.recovery_pending = true;
        }
        let mut backend = Observations {
            statuses: [original.clone(), stopped, rechecked].into(),
            events: vec![],
        };
        assert_eq!(
            lifecycle::restart(&mut backend, &revision)
                .unwrap_err()
                .code(),
            ErrorCode::UnknownInterrupted
        );
        assert_eq!(backend.events, ["stop"], "unsafe restart: {failure}");
    }
    let mut running = original.clone();
    running.systemd_state = "active".into();
    running.container_state = "running".into();
    running.running_revision = Some(revision.clone());
    let mut backend = Observations {
        statuses: [
            original.clone(),
            original.clone(),
            original,
            running.clone(),
        ]
        .into(),
        events: vec![],
    };
    assert_eq!(
        lifecycle::restart(&mut backend, &revision).unwrap(),
        running
    );
    assert_eq!(backend.events, ["stop", "start"]);
}

#[test]
fn submitted_start_without_exact_running_revision_remains_uncertain() {
    let original = fake().status;
    let expected = original.staged_revision.clone().unwrap();
    for failure in [
        "wrong-running",
        "wrong-staged",
        "not-active",
        "not-running",
        "recovery",
    ] {
        let mut result = original.clone();
        result.systemd_state = "active".into();
        result.container_state = "running".into();
        result.running_revision = Some(expected.clone());
        match failure {
            "wrong-running" => {
                result.running_revision = Some(Revision::new("b".repeat(64)).unwrap())
            }
            "wrong-staged" => result.staged_revision = None,
            "not-active" => result.systemd_state = "failed".into(),
            "not-running" => result.container_state = "exited".into(),
            _ => result.recovery_pending = true,
        }
        let mut backend = Observations {
            statuses: [original.clone(), result].into(),
            events: vec![],
        };
        assert_eq!(
            lifecycle::start(&mut backend, &expected)
                .unwrap_err()
                .code(),
            ErrorCode::UnknownInterrupted
        );
        assert_eq!(backend.events, ["start"]);
    }
}
