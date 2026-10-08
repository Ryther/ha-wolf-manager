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
