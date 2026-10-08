//! Revision-gated service transitions; subprocesses are confined to the root adapter.
use wolf_core::{HostStatus, Revision, SafeError};
pub trait Backend {
    fn status(&mut self) -> Result<HostStatus, SafeError>;
    fn start(&mut self) -> Result<(), SafeError>;
    fn stop(&mut self) -> Result<(), SafeError>;
}
fn revision(status: &HostStatus, expected: &Revision) -> Result<(), SafeError> {
    if status.staged_revision.as_ref() != Some(expected) {
        Err(SafeError::new("revision_mismatch"))
    } else {
        Ok(())
    }
}
fn started(status: HostStatus) -> Result<HostStatus, SafeError> {
    if status.systemd_state != "active"
        || status.container_state != "running"
        || status.recovery_pending
        || status.running_revision.is_none()
    {
        Err(SafeError::new("host_unavailable"))
    } else {
        Ok(status)
    }
}
pub fn start(backend: &mut impl Backend, expected: &Revision) -> Result<HostStatus, SafeError> {
    let status = backend.status()?;
    revision(&status, expected)?;
    if status.recovery_pending {
        return Err(SafeError::new("recovery_pending"));
    }
    if status.systemd_state == "active" {
        return started(status);
    }
    backend.start()?;
    started_revision(backend.status()?, expected)
}
fn started_revision(status: HostStatus, expected: &Revision) -> Result<HostStatus, SafeError> {
    revision(&status, expected)?;
    if status.running_revision.as_ref() != Some(expected) {
        return Err(SafeError::new("host_unavailable"));
    }
    started(status)
}
pub fn restart(backend: &mut impl Backend, expected: &Revision) -> Result<HostStatus, SafeError> {
    let status = backend.status()?;
    revision(&status, expected)?;
    stop(backend)?;
    let status = backend.status()?;
    revision(&status, expected)?;
    if status.recovery_pending {
        return Err(SafeError::new("recovery_pending"));
    }
    backend.start()?;
    started_revision(backend.status()?, expected)
}
pub fn stop(backend: &mut impl Backend) -> Result<HostStatus, SafeError> {
    backend.stop()?;
    let status = backend.status()?;
    if status.recovery_pending {
        return Err(SafeError::new("recovery_pending"));
    }
    if status.systemd_state != "inactive" && status.systemd_state != "failed"
        || status.container_state == "running"
    {
        return Err(SafeError::new("host_unavailable"));
    }
    Ok(status)
}
pub trait Startup {
    fn refresh(&mut self) -> Result<(), SafeError>;
    fn cached_image(&mut self) -> Result<bool, SafeError>;
    fn cleanup(&mut self) -> Result<(), SafeError>;
    fn prepare(&mut self) -> Result<(), SafeError>;
    fn up(&mut self) -> Result<(), SafeError>;
    fn down_restore(&mut self) -> Result<(), SafeError>;
}
pub fn startup(backend: &mut impl Startup, pull: bool) -> Result<(), SafeError> {
    if pull {
        let _ = backend.refresh();
    }
    if !backend.cached_image()? {
        return Err(SafeError::new("host_unavailable"));
    }
    backend.cleanup()?;
    if let Err(error) = backend.prepare().and_then(|()| backend.up()) {
        let _ = backend.down_restore();
        return Err(error);
    }
    Ok(())
}
