//! Fixed service transitions and bounded startup with cached-image fallback.
use crate::{
    host_status::{Tool, Tools, checked},
    policy::RootPolicy,
};
use std::{
    io,
    time::{Duration, Instant},
};
use wolf_core::SafeError;
pub trait Effects {
    fn prepare(&mut self) -> io::Result<()>;
    fn restore(&mut self) -> io::Result<()>;
    fn mark_running(&mut self, running: bool) -> io::Result<()>;
}
pub struct StartupAdapter<'a, T: Tools, H: Effects> {
    policy: &'a RootPolicy,
    tools: T,
    effects: H,
    deadline: Option<Instant>,
}
impl<'a, T: Tools, H: Effects> StartupAdapter<'a, T, H> {
    pub fn new(policy: &'a RootPolicy, tools: T, effects: H) -> io::Result<Self> {
        policy.validate_structure()?;
        Ok(Self {
            policy,
            tools,
            effects,
            deadline: None,
        })
    }
}
fn safe(error: io::Error) -> SafeError {
    SafeError::new(if error.kind() == io::ErrorKind::TimedOut {
        "unknown_interrupted"
    } else {
        "recovery_pending"
    })
}
impl<T: Tools, H: Effects> StartupAdapter<'_, T, H> {
    fn remaining(&self) -> io::Result<Duration> {
        let remaining = self
            .deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
            .unwrap_or(Duration::from_secs(180));
        if remaining.is_zero() {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "startup outcome requires reconciliation",
            ))
        } else {
            Ok(remaining)
        }
    }
    fn compose(&mut self, arguments: &[&str]) -> io::Result<()> {
        let path = self
            .policy
            .compose_file
            .to_str()
            .ok_or_else(|| io::Error::other("invalid Compose path"))?;
        let mut args = vec!["compose", "--file", path];
        args.extend_from_slice(arguments);
        let remaining = self.remaining()?;
        checked(self.tools.run(Tool::Docker, &args, remaining)?)?;
        Ok(())
    }
}
impl<T: Tools, H: Effects> crate::lifecycle::Startup for StartupAdapter<'_, T, H> {
    fn refresh(&mut self) -> Result<(), SafeError> {
        checked(
            self.tools
                .run(
                    Tool::Docker,
                    &["pull", &self.policy.image_ref],
                    Duration::from_secs(self.policy.pull_timeout_seconds),
                )
                .map_err(safe)?,
        )
        .map(|_| ())
        .map_err(safe)
    }
    fn cached_image(&mut self) -> Result<bool, SafeError> {
        let output = self
            .tools
            .run(
                Tool::Docker,
                &[
                    "image",
                    "inspect",
                    "--format",
                    "{{json .}}",
                    &self.policy.image_ref,
                ],
                Duration::from_secs(5),
            )
            .map_err(safe)?;
        if output.code != Some(0) {
            return Ok(false);
        }
        let image: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|_| SafeError::new("host_unavailable"))?;
        let architecture = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            _ => return Ok(false),
        };
        Ok(image
            .get("Architecture")
            .and_then(serde_json::Value::as_str)
            == Some(architecture)
            && image.get("Os").and_then(serde_json::Value::as_str) == Some("linux"))
    }
    fn cleanup(&mut self) -> Result<(), SafeError> {
        self.deadline = Some(Instant::now() + Duration::from_secs(180));
        self.compose(&["down", "--timeout", "20"]).map_err(safe)?;
        let remaining = self.remaining().map_err(safe)?;
        stop_owned(self.policy, &mut self.tools, remaining).map_err(safe)?;
        let remaining = self.remaining().map_err(safe)?;
        require_no_container_writers(self.policy, &mut self.tools, remaining).map_err(safe)?;
        self.effects.restore().map_err(safe)?;
        self.effects.mark_running(false).map_err(safe)
    }
    fn prepare(&mut self) -> Result<(), SafeError> {
        self.remaining().map_err(safe)?;
        self.effects.prepare().map_err(safe)?;
        self.remaining().map_err(safe)?;
        Ok(())
    }
    fn up(&mut self) -> Result<(), SafeError> {
        self.compose(&["up", "--detach", "--pull", "never", "--no-build"])
            .map_err(safe)?;
        let remaining = self.remaining().map_err(safe)?;
        let observation =
            crate::host_status::container(self.policy, &mut self.tools, remaining).map_err(safe)?;
        let status = crate::host_status::observed("active", &observation, None, None, false, false)
            .map_err(safe)?;
        if status.container_state != "running" {
            return Err(SafeError::new("host_unavailable"));
        }
        self.effects.mark_running(true).map_err(safe)
    }
    fn down_restore(&mut self) -> Result<(), SafeError> {
        if self.deadline.is_none() {
            self.deadline = Some(Instant::now() + Duration::from_secs(180));
        }
        self.compose(&["down", "--timeout", "20"]).map_err(safe)?;
        let remaining = self.remaining().map_err(safe)?;
        stop_owned(self.policy, &mut self.tools, remaining).map_err(safe)?;
        let remaining = self.remaining().map_err(safe)?;
        require_no_container_writers(self.policy, &mut self.tools, remaining).map_err(safe)?;
        self.effects.restore().map_err(safe)?;
        self.effects.mark_running(false).map_err(safe)
    }
}
pub struct SystemBackend<'a> {
    policy: &'a RootPolicy,
}
impl<'a> SystemBackend<'a> {
    pub fn new(policy: &'a RootPolicy) -> io::Result<Self> {
        policy.validate()?;
        Ok(Self { policy })
    }
}
impl crate::lifecycle::Backend for SystemBackend<'_> {
    fn status(&mut self) -> Result<wolf_core::HostStatus, SafeError> {
        crate::host_status::read(self.policy).map_err(safe)
    }
    fn start(&mut self) -> Result<(), SafeError> {
        self.policy.validate().map_err(safe)?;
        checked(
            crate::host_status::FixedTools
                .run(
                    Tool::Systemctl,
                    &["start", &self.policy.service_unit],
                    Duration::from_secs(self.policy.pull_timeout_seconds + 200),
                )
                .map_err(safe)?,
        )
        .map(|_| ())
        .map_err(safe)
    }
    fn stop(&mut self) -> Result<(), SafeError> {
        self.policy.validate().map_err(safe)?;
        checked(
            crate::host_status::FixedTools
                .run(
                    Tool::Systemctl,
                    &["stop", &self.policy.service_unit],
                    Duration::from_secs(190),
                )
                .map_err(safe)?,
        )
        .map(|_| ())
        .map_err(safe)
    }
}
struct RealEffects<'a> {
    policy: &'a RootPolicy,
    state: crate::state::State,
    staged: Option<(wolf_core::Settings, wolf_core::Revision)>,
}
impl Effects for RealEffects<'_> {
    fn prepare(&mut self) -> io::Result<()> {
        let (settings, _) = self
            .staged
            .as_ref()
            .ok_or_else(|| io::Error::other("staged revision is absent"))?;
        crate::host_steam::prepare(self.policy, settings)
    }
    fn restore(&mut self) -> io::Result<()> {
        crate::host_steam::restore(self.policy)
    }
    fn mark_running(&mut self, running: bool) -> io::Result<()> {
        self.state.set_running(if running {
            Some(
                &self
                    .staged
                    .as_ref()
                    .ok_or_else(|| io::Error::other("staged revision is absent"))?
                    .1,
            )
        } else {
            None
        })
    }
}
pub fn lifecycle_start(policy: &RootPolicy) -> io::Result<()> {
    policy.validate()?;
    let state = crate::state::State::open(&policy.state_root, &policy.pc_id)?;
    let staged = state.staged_or_default(&wolf_core::Settings::default())?;
    let effects = RealEffects {
        policy,
        state,
        staged: Some(staged),
    };
    let mut adapter = StartupAdapter::new(policy, crate::host_status::FixedTools, effects)?;
    crate::lifecycle::startup(&mut adapter, policy.pull_on_start).map_err(|error| {
        io::Error::new(
            if error.code() == wolf_core::ErrorCode::UnknownInterrupted {
                io::ErrorKind::TimedOut
            } else {
                io::ErrorKind::Other
            },
            error.code().as_str(),
        )
    })
}
pub fn lifecycle_stop(policy: &RootPolicy) -> io::Result<()> {
    policy.validate()?;
    let state = crate::state::State::open(&policy.state_root, &policy.pc_id)?;
    let staged = state.staged()?;
    let effects = RealEffects {
        policy,
        state,
        staged,
    };
    let mut adapter = StartupAdapter::new(policy, crate::host_status::FixedTools, effects)?;
    crate::lifecycle::Startup::down_restore(&mut adapter).map_err(|error| {
        io::Error::new(
            if error.code() == wolf_core::ErrorCode::UnknownInterrupted {
                io::ErrorKind::TimedOut
            } else {
                io::ErrorKind::Other
            },
            error.code().as_str(),
        )
    })
}
// Docker label selectors are discovery only; every inspected identity is verified
// again before a stop. Existing containers and all volumes remain retained.
fn tool_before(tools: &mut impl Tools, args: &[&str], deadline: Instant) -> io::Result<Vec<u8>> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "cleanup outcome requires reconciliation",
        ));
    }
    checked(tools.run(Tool::Docker, args, remaining)?)
}
fn ids(bytes: &[u8]) -> io::Result<Vec<String>> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| io::Error::other("invalid container list"))?;
    let mut ids = Vec::new();
    for id in text.lines() {
        if ids.len() >= 1000
            || id.len() != 64
            || !id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || ids.iter().any(|prior| prior == id)
        {
            return Err(io::Error::other(
                "invalid or oversized container identity list",
            ));
        }
        ids.push(id.to_owned());
    }
    Ok(ids)
}
fn inspect(tools: &mut impl Tools, id: &str, deadline: Instant) -> io::Result<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_slice(&tool_before(
        tools,
        &["container", "inspect", "--format", "{{json .}}", id],
        deadline,
    )?)?;
    if value.get("Id").and_then(serde_json::Value::as_str) != Some(id) {
        return Err(io::Error::other("container identity changed"));
    }
    Ok(value)
}
fn owned_status<'a>(policy: &RootPolicy, value: &'a serde_json::Value) -> io::Result<&'a str> {
    let labels = value
        .get("Config")
        .and_then(|c| c.get("Labels"))
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| io::Error::other("container ownership is absent"))?;
    if labels
        .get("io.ha-wolf-manager.pc")
        .and_then(serde_json::Value::as_str)
        != Some(policy.pc_id.as_str())
        || labels
            .get("io.ha-wolf-manager.owner")
            .and_then(serde_json::Value::as_str)
            != Some("managed-steam-v1")
    {
        return Err(io::Error::other("container ownership changed"));
    }
    value
        .get("State")
        .and_then(|v| v.get("Status"))
        .and_then(serde_json::Value::as_str)
        .filter(|s| {
            [
                "created",
                "running",
                "paused",
                "restarting",
                "removing",
                "exited",
                "dead",
            ]
            .contains(s)
        })
        .ok_or_else(|| io::Error::other("invalid owned container state"))
}
pub fn stop_owned(
    policy: &RootPolicy,
    tools: &mut impl Tools,
    timeout: Duration,
) -> io::Result<()> {
    policy.validate_structure()?;
    let deadline = Instant::now() + timeout.min(Duration::from_secs(180));
    let pc = format!("label=io.ha-wolf-manager.pc={}", policy.pc_id.as_str());
    let selected = ids(&tool_before(
        tools,
        &[
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--filter",
            &pc,
            "--filter",
            "label=io.ha-wolf-manager.owner=managed-steam-v1",
            "--format",
            "{{.ID}}",
        ],
        deadline,
    )?)?;
    // Verify the entire discovery result before the first effect.
    for id in &selected {
        owned_status(policy, &inspect(tools, id, deadline)?)?;
    }
    for id in &selected {
        let value = inspect(tools, id, deadline)?;
        let status = owned_status(policy, &value)?;
        if ["running", "paused", "restarting"].contains(&status) {
            tool_before(tools, &["container", "stop", "--time", "20", id], deadline)?;
        }
        if !["created", "exited", "dead"]
            .contains(&owned_status(policy, &inspect(tools, id, deadline)?)?)
        {
            return Err(io::Error::other("owned Steam container is not stopped"));
        }
    }
    Ok(())
}
pub fn require_no_container_writers(
    policy: &RootPolicy,
    tools: &mut impl Tools,
    timeout: Duration,
) -> io::Result<()> {
    policy.validate_structure()?;
    let deadline = Instant::now() + timeout.min(Duration::from_secs(180));
    let selected = ids(&tool_before(
        tools,
        &[
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--format",
            "{{.ID}}",
        ],
        deadline,
    )?)?;
    let roots = policy
        .libraries
        .iter()
        .map(|library| library.steamapps_path.as_path())
        .chain(
            policy
                .steam_profiles
                .iter()
                .map(|profile| profile.root.as_path()),
        )
        .chain(std::iter::once(policy.wolf_config.root.as_path()))
        .collect::<Vec<_>>();
    for id in selected {
        let value = inspect(tools, &id, deadline)?;
        let status = value
            .get("State")
            .and_then(|v| v.get("Status"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| io::Error::other("container writer state is unknown"))?;
        if ["created", "exited", "dead"].contains(&status) {
            continue;
        }
        if !["running", "paused", "restarting", "removing"].contains(&status) {
            return Err(io::Error::other("container writer state is invalid"));
        }
        let mounts = value
            .get("Mounts")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| io::Error::other("container mount authority is unavailable"))?;
        for mount in mounts {
            let rw = mount
                .get("RW")
                .and_then(serde_json::Value::as_bool)
                .ok_or_else(|| io::Error::other("container mount writer permission is unknown"))?;
            if !rw {
                continue;
            }
            let source = mount
                .get("Source")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| io::Error::other("container mount source is unknown"))?;
            let path = std::path::Path::new(source);
            if !path.is_absolute()
                || path.components().any(|component| {
                    matches!(
                        component,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                })
            {
                return Err(io::Error::other("container source identity is invalid"));
            }
            // Canonicalization is read-only observation, never a mutable grant or write path.
            if roots
                .iter()
                .any(|root| path.starts_with(root) || root.starts_with(path))
            {
                return Err(io::Error::other(
                    "unproven Steam container writer remains active",
                ));
            }
            let canonical = path.canonicalize()?;
            if roots
                .iter()
                .any(|root| canonical.starts_with(root) || root.starts_with(&canonical))
            {
                return Err(io::Error::other(
                    "aliased Steam container writer remains active",
                ));
            }
        }
    }
    Ok(())
}
