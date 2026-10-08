//! Private exec health marker bound to Linux boot and process start identity.
use crate::{api::now, protected::internal, store::Store};
use rustix::fs::{Mode, OFlags, ResolveFlags};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::Path,
};
use wolf_core::SafeError;
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    version: u8,
    pid: u32,
    start_ticks: u64,
    boot_id: String,
    heartbeat: i64,
}
fn start(pid: u32) -> Result<u64, SafeError> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).map_err(internal)?;
    stat.rsplit_once(')')
        .ok_or_else(SafeError::validation)?
        .1
        .split_whitespace()
        .nth(19)
        .ok_or_else(SafeError::validation)?
        .parse()
        .map_err(internal)
}
fn boot() -> Result<String, SafeError> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(internal)?
        .trim()
        .into())
}
pub fn healthcheck(data: &Path) -> Result<(), SafeError> {
    if !data.is_absolute() {
        return Err(SafeError::validation());
    }
    let root = File::from(
        rustix::fs::openat2(
            rustix::fs::CWD,
            data,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(internal)?,
    );
    let m = root.metadata().map_err(internal)?;
    if m.mode() & 0o7777 != 0o700 || m.uid() != rustix::process::geteuid().as_raw() {
        return Err(SafeError::new("forbidden"));
    }
    let file = File::from(
        rustix::fs::openat2(
            &root,
            "ready.json",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(internal)?,
    );
    let m = file.metadata().map_err(internal)?;
    if !m.is_file()
        || m.mode() & 0o7777 != 0o600
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.nlink() != 1
        || m.len() > 4096
    {
        return Err(SafeError::new("forbidden"));
    }
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes).map_err(internal)?;
    let ready: Ready = serde_json::from_slice(&bytes).map_err(internal)?;
    if ready.version != 1
        || ready.pid == 0
        || ready.boot_id != boot()?
        || ready.start_ticks != start(ready.pid)?
        || ready.heartbeat > now()
        || now() - ready.heartbeat > 30_000
    {
        return Err(SafeError::new("host_unavailable"));
    }
    Ok(())
}
impl Store {
    pub fn instance_id(&self) -> Result<uuid::Uuid, SafeError> {
        self.root.verify()?;
        let name = "instance-id";
        let id = match self.root.file(name, false) {
            Ok(file) => {
                let mut bytes = String::new();
                file.take(37).read_to_string(&mut bytes).map_err(internal)?;
                let id = uuid::Uuid::parse_str(&bytes).map_err(internal)?;
                if id.is_nil() || id.to_string() != bytes {
                    return Err(SafeError::validation());
                }
                id
            }
            Err(_) => {
                if std::fs::symlink_metadata(self.root.path(name)).is_ok() {
                    return Err(SafeError::new("forbidden"));
                }
                let id = uuid::Uuid::new_v4();
                let mut file = self.root.file(name, true)?;
                file.write_all(id.to_string().as_bytes())
                    .map_err(internal)?;
                file.sync_all().map_err(internal)?;
                self.root.sync()?;
                id
            }
        };
        Ok(id)
    }
    pub fn heartbeat(&self, time: i64) -> Result<(), SafeError> {
        self.root.verify()?;
        if time < 0 {
            return Err(SafeError::validation());
        }
        let ready = Ready {
            version: 1,
            pid: std::process::id(),
            start_ticks: start(std::process::id())?,
            boot_id: boot()?,
            heartbeat: time,
        };
        let name = format!("ready-{}.tmp", uuid::Uuid::new_v4());
        let mut file = self.root.file(&name, true)?;
        file.write_all(&serde_json::to_vec(&ready).map_err(internal)?)
            .map_err(internal)?;
        file.sync_all().map_err(internal)?;
        fs::rename(self.root.path(&name), self.root.path("ready.json")).map_err(internal)?;
        self.root.sync()
    }
    pub fn stop_heartbeat(&self) -> Result<(), SafeError> {
        self.root.verify()?;
        match fs::remove_file(self.root.path("ready.json")) {
            Ok(()) => self.root.sync(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(internal(e)),
        }
    }
}
