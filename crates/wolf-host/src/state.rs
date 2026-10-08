//! Private, atomic staged/running revision state separate from temporary Steam writes.
use fs2::FileExt;
use rustix::fs::{Mode, OFlags, ResolveFlags};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::unix::fs::MetadataExt,
    path::Path,
};
use uuid::Uuid;
use wolf_core::{PcId, Revision, Settings};
const LIMIT: usize = 1024 * 1024;
fn invalid() -> io::Error {
    io::Error::other("private host state invalid")
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Staged {
    version: u8,
    pc_id: PcId,
    settings: Settings,
    revision: Revision,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Running {
    version: u8,
    pc_id: PcId,
    revision: Option<Revision>,
}
pub struct State {
    directory: File,
    pc: PcId,
}
fn private(file: &File, directory: bool) -> io::Result<()> {
    let m = file.metadata()?;
    if m.uid() != rustix::process::geteuid().as_raw()
        || m.mode() & 0o077 != 0
        || m.is_dir() != directory
        || (!directory && (!m.is_file() || m.nlink() != 1))
    {
        return Err(invalid());
    }
    Ok(())
}
impl State {
    pub fn open(path: &Path, pc: &PcId) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(invalid());
        }
        let directory = File::from(rustix::fs::openat2(
            rustix::fs::CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?);
        private(&directory, true)?;
        Ok(Self {
            directory,
            pc: pc.clone(),
        })
    }
    fn read(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        let file = match rustix::fs::openat2(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        ) {
            Ok(fd) => File::from(fd),
            Err(e) if e == rustix::io::Errno::NOENT => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        private(&file, false)?;
        let mut bytes = vec![];
        file.take((LIMIT + 1) as u64).read_to_end(&mut bytes)?;
        if bytes.len() > LIMIT {
            return Err(invalid());
        }
        Ok(Some(bytes))
    }
    fn lock(&self) -> io::Result<File> {
        let file = File::from(rustix::fs::openat(
            &self.directory,
            ".state.lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?);
        private(&file, false)?;
        file.try_lock_exclusive()?;
        Ok(file)
    }
    fn create(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        let mut file = File::from(rustix::fs::openat(
            &self.directory,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?);
        file.write_all(bytes)?;
        file.sync_all()?;
        self.directory.sync_all()
    }
    fn write(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > LIMIT {
            return Err(invalid());
        }
        let prior = self.read(name)?;
        if prior.as_deref() == Some(bytes) {
            return Ok(());
        }
        if let Some(before) = &prior {
            let backup = format!(".{name}-backup-{}", Uuid::new_v4());
            self.create(&backup, before)?;
            if self.read(&backup)?.as_ref() != Some(before) {
                return Err(invalid());
            }
        }
        let temporary = format!(".{name}-new-{}", Uuid::new_v4());
        self.create(&temporary, bytes)?;
        if self.read(name)? != prior {
            return Err(invalid());
        }
        if prior.is_none() {
            rustix::fs::renameat_with(
                &self.directory,
                &temporary,
                &self.directory,
                name,
                rustix::fs::RenameFlags::NOREPLACE,
            )?;
        } else {
            rustix::fs::renameat(&self.directory, &temporary, &self.directory, name)?;
        }
        self.directory.sync_all()
    }
    pub fn stage(&self, settings: &Settings) -> io::Result<Revision> {
        let _lock = self.lock()?;
        let revision = settings.revision().map_err(|_| invalid())?;
        self.staged()?;
        let record = Staged {
            version: 1,
            pc_id: self.pc.clone(),
            settings: settings.clone(),
            revision: revision.clone(),
        };
        self.write("staged.json", &serde_json::to_vec(&record)?)?;
        Ok(revision)
    }
    pub fn staged(&self) -> io::Result<Option<(Settings, Revision)>> {
        let Some(bytes) = self.read("staged.json")? else {
            return Ok(None);
        };
        let record: Staged = serde_json::from_slice(&bytes)?;
        if record.version != 1
            || record.pc_id != self.pc
            || record.settings.revision().map_err(|_| invalid())? != record.revision
        {
            return Err(invalid());
        }
        Ok(Some((record.settings, record.revision)))
    }
    pub fn running(&self) -> io::Result<Option<Revision>> {
        let Some(bytes) = self.read("running.json")? else {
            return Ok(None);
        };
        let record: Running = serde_json::from_slice(&bytes)?;
        if record.version != 1 || record.pc_id != self.pc {
            return Err(invalid());
        }
        Ok(record.revision)
    }
    pub fn set_running(&self, revision: Option<&Revision>) -> io::Result<()> {
        let _lock = self.lock()?;
        self.running()?;
        self.write(
            "running.json",
            &serde_json::to_vec(&Running {
                version: 1,
                pc_id: self.pc.clone(),
                revision: revision.cloned(),
            })?,
        )
    }
}
