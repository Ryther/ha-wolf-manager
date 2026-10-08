//! Durable admission journal: duplicate incomplete requests are never replayed.
//! The admission lock is distinct from Steam hook transaction locks.
use fs2::FileExt;
use rustix::fs::{Mode, OFlags, ResolveFlags};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::unix::fs::MetadataExt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use wolf_core::*;
const LIMIT: usize = 2 * 1024 * 1024;
fn fail(message: &'static str) -> io::Error {
    io::Error::other(message)
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
fn private_file(file: &File) -> io::Result<()> {
    let m = file.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.mode() & 0o077 != 0
    {
        return Err(fail("unsafe journal file"));
    }
    Ok(())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    request: RpcRequest,
    observation: JournalObservation,
    response: Option<RpcResponse>,
}
impl Record {
    fn validate(&self) -> io::Result<()> {
        self.request
            .validate()
            .map_err(|_| fail("invalid journal request"))?;
        let o = &self.observation;
        if self.version != 1
            || !o.found
            || o.request_id != self.request.request_id
            || o.pc_id != self.request.pc_id
            || o.canonical_request_sha256
                != Some(
                    self.request
                        .digest()
                        .map_err(|_| fail("invalid journal request"))?,
                )
            || o.observed_at_ms < 0
        {
            return Err(fail("invalid journal identity"));
        }
        match (&self.response, o.phase) {
            (None, Some(JournalPhase::Accepted | JournalPhase::Running))
                if o.result.is_none() && o.error.is_none() => {}
            (Some(response), Some(phase)) => {
                response
                    .validate_for(&self.request)
                    .map_err(|_| fail("invalid journal reply"))?;
                if phase
                    != if response.ok {
                        JournalPhase::Succeeded
                    } else {
                        JournalPhase::Failed
                    }
                    || o.result.as_deref() != response.result.as_ref()
                    || o.error != response.error
                {
                    return Err(fail("inconsistent journal outcome"));
                }
            }
            _ => return Err(fail("invalid journal phase")),
        }
        Ok(())
    }
}
pub struct Journal {
    directory: File,
}
pub enum Admission {
    Execute(Ticket),
    Cached(RpcResponse),
    Uncertain(JournalObservation),
}
pub struct Ticket {
    directory: File,
    _lock: File,
    record: Box<Record>,
}
fn read(directory: &File, id: Uuid) -> io::Result<Option<Record>> {
    let file = match rustix::fs::openat2(
        directory,
        format!("{id}.json"),
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    ) {
        Ok(fd) => File::from(fd),
        Err(e) if e == rustix::io::Errno::NOENT => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    private_file(&file)?;
    let mut bytes = Vec::new();
    file.take((LIMIT + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > LIMIT {
        return Err(fail("journal exceeds size bound"));
    }
    let record: Record = serde_json::from_slice(&bytes)?;
    record.validate()?;
    if record.request.request_id != id {
        return Err(fail("journal filename identity mismatch"));
    }
    Ok(Some(record))
}
fn write(directory: &File, record: &Record) -> io::Result<()> {
    record.validate()?;
    let bytes = serde_json::to_vec(record)?;
    if bytes.len() > LIMIT {
        return Err(fail("journal exceeds size bound"));
    }
    let temporary = format!(".journal-{}", Uuid::new_v4());
    let mut file = File::from(rustix::fs::openat(
        directory,
        &temporary,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?);
    file.write_all(&bytes)?;
    file.sync_all()?;
    rustix::fs::renameat(
        directory,
        &temporary,
        directory,
        format!("{}.json", record.request.request_id),
    )?;
    directory.sync_all()
}
impl Journal {
    pub fn open(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(fail("journal path must be absolute"));
        }
        let directory = File::from(rustix::fs::openat2(
            rustix::fs::CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?);
        let m = directory.metadata()?;
        if m.uid() != rustix::process::geteuid().as_raw() || m.mode() & 0o077 != 0 {
            return Err(fail("journal directory must be private"));
        }
        Ok(Self { directory })
    }
    pub fn begin(&self, request: &RpcRequest) -> io::Result<Admission> {
        request.validate().map_err(|_| fail("invalid request"))?;
        let lock = File::from(rustix::fs::openat(
            &self.directory,
            ".admission.lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?);
        private_file(&lock)?;
        lock.try_lock_exclusive()?;
        if let Some(record) = read(&self.directory, request.request_id)? {
            if record.request != *request {
                return Err(fail("request identifier conflicts with persisted data"));
            }
            return Ok(match record.response {
                Some(response) => Admission::Cached(response),
                None => Admission::Uncertain(record.observation),
            });
        }
        let record = Record {
            version: 1,
            request: request.clone(),
            observation: JournalObservation {
                found: true,
                request_id: request.request_id,
                pc_id: request.pc_id.clone(),
                canonical_request_sha256: Some(
                    request.digest().map_err(|_| fail("invalid request"))?,
                ),
                phase: Some(JournalPhase::Accepted),
                observed_at_ms: now(),
                result: None,
                error: None,
            },
            response: None,
        };
        write(&self.directory, &record)?;
        Ok(Admission::Execute(Ticket {
            directory: self.directory.try_clone()?,
            _lock: lock,
            record: Box::new(record),
        }))
    }
    pub fn lookup(&self, id: Uuid, pc: &PcId) -> io::Result<JournalObservation> {
        if id.is_nil() {
            return Err(fail("invalid request identity"));
        }
        if let Some(record) = read(&self.directory, id)? {
            if &record.request.pc_id != pc {
                return Err(fail("journal PC identity mismatch"));
            }
            Ok(record.observation)
        } else {
            Ok(JournalObservation {
                found: false,
                request_id: id,
                pc_id: pc.clone(),
                canonical_request_sha256: None,
                phase: None,
                observed_at_ms: now(),
                result: None,
                error: None,
            })
        }
    }
    pub fn status(&self, request: &RpcRequest) -> io::Result<JournalObservation> {
        self.lookup(request.request_id, &request.pc_id)
    }
}
impl Ticket {
    pub fn running(&mut self) -> io::Result<()> {
        if self.record.observation.phase != Some(JournalPhase::Accepted) {
            return Err(fail("request is not accepted"));
        }
        self.record.observation.phase = Some(JournalPhase::Running);
        self.record.observation.observed_at_ms = now();
        write(&self.directory, &self.record)
    }
    pub fn finish(mut self, response: RpcResponse) -> io::Result<()> {
        response
            .validate_for(&self.record.request)
            .map_err(|_| fail("invalid completion"))?;
        self.record.observation.phase = Some(if response.ok {
            JournalPhase::Succeeded
        } else {
            JournalPhase::Failed
        });
        self.record.observation.result = response.result.clone().map(Box::new);
        self.record.observation.error = response.error.clone();
        self.record.observation.observed_at_ms = now();
        self.record.response = Some(response);
        write(&self.directory, &self.record)
    }
}
