//! Guarded, recoverable configuration writes inside a pinned filesystem grant.
//! Backups remain until an operator explicitly archives them; restore refuses drift.
use fs2::FileExt;
use rustix::fs::{Mode, OFlags, RenameFlags, ResolveFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};
use uuid::Uuid;

const LIMIT: usize = 16 * 1024 * 1024;
fn error(message: &'static str) -> io::Error {
    io::Error::other(message)
}
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn read_bounded(mut file: File) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    (&mut file)
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > LIMIT {
        return Err(error("configuration file exceeds limit"));
    }
    Ok(bytes)
}

pub struct Grant {
    root: PathBuf,
    directory: File,
    uid: u32,
    gid: u32,
    device: u64,
    inode: u64,
}
impl Grant {
    pub fn open(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(error("grant must be absolute"));
        }
        let fd = rustix::fs::openat2(
            rustix::fs::CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?;
        let directory = File::from(fd);
        let metadata = directory.metadata()?;
        let root = path.canonicalize()?;
        Ok(Self {
            root,
            directory,
            uid: metadata.uid(),
            gid: metadata.gid(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    pub fn for_owner(path: &Path, uid: u32, gid: u32) -> io::Result<Self> {
        let mut grant = Self::open(path)?;
        if grant.uid != 0 && grant.uid != uid {
            return Err(error("grant owner is not authorized"));
        }
        grant.uid = uid;
        grant.gid = gid;
        Ok(grant)
    }
    fn parent(&self, relative: &str) -> io::Result<(File, String)> {
        let path = Path::new(relative);
        if relative.is_empty()
            || relative.contains('\0')
            || relative
                .split('/')
                .any(|x| x.is_empty() || x == "." || x == "..")
            || path
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err(error("target must be a normal relative path"));
        }
        let current = fs::symlink_metadata(&self.root)?;
        if current.dev() != self.device || current.ino() != self.inode || !current.is_dir() {
            return Err(error("grant identity changed"));
        }
        let parent = path.parent().filter(|x| !x.as_os_str().is_empty());
        let directory = match parent {
            Some(p) => File::from(rustix::fs::openat2(
                &self.directory,
                p,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )?),
            None => self.directory.try_clone()?,
        };
        let name = path
            .file_name()
            .and_then(|x| x.to_str())
            .ok_or_else(|| error("invalid target name"))?
            .to_owned();
        Ok((directory, name))
    }
    fn read_file(&self, parent: &File, name: &str) -> io::Result<(Vec<u8>, fs::Metadata)> {
        let file = File::from(rustix::fs::openat2(
            parent,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?);
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != self.uid
            || metadata.gid() != self.gid
            || metadata.mode() & 0o6000 != 0
        {
            return Err(error("target ownership, links or file type are unsafe"));
        }
        Ok((read_bounded(file)?, metadata))
    }
    fn write_new(&self, parent: &File, name: &str, bytes: &[u8], mode: u32) -> io::Result<()> {
        let mut file = File::from(rustix::fs::openat(
            parent,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?);
        file.write_all(bytes)?;
        rustix::fs::fchown(
            &file,
            Some(rustix::fs::Uid::from_raw(self.uid)),
            Some(rustix::fs::Gid::from_raw(self.gid)),
        )?;
        file.set_permissions(fs::Permissions::from_mode(mode & 0o777))?;
        file.sync_all()?;
        parent.sync_all()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Prepared,
    Quarantined,
    Applied,
    Restoring,
    Restored,
    Conflict,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u8,
    transaction_id: Uuid,
    root: PathBuf,
    root_device: u64,
    root_inode: u64,
    relative: String,
    uid: u32,
    gid: u32,
    mode: u32,
    preimage_sha256: String,
    postimage_sha256: String,
    quarantine: String,
    phase: Phase,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    manifest: Manifest,
    checksum: String,
}

pub struct TransactionStore {
    root: PathBuf,
    directory: File,
}
impl TransactionStore {
    pub fn open(path: &Path) -> io::Result<Self> {
        let grant = Grant::open(path)?;
        let metadata = grant.directory.metadata()?;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(error(
                "backup store must be private and owned by current helper",
            ));
        }
        Ok(Self {
            root: grant.root,
            directory: grant.directory,
        })
    }
    fn lock(&self) -> io::Result<File> {
        let file = File::from(rustix::fs::openat(
            &self.directory,
            ".transaction.lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?);
        let metadata = file.metadata()?;
        if metadata.nlink() != 1
            || !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
        {
            return Err(error("unsafe transaction lock"));
        }
        file.lock_exclusive()?;
        Ok(file)
    }
    fn folder(&self, id: &Uuid) -> io::Result<PathBuf> {
        let path = self.root.join(id.to_string());
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
        {
            return Err(error("unsafe transaction directory"));
        }
        Ok(path)
    }
    fn save(&self, manifest: &Manifest) -> io::Result<()> {
        let folder = self.folder(&manifest.transaction_id)?;
        let checksum = digest(&serde_json::to_vec(manifest)?);
        let bytes = serde_json::to_vec(&Envelope {
            manifest: manifest.clone(),
            checksum,
        })?;
        let temporary = folder.join(format!(".manifest-{}", Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(temporary, folder.join("manifest.json"))?;
        File::open(&folder)?.sync_all()?;
        self.directory.sync_all()
    }
    fn load(&self, id: &Uuid) -> io::Result<Manifest> {
        let folder = self.folder(id)?;
        let file = File::from(rustix::fs::openat2(
            rustix::fs::CWD,
            folder.join("manifest.json"),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?);
        let envelope: Envelope = serde_json::from_slice(&read_bounded(file)?)?;
        if envelope.manifest.version != 1
            || envelope.manifest.transaction_id != *id
            || envelope.checksum != digest(&serde_json::to_vec(&envelope.manifest)?)
        {
            return Err(error("transaction manifest identity or checksum mismatch"));
        }
        Ok(envelope.manifest)
    }
    pub fn transactions(&self) -> io::Result<Vec<Uuid>> {
        let mut ids = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str()
                && let Ok(id) = Uuid::parse_str(name)
            {
                self.folder(&id)?;
                ids.push(id);
            }
        }
        ids.sort();
        Ok(ids)
    }
    pub fn recovery_pending(&self) -> io::Result<bool> {
        for id in self.transactions()? {
            if matches!(
                self.load(&id)?.phase,
                Phase::Prepared | Phase::Quarantined | Phase::Restoring | Phase::Conflict
            ) {
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub fn preimage(&self, id: &Uuid) -> io::Result<Vec<u8>> {
        let manifest = self.load(id)?;
        let path = self.folder(id)?.join("preimage");
        let file = File::from(rustix::fs::openat2(
            rustix::fs::CWD,
            &path,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?);
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
        {
            return Err(error("unsafe backup file"));
        }
        let bytes = read_bounded(file)?;
        if digest(&bytes) != manifest.preimage_sha256 {
            return Err(error("backup checksum mismatch"));
        }
        Ok(bytes)
    }
    pub fn apply(&self, grant: &Grant, relative: &str, bytes: &[u8]) -> io::Result<Uuid> {
        let _lock = self.lock()?;
        if bytes.len() > LIMIT || self.recovery_pending()? {
            return Err(error("unresolved recovery or oversized data"));
        }
        let (parent, name) = grant.parent(relative)?;
        let (before, metadata) = grant.read_file(&parent, &name)?;
        for id in self.transactions()? {
            let previous = self.load(&id)?;
            if previous.root == grant.root
                && previous.relative == relative
                && previous.phase != Phase::Restored
            {
                return Err(error("target already has an active transaction"));
            }
        }
        let id = Uuid::new_v4();
        let folder = self.root.join(id.to_string());
        fs::create_dir(&folder)?;
        fs::set_permissions(&folder, fs::Permissions::from_mode(0o700))?;
        let mut backup = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(folder.join("preimage"))?;
        backup.write_all(&before)?;
        backup.sync_all()?;
        let mut manifest = Manifest {
            version: 1,
            transaction_id: id,
            root: grant.root.clone(),
            root_device: grant.device,
            root_inode: grant.inode,
            relative: relative.to_owned(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode() & 0o777,
            preimage_sha256: digest(&before),
            postimage_sha256: digest(bytes),
            quarantine: format!(".wolf-manager-{id}.quarantine"),
            phase: Phase::Prepared,
        };
        self.save(&manifest)?;
        self.preimage(&id)?;
        let staged = format!(".wolf-manager-{id}.staged");
        grant.write_new(&parent, &staged, bytes, manifest.mode)?;
        rustix::fs::renameat_with(
            &parent,
            &name,
            &parent,
            &manifest.quarantine,
            RenameFlags::NOREPLACE,
        )?;
        parent.sync_all()?;
        manifest.phase = Phase::Quarantined;
        self.save(&manifest)?;
        if digest(&grant.read_file(&parent, &manifest.quarantine)?.0) != manifest.preimage_sha256 {
            let _ = rustix::fs::renameat_with(
                &parent,
                &manifest.quarantine,
                &parent,
                &name,
                RenameFlags::NOREPLACE,
            );
            parent.sync_all()?;
            manifest.phase = Phase::Conflict;
            self.save(&manifest)?;
            return Err(error(
                "target changed during transaction; current bytes retained",
            ));
        }
        // NOREPLACE never overwrites a file introduced by another writer.
        rustix::fs::renameat_with(&parent, &staged, &parent, &name, RenameFlags::NOREPLACE)?;
        parent.sync_all()?;
        manifest.phase = Phase::Applied;
        self.save(&manifest)?;
        Ok(id)
    }
    pub fn restore(&self, grant: &Grant, id: &Uuid) -> io::Result<()> {
        let _lock = self.lock()?;
        let mut manifest = self.load(id)?;
        if manifest.root != grant.root
            || manifest.root_device != grant.device
            || manifest.root_inode != grant.inode
            || manifest.uid != grant.uid
            || manifest.gid != grant.gid
        {
            return Err(error("restore grant mismatch"));
        }
        let before = match self.preimage(id) {
            Ok(value) => value,
            Err(reason) => {
                manifest.phase = Phase::Conflict;
                self.save(&manifest)?;
                return Err(reason);
            }
        };
        let (parent, name) = grant.parent(&manifest.relative)?;
        let current = grant.read_file(&parent, &name);
        if let Ok((bytes, _)) = &current
            && digest(bytes) == manifest.preimage_sha256
        {
            manifest.phase = Phase::Restored;
            self.save(&manifest)?;
            return Ok(());
        }
        let missing = current
            .as_ref()
            .err()
            .is_some_and(|e| e.kind() == io::ErrorKind::NotFound);
        let valid_postimage = current
            .as_ref()
            .ok()
            .is_some_and(|(bytes, _)| digest(bytes) == manifest.postimage_sha256);
        if !missing && !valid_postimage {
            manifest.phase = Phase::Conflict;
            self.save(&manifest)?;
            return Err(error(
                "restore conflict; current and backup bytes preserved",
            ));
        }
        if missing
            && matches!(
                manifest.phase,
                Phase::Applied | Phase::Restored | Phase::Conflict
            )
        {
            manifest.phase = Phase::Conflict;
            self.save(&manifest)?;
            return Err(error(
                "target disappeared after application; refusing replacement",
            ));
        }
        manifest.phase = Phase::Restoring;
        self.save(&manifest)?;
        let staged = format!(".wolf-manager-{id}.restore-{}", Uuid::new_v4());
        grant.write_new(&parent, &staged, &before, manifest.mode)?;
        if valid_postimage {
            let displaced = format!(".wolf-manager-{id}.postimage-{}", Uuid::new_v4());
            rustix::fs::renameat_with(&parent, &name, &parent, &displaced, RenameFlags::NOREPLACE)?;
            parent.sync_all()?;
            if digest(&grant.read_file(&parent, &displaced)?.0) != manifest.postimage_sha256 {
                let _ = rustix::fs::renameat_with(
                    &parent,
                    &displaced,
                    &parent,
                    &name,
                    RenameFlags::NOREPLACE,
                );
                parent.sync_all()?;
                manifest.phase = Phase::Conflict;
                self.save(&manifest)?;
                return Err(error(
                    "restore raced with another writer; current bytes retained",
                ));
            }
        }
        rustix::fs::renameat_with(&parent, &staged, &parent, &name, RenameFlags::NOREPLACE)?;
        parent.sync_all()?;
        if digest(&grant.read_file(&parent, &name)?.0) != manifest.preimage_sha256 {
            return Err(error("restore verification failed"));
        }
        manifest.phase = Phase::Restored;
        self.save(&manifest)
    }
}
