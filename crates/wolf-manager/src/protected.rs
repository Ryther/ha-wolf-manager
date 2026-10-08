//! Linux data-root admission, anchoring and protected durable file creation.
use fs2::FileExt;
use rustix::fs::{Mode, OFlags, ResolveFlags};
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::AsRawFd,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use wolf_core::SafeError;
pub(crate) fn internal<T>(_: T) -> SafeError {
    SafeError::new("internal_error")
}
pub(crate) struct DataRoot {
    pub directory: File,
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl DataRoot {
    pub fn open(path: &Path) -> Result<Self, SafeError> {
        if !path.is_absolute()
            || path.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(SafeError::validation());
        }
        let mut ancestor = PathBuf::from("/");
        for component in path
            .parent()
            .ok_or_else(SafeError::validation)?
            .components()
        {
            if let std::path::Component::Normal(part) = component {
                ancestor.push(part);
            }
            let fd = rustix::fs::openat2(
                rustix::fs::CWD,
                &ancestor,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )
            .map_err(internal)?;
            let metadata = File::from(fd).metadata().map_err(internal)?;
            let sticky_root = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
            if ![0, rustix::process::geteuid().as_raw()].contains(&metadata.uid())
                || (metadata.mode() & 0o022 != 0 && !sticky_root)
            {
                return Err(SafeError::new("forbidden"));
            }
        }
        if !path.exists() {
            let parent = path.parent().ok_or_else(SafeError::validation)?;
            let parent = rustix::fs::openat2(
                rustix::fs::CWD,
                parent,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )
            .map_err(internal)?;
            rustix::fs::mkdirat(
                &parent,
                path.file_name().ok_or_else(SafeError::validation)?,
                Mode::from_raw_mode(0o700),
            )
            .map_err(internal)?;
        }
        let fd = rustix::fs::openat2(
            rustix::fs::CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(internal)?;
        let directory = File::from(fd);
        let metadata = directory.metadata().map_err(internal)?;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o777 != 0o700
        {
            return Err(SafeError::new("forbidden"));
        }
        directory
            .try_lock_exclusive()
            .map_err(|_| SafeError::new("operation_in_progress"))?;
        Ok(Self {
            directory,
            path: path.into(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    pub fn verify(&self) -> Result<(), SafeError> {
        let fd = rustix::fs::openat2(
            rustix::fs::CWD,
            &self.path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(internal)?;
        let metadata = File::from(fd).metadata().map_err(internal)?;
        if metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.mode() & 0o777 != 0o700
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(SafeError::new("forbidden"));
        }
        Ok(())
    }
    pub fn sqlite_path(&self, name: &str) -> Result<PathBuf, SafeError> {
        self.verify()?;
        Ok(self.path.join(name))
    }
    pub fn path(&self, name: &str) -> PathBuf {
        PathBuf::from(format!(
            "/proc/self/fd/{}/{}",
            self.directory.as_raw_fd(),
            name
        ))
    }
    pub fn file(&self, name: &str, create: bool) -> Result<File, SafeError> {
        self.verify()?;
        let flags = if create {
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL
        } else {
            OFlags::RDONLY
        };
        let fd = rustix::fs::openat2(
            &self.directory,
            name,
            flags | OFlags::CLOEXEC,
            if create {
                Mode::from_raw_mode(0o600)
            } else {
                Mode::empty()
            },
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(internal)?;
        let file = File::from(fd);
        let meta = file.metadata().map_err(internal)?;
        if !meta.is_file()
            || meta.nlink() != 1
            || meta.uid() != rustix::process::geteuid().as_raw()
            || meta.mode() & 0o777 != 0o600
        {
            return Err(SafeError::new("forbidden"));
        }
        Ok(file)
    }
    pub fn marker_present(&self) -> Result<bool, SafeError> {
        match std::fs::symlink_metadata(self.path("initialized")) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(internal(e)),
            Ok(_) => {
                let mut bytes = Vec::new();
                self.file("initialized", false)?
                    .take(65)
                    .read_to_end(&mut bytes)
                    .map_err(internal)?;
                if bytes != b"initialized-v1\n" {
                    return Err(SafeError::new("internal_error"));
                }
                Ok(true)
            }
        }
    }
    pub fn initialize_marker(&self) -> Result<(), SafeError> {
        if self.marker_present()? {
            return Ok(());
        }
        let mut file = self.file("initialized", true)?;
        file.write_all(b"initialized-v1\n").map_err(internal)?;
        file.sync_all().map_err(internal)?;
        self.directory.sync_all().map_err(internal)
    }
}
