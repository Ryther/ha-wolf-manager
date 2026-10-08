//! Single-threaded container startup admission before the async runtime exists.
use crate::{
    ha_bootstrap::{AddonOptions, parse_options},
    protected::internal,
    runtime::{Cli, Mode},
};
use rustix::fs::{Mode as FsMode, OFlags, ResolveFlags};
use std::{fs::File, io::Read, os::unix::fs::MetadataExt, path::Path};
use wolf_core::SafeError;
fn open_directory(path: &Path) -> Result<File, SafeError> {
    Ok(File::from(
        rustix::fs::openat2(
            rustix::fs::CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            FsMode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(internal)?,
    ))
}
fn options(directory: &File) -> Result<AddonOptions, SafeError> {
    let file = File::from(
        rustix::fs::openat2(
            directory,
            "options.json",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            FsMode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(internal)?,
    );
    let m = file.metadata().map_err(internal)?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != 0
        || ![0o600, 0o644].contains(&(m.mode() & 0o7777))
        || m.len() > 65536
    {
        return Err(SafeError::new("forbidden"));
    }
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes).map_err(internal)?;
    parse_options(&bytes)
}
/// Admit an exact container data volume without recursively changing existing data.
/// Root-owned Supervisor options remain root-owned and are parsed before dropping UID.
fn admit(directory: &File, allow_fresh: bool) -> Result<(), SafeError> {
    let m = directory.metadata().map_err(internal)?;
    if m.uid() == 1000 && m.gid() == 1000 && m.mode() & 0o7777 == 0o700 {
        return Ok(());
    }
    if !allow_fresh
        || m.uid() != 0
        || m.gid() != 0
        || ![0o700, 0o755].contains(&(m.mode() & 0o7777))
    {
        return Err(SafeError::new("forbidden"));
    }
    // fd-anchored inventory: fresh Supervisor options are the only permitted entry.
    use std::os::fd::AsRawFd;
    for entry in
        std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd())).map_err(internal)?
    {
        if entry.map_err(internal)?.file_name() != "options.json" {
            return Err(SafeError::new("forbidden"));
        }
        options(directory)?;
    }
    rustix::fs::fchmod(directory, FsMode::from_raw_mode(0o700)).map_err(internal)?;
    rustix::fs::fchown(
        directory,
        Some(rustix::process::Uid::from_raw(1000)),
        Some(rustix::process::Gid::from_raw(1000)),
    )
    .map_err(internal)?;
    directory.sync_all().map_err(internal)
}
/// Call only from synchronous main before any threads exist. Kernel thread credential
/// APIs then cover the whole process; all future runtime threads inherit UID/GID1000.
pub fn prepare(cli: &mut Cli) -> Result<(), SafeError> {
    if !rustix::process::geteuid().is_root() {
        return Ok(());
    }
    if cli.data != Path::new("/data") {
        return Err(SafeError::new("forbidden"));
    }
    let directory = open_directory(&cli.data)?;
    if cli.command.is_none() && matches!(cli.mode, Mode::Ingress) {
        if cli.options_file != Path::new("/data/options.json") {
            return Err(SafeError::validation());
        }
        cli.startup_options = Some(options(&directory)?);
    }
    admit(&directory, cli.command.is_none())?;
    rustix::thread::set_thread_groups(&[]).map_err(internal)?;
    let gid = rustix::process::Gid::from_raw(1000);
    let uid = rustix::process::Uid::from_raw(1000);
    rustix::thread::set_thread_res_gid(gid, gid, gid).map_err(internal)?;
    rustix::thread::set_thread_res_uid(uid, uid, uid).map_err(internal)?;
    if rustix::process::getuid() != uid
        || rustix::process::geteuid() != uid
        || rustix::process::getgid() != gid
        || rustix::process::getegid() != gid
        || !rustix::process::getgroups().map_err(internal)?.is_empty()
    {
        return Err(SafeError::new("forbidden"));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn supervisor_options_fifo_refuses_without_waiting_for_a_writer() {
        use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt, sync::mpsc, time::Duration};
        let fixture = tempfile::tempdir().unwrap();
        let fifo = fixture.path().join("options.json");
        assert!(
            std::process::Command::new("mkfifo")
                .args(["-m", "600"])
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let directory = open_directory(fixture.path()).unwrap();
        let (tx, rx) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            tx.send(options(&directory).is_err()).unwrap();
        });
        let immediate = rx.recv_timeout(Duration::from_millis(500));
        // Release an incorrectly blocking open before joining or failing the test.
        let release = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
            .open(&fifo)
            .unwrap();
        thread.join().unwrap();
        drop(release);
        assert!(immediate.expect("Supervisor options FIFO blocked waiting for a writer"));
    }
    #[test]
    #[ignore = "requires isolated root container"]
    fn root_startup_refuses_existing_state_before_any_ownership_change() {
        if !rustix::process::geteuid().is_root() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("manager.sqlite3");
        std::fs::write(&file, b"preserve").unwrap();
        let directory = open_directory(temp.path()).unwrap();
        assert!(admit(&directory, true).is_err());
        assert_eq!(0, directory.metadata().unwrap().uid());
        assert_eq!(b"preserve", std::fs::read(file).unwrap().as_slice());
    }
}
