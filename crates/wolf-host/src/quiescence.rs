//! Fail-closed Steam executable identity checks against the kernel process view.
use std::{collections::BTreeSet, fs, io, os::unix::fs::MetadataExt, path::PathBuf};
fn unsafe_state() -> io::Error {
    io::Error::other("Steam writer state cannot be proven stopped")
}
pub fn require_stopped(uid: u32, executables: &[PathBuf]) -> io::Result<()> {
    if executables.is_empty() || executables.len() > 128 {
        return Err(unsafe_state());
    }
    let mut identities = BTreeSet::new();
    for executable in executables {
        if !executable.is_absolute() {
            return Err(unsafe_state());
        }
        let metadata = fs::metadata(executable)?;
        if !metadata.is_file() {
            return Err(unsafe_state());
        }
        identities.insert((metadata.dev(), metadata.ino()));
    }
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let name = entry.file_name();
        if name
            .to_str()
            .is_none_or(|name| name.parse::<u32>().is_err())
        {
            continue;
        }
        let directory = entry.path();
        let owner = match fs::metadata(&directory) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        if owner.uid() != uid {
            continue;
        }
        let executable = match fs::metadata(directory.join("exe")) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                match fs::read_to_string(directory.join("status")) {
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Ok(status) if status.lines().any(|line| line.starts_with("State:\tZ")) => {
                        continue;
                    }
                    _ => return Err(unsafe_state()),
                }
            }
            Err(_) => return Err(unsafe_state()),
        };
        if identities.contains(&(executable.dev(), executable.ino())) {
            return Err(io::Error::other("Steam writer is running"));
        }
    }
    Ok(())
}
