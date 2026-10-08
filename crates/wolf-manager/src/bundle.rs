//! Offline matched state and private identity snapshots with nondestructive directory cutover.
use crate::{
    protected::{DataRoot, internal},
    store::hash,
};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use wolf_core::{PcId, SafeError};
const MAX_DATABASE: u64 = 1024 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u8,
    files: BTreeMap<String, String>,
}
fn existing_root(path: &Path) -> Result<DataRoot, SafeError> {
    std::fs::symlink_metadata(path).map_err(internal)?;
    DataRoot::open(path)
}
fn readonly(root: &DataRoot) -> Result<Connection, SafeError> {
    let file = root.file("manager.sqlite3", false)?;
    if file.metadata().map_err(internal)?.len() > MAX_DATABASE {
        return Err(SafeError::new("payload_too_large"));
    }
    Connection::open_with_flags(
        root.sqlite_path("manager.sqlite3")?,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(internal)
}
fn validate_database(root: &DataRoot) -> Result<(), SafeError> {
    for name in [
        "manager.sqlite3-wal",
        "manager.sqlite3-shm",
        "manager.sqlite3-journal",
    ] {
        if std::fs::symlink_metadata(root.path(name)).is_ok() {
            return Err(SafeError::new("recovery_pending"));
        }
    }
    let conn = readonly(root)?;
    let expected = Connection::open_in_memory().map_err(internal)?;
    expected
        .execute_batch(include_str!("migration.sql"))
        .map_err(internal)?;
    if schema(&conn)? != schema(&expected)? {
        return Err(SafeError::validation());
    }
    let check: String = conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .map_err(internal)?;
    if check != "ok" {
        return Err(SafeError::validation());
    }
    let rows = conn
        .prepare("SELECT version,checksum FROM schema_migrations ORDER BY version")
        .map_err(internal)?
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))
        .map_err(internal)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(internal)?;
    if rows != vec![(1, hash(include_bytes!("migration.sql")))] {
        return Err(SafeError::validation());
    }
    if conn
        .prepare("PRAGMA foreign_key_check")
        .map_err(internal)?
        .query([])
        .map_err(internal)?
        .next()
        .map_err(internal)?
        .is_some()
    {
        return Err(SafeError::validation());
    }
    let admin: bool = conn
        .query_row("SELECT EXISTS(SELECT 1 FROM administrator)", [], |r| {
            r.get(0)
        })
        .map_err(internal)?;
    if admin != root.marker_present()? {
        return Err(SafeError::validation());
    }
    validate_identities(root, &conn)?;
    Ok(())
}
fn validate_identities(root: &DataRoot, conn: &Connection) -> Result<(), SafeError> {
    let mut stmt=conn.prepare("SELECT pc_id,enrolled_public_key,host_key_algorithm,host_key_public,host_key_fingerprint FROM pcs").map_err(internal)?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
            ))
        })
        .map_err(internal)?;
    for row in rows {
        let (id, public, algorithm, host, fingerprint) = row.map_err(internal)?;
        let id = PcId::new(id)?;
        let path = format!("keys/{}/id_ed25519", id.as_str());
        if let Some(public) = public {
            let bytes = read_limited(root.file(&path, false)?, 16384)?;
            let key = russh::keys::PrivateKey::from_openssh(&bytes).map_err(internal)?;
            if key.is_encrypted()
                || key.algorithm() != russh::keys::Algorithm::Ed25519
                || key.public_key().to_openssh().map_err(internal)? != public
            {
                return Err(SafeError::validation());
            }
        }
        match (algorithm, host, fingerprint) {
            (None, None, None) => {}
            (Some(a), Some(h), Some(f)) => {
                let key = russh::keys::PublicKey::from_openssh(&h).map_err(internal)?;
                if key.algorithm().to_string() != a
                    || key.fingerprint(russh::keys::HashAlg::Sha256).to_string() != f
                {
                    return Err(SafeError::validation());
                }
            }
            _ => return Err(SafeError::validation()),
        }
    }
    Ok(())
}

fn read_limited(file: File, max: u64) -> Result<Vec<u8>, SafeError> {
    if file.metadata().map_err(internal)?.len() > max {
        return Err(SafeError::new("payload_too_large"));
    }
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(internal)?;
    if bytes.len() as u64 > max {
        return Err(SafeError::new("payload_too_large"));
    }
    Ok(bytes)
}
fn digest(mut file: File) -> Result<String, SafeError> {
    let mut sha = Sha256::new();
    let mut bytes = [0; 8192];
    loop {
        let n = file.read(&mut bytes).map_err(internal)?;
        if n == 0 {
            break;
        }
        sha.update(&bytes[..n]);
    }
    Ok(sha.finalize().iter().map(|b| format!("{b:02x}")).collect())
}
fn directory(root: &DataRoot, name: &str) -> Result<(), SafeError> {
    let fd = rustix::fs::openat2(
        &root.directory,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::BENEATH
            | rustix::fs::ResolveFlags::NO_SYMLINKS
            | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(internal)?;
    let m = File::from(fd).metadata().map_err(internal)?;
    if m.uid() != rustix::process::geteuid().as_raw() || m.mode() & 0o7777 != 0o700 {
        return Err(SafeError::new("forbidden"));
    }
    Ok(())
}
fn inventory(root: &DataRoot) -> Result<Vec<String>, SafeError> {
    let mut files = vec!["manager.sqlite3".into()];
    for name in ["initialized", "instance-id"] {
        if std::fs::symlink_metadata(root.path(name)).is_ok() {
            let file = root.file(name, false)?;
            if name == "instance-id" {
                crate::health::parse_instance_id(&read_limited(file, 37)?)?;
            }
            files.push(name.into());
        }
    }
    if std::fs::symlink_metadata(root.path("keys")).is_ok() {
        directory(root, "keys")?;
        inventory_keys(root, &mut files)?;
    }
    files.sort();
    Ok(files)
}
fn inventory_keys(root: &DataRoot, files: &mut Vec<String>) -> Result<(), SafeError> {
    for entry in std::fs::read_dir(root.path("keys")).map_err(internal)? {
        if files.len() > 10002 {
            return Err(SafeError::new("payload_too_large"));
        }
        let entry = entry.map_err(internal)?;
        let id = PcId::new(entry.file_name().into_string().map_err(internal)?)?;
        let dir = format!("keys/{}", id.as_str());
        directory(root, &dir)?;
        let children = std::fs::read_dir(root.path(&dir))
            .map_err(internal)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(internal)?;
        if children.len() != 1 || children[0].file_name() != "id_ed25519" {
            return Err(SafeError::validation());
        }
        let name = format!("{dir}/id_ed25519");
        let bytes = read_limited(root.file(&name, false)?, 16384)?;
        let key = russh::keys::PrivateKey::from_openssh(&bytes).map_err(internal)?;
        if key.is_encrypted() || key.algorithm() != russh::keys::Algorithm::Ed25519 {
            return Err(SafeError::validation());
        }
        files.push(name);
    }
    Ok(())
}

fn create_child(root: &DataRoot, name: &str) -> Result<(), SafeError> {
    match rustix::fs::mkdirat(
        &root.directory,
        name,
        rustix::fs::Mode::from_raw_mode(0o700),
    ) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => directory(root, name)?,
        Err(e) => return Err(internal(e)),
    }
    root.sync()
}
fn copy_files(
    source: &DataRoot,
    target: &DataRoot,
    files: &[String],
    database: bool,
) -> Result<(), SafeError> {
    for name in files {
        if name.starts_with("keys/") {
            create_child(target, "keys")?;
            create_child(
                target,
                name.rsplit_once('/').ok_or_else(SafeError::validation)?.0,
            )?;
        }
        let mut out = target.file(name, true)?;
        if name == "manager.sqlite3" && database {
            drop(out);
            let input = readonly(source)?;
            let mut output = Connection::open_with_flags(
                target.sqlite_path(name)?,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )
            .map_err(internal)?;
            rusqlite::backup::Backup::new(&input, &mut output)
                .map_err(internal)?
                .run_to_completion(100, std::time::Duration::from_millis(10), None)
                .map_err(internal)?;
            drop(output);
            target.file(name, false)?.sync_all().map_err(internal)?;
        } else {
            std::io::copy(&mut source.file(name, false)?, &mut out).map_err(internal)?;
            out.sync_all().map_err(internal)?;
        }
    }
    target.sync()
}
/// Offline only: acquire the runtime's exclusive root lock and create a new private bundle.
/// Supervisor options and external deployment secrets are intentionally not state-bundle inputs.
pub fn backup(source: &Path, destination: &Path) -> Result<(), SafeError> {
    if source.starts_with(destination) || destination.starts_with(source) {
        return Err(SafeError::validation());
    }
    let source = existing_root(source)?;
    validate_database(&source)?;
    let files = inventory(&source)?;
    if std::fs::symlink_metadata(destination).is_ok() {
        return Err(SafeError::new("operation_in_progress"));
    }
    let target = DataRoot::open(destination)?;
    copy_files(&source, &target, &files, true)?;
    validate_database(&target)?;
    let files = files
        .into_iter()
        .map(|name| Ok((name.clone(), digest(target.file(&name, false)?)?)))
        .collect::<Result<BTreeMap<_, _>, SafeError>>()?;
    let bytes = serde_json::to_vec(&Manifest { version: 1, files }).map_err(internal)?;
    let mut manifest = target.file("bundle.json", true)?;
    manifest.write_all(&bytes).map_err(internal)?;
    manifest.sync_all().map_err(internal)?;
    target.sync()?;
    validate_bundle(&target)
}
fn validate_bundle(root: &DataRoot) -> Result<(), SafeError> {
    let manifest: Manifest = serde_json::from_slice(&read_limited(
        root.file("bundle.json", false)?,
        1024 * 1024,
    )?)
    .map_err(internal)?;
    let files = inventory(root)?;
    if manifest.version != 1 || manifest.files.keys().cloned().collect::<Vec<_>>() != files {
        return Err(SafeError::validation());
    }
    for name in files {
        if manifest.files[&name] != digest(root.file(&name, false)?)? {
            return Err(SafeError::validation());
        }
    }
    for entry in std::fs::read_dir(root.path(".")).map_err(internal)? {
        let name = entry.map_err(internal)?.file_name();
        if ![
            "manager.sqlite3",
            "initialized",
            "instance-id",
            "keys",
            "bundle.json",
        ]
        .iter()
        .any(|s| name == *s)
        {
            return Err(SafeError::validation());
        }
    }
    validate_database(root)
}
/// Validate hashes, schema, key material and trust pins without opening SQLite read/write.
pub fn preview(bundle: &Path) -> Result<(), SafeError> {
    validate_bundle(&existing_root(bundle)?)
}
/// Stage a verified complete directory and atomically replace the offline target.
/// The returned rollback directory preserves the entire original target. Mountpoint
/// exchange is refused by the kernel; original mounted data remains untouched.
pub fn restore(bundle: &Path, target: &Path) -> Result<Option<PathBuf>, SafeError> {
    if bundle.starts_with(target) || target.starts_with(bundle) {
        return Err(SafeError::validation());
    }
    let source = existing_root(bundle)?;
    validate_bundle(&source)?;
    let parent = target.parent().ok_or_else(SafeError::validation)?;
    let name = target.file_name().ok_or_else(SafeError::validation)?;
    let existing = if std::fs::symlink_metadata(target).is_ok() {
        let root = DataRoot::open(target)?;
        validate_database(&root)?;
        inventory(&root)?;
        Some(root)
    } else {
        None
    };
    let staging = parent.join(format!("wolf-restore-{}", uuid::Uuid::new_v4()));
    let staged = DataRoot::open(&staging)?;
    copy_files(&source, &staged, &inventory(&source)?, false)?;
    validate_database(&staged)?;
    for name in inventory(&source)? {
        if digest(source.file(&name, false)?)? != digest(staged.file(&name, false)?)? {
            return Err(SafeError::validation());
        }
    }
    if let Some(root) = &existing {
        root.verify()?;
    }
    let parentfd = rustix::fs::openat2(
        rustix::fs::CWD,
        parent,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(internal)?;
    let flags = if existing.is_some() {
        rustix::fs::RenameFlags::EXCHANGE
    } else {
        rustix::fs::RenameFlags::NOREPLACE
    };
    rustix::fs::renameat_with(
        &parentfd,
        staging.file_name().ok_or_else(SafeError::validation)?,
        &parentfd,
        name,
        flags,
    )
    .map_err(internal)?;
    File::from(parentfd).sync_all().map_err(internal)?;
    Ok(existing.map(|_| staging))
}

type SchemaRow = (String, String, String, Option<String>);
fn schema(conn: &Connection) -> Result<Vec<SchemaRow>, SafeError> {
    conn.prepare("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name")
        .map_err(internal)?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .map_err(internal)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(internal)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires isolated root container"]
    fn root_backup_refuses_untrusted_uid_without_creating_destination() {
        assert!(rustix::process::geteuid().is_root());
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        drop(crate::store::Store::open(&source, 1).unwrap());
        let database = File::open(source.join("manager.sqlite3")).unwrap();
        rustix::fs::fchown(&database, Some(rustix::process::Uid::from_raw(1001)), None).unwrap();
        let before = std::fs::read(source.join("manager.sqlite3")).unwrap();
        let target = temp.path().join("backup");
        assert!(backup(&source, &target).is_err());
        assert!(!target.exists());
        assert_eq!(1001, database.metadata().unwrap().uid());
        assert_eq!(
            before,
            std::fs::read(source.join("manager.sqlite3")).unwrap()
        );
    }
}
