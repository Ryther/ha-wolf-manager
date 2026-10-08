//! Durable SQLite state with fail-closed schema checks and verified migration backups.
use crate::protected::{DataRoot, internal};
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::Path,
};
use wolf_core::*;
const MIGRATION: &str = include_str!("migration.sql");
pub(crate) fn hash(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}
pub(crate) fn encode<T: serde::Serialize + ?Sized>(value: &T) -> Result<String, SafeError> {
    String::from_utf8(canonical_json(&value)?).map_err(internal)
}
pub(crate) fn decode<T: serde::de::DeserializeOwned>(value: &str) -> Result<T, SafeError> {
    serde_json::from_str(value).map_err(internal)
}
pub struct Store {
    pub(crate) conn: Connection,
    pub(crate) root: DataRoot,
}
impl Store {
    pub fn open(path: &Path, now: i64) -> Result<Self, SafeError> {
        Self::open_inner(path, now, false)
    }
    pub(crate) fn open_inner(path: &Path, now: i64, recovery: bool) -> Result<Self, SafeError> {
        if now < 0 {
            return Err(SafeError::validation());
        }
        let root = DataRoot::open(path)?;
        let marker = root.marker_present()?;
        let exists = std::fs::symlink_metadata(root.path("manager.sqlite3")).is_ok();
        if marker && !exists {
            return Err(SafeError::new("bootstrap_completed"));
        }
        let mut version = 0;
        if exists {
            root.file("manager.sqlite3", false)?;
            for suffix in [
                "manager.sqlite3-wal",
                "manager.sqlite3-shm",
                "manager.sqlite3-journal",
            ] {
                if std::fs::symlink_metadata(root.path(suffix)).is_ok() {
                    root.file(suffix, false)?;
                }
            }
            let readonly = Connection::open_with_flags(
                root.sqlite_path("manager.sqlite3")?,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )
            .map_err(internal)?;
            let integrity: String = readonly
                .query_row("PRAGMA integrity_check", [], |row| row.get(0))
                .map_err(internal)?;
            if integrity != "ok" {
                return Err(SafeError::new("internal_error"));
            }
            let has_migrations:bool=readonly.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations')",[],|r|r.get(0)).map_err(internal)?;
            if has_migrations {
                let rows = readonly
                    .prepare("SELECT version,checksum FROM schema_migrations ORDER BY version")
                    .map_err(internal)?
                    .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))
                    .map_err(internal)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(internal)?;
                if rows.len() != 1 || rows[0].0 != 1 || rows[0].1 != hash(MIGRATION.as_bytes()) {
                    return Err(SafeError::new("internal_error"));
                }
                version = 1;
                let initialized: bool = readonly
                    .query_row("SELECT EXISTS(SELECT 1 FROM administrator)", [], |r| {
                        r.get(0)
                    })
                    .map_err(internal)?;
                if marker && !initialized && !recovery {
                    return Err(SafeError::new("bootstrap_completed"));
                }
            } else {
                let count: i64 = readonly
                    .query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))
                    .map_err(internal)?;
                if count != 0 || marker {
                    return Err(SafeError::new("internal_error"));
                }
            }
            if version == 0 {
                backup(&root, &readonly, 0)?;
            }
        } else {
            root.file("manager.sqlite3", true)?
                .sync_all()
                .map_err(internal)?;
            root.directory.sync_all().map_err(internal)?;
        }
        let mut conn = Connection::open_with_flags(
            root.sqlite_path("manager.sqlite3")?,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(internal)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(internal)?;
        conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")
            .map_err(internal)?;
        if version == 0 {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Exclusive)
                .map_err(internal)?;
            tx.execute_batch(MIGRATION).map_err(internal)?;
            tx.execute(
                "INSERT INTO schema_migrations VALUES(1,?1,?2)",
                params![hash(MIGRATION.as_bytes()), now],
            )
            .map_err(internal)?;
            let defaults = Settings::default();
            for (id, p) in &defaults.parameters {
                tx.execute(
                    "INSERT INTO parameters VALUES(?1,?2,?3,?4,1,?5,?5)",
                    params![id.as_str(), p.label, p.launch_options, p.description, now],
                )
                .map_err(internal)?;
            }
            tx.execute(
                "INSERT INTO global_debug VALUES(1,0,?1,?2)",
                params![hash(&canonical_json(&defaults)?), now],
            )
            .map_err(internal)?;
            tx.commit().map_err(internal)?;
        }
        conn.execute_batch("UPDATE operations SET state='unknown_interrupted' WHERE state IN ('queued','running');").map_err(internal)?;
        if conn
            .query_row("SELECT EXISTS(SELECT 1 FROM administrator)", [], |r| {
                r.get::<_, bool>(0)
            })
            .map_err(internal)?
        {
            root.initialize_marker()?;
        }
        Ok(Self { conn, root })
    }
    pub fn verified_backup(&self) -> Result<String, SafeError> {
        self.root.verify()?;
        backup(&self.root, &self.conn, 1)
    }
    pub fn settings(&self, pc: &PcId) -> Result<Settings, SafeError> {
        self.root.verify()?;
        crate::domain::ensure_pc(&self.conn, pc)?;
        crate::domain::load_settings(&self.conn, pc)
    }
}
fn backup(root: &DataRoot, source: &Connection, version: u8) -> Result<String, SafeError> {
    root.verify()?;
    let id = uuid::Uuid::new_v4().to_string();
    let name = format!("backup-{id}.sqlite3");
    root.file(&name, true)?;
    let mut target = Connection::open_with_flags(
        root.sqlite_path(&name)?,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(internal)?;
    {
        let backup = rusqlite::backup::Backup::new(source, &mut target).map_err(internal)?;
        backup
            .run_to_completion(100, std::time::Duration::from_millis(10), None)
            .map_err(internal)?;
    }
    let integrity: String = target
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .map_err(internal)?;
    if integrity != "ok" {
        return Err(SafeError::new("internal_error"));
    }
    drop(target);
    let mut file = root.file(&name, false)?;
    file.sync_all().map_err(internal)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let count = file.read(&mut buffer).map_err(internal)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let sha = digest
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let manifest = encode(
        &serde_json::json!({"version":1,"schema_version":version,"database":name,"sha256":sha}),
    )?;
    let mut out = root.file(&format!("backup-{id}.json"), true)?;
    out.write_all(manifest.as_bytes()).map_err(internal)?;
    out.sync_all().map_err(internal)?;
    root.directory.sync_all().map_err(internal)?;
    verify_backup(root, &name)?;
    Ok(name)
}
impl Store {
    pub fn verify_backup(&self, name: &str) -> Result<(), SafeError> {
        verify_backup(&self.root, name)
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupManifest {
    version: u8,
    schema_version: u8,
    database: String,
    sha256: Revision,
}
fn verify_backup(root: &DataRoot, name: &str) -> Result<(), SafeError> {
    root.verify()?;
    let id = name
        .strip_prefix("backup-")
        .and_then(|v| v.strip_suffix(".sqlite3"))
        .ok_or_else(SafeError::validation)?;
    let uuid = uuid::Uuid::parse_str(id).map_err(|_| SafeError::validation())?;
    if uuid.to_string() != id {
        return Err(SafeError::validation());
    }
    let mut bytes = Vec::new();
    root.file(&format!("backup-{id}.json"), false)?
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(internal)?;
    if bytes.len() > 4096 {
        return Err(SafeError::validation());
    }
    let manifest: BackupManifest = serde_json::from_slice(&bytes).map_err(internal)?;
    if manifest.version != 1 || manifest.schema_version > 1 || manifest.database != name {
        return Err(SafeError::validation());
    }
    let mut file = root.file(name, false)?;
    let mut digest = Sha256::new();
    let mut bytes = [0u8; 8192];
    loop {
        let n = file.read(&mut bytes).map_err(internal)?;
        if n == 0 {
            break;
        }
        digest.update(&bytes[..n]);
    }
    if digest
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        != manifest.sha256.as_str()
    {
        return Err(SafeError::new("internal_error"));
    }
    let conn = Connection::open_with_flags(
        root.sqlite_path(name)?,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(internal)?;
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .map_err(internal)?;
    if integrity != "ok" {
        return Err(SafeError::new("internal_error"));
    }
    Ok(())
}
