//! Offline-only credential reset under the same exclusive data-root lock.
use crate::{auth::hash_password, domain::time, protected::internal, store::Store};
use rusqlite::params;
use std::path::Path;
use wolf_core::SafeError;
pub struct Recovery {
    store: Store,
}
impl Recovery {
    pub fn open(path: &Path, now: i64) -> Result<Self, SafeError> {
        Ok(Self {
            store: Store::open_inner(path, now, true)?,
        })
    }
    pub fn reset_password(&mut self, password: &str, now: i64) -> Result<(), SafeError> {
        self.store.root.verify()?;
        time(now)?;
        let password = hash_password(password)?;
        self.store.verified_backup()?;
        self.store.root.initialize_marker()?;
        let tx = self.store.conn.transaction().map_err(internal)?;
        tx.execute("INSERT INTO administrator VALUES(1,?1,?2,?2) ON CONFLICT(id) DO UPDATE SET password_hash=excluded.password_hash,updated_at_ms=excluded.updated_at_ms",params![password,now]).map_err(internal)?;
        tx.execute(
            "UPDATE sessions SET revoked_at_ms=?1 WHERE revoked_at_ms IS NULL",
            [now],
        )
        .map_err(internal)?;
        tx.execute("DELETE FROM login_challenges", [])
            .map_err(internal)?;
        tx.execute("DELETE FROM ingress_csrf_tokens", [])
            .map_err(internal)?;
        tx.commit().map_err(internal)
    }
}
