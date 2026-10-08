//! Explicit offline prototype migration; source bytes and previous state are retained.
use crate::{
    domain::{ensure_pc, load_settings, time},
    protected::internal,
    store::{Store, hash},
};
use rusqlite::params;
use std::io::Write;
use wolf_core::{PcId, Revision, SafeError, Settings, canonical_json};

pub fn preview(version: u8, bytes: &[u8]) -> Result<Settings, SafeError> {
    if version != 1 || bytes.len() > 4 * 1024 * 1024 {
        return Err(SafeError::validation());
    }
    let value = serde_json::from_slice(bytes).map_err(internal)?;
    Settings::import_legacy(&value)
}
impl Store {
    pub fn import_legacy_settings(
        &mut self,
        pc: &PcId,
        expected: &Revision,
        version: u8,
        bytes: &[u8],
        now: i64,
    ) -> Result<Revision, SafeError> {
        self.root.verify()?;
        time(now)?;
        let imported = preview(version, bytes)?;
        ensure_pc(&self.conn, pc)?;
        let count: i64 = self
            .conn
            .query_row("SELECT count(*) FROM pcs", [], |row| row.get(0))
            .map_err(internal)?;
        // Definitions/debug are global. Initial migration cannot alter another PC,
        // including an archived PC whose retained state must remain reproducible.
        if count != 1 || self.active_mutation(pc)?.is_some() {
            return Err(SafeError::new("busy"));
        }
        let mut desired = load_settings(&self.conn, pc)?;
        if &desired.revision()? != expected {
            return Err(SafeError::new("stale_revision"));
        }
        desired.parameters.extend(imported.parameters.clone());
        desired.games.extend(imported.games.clone());
        desired.debug = imported.debug.clone();
        desired.validate()?;
        let revision = desired.revision()?;
        // All backups/source bytes are durable before the single SQL transaction.
        self.verified_backup()?;
        let source_name = format!("legacy-source-{}.json", uuid::Uuid::new_v4());
        let mut source = self.root.file(&source_name, true)?;
        source.write_all(bytes).map_err(internal)?;
        source.sync_all().map_err(internal)?;
        self.root.sync()?;
        let tx = self.conn.transaction().map_err(internal)?;
        for (id, definition) in &imported.parameters {
            tx.execute("INSERT INTO parameters VALUES(?1,?2,?3,?4,0,?5,?5) ON CONFLICT(parameter_id) DO UPDATE SET label=excluded.label,launch_options=excluded.launch_options,description=excluded.description,updated_at_ms=excluded.updated_at_ms",params![id.as_str(),definition.label,definition.launch_options,definition.description,now]).map_err(internal)?;
        }
        let revision_hash = hash(&canonical_json(&desired)?);
        tx.execute(
            "UPDATE global_debug SET test_ball=?1,desired_revision=?2,updated_at_ms=?3 WHERE id=1",
            params![
                desired.debug.test_ball,
                hash(&canonical_json(&imported.debug)?),
                now
            ],
        )
        .map_err(internal)?;
        for (app, game) in &imported.games {
            tx.execute("INSERT INTO settings VALUES(?1,?2,?3,?4,?5,NULL,?6) ON CONFLICT(pc_id,app_id) DO UPDATE SET direct_launch=excluded.direct_launch,proton_cachyos=excluded.proton_cachyos,updated_at_ms=excluded.updated_at_ms",params![pc.as_str(),app.as_str(),game.direct_launch,game.proton_cachyos,revision_hash,now]).map_err(internal)?;
            tx.execute(
                "DELETE FROM game_parameters WHERE pc_id=?1 AND app_id=?2",
                params![pc.as_str(), app.as_str()],
            )
            .map_err(internal)?;
            for (position, parameter) in game.parameters.iter().enumerate() {
                tx.execute(
                    "INSERT INTO game_parameters VALUES(?1,?2,?3,?4)",
                    params![
                        pc.as_str(),
                        app.as_str(),
                        parameter.as_str(),
                        position as i64
                    ],
                )
                .map_err(internal)?;
            }
        }
        tx.execute(
            "UPDATE settings SET desired_revision=?1 WHERE pc_id=?2",
            params![revision_hash, pc.as_str()],
        )
        .map_err(internal)?;
        tx.commit().map_err(internal)?;
        Ok(revision)
    }
}
