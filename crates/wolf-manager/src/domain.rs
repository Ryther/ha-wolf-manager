//! PC-scoped desired state and atomic complete catalog projections.
use crate::{
    protected::internal,
    store::{Store, decode, encode, hash},
};
use rusqlite::{Connection, OptionalExtension, params};
use wolf_core::*;
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcInput {
    pub pc_id: PcId,
    pub display_name: String,
    pub ssh_host: String,
    pub ssh_port: u16,
    pub ssh_user: String,
}
#[derive(Clone, Debug, serde::Serialize)]
pub struct Pc {
    pub pc_id: PcId,
    pub display_name: String,
    pub ssh_host: String,
    pub ssh_port: u16,
    pub ssh_user: String,
    pub host_key_algorithm: Option<String>,
    pub host_key_fingerprint: Option<String>,
    pub protocol_version: u8,
}
impl PcInput {
    pub fn validate(&self) -> Result<(), SafeError> {
        if self.display_name.trim().is_empty()
            || self.display_name.len() > 128
            || self.display_name.contains(['\0', '\r', '\n'])
            || self.ssh_host.is_empty()
            || self.ssh_host.len() > 253
            || self.ssh_host.starts_with('-')
            || !self
                .ssh_host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".:-_".contains(&b))
            || self.ssh_user.is_empty()
            || self.ssh_user.len() > 64
            || self.ssh_user.starts_with('-')
            || !self
                .ssh_user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            || self.ssh_port == 0
        {
            return Err(SafeError::validation());
        }
        Ok(())
    }
}
pub(crate) fn ensure_pc(conn: &Connection, pc: &PcId) -> Result<(), SafeError> {
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pcs WHERE pc_id=?1 AND archived_at_ms IS NULL)",
            [pc.as_str()],
            |r| r.get(0),
        )
        .map_err(internal)?;
    if !exists {
        return Err(SafeError::new("not_found"));
    }
    Ok(())
}
pub(crate) fn time(now: i64) -> Result<(), SafeError> {
    if now < 0 {
        return Err(SafeError::validation());
    }
    Ok(())
}
pub(crate) fn save_revisions(conn: &Connection, now: i64) -> Result<(), SafeError> {
    let pcs: Vec<String> = conn
        .prepare("SELECT pc_id FROM pcs")
        .map_err(internal)?
        .query_map([], |r| r.get(0))
        .map_err(internal)?
        .collect::<Result<_, _>>()
        .map_err(internal)?;
    for pc in pcs {
        let id = PcId::new(pc)?;
        let settings = load_settings(conn, &id)?;
        conn.execute(
            "UPDATE settings SET desired_revision=?1,updated_at_ms=?2 WHERE pc_id=?3",
            params![hash(&canonical_json(&settings)?), now, id.as_str()],
        )
        .map_err(internal)?;
    }
    let settings = load_global_settings(conn)?;
    conn.execute(
        "UPDATE global_debug SET desired_revision=?1,updated_at_ms=?2 WHERE id=1",
        params![hash(&canonical_json(&settings)?), now],
    )
    .map_err(internal)?;
    Ok(())
}
fn load_global_settings(conn: &Connection) -> Result<Settings, SafeError> {
    let mut settings = Settings {
        debug: DebugSettings {
            test_ball: conn
                .query_row("SELECT test_ball FROM global_debug WHERE id=1", [], |r| {
                    r.get(0)
                })
                .map_err(internal)?,
        },
        parameters: Default::default(),
        games: Default::default(),
    };
    let mut query=conn.prepare("SELECT parameter_id,label,launch_options,description FROM parameters ORDER BY parameter_id").map_err(internal)?;
    for row in query
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                ParameterDefinition {
                    label: r.get(1)?,
                    launch_options: r.get(2)?,
                    description: r.get(3)?,
                },
            ))
        })
        .map_err(internal)?
    {
        let (id, p) = row.map_err(internal)?;
        settings.parameters.insert(ParameterId::new(id)?, p);
    }
    settings.validate()?;
    Ok(settings)
}
pub(crate) fn load_settings(conn: &Connection, pc: &PcId) -> Result<Settings, SafeError> {
    let mut settings = load_global_settings(conn)?;
    let mut query=conn.prepare("SELECT app_id,direct_launch,proton_cachyos FROM settings WHERE pc_id=?1 ORDER BY app_id").map_err(internal)?;
    for row in query
        .query_map([pc.as_str()], |r| {
            Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?))
        })
        .map_err(internal)?
    {
        let (app, direct_launch, proton_cachyos) = row.map_err(internal)?;
        let mut selected=conn.prepare("SELECT parameter_id FROM game_parameters WHERE pc_id=?1 AND app_id=?2 ORDER BY position").map_err(internal)?;
        let ids = selected
            .query_map(params![pc.as_str(), app], |r| r.get::<_, String>(0))
            .map_err(internal)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(internal)?;
        settings.games.insert(
            AppId::new(app)?,
            GameSettings {
                direct_launch,
                proton_cachyos,
                parameters: ids
                    .into_iter()
                    .map(ParameterId::new)
                    .collect::<Result<_, _>>()?,
            },
        );
    }
    settings.validate()?;
    Ok(settings)
}
impl Store {
    pub fn global_settings(&self) -> Result<Settings, SafeError> {
        self.root.verify()?;
        load_global_settings(&self.conn)
    }
    pub fn add_pc(&mut self, input: PcInput, now: i64) -> Result<(), SafeError> {
        self.root.verify()?;
        time(now)?;
        input.validate()?;
        let count: i64 = self
            .conn
            .query_row(
                "SELECT count(*) FROM pcs WHERE archived_at_ms IS NULL",
                [],
                |r| r.get(0),
            )
            .map_err(internal)?;
        if count >= 1000 {
            return Err(SafeError::new("payload_too_large"));
        }
        self.conn.execute("INSERT INTO pcs(pc_id,display_name,ssh_host,ssh_port,ssh_user,created_at_ms,updated_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?6)",params![input.pc_id.as_str(),input.display_name,input.ssh_host,input.ssh_port,input.ssh_user,now]).map_err(internal)?;
        Ok(())
    }
    pub fn archived_pc_ids(&self) -> Result<Vec<PcId>, SafeError> {
        self.root.verify()?;
        self.conn
            .prepare("SELECT pc_id FROM pcs WHERE archived_at_ms IS NOT NULL ORDER BY pc_id")
            .map_err(internal)?
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(internal)?
            .map(|r| PcId::new(r.map_err(internal)?))
            .collect()
    }
    pub fn pcs(&self) -> Result<Vec<Pc>, SafeError> {
        self.root.verify()?;
        let mut query=self.conn.prepare("SELECT pc_id,display_name,ssh_host,ssh_port,ssh_user,host_key_algorithm,host_key_fingerprint,protocol_version FROM pcs WHERE archived_at_ms IS NULL ORDER BY pc_id").map_err(internal)?;
        query
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                ))
            })
            .map_err(internal)?
            .map(|r| {
                let (
                    id,
                    display_name,
                    ssh_host,
                    ssh_port,
                    ssh_user,
                    host_key_algorithm,
                    host_key_fingerprint,
                    protocol_version,
                ) = r.map_err(internal)?;
                Ok(Pc {
                    pc_id: PcId::new(id)?,
                    display_name,
                    ssh_host,
                    ssh_port,
                    ssh_user,
                    host_key_algorithm,
                    host_key_fingerprint,
                    protocol_version,
                })
            })
            .collect()
    }
    pub fn update_pc(&mut self, input: PcInput, now: i64) -> Result<(), SafeError> {
        self.root.verify()?;
        time(now)?;
        input.validate()?;
        ensure_pc(&self.conn, &input.pc_id)?;
        self.ensure_no_mutation(&input.pc_id)?;
        self.conn.execute("UPDATE pcs SET host_key_algorithm=CASE WHEN ssh_host!=?2 OR ssh_port!=?3 OR ssh_user!=?4 THEN NULL ELSE host_key_algorithm END,host_key_fingerprint=CASE WHEN ssh_host!=?2 OR ssh_port!=?3 OR ssh_user!=?4 THEN NULL ELSE host_key_fingerprint END,host_key_public=CASE WHEN ssh_host!=?2 OR ssh_port!=?3 OR ssh_user!=?4 THEN NULL ELSE host_key_public END,display_name=?5,ssh_host=?2,ssh_port=?3,ssh_user=?4,updated_at_ms=?6 WHERE pc_id=?1",params![input.pc_id.as_str(),input.ssh_host,input.ssh_port,input.ssh_user,input.display_name,now]).map_err(internal)?;
        Ok(())
    }
    pub fn archive_pc(&mut self, pc: &PcId, now: i64) -> Result<(), SafeError> {
        self.root.verify()?;
        time(now)?;
        ensure_pc(&self.conn, pc)?;
        self.ensure_no_mutation(pc)?;
        self.conn
            .execute(
                "UPDATE pcs SET archived_at_ms=?1,updated_at_ms=?1 WHERE pc_id=?2",
                params![now, pc.as_str()],
            )
            .map_err(internal)?;
        Ok(())
    }
    pub fn save_game(
        &mut self,
        pc: &PcId,
        app: &AppId,
        game: GameSettings,
        expected: &Revision,
        capabilities: &HostCapabilities,
        now: i64,
    ) -> Result<Revision, SafeError> {
        self.root.verify()?;
        time(now)?;
        ensure_pc(&self.conn, pc)?;
        if capabilities.pc_id != *pc {
            return Err(SafeError::validation());
        }
        let tx = self.conn.transaction().map_err(internal)?;
        let mut settings = load_settings(&tx, pc)?;
        if &settings.revision()? != expected {
            return Err(SafeError::new("stale_revision"));
        }
        settings.games.insert(app.clone(), game.clone());
        settings.validate_capabilities(capabilities)?;
        let revision = settings.revision()?;
        tx.execute("INSERT INTO settings VALUES(?1,?2,?3,?4,?5,NULL,?6) ON CONFLICT(pc_id,app_id) DO UPDATE SET direct_launch=excluded.direct_launch,proton_cachyos=excluded.proton_cachyos,updated_at_ms=excluded.updated_at_ms",params![pc.as_str(),app.as_str(),game.direct_launch,game.proton_cachyos,hash(&canonical_json(&settings)?),now]).map_err(internal)?;
        tx.execute(
            "DELETE FROM game_parameters WHERE pc_id=?1 AND app_id=?2",
            params![pc.as_str(), app.as_str()],
        )
        .map_err(internal)?;
        for (position, id) in game.parameters.iter().enumerate() {
            tx.execute(
                "INSERT INTO game_parameters VALUES(?1,?2,?3,?4)",
                params![pc.as_str(), app.as_str(), id.as_str(), position as i64],
            )
            .map_err(internal)?;
        }
        tx.execute(
            "UPDATE settings SET desired_revision=?1 WHERE pc_id=?2",
            params![hash(&canonical_json(&settings)?), pc.as_str()],
        )
        .map_err(internal)?;
        tx.commit().map_err(internal)?;
        Ok(revision)
    }
    pub fn save_parameter(
        &mut self,
        id: &ParameterId,
        definition: ParameterDefinition,
        now: i64,
    ) -> Result<(), SafeError> {
        self.root.verify()?;
        time(now)?;
        definition.validate_api_input()?;
        let tx = self.conn.transaction().map_err(internal)?;
        tx.execute("INSERT INTO parameters VALUES(?1,?2,?3,?4,0,?5,?5) ON CONFLICT(parameter_id) DO UPDATE SET label=excluded.label,launch_options=excluded.launch_options,description=excluded.description,updated_at_ms=excluded.updated_at_ms",params![id.as_str(),definition.label,definition.launch_options,definition.description,now]).map_err(internal)?;
        save_revisions(&tx, now)?;
        tx.commit().map_err(internal)
    }
    pub fn delete_parameter(&mut self, id: &ParameterId, now: i64) -> Result<(), SafeError> {
        self.root.verify()?;
        time(now)?;
        let tx = self.conn.transaction().map_err(internal)?;
        let builtin: Option<bool> = tx
            .query_row(
                "SELECT built_in FROM parameters WHERE parameter_id=?1",
                [id.as_str()],
                |r| r.get(0),
            )
            .optional()
            .map_err(internal)?;
        if builtin == Some(true) {
            return Err(SafeError::validation());
        }
        let assigned: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM game_parameters WHERE parameter_id=?1)",
                [id.as_str()],
                |r| r.get(0),
            )
            .map_err(internal)?;
        if assigned {
            return Err(SafeError::new("parameter_in_use"));
        }
        tx.execute(
            "DELETE FROM parameters WHERE parameter_id=?1",
            [id.as_str()],
        )
        .map_err(internal)?;
        save_revisions(&tx, now)?;
        tx.commit().map_err(internal)
    }
    pub fn save_debug(&mut self, debug: DebugSettings, now: i64) -> Result<(), SafeError> {
        self.root.verify()?;
        time(now)?;
        let tx = self.conn.transaction().map_err(internal)?;
        tx.execute(
            "UPDATE global_debug SET test_ball=?1 WHERE id=1",
            [debug.test_ball],
        )
        .map_err(internal)?;
        save_revisions(&tx, now)?;
        tx.commit().map_err(internal)
    }
    pub fn commit_catalog(
        &mut self,
        manifest: &CatalogManifest,
        attributes: &[CatalogAttributes],
    ) -> Result<(), SafeError> {
        self.root.verify()?;
        ensure_pc(&self.conn, &manifest.pc_id)?;
        let previous = self.catalog(&manifest.pc_id)?;
        let old = previous.as_ref().map(|(manifest, entries)| {
            (
                manifest,
                entries
                    .iter()
                    .map(|a| (a.app_id.clone(), a.clone()))
                    .collect::<std::collections::BTreeMap<_, _>>(),
            )
        });
        let validated = validate_catalog_generation(
            &manifest.pc_id,
            manifest,
            attributes,
            old.as_ref().map(|(m, e)| (*m, e)),
        )?;
        let generation =
            i64::try_from(manifest.catalog_generation).map_err(|_| SafeError::validation())?;
        let tx = self.conn.transaction().map_err(internal)?;
        tx.execute(
            "DELETE FROM catalog_entries WHERE pc_id=?1",
            [manifest.pc_id.as_str()],
        )
        .map_err(internal)?;
        for (app, attrs) in validated {
            tx.execute(
                "INSERT INTO catalog_entries VALUES(?1,?2,?3,?4,?5)",
                params![
                    manifest.pc_id.as_str(),
                    app.as_str(),
                    encode(&attrs)?,
                    generation,
                    attrs.observed_at_ms
                ],
            )
            .map_err(internal)?;
        }
        tx.execute("INSERT INTO catalog_manifests VALUES(?1,?2) ON CONFLICT(pc_id) DO UPDATE SET manifest_json=excluded.manifest_json",params![manifest.pc_id.as_str(),encode(manifest)?]).map_err(internal)?;
        tx.commit().map_err(internal)
    }
    pub fn catalog(
        &self,
        pc: &PcId,
    ) -> Result<Option<(CatalogManifest, Vec<CatalogAttributes>)>, SafeError> {
        self.root.verify()?;
        ensure_pc(&self.conn, pc)?;
        let manifest: Option<String> = self
            .conn
            .query_row(
                "SELECT manifest_json FROM catalog_manifests WHERE pc_id=?1",
                [pc.as_str()],
                |r| r.get(0),
            )
            .optional()
            .map_err(internal)?;
        let Some(manifest) = manifest else {
            return Ok(None);
        };
        let manifest: CatalogManifest = decode(&manifest)?;
        let entries: Vec<String> = self
            .conn
            .prepare("SELECT observed_json FROM catalog_entries WHERE pc_id=?1 ORDER BY app_id")
            .map_err(internal)?
            .query_map([pc.as_str()], |r| r.get(0))
            .map_err(internal)?
            .collect::<Result<_, _>>()
            .map_err(internal)?;
        let entries = entries
            .iter()
            .map(|v| decode(v))
            .collect::<Result<Vec<_>, _>>()?;
        validate_catalog_generation(pc, &manifest, &entries, None)?;
        Ok(Some((manifest, entries)))
    }
}
