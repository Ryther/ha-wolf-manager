//! Complete, bounded Steam scans. Library canonical paths point to steamapps.
use fs2::FileExt;
use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};
use unicode_general_category::{GeneralCategory, get_general_category};
use unicode_normalization::UnicodeNormalization;
use wolf_core::{AppId, CatalogAttributes, CatalogManifest, PcId, steam_cover_url};
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Library {
    pub library_id: String,
    pub canonical_path: PathBuf,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogConfig {
    pub pc_id: PcId,
    pub libraries: Vec<Library>,
    pub state_directory: PathBuf,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub manifest: CatalogManifest,
    pub attributes: Vec<CatalogAttributes>,
}
fn invalid() -> io::Error {
    io::Error::other("catalog scan or private state invalid")
}
fn anchored(root: &File, path: &Path, directory: bool) -> io::Result<File> {
    let flags = OFlags::RDONLY
        | OFlags::CLOEXEC
        | if directory {
            OFlags::DIRECTORY
        } else {
            OFlags::empty()
        };
    Ok(File::from(openat2(
        root,
        path,
        flags,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?))
}
fn root(path: &Path) -> io::Result<File> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid());
    }
    Ok(File::from(openat2(
        rustix::fs::CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?))
}
fn read_bounded(mut file: File) -> io::Result<String> {
    let m = file.metadata()?;
    if !m.is_file() || m.nlink() != 1 || m.len() > 1024 * 1024 {
        return Err(invalid());
    }
    let mut text = String::new();
    Read::by_ref(&mut file)
        .take(1024 * 1024 + 1)
        .read_to_string(&mut text)?;
    let after = file.metadata()?;
    if text.len() > 1024 * 1024
        || m.len() != after.len()
        || m.mtime() != after.mtime()
        || m.mtime_nsec() != after.mtime_nsec()
        || m.ctime() != after.ctime()
        || m.ctime_nsec() != after.ctime_nsec()
    {
        return Err(invalid());
    }
    Ok(text)
}
pub fn clean_game_name(value: &str) -> String {
    value
        .chars()
        .filter(|c| !matches!(c, '™' | '®' | '©'))
        .collect::<String>()
        .nfkc()
        .filter(|c| {
            !matches!(
                get_general_category(*c),
                GeneralCategory::Control
                    | GeneralCategory::Format
                    | GeneralCategory::Surrogate
                    | GeneralCategory::PrivateUse
                    | GeneralCategory::Unassigned
            )
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}
fn atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or_else(invalid)?;
    let temporary = parent.join(format!(".catalog-{}", uuid::Uuid::new_v4()));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()
}
fn private_read(path: &Path) -> io::Result<Option<String>> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
    {
        Ok(f) => {
            let m = f.metadata()?;
            if m.uid() != rustix::process::geteuid().as_raw() || m.mode() & 0o777 != 0o600 {
                return Err(invalid());
            }
            {
                let mut file = f;
                let mut text = String::new();
                Read::by_ref(&mut file)
                    .take(16 * 1024 * 1024 + 1)
                    .read_to_string(&mut text)?;
                if text.len() > 16 * 1024 * 1024 || m.nlink() != 1 || !m.is_file() {
                    return Err(invalid());
                }
                Ok(Some(text))
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
/// Reserve generation durably only after a complete successful scan; failures leave accepted.json intact.
pub fn scan(config: &CatalogConfig, observed_at_ms: i64) -> io::Result<Snapshot> {
    if observed_at_ms < 0 || config.libraries.is_empty() || config.libraries.len() > 64 {
        return Err(invalid());
    }
    let state = root(&config.state_directory)?;
    let sm = state.metadata()?;
    if sm.uid() != rustix::process::geteuid().as_raw() || sm.mode() & 0o777 != 0o700 {
        return Err(invalid());
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(config.state_directory.join("catalog.lock"))?;
    let lm = lock.metadata()?;
    if !lm.is_file() || lm.nlink() != 1 || lm.uid() != sm.uid() || lm.mode() & 0o777 != 0o600 {
        return Err(invalid());
    }
    lock.lock_exclusive()?;
    let mut found = inventory(config, observed_at_ms)?;
    let generation = match private_read(&config.state_directory.join("generation"))? {
        Some(s) => {
            let reserved = s.trim().parse::<u64>().map_err(|_| invalid())?;
            for checkpoint in ["accepted.json", "published.json"] {
                if let Some(text) = private_read(&config.state_directory.join(checkpoint))? {
                    let old: Snapshot = serde_json::from_str(&text)?;
                    wolf_core::validate_catalog_generation(
                        &config.pc_id,
                        &old.manifest,
                        &old.attributes,
                        None,
                    )
                    .map_err(|_| invalid())?;
                    if old.manifest.catalog_generation > reserved {
                        return Err(invalid());
                    }
                }
            }
            reserved.checked_add(1).ok_or_else(invalid)?
        }
        None => {
            if config
                .state_directory
                .join("accepted.json")
                .symlink_metadata()
                .is_ok()
                || config
                    .state_directory
                    .join("published.json")
                    .symlink_metadata()
                    .is_ok()
            {
                return Err(invalid());
            }
            1
        }
    };
    for value in found.values_mut() {
        value.catalog_generation = generation
    }
    let snapshot = Snapshot {
        manifest: CatalogManifest {
            version: 1,
            pc_id: config.pc_id.clone(),
            catalog_generation: generation,
            app_ids: found.keys().cloned().collect(),
            observed_at_ms,
            complete: true,
        },
        attributes: found.into_values().collect(),
    };
    wolf_core::validate_catalog_generation(
        &config.pc_id,
        &snapshot.manifest,
        &snapshot.attributes,
        None,
    )
    .map_err(|_| invalid())?;
    atomic(
        &config.state_directory.join("generation"),
        generation.to_string().as_bytes(),
    )?;
    atomic(
        &config.state_directory.join("accepted.json"),
        &serde_json::to_vec(&snapshot)?,
    )?;
    Ok(snapshot)
}
fn state_guard(config: &CatalogConfig) -> io::Result<File> {
    let dir = root(&config.state_directory)?;
    let m = dir.metadata()?;
    if m.uid() != rustix::process::geteuid().as_raw() || m.mode() & 0o777 != 0o700 {
        return Err(invalid());
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(config.state_directory.join("catalog.lock"))?;
    let lm = lock.metadata()?;
    if !lm.is_file() || lm.nlink() != 1 || lm.uid() != m.uid() || lm.mode() & 0o777 != 0o600 {
        return Err(invalid());
    }
    lock.lock_exclusive()?;
    Ok(lock)
}
fn read_published(config: &CatalogConfig) -> io::Result<Option<Snapshot>> {
    let Some(text) = private_read(&config.state_directory.join("published.json"))? else {
        return Ok(None);
    };
    let snapshot: Snapshot = serde_json::from_str(&text)?;
    wolf_core::validate_catalog_generation(
        &config.pc_id,
        &snapshot.manifest,
        &snapshot.attributes,
        None,
    )
    .map_err(|_| invalid())?;
    Ok(Some(snapshot))
}
/// Last fully acknowledged broker publication, distinct from accepted scan state.
pub fn load_published(config: &CatalogConfig) -> io::Result<Option<Snapshot>> {
    let _lock = state_guard(config)?;
    read_published(config)
}
/// Call only after Publisher::publish_snapshot succeeds. Corrupt prior state is never reset.
pub fn record_published(config: &CatalogConfig, snapshot: &Snapshot) -> io::Result<()> {
    let _lock = state_guard(config)?;
    let previous = read_published(config)?;
    let entries = previous.as_ref().map(|p| {
        p.attributes
            .iter()
            .map(|a| (a.app_id.clone(), a.clone()))
            .collect::<BTreeMap<_, _>>()
    });
    let old = previous
        .as_ref()
        .zip(entries.as_ref())
        .map(|(p, e)| (&p.manifest, e));
    wolf_core::validate_catalog_generation(
        &config.pc_id,
        &snapshot.manifest,
        &snapshot.attributes,
        old,
    )
    .map_err(|_| invalid())?;
    let reserved = private_read(&config.state_directory.join("generation"))?
        .ok_or_else(invalid)?
        .parse::<u64>()
        .map_err(|_| invalid())?;
    if snapshot.manifest.catalog_generation > reserved {
        return Err(invalid());
    }
    atomic(
        &config.state_directory.join("published.json"),
        &serde_json::to_vec(snapshot)?,
    )
}

/// Read-only inventory for root lifecycle hooks; never advances published generations.
pub fn inventory(
    config: &CatalogConfig,
    observed_at_ms: i64,
) -> io::Result<BTreeMap<AppId, CatalogAttributes>> {
    if observed_at_ms < 0 || config.libraries.is_empty() || config.libraries.len() > 64 {
        return Err(invalid());
    }
    let mut found = BTreeMap::new();
    let mut libraries = std::collections::BTreeSet::new();
    let mut count = 0;
    for library in &config.libraries {
        if library.library_id.is_empty()
            || library.library_id.len() > 256
            || !libraries.insert(&library.library_id)
        {
            return Err(invalid());
        }
        let dir = root(&library.canonical_path)?;
        let identity = dir.metadata()?;
        let mut paths = fs::read_dir(&library.canonical_path)?
            .take(50001)
            .map(|e| e.map(|e| e.file_name()))
            .collect::<io::Result<Vec<_>>>()?;
        if paths.len() > 50000 {
            return Err(invalid());
        }
        paths.sort();
        for name in paths {
            let Some(name) = name.to_str() else {
                return Err(invalid());
            };
            if !name.starts_with("appmanifest_") || !name.ends_with(".acf") {
                continue;
            }
            count += 1;
            if count > 10000 {
                return Err(invalid());
            }
            let text = read_bounded(anchored(&dir, Path::new(name), false)?)?;
            let doc = crate::vdf::Document::parse(&text)?;
            let get = |field| doc.get(&["AppState", field]);
            let id = get("appid")?.ok_or_else(invalid)?;
            let app = AppId::new(&id).map_err(|_| invalid())?;
            if name != format!("appmanifest_{id}.acf") {
                return Err(invalid());
            }
            let cleaned = clean_game_name(&get("name")?.ok_or_else(invalid)?);
            let install = get("installdir")?.ok_or_else(invalid)?;
            let flags = get("StateFlags")?.unwrap_or_default();
            if cleaned.is_empty()
                || [
                    "proton",
                    "steam linux runtime",
                    "steamworks common redistributables",
                ]
                .iter()
                .any(|p| cleaned.to_lowercase().contains(p))
                || (!flags.is_empty() && flags != "4")
            {
                continue;
            }
            if install.is_empty()
                || Path::new(&install)
                    .components()
                    .any(|c| !matches!(c, Component::Normal(_)))
                || Path::new(&install).components().count() != 1
            {
                return Err(invalid());
            }
            match anchored(&dir, &Path::new("common").join(&install), true) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            let attr = CatalogAttributes {
                version: 1,
                pc_id: config.pc_id.clone(),
                app_id: app.clone(),
                name: cleaned,
                cover_url: steam_cover_url(&app),
                library_id: library.library_id.clone(),
                catalog_generation: 0,
                observed_at_ms,
            };
            attr.validate().map_err(|_| invalid())?;
            if found.insert(app, attr).is_some() {
                return Err(invalid());
            }
        }
        let current = fs::symlink_metadata(&library.canonical_path)?;
        if !current.is_dir()
            || current.dev() != identity.dev()
            || current.ino() != identity.ino()
            || current.mtime() != identity.mtime()
            || current.mtime_nsec() != identity.mtime_nsec()
        {
            return Err(invalid());
        }
    }
    Ok(found)
}
