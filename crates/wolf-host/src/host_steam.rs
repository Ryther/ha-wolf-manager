//! Root-policy Steam overlays and permanent, pairing-preserving Wolf app updates.
use crate::{
    policy::RootPolicy,
    transactions::{Grant, TransactionStore},
};
use std::{collections::BTreeMap, fs, io, path::Path};
use wolf_core::Settings;
fn invalid() -> io::Error {
    io::Error::other("root Steam adapter policy is invalid")
}
pub fn runner(policy: &RootPolicy) -> io::Result<toml::Table> {
    let mut runner = policy.steam_runner.clone();
    let existing = runner
        .get("mounts")
        .map(|v| v.as_array().cloned().ok_or_else(invalid))
        .transpose()?
        .unwrap_or_default();
    let mut mounts = BTreeMap::<String, String>::new();
    for value in existing {
        let value = value.as_str().ok_or_else(invalid)?;
        let parts = value.split(':').collect::<Vec<_>>();
        if parts.len() < 2
            || parts.len() > 3
            || !parts[0].starts_with('/')
            || !parts[1].starts_with('/')
        {
            return Err(invalid());
        }
        if mounts
            .insert(parts[1].to_owned(), value.to_owned())
            .is_some()
        {
            return Err(invalid());
        }
    }
    let mut insert = |host: &Path, destination: &Path, mode: &str| -> io::Result<()> {
        let host = host.to_str().ok_or_else(invalid)?;
        let destination = destination.to_str().ok_or_else(invalid)?;
        if !host.starts_with('/')
            || !destination.starts_with('/')
            || host.contains([':', '\n', '\r'])
            || destination.contains([':', '\n', '\r'])
        {
            return Err(invalid());
        }
        let value = format!("{host}:{destination}:{mode}");
        if let Some(old) = mounts.get(destination)
            && old != &value
        {
            return Err(io::Error::other(
                "runner destination conflicts with authorized storage mapping",
            ));
        }
        mounts.insert(destination.to_owned(), value);
        Ok(())
    };
    for library in &policy.libraries {
        for destination in &library.container_paths {
            insert(&library.steamapps_path, destination, "rw")?;
        }
    }
    for profile in &policy.steam_profiles {
        if profile.container_userdata_paths.is_empty() {
            return Err(io::Error::other(
                "profile config requires an authorized container userdata mapping",
            ));
        }
        for destination in &profile.container_userdata_paths {
            if destination.file_name().and_then(|n| n.to_str()) != Some("userdata") {
                return Err(invalid());
            }
            let base = destination.parent().ok_or_else(invalid)?;
            insert(
                &profile.root.join(&profile.config_vdf),
                &base.join("config/config.vdf"),
                "rw",
            )?;
            insert(
                &profile.root.join(&profile.userdata_directory),
                destination,
                "rw",
            )?;
        }
    }
    if let Some(proton) = &policy.proton {
        for destination in &proton.container_paths {
            insert(&proton.host_path, destination, "ro")?;
        }
    }
    runner.insert(
        "mounts".into(),
        toml::Value::Array(mounts.into_values().map(toml::Value::String).collect()),
    );
    let mut env = runner
        .get("env")
        .map(|v| v.as_array().cloned().ok_or_else(invalid))
        .transpose()?
        .unwrap_or_default();
    if env.iter().any(|value| value.as_str().is_none()) {
        return Err(invalid());
    }
    env.retain(|value| {
        !value.as_str().unwrap().starts_with("PUID=")
            && !value.as_str().unwrap().starts_with("PGID=")
    });
    env.extend(
        [
            format!("PUID={}", policy.steam_uid),
            format!("PGID={}", policy.steam_gid),
        ]
        .into_iter()
        .map(toml::Value::String),
    );
    runner.insert("env".into(), toml::Value::Array(env));
    labelled_runner(&runner, &policy.pc_id)
}
fn commit_current(
    store: &TransactionStore,
    grant: &Grant,
    relative: &str,
    moonlight: &str,
    user: &str,
) -> io::Result<()> {
    let current = grant.read(relative)?;
    let current = std::str::from_utf8(&current).map_err(|_| invalid())?;
    let next = crate::steam::generated_sections(current, moonlight, user)?;
    if next.as_bytes() != current.as_bytes() {
        let id = store.apply_expected(grant, relative, current.as_bytes(), next.as_bytes())?;
        store.commit(grant, &id)?;
    }
    Ok(())
}
pub fn clear_current(store: &TransactionStore, grant: &Grant, relative: &str) -> io::Result<()> {
    commit_current(store, grant, relative, "", "")
}
fn bounded_plan(changes: &[(usize, String, Vec<u8>, Vec<u8>)]) -> io::Result<()> {
    if changes.len() > 1024
        || changes
            .iter()
            .map(|(_, _, after, before)| after.len() + before.len())
            .sum::<usize>()
            > 64 * 1024 * 1024
    {
        return Err(io::Error::other(
            "Steam overlay plan exceeds bounded memory or file count",
        ));
    }
    Ok(())
}
pub fn prepare(policy: &RootPolicy, settings: &Settings) -> io::Result<()> {
    policy.validate()?;
    crate::host_runtime::require_no_container_writers(
        policy,
        &mut crate::host_status::FixedTools,
        std::time::Duration::from_secs(15),
    )?;
    prepare_impl(policy, settings, true, || {
        crate::quiescence::require_stopped(policy.steam_uid, &policy.steam_executables)
    })
}
pub fn prepare_with(
    policy: &RootPolicy,
    settings: &Settings,
    quiescent: impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    prepare_impl(policy, settings, false, quiescent)
}
fn prepare_impl(
    policy: &RootPolicy,
    settings: &Settings,
    online: bool,
    quiescent: impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    policy.validate()?;
    settings.validate().map_err(|_| invalid())?;
    quiescent()?;
    let store = TransactionStore::open(&policy.backup_root)?;
    if !store.active()?.is_empty() {
        return Err(io::Error::other("previous Steam overlay requires recovery"));
    }
    let config = crate::catalog::CatalogConfig {
        pc_id: policy.pc_id.clone(),
        libraries: policy
            .libraries
            .iter()
            .map(|library| crate::catalog::Library {
                library_id: library.library_id.clone(),
                canonical_path: library.steamapps_path.clone(),
            })
            .collect(),
        state_directory: policy.catalog_state_directory.clone(),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| invalid())?
        .as_millis();
    let inventory = crate::catalog::inventory(&config, i64::try_from(now).map_err(|_| invalid())?)?;
    let mut active_settings = settings.clone();
    active_settings
        .games
        .retain(|app, _| inventory.contains_key(app));
    if policy.proton.is_none()
        && active_settings
            .games
            .values()
            .any(|game| game.proton_cachyos)
    {
        return Err(invalid());
    }
    let mut needs_localconfig = false;
    let mut options_size = 0usize;
    for game in active_settings.games.values() {
        let options = crate::steam::launch_options(game, &active_settings)?;
        options_size = options_size
            .checked_add(options.len())
            .ok_or_else(invalid)?;
        if options_size > 8 * 1024 * 1024 {
            return Err(io::Error::other(
                "Steam launch option expansion exceeds bounds",
            ));
        }
        needs_localconfig |= !options.is_empty();
    }
    let mut localconfig_count = 0usize;
    let mut mappings = Vec::new();
    for library in &policy.libraries {
        let host = library
            .steamapps_path
            .parent()
            .and_then(Path::to_str)
            .ok_or_else(invalid)?;
        let destination = library
            .container_paths
            .first()
            .and_then(|p| p.parent())
            .and_then(Path::to_str)
            .ok_or_else(invalid)?;
        let apps = inventory
            .values()
            .filter(|app| app.library_id == library.library_id)
            .map(|app| app.app_id.clone())
            .collect::<Vec<_>>();
        mappings.push((host.to_owned(), destination.to_owned(), apps));
    }
    let grants = policy
        .steam_profiles
        .iter()
        .map(|profile| Grant::for_owner(&profile.root, policy.steam_uid, policy.steam_gid))
        .collect::<io::Result<Vec<_>>>()?;
    let mut changes: Vec<(usize, String, Vec<u8>, Vec<u8>)> = Vec::new();
    for (index, profile) in policy.steam_profiles.iter().enumerate() {
        let grant = &grants[index];
        if let Some(proton) = &policy.proton {
            let original = grant.read(&profile.config_vdf)?;
            let text = std::str::from_utf8(&original).map_err(|_| invalid())?;
            changes.push((
                index,
                profile.config_vdf.clone(),
                crate::steam::compatibility(text, &active_settings, &proton.name)?.into_bytes(),
                original,
            ));
            bounded_plan(&changes)?;
        }
        for relative in &profile.libraryfolders_vdf {
            let original = grant.read(relative)?;
            let text = std::str::from_utf8(&original).map_err(|_| invalid())?;
            changes.push((
                index,
                relative.clone(),
                crate::steam::libraryfolders(text, &mappings)?.into_bytes(),
                original,
            ));
            bounded_plan(&changes)?;
        }
        let userdata = profile.root.join(&profile.userdata_directory);
        let mut accounts = fs::read_dir(&userdata)?
            .take(1001)
            .collect::<io::Result<Vec<_>>>()?;
        if accounts.len() > 1000 {
            return Err(invalid());
        }
        accounts.sort_by_key(|e| e.file_name());
        for account in accounts {
            let name = account.file_name();
            let name = name.to_str().ok_or_else(invalid)?;
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let relative = format!(
                "{}/{name}/config/localconfig.vdf",
                profile.userdata_directory
            );
            match fs::symlink_metadata(profile.root.join(&relative)) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
                Ok(_) => {}
            }
            let original = grant.read(&relative)?;
            localconfig_count += 1;
            let text = std::str::from_utf8(&original).map_err(|_| invalid())?;
            changes.push((
                index,
                relative,
                crate::steam::localconfig(text, &active_settings)?.into_bytes(),
                original,
            ));
            bounded_plan(&changes)?;
        }
    }
    if needs_localconfig && localconfig_count == 0 {
        return Err(io::Error::other(
            "Steam login must initialize an owned localconfig before launch options can apply",
        ));
    }
    let mut targets = std::collections::BTreeSet::new();
    for (index, relative, _, _) in &changes {
        if !targets.insert(policy.steam_profiles[*index].root.join(relative)) {
            return Err(io::Error::other("duplicate mutable Steam target"));
        }
    }
    let trusted_runner = runner(policy)?;
    let apps = settings
        .games
        .iter()
        .filter(|(id, game)| game.direct_launch && inventory.contains_key(id))
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    let icons = crate::icons::prepare(policy, &apps, online)?;
    let (moonlight, user) =
        crate::generated_apps::generate_with_icons(settings, &inventory, &trusted_runner, &icons)?;
    let wolf = Grant::for_owner(
        &policy.wolf_config.root,
        policy.wolf_config.uid,
        policy.wolf_config.gid,
    )?;
    // Parse the Wolf candidate before any temporary file effects.
    let current = wolf.read(&policy.wolf_config.relative_path)?;
    crate::steam::generated_sections(
        std::str::from_utf8(&current).map_err(|_| invalid())?,
        &moonlight,
        &user,
    )?;
    let overlays = changes
        .iter()
        .map(|(index, relative, bytes, _)| crate::hooks::Overlay {
            grant: &grants[*index],
            relative,
            bytes: bytes.clone(),
        })
        .collect::<Vec<_>>();
    let expected = changes
        .iter()
        .map(|(_, _, _, original)| original.clone())
        .collect::<Vec<_>>();
    crate::hooks::apply_expected(&store, &overlays, &expected, &quiescent)?;
    if let Err(error) = quiescent().and_then(|()| {
        commit_current(
            &store,
            &wolf,
            &policy.wolf_config.relative_path,
            &moonlight,
            &user,
        )
    }) {
        let _ = restore_overlays(policy, &store, &quiescent);
        return Err(error);
    }
    Ok(())
}
fn restore_overlays(
    policy: &RootPolicy,
    store: &TransactionStore,
    quiescent: impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    let grants = policy
        .steam_profiles
        .iter()
        .map(|profile| (profile.root.as_path(), policy.steam_uid, policy.steam_gid))
        .chain(std::iter::once((
            policy.wolf_config.root.as_path(),
            policy.wolf_config.uid,
            policy.wolf_config.gid,
        )))
        .collect::<Vec<_>>();
    crate::hooks::restore(store, &grants, quiescent)
}
pub fn restore(policy: &RootPolicy) -> io::Result<()> {
    policy.validate()?;
    crate::host_runtime::require_no_container_writers(
        policy,
        &mut crate::host_status::FixedTools,
        std::time::Duration::from_secs(15),
    )?;
    restore_with(policy, || {
        crate::quiescence::require_stopped(policy.steam_uid, &policy.steam_executables)
    })
}
pub fn restore_with(policy: &RootPolicy, quiescent: impl Fn() -> io::Result<()>) -> io::Result<()> {
    policy.validate()?;
    quiescent()?;
    let store = TransactionStore::open(&policy.backup_root)?;
    restore_overlays(policy, &store, &quiescent)?;
    quiescent()?;
    let wolf = Grant::for_owner(
        &policy.wolf_config.root,
        policy.wolf_config.uid,
        policy.wolf_config.gid,
    )?;
    clear_current(&store, &wolf, &policy.wolf_config.relative_path)
}
pub fn labelled_runner(template: &toml::Table, pc: &wolf_core::PcId) -> io::Result<toml::Table> {
    let mut runner = template.clone();
    let mut create = match runner.get("base_create_json") {
        None => serde_json::Map::new(),
        Some(value) => {
            let value: serde_json::Value =
                serde_json::from_str(value.as_str().ok_or_else(invalid)?)?;
            value.as_object().cloned().ok_or_else(invalid)?
        }
    };
    let mut labels = match create.remove("Labels") {
        None => serde_json::Map::new(),
        Some(value) => value.as_object().cloned().ok_or_else(invalid)?,
    };
    if labels.values().any(|value| value.as_str().is_none()) {
        return Err(invalid());
    }
    for (key, value) in [
        ("io.ha-wolf-manager.pc", pc.as_str()),
        ("io.ha-wolf-manager.owner", "managed-steam-v1"),
    ] {
        if labels
            .get(key)
            .is_some_and(|old| old.as_str() != Some(value))
        {
            return Err(io::Error::other("runner ownership label conflict"));
        }
        labels.insert(key.into(), serde_json::Value::String(value.into()));
    }
    create.insert("Labels".into(), serde_json::Value::Object(labels));
    runner.insert(
        "base_create_json".into(),
        toml::Value::String(serde_json::to_string(&create)?),
    );
    Ok(runner)
}
