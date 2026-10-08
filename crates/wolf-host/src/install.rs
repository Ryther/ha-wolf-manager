//! Root-only, explicit installer plans. Applying never starts Wolf or migrates data.
use crate::policy::{RootPolicy, trusted_path};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};
use uuid::Uuid;

const LIMIT: usize = 128 * 1024 * 1024;
fn fail(message: &'static str) -> io::Error {
    io::Error::other(message)
}
fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallMode {
    Install,
    Adopt,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitialFile {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}
#[derive(Clone, Debug)]
pub struct InstallRequest {
    pub mode: InstallMode,
    pub policy: RootPolicy,
    pub authorized_public_keys: Vec<String>,
    pub source_binary: PathBuf,
    pub broker_config_source: Option<PathBuf>,
    pub initial_files: Vec<InitialFile>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub sha256: String,
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageMapping {
    pub old: PathBuf,
    pub new: PathBuf,
    pub action: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedWrite {
    pub destination: PathBuf,
    pub sha256: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub expected: Option<FileIdentity>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryIdentity {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedDirectory {
    pub path: PathBuf,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub expected: Option<DirectoryIdentity>,
    pub anchor: PathBuf,
    pub anchor_identity: DirectoryIdentity,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceState {
    pub active: bool,
    pub enabled: bool,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSnapshot {
    pub wolf: ServiceState,
    pub catalog: ServiceState,
    pub ssh_unit: String,
    pub ssh: ServiceState,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallPlan {
    pub version: u8,
    pub id: Uuid,
    pub mode: InstallMode,
    pub policy: RootPolicy,
    pub storage_mapping: Vec<StorageMapping>,
    pub proposed_writes: Vec<PlannedWrite>,
    #[serde(default)]
    pub proposed_directories: Vec<PlannedDirectory>,
    #[serde(default)]
    pub initial_files: Vec<InitialFile>,
    pub source_binary: PathBuf,
    pub source_identity: FileIdentity,
    pub broker_config_source: Option<PathBuf>,
    pub broker_identity: Option<FileIdentity>,
    pub authorized_public_keys: Vec<String>,
    pub account_exists: bool,
    #[serde(default)]
    pub service_snapshot: ServiceSnapshot,
    #[serde(default)]
    pub receipt_identity: Option<FileIdentity>,
    pub rollback: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallReport {
    pub version: u8,
    pub id: Uuid,
    pub changed_files: Vec<PathBuf>,
    pub installed_files: std::collections::BTreeMap<PathBuf, FileIdentity>,
    pub verified_backup_directory: PathBuf,
    pub activation_required: bool,
    #[serde(default)]
    pub retained_files: Vec<PathBuf>,
    pub recovery_instructions: String,
}
struct Recipe {
    path: PathBuf,
    bytes: Vec<u8>,
    mode: u32,
    uid: u32,
    gid: u32,
}
fn read(path: &Path) -> io::Result<(Vec<u8>, FileIdentity)> {
    let file = File::from(rustix::fs::openat2(
        rustix::fs::CWD,
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    )?);
    let m = file.metadata()?;
    if !m.is_file() || m.nlink() != 1 || m.mode() & 0o6022 != 0 || m.len() > LIMIT as u64 {
        return Err(fail("unsafe input type, aliases, mode or size"));
    }
    // Refuse metadata we cannot preserve; never silently discard ACLs/security labels.
    let mut attrs = [0u8; 65536];
    match rustix::fs::flistxattr(&file, &mut attrs[..]) {
        Ok(0) => {}
        Err(e) if e == rustix::io::Errno::OPNOTSUPP => {}
        _ => return Err(fail("extended attributes require guarded manual adoption")),
    }
    let mut bytes = Vec::new();
    file.take((LIMIT + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > LIMIT {
        return Err(fail("input exceeds bound"));
    }
    let identity = FileIdentity {
        sha256: sha(&bytes),
        device: m.dev(),
        inode: m.ino(),
        size: m.len(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode() & 0o777,
    };
    Ok((bytes, identity))
}

impl FileIdentity {
    pub fn capture(path: &Path) -> io::Result<Self> {
        Ok(read(path)?.1)
    }
    pub fn verify(&self, path: &Path) -> io::Result<()> {
        if Self::capture(path)? != *self {
            return Err(fail("input identity or bytes changed"));
        }
        Ok(())
    }
}

fn expected(path: &Path) -> io::Result<Option<FileIdentity>> {
    match read(path) {
        Ok((_, identity)) => Ok(Some(identity)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Accept only a canonical Ed25519 public key; callers cannot inject key options.
pub fn validate_public_key(value: &str) -> io::Result<String> {
    if value.len() > 4096 || value.bytes().any(|b| !(32..=126).contains(&b)) {
        return Err(fail("invalid public key characters"));
    }
    let mut words = value.split_ascii_whitespace();
    if words.next() != Some("ssh-ed25519") {
        return Err(fail("only Ed25519 public keys are supported"));
    }
    let encoded = words.next().ok_or_else(|| fail("missing public key"))?;
    if encoded.len() != 68 {
        return Err(fail("invalid Ed25519 public key length"));
    }
    let mut decoded = Vec::new();
    let mut bits = 0u32;
    let mut count = 0;
    for c in encoded.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err(fail("invalid public key encoding")),
        };
        bits = (bits << 6) | v as u32;
        count += 6;
        if count >= 8 {
            count -= 8;
            decoded.push((bits >> count) as u8);
        }
    }
    if decoded.len() != 51
        || decoded[..15] != *b"\0\0\0\x0bssh-ed25519"
        || decoded[15..19] != [0, 0, 0, 32]
    {
        return Err(fail("public key wire type or length mismatch"));
    }
    Ok(format!(
        "restrict,command=\"/usr/libexec/wolf-manager/ssh-dispatcher\" ssh-ed25519 {encoded}"
    ))
}
/// The release boundary verifies checksums; this rejects dynamic or wrong-CPU ELF.
pub fn validate_static_binary(bytes: &[u8], architecture: &str) -> io::Result<()> {
    if bytes.len() < 64
        || bytes[..4] != *b"\x7fELF"
        || bytes[4] != 2
        || bytes[5] != 1
        || bytes[6] != 1
    {
        return Err(fail("expected ELF64 little-endian executable"));
    }
    let machine = u16::from_le_bytes(bytes[18..20].try_into().unwrap());
    if machine
        != match architecture {
            "x86_64" => 62,
            "aarch64" => 183,
            _ => return Err(fail("unsupported host architecture")),
        }
        || ![2, 3].contains(&u16::from_le_bytes(bytes[16..18].try_into().unwrap()))
    {
        return Err(fail("wrong ELF architecture or type"));
    }
    let offset = usize::try_from(u64::from_le_bytes(bytes[32..40].try_into().unwrap()))
        .map_err(|_| fail("invalid ELF offset"))?;
    let size = u16::from_le_bytes(bytes[54..56].try_into().unwrap()) as usize;
    let count = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
    if size != 56
        || count == 0
        || count > 128
        || offset
            .checked_add(size * count)
            .is_none_or(|end| end > bytes.len())
    {
        return Err(fail("invalid ELF program headers"));
    }
    for i in 0..count {
        if u32::from_le_bytes(
            bytes[offset + i * size..offset + i * size + 4]
                .try_into()
                .unwrap(),
        ) == 3
        {
            return Err(fail("dynamic interpreter is forbidden"));
        }
    }
    Ok(())
}
pub fn render_privilege_templates(keys: &[String]) -> io::Result<Vec<(String, Vec<u8>, u32)>> {
    if keys.is_empty() || keys.len() > 32 {
        return Err(fail("one to 32 authorized keys required"));
    }
    let mut unique = std::collections::BTreeSet::new();
    for key in keys {
        unique.insert(validate_public_key(key)?);
    }
    let authorized = unique.into_iter().collect::<Vec<_>>().join("\n") + "\n";
    Ok(vec![
        (
            "/usr/libexec/wolf-manager/ssh-dispatcher".into(),
            include_bytes!("../../../installer/templates/ssh-dispatcher").to_vec(),
            0o755,
        ),
        (
            "/usr/libexec/wolf-manager/wolf-host-root".into(),
            include_bytes!("../../../installer/templates/wolf-host-root").to_vec(),
            0o755,
        ),
        (
            "/etc/ssh/sshd_config.d/90-wolf-manager.conf".into(),
            include_bytes!("../../../installer/templates/90-wolf-manager.conf").to_vec(),
            0o644,
        ),
        (
            "/etc/sudoers.d/wolf-manager".into(),
            include_bytes!("../../../installer/templates/wolf-manager.sudoers").to_vec(),
            0o440,
        ),
        (
            "/etc/ssh/authorized_keys.d/wolf-manager".into(),
            authorized.into_bytes(),
            0o644,
        ),
    ])
}
fn quote_unit(path: &Path) -> io::Result<String> {
    let value = path.to_str().ok_or_else(|| fail("non-UTF8 service path"))?;
    if value.chars().any(char::is_control) {
        return Err(fail("control character in service path"));
    }
    Ok(format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    ))
}
fn recipes(request: &InstallRequest) -> io::Result<Vec<Recipe>> {
    let mut recipes = render_privilege_templates(&request.authorized_public_keys)?
        .into_iter()
        .map(|(path, bytes, mode)| Recipe {
            path: path.into(),
            bytes,
            mode,
            uid: 0,
            gid: 0,
        })
        .collect::<Vec<_>>();
    let (binary, _) = read(&request.source_binary)?;
    validate_static_binary(&binary, std::env::consts::ARCH)?;
    recipes.push(Recipe {
        path: "/usr/local/bin/wolf-manager-host".into(),
        bytes: binary,
        mode: 0o755,
        uid: 0,
        gid: 0,
    });
    recipes.push(Recipe {
        path: "/etc/wolf-manager/host-policy.json".into(),
        bytes: serde_json::to_vec_pretty(&request.policy)?,
        mode: 0o644,
        uid: 0,
        gid: 0,
    });
    let catalog = include_str!("../../../installer/templates/wolf-manager-catalog.service")
        .replace("@STEAM_UID@", &request.policy.steam_uid.to_string())
        .replace("@STEAM_GID@", &request.policy.steam_gid.to_string())
        .replace(
            "@CATALOG_STATE@",
            &quote_unit(&request.policy.catalog_state_directory)?,
        );
    recipes.push(Recipe {
        path: "/etc/systemd/system/wolf-manager-catalog.service".into(),
        bytes: catalog.into_bytes(),
        mode: 0o644,
        uid: 0,
        gid: 0,
    });
    let (path, unit)=match request.mode { InstallMode::Install => (PathBuf::from(format!("/etc/systemd/system/{}",request.policy.service_unit)), include_str!("../../../installer/templates/wolf.service").to_owned()), InstallMode::Adopt => (PathBuf::from(format!("/etc/systemd/system/{}.d/90-wolf-manager.conf",request.policy.service_unit)), "# Managed by HA Wolf Manager\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStartPre=\nExecStart=\nExecStart=/usr/local/bin/wolf-manager-host lifecycle-start\nExecStop=\nExecStop=/usr/local/bin/wolf-manager-host lifecycle-stop\nExecStopPost=\nTimeoutStartSec=@START_TIMEOUT@\nTimeoutStopSec=180\n".to_owned()) };
    recipes.push(Recipe {
        path,
        bytes: unit
            .replace(
                "@START_TIMEOUT@",
                &(request.policy.pull_timeout_seconds + 185).to_string(),
            )
            .into_bytes(),
        mode: 0o644,
        uid: 0,
        gid: 0,
    });
    append_broker_recipe(request, &mut recipes)?;
    append_initial_recipes(request, &mut recipes)?;
    Ok(recipes)
}

fn installation_recipes(
    request: &InstallRequest,
    environment: &Environment,
) -> io::Result<Vec<Recipe>> {
    let mut recipes = recipes(request)?;
    for recipe in &mut recipes {
        if !request.initial_files.iter().any(|f| f.path == recipe.path)
            && request.policy.broker_secret_file.as_ref() != Some(&recipe.path)
        {
            recipe.path = environment.path(&recipe.path);
        }
    }
    Ok(recipes)
}

fn append_broker_recipe(request: &InstallRequest, recipes: &mut Vec<Recipe>) -> io::Result<()> {
    if let Some(source) = &request.broker_config_source {
        let target = request
            .policy
            .broker_secret_file
            .clone()
            .ok_or_else(|| fail("broker source requires explicit policy destination"))?;
        if !target.starts_with("/etc/wolf-manager/") {
            return Err(fail(
                "installer broker destination must be under root authority",
            ));
        }
        let (bytes, _) = read(source)?;
        recipes.push(Recipe {
            path: target,
            bytes,
            mode: 0o600,
            uid: request.policy.steam_uid,
            gid: request.policy.steam_gid,
        });
    }
    Ok(())
}

fn append_initial_recipes(request: &InstallRequest, recipes: &mut Vec<Recipe>) -> io::Result<()> {
    let mut initial_paths = std::collections::BTreeSet::new();
    for initial in &request.initial_files {
        validate_initial_file(request, initial, &mut initial_paths)?;
        recipes.insert(
            0,
            Recipe {
                path: initial.path.clone(),
                bytes: initial.bytes.clone(),
                uid: 0,
                gid: 0,
                mode: 0o644,
            },
        );
    }
    validate_required_sources(request, &initial_paths)
}

fn validate_initial_file<'a>(
    request: &InstallRequest,
    initial: &'a InitialFile,
    initial_paths: &mut std::collections::BTreeSet<&'a PathBuf>,
) -> io::Result<()> {
    if request.mode != InstallMode::Install
        || !initial_paths.insert(&initial.path)
        || initial.uid != 0
        || initial.gid != 0
        || ![0o600, 0o644].contains(&initial.mode)
        || initial.bytes.len() > 2 * 1024 * 1024
    {
        return Err(fail("invalid bootstrap file authority"));
    }
    if expected(&initial.path)?.is_some() {
        return Err(fail("bootstrap defaults cannot replace existing state"));
    }
    if initial.path
        == request
            .policy
            .wolf_config
            .root
            .join(&request.policy.wolf_config.relative_path)
    {
        let text = std::str::from_utf8(&initial.bytes)
            .map_err(|_| fail("bootstrap Wolf config must be UTF8"))?;
        let _: toml::Table = toml::from_str(text).map_err(|_| fail("invalid initial Wolf TOML"))?;
    } else if initial.path == request.policy.compose_file {
        validate_compose_initial(&initial.bytes, &request.policy)?;
    } else {
        return Err(fail("bootstrap input path is not granted"));
    }
    Ok(())
}

fn validate_required_sources(
    request: &InstallRequest,
    initial_paths: &std::collections::BTreeSet<&PathBuf>,
) -> io::Result<()> {
    for required in [
        request
            .policy
            .wolf_config
            .root
            .join(&request.policy.wolf_config.relative_path),
        request.policy.compose_file.clone(),
    ] {
        if expected(&required)?.is_none() && !initial_paths.contains(&required) {
            return Err(fail(
                "missing Wolf source requires explicit default producer input",
            ));
        }
        if expected(&required)?.is_some() {
            trusted_path(&required, 0, false)?;
        }
    }
    Ok(())
}

fn validate_locked_home() -> io::Result<()> {
    let home = Path::new("/nonexistent");
    match fs::symlink_metadata(home) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
        Ok(metadata)
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 =>
        {
            return Err(fail("managed home authority is unsafe"));
        }
        Ok(_) => {}
    }
    match fs::symlink_metadata(home.join(".ssh")) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
        Ok(_) => Err(fail(
            "managed home has SSH state; no implicit adoption of user environment",
        )),
    }
}
fn account_exists() -> io::Result<bool> {
    validate_locked_home()?;
    let passwd = fs::read_to_string("/etc/passwd")?;
    let Some(line) = passwd.lines().find(|l| l.starts_with("wolf-manager:")) else {
        return Ok(false);
    };
    let fields = line.split(':').collect::<Vec<_>>();
    if fields.len() != 7
        || fields[2].parse::<u32>().ok().is_none_or(|uid| uid == 0)
        || fields[3].parse::<u32>().ok().is_none_or(|gid| gid == 0)
        || fields[5] != "/nonexistent"
        || fields[6] != "/bin/sh"
    {
        return Err(fail(
            "existing account does not match restricted system account",
        ));
    }
    let group = fs::read_to_string("/etc/group")?;
    if !group.lines().any(|line| {
        let f = line.split(':').collect::<Vec<_>>();
        f.len() == 4 && f[0] == "wolf-manager" && f[2] == fields[3]
    }) {
        return Err(fail("account primary group is not dedicated"));
    }
    for line in group.lines() {
        let f = line.split(':').collect::<Vec<_>>();
        if f.len() != 4 {
            return Err(fail("malformed group database"));
        }
        if f[3].split(',').any(|name| name == "wolf-manager") && f[2] != fields[3] {
            return Err(fail("managed account has supplementary privileges"));
        }
    }
    let shadow = fs::read_to_string("/etc/shadow")?;
    let password = shadow
        .lines()
        .find(|l| l.starts_with("wolf-manager:"))
        .and_then(|l| l.split(':').nth(1))
        .ok_or_else(|| fail("managed account lacks shadow lock"))?;
    if !(password.starts_with('!') || password.starts_with('*')) {
        return Err(fail("managed account password is not locked"));
    }
    Ok(true)
}
fn ancestor(path: &Path) -> io::Result<()> {
    let mut cursor = path
        .parent()
        .ok_or_else(|| fail("destination lacks parent"))?;
    while !cursor.exists() {
        cursor = cursor
            .parent()
            .ok_or_else(|| fail("missing filesystem root"))?;
    }
    if cursor == Path::new("/") {
        return Ok(());
    }
    trusted_path(cursor, 0, true)
}
fn pending(policy: &RootPolicy) -> io::Result<()> {
    let legacy_marker = policy
        .wolf_config
        .root
        .join("state/steam-config-backups/restore-pending");
    match fs::symlink_metadata(&legacy_marker) {
        Ok(_) => {
            return Err(fail(
                "source legacy restore is pending; finish recovery before adoption",
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    if policy.backup_root.exists()
        && crate::transactions::TransactionStore::open(&policy.backup_root)?.recovery_pending()?
    {
        return Err(fail("unresolved native restore prevents installation"));
    }
    // Legacy state is never guessed away. Operator must finish its restore first.
    for name in [
        "steam-backup",
        "steam-config-backup",
        "pending-restore.json",
        "backup-manifest.json",
    ] {
        if policy.state_root.join(name).exists() {
            return Err(fail("legacy restore evidence requires explicit recovery"));
        }
    }
    Ok(())
}
fn inspect_adopt(policy: &RootPolicy) -> io::Result<()> {
    let paths = [
        PathBuf::from(format!("/etc/systemd/system/{}", policy.service_unit)),
        PathBuf::from(format!("/usr/lib/systemd/system/{}", policy.service_unit)),
    ];
    let path = paths
        .iter()
        .find(|p| p.exists())
        .ok_or_else(|| fail("adoption requires an existing recognized unit"))?;
    trusted_path(path, 0, false)?;
    let (bytes, _) = read(path)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| fail("unit is not UTF8"))?;
    let compose = policy
        .compose_file
        .to_str()
        .ok_or_else(|| fail("compose path is not UTF8"))?;
    let explicit = text.lines().any(|line| {
        line == format!("ExecStart=/usr/bin/docker compose -f {compose} up --remove-orphans")
    });
    let parent = policy
        .compose_file
        .parent()
        .and_then(Path::to_str)
        .ok_or_else(|| fail("invalid compose directory"))?;
    let captured = text
        .lines()
        .any(|line| line == format!("WorkingDirectory={parent}"))
        && text
            .lines()
            .any(|line| line == "ExecStart=/usr/bin/docker compose up --remove-orphans")
        && text
            .lines()
            .any(|line| line == "ExecStop=/usr/bin/docker compose down --remove-orphans");
    if !explicit && !captured {
        return Err(fail(
            "existing unit has an unrecognized lifecycle; guarded manual adoption required",
        ));
    }
    Ok(())
}
pub fn preflight(request: &InstallRequest) -> io::Result<InstallPlan> {
    preflight_with(request, &Environment::default())
}
fn preflight_with(request: &InstallRequest, environment: &Environment) -> io::Result<InstallPlan> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(fail(
            "installer preflight requires root authority inspection",
        ));
    }
    request.policy.validate_install_prerequisites()?;
    if !environment.fixture() {
        validate_ssh_policy_tree(Path::new("/etc/ssh/sshd_config"), Path::new("/etc/ssh"))?;
    }
    validate_existing_storage_authority(request, environment)?;

    pending(&request.policy)?;
    // The current upstream stable image is amd64-only. Do not silently emulate it.
    if std::env::consts::ARCH != "x86_64" {
        return Err(fail(
            "Wolf image architecture requires independently verified compatibility",
        ));
    }
    if request.mode == InstallMode::Adopt {
        inspect_adopt(&request.policy)?;
    }
    let (_, source_identity) = read(&request.source_binary)?;
    let broker_identity = request
        .broker_config_source
        .as_deref()
        .map(read)
        .transpose()?
        .map(|(_, i)| i);
    let recipes = installation_recipes(request, environment)?;
    let receipt_path = request.policy.state_root.join("installation.json");
    let previous: Option<InstallReport> = if receipt_path.exists() {
        trusted_path(&receipt_path, 0, false)?;
        Some(serde_json::from_slice(&read(&receipt_path)?.0)?)
    } else {
        None
    };
    let writes = preview_writes(recipes, previous.as_ref())?;
    let mut mappings = Vec::new();
    for library in &request.policy.libraries {
        mappings.push(StorageMapping {
            old: library.steamapps_path.clone(),
            new: library.steamapps_path.clone(),
            action: "preserve in place; no library migration".into(),
        });
    }
    for profile in &request.policy.steam_profiles {
        mappings.push(StorageMapping {
            old: profile.root.clone(),
            new: profile.root.clone(),
            action: "preserve pairing/profile/userdata; no migration".into(),
        });
    }
    mappings.push(StorageMapping {
        old: request
            .policy
            .wolf_config
            .root
            .join(&request.policy.wolf_config.relative_path),
        new: request
            .policy
            .wolf_config
            .root
            .join(&request.policy.wolf_config.relative_path),
        action: "preserve Wolf identity, custom apps and bind mounts".into(),
    });
    Ok(InstallPlan{version:1,id:Uuid::new_v4(),mode:request.mode.clone(),policy:request.policy.clone(),storage_mapping:mappings,proposed_writes:writes.clone(),proposed_directories:planned_directories(&request.policy,&writes)?,initial_files:request.initial_files.clone(),source_binary:request.source_binary.clone(),source_identity,broker_config_source:request.broker_config_source.clone(),broker_identity,authorized_public_keys:request.authorized_public_keys.clone(),account_exists:environment.account_exists()?,service_snapshot:environment.services(&request.policy)?,receipt_identity:expected(&receipt_path)?,rollback:"All changed existing files are verified in backup_root/installer/<plan UUID>; restore only if current postimage still matches. New files may be removed only if installer-owned postimages match. Never remove the account, backups, Steam data or Wolf state automatically.".into()})
}
fn preview_writes(
    recipes: Vec<Recipe>,
    previous: Option<&InstallReport>,
) -> io::Result<Vec<PlannedWrite>> {
    let mut writes = Vec::new();
    for r in recipes {
        ancestor(&r.path)?;
        let current = expected(&r.path)?;
        if let Some(identity) = &current {
            if identity.uid != r.uid || identity.gid != r.gid {
                return Err(fail("existing destination ownership differs"));
            }
            if identity.sha256 != sha(&r.bytes)
                && !previous.is_some_and(|p| p.installed_files.get(&r.path) == Some(identity))
            {
                return Err(fail("refusing an unrecognized existing destination"));
            }
        }
        writes.push(PlannedWrite {
            destination: r.path,
            sha256: sha(&r.bytes),
            mode: r.mode,
            uid: r.uid,
            gid: r.gid,
            expected: current,
        });
    }
    Ok(writes)
}

fn validate_existing_storage_authority(
    request: &InstallRequest,
    environment: &Environment,
) -> io::Result<()> {
    let existing_policy_path = environment.path(Path::new("/etc/wolf-manager/host-policy.json"));
    let existing_policy = existing_policy_path.as_path();
    if existing_policy.exists() {
        trusted_path(existing_policy, 0, false)?;
        let previous: RootPolicy = serde_json::from_slice(&read(existing_policy)?.0)?;
        if previous.pc_id != request.policy.pc_id {
            return Err(fail(
                "existing PC identity cannot change during installation",
            ));
        }
        let old = serde_json::to_value(&previous)?;
        let new = serde_json::to_value(&request.policy)?;
        for field in [
            "steam_uid",
            "steam_gid",
            "libraries",
            "steam_profiles",
            "wolf_config",
            "compose_file",
            "backup_root",
            "state_root",
        ] {
            if old[field] != new[field] {
                return Err(fail(
                    "storage authority changed; explicit guarded migration is required",
                ));
            }
        }
    }
    Ok(())
}

fn directory(path: &Path, mode: u32) -> io::Result<()> {
    if path.exists() {
        return trusted_path(path, 0, true);
    }
    let parent = path
        .parent()
        .ok_or_else(|| fail("directory has no parent"))?;
    directory(parent, 0o755)?;
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    File::open(parent)?.sync_all()
}
fn create_file(path: &Path, bytes: &[u8], mode: u32, uid: u32, gid: u32) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    f.write_all(bytes)?;
    rustix::fs::fchown(
        &f,
        Some(rustix::fs::Uid::from_raw(uid)),
        Some(rustix::fs::Gid::from_raw(gid)),
    )?;
    f.set_permissions(fs::Permissions::from_mode(mode))?;
    f.sync_all()?;
    File::open(path.parent().unwrap())?.sync_all()
}
// Conservative first-release parser: no conditional policy outside our exact fragment.
// Include paths are bounded, root-trusted and opened without following aliases.
fn ssh_include_matches(pattern: &[u8], value: &[u8]) -> bool {
    let mut row = vec![false; value.len() + 1];
    row[0] = true;
    for c in pattern {
        let mut next = vec![false; value.len() + 1];
        if *c == b'*' {
            next[0] = row[0];
        }
        for i in 1..=value.len() {
            next[i] = if *c == b'*' {
                row[i] || next[i - 1]
            } else {
                row[i - 1] && (*c == b'?' || *c == value[i - 1])
            };
        }
        row = next;
    }
    row[value.len()]
}

struct SshPolicyReader<'a> {
    base: &'a Path,
    seen: std::collections::BTreeSet<PathBuf>,
    total: usize,
}
impl SshPolicyReader<'_> {
    fn visit(&mut self, path: &Path, depth: usize) -> io::Result<()> {
        if depth > 16 || self.seen.len() >= 128 || !self.seen.insert(path.to_owned()) {
            return Err(fail("SSH include cycle or bounds exceeded"));
        }
        trusted_path(path, 0, false)?;
        let file = File::from(rustix::fs::openat2(
            rustix::fs::CWD,
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        )?);
        let mut bytes = Vec::new();
        file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
        self.total += bytes.len();
        if self.total > 1024 * 1024 {
            return Err(fail("SSH configuration exceeds bounded size"));
        }
        if path == Path::new("/etc/ssh/sshd_config.d/90-wolf-manager.conf")
            && bytes == include_bytes!("../../../installer/templates/90-wolf-manager.conf")
        {
            return Ok(());
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| fail("SSH configuration is not UTF-8"))?;
        for line in text.lines() {
            self.inspect_line(line, depth)?;
        }
        Ok(())
    }

    fn inspect_line(&mut self, line: &str, depth: usize) -> io::Result<()> {
        let line = line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            return Ok(());
        }
        let line = line.split('#').next().unwrap().trim();
        let words = line.split_ascii_whitespace().collect::<Vec<_>>();
        let directive = words[0].split('=').next().unwrap();
        if directive.eq_ignore_ascii_case("Match") {
            return Err(fail(
                "pre-existing conditional SSH Match policy requires explicit operator review",
            ));
        }
        if !directive.eq_ignore_ascii_case("Include") {
            return Ok(());
        }
        if words.len() < 2 || words[0].contains('=') {
            return Err(fail("unsupported SSH Include syntax"));
        }
        for token in &words[1..] {
            self.include_token(token, depth)?;
        }
        Ok(())
    }

    fn include_token(&mut self, token: &str, depth: usize) -> io::Result<()> {
        if token.bytes().any(|c| b"\\\"'[]{}".contains(&c)) {
            return Err(fail(
                "complex SSH Include syntax requires explicit operator review",
            ));
        }
        let include = if Path::new(token).is_absolute() {
            PathBuf::from(token)
        } else {
            self.base.join(token)
        };
        let parent = include
            .parent()
            .ok_or_else(|| fail("invalid SSH include"))?;
        if parent.to_string_lossy().contains(['*', '?']) {
            return Err(fail("SSH wildcard directories are unsupported"));
        }
        let name = include
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| fail("invalid SSH include name"))?;
        if name.contains(['*', '?']) {
            for child in selected_ssh_includes(parent, name)? {
                self.visit(&child, depth + 1)?;
            }
        } else {
            match fs::symlink_metadata(&include) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
                Ok(_) => self.visit(&include, depth + 1)?,
            }
        }
        Ok(())
    }
}

fn selected_ssh_includes(parent: &Path, name: &str) -> io::Result<Vec<PathBuf>> {
    if !parent.exists() {
        return Ok(Vec::new());
    }
    trusted_path(parent, 0, true)?;
    let mut selected = Vec::new();
    for (index, entry) in fs::read_dir(parent)?.enumerate() {
        if index >= 1024 {
            return Err(fail("SSH include directory exceeds bounds"));
        }
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name = file_name
            .to_str()
            .ok_or_else(|| fail("non-UTF8 SSH include filename"))?;
        if ssh_include_matches(name.as_bytes(), file_name.as_bytes()) {
            selected.push(entry.path());
        }
    }
    selected.sort();
    Ok(selected)
}

fn validate_ssh_policy_tree(path: &Path, include_base: &Path) -> io::Result<()> {
    SshPolicyReader {
        base: include_base,
        seen: std::collections::BTreeSet::new(),
        total: 0,
    }
    .visit(path, 0)
}
fn bounded_client_environment(environment: &[&str]) -> bool {
    // OpenSSH accumulates repeated AcceptEnv directives, including when the
    // installed drop-in is also appended for prospective validation. Repeated
    // identical sentinels grant no additional client environment variables.
    !environment.is_empty()
        && environment
            .iter()
            .all(|value| *value == "acceptenv WOLF_MANAGER_UNUSED_ENV")
}

fn validate_configs(folder: &Path, recipes: &[Recipe]) -> io::Result<()> {
    validate_ssh_policy_tree(Path::new("/etc/ssh/sshd_config"), Path::new("/etc/ssh"))?;
    let sudo = recipes
        .iter()
        .find(|r| r.path == Path::new("/etc/sudoers.d/wolf-manager"))
        .unwrap();
    let sudo_path = folder.join("sudoers-check");
    create_file(&sudo_path, &sudo.bytes, 0o440, 0, 0)?;
    let visudo = ["/usr/sbin/visudo", "/usr/bin/visudo"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .ok_or_else(|| fail("visudo prerequisite is absent"))?;
    if !Command::new(visudo)
        .args(["-c", "-f"])
        .arg(&sudo_path)
        .env_clear()
        .status()?
        .success()
    {
        return Err(fail("sudoers validation failed before activation"));
    }
    let ssh = recipes
        .iter()
        .find(|r| r.path == Path::new("/etc/ssh/sshd_config.d/90-wolf-manager.conf"))
        .unwrap();
    let mut config = fs::read("/etc/ssh/sshd_config")?;
    config.extend_from_slice(b"\n");
    config.extend_from_slice(&ssh.bytes);
    let ssh_path = folder.join("sshd-check");
    create_file(&ssh_path, &config, 0o600, 0, 0)?;
    let sshd = ["/usr/sbin/sshd", "/usr/bin/sshd"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .ok_or_else(|| fail("sshd prerequisite is absent"))?;
    if !Command::new(sshd)
        .args(["-t", "-f"])
        .arg(&ssh_path)
        .env_clear()
        .status()?
        .success()
    {
        return Err(fail("sshd validation failed before activation"));
    }
    let output = Command::new(sshd)
        .args(["-T", "-f"])
        .arg(&ssh_path)
        .args(["-C", "user=wolf-manager,host=localhost,addr=127.0.0.1"])
        .env_clear()
        .output()?;
    if !output.status.success() {
        return Err(fail("effective SSH account policy could not be evaluated"));
    }
    let effective =
        std::str::from_utf8(&output.stdout).map_err(|_| fail("invalid effective SSH output"))?;
    let normalized: Vec<String> = effective
        .lines()
        .filter_map(|line| {
            line.split_once(' ')
                .map(|(key, value)| format!("{} {}", key.to_ascii_lowercase(), value))
        })
        .collect();
    let environment = normalized
        .iter()
        .map(String::as_str)
        .filter(|line| line.starts_with("acceptenv "))
        .collect::<Vec<_>>();
    if !bounded_client_environment(&environment) {
        return Err(fail("inherited client environment policy is not bounded"));
    }
    if normalized
        .iter()
        .any(|line| line.starts_with("setenv ") && line != "setenv none")
    {
        return Err(fail("inherited server environment policy is not bounded"));
    }
    for expected in [
        "authenticationmethods publickey",
        "authorizedkeyscommand none",
        "trustedusercakeys none",
        "authorizedprincipalscommand none",
        "authorizedprincipalsfile none",
        "passwordauthentication no",
        "kbdinteractiveauthentication no",
        "permittty no",
        "disableforwarding yes",
        "permituserrc no",
        "forcecommand /usr/libexec/wolf-manager/ssh-dispatcher",
        "authorizedkeysfile /etc/ssh/authorized_keys.d/wolf-manager",
    ] {
        if !normalized.iter().any(|line| line == expected) {
            return Err(fail(
                "effective SSH account policy differs from restricted contract",
            ));
        }
    }
    Ok(())
}
pub fn apply(plan: &InstallPlan) -> io::Result<InstallReport> {
    apply_with(plan, &Environment::default())
}
fn apply_with(plan: &InstallPlan, environment: &Environment) -> io::Result<InstallReport> {
    if rustix::process::geteuid().as_raw() != 0 || plan.version != 1 {
        return Err(fail("root authority and plan version required"));
    }
    plan.policy.validate_install_prerequisites()?;
    pending(&plan.policy)?;
    let request = InstallRequest {
        mode: plan.mode.clone(),
        policy: plan.policy.clone(),
        authorized_public_keys: plan.authorized_public_keys.clone(),
        source_binary: plan.source_binary.clone(),
        broker_config_source: plan.broker_config_source.clone(),
        initial_files: plan.initial_files.clone(),
    };
    let admission = if plan.policy.backup_root.join("requests").exists() {
        Some(environment.admission(&plan.policy)?)
    } else {
        None
    };
    let refreshed = preflight_with(&request, environment)?;
    validate_refreshed_plan(plan, &refreshed)?;
    for directory in &plan.proposed_directories {
        create_planned_directory(directory)?;
    }
    let _late_admission = if admission.is_none() {
        Some(environment.admission(&plan.policy)?)
    } else {
        None
    };
    let lock_path = plan.policy.state_root.join("installer.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(lock_path)?;
    lock.lock_exclusive()?;
    let metadata = lock.metadata()?;
    if metadata.uid() != 0 || metadata.nlink() != 1 || metadata.mode() & 0o077 != 0 {
        return Err(fail("unsafe installer lock"));
    }
    let folder = plan
        .policy
        .backup_root
        .join("installer")
        .join(plan.id.to_string());
    directory(&folder, 0o700)?;
    let recipes = installation_recipes(&request, environment)?;
    validate_recipe_consistency(plan, &recipes)?;
    environment.validate_configs(&folder, &recipes)?;

    backup_installation_files(plan, &folder)?;
    create_file(
        &folder.join("plan.json"),
        &serde_json::to_vec_pretty(plan)?,
        0o600,
        0,
        0,
    )?;
    create_restricted_account(plan, environment)?;
    let mut changed = Vec::new();
    for (r, write) in recipes.iter().zip(&plan.proposed_writes) {
        environment.before_write(changed.len())?;
        if apply_recipe(plan, r, write)? {
            changed.push(r.path.clone());
        }
    }
    let report = InstallReport {
        version: 1,
        id: plan.id,
        changed_files: changed,
        installed_files: recipes
            .iter()
            .map(|r| Ok((r.path.clone(), read(&r.path)?.1)))
            .collect::<io::Result<_>>()?,
        verified_backup_directory: folder.clone(),
        activation_required: true,
        retained_files: Vec::new(),
        recovery_instructions: plan.rollback.clone(),
    };
    create_file(
        &folder.join("report.json"),
        &serde_json::to_vec_pretty(&report)?,
        0o600,
        0,
        0,
    )?;
    store_install_receipt(plan, &report, &folder)?;
    // No automatic service start/restart: operator reviews the verified plan before cutover.
    Ok(report)
}

fn validate_recipe_consistency(plan: &InstallPlan, recipes: &[Recipe]) -> io::Result<()> {
    if recipes.len() != plan.proposed_writes.len()
        || recipes.iter().zip(&plan.proposed_writes).any(|(r, w)| {
            r.path != w.destination
                || sha(&r.bytes) != w.sha256
                || r.mode != w.mode
                || r.uid != w.uid
                || r.gid != w.gid
        })
    {
        return Err(fail("recipe changed before effects"));
    }
    Ok(())
}

fn validate_refreshed_plan(plan: &InstallPlan, refreshed: &InstallPlan) -> io::Result<()> {
    if refreshed.proposed_writes != plan.proposed_writes
        || refreshed.proposed_directories != plan.proposed_directories
        || refreshed.service_snapshot != plan.service_snapshot
        || refreshed.source_identity != plan.source_identity
        || refreshed.broker_identity != plan.broker_identity
        || refreshed.storage_mapping != plan.storage_mapping
        || refreshed.receipt_identity != plan.receipt_identity
        || refreshed.account_exists != plan.account_exists
    {
        return Err(fail(
            "installer inputs changed since preview; no writes permitted",
        ));
    }
    Ok(())
}

fn store_install_receipt(
    plan: &InstallPlan,
    report: &InstallReport,
    folder: &Path,
) -> io::Result<()> {
    let receipt = plan.policy.state_root.join("installation.json");
    let previous = expected(&receipt)?;
    if let Some(identity) = &previous {
        let bytes = read(&receipt)?.0;
        create_file(&folder.join("receipt-preimage"), &bytes, 0o600, 0, 0)?;
        if sha(&read(&folder.join("receipt-preimage"))?.0) != identity.sha256 {
            return Err(fail("receipt backup failed"));
        }
    }
    let stage = plan
        .policy
        .state_root
        .join(format!(".installation-{}.new", plan.id));
    create_file(&stage, &serde_json::to_vec_pretty(&report)?, 0o600, 0, 0)?;
    if expected(&receipt)? != previous {
        return Err(fail("installation receipt drift"));
    }
    if previous.is_some() {
        let displaced = plan
            .policy
            .state_root
            .join(format!(".installation-{}.previous", plan.id));
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            &receipt,
            rustix::fs::CWD,
            &displaced,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
    }
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        &stage,
        rustix::fs::CWD,
        &receipt,
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    File::open(&plan.policy.state_root)?.sync_all()?;
    Ok(())
}

fn apply_recipe(plan: &InstallPlan, r: &Recipe, write: &PlannedWrite) -> io::Result<bool> {
    if write
        .expected
        .as_ref()
        .is_some_and(|i| i.sha256 == write.sha256 && i.mode == write.mode)
    {
        return Ok(false);
    }
    if expected(&r.path)? != write.expected {
        return Err(fail(
            "destination drift; verified backups retained for guarded rollback",
        ));
    }
    directory(r.path.parent().unwrap(), 0o755)?;
    let stage = r
        .path
        .parent()
        .unwrap()
        .join(format!(".wolf-manager-{}.new", Uuid::new_v4()));
    create_file(&stage, &r.bytes, r.mode, r.uid, r.gid)?;
    // Preserve the existing inode until successful verification; never overwrite a racing writer.
    if let Some(identity) = &write.expected {
        let old = r
            .path
            .parent()
            .unwrap()
            .join(format!(".wolf-manager-{}.previous", plan.id));
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            &r.path,
            rustix::fs::CWD,
            &old,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        if read(&old)?.1 != *identity {
            let _ = rustix::fs::renameat_with(
                rustix::fs::CWD,
                &old,
                rustix::fs::CWD,
                &r.path,
                rustix::fs::RenameFlags::NOREPLACE,
            );
            return Err(fail("replacement raced; displaced original retained"));
        }
    }
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        &stage,
        rustix::fs::CWD,
        &r.path,
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    File::open(r.path.parent().unwrap())?.sync_all()?;
    let (_, installed) = read(&r.path)?;
    if installed.sha256 != write.sha256
        || installed.mode != write.mode
        || installed.uid != write.uid
        || installed.gid != write.gid
    {
        return Err(fail(
            "installed postimage verification failed; backups retained",
        ));
    }
    Ok(true)
}

fn backup_installation_files(plan: &InstallPlan, folder: &Path) -> io::Result<()> {
    for (index, write) in plan.proposed_writes.iter().enumerate() {
        if expected(&write.destination)? != write.expected {
            return Err(fail("destination drift before backup"));
        }
        if let Some(identity) = &write.expected {
            let (bytes, now) = read(&write.destination)?;
            if &now != identity {
                return Err(fail("destination changed during backup"));
            }
            let backup = folder.join(format!("preimage-{index}"));
            create_file(&backup, &bytes, 0o600, 0, 0)?;
            if read(&backup)?.1.sha256 != identity.sha256 {
                return Err(fail("backup verification failed"));
            }
        }
    }
    Ok(())
}

fn create_restricted_account(plan: &InstallPlan, environment: &Environment) -> io::Result<()> {
    // Account creation is deliberately last among prerequisites, before policy installation.
    if !plan.account_exists && !environment.fixture() {
        let useradd = ["/usr/sbin/useradd", "/usr/bin/useradd"]
            .into_iter()
            .find(|p| Path::new(p).exists())
            .ok_or_else(|| fail("useradd prerequisite is absent"))?;
        if !Command::new(useradd)
            .args([
                "--system",
                "--user-group",
                "--no-create-home",
                "--home-dir",
                "/nonexistent",
                "--shell",
                "/bin/sh",
                "--password",
                "!",
                "wolf-manager",
            ])
            .env_clear()
            .status()?
            .success()
        {
            return Err(fail("restricted account creation failed"));
        }
        if !account_exists()? {
            return Err(fail("new account does not satisfy restricted policy"));
        }
    }
    Ok(())
}

// Root-only disposable filesystem fixtures are added with the guarded core below.

#[derive(Default)]
struct Environment {
    #[cfg(test)]
    prefix: Option<PathBuf>,
    #[cfg(test)]
    fail_after: Option<usize>,
}
impl Environment {
    fn admission(&self, policy: &RootPolicy) -> io::Result<File> {
        let directory_path = policy.backup_root.join("requests");
        directory(&directory_path, 0o700)?;
        let path = directory_path.join(".admission.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(path)?;
        let m = file.metadata()?;
        if m.uid() != 0 || m.nlink() != 1 || m.mode() & 0o077 != 0 {
            return Err(fail("unsafe RPC admission lock"));
        }
        file.lock_exclusive()?;
        Ok(file)
    }
    fn fixture(&self) -> bool {
        #[cfg(test)]
        {
            self.prefix.is_some()
        }
        #[cfg(not(test))]
        {
            false
        }
    }
    fn path(&self, path: &Path) -> PathBuf {
        #[cfg(test)]
        if let Some(prefix) = &self.prefix {
            return prefix.join(path.strip_prefix("/").unwrap());
        }
        path.to_owned()
    }
    fn account_exists(&self) -> io::Result<bool> {
        if self.fixture() {
            Ok(true)
        } else {
            account_exists()
        }
    }
    fn validate_configs(&self, folder: &Path, recipes: &[Recipe]) -> io::Result<()> {
        if self.fixture() {
            return Ok(());
        }
        validate_configs(folder, recipes)
    }
    fn before_write(&self, _completed: usize) -> io::Result<()> {
        #[cfg(test)]
        if self.fail_after.is_some_and(|limit| _completed >= limit) {
            return Err(fail("injected failure before next write"));
        }
        Ok(())
    }
    fn prepare_rollback(&self, _plan: &InstallPlan, _folder: &Path) -> io::Result<()> {
        if _folder.join("activation.json").exists() && !self.fixture() {
            if self.services(&_plan.policy)?.catalog.active {
                checked_systemctl(&["stop", "wolf-manager-catalog.service"])?;
            }
            if self.services(&_plan.policy)?.wolf.active {
                checked_systemctl(&["stop", &_plan.policy.service_unit])?;
            }
        }
        Ok(())
    }
    fn finish_rollback(&self, _plan: &InstallPlan, _folder: &Path) -> io::Result<()> {
        if !_folder.join("activation.json").exists() {
            return Ok(());
        }
        if self.fixture() {
            return self.store_services(&_plan.service_snapshot);
        }
        checked_systemctl(&["daemon-reload"])?;
        restore_state(&_plan.policy.service_unit, &_plan.service_snapshot.wolf)?;
        restore_state(
            "wolf-manager-catalog.service",
            &_plan.service_snapshot.catalog,
        )?;
        if _plan.service_snapshot.ssh.active {
            checked_systemctl(&["try-reload-or-restart", &_plan.service_snapshot.ssh_unit])?;
        }
        Ok(())
    }
    fn services(&self, policy: &RootPolicy) -> io::Result<ServiceSnapshot> {
        #[cfg(test)]
        if let Some(prefix) = &self.prefix {
            let path = prefix.join(".service-state.json");
            if path.exists() {
                return Ok(serde_json::from_slice(&read(&path)?.0)?);
            }
            return Ok(ServiceSnapshot {
                ssh_unit: "sshd.service".into(),
                ..ServiceSnapshot::default()
            });
        }
        capture_services(policy)
    }
    fn store_services(&self, _snapshot: &ServiceSnapshot) -> io::Result<()> {
        #[cfg(test)]
        if let Some(prefix) = &self.prefix {
            let path = prefix.join(".service-state.json");
            let bytes = serde_json::to_vec(_snapshot)?;
            fs::write(&path, bytes)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            File::open(&path)?.sync_all()?;
            File::open(prefix)?.sync_all()?;
        }
        Ok(())
    }
    fn activate_services(&self, plan: &InstallPlan, options: &ActivationOptions) -> io::Result<()> {
        if self.fixture() {
            let mut state = self.services(&plan.policy)?;
            if options.start_wolf {
                state.wolf.active = true;
            }
            if options.start_catalog {
                state.catalog.active = true;
            }
            if options.enable_on_boot {
                state.wolf.enabled = true;
                if plan.policy.broker_secret_file.is_some() {
                    state.catalog.enabled = true;
                }
            }
            return self.store_services(&state);
        }
        checked_systemctl(&["daemon-reload"])?;
        if plan.service_snapshot.ssh.active {
            checked_systemctl(&["try-reload-or-restart", &plan.service_snapshot.ssh_unit])?;
        }
        enable_requested_services(plan, options)?;
        if options.start_catalog {
            checked_systemctl(&["start", "wolf-manager-catalog.service"])?;
        }
        if options.start_wolf {
            checked_systemctl(&["start", &plan.policy.service_unit])?;
        }
        Ok(())
    }
}
fn enable_requested_services(plan: &InstallPlan, options: &ActivationOptions) -> io::Result<()> {
    if options.enable_on_boot {
        checked_systemctl(&["enable", &plan.policy.service_unit])?;
        if plan.policy.broker_secret_file.is_some() {
            checked_systemctl(&["enable", "wolf-manager-catalog.service"])?;
        }
    }
    Ok(())
}

fn directory_identity(path: &Path) -> io::Result<DirectoryIdentity> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.file_type().is_symlink() || m.mode() & 0o022 != 0 {
        return Err(fail("unsafe directory identity"));
    }
    Ok(DirectoryIdentity {
        device: m.dev(),
        inode: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode() & 0o777,
    })
}
fn planned_directories(
    policy: &RootPolicy,
    writes: &[PlannedWrite],
) -> io::Result<Vec<PlannedDirectory>> {
    let mut desired = std::collections::BTreeMap::new();
    for write in writes {
        let mut path = write.destination.parent().unwrap().to_owned();
        while !path.exists() {
            desired.entry(path.clone()).or_insert((0, 0, 0o755));
            path = path
                .parent()
                .ok_or_else(|| fail("missing directory root"))?
                .to_owned();
        }
    }
    let requests = policy.backup_root.join("requests");
    for (path, uid, gid, mode) in [
        (&requests, 0, 0, 0o700),
        (&policy.backup_root, 0, 0, 0o700),
        (&policy.state_root, 0, 0, 0o700),
        (
            &policy.catalog_state_directory,
            policy.steam_uid,
            policy.steam_gid,
            0o700,
        ),
    ] {
        desired.insert(path.clone(), (uid, gid, mode));
        let mut parent = path.parent().unwrap();
        while !parent.exists() {
            desired
                .entry(parent.to_owned())
                .or_insert((uid, gid, 0o755));
            parent = parent
                .parent()
                .ok_or_else(|| fail("missing grant ancestor"))?;
        }
    }
    let mut dirs = desired
        .into_iter()
        .map(|(path, (uid, gid, mode))| planned_directory(path, uid, gid, mode))
        .collect::<io::Result<Vec<_>>>()?;
    dirs.sort_by_key(|d| d.path.components().count());
    Ok(dirs)
}
fn planned_directory(path: PathBuf, uid: u32, gid: u32, mode: u32) -> io::Result<PlannedDirectory> {
    let expected = if path.exists() {
        Some(directory_identity(&path)?)
    } else {
        None
    };
    if expected
        .as_ref()
        .is_some_and(|i| i.uid != uid || i.gid != gid || (mode == 0o700 && i.mode & 0o077 != 0))
    {
        return Err(fail("existing store ownership or privacy mismatch"));
    }
    let mut anchor = path.parent().unwrap();
    while !anchor.exists() {
        anchor = anchor.parent().ok_or_else(|| fail("missing anchor"))?;
    }
    trusted_path(anchor, uid, true)?;
    let anchor_identity = directory_identity(anchor)?;
    let anchor = anchor.to_owned();
    Ok(PlannedDirectory {
        path,
        uid,
        gid,
        mode,
        expected,
        anchor,
        anchor_identity,
    })
}

fn create_planned_directory(directory: &PlannedDirectory) -> io::Result<()> {
    if directory_identity(&directory.anchor)? != directory.anchor_identity {
        return Err(fail("directory anchor changed"));
    }
    if let Some(identity) = &directory.expected {
        if directory_identity(&directory.path)? != *identity {
            return Err(fail("existing directory drift"));
        }
        return Ok(());
    }
    let parent = directory
        .path
        .parent()
        .ok_or_else(|| fail("missing directory parent"))?;
    let fd = File::from(rustix::fs::openat2(
        rustix::fs::CWD,
        parent,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    )?);
    let name = directory
        .path
        .file_name()
        .ok_or_else(|| fail("missing directory name"))?;
    rustix::fs::mkdirat(&fd, name, rustix::fs::Mode::from_raw_mode(0o700))?;
    let created = File::from(rustix::fs::openat2(
        &fd,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::BENEATH
            | rustix::fs::ResolveFlags::NO_SYMLINKS
            | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    )?);
    rustix::fs::fchown(
        &created,
        Some(rustix::fs::Uid::from_raw(directory.uid)),
        Some(rustix::fs::Gid::from_raw(directory.gid)),
    )?;
    created.set_permissions(fs::Permissions::from_mode(directory.mode))?;
    created.sync_all()?;
    fd.sync_all()
}
fn validate_compose_initial(bytes: &[u8], policy: &RootPolicy) -> io::Result<()> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| fail("bootstrap Compose must be closed JSON YAML subset"))?;
    let root = value
        .as_object()
        .ok_or_else(|| fail("invalid Compose object"))?;
    if root.len() != 1 || !root.contains_key("services") {
        return Err(fail("unknown Compose top-level field"));
    }
    let services = value["services"]
        .as_object()
        .ok_or_else(|| fail("invalid Compose services"))?;
    if services.len() != 1 || !services.contains_key("wolf") {
        return Err(fail("only configured Wolf service is allowed"));
    }
    let wolf = services["wolf"]
        .as_object()
        .ok_or_else(|| fail("invalid Wolf Compose service"))?;
    for field in wolf.keys() {
        if ![
            "image",
            "container_name",
            "pull_policy",
            "restart",
            "network_mode",
            "privileged",
            "volumes",
            "devices",
            "device_cgroup_rules",
            "environment",
            "group_add",
            "security_opt",
            "user",
            "working_dir",
        ]
        .contains(&field.as_str())
        {
            return Err(fail("unknown bootstrap Compose service field"));
        }
    }
    if wolf.get("image").and_then(|v| v.as_str()) != Some(&policy.image_ref)
        || wolf.get("container_name").and_then(|v| v.as_str()) != Some(&policy.container_name)
        || wolf.get("pull_policy").and_then(|v| v.as_str()) != Some("never")
    {
        return Err(fail("Compose policy identity mismatch"));
    }
    Ok(())
}
fn systemctl(args: &[&str]) -> io::Result<std::process::Output> {
    trusted_path(Path::new("/usr/bin/systemctl"), 0, false)?;
    Command::new("/usr/bin/systemctl")
        .args(args)
        .env_clear()
        .output()
}
fn checked_systemctl(args: &[&str]) -> io::Result<()> {
    let output = systemctl(args)?;
    if !output.status.success() {
        return Err(fail(
            "fixed service action failed; installer recovery remains pending",
        ));
    }
    Ok(())
}
fn restore_state(unit: &str, state: &ServiceState) -> io::Result<()> {
    checked_systemctl(&[if state.enabled { "enable" } else { "disable" }, unit])?;
    checked_systemctl(&[if state.active { "start" } else { "stop" }, unit])
}
fn capture_state(unit: &str) -> io::Result<ServiceState> {
    let active = systemctl(&["is-active", "--quiet", unit])?.status.success();
    let enabled = systemctl(&["is-enabled", unit])?;
    let text = String::from_utf8_lossy(&enabled.stdout);
    if text.trim() == "masked" {
        return Err(fail("masked units require explicit operator recovery"));
    }
    Ok(ServiceState {
        active,
        enabled: enabled.status.success() && text.trim().starts_with("enabled"),
    })
}
fn capture_services(policy: &RootPolicy) -> io::Result<ServiceSnapshot> {
    let mut ssh_unit = None;
    for candidate in ["sshd.service", "ssh.service"] {
        let state = systemctl(&["show", "--property=LoadState", "--value", candidate])?;
        if state.status.success() && String::from_utf8_lossy(&state.stdout).trim() == "loaded" {
            ssh_unit = Some(candidate);
            break;
        }
    }
    let ssh_unit = ssh_unit.ok_or_else(|| fail("no supported SSH service found"))?;
    Ok(ServiceSnapshot {
        wolf: capture_state(&policy.service_unit)?,
        catalog: capture_state("wolf-manager-catalog.service")?,
        ssh_unit: ssh_unit.into(),
        ssh: capture_state(ssh_unit)?,
    })
}

fn saved_plan(plan: &InstallPlan) -> io::Result<PathBuf> {
    if rustix::process::geteuid().as_raw() != 0 || plan.version != 1 {
        return Err(fail("root and supported plan version required"));
    }
    plan.policy.validate_structure()?;
    trusted_path(&plan.policy.backup_root, 0, true)?;
    let folder = plan
        .policy
        .backup_root
        .join("installer")
        .join(plan.id.to_string());
    trusted_path(&folder, 0, true)?;
    let (bytes, identity) = read(&folder.join("plan.json"))?;
    if identity.uid != 0 || identity.mode != 0o600 {
        return Err(fail("unsafe saved installation plan"));
    }
    let original: InstallPlan = serde_json::from_slice(&bytes)?;
    if sha(&serde_json::to_vec(&original)?) != sha(&serde_json::to_vec(plan)?) {
        return Err(fail("supplied plan differs from protected saved plan"));
    }
    Ok(folder)
}
fn matches_identity(current: &FileIdentity, expected: &FileIdentity) -> bool {
    current.sha256 == expected.sha256
        && current.uid == expected.uid
        && current.gid == expected.gid
        && current.mode == expected.mode
}
fn installer_lock(policy: &RootPolicy) -> io::Result<File> {
    trusted_path(&policy.state_root, 0, true)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(policy.state_root.join("installer.lock"))?;
    let metadata = lock.metadata()?;
    if metadata.uid() != 0 || metadata.nlink() != 1 || metadata.mode() & 0o077 != 0 {
        return Err(fail("unsafe installer lock"));
    }
    lock.lock_exclusive()?;
    Ok(lock)
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationOptions {
    pub start_wolf: bool,
    pub start_catalog: bool,
    pub enable_on_boot: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationReport {
    pub version: u8,
    pub id: Uuid,
    pub requested: ActivationOptions,
    pub phase: String,
    pub before: ServiceSnapshot,
    pub after: Option<ServiceSnapshot>,
}
pub fn activate(plan: &InstallPlan, options: ActivationOptions) -> io::Result<ActivationReport> {
    activate_with(plan, options, &Environment::default())
}
fn activate_with(
    plan: &InstallPlan,
    options: ActivationOptions,
    environment: &Environment,
) -> io::Result<ActivationReport> {
    let folder = saved_plan(plan)?;
    let _admission = environment.admission(&plan.policy)?;
    let _lock = installer_lock(&plan.policy)?;
    plan.policy.validate()?;
    pending(&plan.policy)?;
    if !["sshd.service", "ssh.service"].contains(&plan.service_snapshot.ssh_unit.as_str()) {
        return Err(fail("invalid captured SSH unit"));
    }
    if options.start_catalog && plan.policy.broker_secret_file.is_none() {
        return Err(fail(
            "catalog activation requires configured private broker credentials",
        ));
    }
    let report: InstallReport =
        serde_json::from_slice(&read(&plan.policy.state_root.join("installation.json"))?.0)?;
    if report.id != plan.id || report.version != 1 {
        return Err(fail("activation requires this completed installation"));
    }
    let config = plan
        .policy
        .wolf_config
        .root
        .join(&plan.policy.wolf_config.relative_path);
    for (path, identity) in &report.installed_files {
        if path != &config {
            identity.verify(path)?;
        }
    }
    let before = environment.services(&plan.policy)?;
    if before != plan.service_snapshot {
        return Err(fail(
            "service state changed since preview; activation refused",
        ));
    }
    let mut templates = render_privilege_templates(&plan.authorized_public_keys)?
        .into_iter()
        .map(|(p, bytes, mode)| Recipe {
            path: environment.path(Path::new(&p)),
            bytes,
            mode,
            uid: 0,
            gid: 0,
        })
        .collect::<Vec<_>>();
    for recipe in &mut templates {
        recipe.bytes = read(&recipe.path)?.0;
    }
    let checks = folder.join(format!("activation-check-{}", Uuid::new_v4()));
    directory(&checks, 0o700)?;
    environment.validate_configs(&checks, &templates)?;
    let mut record = ActivationReport {
        version: 1,
        id: plan.id,
        requested: options.clone(),
        phase: "started".into(),
        before,
        after: None,
    };
    create_file(
        &folder.join("activation.json"),
        &serde_json::to_vec_pretty(&record)?,
        0o600,
        0,
        0,
    )?;
    environment.activate_services(plan, &options)?;
    record.phase = "completed".into();
    record.after = Some(environment.services(&plan.policy)?);
    create_file(
        &folder.join("activation-completed.json"),
        &serde_json::to_vec_pretty(&record)?,
        0o600,
        0,
        0,
    )?;
    Ok(record)
}
pub fn rollback(plan: &InstallPlan) -> io::Result<InstallReport> {
    rollback_with(plan, &Environment::default())
}
fn rollback_with(plan: &InstallPlan, environment: &Environment) -> io::Result<InstallReport> {
    let folder = saved_plan(plan)?;
    let _admission = environment.admission(&plan.policy)?;
    let _lock = installer_lock(&plan.policy)?;
    let receipt = plan.policy.state_root.join("installation.json");
    let receipt_current = expected(&receipt)?;
    let receipt_is_new = if receipt_current.is_some() {
        let report: InstallReport = serde_json::from_slice(&read(&receipt)?.0)?;
        report.id == plan.id
    } else {
        false
    };
    if !receipt_is_new && receipt_current != plan.receipt_identity {
        return Err(fail("another install or receipt drift blocks rollback"));
    }
    let RollbackAdmission { work, retained } = collect_rollback_work(plan, &folder)?;
    if receipt_is_new && let Some(identity) = &plan.receipt_identity {
        let backup = read(&folder.join("receipt-preimage"))?.1;
        if backup.sha256 != identity.sha256 {
            return Err(fail("previous installation receipt backup is corrupt"));
        }
    }
    environment.prepare_rollback(plan, &folder)?;
    let mut changed = Vec::new();
    for RollbackWrite {
        index,
        write,
        current,
    } in work
    {
        restore_rollback_write(plan, &folder, index, write, &current)?;
        changed.push(write.destination.clone());
        File::open(write.destination.parent().unwrap())?.sync_all()?;
    }
    if receipt_is_new {
        restore_previous_receipt(plan, &folder, &receipt, &receipt_current)?;
    }
    environment.finish_rollback(plan, &folder)?;
    let report=InstallReport{version:1,id:plan.id,changed_files:changed,installed_files:plan.proposed_writes.iter().filter_map(|w|expected(&w.destination).transpose().map(|result|result.map(|i|(w.destination.clone(),i)))).collect::<io::Result<_>>()?,verified_backup_directory:folder.clone(),activation_required:false,retained_files:retained,recovery_instructions:"Original verified metadata restored. Created Wolf configuration/Compose, broker secrets, directories, account and every backup remain preserved; review retained_files before another install. No Steam data removed.".into()};
    create_file(
        &folder.join(format!("rollback-report-{}.json", Uuid::new_v4())),
        &serde_json::to_vec_pretty(&report)?,
        0o600,
        0,
        0,
    )?;
    Ok(report)
}

fn restore_previous_receipt(
    plan: &InstallPlan,
    folder: &Path,
    receipt: &Path,
    receipt_current: &Option<FileIdentity>,
) -> io::Result<()> {
    let preserved = plan.policy.state_root.join(format!(
        ".installation-rollback-{}.postimage",
        Uuid::new_v4()
    ));
    if expected(receipt)?.as_ref() != receipt_current.as_ref() {
        return Err(fail("receipt changed during rollback"));
    }
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        receipt,
        rustix::fs::CWD,
        &preserved,
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    if let Some(identity) = &plan.receipt_identity {
        let displaced = plan
            .policy
            .state_root
            .join(format!(".installation-{}.previous", plan.id));
        if expected(&displaced)?.as_ref() == Some(identity) {
            rustix::fs::renameat_with(
                rustix::fs::CWD,
                &displaced,
                rustix::fs::CWD,
                receipt,
                rustix::fs::RenameFlags::NOREPLACE,
            )?;
        } else {
            create_file(
                receipt,
                &read(&folder.join("receipt-preimage"))?.0,
                identity.mode,
                identity.uid,
                identity.gid,
            )?;
        }
    }
    File::open(&plan.policy.state_root)?.sync_all()?;
    Ok(())
}

fn restore_rollback_write(
    plan: &InstallPlan,
    folder: &Path,
    index: usize,
    write: &PlannedWrite,
    current: &Option<FileIdentity>,
) -> io::Result<()> {
    if expected(&write.destination)?.as_ref() != current.as_ref() {
        return Err(fail("rollback destination changed after preview"));
    }
    let parent = write.destination.parent().unwrap();
    trusted_path(parent, 0, true)?;
    if current.is_some() {
        let preserved = parent.join(format!(
            ".wolf-manager-rollback-{}-{index}.postimage",
            Uuid::new_v4()
        ));
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            &write.destination,
            rustix::fs::CWD,
            &preserved,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        if expected(&preserved)?.as_ref() != current.as_ref() {
            let _ = rustix::fs::renameat_with(
                rustix::fs::CWD,
                &preserved,
                rustix::fs::CWD,
                &write.destination,
                rustix::fs::RenameFlags::NOREPLACE,
            );
            return Err(fail("rollback raced with another writer; bytes retained"));
        }
        File::open(parent)?.sync_all()?;
    }
    if let Some(original) = &write.expected {
        let displaced = parent.join(format!(".wolf-manager-{}.previous", plan.id));
        if expected(&displaced)?.as_ref() == Some(original) {
            rustix::fs::renameat_with(
                rustix::fs::CWD,
                &displaced,
                rustix::fs::CWD,
                &write.destination,
                rustix::fs::RenameFlags::NOREPLACE,
            )?;
        } else {
            let bytes = read(&folder.join(format!("preimage-{index}")))?.0;
            create_file(
                &write.destination,
                &bytes,
                original.mode,
                original.uid,
                original.gid,
            )?;
        }
        if !matches_identity(&read(&write.destination)?.1, original) {
            return Err(fail("restored preimage verification failed"));
        }
    }
    Ok(())
}

fn rollback_write_needed(
    plan: &InstallPlan,
    folder: &Path,
    index: usize,
    write: &PlannedWrite,
    current: &Option<FileIdentity>,
) -> io::Result<bool> {
    if let Some(identity) = &write.expected {
        let (_, backup) = read(&folder.join(format!("preimage-{index}")))?;
        if backup.sha256 != identity.sha256 || backup.uid != 0 || backup.mode != 0o600 {
            return Err(fail("rollback backup is corrupt or untrusted"));
        }
        if current
            .as_ref()
            .is_some_and(|now| matches_identity(now, identity))
        {
            return Ok(false);
        }
    } else if current.is_none() {
        return Ok(false);
    }
    if current.as_ref().is_some_and(|now| {
        now.sha256 != write.sha256
            || now.uid != write.uid
            || now.gid != write.gid
            || now.mode != write.mode
    }) {
        return Err(fail("postimage drift blocks all rollback effects"));
    }
    if current.is_none() && write.expected.is_some() {
        let displaced = write
            .destination
            .parent()
            .unwrap()
            .join(format!(".wolf-manager-{}.previous", plan.id));
        if expected(&displaced)?.as_ref() != write.expected.as_ref() {
            return Err(fail(
                "missing destination is not a verified interrupted replacement",
            ));
        }
    }
    Ok(true)
}

struct RollbackWrite<'a> {
    index: usize,
    write: &'a PlannedWrite,
    current: Option<FileIdentity>,
}
struct RollbackAdmission<'a> {
    work: Vec<RollbackWrite<'a>>,
    retained: Vec<PathBuf>,
}
fn collect_rollback_work<'a>(
    plan: &'a InstallPlan,
    folder: &Path,
) -> io::Result<RollbackAdmission<'a>> {
    let mut work = Vec::new();
    let mut retained = Vec::new();
    for (index, write) in plan.proposed_writes.iter().enumerate() {
        if plan
            .initial_files
            .iter()
            .any(|f| f.path == write.destination)
            || plan.policy.broker_secret_file.as_ref() == Some(&write.destination)
        {
            if write.destination.exists() {
                retained.push(write.destination.clone());
            }
            continue;
        }
        let current = expected(&write.destination)?;
        if !rollback_write_needed(plan, folder, index, write, &current)? {
            continue;
        }
        work.push(RollbackWrite {
            index,
            write,
            current,
        });
    }
    Ok(RollbackAdmission { work, retained })
}

#[cfg(test)]
mod root_fixture_tests {
    #[test]
    fn repeated_effective_acceptenv_remains_bounded() {
        let sentinel = "acceptenv WOLF_MANAGER_UNUSED_ENV";
        assert!(super::bounded_client_environment(&[sentinel]));
        assert!(super::bounded_client_environment(&[sentinel, sentinel]));
        for invalid in [
            vec![],
            vec!["acceptenv *"],
            vec![sentinel, "acceptenv LANG"],
            vec!["acceptenv WOLF_MANAGER_UNUSED_ENV LD_PRELOAD"],
        ] {
            assert!(!super::bounded_client_environment(&invalid));
        }
    }

    use super::*;
    struct RootFixture {
        directory: tempfile::TempDir,
        request: InstallRequest,
        environment: Environment,
    }
    impl RootFixture {
        fn new() -> Self {
            let directory = tempfile::Builder::new()
                .prefix("wolf-installer-")
                .tempdir_in("/root")
                .unwrap();
            let base = directory.path();
            for path in [
                "profile/config",
                "profile/steamapps/common",
                "profile/userdata",
                "wolf",
                "bin",
            ] {
                fs::create_dir_all(base.join(path)).unwrap();
            }
            for path in [
                "profile/config/config.vdf",
                "profile/steamapps/libraryfolders.vdf",
            ] {
                let path = base.join(path);
                fs::write(&path, b"\"Steam\" {}\n").unwrap();
                let f = File::open(&path).unwrap();
                rustix::fs::fchown(
                    &f,
                    Some(rustix::fs::Uid::from_raw(1000)),
                    Some(rustix::fs::Gid::from_raw(1000)),
                )
                .unwrap();
            }
            fs::write(
                base.join("wolf/config.toml"),
                b"config_version=7\nuuid=\"preserve\"\n",
            )
            .unwrap();
            fs::write(base.join("wolf/compose.json"), b"{}\n").unwrap();
            fs::write(base.join("bin/steam"), b"placeholder process identity").unwrap();
            let mut binary = vec![0u8; 128];
            binary[..4].copy_from_slice(b"\x7fELF");
            binary[4] = 2;
            binary[5] = 1;
            binary[6] = 1;
            binary[16..18].copy_from_slice(&2u16.to_le_bytes());
            binary[18..20].copy_from_slice(&62u16.to_le_bytes());
            binary[32..40].copy_from_slice(&64u64.to_le_bytes());
            binary[54..56].copy_from_slice(&56u16.to_le_bytes());
            binary[56..58].copy_from_slice(&1u16.to_le_bytes());
            binary[64..68].copy_from_slice(&1u32.to_le_bytes());
            fs::write(base.join("source-binary"), binary).unwrap();
            let policy:RootPolicy=serde_json::from_value(serde_json::json!({"version":1,"pc_id":"fixture","steam_uid":1000,"steam_gid":1000,"libraries":[{"library_id":"primary","steamapps_path":base.join("profile/steamapps"),"container_paths":["/home/steam/Steam/steamapps"]}],"steam_profiles":[{"root":base.join("profile"),"config_vdf":"config/config.vdf","libraryfolders_vdf":["steamapps/libraryfolders.vdf"],"userdata_directory":"userdata","container_userdata_paths":["/home/steam/Steam/userdata"]}],"wolf_config":{"root":base.join("wolf"),"relative_path":"config.toml","uid":0,"gid":0},"compose_file":base.join("wolf/compose.json"),"service_unit":"wolf.service","container_name":"wolf","image_ref":"ghcr.io/games-on-whales/wolf:stable","backup_root":base.join("backups"),"state_root":base.join("state"),"catalog_state_directory":base.join("catalog"),"broker_secret_file":null,"pull_on_start":true,"pull_timeout_seconds":60,"proton":null,"steam_executables":[base.join("bin/steam")],"steam_runner":{"type":"docker","image":"example.invalid/steam:stable"}})).unwrap();
            let request=InstallRequest{mode:InstallMode::Install,policy,authorized_public_keys:vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA fixture".into()],source_binary:base.join("source-binary"),broker_config_source:None,initial_files:Vec::new()};
            let environment = Environment {
                prefix: Some(base.join("system")),
                fail_after: None,
            };
            Self {
                directory,
                request,
                environment,
            }
        }
    }
    #[test]
    #[ignore = "requires disposable root container; never execute on household host"]
    fn prepared_sources_allow_missing_private_stores_without_writes() {
        assert_eq!(
            rustix::process::geteuid().as_raw(),
            0,
            "disposable root container required"
        );
        let fixture = RootFixture::new();
        fixture
            .request
            .policy
            .validate_install_prerequisites()
            .unwrap();
        assert!(!fixture.request.policy.backup_root.exists());
        assert!(!fixture.request.policy.state_root.exists());
        assert!(fixture.directory.path().exists());
    }
    #[test]
    #[ignore = "requires disposable root container; never execute on household host"]
    fn root_apply_is_idempotent_and_preserves_original_wolf_bytes() {
        assert_eq!(
            rustix::process::geteuid().as_raw(),
            0,
            "disposable root container required"
        );
        let fixture = RootFixture::new();
        let config = fixture
            .request
            .policy
            .wolf_config
            .root
            .join(&fixture.request.policy.wolf_config.relative_path);
        let before = fs::read(&config).unwrap();
        let plan = preflight_with(&fixture.request, &fixture.environment).unwrap();
        let first = apply_with(&plan, &fixture.environment).unwrap();
        assert!(!first.changed_files.is_empty());
        assert_eq!(fs::read(&config).unwrap(), before);
        fixture.request.policy.validate().unwrap();
        let next = preflight_with(&fixture.request, &fixture.environment).unwrap();
        let second = apply_with(&next, &fixture.environment).unwrap();
        assert!(second.changed_files.is_empty());
        assert_eq!(fs::read(&config).unwrap(), before);
        assert_eq!(
            fs::metadata(&fixture.request.policy.backup_root)
                .unwrap()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&fixture.request.policy.catalog_state_directory)
                .unwrap()
                .uid(),
            1000
        );
    }

    #[test]
    #[ignore = "requires disposable root container; never execute on household host"]
    fn faulted_apply_has_verified_recovery_plan_and_guarded_rollback() {
        assert_eq!(
            rustix::process::geteuid().as_raw(),
            0,
            "disposable root container required"
        );
        let mut fixture = RootFixture::new();
        let plan = preflight_with(&fixture.request, &fixture.environment).unwrap();
        fixture.environment.fail_after = Some(2);
        assert!(apply_with(&plan, &fixture.environment).is_err());
        let folder = plan
            .policy
            .backup_root
            .join("installer")
            .join(plan.id.to_string());
        assert!(folder.join("plan.json").is_file());
        fixture.environment.fail_after = None;
        let report = rollback_with(&plan, &fixture.environment).unwrap();
        assert!(!report.changed_files.is_empty());
        assert!(
            plan.policy
                .wolf_config
                .root
                .join(&plan.policy.wolf_config.relative_path)
                .exists()
        );
        assert!(folder.join("plan.json").exists());
    }
    #[test]
    #[ignore = "requires disposable root container; never execute on household host"]
    fn rollback_refuses_changed_installed_file_and_retains_original_data() {
        assert_eq!(
            rustix::process::geteuid().as_raw(),
            0,
            "disposable root container required"
        );
        let fixture = RootFixture::new();
        let plan = preflight_with(&fixture.request, &fixture.environment).unwrap();
        apply_with(&plan, &fixture.environment).unwrap();
        let target = fixture
            .environment
            .path(Path::new("/etc/ssh/authorized_keys.d/wolf-manager"));
        fs::write(&target, b"legitimate operator edits").unwrap();
        assert!(rollback_with(&plan, &fixture.environment).is_err());
        assert_eq!(fs::read(target).unwrap(), b"legitimate operator edits");
    }

    #[test]
    #[ignore = "requires disposable root container; never execute on household host"]
    fn activation_is_explicit_and_rollback_restores_service_snapshot() {
        assert_eq!(
            rustix::process::geteuid().as_raw(),
            0,
            "disposable root container required"
        );
        let fixture = RootFixture::new();
        let plan = preflight_with(&fixture.request, &fixture.environment).unwrap();
        apply_with(&plan, &fixture.environment).unwrap();
        let record = plan
            .policy
            .backup_root
            .join("installer")
            .join(plan.id.to_string())
            .join("activation.json");
        assert!(!record.exists());
        let result = activate_with(
            &plan,
            ActivationOptions {
                start_wolf: true,
                start_catalog: false,
                enable_on_boot: true,
            },
            &fixture.environment,
        )
        .unwrap();
        assert!(result.after.unwrap().wolf.active);
        rollback_with(&plan, &fixture.environment).unwrap();
        assert_eq!(
            fixture.environment.services(&plan.policy).unwrap(),
            plan.service_snapshot
        );
        assert!(record.exists());
    }
    fn replace_native_validation_candidate(
        candidates: &mut [Recipe],
        config: &Path,
        managed: &Path,
        inherited: &str,
        kind: &str,
        value: &str,
    ) {
        if kind == "sshd" {
            // Remove the installed include so the candidate policy is the effective authority.
            fs::write(
                config,
                format!("{inherited}HostKey /etc/ssh/ssh_host_ed25519_key\n"),
            )
            .unwrap();
            let recipe = candidates.iter_mut().find(|r| r.path == managed).unwrap();
            let text = String::from_utf8(recipe.bytes.clone()).unwrap();
            recipe.bytes = if value.starts_with("ForceCommand") {
                text.replace(
                    "ForceCommand /usr/libexec/wolf-manager/ssh-dispatcher",
                    value,
                )
                .into_bytes()
            } else if value.starts_with("AcceptEnv") {
                text.replace("AcceptEnv WOLF_MANAGER_UNUSED_ENV", value)
                    .into_bytes()
            } else {
                format!("{text}\n{value}\n").into_bytes()
            };
        } else {
            candidates
                .iter_mut()
                .find(|r| r.path == Path::new("/etc/sudoers.d/wolf-manager"))
                .unwrap()
                .bytes = value.as_bytes().to_vec();
        }
    }

    #[test]
    #[ignore = "requires dedicated disposable root container and WOLF_TEST_NATIVE_VALIDATORS=1"]
    fn native_validators_accept_repeated_restricted_policy_and_refuse_privilege_drift() {
        assert_eq!(rustix::process::geteuid().as_raw(), 0);
        assert_eq!(
            std::env::var("WOLF_TEST_NATIVE_VALIDATORS").as_deref(),
            Ok("1")
        );
        assert_eq!(
            fs::read("/run/wolf-native-validator-fixture").unwrap(),
            b"disposable-container"
        );
        struct Restore(Vec<(PathBuf, Option<Vec<u8>>, Option<u32>)>);
        impl Drop for Restore {
            fn drop(&mut self) {
                for (path, bytes, mode) in &self.0 {
                    if let Some(bytes) = bytes {
                        fs::write(path, bytes).unwrap();
                        fs::set_permissions(path, fs::Permissions::from_mode(mode.unwrap()))
                            .unwrap();
                    } else if path.exists() {
                        fs::remove_file(path).unwrap();
                    }
                }
            }
        }
        let config = Path::new("/etc/ssh/sshd_config");
        let managed = Path::new("/etc/ssh/sshd_config.d/90-wolf-manager.conf");
        let _restore = Restore(
            [config, managed]
                .into_iter()
                .map(|path| {
                    (
                        path.to_owned(),
                        fs::read(path).ok(),
                        fs::metadata(path).ok().map(|m| m.mode() & 0o777),
                    )
                })
                .collect(),
        );
        let fixture = RootFixture::new();
        let base = "HostKey /etc/ssh/ssh_host_ed25519_key\nInclude /etc/ssh/sshd_config.d/90-wolf-manager.conf\n";
        fs::write(
            managed,
            include_bytes!("../../../installer/templates/90-wolf-manager.conf"),
        )
        .unwrap();
        let original_wolf =
            fs::read(fixture.request.policy.wolf_config.root.join("config.toml")).unwrap();
        for (index, inherited, replacement, expected_error) in [
            (0, "", None, None),
            (1, "AcceptEnv WOLF_MANAGER_UNUSED_ENV\n", None, None),
            (
                2,
                "",
                Some(("sshd", "AcceptEnv LD_PRELOAD")),
                Some("inherited client environment policy is not bounded"),
            ),
            (
                3,
                "SetEnv LD_PRELOAD=/unsafe\n",
                None,
                Some("inherited server environment policy is not bounded"),
            ),
            (
                4,
                "",
                Some(("sshd", "ForceCommand /bin/sh")),
                Some("effective SSH account policy differs from restricted contract"),
            ),
            (
                5,
                "",
                Some(("sshd", "UnknownDirective invalid")),
                Some("sshd validation failed before activation"),
            ),
            (
                6,
                "",
                Some(("sudo", "this is not valid sudoers !!")),
                Some("sudoers validation failed before activation"),
            ),
        ] {
            fs::write(config, format!("{inherited}{base}")).unwrap();
            let config_before = fs::read(config).unwrap();
            let managed_before = fs::read(managed).unwrap();
            let mut candidates = recipes(&fixture.request).unwrap();
            if let Some((kind, value)) = replacement {
                replace_native_validation_candidate(
                    &mut candidates,
                    config,
                    managed,
                    inherited,
                    kind,
                    value,
                );
            }
            let config_under_test = fs::read(config).unwrap();
            let folder = fixture.directory.path().join(format!("native-{index}"));
            fs::create_dir(&folder).unwrap();
            let result = validate_configs(&folder, &candidates);
            if let Some(expected) = expected_error {
                assert_eq!(result.unwrap_err().to_string(), expected);
            } else {
                result.unwrap();
                assert_eq!(config_under_test, config_before);
            }
            assert_eq!(fs::read(config).unwrap(), config_under_test);
            assert_eq!(fs::read(managed).unwrap(), managed_before);
            assert_eq!(
                fs::read(fixture.request.policy.wolf_config.root.join("config.toml")).unwrap(),
                original_wolf
            );
            assert!(!fixture.request.policy.state_root.exists());
        }
    }

    #[test]
    #[ignore = "requires dedicated disposable root container and WOLF_TEST_NATIVE_VALIDATORS=1"]
    fn native_account_admission_refuses_privileged_or_unlocked_existing_accounts() {
        assert_eq!(rustix::process::geteuid().as_raw(), 0);
        assert_eq!(
            std::env::var("WOLF_TEST_NATIVE_VALIDATORS").as_deref(),
            Ok("1")
        );
        assert_eq!(
            fs::read("/run/wolf-native-validator-fixture").unwrap(),
            b"disposable-container"
        );
        assert!(
            !Path::new("/nonexistent").exists(),
            "fixture requires absent managed home"
        );
        struct RestoreDatabases(Vec<(PathBuf, Vec<u8>)>);
        impl Drop for RestoreDatabases {
            fn drop(&mut self) {
                for (path, bytes) in &self.0 {
                    fs::write(path, bytes).unwrap();
                }
                if Path::new("/nonexistent").exists() {
                    fs::remove_dir_all("/nonexistent").unwrap();
                }
            }
        }
        let saved = RestoreDatabases(
            ["/etc/passwd", "/etc/group", "/etc/shadow"]
                .into_iter()
                .map(|path| {
                    let bytes = fs::read(path).unwrap();
                    assert!(
                        !String::from_utf8_lossy(&bytes)
                            .lines()
                            .any(|line| line.starts_with("wolf-manager:"))
                    );
                    (PathBuf::from(path), bytes)
                })
                .collect(),
        );
        assert!(!account_exists().unwrap());
        for (passwd, group, shadow, error) in [
            (
                "wolf-manager:x:32001:32001::/nonexistent:/bin/sh",
                "wolf-manager:x:32001:",
                "wolf-manager:!:0:0:99999:7:::",
                None,
            ),
            (
                "wolf-manager:x:0:32001::/nonexistent:/bin/sh",
                "wolf-manager:x:32001:",
                "wolf-manager:!:0:0:99999:7:::",
                Some("existing account does not match restricted system account"),
            ),
            (
                "wolf-manager:x:32001:0::/nonexistent:/bin/sh",
                "wolf-manager:x:0:",
                "wolf-manager:!:0:0:99999:7:::",
                Some("existing account does not match restricted system account"),
            ),
            (
                "wolf-manager:x:32001:32001::/root:/bin/sh",
                "wolf-manager:x:32001:",
                "wolf-manager:!:0:0:99999:7:::",
                Some("existing account does not match restricted system account"),
            ),
            (
                "wolf-manager:x:32001:32001::/nonexistent:/bin/bash",
                "wolf-manager:x:32001:",
                "wolf-manager:!:0:0:99999:7:::",
                Some("existing account does not match restricted system account"),
            ),
            (
                "wolf-manager:x:32001:32001::/nonexistent:/bin/sh",
                "wolf-manager:x:32002:",
                "wolf-manager:!:0:0:99999:7:::",
                Some("account primary group is not dedicated"),
            ),
            (
                "wolf-manager:x:32001:32001::/nonexistent:/bin/sh",
                "wolf-manager:x:32001:\nfixture-admin:x:32002:wolf-manager",
                "wolf-manager:!:0:0:99999:7:::",
                Some("managed account has supplementary privileges"),
            ),
            (
                "wolf-manager:x:32001:32001::/nonexistent:/bin/sh",
                "wolf-manager:x:32001:\nmalformed",
                "wolf-manager:!:0:0:99999:7:::",
                Some("malformed group database"),
            ),
            (
                "wolf-manager:x:32001:32001::/nonexistent:/bin/sh",
                "wolf-manager:x:32001:",
                "wolf-manager:unlocked-password:0:0:99999:7:::",
                Some("managed account password is not locked"),
            ),
            (
                "wolf-manager:x:32001:32001::/nonexistent:/bin/sh",
                "wolf-manager:x:32001:",
                "",
                Some("managed account lacks shadow lock"),
            ),
        ] {
            for ((path, original), appended) in saved.0.iter().zip([passwd, group, shadow]) {
                let mut bytes = original.clone();
                bytes.extend_from_slice(format!("{appended}\n").as_bytes());
                fs::write(path, bytes).unwrap();
            }
            let before = saved
                .0
                .iter()
                .map(|(path, _)| fs::read(path).unwrap())
                .collect::<Vec<_>>();
            let result = account_exists();
            if let Some(expected) = error {
                assert_eq!(result.unwrap_err().to_string(), expected);
            } else {
                assert!(result.unwrap());
            }
            assert_eq!(
                saved
                    .0
                    .iter()
                    .map(|(path, _)| fs::read(path).unwrap())
                    .collect::<Vec<_>>(),
                before
            );
        }
        fs::create_dir("/nonexistent").unwrap();
        fs::set_permissions("/nonexistent", fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            validate_locked_home().unwrap_err().to_string(),
            "managed home authority is unsafe"
        );
        fs::set_permissions("/nonexistent", fs::Permissions::from_mode(0o755)).unwrap();
        validate_locked_home().unwrap();
        fs::create_dir("/nonexistent/.ssh").unwrap();
        assert_eq!(
            validate_locked_home().unwrap_err().to_string(),
            "managed home has SSH state; no implicit adoption of user environment"
        );
    }

    #[test]
    #[ignore = "requires dedicated disposable root container and WOLF_TEST_NATIVE_VALIDATORS=1"]
    fn native_adoption_accepts_recognized_units_without_touching_wolf_or_steam() {
        assert_eq!(rustix::process::geteuid().as_raw(), 0);
        assert_eq!(
            std::env::var("WOLF_TEST_NATIVE_VALIDATORS").as_deref(),
            Ok("1")
        );
        assert_eq!(
            fs::read("/run/wolf-native-validator-fixture").unwrap(),
            b"disposable-container"
        );
        let fixture = RootFixture::new();
        let mut policy = fixture.request.policy.clone();
        policy.service_unit = format!("wolf-fixture-{}.service", Uuid::new_v4());
        let unit = PathBuf::from(format!("/etc/systemd/system/{}", policy.service_unit));
        fs::create_dir_all(unit.parent().unwrap()).unwrap();
        struct RemoveUnit(PathBuf);
        impl Drop for RemoveUnit {
            fn drop(&mut self) {
                if self.0.exists() {
                    fs::remove_file(&self.0).unwrap();
                }
            }
        }
        assert!(!unit.exists());
        let _remove = RemoveUnit(unit.clone());
        let config = policy
            .wolf_config
            .root
            .join(&policy.wolf_config.relative_path);
        let original_wolf = fs::read(&config).unwrap();
        let steam_config = fixture.directory.path().join("profile/config/config.vdf");
        let original_steam = fs::read(&steam_config).unwrap();
        assert_eq!(
            inspect_adopt(&policy).unwrap_err().to_string(),
            "adoption requires an existing recognized unit"
        );
        for (bytes, accepted) in [
            (format!("[Service]\nExecStart=/usr/bin/docker compose -f {} up --remove-orphans\n", policy.compose_file.display()).into_bytes(), true),
            (format!("[Service]\nWorkingDirectory={}\nExecStart=/usr/bin/docker compose up --remove-orphans\nExecStop=/usr/bin/docker compose down --remove-orphans\n", policy.compose_file.parent().unwrap().display()).into_bytes(), true),
            (b"[Service]\nExecStart=/bin/sh /custom/start-wolf\n".to_vec(), false),
            (vec![255], false),
        ] {
            fs::write(&unit, &bytes).unwrap();
            fs::set_permissions(&unit, fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(inspect_adopt(&policy).is_ok(), accepted);
            assert_eq!(fs::read(&unit).unwrap(), bytes);
            assert_eq!(fs::read(&config).unwrap(), original_wolf);
            assert_eq!(fs::read(&steam_config).unwrap(), original_steam);
            assert!(!policy.state_root.exists());
        }
    }

    fn install_then_upgrade(fixture: &mut RootFixture) -> (InstallPlan, Vec<u8>) {
        let first = preflight_with(&fixture.request, &fixture.environment).unwrap();
        apply_with(&first, &fixture.environment).unwrap();
        let receipt = fs::read(first.policy.state_root.join("installation.json")).unwrap();
        let mut binary = fs::read(&fixture.request.source_binary).unwrap();
        binary[127] = 1;
        fs::write(&fixture.request.source_binary, binary).unwrap();
        let upgrade = preflight_with(&fixture.request, &fixture.environment).unwrap();
        assert!(upgrade.receipt_identity.is_some());
        apply_with(&upgrade, &fixture.environment).unwrap();
        (upgrade, receipt)
    }

    fn installed_snapshot(plan: &InstallPlan) -> Vec<(PathBuf, Vec<u8>, FileIdentity)> {
        plan.proposed_writes
            .iter()
            .map(|write| {
                let (bytes, identity) = read(&write.destination).unwrap();
                (write.destination.clone(), bytes, identity)
            })
            .chain(std::iter::once({
                let path = plan.policy.state_root.join("installation.json");
                let (bytes, identity) = read(&path).unwrap();
                (path, bytes, identity)
            }))
            .collect()
    }

    #[test]
    #[ignore = "requires disposable root container; never execute on household host"]
    fn upgrade_rollback_restores_previous_installation_and_preserves_pairings_and_steam() {
        assert_eq!(rustix::process::geteuid().as_raw(), 0);
        let mut fixture = RootFixture::new();
        let steam_save = fixture
            .directory
            .path()
            .join("profile/userdata/valuable-save");
        fs::write(&steam_save, b"irreplaceable Steam save").unwrap();
        let (upgrade, first_receipt) = install_then_upgrade(&mut fixture);
        let binary_write = upgrade
            .proposed_writes
            .iter()
            .find(|write| write.destination.ends_with("wolf-manager-host"))
            .unwrap();
        let original_identity = binary_write.expected.clone().unwrap();
        let config = upgrade
            .policy
            .wolf_config
            .root
            .join(&upgrade.policy.wolf_config.relative_path);
        let paired = b"config_version=7\nuuid=\"preserve\"\npaired_clients=[\"new-client\"]\n";
        fs::write(&config, paired).unwrap();
        let report = rollback_with(&upgrade, &fixture.environment).unwrap();
        assert!(report.changed_files.contains(&binary_write.destination));
        assert!(matches_identity(
            &read(&binary_write.destination).unwrap().1,
            &original_identity
        ));
        assert_eq!(
            fs::read(upgrade.policy.state_root.join("installation.json")).unwrap(),
            first_receipt
        );
        assert_eq!(fs::read(config).unwrap(), paired);
        assert_eq!(fs::read(steam_save).unwrap(), b"irreplaceable Steam save");
        assert!(
            report
                .verified_backup_directory
                .join("receipt-preimage")
                .exists()
        );
    }

    #[test]
    #[ignore = "requires disposable root container; never execute on household host"]
    fn upgrade_rollback_can_restore_verified_backups_without_displaced_inodes() {
        assert_eq!(rustix::process::geteuid().as_raw(), 0);
        let mut fixture = RootFixture::new();
        let (plan, first_receipt) = install_then_upgrade(&mut fixture);
        let folder = saved_plan(&plan).unwrap();
        let binary = plan
            .proposed_writes
            .iter()
            .find(|write| write.destination.ends_with("wolf-manager-host"))
            .unwrap();
        let displaced = binary
            .destination
            .parent()
            .unwrap()
            .join(format!(".wolf-manager-{}.previous", plan.id));
        let original_binary = fs::read(&displaced).unwrap();
        fs::rename(&displaced, folder.join("retained-original-binary")).unwrap();
        let displaced_receipt = plan
            .policy
            .state_root
            .join(format!(".installation-{}.previous", plan.id));
        fs::rename(&displaced_receipt, folder.join("retained-original-receipt")).unwrap();
        rollback_with(&plan, &fixture.environment).unwrap();
        assert_eq!(fs::read(&binary.destination).unwrap(), original_binary);
        assert_eq!(
            fs::read(plan.policy.state_root.join("installation.json")).unwrap(),
            first_receipt
        );
        assert_eq!(
            fs::read(folder.join("retained-original-binary")).unwrap(),
            original_binary
        );
        assert_eq!(
            fs::read(folder.join("retained-original-receipt")).unwrap(),
            first_receipt
        );
    }

    #[test]
    #[ignore = "requires disposable root container; never execute on household host"]
    fn changed_source_after_preview_refuses_before_creating_installation_state() {
        assert_eq!(rustix::process::geteuid().as_raw(), 0);
        let fixture = RootFixture::new();
        let plan = preflight_with(&fixture.request, &fixture.environment).unwrap();
        let original_config =
            fs::read(fixture.request.policy.wolf_config.root.join("config.toml")).unwrap();
        let mut source = fs::read(&fixture.request.source_binary).unwrap();
        source[127] = 42;
        fs::write(&fixture.request.source_binary, source).unwrap();
        assert_eq!(
            apply_with(&plan, &fixture.environment)
                .unwrap_err()
                .to_string(),
            "installer inputs changed since preview; no writes permitted"
        );
        assert!(!fixture.request.policy.backup_root.exists());
        assert!(!fixture.request.policy.state_root.exists());
        assert!(!fixture.environment.prefix.as_ref().unwrap().exists());
        assert_eq!(
            fs::read(fixture.request.policy.wolf_config.root.join("config.toml")).unwrap(),
            original_config
        );
    }

    #[test]
    #[ignore = "requires disposable root container; never execute on household host"]
    fn rollback_refuses_corrupt_or_untrusted_backups_before_any_installed_write() {
        assert_eq!(rustix::process::geteuid().as_raw(), 0);
        for untrusted_mode in [false, true] {
            let mut fixture = RootFixture::new();
            let (plan, _) = install_then_upgrade(&mut fixture);
            let folder = saved_plan(&plan).unwrap();
            let index = plan
                .proposed_writes
                .iter()
                .position(|write| write.destination.ends_with("wolf-manager-host"))
                .unwrap();
            let backup = folder.join(format!("preimage-{index}"));
            if untrusted_mode {
                fs::set_permissions(&backup, fs::Permissions::from_mode(0o644)).unwrap();
            } else {
                fs::write(&backup, b"corrupted retained preimage").unwrap();
            }
            let corrupted_backup = read(&backup).unwrap();
            let installed = installed_snapshot(&plan);
            let error = rollback_with(&plan, &fixture.environment).unwrap_err();
            assert_eq!(error.to_string(), "rollback backup is corrupt or untrusted");
            assert_eq!(installed_snapshot(&plan), installed);
            assert_eq!(read(&backup).unwrap(), corrupted_backup);
            assert!(folder.join("plan.json").exists());
        }
    }

    #[test]
    #[ignore = "requires disposable root container; never execute on household host"]
    fn rollback_refuses_corrupt_previous_receipt_before_restoring_files() {
        assert_eq!(rustix::process::geteuid().as_raw(), 0);
        let mut fixture = RootFixture::new();
        let (plan, _) = install_then_upgrade(&mut fixture);
        let folder = saved_plan(&plan).unwrap();
        let backup = folder.join("receipt-preimage");
        fs::write(&backup, b"corrupted previous installation receipt").unwrap();
        let installed = installed_snapshot(&plan);
        let error = rollback_with(&plan, &fixture.environment).unwrap_err();
        assert_eq!(
            error.to_string(),
            "previous installation receipt backup is corrupt"
        );
        assert_eq!(installed_snapshot(&plan), installed);
        assert_eq!(
            fs::read(backup).unwrap(),
            b"corrupted previous installation receipt"
        );
        assert!(folder.join("plan.json").exists());
    }

    #[test]
    #[ignore = "requires disposable root container; never execute on household host"]
    fn bootstrap_default_state_survives_rollback_with_new_pairings() {
        assert_eq!(
            rustix::process::geteuid().as_raw(),
            0,
            "disposable root container required"
        );
        let mut fixture = RootFixture::new();
        let config = fixture
            .request
            .policy
            .wolf_config
            .root
            .join(&fixture.request.policy.wolf_config.relative_path);
        fs::remove_file(&config).unwrap();
        fs::remove_file(&fixture.request.policy.compose_file).unwrap();
        fixture.request.initial_files=vec![InitialFile{path:config.clone(),bytes:b"config_version=7\nuuid=\"new-server\"\n".to_vec(),uid:0,gid:0,mode:0o600},InitialFile{path:fixture.request.policy.compose_file.clone(),bytes:serde_json::to_vec(&serde_json::json!({"services":{"wolf":{"image":fixture.request.policy.image_ref,"container_name":"wolf","pull_policy":"never"}}})).unwrap(),uid:0,gid:0,mode:0o600}];
        let plan = preflight_with(&fixture.request, &fixture.environment).unwrap();
        apply_with(&plan, &fixture.environment).unwrap();
        let paired =
            b"config_version=7\nuuid=\"new-server\"\npaired_clients=[\"valuable-pairing\"]\n";
        fs::write(&config, paired).unwrap();
        let report = rollback_with(&plan, &fixture.environment).unwrap();
        assert_eq!(fs::read(&config).unwrap(), paired);
        assert!(report.retained_files.contains(&config));
        assert!(fixture.request.policy.compose_file.exists());
    }
    #[test]
    #[ignore = "run only in a disposable root container"]
    fn nonlocal_ssh_match_in_nested_include_refuses_without_changing_config() {
        assert_eq!(rustix::process::geteuid().as_raw(), 0);
        let directory = tempfile::Builder::new()
            .prefix("wolf-ssh-")
            .tempdir_in("/root")
            .unwrap();
        let root = directory.path();
        fs::create_dir(root.join("conf.d")).unwrap();
        let config = root.join("sshd_config");
        let original = format!("AcceptEnv LANG\nInclude {}/conf.d/*.conf\n", root.display());
        fs::write(&config, &original).unwrap();
        let nested = root.join("conf.d/nonlocal.conf");
        let dangerous = b"Match Address 192.168.50.0/24\nForceCommand /bin/sh\nAcceptEnv *\n";
        fs::write(&nested, dangerous).unwrap();
        assert!(validate_ssh_policy_tree(&config, root).is_err());
        assert_eq!(fs::read(&config).unwrap(), original.as_bytes());
        assert_eq!(fs::read(&nested).unwrap(), dangerous);
        fs::write(&nested, b"AcceptEnv LANG\n").unwrap();
        validate_ssh_policy_tree(&config, root).unwrap();
        fs::write(&nested, format!("Include {}\n", config.display())).unwrap();
        assert!(validate_ssh_policy_tree(&config, root).is_err());
        fs::remove_file(&nested).unwrap();
        std::os::unix::fs::symlink(&config, &nested).unwrap();
        assert!(validate_ssh_policy_tree(&config, root).is_err());
        assert_eq!(fs::read(&config).unwrap(), original.as_bytes());
    }
}
