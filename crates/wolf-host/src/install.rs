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
#[derive(Clone, Debug)]
pub struct InstallRequest {
    pub mode: InstallMode,
    pub policy: RootPolicy,
    pub authorized_public_keys: Vec<String>,
    pub source_binary: PathBuf,
    pub broker_config_source: Option<PathBuf>,
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
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallPlan {
    pub version: u8,
    pub id: Uuid,
    pub mode: InstallMode,
    pub policy: RootPolicy,
    pub storage_mapping: Vec<StorageMapping>,
    pub proposed_writes: Vec<PlannedWrite>,
    pub source_binary: PathBuf,
    pub source_identity: FileIdentity,
    pub broker_config_source: Option<PathBuf>,
    pub broker_identity: Option<FileIdentity>,
    pub authorized_public_keys: Vec<String>,
    pub account_exists: bool,
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
    let (path, unit)=match request.mode { InstallMode::Install => (PathBuf::from(format!("/etc/systemd/system/{}",request.policy.service_unit)), include_str!("../../../installer/templates/wolf.service").to_owned()), InstallMode::Adopt => (PathBuf::from(format!("/etc/systemd/system/{}.d/90-wolf-manager.conf",request.policy.service_unit)), "# Managed by HA Wolf Manager\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStartPre=\nExecStart=\nExecStart=/usr/local/bin/wolf-manager-host lifecycle-start\nExecStop=\nExecStop=/usr/local/bin/wolf-manager-host lifecycle-stop\nExecStopPost=\nTimeoutStartSec=370\nTimeoutStopSec=190\n".to_owned()) };
    recipes.push(Recipe {
        path,
        bytes: unit.into_bytes(),
        mode: 0o644,
        uid: 0,
        gid: 0,
    });
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
    Ok(recipes)
}
fn account_exists() -> io::Result<bool> {
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

    if crate::transactions::TransactionStore::open(&policy.backup_root)?.recovery_pending()? {
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
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(fail(
            "installer preflight requires root authority inspection",
        ));
    }
    request.policy.validate()?;
    let existing_policy = Path::new("/etc/wolf-manager/host-policy.json");
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
    let recipes = recipes(request)?;
    let receipt_path = request.policy.state_root.join("installation.json");
    let previous: Option<InstallReport> = if receipt_path.exists() {
        trusted_path(&receipt_path, 0, false)?;
        Some(serde_json::from_slice(&read(&receipt_path)?.0)?)
    } else {
        None
    };
    let mut writes = Vec::new();
    for r in recipes {
        ancestor(&r.path)?;
        let current = expected(&r.path)?;
        if let Some(identity) = &current {
            if identity.uid != r.uid || identity.gid != r.gid {
                return Err(fail("existing destination ownership differs"));
            }
            if identity.sha256 != sha(&r.bytes)
                && !previous
                    .as_ref()
                    .is_some_and(|p| p.installed_files.get(&r.path) == Some(identity))
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
    Ok(InstallPlan{version:1,id:Uuid::new_v4(),mode:request.mode.clone(),policy:request.policy.clone(),storage_mapping:mappings,proposed_writes:writes,source_binary:request.source_binary.clone(),source_identity,broker_config_source:request.broker_config_source.clone(),broker_identity,authorized_public_keys:request.authorized_public_keys.clone(),account_exists:account_exists()?,rollback:"All changed existing files are verified in backup_root/installer/<plan UUID>; restore only if current postimage still matches. New files may be removed only if installer-owned postimages match. Never remove the account, backups, Steam data or Wolf state automatically.".into()})
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
fn validate_configs(folder: &Path, recipes: &[Recipe]) -> io::Result<()> {
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
    Ok(())
}
pub fn apply(plan: &InstallPlan) -> io::Result<InstallReport> {
    if rustix::process::geteuid().as_raw() != 0 || plan.version != 1 {
        return Err(fail("root authority and plan version required"));
    }
    plan.policy.validate()?;
    pending(&plan.policy)?;
    let request = InstallRequest {
        mode: plan.mode.clone(),
        policy: plan.policy.clone(),
        authorized_public_keys: plan.authorized_public_keys.clone(),
        source_binary: plan.source_binary.clone(),
        broker_config_source: plan.broker_config_source.clone(),
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
    let refreshed = preflight(&request)?;
    if refreshed.proposed_writes != plan.proposed_writes
        || refreshed.source_identity != plan.source_identity
        || refreshed.broker_identity != plan.broker_identity
        || refreshed.storage_mapping != plan.storage_mapping
        || refreshed.account_exists != plan.account_exists
    {
        return Err(fail(
            "installer inputs changed since preview; no writes permitted",
        ));
    }
    let folder = plan
        .policy
        .backup_root
        .join("installer")
        .join(plan.id.to_string());
    directory(&folder, 0o700)?;
    let recipes = recipes(&request)?;
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
    validate_configs(&folder, &recipes)?;

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
    create_file(
        &folder.join("plan.json"),
        &serde_json::to_vec_pretty(plan)?,
        0o600,
        0,
        0,
    )?;
    // Account creation is deliberately last among prerequisites, before policy installation.
    if !plan.account_exists {
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
    let mut changed = Vec::new();
    for (r, write) in recipes.iter().zip(&plan.proposed_writes) {
        if write
            .expected
            .as_ref()
            .is_some_and(|i| i.sha256 == write.sha256 && i.mode == write.mode)
        {
            continue;
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
        changed.push(r.path.clone());
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
        recovery_instructions: plan.rollback.clone(),
    };
    create_file(
        &folder.join("report.json"),
        &serde_json::to_vec_pretty(&report)?,
        0o600,
        0,
        0,
    )?;
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
    // No automatic service start/restart: operator reviews the verified plan before cutover.
    Ok(report)
}
