//! Closed root-owned host policy. Browser and RPC inputs cannot choose this authority.
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs, io,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};
use wolf_core::PcId;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibraryGrant {
    pub library_id: String,
    pub steamapps_path: PathBuf,
    pub container_paths: Vec<PathBuf>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileGrant {
    pub root: PathBuf,
    pub config_vdf: String,
    pub libraryfolders_vdf: Vec<String>,
    pub userdata_directory: String,
    pub container_userdata_paths: Vec<PathBuf>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutableTarget {
    pub root: PathBuf,
    pub relative_path: String,
    pub uid: u32,
    pub gid: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtonGrant {
    pub name: String,
    pub host_path: PathBuf,
    pub container_paths: Vec<PathBuf>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootPolicy {
    pub version: u8,
    pub pc_id: PcId,
    pub steam_uid: u32,
    pub steam_gid: u32,
    pub libraries: Vec<LibraryGrant>,
    pub steam_profiles: Vec<ProfileGrant>,
    pub wolf_config: MutableTarget,
    pub compose_file: PathBuf,
    pub service_unit: String,
    pub container_name: String,
    pub image_ref: String,
    pub backup_root: PathBuf,
    pub state_root: PathBuf,
    pub catalog_state_directory: PathBuf,
    pub broker_secret_file: Option<PathBuf>,
    pub pull_on_start: bool,
    pub pull_timeout_seconds: u64,
    pub proton: Option<ProtonGrant>,
    pub steam_executables: Vec<PathBuf>,
    pub steam_runner: toml::Table,
}
fn fail(message: &'static str) -> io::Error {
    io::Error::other(message)
}
pub(crate) fn absolute(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        || path.as_os_str().as_encoded_bytes().contains(&0)
    {
        return Err(fail("path must be normal and absolute"));
    }
    Ok(())
}
pub(crate) fn relative(value: &str) -> io::Result<()> {
    if value.is_empty()
        || value
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
        || value.contains('\0')
        || Path::new(value)
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(fail("path must be normal and relative"));
    }
    Ok(())
}
fn identifier(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
}
pub(crate) fn trusted_path(path: &Path, uid: u32, directory: bool) -> io::Result<()> {
    absolute(path)?;
    let mut cursor = PathBuf::from("/");
    for component in path.components().skip(1) {
        cursor.push(component.as_os_str());
        let meta = fs::symlink_metadata(&cursor)?;
        let last = cursor == path;
        if meta.file_type().is_symlink()
            || (!last && !meta.is_dir())
            || (meta.uid() != 0 && meta.uid() != uid)
            || meta.mode() & 0o022 != 0
        {
            return Err(fail("unsafe ownership, writable ancestor or path alias"));
        }
        if last
            && (meta.is_dir() != directory
                || (!directory && (!meta.is_file() || meta.nlink() != 1)))
        {
            return Err(fail("unsafe target type or hard link"));
        }
    }
    Ok(())
}
impl RootPolicy {
    /// Structural checks are also usable before creating a new installation.
    pub fn validate_structure(&self) -> io::Result<()> {
        if self.version != 1
            || self.steam_uid == 0
            || self.steam_gid == 0
            || self.libraries.is_empty()
            || self.steam_profiles.is_empty()
            || self.libraries.len() > 128
            || self.steam_profiles.len() > 64
            || self.steam_executables.is_empty()
            || !(1..=300).contains(&self.pull_timeout_seconds)
        {
            return Err(fail("invalid policy version, identity or bounds"));
        }
        if !self.service_unit.ends_with(".service")
            || !identifier(&self.service_unit, 128)
            || !identifier(&self.container_name, 128)
            || self.image_ref.is_empty()
            || self.image_ref.len() > 512
            || !self
                .image_ref
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_.:@-".contains(&b))
            || (self.image_ref.starts_with('-')
                || self.image_ref.starts_with('/')
                || self.image_ref.ends_with('/')
                || self.image_ref.contains("//"))
        {
            return Err(fail("invalid unit, container or image reference"));
        }
        let mut ids = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for library in &self.libraries {
            if !identifier(&library.library_id, 64)
                || !ids.insert(&library.library_id)
                || !paths.insert(&library.steamapps_path)
                || library.container_paths.is_empty()
            {
                return Err(fail("duplicate or invalid library grant"));
            }
            absolute(&library.steamapps_path)?;
            for path in &library.container_paths {
                absolute(path)?;
            }
        }
        let mut profile_roots = BTreeSet::new();
        for profile in &self.steam_profiles {
            if !profile_roots.insert(&profile.root) {
                return Err(fail("duplicate profile root"));
            }
            absolute(&profile.root)?;
            relative(&profile.config_vdf)?;
            relative(&profile.userdata_directory)?;
            for p in &profile.libraryfolders_vdf {
                relative(p)?;
            }
            for p in &profile.container_userdata_paths {
                absolute(p)?;
            }
        }
        absolute(&self.wolf_config.root)?;
        relative(&self.wolf_config.relative_path)?;
        if self.wolf_config.uid != 0 || self.wolf_config.gid != 0 {
            return Err(fail("Wolf configuration authority must be root owned"));
        }
        for path in [
            &self.compose_file,
            &self.backup_root,
            &self.state_root,
            &self.catalog_state_directory,
        ]
        .into_iter()
        .chain(self.broker_secret_file.iter())
        .chain(self.steam_executables.iter())
        {
            absolute(path)?;
        }
        if self.backup_root == self.state_root || self.steam_runner.is_empty() {
            return Err(fail("missing runner or overlapping stores"));
        }
        if let Some(proton) = &self.proton {
            if !identifier(&proton.name, 128) || proton.container_paths.is_empty() {
                return Err(fail("invalid Proton grant"));
            }
            absolute(&proton.host_path)?;
            for path in &proton.container_paths {
                absolute(path)?;
            }
        }
        Ok(())
    }
    pub fn validate(&self) -> io::Result<()> {
        self.validate_structure()?;
        for library in &self.libraries {
            trusted_path(&library.steamapps_path, self.steam_uid, true)?;
        }
        for profile in &self.steam_profiles {
            trusted_path(&profile.root, self.steam_uid, true)?;
            for path in
                std::iter::once(&profile.config_vdf).chain(profile.libraryfolders_vdf.iter())
            {
                let path = profile.root.join(path);
                trusted_path(&path, self.steam_uid, false)?;
                let m = fs::metadata(path)?;
                if m.uid() != self.steam_uid || m.gid() != self.steam_gid {
                    return Err(fail("Steam file owner differs from grant"));
                }
            }
            trusted_path(
                &profile.root.join(&profile.userdata_directory),
                self.steam_uid,
                true,
            )?;
        }
        trusted_path(
            &self.wolf_config.root.join(&self.wolf_config.relative_path),
            0,
            false,
        )?;
        trusted_path(&self.compose_file, 0, false)?;
        for path in [&self.backup_root, &self.state_root] {
            trusted_path(path, 0, true)?;
            if fs::metadata(path)?.mode() & 0o077 != 0 {
                return Err(fail("root state store must be private"));
            }
        }
        trusted_path(&self.catalog_state_directory, self.steam_uid, true)?;
        for path in &self.steam_executables {
            trusted_path(path, self.steam_uid, false)?;
        }
        if let Some(path) = &self.broker_secret_file {
            trusted_path(path, self.steam_uid, false)?;
            if fs::metadata(path)?.mode() & 0o007 != 0 {
                return Err(fail("broker secret must not be world readable"));
            }
        }
        if let Some(proton) = &self.proton {
            trusted_path(&proton.host_path, self.steam_uid, true)?;
        }
        Ok(())
    }
    /// Catalog processes inspect public root policy without traversing private stores.
    pub fn load_catalog_fixed() -> io::Result<Self> {
        let path = Path::new("/etc/wolf-manager/host-policy.json");
        trusted_path(path, 0, false)?;
        let file = std::fs::File::from(rustix::fs::openat2(
            rustix::fs::CWD,
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        )?);
        if file.metadata()?.uid() != 0 || file.metadata()?.mode() & 0o022 != 0 {
            return Err(fail("policy changed trust during open"));
        }
        let mut bytes = Vec::new();
        use std::io::Read;
        file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 1024 * 1024 {
            return Err(fail("policy exceeds bound"));
        }
        let policy: Self = serde_json::from_slice(&bytes)?;
        policy.validate_structure()?;
        Ok(policy)
    }
    pub fn load_fixed() -> io::Result<Self> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(fail("root helper requires root"));
        }
        Self::load(Path::new("/etc/wolf-manager/host-policy.json"))
    }
    pub fn load(path: &Path) -> io::Result<Self> {
        trusted_path(path, 0, false)?;
        let file = std::fs::File::from(rustix::fs::openat2(
            rustix::fs::CWD,
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        )?);
        let metadata = file.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 || metadata.nlink() != 1 {
            return Err(fail("policy trust changed during open"));
        }
        use std::io::Read;
        let mut bytes = Vec::new();
        file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 1024 * 1024 {
            return Err(fail("policy exceeds bound"));
        }
        let policy: Self = serde_json::from_slice(&bytes)?;
        policy.validate()?;
        Ok(policy)
    }
}
