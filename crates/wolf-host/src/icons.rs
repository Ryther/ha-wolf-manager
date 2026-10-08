//! Bounded PNG cache inside the explicitly mounted Wolf configuration grant.
use image::{ImageFormat, ImageReader, Limits};
use rustix::fs::{Mode, OFlags, ResolveFlags};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Cursor, Read, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};
use wolf_core::AppId;
const MAX: usize = 4 * 1024 * 1024;
const DIRECTORY: &str = ".ha-wolf-manager-icons";
fn invalid() -> io::Error {
    io::Error::other("invalid Wolf icon authority or bounded image")
}
pub trait Fetch {
    fn get(&mut self, app: &AppId, timeout: Duration) -> io::Result<Vec<u8>>;
}
fn decode(bytes: &[u8]) -> io::Result<image::DynamicImage> {
    if bytes.len() > MAX {
        return Err(invalid());
    }
    let mut reader = ImageReader::new(Cursor::new(bytes)).with_guessed_format()?;
    if !matches!(reader.format(), Some(ImageFormat::Jpeg | ImageFormat::Png)) {
        return Err(invalid());
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(2048);
    limits.max_image_height = Some(2048);
    limits.max_alloc = Some(32 * 1024 * 1024);
    reader.limits(limits);
    reader.decode().map_err(|_| invalid())
}
pub fn convert(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let decoded = decode(bytes)?;
    let mut out = Cursor::new(Vec::new());
    decoded
        .write_to(&mut out, ImageFormat::Png)
        .map_err(|_| invalid())?;
    let bytes = out.into_inner();
    if bytes.len() > MAX {
        return Err(invalid());
    }
    Ok(bytes)
}
fn fallback() -> io::Result<Vec<u8>> {
    let image = image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(
        1,
        1,
        image::Rgb([128, 128, 128]),
    ));
    let mut bytes = Cursor::new(Vec::new());
    image
        .write_to(&mut bytes, ImageFormat::Png)
        .map_err(|_| invalid())?;
    Ok(bytes.into_inner())
}
fn png(file: File, uid: u32, gid: u32) -> io::Result<Vec<u8>> {
    let m = file.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != uid
        || m.gid() != gid
        || m.mode() & 0o7777 != 0o644
        || m.len() > MAX as u64
    {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    file.take((MAX + 1) as u64).read_to_end(&mut bytes)?;
    if !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Err(invalid());
    }
    decode(&bytes)?;
    Ok(bytes)
}
pub fn cache_with(
    root: &Path,
    uid: u32,
    gid: u32,
    container: &Path,
    apps: &[AppId],
    fetch: &mut impl Fetch,
) -> io::Result<BTreeMap<AppId, String>> {
    if apps.len() > 1024 {
        return Err(invalid());
    }
    absolute(container)?;
    let root = File::from(rustix::fs::openat2(
        rustix::fs::CWD,
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?);
    let m = root.metadata()?;
    if m.uid() != uid || m.gid() != gid || m.mode() & 0o022 != 0 {
        return Err(invalid());
    }
    let created = match rustix::fs::mkdirat(&root, DIRECTORY, Mode::from_raw_mode(0o755)) {
        Ok(()) => true,
        Err(rustix::io::Errno::EXIST) => false,
        Err(e) => return Err(e.into()),
    };
    let folder = File::from(rustix::fs::openat2(
        &root,
        DIRECTORY,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?);
    if created {
        rustix::fs::fchmod(&folder, Mode::from_raw_mode(0o755))?;
        folder.sync_all()?;
        root.sync_all()?;
    }
    let m = folder.metadata()?;
    if m.uid() != uid || m.gid() != gid || m.mode() & 0o7777 != 0o755 {
        return Err(invalid());
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut paths = BTreeMap::new();
    for app in apps {
        let name = format!("{}.png", app.as_str());
        match rustix::fs::openat2(
            &folder,
            &name,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        ) {
            Ok(fd) => {
                png(File::from(fd), uid, gid)?;
            }
            Err(rustix::io::Errno::NOENT) => {
                let remaining = deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_secs(5));
                let bytes = if remaining.is_zero() {
                    fallback()?
                } else {
                    fetch
                        .get(app, remaining)
                        .and_then(|b| convert(&b))
                        .or_else(|_| fallback())?
                };
                let staging = format!(".{}.new", uuid::Uuid::new_v4());
                let mut file = File::from(rustix::fs::openat2(
                    &folder,
                    &staging,
                    OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o644),
                    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
                )?);
                rustix::fs::fchmod(&file, Mode::from_raw_mode(0o644))?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                rustix::fs::renameat_with(
                    &folder,
                    &staging,
                    &folder,
                    &name,
                    rustix::fs::RenameFlags::NOREPLACE,
                )?;
                folder.sync_all()?;
                let fd = rustix::fs::openat2(
                    &folder,
                    &name,
                    OFlags::RDONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
                )?;
                png(File::from(fd), uid, gid)?;
            }
            Err(e) => return Err(e.into()),
        }
        paths.insert(
            app.clone(),
            container
                .join(DIRECTORY)
                .join(name)
                .to_str()
                .ok_or_else(invalid)?
                .to_owned(),
        );
    }
    Ok(paths)
}
fn absolute(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        || path.to_str().is_none_or(|s| s.contains(['\n', '\r', ':']))
    {
        return Err(invalid());
    }
    Ok(())
}
pub fn container_root(compose: &serde_json::Value, root: &Path, name: &str) -> io::Result<PathBuf> {
    let services = compose
        .get("services")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(invalid)?;
    let matching = services
        .values()
        .filter(|v| v.get("container_name").and_then(serde_json::Value::as_str) == Some(name))
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(invalid());
    }
    let volumes = matching[0]
        .get("volumes")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(invalid)?;
    let mut targets = Vec::new();
    let mut other_targets = Vec::new();
    for volume in volumes {
        let mapping = if let Some(s) = volume.as_str() {
            let parts = s.split(':').collect::<Vec<_>>();
            if parts.len() == 2 || parts.len() == 3 {
                Some((parts[0], parts[1]))
            } else {
                None
            }
        } else if volume.get("type").and_then(serde_json::Value::as_str) == Some("bind") {
            volume
                .get("source")
                .and_then(serde_json::Value::as_str)
                .zip(volume.get("target").and_then(serde_json::Value::as_str))
        } else {
            None
        };
        if let Some((source, target)) = mapping {
            absolute(Path::new(target))?;
            if Path::new(source) == root {
                targets.push(PathBuf::from(target));
            } else {
                other_targets.push(PathBuf::from(target));
            }
        } else if let Some(target) = volume.get("target").and_then(serde_json::Value::as_str) {
            absolute(Path::new(target))?;
            other_targets.push(PathBuf::from(target));
        } else if let Some(text) = volume.as_str() {
            let parts = text.split(':').collect::<Vec<_>>();
            let target = parts.get(1).copied().unwrap_or(text);
            absolute(Path::new(target))?;
            other_targets.push(PathBuf::from(target));
        } else {
            return Err(invalid());
        }
    }
    if targets.len() != 1 {
        return Err(invalid());
    }
    let target = targets.remove(0);
    let icons = target.join(DIRECTORY);
    if other_targets
        .iter()
        .any(|other| icons.starts_with(other) || other.starts_with(&icons))
    {
        return Err(invalid());
    }
    Ok(target)
}
struct Http(reqwest::blocking::Client);
impl Fetch for Http {
    fn get(&mut self, app: &AppId, timeout: Duration) -> io::Result<Vec<u8>> {
        let response = self
            .0
            .get(wolf_core::steam_cover_url(app))
            .timeout(timeout)
            .send()
            .map_err(|_| invalid())?;
        if !response.status().is_success()
            || response.content_length().is_some_and(|n| n > MAX as u64)
        {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        response.take((MAX + 1) as u64).read_to_end(&mut bytes)?;
        if bytes.len() > MAX {
            return Err(invalid());
        }
        Ok(bytes)
    }
}
struct Offline;
impl Fetch for Offline {
    fn get(&mut self, _: &AppId, _: Duration) -> io::Result<Vec<u8>> {
        Err(invalid())
    }
}
pub fn prepare(
    policy: &crate::policy::RootPolicy,
    apps: &[AppId],
    online: bool,
) -> io::Result<BTreeMap<AppId, String>> {
    if apps.is_empty() {
        return Ok(BTreeMap::new());
    }
    let file = File::from(rustix::fs::openat2(
        rustix::fs::CWD,
        &policy.compose_file,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?);
    if file.metadata()?.len() > 1024 * 1024 {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err(invalid());
    }
    let compose = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) if online => {
            let output = crate::commands::run(
                crate::commands::Tool::Docker,
                &[
                    "compose",
                    "--file",
                    policy.compose_file.to_str().ok_or_else(invalid)?,
                    "config",
                    "--format",
                    "json",
                ],
                Duration::from_secs(5),
            )?;
            if output.code != Some(0) {
                return Err(invalid());
            }
            serde_json::from_slice(&output.stdout).map_err(|_| invalid())?
        }
        Err(_) => return Err(invalid()),
    };
    let container = container_root(&compose, &policy.wolf_config.root, &policy.container_name)?;
    if online {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::blocking::Client::builder()
            .tls_backend_rustls()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| invalid())?;
        cache_with(
            &policy.wolf_config.root,
            policy.wolf_config.uid,
            policy.wolf_config.gid,
            &container,
            apps,
            &mut Http(client),
        )
    } else {
        cache_with(
            &policy.wolf_config.root,
            policy.wolf_config.uid,
            policy.wolf_config.gid,
            &container,
            apps,
            &mut Offline,
        )
    }
}
