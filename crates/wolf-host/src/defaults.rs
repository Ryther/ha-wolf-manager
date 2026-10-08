//! Explicit, absent-only initial files. Adoption never calls this producer.
use crate::{install::InitialFile, policy::RootPolicy};
use std::{io, path::Path};
const WOLF_CONFIG: &str = include_str!("../../../installer/vendor/wolf/config.v7.toml");
/// Generate operator-reviewable defaults without writing or touching a service.
/// The caller's policy defines the persistent configuration mapping.
pub fn initial_files(policy: &RootPolicy) -> io::Result<Vec<InitialFile>> {
    policy.validate_structure()?;
    let mut files = Vec::new();
    let config_path = policy
        .wolf_config
        .root
        .join(&policy.wolf_config.relative_path);
    if absent(&config_path)? {
        files.push(InitialFile {
            path: config_path,
            bytes: WOLF_CONFIG.as_bytes().to_vec(),
            uid: 0,
            gid: 0,
            mode: 0o600,
        });
    }
    if absent(&policy.compose_file)? {
        let config = policy
            .wolf_config
            .root
            .to_str()
            .ok_or_else(|| io::Error::other("non-UTF8 config mapping"))?;
        let compose = serde_json::json!({"services":{"wolf":{
         "image":policy.image_ref,"container_name":policy.container_name,
         "network_mode":"host","restart":"unless-stopped","pull_policy":"never",
         "environment":{"WOLF_LOG_LEVEL":"DEBUG","GST_DEBUG":"3","WOLF_DEFAULT_RUN_UID":policy.steam_uid.to_string(),"WOLF_DEFAULT_RUN_GID":policy.steam_gid.to_string(),"WOLF_CFG_FILE":format!("/etc/wolf/{}",policy.wolf_config.relative_path)},
         "volumes":[format!("{config}:/etc/wolf:rw"),"/var/run/docker.sock:/var/run/docker.sock:rw","/dev:/dev:rw","/run/udev:/run/udev:rw"],
         "devices":["/dev/dri:/dev/dri","/dev/uinput:/dev/uinput","/dev/uhid:/dev/uhid","/dev/fuse:/dev/fuse"],
         "device_cgroup_rules":["c 13:* rmw","c 226:* rmw","c 244:* rmw"]
        }}});
        files.push(InitialFile {
            path: policy.compose_file.clone(),
            bytes: serde_json::to_vec_pretty(&compose)?,
            uid: 0,
            gid: 0,
            mode: 0o600,
        });
    }
    Ok(files)
}
fn absent(path: &Path) -> io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e),
    }
}
