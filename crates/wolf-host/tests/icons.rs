use std::{
    io,
    os::unix::fs::{PermissionsExt, symlink},
    time::Duration,
};
use wolf_core::AppId;
use wolf_manager_host::icons::{self, Fetch};
struct Offline;
impl Fetch for Offline {
    fn get(&mut self, _: &AppId, _: Duration) -> io::Result<Vec<u8>> {
        Err(io::Error::other("offline"))
    }
}
#[test]
fn jpeg_is_converted_to_actual_png_and_decode_limits_refuse() {
    let image = image::RgbImage::from_pixel(2, 2, image::Rgb([90, 100, 110]));
    let mut jpeg = Vec::new();
    image::codecs::jpeg::JpegEncoder::new(&mut jpeg)
        .encode_image(&image)
        .unwrap();
    let png = icons::convert(&jpeg).unwrap();
    assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));
    assert_eq!(image::load_from_memory(&png).unwrap().width(), 2);
    assert!(icons::convert(&vec![0; 4 * 1024 * 1024 + 1]).is_err());
    let large = image::RgbImage::new(2049, 1);
    let mut bytes = Vec::new();
    image::codecs::jpeg::JpegEncoder::new(&mut bytes)
        .encode_image(&large)
        .unwrap();
    assert!(icons::convert(&bytes).is_err());
}
#[test]
fn offline_cache_is_png_stable_and_aliases_or_modified_files_refuse() {
    let temp = tempfile::tempdir().unwrap();
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    let app = AppId::new("10").unwrap();
    let paths = icons::cache_with(
        temp.path(),
        uid,
        gid,
        std::path::Path::new("/mapped/wolf"),
        std::slice::from_ref(&app),
        &mut Offline,
    )
    .unwrap();
    assert_eq!(paths[&app], "/mapped/wolf/.ha-wolf-manager-icons/10.png");
    let path = temp.path().join(".ha-wolf-manager-icons/10.png");
    let first = std::fs::read(&path).unwrap();
    assert!(first.starts_with(b"\x89PNG\r\n\x1a\n"));
    icons::cache_with(
        temp.path(),
        uid,
        gid,
        std::path::Path::new("/mapped/wolf"),
        std::slice::from_ref(&app),
        &mut Offline,
    )
    .unwrap();
    assert_eq!(first, std::fs::read(&path).unwrap());
    std::fs::write(&path, b"unknown data").unwrap();
    assert!(
        icons::cache_with(
            temp.path(),
            uid,
            gid,
            std::path::Path::new("/mapped/wolf"),
            &[app],
            &mut Offline
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"unknown data");
    let alias = tempfile::tempdir().unwrap();
    symlink(
        temp.path().join(".ha-wolf-manager-icons"),
        alias.path().join(".ha-wolf-manager-icons"),
    )
    .unwrap();
    assert!(
        icons::cache_with(
            alias.path(),
            uid,
            gid,
            std::path::Path::new("/mapped"),
            &[],
            &mut Offline
        )
        .is_err()
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
}
#[test]
fn compose_mapping_is_explicit_and_ambiguous_or_unmapped_refuse() {
    let root = std::path::Path::new("/authorized/wolf");
    let compose = serde_json::json!({"services":{"wolf":{"container_name":"wolf","volumes":["/authorized/wolf:/custom/wolf:rw"]}}});
    assert_eq!(
        icons::container_root(&compose, root, "wolf").unwrap(),
        std::path::Path::new("/custom/wolf")
    );
    assert!(icons::container_root(&serde_json::json!({}), root, "wolf").is_err());
    let ambiguous = serde_json::json!({"services":{"wolf":{"container_name":"wolf","volumes":["/authorized/wolf:/custom/wolf:rw","/authorized/wolf:/other:rw"]}}});
    assert!(icons::container_root(&ambiguous, root, "wolf").is_err());
}
#[test]
fn submount_cannot_shadow_the_authorized_png_cache() {
    let compose = serde_json::json!({"services":{"wolf":{"container_name":"wolf","volumes":["/authorized/wolf:/etc/wolf:rw","/other:/etc/wolf/.ha-wolf-manager-icons:rw"]}}});
    assert!(
        icons::container_root(&compose, std::path::Path::new("/authorized/wolf"), "wolf").is_err()
    );
}
