use wolf_manager_host::install::{
    render_privilege_templates, validate_public_key, validate_static_binary,
};
const KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA operator";
#[test]
fn fixed_key_options_and_minimal_sudo_are_exact() {
    let key = validate_public_key(KEY).unwrap();
    assert!(
        key.starts_with(
            "restrict,command=\"/usr/libexec/wolf-manager/ssh-dispatcher\" ssh-ed25519 "
        )
    );
    let templates = render_privilege_templates(&[KEY.into()]).unwrap();
    let (_, sudo, mode) = templates
        .iter()
        .find(|(p, _, _)| p == "/etc/sudoers.d/wolf-manager")
        .unwrap();
    assert_eq!(*mode, 0o440);
    assert!(
        String::from_utf8_lossy(sudo)
            .contains("NOSETENV: /usr/libexec/wolf-manager/wolf-host-root \"\"")
    );
    let (_, _, mode) = templates
        .iter()
        .find(|(p, _, _)| p == "/etc/ssh/authorized_keys.d/wolf-manager")
        .unwrap();
    assert_eq!(*mode, 0o644);
}
#[test]
fn malicious_public_key_options_and_lines_refuse() {
    for key in [
        format!("command=\"sh\" {KEY}"),
        format!("{KEY}\n{KEY}"),
        "ssh-rsa nonsense".into(),
        "ssh-ed25519 AAAA".into(),
    ] {
        assert!(validate_public_key(&key).is_err());
    }
}
fn elf() -> Vec<u8> {
    let mut b = vec![0u8; 128];
    b[..4].copy_from_slice(b"\x7fELF");
    b[4] = 2;
    b[5] = 1;
    b[6] = 1;
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    b[18..20].copy_from_slice(&62u16.to_le_bytes());
    b[32..40].copy_from_slice(&64u64.to_le_bytes());
    b[54..56].copy_from_slice(&56u16.to_le_bytes());
    b[56..58].copy_from_slice(&1u16.to_le_bytes());
    b[64..68].copy_from_slice(&1u32.to_le_bytes());
    b
}
#[test]
fn static_matching_elf_accepts_and_interpreter_or_wrong_arch_refuses() {
    let mut b = elf();
    validate_static_binary(&b, "x86_64").unwrap();
    assert!(validate_static_binary(&b, "aarch64").is_err());
    b[64..68].copy_from_slice(&3u32.to_le_bytes());
    assert!(validate_static_binary(&b, "x86_64").is_err());
    assert!(validate_static_binary(b"not ELF", "x86_64").is_err());
}
#[test]
fn input_identity_refuses_byte_drift_and_replacement_without_writes() {
    use wolf_manager_host::install::FileIdentity;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("source");
    std::fs::write(&path, b"original bytes").unwrap();
    let identity = FileIdentity::capture(&path).unwrap();
    identity.verify(&path).unwrap();
    std::fs::write(&path, b"operator changed bytes").unwrap();
    assert!(identity.verify(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"operator changed bytes");
    let new = temp.path().join("new-source");
    std::fs::write(&new, b"original bytes").unwrap();
    std::fs::rename(&new, &path).unwrap();
    assert!(identity.verify(&path).is_err());
}
