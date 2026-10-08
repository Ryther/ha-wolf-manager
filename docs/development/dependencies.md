# Verified dependency selection

Selected 2026-10-08 from the canonical crates.io registry using cargo search/info, not reference pins. Cargo.lock is committed once resolved. Rust 1.99.0 is the latest stable verified at https://blog.rust-lang.org/releases/ and the official builder is pinned to sha256:0cce0a5e0e8ba67b455257a3a02a1d99005f382748789d6464460028810f1627. The manager and host use native Rust crypto; static linkage remains a required test. Rustls 0.23.45 is the latest stable; registry 0.24.0-dev.1 is a development prerelease. All selected direct versions are in Cargo.toml. Reverify new dependencies and features from their official metadata/documentation before adoption.

Rustix 1.1.5 was verified from crates.io and https://docs.rs/rustix/1.1.5/ before selection. It provides anchored openat2/rename operations for privileged filesystem grants; unsupported kernel capability is a refusal, never an unsafe fallback.

Rustix descriptor xattr APIs were checked against the canonical upstream source and docs.rs: https://docs.rs/rustix/1.1.5/rustix/fs/fn.flistxattr.html and https://docs.rs/rustix/1.1.5/rustix/fs/fn.fsetxattr.html (2026-10-08). Metadata copy is bounded and verified; unsupported preservation refuses before target replacement.
