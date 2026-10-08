# Verified dependency selection

Selected 2026-10-08 from the canonical crates.io registry using cargo search/info, not reference pins. Cargo.lock is committed once resolved. Rust 1.99.0 is the latest stable verified at https://blog.rust-lang.org/releases/ and the official builder is pinned to sha256:0cce0a5e0e8ba67b455257a3a02a1d99005f382748789d6464460028810f1627. The manager and host use native Rust crypto; static linkage remains a required test. Rustls 0.23.45 is the latest stable; registry 0.24.0-dev.1 is a development prerelease. All selected direct versions are in Cargo.toml. Reverify new dependencies and features from their official metadata/documentation before adoption.

Rustix 1.1.5 was verified from crates.io and https://docs.rs/rustix/1.1.5/ before selection. It provides anchored openat2/rename operations for privileged filesystem grants; unsupported kernel capability is a refusal, never an unsafe fallback.

Rustix descriptor xattr APIs were checked against the canonical upstream source and docs.rs: https://docs.rs/rustix/1.1.5/rustix/fs/fn.flistxattr.html and https://docs.rs/rustix/1.1.5/rustix/fs/fn.fsetxattr.html (2026-10-08). Metadata copy is bounded and verified; unsupported preservation refuses before target replacement.

TOML1.1.7 document API checked against canonical crate source and https://docs.rs/toml/1.1.7+spec-1.1.0/toml/ (2026-10-08): parse complete documents as Table or through toml::from_str, not Value::from_str.

Faithful Steam name normalization: unicode-normalization0.1.25 and unicode-general-category1.1.0 were independently checked by the catalog worker against canonical crates.io via cargo search on2026-10-08: https://crates.io/crates/unicode-normalization and https://crates.io/crates/unicode-general-category. NFKC/control-category cleanup matches captured prototype behavior.

Wolf stable channel was checked at2026-10-08T13:17Z from official Git and GHCR. Stable source SHA6a5053b4ebbb19f2c0f3bf1e8fbbd8babf109273; upstream default configv7 source is MIT-licensed. GHCR stable platform manifestsha256:7d6b68e851f744e2f81141587233390ef301632dcb6ae806aa53cb30a7de10fa islinux/amd64; its other index entry is an attestation (unknown/unknown), not arm64. ARM host-tool builds therefore do not establish upstream Wolf ARM streaming support; installer must refuse an incompatible image unless the operator chooses a verified compatible upstream image. The published manager's own scratch multi-architecture target is separate. Upstream default apps use rolling edge/main channels; any intentionally retained upstream channel must be documented rather than called a stable semantic release.

MQTT TLS feature correction: canonical rumqttc0.25.1 Cargo metadata shows use-rustls also activates tokio-rustls/default and an implicit AWS-LC provider. Use use-rustls-no-provider plus explicit rustls ring provider instead, matching the frozen native TLS backend and avoiding provider ambiguity. Runtime adapters initialize/configure ring explicitly.

Native HTTPS verification (2026-10-08): `tokio-rustls` 0.26.6 ([canonical package](https://docs.rs/crate/tokio-rustls/latest)), `hyper-util` 0.1.21 ([canonical package](https://docs.rs/crate/hyper-util/latest)), and `rustls-pemfile` 2.2.0 ([canonical package](https://docs.rs/crate/rustls-pemfile/latest)). TLS disables default providers and explicitly uses ring. PEM parsing retains the stable compatibility API; the upstream package now delegates to rustls-pki-types.

Reqwest 0.13.5 uses `rustls-no-provider` rather than `rustls`: verified canonical registry package `Cargo.toml` shows `rustls` enables AWS-LC; the provider-free feature allows the explicit ring provider shared by native HTTPS/SSH/MQTT. The feature still includes the platform verifier dependency; scratch HTTPS clients must use an explicit preconfigured Rustls client with embedded/private roots instead of invoking the default platform verifier.

PNG icon conversion: image 0.25.10 was freshly verified with canonical `cargo info image` on 2026-10-08 ([package metadata](https://crates.io/crates/image/0.25.10)); only JPEG and PNG features are enabled. The host uses the already verified reqwest 0.13.5 blocking feature with explicit embedded WebPKI roots and ring; redirects and environment proxies are disabled. Image decoding and aggregate request budgets are bounded; unavailable covers produce an actual neutral PNG, not JPEG bytes labeled PNG.
## Documentation builder

Verified on 2026-10-08 against the canonical PyPI releases:
[MkDocs 1.6.1](https://pypi.org/project/mkdocs/) and
[Material for MkDocs 9.7.7](https://pypi.org/project/mkdocs-material/).
MkDocs 2.0 development releases are prereleases; the site uses the latest stable
1.6.1 with the stable Material theme. Reassess compatibility and maintenance
before upgrading either package. Public docs build strictly with
`python -m mkdocs build --strict`; local planning and evidence are excluded.

## Execution coverage tools

`cargo-llvm-cov` 0.9.1 measures the pinned Rust toolchain. `coverage.py` 7.16.2
measures all release Python modules with the checked-in configuration. Browser
tests collect Chromium V8 execution; `v8-to-istanbul` 9.3.0 converts those reports
and its own measured Node execution to LCOV. Both are development-only tools;
the scratch runtime contains no Python or Node interpreter. Pins and primary
release sources are recorded in `scripts/ci/versions.json`.

## Temporary MQTT TLS dependency patch

On 2026-10-09, GitHub dependency analysis identified four advisories against the
`rustls-webpki` 0.102.8 dependency declared by the latest stable `rumqttc` 0.25.1:
GHSA-82j2-j2ch-gfr8, GHSA-xgp8-3hg3-c2mh, GHSA-965h-392x-2mh5 and
GHSA-pwjx-qhcg-rvj4. The separately resolved Rustls dependency already used
0.103.15; that did not remove the older MQTT dependency.

The workspace temporarily patches `rumqttc` to `vendor/rumqttc`. Its source is the
[canonical published 0.25.1 archive](https://crates.io/crates/rumqttc/0.25.1),
verified against the registry checksum:
`0feff8d882bff0b2fddaf99355a10336d43dd3ed44204f85ece28cf9626ab519`.
The active normalized `Cargo.toml` changes only the `rustls-webpki` requirement
from 0.102.8 to 0.103.15. Upstream runtime source remains unchanged, and the
workspace retains `use-rustls-no-provider` and the explicit ring provider.
The original manifest remains available as `Cargo.toml.orig` for provenance.
Trailing spaces in the upstream `CHANGELOG.md` and `design.md` are normalized
for repository whitespace checks; executable source remains byte-identical.
The archive's standalone `Cargo.lock` is intentionally omitted: the product root
lockfile is the only authoritative resolved graph, and the unused upstream
lockfile still records vulnerable historical dependencies. The verified original
archive is retained privately for comparison.
The published archive omitted the license file; the included Apache 2.0
`LICENSE` is copied from the archive's recorded upstream commit
`f1e9e8d558783f942993046679cdf3c8c3a3d36b`, with SHA-256
`cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`.
The vendored crate is excluded from workspace membership; its upstream tests are
not represented as product tests or product coverage.

[Upstream PR 1037](https://github.com/bytebeamio/rumqtt/pull/1037) proposes the
same dependency-series correction, but was still open when checked. Remove the
local patch and vendored source after a stable upstream release includes a
fixed WebPKI requirement. Verify the replacement's complete lock diff, MQTT TLS
and reconnect behavior, dependency audit, and both native architectures before
removing this fallback. Do not ignore or dismiss the advisories instead of
removing the vulnerable dependency.

Verification with pinned `cargo-audit` 0.22.2 and the current RustSec database
reported zero vulnerabilities in the product lockfile. The informational
`rustls-pemfile` 2.2.0 maintenance advisory remains; its documented compatibility
pin is separate from the removed WebPKI vulnerabilities. Workspace tests,
strict Clippy, native MQTT TLS certificate acceptance/refusal, and four
disposable MQTT5 reconnect/discovery/shutdown fixtures passed. These local checks
do not replace the release candidate's independent native architecture and
security jobs.
