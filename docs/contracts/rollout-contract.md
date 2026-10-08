# Canonical install and release contract

## Safe installation

The Rust host binary performs install/adopt preflight and emits a preview before writes. Record UID/GID, canonical Steam/Wolf/storage mappings, existing service and SSH configuration, backup hashes, and recovery instructions. Refuse unsupported layouts and ambiguous or mutable write-path aliases/symlinks and existing unresolved recovery. Back up every affected existing file before replacement; use atomic writes and validate sshd/sudoers before enabling policies. Rollback restores recorded files and service state. Removal preserves data by default. Docker/GPU/firewall remain prerequisites unless an explicit supported option authorizes a change. No automatic household cutover is part of development.

## Authored producer and output

Source owner: this repository. Producer: Cargo.toml/Cargo.lock, crates/, web/, Dockerfile, wolf_manager/config.yaml, installer/, scripts/ci/ and .github/workflows/{candidate,publish,pull-request,release-please}.yaml. Input: immutable candidate Git SHA with one coordinated version and locked dependencies. All Rust crates inherit workspace.package.version. The runtime Dockerfile uses FROM scratch and copies exact prebuilt static binaries without recompilation. Native startup briefly prepares an empty Supervisor /data volume, then clears supplementary groups and drops every real/effective/saved UID/GID to 1000 before starting Tokio. Existing state must already have safe ownership/modes; startup never recursively changes ownership. Entrypoint and healthcheck use exec-form native commands. Build/test environments may contain tools.

Outputs:
- ghcr.io/ryther/ha-wolf-manager:<version>, OCI index containing linux/amd64 and linux/arm64.
- wolf-manager-host-v<version>-x86_64-unknown-linux-musl.tar.gz and wolf-manager-host-v<version>-aarch64-unknown-linux-musl.tar.gz, each containing bin/wolf-manager-host.
- ha-wolf-manager-installer-v<version>.tar.gz containing install.sh, installer/templates and documented metadata.
- SHA256SUMS and release-receipt.json.

Addon config: slug ha_wolf_manager, coordinated version, arch [amd64,aarch64], image ghcr.io/ryther/ha-wolf-manager, ingress true, ingress_port 8099, panel_admin true, services [mqtt:need], init false. No published ports, host_network or privileged mode. Supervisor resolves image:<version>; aarch64 maps to OCI arm64. Both platforms must exist and pass checks. Authority: https://developers.home-assistant.io/docs/apps/publishing/ and configuration/.

## Exact candidate and receipt

An unprivileged build job produces archives and an OCI layout; test and scan those bytes. A separate trusted serialized publish job downloads the exact run artifacts, executes only trusted verifier code, verifies hashes/digests/receipt, transfers the same OCI blobs/manifests with digest preservation, uploads assets to a resumable draft, verifies remote identity, then publishes. No privileged rebuild. If transfer tooling changes bytes, repeat validation and bind the actual published digests before publication. Select and verify the transfer tool version from official sources at implementation time. Publication never executes candidate scripts with credentials.

Receipt v1 fields: schema_version:1, candidate_sha (40 hex), version, workflow_run_id, source_repository, target_triples, checks [{name,result,candidate_sha}], assets [{name,download_url,sha256,size_bytes}], image {repository,tag,index_digest,platforms:[{os,architecture,digest}]}, addon {slug,version,image_reference}, publication_state (draft/published). All identities refer to one SHA/version. Required successful check names: rust, auth-ingress, ssh-policy, persistence, mqtt, lifecycle, ui, distro-containers, static-amd64, static-arm64, addon-schema, codeql, secrets, cargo-audit, image-scan-amd64, image-scan-arm64, sonar. Each check records its scope and evidence location. Refuse missing/duplicate names, unsupported receipt version, wrong identity, malformed archives, checksum/size/digest mismatch, or absent platforms. Receipt proves pipeline identity; it is not an independent signature of an untrusted publisher.

Release Please is the sole version authority, using the simple release strategy with version.txt, CHANGELOG.md, a TOML extra-file updater for $.workspace.package.version and YAML updater for wolf_manager/config.yaml $.version. Initial coordinated public version is 0.1.0. The empty initial release manifest plus initial-version:0.1.0 represents an unreleased project. An actual compiled updater fixture verifies first-release behavior, all owned Cargo.lock package versions, inherited Cargo fields, npm metadata and add-on version. Cargo.lock predicates use @.name.value because the bundled TOML parser wraps scalar names. The latest stable Action bundles an older core library; the fixture intentionally matches that library, as recorded in scripts/ci/versions.json. Authority: https://github.com/googleapis/release-please/blob/main/docs/customizing.md and docs/manifest-releaser.md. No competing Commitizen version bump job.

## CI trust and evidence

Untrusted PR jobs get no persistent release or Sonar secrets. Trusted jobs use least privilege and job-scoped RELEASE_PLEASE_TOKEN, SONAR_TOKEN and GITHUB_TOKEN; values are never exported into evidence. Sonar waits for the exact candidate analysis/quality gate. CodeQL, secret and vulnerability gates apply to the same candidate. Verify GHCR visibility, Actions permissions and required checks when workflows exist. Optional Pages is controlled by DOCS_PAGES_ENABLED. Dependency/action/image versions are primary-source verified when selected.

Retain previous binaries/images and verified SQLite/host backups. Never blindly downgrade a newer database schema. Add-on/Docker state mounts survive upgrades. Record local, simulated, container-only and actual OS/GPU evidence separately. Verify actual GitHub checks and published artifact identities before claiming a release is available.

## Trusted acceptance authority

Downloaded receipt check claims cannot authorize publication. Trusted verifier obtains GitHub check/workflow evidence independently using read-only API credentials and an allowlist of this repository's trusted workflow IDs and check names. Require exact owner/repository, workflow file identity, workflow run ID, event push to authorized release branch or explicit trusted dispatch, full head SHA, successful completed check/job conclusions and target evidence. Reject fork/PR publication and candidate-selected workflow IDs. Persist retrieved evidence hashes with the immutable candidate receipt. Trusted publisher code is from the protected workflow revision, never candidate scripts.

Receipt assets include workflow artifact IDs and immutable build artifact hashes; validate archive entry names (no absolute paths, '..', links/devices or duplicate entries), executable target and bounded size before extraction. Candidate evidence is immutable; publication URLs and draft/published status live in a separate publication record referencing its SHA256, so a resumed draft cannot rewrite build evidence. Actual GitHub permissions and protected revision remain release gates.

## Producer artifact handoff completion

The trusted verifier independently selects exactly one artifact named `release-candidate-<fullSHA>` in the allowlisted producer run. The receipt artifact ID must match that selection. Preserve the GitHub ZIP bytes and independently verified artifact digest; its bundle contains the three versioned tar.gz archives, SHA256SUMS and a standard `oci/` layout. Finalize the receipt separately after upload to bind artifact ID/digest without recursive self-hashing. Evidence locations and claimed check results never substitute for independent run/job/artifact authority. Protected quality jobs must verify these exact candidate bytes. No trusted publisher rebuild is allowed.

## Matched offline manager recovery

A manager backup contains a consistent SQLite database, accounts, host-key pins, initialized marker and exact private SSH keys with a closed checksum manifest. TLS files and Supervisor options are external configuration. Restore preview makes no writes. Restore stages a verified complete directory and uses atomic exchange, retaining the previous directory for rollback. A mounted /data directory cannot be exchanged: refuse with unchanged bytes, restore to an alternate protected directory or volume, then explicitly remap storage while offline. Never partially copy into live data. Pending SQLite sidecars, unsupported/newer schema, corrupt keys or unsafe paths/modes require guarded recovery rather than automatic replacement.
