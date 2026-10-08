# Trusted candidate verifier

`verify_candidate.py` uses only Python's standard library. It verifies downloads;
it never extracts archives, executes candidate code, rebuilds artifacts, changes
a release, uploads images or reads household state.

Run local adversarial tests:

```sh
python -m unittest discover -s tests/release -v
```

The protected publisher must invoke a verifier from its trusted revision, not a
candidate checkout. Supply all expected identity arguments independently from
an allowlisted event/run and trusted coordinated release metadata. Never copy
SHA/version/run/workflow expectations out of the receipt you are validating.

```sh
python /trusted/scripts/ci/verify_candidate.py \
  --receipt /candidate/release-receipt.json \
  --artifacts /candidate/preserved-zip-downloads \
  --repository Ryther/ha-wolf-manager \
  --sha "$TRUSTED_CANDIDATE_SHA" \
  --version "$TRUSTED_RELEASE_VERSION" \
  --run-id "$TRUSTED_RUN_ID" \
  --workflow-id "$ALLOWLISTED_WORKFLOW_ID" \
  --workflow-path .github/workflows/candidate.yaml
```

`GITHUB_TOKEN` must be a job-scoped read-only authority credential. The tool
retrieves workflow/run/jobs/artifact metadata directly from api.github.com with
the verified API version 2026-03-10. Redirects are refused, preventing forwarded
API credentials from leaving that origin. CLI failures emit a fixed refusal
message; no raw API errors or credential values are printed.

## Producer handoff

The allowlisted successful candidate run must expose one immutable workflow
artifact named `release-candidate-<full-40-character-SHA>`. The verifier selects
that unique name independently through the run-artifact API. Preserve its
original GitHub ZIP download as `<artifact-id>.zip`, without re-zipping it.
All four receipt asset entries reference that artifact ID and ZIP SHA256.

The ZIP contains these top-level versioned release assets:

- `wolf-manager-host-v<version>-x86_64-unknown-linux-musl.tar.gz`
- `wolf-manager-host-v<version>-aarch64-unknown-linux-musl.tar.gz`
- `ha-wolf-manager-installer-v<version>.tar.gz`
- `SHA256SUMS`, containing exactly the three sorted archive checksum lines

It also contains `oci/oci-layout`, `oci/index.json` and OCI content-addressed
blobs under `oci/blobs/sha256/`. The top-level OCI layout index references one
OCI image index containing exactly linux/amd64 and linux/arm64 manifests. Every
reachable index/manifest/config/layer digest and size is checked locally.

Finalize `release-receipt.json` separately **after** artifact upload: embedding a
receipt that includes its containing ZIP hash would create a circular hash.
Receipt assets add `workflow_artifact_id` and `workflow_artifact_sha256`; checks
add nonempty `scope` and `evidence_location`. Check evidence locations use
`artifact:<artifact-id>/<safe-relative-bundle-path>` and must resolve to bounded
nonempty files in the verified ZIP. Returned evidence includes their SHA256.

Each canonical required check is an explicit successful job name in the same
allowlisted run/attempt. No skipped, suffixed matrix alias, missing, duplicate,
foreign-SHA or failed job substitutes for that name. Protected check jobs must
actually verify the exact bundle subjects they attest; receipt strings and
candidate-authored reports are not independent quality-gate authority.

Host archives allow only the executable `bin/wolf-manager-host` plus optional
`bin/` directory. ELF target machine, bounds, executable load segment, absence
of PT_INTERP and absence of DT_NEEDED are verified. Installer archives contain
executable POSIX `install.sh`, `installer/templates/**`, optional directory
entries and optional `installer/metadata.json`. No links, devices, traversal,
duplicate names, control characters or setuid/setgid entries are accepted.

Limits are 8 MiB JSON, 10,000 archive members, 256 MiB per file and 1 GiB per
bundle/expanded archive. These are deliberate refusal defaults; change them
only with bounded tests and a documented producer requirement.

## Publication boundary

The output binds receipt SHA256, independent API-evidence SHA256, check evidence
hashes, downloaded ZIP SHA256 and OCI digests. Retain that output beside the
immutable receipt. A separate publication record references receipt SHA256;
resuming a draft must not rewrite the original candidate evidence.

Protected workflows and byte-transfer tooling are described below. Actual
GitHub checks, remote identity, credentials, branch/environment rules and
release behavior must be verified before publication is enabled.
Synthetic ELF/API fixtures prove parser/refusal logic, not compiled executable
startup, actual security scans or live GitHub/GHCR publication.

## Implemented workflow commands

`candidate.yaml` runs only on trusted `main` pushes or dispatches. Native
`static-amd64` and `static-arm64` jobs compile both binaries once using the
pinned musl builder. `native-build.sh` validates ELF linkage and versions and
packages prebuilt bytes through the root `FROM scratch` Dockerfile. Buildx
exports OCI and a local smoke-test image from the same build operation.
`producer.py assemble` creates reproducible host/installer archives and merges
platform manifests without changing their bytes. `check_subject.py` seals and
verifies the full subject file map, host ELFs, archive checksums and OCI graph.

Every subsequent quality job first receives the uniquely named subject
artifact, verifies its original ZIP against GitHub's digest and checks that the
source checkout and full subject manifest match the same SHA. Independent
named jobs run Rust tests/coverage, authentication, SSH policy, persistence,
MQTT broker fixtures, lifecycle, Chromium UI fixtures, seven disposable Linux
container families, add-on schema, Cargo audit, Gitleaks, CodeQL and per-platform
Trivy scans. CodeQL supports Rust with `build-mode: none`, and also analyzes
JavaScript/TypeScript, Python and Actions. The SARIF gate refuses high/critical
security findings. Trivy's scratch-image scan complements Cargo.lock auditing;
it does not substitute for dependency analysis of statically compiled Rust.

The add-on schema is the pinned community app schema, with its upstream license
retained. Container checks establish restricted SSH/policy and syntax behavior,
not direct-OS, systemd PID1, GPU or streaming certification. Browser API fixtures
remain simulated. Local verifier tests use synthetic ELF and independent API
fixtures; they do not certify native ARM execution or remote publication.

`sonar` imports actual workspace LCOV and Clippy reports, waits for the quality
gate, then independently binds the task's analysis ID to the full SHA and
requires imported nonempty coverage. Concurrent newer project analyses cause a
refusal rather than borrowing their measures. Quality gate policy must be
configured and verified in the actual Sonar project.

`candidate-receipt` collects successful evidence, uploads the final immutable
bundle, downloads its original ZIP and finalizes the separate receipt against
actual artifact metadata. The first producer run does not need a pre-existing
workflow-ID variable; the publisher independently requires an administrator's
allowlisted ID. `pull-request.yaml` runs the corresponding 16 checks with read
permissions and no Sonar or release secret references. Its artifacts cannot
authorize publication.

## Protected publication configuration

`release-please.yaml` uses `RELEASE_PLEASE_TOKEN` and the root coordinated
configuration to create release PRs and tagged drafts. `publish.yaml` checks out
`github.workflow_sha`, never the producer SHA, and serializes publication. Its
first job has read permissions only. The environment-protected publication job
repeats the verification before granting its token to the closed transfer code.
Candidate archive contents are never executed with publication credentials.

Configure and independently verify these settings before enabling publication:

- Secrets: `RELEASE_PLEASE_TOKEN`, `SONAR_TOKEN`.
- Variables: `SONAR_ORGANIZATION`, `SONAR_PROJECT_KEY`, numeric
  `CANDIDATE_WORKFLOW_ID`, and finally `RELEASE_PUBLISH_ENABLED=true`.
- Protected `main`, required independent checks and the `release` environment.
- Sonar Rust coverage/quality policy and GHCR package permission/public visibility.

The publisher retrieves run identity, coordinated version, draft release and
resolved tag commit independently. Unrelated main pushes without a release
draft are ineligible. A tag on another commit, failed/missing job, fork/PR run,
unallowlisted workflow or altered archive fails closed. Registry requests are
restricted to the fixed GHCR repository; manifests and blobs retain their raw
bytes and remote digests are checked. Existing version tags or release assets
with different identities are refused; no remote deletion occurs. Matching
partial draft assets may be resumed. Receipt bytes remain immutable, with
separate verification and publication records. Published releases are never
modified by automatic replay.

`versions.json` records current primary-source selections. Local workflow lint,
parser tests and scanner runs are useful evidence, but actual successful GitHub
checks, native ARM runs, Sonar and release/GHCR identities remain release gates.

The add-on metadata gate also executes the actual Release Please updaters and
manifest strategy against isolated GitHub-history fixtures. The latest stable
action v5.0.0 bundles core 17.6.0; standalone core 17.11.2 is newer. The fixture
intentionally matches the selected action's committed dependency version.
An empty initial manifest with `initial-version: 0.1.0` proposes the first
0.1.0 release. A fabricated prior 0.1.0 manifest instead proposes 0.2.0. The
Cargo.lock updater must filter tagged TOML scalar values (`@.name.value`),
otherwise it silently matches zero entries. Root/npm lock/add-on updates and
all unchanged third-party lock entries are verified in memory.

```sh
sh scripts/ci/release-metadata.sh
```

## Rust coverage ingestion gate

The Sonar job imports the frozen Rust job's LCOV and Clippy JSON reports. Automatic Clippy execution is disabled to avoid duplicate imported findings. The receiver requires the completed task, exact source revision, OK quality gate and unchanged latest analysis. Project-wide coverage alone is insufficient in this mixed Rust/JavaScript/Python project.

`sonar_gate --rust-lcov <file>` parses production Rust `crates/*/src/**/*.rs` records and verifies each file's `lines_to_cover` and `uncovered_lines` through paginated `/api/measures/component_tree` results. Every expected file must match the LCOV counts, and at least one Rust line must actually be covered. Missing Rust import, all-zero reports, duplicate records, mismatched metrics or a concurrent analysis fail closed. The retained evidence includes the LCOV digest, Rust file count and covered-line count. This is a strict import check, not a replacement for the configured quality gate's coverage threshold.

The [official Rust analyzer documentation](https://docs.sonarsource.com/sonarqube-cloud/advanced-setup/languages/rust/) documents LCOV/Clippy support and the automatic-Clippy setting. The [upstream measure API implementation](https://github.com/SonarSource/sonarqube/blob/master/server/sonar-webserver-webapi/src/main/java/org/sonar/server/measure/ws/ComponentTreeAction.java) defines paginated file-level measures. These interfaces were reviewed on 2026-10-08. Synthetic API tests prove local rejection/acceptance behavior; the first real Sonar analysis must still confirm server ingestion and permissions.
