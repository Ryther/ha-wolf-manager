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

No workflow or transfer tool is wired here. The integrator must implement and
verify protected producer/check/publisher workflow commands, same-byte OCI
transfer, remote asset/digest identity, quality/security checks, credentials,
branch rules and actual GitHub release behavior before publication is enabled.
Synthetic ELF/API fixtures prove parser/refusal logic, not compiled executable
startup, actual security scans or live GitHub/GHCR publication.
