# Verify and publish a release

[Documentation home](index.md) · [Back up before upgrading](backup-recovery.md)

This runbook describes the implemented pipeline. It does not assert that a release, image, GitHub protection rule or Sonar analysis is already available. Local syntax checks and synthetic verifier tests cannot replace successful remote checks on the exact release commit.

## Prepare the external gates

An administrator must configure and independently verify the following before enabling publication. Do not put secret values in issue reports, workflow inputs, repository variables or command arguments.

| Setting | Purpose |
| --- | --- |
| Secret `RELEASE_PLEASE_TOKEN` | Allows the coordinated release workflow to create release PRs and tagged drafts in this repository. Use a repository-scoped identity with the required contents/PR permissions. |
| Secret `SONAR_TOKEN` | Authenticates trusted main-branch analysis in the configured Sonar project. PR workflows do not receive it. |
| Variables `SONAR_ORGANIZATION`, `SONAR_PROJECT_KEY` | Select the actual project whose Rust report import and quality-gate policy must be verified. |
| Variable `CANDIDATE_WORKFLOW_ID` | Numeric GitHub ID of `.github/workflows/candidate.yaml`, independently confirmed through repository workflow metadata. A receipt cannot select its own trusted workflow. |
| Environment `release` | Protects the publication job with the repository's chosen approval and main-branch rules. Declaring the environment in YAML alone does not configure protection. |
| Variable `RELEASE_PUBLISH_ENABLED=true` | Enables the protected publisher and scheduled published-image rescan. Set this last, after the other gates are verified. |

Protect `main` and require the 16 checks provided by the read-only PR workflow. Sonar is a seventeenth **publication** check on trusted main candidates; it is absent from PR workflows and should not be required as a PR status. Verify GitHub Actions permissions, native ARM runner availability, the release identity's GHCR package permissions and public visibility. An add-on cannot pull a private image without separate access arrangements.

Configure the Sonar project's intended coverage/security policy and disable automatic analysis if it would race the CI analysis. Rust LCOV, actual browser/Node JavaScript LCOV, Python coverage XML and pre-generated Clippy reports are imported by the candidate job. The receiver checks actual per-file metrics for all three languages against the frozen reports, the exact commit and unchanged analysis ID, and refuses combined project coverage below 80%. Generic positive project coverage cannot substitute for verified report ingestion. A real first run must confirm project permissions and importer behavior.

The [workflow source](https://github.com/Ryther/ha-wolf-manager/tree/main/.github/workflows), [receiver documentation](https://github.com/Ryther/ha-wolf-manager/blob/main/scripts/ci/README.md) and [rollout contract](../contracts/rollout-contract.md) define the detailed trust boundary.

Ensure the Sonar project's main branch is named `main`, matching this repository.
The exact-analysis verifier queries that principal branch; an analysis on a
short-lived branch with the same name cannot replace it. If an empty default
`master` conflicts with an already analyzed short-lived `main`, a project
administrator must retain the diagnostic reports, remove only the conflicting
Sonar analysis branch and rename the empty principal branch to `main`. This does
not change GitHub branches. Follow [SonarCloud's branch administration guidance](https://community.sonarsource.com/t/unable-to-update-the-long-lasting-branch-of-my-repo/179587),
then dispatch a complete fresh candidate rather than mixing rerun evidence.

## Let Release Please coordinate metadata

Use conventional commits and review the PR created by **Coordinated release metadata**. Release Please updates the canonical version, workspace/package metadata, owned Cargo.lock entries, npm lock metadata and add-on version together. Do not bump individual services or independently run a version command.

For this initial repository, the empty release manifest and `initial-version: 0.1.0` prepare a first `0.1.0` release rather than inventing an earlier published release. Review changelog, manifest and every version update before merging the release PR. The configured release is a **draft**, and its `v<version>` tag must resolve to the exact commit of the successful candidate. Tag creation does not authorize publication.

An ordinary main push also builds a candidate but is not a publication request unless a matching coordinated draft/tag exists. Never move an existing release tag to make a failed identity check pass.

## Inspect the exact candidate

**Release candidate** builds the manager and host tools once on native `amd64` and `arm64` runners using explicit musl targets. It rejects an architecture mismatch and dynamic ELF dependencies. The scratch runtime image copies these prebuilt binaries; the producer checks their versions and native execution. These checks do not certify a GPU, directly installed OS, Home Assistant session or Moonlight stream.

The candidate subject includes both platform OCI manifests/blobs, versioned host archives, the offline installer archive and SHA256 sums. Each quality job retrieves and verifies the same subject and exact source SHA before running. The following independent checks must all succeed:

| Check | Evidence scope |
| --- | --- |
| `rust` | Workspace formatting, Clippy, executable tests and LCOV; release-tooling regressions |
| `auth-ingress` | Authentication, HTTP, Supervisor bootstrap and runtime fixtures |
| `ssh-policy` | SSH adapter, restricted dispatcher and root policy fixtures |
| `persistence` | Manager bundles and host state/transaction/quiescence fixtures |
| `mqtt` | Manager/host protocol tests using a disposable broker |
| `lifecycle` | Coordinator, host lifecycle/hooks/generated apps and journal/RPC fixtures |
| `ui` | Chromium browser tests against explicitly simulated API fixtures |
| `distro-containers` | Seven distribution container fixtures, within their declared scope |
| `static-amd64` | Native musl binaries, ELF validation and scratch packaging |
| `static-arm64` | Native ARM64 musl binaries, ELF validation and scratch packaging |
| `addon-schema` | Add-on schema and coordinated metadata validation |
| `codeql` | Rust, JavaScript/TypeScript, Python and Actions source analysis |
| `secrets` | Redacted Gitleaks scan of source history |
| `cargo-audit` | Cargo dependency advisory scan |
| `image-scan-amd64` | HIGH/CRITICAL scan of the exact candidate OCI platform |
| `image-scan-arm64` | HIGH/CRITICAL scan of the exact candidate OCI platform |
| `sonar` | Exact-SHA quality gate and verified Rust LCOV ingestion |

A check's receipt entry is a claim, not authority. The trusted receiver independently retrieves GitHub's same-run job identities and conclusions, allowlisted workflow/event/repository metadata and unique original ZIP artifact digest. The producer uploads `release-candidate-<full-SHA>` first, then finalizes a separate `release-receipt-<full-SHA>` binding the immutable ZIP. Archive traversal, aliases, links, duplicate/malformed entries, unexpected payloads and invalid image/ELF identities are refused.

Review actual logs and retained reports. Do not replace a failed required check with a passing mock, a status on another SHA or a new image built after the checks. Source/browser/container fixture success must retain its stated compatibility limits.

## Publish without rebuilding

**Publish verified candidate** can run after a successful main candidate, or be dispatched manually with its existing `run_id`. Select `main` as the publisher workflow branch. Its read-only verification job checks eligibility; the protected `release` job repeats verification before transferring bytes.

The publisher executes its own trusted workflow revision, never candidate archive content. It resolves the coordinated version, draft and tag independently; a fork/PR producer, wrong tag commit, missing/failed check, ambiguous artifact or altered ZIP is rejected. It uploads the original verified blobs/manifests to `ghcr.io/ryther/ha-wolf-manager` and original versioned archives/evidence to the existing GitHub draft. It performs no compilation or image rebuild. Only after remote identities and anonymous image access match does it make that draft public.

Review the published `release-receipt.json`, `release-verification.json` and `publication.json`, including full source SHA, run ID, checksums/sizes, image index digest and both platform digests. Use the digest from that verified record for standalone deployment. The add-on uses the coordinated version tag, so keep GHCR writers restricted and version tags immutable. Registry writes require external protection; this script cannot create a registry-wide atomic tag policy.

Published releases are not mutated by automatic replays. Matching partial draft assets can be resumed; conflicting asset/tag identities refuse publication without remote deletion. Preserve the original evidence when troubleshooting.

## Resume a delayed or failed pipeline

If the candidate finishes before Release Please has created its draft, the publisher correctly reports ineligible. Once the draft/tag exists and resolves to that exact candidate SHA, manually dispatch the publisher with that successful candidate run ID. Do not rebuild simply to make the draft appear.

If artifact-upload jobs fail on a rerun because the same immutable names already exist, dispatch a **new Release candidate run on the same main SHA**. Let every required check complete in that new run; do not delete or overwrite the prior evidence and do not mix checks from different runs. Expired artifacts require a new complete candidate run, not a replacement receipt over invented bytes.

For an unsuccessful transfer, inspect protected job logs and remote identities. Re-dispatch the publisher against the same verified candidate only when the recorded draft remains eligible. A published release, conflicting tag or unverifiable remote asset requires investigation rather than forced replacement.

## Rescan the published bytes

**Rescan published image** is scheduled for Mondays at 06:31 UTC and can be dispatched manually. With publication enabled, it retrieves the latest public release's `publication.json`, validates version/platform identities and resolves the immutable image index digest. It scans that same published image on both `amd64` and `arm64`, failing on HIGH/CRITICAL findings and retaining `published-image-rescan-<run-id>` reports for 30 days.

The rescan does not rebuild, alter the image or republish a release. Investigate new findings, fix affected source/dependencies and release a new complete candidate through the normal gates. A scheduled scan cannot run successfully before a public release record and accessible image exist; verify the first real execution explicitly.

## First GHCR package visibility

[GitHub defaults a newly uploaded GHCR package to private](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry).
The publisher independently requests an anonymous pull token and verifies the
exact version tag, root/platform manifests and each config/layer identity.
Publisher credentials never substitute for public access. If that check fails,
the uploaded image and release assets remain available for verification while
the GitHub release stays a draft.

In the account's **Packages** page, open **ha-wolf-manager**, choose **Package
settings**, and change visibility to **Public**. GitHub documents this as an
irreversible visibility change; it is part of publishing the public product.
Then rerun the protected publisher with the same successful candidate run ID.
It verifies the existing immutable bytes and completes publication without
rebuilding or rebinding tags. Confirm anonymous pulls for both architectures.
