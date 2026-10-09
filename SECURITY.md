# Security policy

## Report privately

Use the repository's **Security → Report a vulnerability** flow when private vulnerability reporting is enabled. If it is unavailable, contact the maintainer through the [GitHub profile](https://github.com/Ryther) to arrange a private channel before sending details. Do not open a public issue containing an exploit against a live installation, credentials or private state. This repository does not promise a response deadline or assert that reporting settings have already been enabled.

Include the affected commit/release and deployment mode, the relevant trust boundary, a sanitized reproduction in a disposable environment, expected/observed behavior and the practical impact. Never attach private SSH keys, broker/bootstrap tokens, passwords, manager bundles/databases, host journals containing private data or household configuration. Coordinate public disclosure after a fix and its release evidence are available.

## Scope and trust boundaries

The standalone manager requires authenticated HTTPS sessions and CSRF checks. Ingress trusts only the supported Supervisor proxy and Home Assistant administrator context. A supplied header alone is insufficient. PC management uses pinned SSH host keys and a restricted account whose fixed RPC dispatcher and narrow sudo helper are constrained by root-owned policy. Browsers and MQTT commands cannot choose arbitrary host paths or shell commands.

The manager does not require a Docker socket. Wolf itself needs privileged device/container capabilities on its PC according to the operator's chosen deployment. Protect that PC and the administrator account independently; restricted manager SSH is not isolation from a compromised local root account.

Backups contain secrets and require private custody. Failed recovery, uncertain operations or checksum mismatches must preserve evidence rather than authorize deletion/replay. See [backup and recovery](docs/guides/backup-recovery.md).

## Release evidence

This is an experimental AI-generated implementation. Passing tests, reviews or release gates does not guarantee safety or correctness. If no public release is listed, there is no published version to install. Once versions are published, prefer the newest verified release and review its notes for security fixes; older versions are not automatically supported indefinitely. An issue may also affect the current development branch, which is not a substitute for a published artifact.

Candidate checks cover dependencies, secrets, source analysis, immutable artifacts and image scans. The protected publisher verifies independently retrieved workflow/job/artifact/tag identities and transfers verified bytes without rebuilding. Weekly rescans examine the published image digest for newly disclosed HIGH/CRITICAL findings. A successful historical scan does not guarantee absence of future vulnerabilities. See the [release runbook](docs/guides/releases.md) for verification and the external settings required before publication.
