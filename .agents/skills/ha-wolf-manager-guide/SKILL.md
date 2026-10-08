---
name: ha-wolf-manager-guide
description: Install, configure, operate or troubleshoot HA Wolf Manager, its Home Assistant add-on, standalone dashboard and restricted Wolf PC toolkit.
---

# HA Wolf Manager

Use the repository's current guides and executable help as authority. This skill
supports using the product; it does not authorize changing unrelated Home
Assistant automations, SSH policy, containers or persistent game data.

## Choose the deployment

The same Rust manager supports Home Assistant Ingress and standalone HTTPS.
Ingress uses Supervisor-provided MQTT credentials and its actual trusted peer.
Standalone uses an administrator account, sessions and CSRF protection, with
native TLS or an explicitly trusted HTTPS proxy. Keep bootstrap tokens, TLS keys
and broker passwords in protected secret files, never URLs or browser storage.
Use the exact coordinated image version from a published release. Follow
`docs/guides/` and the deployment examples; do not substitute a development image
or interpret an ARM toolkit artifact as proof that upstream Wolf supports ARM.

## Enroll each PC

The independent `wolf-manager-host` toolkit requires no Ansible. Preview install
or adoption before applying it. Adoption must preserve the existing Wolf identity,
pairings, custom apps, Steam libraries and saves. Review the recorded paths and
retained recovery files; do not guess a layout or move state to make validation pass.

Add the PC in the dashboard, obtain its generated SSH public key and authorize
only the toolkit's forced dispatcher. Verify the host-key fingerprint through a
separate trusted channel before enrollment. The managed account has no shell,
forwarding or broad Docker/root privileges. An endpoint or host-key change needs
explicit re-enrollment; never bypass a mismatch. For a manually created key,
follow the guide's Ed25519 and restricted authorized-key instructions.

## Operate and diagnose

Work on the explicitly selected PC. Saving desired settings stages a revision;
it does not change a running game session. Start or dashboard Restart applies the
requested staged revision through the fixed service. MQTT exposes exact ON/OFF
controls for Home Assistant and voice automations; it does not expose Restart.

Game settings include ordered launch parameters, optional configured
Proton-CachyOS, FSR4 options and the diagnostic test ball. Read host capability and
catalog freshness before choosing games or assuming a setting is effective.
Catalog discovery is scoped to each PC; never erase unrelated retained topics.

After a disconnect, timeout or process restart, an operation may be
`unknown_interrupted`. Reconcile its original request IDs against the host journal.
Do not retry it or infer non-execution from the current service state. Pending
Steam restoration blocks another unsafe start. Retain the backup and changed
files if restoration reports drift; do not force a replacement.

Use bounded dashboard diagnostics and the fixed service's journal. Report safe
error codes, operation IDs, staged/running revisions and timestamps. Redact tokens,
private keys, raw RPC payloads, game/library paths and endpoint details before
sharing logs. A registry outage can use a verified cached image; it cannot start
without a compatible cached image. Docker's internal restarts do not pull images.

## Recovery and evidence

Stop the manager before offline backup, restore preview or password recovery.
Manager backups must match SQLite state, initialization/MQTT identity and enrolled
private keys. Follow `docs/contracts/recovery-contract.md`; preview is read-only
and restoration retains the old target. Restore a mounted target through a
separate verified directory and explicit remapping rather than deleting it.

Distinguish container checks from direct OS, Supervisor and GPU/Moonlight
streaming evidence. Do not claim hardware compatibility from syntax checks,
browser fixtures or a successful binary build. State the concrete observation and
remaining uncertainty when helping someone troubleshoot.
