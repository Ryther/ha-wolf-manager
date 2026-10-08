# Canonical v1 data contract

This file replaces earlier proposal-only schema text. Authority: independent domain, auth and gap reports; source evidence manifest; confirmed decisions D01-D16. Internal engineering defaults below require tests, not additional user policy.

## Ownership and durable store

Manager owns one local SQLite database /data/manager.sqlite3. Default data directory0700 and files0600; fixed key paths /data/keys/<pc_id>/id_ed25519 and known-host trust beneath the same protected tree. No private-key bytes in SQL, HTTP, MQTT or logs. Catalog/service status are observations, not authority for root policy or desired settings.

Use integer Unix milliseconds, TEXT canonical JSON, 32-byte BLOB digests and UUID text operation IDs. pcs IDs match [a-z0-9][a-z0-9_-]{0,63}; Steam app IDs are decimal strings; parameter IDs match [A-Za-z0-9_.-]{1,64}. Canonical JSON sorts object keys and emits no insignificant whitespace; SHA256 of validated canonical desired data is the revision. Root policy remains a host-owned file, not a row editable by the browser.

## Required migration1 DDL shape

```sql
PRAGMA foreign_keys = ON;
CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, checksum BLOB NOT NULL CHECK(length(checksum)=32), applied_at_ms INTEGER NOT NULL);
CREATE TABLE administrator(id INTEGER PRIMARY KEY CHECK(id=1), password_hash TEXT NOT NULL, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL);
CREATE TABLE sessions(token_digest BLOB PRIMARY KEY CHECK(length(token_digest)=32), csrf_digest BLOB NOT NULL CHECK(length(csrf_digest)=32), created_at_ms INTEGER NOT NULL, last_seen_at_ms INTEGER NOT NULL, idle_expires_at_ms INTEGER NOT NULL, absolute_expires_at_ms INTEGER NOT NULL, revoked_at_ms INTEGER);
CREATE TABLE login_challenges(challenge_digest BLOB PRIMARY KEY CHECK(length(challenge_digest)=32), peer_ip TEXT NOT NULL, purpose TEXT NOT NULL CHECK(purpose IN ('login','bootstrap')), expires_at_ms INTEGER NOT NULL, consumed_at_ms INTEGER);
CREATE TABLE ingress_csrf_tokens(token_digest BLOB PRIMARY KEY CHECK(length(token_digest)=32), origin TEXT NOT NULL, expires_at_ms INTEGER NOT NULL);
CREATE TABLE pcs(pc_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, ssh_host TEXT NOT NULL, ssh_port INTEGER NOT NULL CHECK(ssh_port BETWEEN 1 AND 65535), ssh_user TEXT NOT NULL, host_key_algorithm TEXT, host_key_fingerprint TEXT, host_key_public TEXT, enrolled_public_key TEXT, protocol_version INTEGER NOT NULL DEFAULT 1 CHECK(protocol_version=1), created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL, archived_at_ms INTEGER);
CREATE TABLE parameters(parameter_id TEXT PRIMARY KEY, label TEXT NOT NULL, launch_options TEXT NOT NULL, description TEXT NOT NULL, built_in INTEGER NOT NULL CHECK(built_in IN (0,1)), created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL);
CREATE TABLE global_debug(id INTEGER PRIMARY KEY CHECK(id=1), test_ball INTEGER NOT NULL CHECK(test_ball IN (0,1)), desired_revision BLOB NOT NULL CHECK(length(desired_revision)=32), updated_at_ms INTEGER NOT NULL);
CREATE TABLE settings(pc_id TEXT NOT NULL REFERENCES pcs(pc_id) ON DELETE RESTRICT, app_id TEXT NOT NULL, direct_launch INTEGER NOT NULL CHECK(direct_launch IN (0,1)), proton_cachyos INTEGER NOT NULL CHECK(proton_cachyos IN (0,1)), desired_revision BLOB NOT NULL CHECK(length(desired_revision)=32), staged_revision BLOB, updated_at_ms INTEGER NOT NULL, PRIMARY KEY(pc_id,app_id));
CREATE TABLE game_parameters(pc_id TEXT NOT NULL, app_id TEXT NOT NULL, parameter_id TEXT NOT NULL REFERENCES parameters(parameter_id) ON DELETE RESTRICT, position INTEGER NOT NULL CHECK(position>=0), PRIMARY KEY(pc_id,app_id,parameter_id), UNIQUE(pc_id,app_id,position), FOREIGN KEY(pc_id,app_id) REFERENCES settings(pc_id,app_id) ON DELETE RESTRICT);
CREATE TABLE catalog_entries(pc_id TEXT NOT NULL REFERENCES pcs(pc_id) ON DELETE RESTRICT, app_id TEXT NOT NULL, observed_json TEXT NOT NULL, catalog_generation INTEGER NOT NULL, observed_at_ms INTEGER NOT NULL, PRIMARY KEY(pc_id,app_id));
CREATE TABLE operations(operation_id TEXT PRIMARY KEY, pc_id TEXT NOT NULL REFERENCES pcs(pc_id) ON DELETE RESTRICT, kind TEXT NOT NULL CHECK(kind IN ('preflight','status','apply_settings','start','stop','restart','bounded_logs')), desired_revision BLOB, state TEXT NOT NULL CHECK(state IN ('queued','running','succeeded','failed','rejected','unknown_interrupted')), submitted_at_ms INTEGER NOT NULL, started_at_ms INTEGER, completed_at_ms INTEGER, sanitized_result TEXT);
CREATE INDEX operations_pc_time ON operations(pc_id,submitted_at_ms);
CREATE INDEX sessions_expiry ON sessions(absolute_expires_at_ms,revoked_at_ms);
```

Add finite DTO/column length checks in the validated adapter. Required request bounds are in API/RPC contracts. No destructive FK cascade; PC removal is archive plus explicit owned-discovery cleanup, preserving settings, trust and history. Deleting a parameter in use returns409; built-in definitions and legacy FSR4/indicator import follow captured normalizer semantics. global_debug is one row and changes the whole-PC desired override revision. Game assignments preserve selection order; desired revision includes relevant parameter definitions and debug so changes invalidate affected PC revisions.

## Migration, bootstrap and recovery

Before opening existing data read-write, open read-only, check integrity, maximum migration version and recorded migration checksums. Newer schema, checksum mismatch or corrupt data fails without writes. One manager holds an exclusive data-root process lock; migration also holds an exclusive SQLite transaction. Backup with SQLite's consistent backup mechanism, then verify backup integrity and SHA256 manifest before migration; logical snapshot consistency is required, not an unprovable byte-identical WAL copy. Fsync backup/manifest and destination durability. Refuse unknown downgrade. Failed migration retains verified recovery bytes and never deletes source state.

Initial database seed creates default parameters/global debug from prototype golden fixtures, no administrator/password by default. Standalone bootstrap is disabled atomically when administrator is created; do not unlink operator-mounted read-only secret. A protected initialized marker prevents bootstrap from silently reappearing if an already initialized data directory loses/restores an old DB. Recovery is offline-only under the exclusive process lock; change hash and revoke all sessions without deleting PCs/keys/settings/history. Restore a verified DB/keys manifest as a matched set, never a fabricated fresh volume.

Prototype import is explicit, previewed and backed up, refuses unknown format, normalizes per captured settings_store and preserves unknown source bytes in recovery evidence. The RPC apply_settings operation stages validated overrides on the PC; actual Steam configuration is applied by the Wolf start hook. Distinguish desired, staged and effective running revision in UI/status rather than asserting that file delivery changed a live game session.

Retention: expire/revoke sessions and5-minute challenges; prune expired Ingress CSRF records. Keep terminal operations30days/max1000perPC with sanitized result<=64KiB; never prune nonterminal or unresolved unknown_interrupted automatically. Reject new mutations when unresolved operations reach100perPC pending operator reconciliation, keeping history bounded without hiding uncertain outcomes. Logs are transient<=500lines/1MiB, not a growing SQL log store.

## Host persistent state

Root-owned /etc/wolf-manager/host-policy.json is validated against runtime contract. Host transaction manifest under its configured backup_root/<UUID> records version, policy/PC identity, staged revision, each source/destination mapping, preimage digest, ownership/mode, transaction phase and restore result. Before Steam mutation require quiescent target, regular non-hardlinked files within canonical granted roots and a verified fsynced backup. Preserve recovery-pending manifests across crashes; refuse a new startup until required restore is resolved. Never remove libraries, pairing or stale app-profile state as automatic catalog cleanup.

## Journal/recovery completion

Add operations.request_digest BLOB (32 bytes), dispatch_phase TEXT NOT NULL DEFAULT 'not_dispatched' constrained to not_dispatched/sending/sent, and resolution_json TEXT. Set sending durably before network submission; a crash at sending counts as possibly dispatched. Reconciliation stores journal identity/phase/evidence timestamp and never overwrites uncertainty with guessed success.

Steam transaction manifests additionally record postimage SHA256 for each changed target. Restore only if current target equals the recorded postimage (or already equals preimage). On drift, preserve both current bytes and verified preimage, record conflict and recovery_pending, refuse overwriting and block new startup. No automatic whole-file overwrite of legitimate subsequent changes. Manual recovery previews the owned-field difference and preserves a copy of conflicting bytes before an operator-approved restore; it is not a generic force option in RPC. Rollback does not bypass drift checks.

Adoption may resolve an existing library-root alias once in the recorded preview/mapping to a canonical grant. Mutable targets and subsequent traversal must remain free of symlinks/hardlinks/aliases. Rollout's general alias refusal applies to ambiguous or mutable write paths, not that explicitly verified read-root mapping.

## Parent and child RPC identity (authoritative completion)

Add operation_rpc_requests: request_id TEXT PRIMARY KEY (UUID), operation_id TEXT NOT NULL REFERENCES operations(operation_id) ON DELETE RESTRICT, pc_id TEXT NOT NULL REFERENCES pcs(pc_id) ON DELETE RESTRICT, kind TEXT NOT NULL, ordinal INTEGER NOT NULL CHECK(ordinal>=0), canonical_request_sha256 BLOB NOT NULL CHECK(length(canonical_request_sha256)=32), dispatch_phase TEXT NOT NULL CHECK(dispatch_phase IN ('not_dispatched','sending','sent')), observed_phase TEXT, safe_result TEXT, resolution_json TEXT, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL, UNIQUE(operation_id,ordinal). Every preparatory stage and primary lifecycle RPC has a distinct generated UUID durably inserted before submission; manager operation_id identifies the parent only, never implicitly a host request. Parent request_digest/dispatch_phase are summary projections and cannot substitute for this table.
