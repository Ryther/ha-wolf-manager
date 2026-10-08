# Canonical v1 runtime and host command contract

One Rust workspace: crates/wolf-core pure protocol1/IDs/settings/DTO/errors; crates/wolf-manager owns auth/api/storage/ssh/mqtt/operations/logs; crates/wolf-host owns policy/catalog/steam_vdf/config_transaction/backup/wolf_lifecycle/mqtt/rpc. Package/binaries ha-wolf-manager and wolf-manager-host; shared packagewolf-core. Authored web assets are embedded/served by manager. No omitted omnibus Python-to-Rust port.

## Manager

Non-root process with /data0700, protected keys/SQLite, bounded task/queue and per-PC mutation serialization. Other PCs progress independently. Operation lifecycle queued/running/succeeded/failed/rejected/unknown_interrupted; restart changes nonterminal to unknown_interrupted and never retries mutations automatically. Status polling/read-only reconnection is allowed; explicit operator reconciliation precedes another mutation when outcome is uncertain.

Native Rust SSH/TLS adapter behind narrow traits. russh/rustls are primary-source candidates; current stable versions/features must be verified and a locked amd64/aarch64-musl spike must pass before adoption. No OpenSSH/OpenSSL dynamic program/runtime in manager scratch. Static host executable may invoke fixed host systemctl/docker/journalctl only inside the root-owned configured service/helper scope, never UI-supplied commands.

Exec-form scratch healthcheck is /usr/local/bin/ha-wolf-manager healthcheck. It validates protected ready marker containing PID/start identity/heartbeat updated by service, no HTTP peer/auth bypass needed. Main shutdown stops admissions, drains bounded work, preserves uncertain/recovery state, publishes availability offline and exits cleanly. Missing OS shell/CAstore is expected; TLS roots/optional private CA support and secret-file precedence are explicit configuration contracts.

## Installed paths and privilege boundary

- /usr/local/bin/wolf-manager-host root:root0755 native binary.
- /usr/libexec/wolf-manager/ssh-dispatcher root:root0755 fixed wrapper/entrypoint.
- /usr/libexec/wolf-manager/wolf-host-root root:root0755 fixed no-argument helper entrypoint.
- /etc/wolf-manager/host-policy.json root:root0644; policy/parents are non-writable to managed account.
- /etc/ssh/authorized_keys.d/wolf-manager root:root0644; root-controlled authorization.
- /etc/ssh/sshd_config.d/90-wolf-manager.conf root:root0644.
- /etc/sudoers.d/wolf-manager root:root0440.
- Root-owned service units/drop-ins and /etc/wolf-manager/state backup paths; brokersecret file readable only by selected catalog service identity.

Dedicated system account wolf-manager has locked password, shell/bin/sh, home/nonexistent(no directory), no Docker/journal/admin supplementary groups. OpenSSH runs ForceCommand through login shell-c; nologin would break the allowed command. sshd MatchUser wolf-manager: AuthenticationMethods publickey; PasswordAuthentication no; KbdInteractiveAuthentication no; PermitTTY no; DisableForwarding yes; PermitUserRC no; AuthorizedKeysFile fixed root file; ForceCommand fixed ssh-dispatcher. Each key adds restrict,command="/usr/libexec/wolf-manager/ssh-dispatcher". No interactive access is authorized.

Exact sudo entry: wolf-manager ALL=(root) NOPASSWD: NOSETENV: /usr/libexec/wolf-manager/wolf-host-root "". Validate with visudo-c; empty quoted argument list means no args, no wildcards. Dispatcher accepts SSH_ORIGINAL_COMMAND exactlywolf-manager-rpc-v1, reads65537bytes to reject input>65536, parses closed DTO then invokes only sudo-n /usr/libexec/wolf-manager/wolf-host-root with validated stdin and no args. Root helper repeats all schema/policy validation and refuses non-root invocation. Wrappers exec fixed binary/subcommands and forward no attacker command/path/env. Validate sshd-t before activation and preserve existing unrelated SSH policy.

## Root policy and RPC

The closed root policy fields and installation inputs are defined in [host adapter contracts](../development/host-adapter-contract.md). Root owns all privileged policy, service and Compose inputs; requests cannot override them. Adoption records canonical storage mappings once. Mutable traversal rejects aliases, special files, hard links and unauthorized ownership.

RPC request: {version:1,request_id:UUID,pc_id,operation,payload}. Unknown/missing/extra fields/version/pcid mismatch reject before mutation. Reply: {version:1,request_id,pc_id,ok,result,error}; error is controlled code/message, result matches operation. SSH deadlines are 30 seconds for read-only calls, 60 seconds for staging and 810 seconds for start/stop/restart; the privileged dispatcher allows 800 seconds; manager timeout produces unknown outcome rather than blind retry. Output<=1MiB. Root serializes mutations under owned lock and records request_id/result to prevent repeated non-idempotent transaction execution.

Allowed operations/payload:

- preflight {} -> capabilities/version/policy identity/readiness and safe prerequisite reasons.
- status {} -> systemd state, configured Wolf container state/restartcount/exit evidence, staged and effective running revision, recovery_pending.
- apply_settings {settings:full validated legacy-compatible overrideDTO,revision:SHA256} -> atomically stage override file, no live restart or Steam mutation; verify hash and backuppriorbytes. Source behavior: captured wolf-install-game-config writes validated override JSON only.
- start {expected_staged_revision:SHA256} -> verify the requested staged revision and absence of pending recovery first; an already active service succeeds only with a running container and a known running revision, without pull/apply; inactive starts the fixed service and verifies the requested running revision. Manager stages desired settings first when needed.
- stop {} -> idempotent fixedservice stop and restore hook; preserve pending restorefailure.
- restart {expected_staged_revision:SHA256} -> verify staged revision before stopping, then explicit stop/restore and verify again before start; unresolved restore refuses newstart. No MQTTrestart.
- bounded_logs {lines:1..500} -> configured service/container only, <=500 lines/64 KiB, with each sanitized line limited to 4096 characters, nofollow/pager, sanitized lines+truncatedflag.

No payload paths/units/shell/Docker/SQL/arbitrary environment. Root helper host subprocess args are fixed validated config plus typed bounds; use argv, not interpolated shell. UI desired/apply semantics reflect staged versus effective configuration.

## Wolf/Steam lifecycle

Root-owned unit retains ordering: bounded optional dockercomposepull, cached-imageinspect BEFORE cleanup, temporary Steamapply, compose up with pull_policy: never, composestop and post-stoprestore. Defaultpull60seconds+5killgrace; registry failure uses cache, absentcache refuses before cleanup. InternalDockerrestartdoesnotpull. Game cleanup stops only containers whose exact inspected identity and both ownership labels match this PC; it never removes those game containers or volumes. Compose down recreates the managed Wolf service container while retaining its bind-mounted data and volumes. Preserve bindmounts/profileuserdata/pairingUUID/customapps and generated-marker appblocks. Repeated unchanged reconcile is byte-stable and does not restart. Core Steam/VDF parsing, TOML appgeneration, icon/covers and optional Proton/parameter behavior are ported into separate modules with source-backed golden fixtures. Never auto-delete stale app-profile/libraries as catalog cleanup.

PC CLI responsibilities: catalogdaemon(read-onlySteam+MQTT), dispatch-rpc(unprivileged validation/sudo), privileged-rpc(rootvalidation/operations), apply-steam/restore-steam(rootlifecyclehooks), installer-preflight/dryrun. Exact subcommand spelling is shared installed templates and tests, not a source of arbitrary RPCrouting. Catalogdaemon runs selected nonrootSteamidentity with configured readable brokersecret; no broadrootdaemon.

## Canonical safety completion

Authorized keys contain public data, root-owned mode 0644 with root-owned traversable, non-writable parents: OpenSSH opens them under the target UID. Private manager keys remain 0600.

Root RPC journal: backup_root/requests/<request_id>.json, root-owned 0600, atomic fsynced writes. Fields: version, request_id, pc_id, operation, canonical_request_sha256, phase (accepted/running/succeeded/failed/unknown_interrupted), timestamps, safe_result/error. Persist accepted then running before effects; persist final result only after verified completion. Same ID with different canonical bytes refuses request_id_conflict; completed identical requests return the cached result without effects; incomplete identical requests never reexecute. Startup turns incomplete records unknown_interrupted. Keep unresolved records indefinitely; terminal retention matches manager policy.

Read-only request_status {original_request_id:UUID} returns found, digest, phase and safe result. Missing record means not_found, never proof of non-execution after dispatch. Reconciliation compares exact PC/request/digest, not merely current service state. Manager POST /operations/<id>/reconcile accepts {}; authenticated CSRF applies, and reconciliation is read-only remotely. Verified completed journal records transition to succeeded/failed; local dispatch_phase=not_dispatched proves non-execution and permits rejected. Sent requests with missing/incomplete/mismatched records remain unknown_interrupted. Do not unblock a new mutation on plausible observations. Recovery of a lost journal uses verified backup/operator runbook, never a blind replay or automatic acknowledgment. Read-only preflight/status/log/reconciliation remain available while mutations are blocked.

Manager start/restart serialized sequence: validate desired revision, stage overrides with apply_settings, verify staged revision, then invoke start/restart. Stage failure leaves current service untouched. Restart refuses revision mismatch before stopping; stop/restore failure preserves pending recovery and never starts; start failure leaves service stopped with durable failure/uncertainty. API wording that previously implied staging after stop is superseded. Staging has no effect on an already running Steam session.

Lock protocol: RPC admission uses backup_root/requests/.admission.lock for per-PC mutation serialization. Steam hooks independently acquire backup_root/.transaction.lock, never the RPC lock; RPC must not hold the transaction lock while waiting for systemd, preventing hook deadlock. Fixed-unit systemd jobs serialize start/stop; hooks verify current journal/recovery phase under the transaction lock. Stage overrides uses a separate atomic stage-file transaction and never edits active Steam targets. Detect target Steam processes owned by the granted UID using executable identity and refuse mutation while any target writer is running. Systemd hooks perform this check before backup/apply/restore. Cannot prove quiescence means refusal, not best effort.

## Multi-RPC reconciliation (supersedes single-request shorthand)

A manager operation owns an ordered durable RPC plan. For start/restart insert stage (ordinal0) and lifecycle (ordinal1) child rows, each with a distinct UUID and canonical envelope digest, before the first network effect. For one-RPC operations insert one child. Submit only the recorded bytes/ID; persist sending before network and sent after acknowledgment. Child identifiers never change on retry/reconciliation. Staging failure prevents primary dispatch.

Reconcile every child that is sending/sent through request_status, compare exact PC/UUID/digest and persist independent evidence. Parent resolves succeeded only if all required children have verified success. A verified failed child with every other child either verified terminal or durably not_dispatched resolves failed with partial-stage evidence; never claim the service action succeeded. Parent resolves rejected/non-executed only if ALL children are durably not_dispatched. Any possibly dispatched child with missing/incomplete/conflicting evidence keeps parent unknown_interrupted and blocks unsafe mutations, even when primary never went out. Current observed service state alone is insufficient. Parent summary dispatch_phase is not proof.

## Verified stage-only completion

If staging is independently verified succeeded and the planned primary child remains durably not_dispatched, reconciliation terminates the parent as failed with code primary_not_dispatched and explicit stage_succeeded evidence. Desired/staged revision is visible, running revision remains the observed prior value. This is verified partial execution, never parent success or non-execution. No replay occurs; a subsequent explicit user action is a new operation after reconciliation. Any other possibly dispatched child must be terminally evidenced first; otherwise the parent remains unknown_interrupted. Test the crash after stage acknowledgment but before primary sending is committed.

## Lifecycle completion evidence

After a service command is submitted, a nonzero exit, broken output pipe or
failed post-action observation cannot prove that no effect occurred. Such errors
leave the original request Running with an uncertain outcome; no terminal RPC
reply is issued and the original request cannot be replayed. Pre-submission
revision, capability and recovery refusals may return a confirmed failure.
