# Troubleshoot without losing state

[Documentation home](index.md) · [Backup and recovery](backup-recovery.md)

## Collect a bounded snapshot

Record the PC ID, operation ID, **Observed at** timestamp, availability and Desired/Staged/Running revisions. In **Diagnostics**, choose **Log lines** (1–500) and **Read logs**. Output is a sanitized bounded snapshot, not a continuous stream; it may explicitly report truncation. A snapshot can contain only the available recent logs and cannot prove the absence of an earlier error.

On the PC, a local administrator can inspect the actual units and container selected in its policy:

```sh
sudo journalctl -u wolf.service -u wolf-manager-catalog.service --since '30 minutes ago' --no-pager
sudo docker logs --tail 200 wolf
```

Replace `wolf.service` and `wolf` if your policy uses other names. Preserve useful timestamps and redact private addresses, identities and launch options before sharing logs. New-install Compose defaults use `WOLF_LOG_LEVEL=DEBUG` and `GST_DEBUG=3`. Adoption preserves the existing Compose file, so inspect its environment instead of assuming those defaults were installed.

## Common symptoms

| Symptom | Checks |
| --- | --- |
| Manager cannot start | Inspect container exit output; verify mode, exact HTTPS origin, protected file owner/mode, MQTT configuration and certificate/key pair. Scratch images have no shell to exec into. |
| TLS or sign-in fails | Use the configured HTTPS origin and a trusted certificate. Check clock and proxy peer configuration. Do not bypass CSRF or replace Ingress with caller-supplied headers. |
| SSH probe works but connection test fails | Independently verify and enroll the exact fingerprint; check the generated public key is installed for the restricted account, PC ID matches policy and SSH route/firewall is reachable. |
| PC shows offline with old running state | Treat state as historical; compare observation time and current reachability. Refresh and inspect the corresponding operation. |
| Games missing | Check catalog unit, broker ACLs/topic roots, Steam library paths, complete-generation publication and host availability. Failed scans retain earlier complete data. |
| Start fails when registry is unavailable | Cached image fallback works only if the selected image already exists locally. A failed pull with no cache fails startup; do not change the image reference to hide that failure. |
| Steam restoration refused | Stop the authorized Steam writers and preserve transaction backups. Investigate mismatched preimages/owners; do not delete state or force overwrite. |
| Operation remains uncertain | Use Reconcile operation; retain the exact host journal. Current ON/OFF is insufficient evidence. |
| Moonlight remains Connecting | Manager readiness is not a streaming test. Inspect Wolf/GStreamer logs, actual host listener/firewall, GPU/device access and traffic from the client. The toolkit does not open your firewall. |

Host startup attempts a bounded optional pull, then verifies a local image before cleanup. Docker's internal container restarts do not refresh the image. The host service's systemd state alone is insufficient: it is a oneshot lifecycle wrapper, while the container is independently observed.

If the administrator password is lost, use the offline native reset procedure in [backup and recovery](backup-recovery.md). Do not remove the initialization marker, database or SSH keys to make bootstrap reappear.

## Manager process diagnostics and bounded connections

The manager writes its own structured product events as JSON to stderr. `RUST_LOG` defaults to `info`; set `RUST_LOG=debug` in the standalone Compose environment and recreate the manager when investigating a problem. Read the resulting output with `docker compose logs --tail 200 wolf-manager`. Ingress deployments use the add-on log view. Only manager product targets are admitted by the logger: increasing the filter does not enable dependency payload logs. Treat even product diagnostics as private before sharing them. More verbosity cannot reconstruct events that were never recorded.

TLS negotiation, request headers and request body reads have bounded lifetimes; body reads are limited to 10 seconds and a connection has a 60-second lifetime. Normal browsers establish another connection when needed. An idle connection closing is not evidence of Wolf restarting. Correlate manager process start/stop events, Docker status, host observations and operation IDs before deciding which process stopped.

Native TLS certificate/CA inputs are bounded at 1 MiB and must be regular, single-link files owned by root or the runtime UID, without writable group/world permissions or path aliases. Private TLS keys use the stricter secret-file check and a 16 KiB bound. The bootstrap token, broker credentials and other secret inputs have their own limits; preserve their private file modes rather than relaxing checks to silence a startup error.

## Host refusal and image-cache symptoms

Steam writer detection examines processes for the authorized UID. A native process name beginning with `steam` (case insensitive) is conservatively treated as a writer even if its executable was omitted from policy. Declared helper executable identities are also checked. If restoration/staging reports an active writer, exit those processes and retry the explicit operation; do not weaken the policy or erase preimages.

Host-generated app icons are cached as validated PNG files inside the authorized Wolf configuration mapping. Fetching/decoding is bounded, with a shared 20-second budget and a fallback image if the CDN cannot supply a valid cover. Existing valid cache entries are retained rather than refreshed automatically. An invalid or unauthorized existing cache entry is rejected, not overwritten. A missing/old cover therefore does not establish that a game or its catalog is missing. Investigate the recorded configuration mount and cache ownership while preserving its contents.
