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
