# Configure HA Wolf Manager

## Prerequisites and installation

Use Home Assistant with Supervisor, an administrator account, a configured MQTT broker/MQTT integration, and at least one independently prepared Wolf PC. Once a verified release is available, add `https://github.com/Ryther/ha-wolf-manager` to the add-on store's repository list, select **HA Wolf Manager**, install it, start it and open **Wolf Manager**. Read the release notes before updating and keep a backup.

Ingress uses Home Assistant's administrator authentication. Do not enter standalone passwords, bootstrap tokens, TLS settings or broker credentials in the add-on options. Supervisor supplies the MQTT service configuration. The shared image selects Ingress mode; no direct external port is declared by the add-on.

## Options

```yaml
topic_base: wolf-manager/v1
discovery_prefix: homeassistant
```

Keep both roots identical in the manager and each host catalog publisher. Changing roots also changes MQTT discovery/state routes: coordinate broker ACLs, publishers and automations, retaining previous discovery evidence until cleanup is verified.

## Register a PC

Install or adopt it with the [host toolkit](../docs/guides/host-installation.md). Choose **Add PC**, use that policy's immutable PC ID and SSH endpoint, then complete **SSH setup**. Install the displayed public key through the reviewed local installer. Compare **Probe host key** with a fingerprint obtained independently from the PC console before trusting it. **Test connection** is an operation; refresh history to inspect its outcome.

The host publisher supplies installed-game catalog entities. The manager supplies the PC's **Wolf** switch through MQTT discovery. Use that discovered switch in your own Home Assistant automations. Voice exposure uses your existing Home Assistant configuration; this project does not configure Google Home or power on a shut-down PC.

Saving game/shared settings changes only Desired. Explicitly stage/start/restart to apply them, after finishing gaming sessions. Last-known state on an offline PC is historical. Uncertain operations must be reconciled against the host journal, not repeatedly replayed. See [operating multiple PCs](../docs/guides/operations.md).

## Logs, backup and recovery

Use the add-on log view for structured manager process diagnostics and **Diagnostics → Read logs** for the bounded host snapshot. The scratch image has no shell. Do not edit protected data to bypass authentication or recovery checks.

The add-on declares a cold Supervisor backup. Keep verified backups before updates, plus separate Steam saves/libraries, Wolf configuration/pairings, host policy and journals. Manager backups contain private SSH keys and require secret custody. See [backup and recovery](../docs/guides/backup-recovery.md) and [troubleshooting](../docs/guides/troubleshooting.md).
