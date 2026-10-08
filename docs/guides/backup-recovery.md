# Back up and recover without replacing live state

[Documentation home](index.md) · [Troubleshooting](troubleshooting.md)

## What to preserve

The manager bundle contains matching database state, account initialization marker, MQTT instance identity when present, and private SSH keys. Treat it as secret material. Keep it mode-private and encrypt off-site copies. A manager bundle does not contain Steam libraries/saves, Wolf pairings/configuration, host policy, host operation journal or transaction preimages. Back those up separately and record the PC-to-path/container mapping.

Keep host journals and pending transaction backups together. An uncertain operation requires its exact request IDs/digests and journal evidence. Restoring manager state does not authorize replay or manufacture a missing result. Never delete the initialization marker or transaction state to clear an error.

## Create and verify a standalone bundle

Stop the manager first. Use the same verified image and UID as the deployment. The destination is a **new directory**, outside the source data, and must not already exist. In the [Compose example](https://github.com/Ryther/ha-wolf-manager/blob/main/examples/standalone/compose.yaml):

```sh
docker compose stop wolf-manager
docker compose run --rm --no-deps wolf-manager --data /data \
  backup --destination /backups/manager-before-upgrade
docker compose run --rm --no-deps wolf-manager --data /data \
  restore-preview --bundle /backups/manager-before-upgrade
docker compose up -d wolf-manager
```

Both commands must succeed before relying on the backup. Verification checks the bundle inventory/checksums and the database/account/key semantics. A checksum-valid arbitrary SQLite file is not a valid recovery bundle. Keep the entire directory, including `bundle.json`, with its protected permissions. Do not copy only the SQLite file from a running process.

## Restore to a separate target

Stop the manager and preserve its current data directory unchanged. Do not restore directly over `/data` when `/data` is the container's bind-mount root: a mounted root cannot be safely exchanged and the operation will refuse. Instead mount a new private parent and restore to an absent child directory. For example, after creating a new private `recovery` directory owned by UID/GID 1000:

```sh
docker compose stop wolf-manager
docker run --rm --user 1000:1000 \
  --mount type=bind,src="$PWD/backups",dst=/backups,readonly \
  --mount type=bind,src="$PWD/recovery",dst=/recovery \
  "$WOLF_MANAGER_IMAGE" --data /recovery/restored \
  restore-preview --bundle /backups/manager-before-upgrade
docker run --rm --user 1000:1000 \
  --mount type=bind,src="$PWD/backups",dst=/backups,readonly \
  --mount type=bind,src="$PWD/recovery",dst=/recovery \
  "$WOLF_MANAGER_IMAGE" --data /recovery/restored \
  restore --bundle /backups/manager-before-upgrade
```

Set `WOLF_MANAGER_IMAGE` in your current shell to the same verified digest used in `.env`; Docker Compose's `.env` is not automatically exported to `docker run`. The new target is prepared and verified before rename. When restoring over an existing valid target within a normal directory, the tool retains and prints the previous state as a rollback directory. Keep it.

After successful verification, explicitly change the Compose data source from `./data:/data` to `./recovery/restored:/data`, start the manager, and validate sign-in, enrolled host keys, revisions and history. Retain the original `./data` and image digest until these checks pass. Return to the original bind mapping and compatible image if recovery validation fails; do not delete either data tree during cutover.

For Supervisor deployments, stop the add-on and use Home Assistant's documented backup/restore flow. Independent native bundle recovery requires an offline environment with the same protected ownership rules; the scratch add-on has no shell. Do not improvise edits to Supervisor-managed mount roots.

## Reset a lost administrator password

This applies to standalone authentication. Stop the manager, create `secrets/new-password` as a protected regular UID-1000-owned `0600` file containing the new password, then:

```sh
docker compose run --rm --no-deps wolf-manager --data /data \
  reset-password --password-file /run/wolf-secrets/new-password
docker compose up -d wolf-manager
```

The command takes an exclusive recovery lock, creates a verified backup before changing the account, and revokes existing sessions/challenges. Store the resulting backup securely. Remove the temporary reset-password file only after confirming the new login and after deciding its retention according to your own secret policy. Ingress authentication remains Home Assistant's responsibility.

## Import the prototype add-on's settings offline

This is an explicit initial migration, separate from bundle restore. Export the prototype's settings JSON to a protected regular file and retain its original copy. The supported source is the legacy object containing `parameters`, `games` and `debug`; it does not contain a top-level `version` field. Select the format explicitly with `--format-version 1`. Unknown format versions are rejected. The file must be an absolute path inside the container, at most 4 MiB, owned by root or the executing UID, mode-private, with no symlink aliases or hard links.

Initialize the new manager, register **only the intended PC**, and copy its actual **Desired** revision from the dashboard before stopping the manager. The example PC is `gaming-pc`; replace it with your registered immutable ID. The entire database must contain exactly one PC, including archived records: archiving another PC does not make this migration safe because definitions and diagnostic settings are global. Resolve queued/running/uncertain mutations before importing.

Put the protected export at `legacy/settings.json` in the deployment directory. Enter the copied desired revision into a shell variable, then preview without mutating manager state:

```sh
read -r EXPECTED_REVISION
docker compose stop wolf-manager
docker compose run --rm --no-deps \
  --volume "$PWD/legacy:/legacy:ro" wolf-manager --data /data \
  import-preview --source /legacy/settings.json --format-version 1
```

Review the printed normalized `settings` carefully. The parser preserves valid long legacy labels/descriptions, normalizes IDs and legacy values, preserves the order of valid selected parameters and removes duplicate selections. Invalid legacy entries may be omitted by normalization; a definition exceeding hard transport limits refuses the import rather than silently truncating it. Confirm that all settings you intend to retain are present before applying.

```sh
docker compose run --rm --no-deps \
  --volume "$PWD/legacy:/legacy:ro" wolf-manager --data /data \
  import-legacy --source /legacy/settings.json --format-version 1 \
  --pc gaming-pc --expected-revision "$EXPECTED_REVISION"
docker compose up -d wolf-manager
```

A stale revision or another active mutation refuses the import. Existing desired games/definitions are merged: matching imported IDs are updated, unrelated current entries remain, and the global diagnostic setting comes from the source. Before the atomic SQLite transaction, the tool creates a verified SQLite backup and retains the exact export as a private `legacy-source-<UUID>.json` file in the manager data directory. Keep both as recovery evidence. Success prints the new desired revision; verify it in the dashboard after restart.

Neither command sends host RPC, stages settings, edits Steam/Wolf files or starts a PC. Apply the imported desired state only through an explicit later Stage/Start/Restart after reviewing the host configuration. These commands do not migrate prototype SSH credentials, identities, pairings, broker settings or automation entity IDs. Retain those separately and enroll the new restricted manager identity.
