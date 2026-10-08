# Offline manager recovery

Manager backups include the matching SQLite database, initialization marker,
MQTT instance identity and enrolled private SSH keys. Stop the manager before
creating or restoring a backup; an exclusive state lock prevents concurrent use.

Backup and preview validate the database schema, integrity and account/marker
consistency, private-file ownership and modes, enrolled SSH identity, and bundle
checksums. A present `instance-id` must be a canonical lowercase UUID and cannot
be nil. This semantic validation also applies when the bundle checksum matches.
An absent identity is allowed before first MQTT initialization; backup does not
create one or otherwise initialize source state.

Malformed source or bundle state is refused before creating a destination.
Preview is read-only. Restore prepares a complete private directory and exchanges
it with the target, retaining the prior target as a rollback directory. If an
existing mounted target cannot be exchanged, restore refuses without changing
it; restore to a separate private path and explicitly remap it while stopped.

Operations which may have been submitted remain uncertain after restoration.
Restoring state never authorizes replay; reconcile them against the host journal.
