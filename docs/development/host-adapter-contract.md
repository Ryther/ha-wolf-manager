# Host adapter implementation boundary

The root-owned JSON policy is the sole path/unit/image authority. RootPolicy uses closed serde fields: version1, pc_id, steam_uid/steam_gid, libraries, steam_profiles, wolf_config, compose_file, service_unit, container_name, image_ref, backup_root, state_root, catalog_state_directory, broker_secret_file (nullable), pull_on_start, pull_timeout_seconds, proton (nullable), steam_executables, steam_runner. No browser/RPC operation may supply these fields.

LibraryGrant is {library_id, steamapps_path: absolute canonical path, container_paths: nonempty array of absolute container paths}. steamapps_path contains appmanifest_*.acf and common/. ProfileGrant is {root: absolute canonical path, config_vdf: relative path, libraryfolders_vdf: array of relative paths, userdata_directory: relative path, container_userdata_paths: array of absolute paths}. Profile files belong to steam_uid/gid; existing library aliases may be resolved once in the explicit adoption mapping, never during mutable traversal. MutableTarget is {root, relative_path, uid, gid}; wolf_config is one such target. ProtonGrant is {name, host_path, container_paths}. steam_runner is a root-policy-owned TOML table copied from the selected existing/default Steam app; root policy owns its Docker image, mount/privilege baseline and runner name. Generated games replace only title/icon/startup flags in that trusted template.

Public Rust policy API: RootPolicy::validate()->io::Result<()>, RootPolicy::load_fixed()->io::Result<RootPolicy> (root helper only, fixed /etc/wolf-manager/host-policy.json), and RootPolicy::load(path)->io::Result<RootPolicy> for offline CLI/preflight (same trust checks). All path components/owners/modes and alias/regular-file checks are validated before privileged effects. Units/image/container names use closed finite grammar and only fixed argv execution; no shell payload interpolation. Missing file/directory prerequisites are previewed or refused, never silently invented during adoption.

Installer API: InstallMode::{Install,Adopt}; InstallRequest {mode,policy,authorized_public_keys:Vec<String>,source_binary:PathBuf,broker_config_source:Option<PathBuf>, initial_files:Vec<InitialFile>}; preflight(&request)->io::Result<InstallPlan>, apply(&plan)->io::Result<InstallReport>. A serialized plan/report omits secret bytes and captures expected identities/hashes, proposed writes, old-to-new storage mapping and verified backups/rollback before effects. Refuse unrecognized existing files/units/account privileges, unsupported architecture/image and any pending legacy/native restore. Apply revalidates all expected inputs. Root policy PC identity never changes through idempotent install/adopt. Never delete a profile/library/backup, overwrite drift, use Docker prune, or migrate data implicitly.

Installed fixed wrappers/units consume wolf-manager-host CLI subcommands dispatch-rpc, privileged-rpc, apply-steam, restore-steam, lifecycle-start, lifecycle-stop, catalog-daemon. Dispatcher/helper wrapper has no arguments from SSH; original command must equal wolf-manager-rpc-v1. Separate admission and transaction locks prevent systemd hook deadlocks. Systemd lifecycle hooks and privilege syntax are verified in disposable fixtures, with actual OS/systemd evidence recorded separately.


## Implemented lock and configuration semantics

The host journal serializes privileged mutations with `backup_root/requests/.admission.lock`; installer activation uses that exact lock. Steam hooks use distinct `.hooks.lock` and `.transaction.lock` inside `backup_root` and must never acquire the admission lock while systemd waits for them.

Temporary Steam overlays remain active until verified restoration. Wolf managed app blocks use a guarded permanent commit of a verified postimage after the preimage is durably backed up. Committed transactions remain available for explicit recovery but are excluded from automatic Steam restoration. On stop, managed block edits operate on the current Wolf TOML so new pairing data and custom apps remain intact. Full-file restore refuses drift. Runtime integration and pairing-during-session evidence remain required.

## OpenSSH environment boundary

`PermitUserEnvironment` is a global OpenSSH directive and must not appear in a Match block. The managed account has a locked password, a root-controlled unavailable home and no user environment file. Generated authorized keys never accept environment options. Validate the effective per-user `AcceptEnv` restriction with `sshd -T` and refuse activation if unsafe inherited environment rules remain. Preserve global policy for unrelated users.
## Transform preimages

Steam and Wolf transformations must pass the exact bytes they read to the
guarded write. `TransactionStore::apply_expected` compares those bytes with its
captured preimage under the transaction lock before creating a backup or changing
a target. `hooks::apply_expected` validates all supplied preimages before the
first overlay and repeats the comparison for each write. An intervening change
is a refusal; already applied overlays restore only verified postimages, retaining
conflicting files and recovery evidence.

## PNG icons and profile configuration reachability

The host converts Steam cover JPEGs to actual bounded PNGs. Cache files are
absent-only `.ha-wolf-manager-icons/<AppId>.png` inside the root-owned
`wolf_config.root` grant (directory mode0755, regular single-link file mode0644). Existing
valid PNGs remain byte-stable; aliases, hardlinks, wrong owners/permissions and
unknown existing bytes refuse. No icon or staging files are automatically
removed. A network failure creates a neutral embedded PNG; that valid fallback
is retained on later runs rather than silently replacing existing data.

Fetches regenerate the closed Steam CDN URL from validated AppId, disable
redirects/proxies, use native Rust TLS and are bounded to 5 seconds each and 20
seconds total. Encoded input/output is at most 4MiB; dimensions are at most 2048
per axis and decoder allocation budget 32MiB. JPEG and PNG are the only formats.
Production resolves an explicit Compose bind of the granted configuration root
and uses an absolute container path; it never assumes Wolf's state-folder base.
Missing/ambiguous mappings and submounts shadowing the cache refuse. YAML Compose
is normalized by the fixed Docker CLI with a bounded 5-second call; deterministic
fixtures use equivalent JSON without network activity.

Every Steam profile must authorize at least one container userdata path ending
in `userdata`. Its sibling `config/config.vdf` is mounted from that profile's
exact granted config_vdf. Conflicting pre-existing destination mappings refuse.
This connects compatibility-tool settings to the same container profile whose
userdata receives launch options; no unsupported profile mapping is silently
accepted. Container mount fixtures prove path/data correspondence, not an actual
Steam/GPU launch or Moonlight image decoding on a physical client.
