# Install or adopt a Wolf PC

[Documentation home](index.md) · [Next: operate the PC](operations.md)

## Record the existing storage first

Use a local administrator console. You need systemd, OpenSSH server, sudo, Docker with Compose, a working GPU/device setup, and Steam initialized under the intended non-root UID/GID. Prepare the network/firewall independently. The toolkit does not require Ansible or install these prerequisites for you. Direct-OS and native streaming compatibility must be checked separately from distribution container tests.

Before installing, record the existing Wolf configuration, pairings, custom apps, Compose file, Steam profiles, libraries, userdata/saves and all container mount destinations. Take verified backups and establish the return path to your existing service. Stop gaming sessions and Steam writers before activation. Do not move or replace existing data to fit this example.

Download the host archive for your architecture from a verified release. Check the archive's SHA256 against trusted release metadata before extracting it. Keep the executable and installer in a root-owned, non-writable location. No command below downloads code or modifies a live host without an explicit apply/activate step.

## Build the policy from your real mappings

Copy [host-policy.example.json](../../examples/host/host-policy.example.json) to a root-owned `0600` regular file, for example `/root/wolf-policy.json`. It is a **template**, not a ready-to-run hardware configuration. Replace image placeholders with verified Wolf and Steam runner images, UID/GID with the actual Steam account, and every path with its existing authorized mapping. `steam_runner` is the Wolf runner template: supply the image and any GPU/runtime settings needed by your known-working deployment. The toolkit injects authorized library/userdata/Proton mounts and ownership labels; it cannot infer your encoder or runner's hardware requirements.

The `wolf_config` root must be root owned. Steam config/library files must match the declared Steam UID/GID. Paths must be absolute, normal and free from symlink aliases, hard links and writable ancestors. The example uses an illustrative `/home/gamer/Steam`; installations using `.steam` symlinks should resolve the actual trusted path instead. Record real Steam executable paths used for writer detection.

Keep `proton: null` unless you have an existing Proton-CachyOS directory. To grant it, replace null with an object containing `name`, `host_path`, and `container_paths`. Host installation is not a Proton download mechanism.

Use `--mode adopt` for existing Wolf/Compose configuration. Adoption preserves those files. Install mode produces defaults only for absent configuration/Compose files; it still requires initialized, authorized Steam paths. Review the complete plan rather than assuming absent-only creation is sufficient for your PC.

## Generate the manager's restricted SSH key

In the manager, choose **Add PC** with the policy's PC ID, then **SSH setup**. Opening setup generates a per-PC Ed25519 key; only its public key is shown. Copy that public key to a protected root-owned file on the PC, such as `/root/wolf-manager.pub`. The private key stays in the manager's protected data and must be included in its backups.

For a separately managed RPC client, a local administrator can create a separate identity:

```sh
umask 077
ssh-keygen -t ed25519 -f ./wolf-rpc-key
```

Protect its private key and use a passphrase for interactive custody. Only the `.pub` file is supplied to the installer. The browser does not import this private key; do not replace the manager's stored identity by editing its data directory. Each repeated `--authorized-key` grants another identity the same restricted RPC rights, so install only identities you intend to authorize.

## Preview, apply and activate

The example assumes the verified executable is `/root/wolf-release/bin/wolf-manager-host` and the extracted installer is `/root/wolf-release/install.sh`. Check `--help` and `--version` from that exact executable.

```sh
sudo /root/wolf-release/install.sh /root/wolf-release/bin/wolf-manager-host install-preview \
  --policy /root/wolf-policy.json \
  --host-binary /root/wolf-release/bin/wolf-manager-host \
  --authorized-key /root/wolf-manager.pub \
  --mode adopt \
  --output /root/wolf-install-plan.json
```

The plan output must not already exist. Preview records identities, intended changes, retained preimages and rollback mappings without applying them. Review it locally, including policy paths, service names, existing SSH/sudo configuration and account changes. Do not post it publicly. Then:

```sh
sudo /root/wolf-release/install.sh /root/wolf-release/bin/wolf-manager-host install-apply \
  --plan /root/wolf-install-plan.json
sudo /root/wolf-release/install.sh /root/wolf-release/bin/wolf-manager-host install-activate \
  --plan /root/wolf-install-plan.json
```

Activation without flags does not request starting Wolf or the catalog. Once the reviewed setup is ready, explicitly add `--start-wolf`, `--start-catalog` and/or `--enable-on-boot` to activation according to the services you want. Do not request catalog startup without its broker configuration. Existing services/data remain subject to preflight identity checks; changed files make a saved plan stale rather than permission to overwrite them.

The installed `wolf-manager` account has no Docker/admin/journal group membership. SSH disables passwords, PTY, forwarding and user rc files; a fixed dispatcher accepts only `wolf-manager-rpc-v1`. Sudo admits only the fixed no-argument privileged helper, with no environment injection. This is not an interactive SSH account. Restrict its network reachability to the manager where practical.

## Configure the catalog publisher

Before preview, create a broker configuration from [broker.example.json](../../examples/host/broker.example.json). Replace host, PC name and protected credential-file paths. Its `username_file` and `password_file` contain separate broker credentials; never copy the manager's broad broker identity. The catalog configuration and files must meet the host's protected-file checks. The config runs under the Steam UID; give that UID ownership, mode `0600`, and a private directory. Set the policy's `broker_secret_file` to `/etc/wolf-manager/catalog.json` (the installer requires a destination under `/etc/wolf-manager/`) and pass the prepared source file using `--broker-config /root/wolf-broker.json` during preview. The source preview input is root owned; the installed catalog file is owned by the Steam identity.

For a private broker CA, supply an absolute `ca_file` and keep `tls: true`. Omit the CA or use null for publicly trusted roots. The host publisher uses MQTT v3; the manager's command adapter uses MQTT v5. The broker must support both. Keep catalog state durable so generation numbers and owned discovery cleanup survive restarts.

## Verify the host fingerprint independently

From the PC's trusted console:

```sh
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

In **SSH setup**, select **Probe host key** and compare the algorithm and SHA256 fingerprint with the console result. A probe is an untrusted proposal, not verification. Check **I verified this fingerprint independently**, then **Trust fingerprint** and **Test connection**. Refresh operation history to confirm the test result. Endpoint changes require a fresh probe/enrollment. An unexpected key change requires independent investigation, not automatic acceptance.

Before a first Start, verify the selected image is cached or its registry is reachable, Docker/GPU devices work, and the Steam runner template is correct. A bounded optional pull falls back to the cached image; no cache means startup fails safely.

For a guarded installation rollback:

```sh
sudo /root/wolf-release/install.sh /root/wolf-release/bin/wolf-manager-host install-rollback \
  --plan /root/wolf-install-plan.json
```

Rollback checks recorded identities and preimages. Preserve backups when it refuses; do not force-remove files that changed after installation. Installation rollback does not substitute for Steam saves, manager state or Wolf backups.
