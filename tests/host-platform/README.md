# Host platform checks

Run from the repository root:

```sh
python3 tests/host-platform/run.py --jobs 3
python3 tests/host-platform/run.py --family debian --family ubuntu
```

The runner uses Docker and Python's standard library. It creates temporary
containers from the digest-pinned official images in `images.json`, installs
current packages from their distribution repositories, mounts only these test
scripts and installer templates read-only, and removes its containers afterward.
It does not mount the host Docker socket, Steam data, SSH keys or system folders,
expose ports, use host networking, or run the installer on the host.

Each container verifies:

- A locked system account with `/bin/sh`, `/nonexistent`, and no supplementary
  privileges.
- Actual `visudo` acceptance, permission for the one no-argument helper, and
  refusal of arbitrary arguments or a shell.
- Root-owned public keys that the target account can read but cannot modify.
- Actual `sshd -t` and `sshd -T` account policy, including bounded client
  environment when the global configuration accepts arbitrary variables.
  Client requests for `BASH_ENV`, `ENV` and `LD_PRELOAD` are rejected.
  `PermitUserEnvironment` is global-only and is not placed in `Match`; the
  locked account home has no `.ssh` state and generated keys have no environment
  options. Alternate key commands, CA keys and principal providers are disabled
  for the account; other users' global policy is unchanged. Production installer
  validation also refuses inherited server `SetEnv` values.
- A local SSH connection using temporary generated test keys: the fixed original
  command succeeds, an arbitrary command fails, and TCP forwarding is denied.
- Offline `systemd-analyze verify` of the lifecycle and catalog unit templates.

The SSH fixture uses a fixed fake host executable to observe OS restrictions.
It does **not** prove native Rust RPC behavior; native protocol/dispatcher tests
are separate. Offline unit validation does not execute systemd as PID 1.
No test here certifies an installed operating system, GPU access, Steam, Wolf
streaming or live Home Assistant behavior. Container results must be labeled
**container-only** in compatibility documentation.

Results and bounded failure logs are written under ignored `_tmp/host-platform/`.
They include resolved image digests, installed tool versions and `/etc/os-release`.
Distribution repository state can change even with a pinned base image; compare
recorded package versions when investigating a later difference. Refresh image
pins only after verifying current stable releases through the listed official
sources. Arch, CachyOS and Tumbleweed are rolling snapshots; Leap 16.1 was still
an RC when Leap 16.0 was selected on 2026-10-08.

The first release deliberately refuses pre-existing conditional `Match` blocks
outside its exact generated fragment, including blocks reached through nested
`Include` files. The installer inspects root-owned nonwritable configurations
without following symlinks, with bounded file/depth/size limits. Quoted or complex
include expressions and wildcard directories require explicit operator review.
This may refuse an existing distribution crypto-policy symlink or custom SSH
configuration; it does not rewrite other users' policy. These isolated SSH
fixtures use explicit temporary configurations; their passing result does not
certify adoption of every installed distribution's SSH configuration.

The measured snapshot in `verified-results.json` records all seven passing
container checks on 2026-10-08. It is historical evidence, not a guarantee for
future repository package versions or arbitrary installed SSH configurations.
