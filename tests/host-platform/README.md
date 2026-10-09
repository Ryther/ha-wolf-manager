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
Each distribution retains at most 1 MiB of combined command output and a separate
1 MiB setup log. Results record the failed stage, controlled error code, timeout,
cleanup outcome and discarded-byte counts. Timeout output remains available;
truncated successful evidence is refused rather than reported as a pass.
They include resolved image digests, installed tool versions and `/etc/os-release`.
Distribution repository state can change even with a pinned base image; compare
recorded package versions when investigating a later difference. Refresh image
pins only after verifying current stable releases through the listed official
sources. Arch, CachyOS and Tumbleweed are rolling snapshots; Leap 16.1 was still
an RC when Leap 16.0 was selected on 2026-10-08.

Tumbleweed uses the official openSUSE registry's dated `20261003` tag and exact
multiarchitecture index digest. On 2026-10-09, fresh pulls of its AMD64 and ARM64
manifests succeeded, and the full AMD64 distribution fixture passed with
OpenSSH 10.5p1, sudo 1.9.17p2 and systemd 261.3. ARM64 pull availability does not
establish execution of this distribution fixture on ARM64. This six-day-old
snapshot was selected over the observed `20261005` and `20261006` partial
indexes, which lacked ARM64; the earlier index selected through `latest` returned
`404 MANIFEST_UNKNOWN` to a fresh registry request even though a cached local
image still ran successfully. The registry's [published tags](https://registry.opensuse.org/v2/opensuse/tumbleweed/tags/list)
identify the selected dated snapshot; Docker Hub's [official project image](https://hub.docker.com/r/opensuse/tumbleweed)
currently exposes only `latest`, so it is not a dated-tag substitute.

A dated tag and digest do not guarantee indefinite upstream retention. Verify
the index and both target manifests remotely, then explicitly pull each target
platform before accepting an updated pin. A passing test using a cached image
is insufficient evidence of fresh-runner availability. Package repositories
remain rolling even when the base snapshot is fixed. The per-image
`verified_at` records this later Tumbleweed check; the matrix's original date
and `verified-results.json` remain historical evidence for the earlier cohort.

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
