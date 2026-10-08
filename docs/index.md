# HA Wolf Manager

Manage Wolf hosts from Home Assistant Ingress or an authenticated standalone
HTTPS dashboard. A Rust manager communicates with independently installed Rust
PC tools through restricted, host-key-pinned SSH. Ansible is not required.

Start with [deployment choices](guides/index.md), then follow the
[Home Assistant](guides/home-assistant.md) or
[standalone Docker](guides/standalone.md) guide and
[install or adopt a PC](guides/host-installation.md).

For daily use, read [controls and games](guides/operations.md). Before changing
existing data, review [backup and recovery](guides/backup-recovery.md).
[Troubleshooting](guides/troubleshooting.md) explains structured logs and
bounded diagnostics.

This project is preparing its first public release. Container checks do not
certify direct OS boot, GPU access, live Supervisor execution or Moonlight
streaming. See the [test matrix](contracts/test-matrix.md) for evidence boundaries.

Contributors can use the [isolated development environment](development/environment.md)
and [crate interfaces](development/crate-contract.md). Maintainers must follow
the [release procedure](guides/releases.md), which verifies the exact candidate
bytes before publication.
