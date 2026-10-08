# HA Wolf Manager

Manage multiple [Wolf](https://github.com/games-on-whales/wolf) PCs from Home
Assistant or an authenticated standalone dashboard. The Rust manager connects
through restricted, host-key-pinned SSH. A separate Rust toolkit runs on each PC;
it does not require Ansible.

Installation and runtime integration are experimental. Passing isolated tests does not certify your PC,
GPU, Moonlight client or live Home Assistant installation.

The project includes:

- Home Assistant Ingress and standalone HTTPS authentication.
- MQTT discovery of Steam games and a Wolf ON/OFF switch for automations and
  voice assistants; dashboard restart, status and bounded diagnostics.
- Per-game direct launch, ordered launch parameters, optional Proton-CachyOS,
  FSR4 settings and a diagnostic test ball.
- Independent previewed install/adopt, restricted SSH enrollment, bounded image
  refresh with cached-image fallback, and retained backups for Steam restoration.
- Durable operation tracking that requires reconciliation after a lost reply,
  preserving Wolf identity, pairings and custom applications.

Owned runtime images are designed from `scratch`, with native SSH, TLS,
bootstrap and health checks. The Wolf image and game containers are separate
upstream components.

## Compatibility evidence

| Distribution family | Container checks | Direct OS / GPU streaming |
| --- | --- | --- |
| Arch / CachyOS | Passed restricted SSH, sudo and offline unit checks | Not tested |
| Debian / Ubuntu LTS | Passed restricted SSH, sudo and offline unit checks | Debian VM: installer, systemd catalog and Wolf control plane passed; Ubuntu and GPU streaming not tested |
| Fedora | Passed restricted SSH, sudo and offline unit checks | Not tested |
| openSUSE Leap / Tumbleweed | Passed restricted SSH, sudo and offline unit checks | Not tested |

See [the platform test procedure](tests/host-platform/README.md) and its recorded
image digests. Containers do not prove systemd boot, hardware permissions,
SELinux behavior or streaming compatibility. The manager and host toolkit target
amd64 and arm64; the verified upstream Wolf stable image is currently amd64-only.
An ARM toolkit build does not establish an ARM Wolf deployment.

The [Home Assistant interface captures](docs/guides/home-assistant.md#verified-local-interface)
show actual Supervisor Ingress and MQTT discovery on an isolated HAOS VM.
Restricted SSH enrollment, settings staging and Wolf start/restart/stop were
exercised against a separate Debian VM with synthetic Steam catalog manifests.
See the [test matrix](docs/contracts/test-matrix.md) for source revisions,
coverage and remaining limits.

## Development

Start with the [deployment and user guides](docs/guides/index.md). The
[release procedure](docs/guides/releases.md) describes publication and required
GitHub configuration. The [application-use skill](.agents/skills/ha-wolf-manager-guide/SKILL.md)
provides the same operational boundaries for AI assistants; Claude uses a
relative compatibility link.

Read [AGENTS.md](AGENTS.md) for contributor instructions, verification commands
and security boundaries. [Crate interfaces](docs/development/crate-contract.md),
[installation authority](docs/development/host-adapter-contract.md) and
[dependency sources](docs/development/dependencies.md) document the implementation.
The [public contracts](docs/contracts/) cover configuration, SSH, API, MQTT,
recovery and release behavior.
The [development environment](docs/development/environment.md) keeps MQTT,
SSH and state fixtures isolated from household services. Read
[CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) before submitting
changes or security reports.

Development uses isolated fixtures. Never run experimental installation or
recovery checks against your only copy of Steam or Wolf data. Review the proposed
storage mapping and verified recovery path before applying a host plan.

Code has been developed with AI assistance and requires review and measured
validation. Owned code uses the [MIT license](LICENSE); the vendored MQTT crate
retains its [Apache 2.0 license](vendor/rumqttc/LICENSE). Wolf is an independent
upstream project; this manager does not imply upstream endorsement.
