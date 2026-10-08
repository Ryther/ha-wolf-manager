# Isolated development environment

Install Docker with Compose and the VS Code Dev Containers extension. Open this
checkout and select **Dev Containers: Reopen in Container**. The setup installs
locked npm dependencies and fetches locked Rust dependencies; it does not start
the manager or enroll a PC.

The container includes Rust 1.99.0 with Clippy and rustfmt, Ubuntu GNU build tools,
Python 3, an OpenSSH client, Node/npm and Playwright's browser binaries. Browser
tests use the repository's matching Playwright 1.64.0 package. Development uses
GNU binaries; published scratch images have a separate build and verification
contract.

## Services and boundaries

Compose starts a disposable Mosquitto broker in the development container's
network namespace at `127.0.0.1:18889`. It publishes no host ports and disables
persistence. Anonymous access is confined to this private fixture network.
`WOLF_TEST_MQTT_HOST` and `WOLF_TEST_MQTT_PORT` select this broker explicitly.

Only this checkout is bind-mounted. Cargo downloads and compilation outputs use
Compose-scoped named volumes in the developer's home, keeping builds separate
from the checkout's `target/`. There are no Docker socket, household SSH key,
SSH-agent, Home Assistant configuration or Steam library mounts. Do not add
household credentials to fixtures. Editor port forwarding for a manually started
manager uses the editor's normal localhost forwarding; the broker is not
forwarded.

SSH integration tests start native loopback fixture servers with temporary keys.
They do not need a household SSH host or an installed SSH daemon. Root installer
and host-policy fixtures require their separate disposable test environment;
this nonroot development container does not establish SteamOS compatibility.

## Commands

The same environment can run without VS Code:

```sh
docker compose -f .devcontainer/compose.yaml up -d --build
docker compose -f .devcontainer/compose.yaml exec devcontainer sh .devcontainer/post-create.sh
docker compose -f .devcontainer/compose.yaml exec devcontainer sh .devcontainer/verify.sh
```

Inside the container, run affected checks or the regular repository checks:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
npm run test:ui
python3 -m unittest discover -s tests/release -v
cargo test --locked -p ha-wolf-manager --test ssh --test coordinator
cargo test --locked -p ha-wolf-manager --test mqtt -- --ignored
```

The final command opts into actual MQTT broker fixtures. Do not enable every
ignored test indiscriminately: other fixtures have different privilege and
service prerequisites. Browser tests use API fixtures and do not certify a live
manager or Home Assistant installation.

Stop only the development services with
`docker compose -f .devcontainer/compose.yaml down`. Named build caches survive;
there is no product database or persistent broker state in this setup.

## Optional Home Assistant fixture

Home Assistant is optional and is not automatically launched or configured.
For Supervisor/Ingress integration, follow the official
[local app testing guide](https://developers.home-assistant.io/docs/apps/testing/)
in a separately created disposable Home Assistant environment. Connect only
fixture manager/host instances and synthetic credentials. A standalone Home
Assistant Core container does not provide Supervisor or prove Ingress behavior.
Never use a household instance as the development fixture.

## Image and tool sources

Image versions and digests were verified against primary sources on
2026-10-08 and are pinned in the Dockerfile and Compose file:

| Component | Pin | Primary source |
| --- | --- | --- |
| Rust GNU toolchain | 1.99.0, slim-trixie toolchain stage | [Rust release](https://blog.rust-lang.org/2026/10/01/Rust-1.99.0/) |
| Browser development image | Playwright 1.64.0, Ubuntu Noble | [Playwright Docker documentation](https://playwright.dev/docs/docker) |
| Private broker fixture | Mosquitto 2.1.2, Alpine | [Mosquitto downloads](https://mosquitto.org/download/) and [official image manifest](https://github.com/docker-library/official-images/blob/master/library/eclipse-mosquitto) |

Ubuntu build tools come from the image's supported Noble repositories. They
intentionally follow the distribution's maintained package versions rather than
independently pinned upstream versions. Only Rust's upstream toolchain is copied
from the Debian stage; Ubuntu supplies the compiler and system libraries. Match
Playwright's image version to `package-lock.json` when updating browser tools.
Node and npm follow that image's bundled tooling and are not independently
upgraded during container setup.

The image build and verification script were exercised on Linux amd64: GNU Rust
core, coordinator and native SSH tests, actual private-broker MQTT fixtures,
Chromium browser tests and the Python release suites passed. ARM64, published
scratch runtimes, Supervisor/Ingress and SteamOS/GPU behavior require their
separate verification fixtures.
