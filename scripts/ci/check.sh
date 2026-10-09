#!/bin/sh
# Commands run on disposable hosted runners; no household endpoints are used.
set -eu
check=${1:?required canonical check name}
mkdir -p _tmp/evidence
python -m scripts.ci.check_subject --bundle _tmp/subject --sha "$CANDIDATE_SHA" > "_tmp/evidence/$check-subject.json"
# The runner account can own unrelated processes whose executable identity is
# inaccessible. Native process fixtures need their own PID namespace, preserving
# the runner UID/GID and absolute source/cache/profile paths used by coverage.
host_cargo_home=${CARGO_HOME:-$HOME/.cargo}
build_gnu_fixture() {
  docker build -f .devcontainer/Dockerfile -t wolf-coverage-fixture .
}
isolated_cargo() {
  docker run --rm --user "$(id -u):$(id -g)" \
    --mount "type=bind,source=$PWD,target=$PWD" \
    --mount "type=bind,source=$host_cargo_home,target=$host_cargo_home" \
    --workdir "$PWD" -e CARGO_HOME="$host_cargo_home" \
    -e CARGO_TARGET_DIR="$PWD/target" \
    -e CARGO_LLVM_COV_TARGET_DIR="$PWD/target/llvm-cov-target" \
    -e PATH="/usr/local/cargo/bin:$host_cargo_home/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    wolf-coverage-fixture "$@"
}
case "$check" in
  rust)
    cargo fmt --all -- --check
    cargo clippy --locked --workspace --all-targets -- -D warnings
    cargo install cargo-llvm-cov --version 0.9.1 --locked
    build_gnu_fixture
    isolated_cargo cargo llvm-cov --locked --workspace --no-report
    # Root fixtures run only in a dedicated container, never on the runner host.
    docker run --rm --user 0 --mount "type=bind,source=$PWD,target=$PWD" \
      --mount "type=bind,source=$host_cargo_home,target=$host_cargo_home" \
      --workdir "$PWD" -e CARGO_HOME="$host_cargo_home" \
      -e PATH="/usr/local/cargo/bin:$host_cargo_home/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
      -e CARGO_TARGET_DIR="$PWD/target" \
      -e CARGO_LLVM_COV_TARGET_DIR="$PWD/target/llvm-cov-target" \
      wolf-coverage-fixture sh -eu -c '
        restore_fixture_ownership() {
          chown -R "$(stat -c %u .):$(stat -c %g .)" target "$CARGO_HOME"
        }
        trap restore_fixture_ownership EXIT
        # Add-on and catalog children drop to UID 1000; the hosted runner may
        # use another UID. Grant profile writes without world-writable outputs.
        chown 1000:1000 "$CARGO_LLVM_COV_TARGET_DIR"
        chmod 0755 "$CARGO_LLVM_COV_TARGET_DIR"
        apt-get update
        apt-get install -y --no-install-recommends openssh-server sudo
        mkdir -p /run/sshd
        ssh-keygen -A
        printf disposable-container > /run/wolf-native-validator-fixture
        WOLF_TEST_NATIVE_VALIDATORS=1 cargo llvm-cov --locked --no-report -p wolf-manager-host --lib -- --ignored --test-threads=1
        cargo llvm-cov --locked --no-report -p wolf-manager-host --test host_steam -- --ignored --exact policy_adapter_overlays_userdata_and_library_aliases_then_restores_pairing_safely
        cargo llvm-cov --locked --no-report -p ha-wolf-manager --test ha_bootstrap -- --ignored --exact native_supervisor_get_only_bearer_bounded_response_and_failure
        cargo llvm-cov --locked --no-report -p ha-wolf-manager --test cli_runtime -- --ignored --exact root_addon_startup_preserves_existing_state_and_admits_only_fresh_options
        WOLF_TEST_CLI_RUNTIME=1 cargo llvm-cov --locked --no-report -p wolf-manager-host --test cli_runtime -- --ignored --test-threads=1
      '
    printf 'listener 18889\nallow_anonymous true\npersistence false\n' > _tmp/coverage-mqtt.conf
    docker run -d --name ci-coverage-mqtt --network host --mount "type=bind,source=$PWD/_tmp/coverage-mqtt.conf,target=/mosquitto/config/mosquitto.conf,readonly" eclipse-mosquitto:2.1.2-alpine@sha256:38c0da4f2ef84284d47b3b3eeea1cb3bdeabe81ee10caf0cd5c5ff61ee3ea408
    trap 'docker rm -f ci-coverage-mqtt >/dev/null 2>&1 || true' EXIT HUP INT TERM
    export WOLF_TEST_MQTT_HOST=127.0.0.1 WOLF_TEST_MQTT_PORT=18889
    python - <<'PYREADY'
import os, socket, time
port = int(os.environ['WOLF_TEST_MQTT_PORT'])
deadline = time.monotonic() + 30
while True:
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=1):
            break
    except OSError:
        if time.monotonic() >= deadline:
            raise SystemExit('Disposable MQTT broker did not become ready')
        time.sleep(0.1)
PYREADY
    cargo llvm-cov --locked --no-report -p ha-wolf-manager --test mqtt -- --ignored
    cargo llvm-cov --locked --no-report -p ha-wolf-manager --test cli_runtime -- --ignored --exact live_broker_runtime_becomes_ready_and_drains_on_sigterm
    cargo llvm-cov --locked --no-report -p wolf-manager-host --test catalog_daemon -- --ignored --exact actual_broker_birth_scan_concurrency_and_graceful_offline
    cargo llvm-cov report --locked --workspace --ignore-filename-regex '/tests/' --lcov --output-path _tmp/evidence/rust.lcov
    cargo clippy --locked --workspace --all-targets --message-format=json > _tmp/evidence/clippy.json
    python -m venv _tmp/coverage-venv
    _tmp/coverage-venv/bin/python -m pip install --only-binary=:all: -r scripts/ci/requirements.txt
    _tmp/coverage-venv/bin/python -m coverage run --rcfile=scripts/ci/python_coverage.ini -m unittest discover -s tests/release -v
    _tmp/coverage-venv/bin/python -m coverage xml --rcfile=scripts/ci/python_coverage.ini -o _tmp/evidence/python.xml
    ;;
  auth-ingress) cargo test --locked -p ha-wolf-manager --test state_auth --test http --test ha_bootstrap --test runtime ;;
  ssh-policy) cargo test --locked -p ha-wolf-manager --test ssh; cargo test --locked -p wolf-manager-host --test policy --test dispatcher ;;
  persistence)
    cargo test --locked -p ha-wolf-manager --test bundle
    cargo test --locked -p wolf-manager-host --test state --test transactions
    build_gnu_fixture
    isolated_cargo cargo test --locked -p wolf-manager-host --test quiescence
    ;;
  lifecycle) cargo test --locked -p ha-wolf-manager --test coordinator; cargo test --locked -p wolf-manager-host --test lifecycle --test hooks --test generated_apps --test journal --test rpc ;;
  mqtt)
    printf 'listener 1883\nallow_anonymous true\npersistence false\n' > _tmp/mqtt.conf
    docker run -d --name ci-mqtt --network host --mount "type=bind,source=$PWD/_tmp/mqtt.conf,target=/mosquitto/config/mosquitto.conf,readonly" eclipse-mosquitto:2.1.2-alpine@sha256:38c0da4f2ef84284d47b3b3eeea1cb3bdeabe81ee10caf0cd5c5ff61ee3ea408
    trap 'docker rm -f ci-mqtt >/dev/null 2>&1 || true' EXIT HUP INT TERM
    export WOLF_TEST_MQTT_HOST=127.0.0.1 WOLF_TEST_MQTT_PORT=1883
    python - <<'PYREADY'
import os, socket, time
port = int(os.environ['WOLF_TEST_MQTT_PORT'])
deadline = time.monotonic() + 30
while True:
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=1):
            break
    except OSError:
        if time.monotonic() >= deadline:
            raise SystemExit('Disposable MQTT broker did not become ready')
        time.sleep(0.1)
PYREADY
    cargo test --locked -p ha-wolf-manager --test mqtt
    cargo test --locked -p ha-wolf-manager --test mqtt -- --ignored
    cargo test --locked -p wolf-manager-host --test catalog_mqtt
    ;;
  ui)
    npm ci --ignore-scripts
    ./node_modules/.bin/playwright install --with-deps chromium
    WOLF_UI_COVERAGE=1 npm run test:ui -- --workers=1 --reporter=line
    NODE_V8_COVERAGE=_tmp/evidence/node-v8 node scripts/ci/browser_coverage.cjs --browser-only
    node scripts/ci/browser_coverage.cjs
    ;;
  distro-containers) python tests/host-platform/run.py --jobs 3 ;;
  addon-schema) python -m scripts.ci.producer metadata ;;
  cargo-audit)
    cargo install cargo-audit --version 0.22.2 --locked
    cargo audit --json > _tmp/evidence/cargo-audit-results.json
    ;;
  *) echo 'Unsupported check command' >&2; exit 1 ;;
esac
python -m scripts.ci.producer report --name "$check" --sha "$CANDIDATE_SHA" \
  --scope "Frozen OCI/host/installer subject and exact source SHA; $check" --output "_tmp/evidence/$check.json"
