#!/bin/sh
# Commands run on disposable hosted runners; no household endpoints are used.
set -eu
check=${1:?required canonical check name}
mkdir -p _tmp/evidence
python -m scripts.ci.check_subject --bundle _tmp/subject --sha "$CANDIDATE_SHA" > "_tmp/evidence/$check-subject.json"
case "$check" in
  rust)
    cargo fmt --all -- --check
    cargo clippy --locked --workspace --all-targets -- -D warnings
    cargo install cargo-llvm-cov --version 0.9.1 --locked
    cargo llvm-cov --locked --workspace --lcov --output-path _tmp/evidence/rust.lcov
    cargo clippy --locked --workspace --all-targets --message-format=json > _tmp/evidence/clippy.json
    python -m unittest discover -s tests/release -v
    ;;
  auth-ingress) cargo test --locked -p ha-wolf-manager --test state_auth --test http --test ha_bootstrap --test runtime ;;
  ssh-policy) cargo test --locked -p ha-wolf-manager --test ssh; cargo test --locked -p wolf-manager-host --test policy --test dispatcher ;;
  persistence) cargo test --locked -p ha-wolf-manager --test bundle; cargo test --locked -p wolf-manager-host --test state --test transactions --test quiescence ;;
  lifecycle) cargo test --locked -p ha-wolf-manager --test coordinator; cargo test --locked -p wolf-manager-host --test lifecycle --test hooks --test generated_apps --test journal --test rpc ;;
  mqtt)
    printf 'listener 1883\nallow_anonymous true\npersistence false\n' > _tmp/mqtt.conf
    docker run -d --name ci-mqtt --network host --mount "type=bind,source=$PWD/_tmp/mqtt.conf,target=/mosquitto/config/mosquitto.conf,readonly" eclipse-mosquitto:2.1.2-alpine@sha256:38c0da4f2ef84284d47b3b3eeea1cb3bdeabe81ee10caf0cd5c5ff61ee3ea408
    trap 'docker rm -f ci-mqtt >/dev/null 2>&1 || true' EXIT HUP INT TERM
    export WOLF_TEST_MQTT_HOST=127.0.0.1 WOLF_TEST_MQTT_PORT=1883
    cargo test --locked -p ha-wolf-manager --test mqtt
    cargo test --locked -p ha-wolf-manager --test mqtt -- --ignored
    cargo test --locked -p wolf-manager-host --test catalog_mqtt
    ;;
  ui)
    npm ci
    npx playwright install --with-deps chromium
    npm run test:ui -- --workers=1 --reporter=line
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
