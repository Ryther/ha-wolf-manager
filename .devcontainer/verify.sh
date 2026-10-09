#!/bin/sh
set -eu
rustc -vV
cargo --version
gcc --version | head -n 1
ldd --version | head -n 1
node --version
npm --version
python3 --version
ssh -V

# The workflow contract fixtures execute Python commands in child shells too.
# Activate the environment so those children use the same interpreter and tools.
python3 -m venv _tmp/dev-verify/python
. _tmp/dev-verify/python/bin/activate
python -m pip install --only-binary=:all: -r scripts/ci/requirements.txt -r docs/requirements.txt

cargo fmt --all -- --check
CARGO_BUILD_JOBS=2 cargo clippy --locked --workspace --all-targets -- -D warnings
CARGO_BUILD_JOBS=2 cargo test --locked --workspace
CARGO_BUILD_JOBS=2 cargo test --locked -p ha-wolf-manager --test mqtt -- --ignored
CARGO_BUILD_JOBS=2 cargo test --locked -p ha-wolf-manager --test cli_runtime -- --ignored --exact live_broker_runtime_becomes_ready_and_drains_on_sigterm
CARGO_BUILD_JOBS=2 cargo test --locked -p wolf-manager-host --test catalog_daemon -- --ignored --exact actual_broker_birth_scan_concurrency_and_graceful_offline
npm ci --ignore-scripts
npm run test:ui -- --workers=1
python -m unittest discover -s tests/release -v
python -m mkdocs build --strict --site-dir _tmp/dev-verify/site
