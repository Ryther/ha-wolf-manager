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
cargo test --locked -p wolf-core
CARGO_BUILD_JOBS=2 cargo test --locked -p ha-wolf-manager --test ssh --test coordinator
CARGO_BUILD_JOBS=2 cargo test --locked -p ha-wolf-manager --test mqtt -- --ignored
npm run test:ui
python3 -m unittest discover -s tests/release -v
