#!/bin/sh
# Native-only compilation; no emulator and no rebuild in the publisher.
set -eu
architecture=${1:?amd64 or arm64 required}
case "$architecture:$(uname -m)" in
  amd64:x86_64) triple=x86_64-unknown-linux-musl ;;
  arm64:aarch64) triple=aarch64-unknown-linux-musl ;;
  *) echo 'Native architecture mismatch' >&2; exit 1 ;;
esac
version=$(python -m scripts.ci.producer metadata)
mkdir -p _tmp/native-target _tmp/native-cargo _tmp/platform/build _tmp/platform/oci
builder=rust:1.99.0-alpine@sha256:0cce0a5e0e8ba67b455257a3a02a1d99005f382748789d6464460028810f1627
docker run --rm --platform "linux/$architecture" \
  --mount "type=bind,source=$PWD,target=/workspace" \
  --mount "type=bind,source=$PWD/_tmp/native-cargo,target=/usr/local/cargo/registry" \
  --mount "type=bind,source=$PWD/_tmp/native-target,target=/workspace/target" \
  --workdir /workspace "$builder" \
  cargo build --release --locked --workspace --target "$triple"
cp "_tmp/native-target/$triple/release/ha-wolf-manager" _tmp/platform/build/ha-wolf-manager
cp "_tmp/native-target/$triple/release/wolf-manager-host" _tmp/platform/build/wolf-manager-host
python - "$architecture" <<'PY'
import sys
from pathlib import Path
from scripts.ci.verify_candidate import static_elf
machine = {'amd64': 62, 'arm64': 183}[sys.argv[1]]
for name in ('ha-wolf-manager', 'wolf-manager-host'):
    static_elf((Path('_tmp/platform/build') / name).read_bytes(), machine)
PY
# Version, native loader and scratch packaging checks execute the exact binaries.
_tmp/platform/build/ha-wolf-manager --version | grep -Fx "ha-wolf-manager $version"
_tmp/platform/build/wolf-manager-host --version | grep -Fx "wolf-manager-host $version"
cp _tmp/platform/build/wolf-manager-host _tmp/platform/wolf-manager-host
mkdir -p build
cp _tmp/platform/build/ha-wolf-manager build/ha-wolf-manager
cp _tmp/platform/build/wolf-manager-host build/wolf-manager-host
docker buildx build --platform "linux/$architecture" --provenance=false --sbom=false \
  --build-arg "VERSION=$version" --build-arg "REVISION=$CANDIDATE_SHA" \
  --output type=oci,dest=_tmp/platform.oci.tar \
  --output "type=docker,name=wolf-candidate:$architecture" -f Dockerfile .
tar -xf _tmp/platform.oci.tar -C _tmp/platform/oci
# Execute the existing bytes; the driver compiles separately on this native host.
docker run --rm --network none "wolf-candidate:$architecture" --version | grep -Fx "ha-wolf-manager $version"
rustup toolchain install 1.99.0 --profile minimal
WOLF_TEST_SCRATCH_IMAGE="wolf-candidate:$architecture" \
WOLF_TEST_SCRATCH_ROOT="$PWD/_tmp/candidate-runtime" \
  cargo +1.99.0 test --locked -p ha-wolf-manager --test runtime_candidate -- \
    --ignored --exact exact_scratch_native_tls_ssh_mqtt_state_health_and_sigterm
