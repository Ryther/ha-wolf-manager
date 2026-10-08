#!/bin/sh
# Compile only the upstream version actually bundled by the pinned action.
set -eu
git clone --quiet --depth 1 --branch v17.6.0 https://github.com/googleapis/release-please.git _tmp/release-please-fixture
actual=$(git -C _tmp/release-please-fixture rev-parse HEAD)
[ "$actual" = 712fcf01effd08d7b0e7b1fd3861f2cb388bc8d1 ] || exit 1
(
  cd _tmp/release-please-fixture
  npm ci --ignore-scripts
  npm run compile
)
node tests/release/release-please-fixture.cjs _tmp/release-please-fixture
