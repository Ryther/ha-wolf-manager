#!/bin/sh
set -eu
cargo fetch --locked
npm ci
