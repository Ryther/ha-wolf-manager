#!/bin/sh
# Run the separately downloaded and checksum-verified native host toolkit.
# This wrapper never downloads code, chooses sudo permissions, or starts Wolf.
set -eu

if [ "$#" -lt 2 ]; then
    printf '%s\n' 'Usage: install.sh /absolute/path/wolf-manager-host install-preview|install-apply|install-activate|install-rollback [options]' >&2
    exit 64
fi
binary=$1
shift
case "$binary" in
    /*) ;;
    *) printf '%s\n' 'The host binary path must be absolute.' >&2; exit 64 ;;
esac
case "$1" in
    install-preview|install-apply|install-activate|install-rollback) ;;
    *) printf '%s\n' 'Select an explicit installation operation.' >&2; exit 64 ;;
esac
if [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
    printf '%s\n' 'A verified executable host binary is required.' >&2
    exit 64
fi
exec "$binary" "$@"
