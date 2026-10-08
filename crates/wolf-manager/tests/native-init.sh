#!/bin/sh
# Isolated root-container test; /data must be a fresh disposable tmpfs.
set -eu
manager=${1:?manager binary required}
[ "$(id -u)" = 0 ]
[ "$(find /data -mindepth 1 -maxdepth 1 | wc -l)" = 0 ]
printf '%s\n' '{"topic_base":"wolf-manager/v1","discovery_prefix":"homeassistant"}' >/data/options.json
chmod 600 /data/options.json
mkdir /tmp/wolf-secret
printf '%s\n' 'synthetic-bootstrap-token-256bits!' >/tmp/wolf-secret/token
chmod 700 /tmp/wolf-secret
chmod 400 /tmp/wolf-secret/token
chown -R 1000:1000 /tmp/wolf-secret
"$manager" --mode standalone --mqtt-disabled --public-origin https://fixture.test --trusted-proxy 127.0.0.1 --bootstrap-token-file /tmp/wolf-secret/token --listen 127.0.0.1:18099 >/tmp/manager-output 2>&1 &
manager_pid=$!
trap 'kill "$manager_pid" 2>/dev/null || true' EXIT
ready=false
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if "$manager" healthcheck; then ready=true;break;fi
    sleep 1
done
[ "$ready" = true ]
[ "$(stat -c '%u:%g:%a' /data)" = 1000:1000:700 ]
[ "$(stat -c '%u:%g:%a' /data/options.json)" = 0:0:600 ]
awk '/^Uid:/ {if ($2!=1000 || $3!=1000 || $4!=1000 || $5!=1000) exit 1; uid=1} /^Gid:/ {if ($2!=1000 || $3!=1000 || $4!=1000 || $5!=1000) exit 1;gid=1} /^Groups:/ {if (NF!=1) exit 1;groups=1} END {if (!uid || !gid || !groups) exit 1}' "/proc/$manager_pid/status"
kill -TERM "$manager_pid"
wait "$manager_pid"
if "$manager" healthcheck;then exit 1;fi
[ ! -e /data/ready.json ]
before_restore=$(sha256sum /data/manager.sqlite3)
"$manager" backup --destination /tmp/wolf-bundle
"$manager" restore-preview --bundle /tmp/wolf-bundle
if "$manager" restore --bundle /tmp/wolf-bundle;then exit 1;fi
[ "$before_restore" = "$(sha256sum /data/manager.sqlite3)" ]
printf '%s\n' 'Offline native CLI backup/preview and mounted-data restore refusal preserved original bytes.'
printf '%s\n' 'Native initialization, permanent UID/GID drop, options preservation, readiness, and graceful shutdown passed.'
