#!/bin/sh
# Runs exclusively inside a disposable distribution container.
set -eu
family=$1
case "$family" in
  arch|cachyos)
    pacman -Syu --noconfirm openssh sudo systemd shadow python > /tmp/wolf-platform-setup.log 2>&1
    ;;
  debian|ubuntu)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update > /tmp/wolf-platform-setup.log 2>&1
    apt-get install -y --no-install-recommends openssh-server openssh-client sudo systemd passwd python3 >> /tmp/wolf-platform-setup.log 2>&1
    ;;
  fedora)
    dnf -y install openssh-server openssh-clients sudo systemd shadow-utils python3 > /tmp/wolf-platform-setup.log 2>&1
    ;;
  leap|tumbleweed)
    zypper --non-interactive refresh > /tmp/wolf-platform-setup.log 2>&1
    zypper --non-interactive install openssh sudo systemd shadow python3 >> /tmp/wolf-platform-setup.log 2>&1
    ;;
  *) exit 64 ;;
esac
exec python3 /fixture/check.py "$family"
