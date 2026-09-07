#!/usr/bin/env bash
set -euo pipefail

[ "$(id -u)" -eq 0 ] || {
    echo "Run as root." >&2
    exit 1
}

rpm_packages=(bash coreutils grep sed gawk findutils util-linux curl systemd procps-ng)
deb_packages=(bash coreutils grep sed gawk findutils util-linux curl systemd procps)

if command -v dnf >/dev/null 2>&1; then
    dnf install -y "${rpm_packages[@]}"
elif command -v yum >/dev/null 2>&1; then
    yum install -y "${rpm_packages[@]}"
elif command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${deb_packages[@]}"
else
    echo "Unsupported package manager." >&2
    echo "Install manually: bash coreutils grep sed awk findutils util-linux curl systemd procps" >&2
    exit 1
fi
