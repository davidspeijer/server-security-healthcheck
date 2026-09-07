#!/usr/bin/env bash
set -euo pipefail

[ "$(id -u)" -eq 0 ] || {
    echo "Run as root." >&2
    exit 1
}

systemctl disable --now server-security-healthcheck.timer 2>/dev/null || true

rm -f /usr/local/sbin/server-security-healthcheck
rm -rf /usr/local/lib/server-security-healthcheck
rm -f /etc/systemd/system/server-security-healthcheck.service
rm -f /etc/systemd/system/server-security-healthcheck.timer

systemctl daemon-reload

echo "Program files removed."
echo "Configuration kept in /etc/server-security-healthcheck."
