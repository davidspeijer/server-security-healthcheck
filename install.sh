#!/usr/bin/env bash
set -euo pipefail

[ "$(id -u)" -eq 0 ] || {
    echo "Run as root." >&2
    exit 1
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

install -d -m 0755 /usr/local/lib/server-security-healthcheck/checks
install -d -m 0755 /usr/local/lib/server-security-healthcheck/notify
install -d -m 0755 /etc/server-security-healthcheck

install -m 0755 "$ROOT_DIR/bin/server-security-healthcheck" \
    /usr/local/sbin/server-security-healthcheck
install -m 0644 "$ROOT_DIR/lib/common.sh" \
    /usr/local/lib/server-security-healthcheck/common.sh

for f in "$ROOT_DIR"/lib/checks/*.sh; do
    install -m 0644 "$f" \
        "/usr/local/lib/server-security-healthcheck/checks/$(basename "$f")"
done

for f in "$ROOT_DIR"/lib/notify/*.sh; do
    install -m 0644 "$f" \
        "/usr/local/lib/server-security-healthcheck/notify/$(basename "$f")"
done

if [ ! -f /etc/server-security-healthcheck/healthcheck.conf ]; then
    install -m 0644 "$ROOT_DIR/config/healthcheck.conf.example" \
        /etc/server-security-healthcheck/healthcheck.conf
fi

if [ ! -f /etc/server-security-healthcheck/telegram.conf ]; then
    install -m 0600 "$ROOT_DIR/config/telegram.conf.example" \
        /etc/server-security-healthcheck/telegram.conf
fi

install -m 0644 "$ROOT_DIR/systemd/server-security-healthcheck.service" \
    /etc/systemd/system/server-security-healthcheck.service
install -m 0644 "$ROOT_DIR/systemd/server-security-healthcheck.timer" \
    /etc/systemd/system/server-security-healthcheck.timer

systemctl daemon-reload

echo "Installed Server Security Healthcheck."
echo
echo "Configure:"
echo "  /etc/server-security-healthcheck/healthcheck.conf"
echo "  /etc/server-security-healthcheck/telegram.conf"
echo
echo "Test:"
echo "  server-security-healthcheck --test-notification"
echo "  server-security-healthcheck --list-checks"
echo "  server-security-healthcheck"
echo
echo "Enable timer:"
echo "  systemctl enable --now server-security-healthcheck.timer"
