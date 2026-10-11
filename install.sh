#!/usr/bin/env bash
set -euo pipefail

[ "$(id -u)" -eq 0 ] || {
    echo "Run as root." >&2
    exit 1
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Stage beside the active runtime: all publication renames share a filesystem.
ACTIVE=/usr/local/lib/server-security-healthcheck
RELEASES=/usr/local/lib/.server-security-healthcheck-releases
install -d -m 0755 "$RELEASES" /etc/server-security-healthcheck
STAGE="$(mktemp -d "$RELEASES/release.XXXXXXXX")"
NEXT="$ACTIVE.next.$$"
BACKUP="$ACTIVE.previous.$$"
ACTIVATED=0
PREVIOUS_TARGET=''
[ ! -L "$ACTIVE" ] || PREVIOUS_TARGET="$(readlink -- "$ACTIVE")"
cleanup() {
    local result=$?
    rm -f -- "$NEXT"
    if [ "$ACTIVATED" = 0 ]; then
        if [ -L "$ACTIVE" ] && [ "$(readlink -- "$ACTIVE")" = "$STAGE" ]; then
            if [ -n "$PREVIOUS_TARGET" ]; then
                ln -s "$PREVIOUS_TARGET" "$NEXT"
                mv -Tf -- "$NEXT" "$ACTIVE"
            else rm -f -- "$ACTIVE"; fi
        fi
        [ ! -e "$BACKUP" ] || mv -T -- "$BACKUP" "$ACTIVE"
        rm -rf -- "$STAGE"
        [ "$result" = 0 ] || echo 'Installation failed before activation; previous runtime retained.' >&2
    elif [ "$result" != 0 ]; then
        echo 'Installation failed after activation; validated runtime is active. Retry installation.' >&2
    fi
    return "$result"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
install -d -m 0755 "$STAGE/checks" "$STAGE/notify" "$STAGE/bin"
[ -f "$ROOT_DIR/runtime.manifest" ] || { echo 'Runtime manifest missing' >&2; exit 1; }
while IFS= read -r relative; do
    [[ "$relative" =~ ^(common.sh|checks/[a-z_]+\.(sh|py)|notify/[a-z_]+\.sh)$ ]] || {
        echo 'Invalid runtime manifest' >&2; exit 1;
    }
    [ -f "$ROOT_DIR/lib/$relative" ] || { echo "Required runtime missing: $relative" >&2; exit 1; }
    install -m 0644 "$ROOT_DIR/lib/$relative" "$STAGE/$relative"
done < "$ROOT_DIR/runtime.manifest"
install -m 0644 "$ROOT_DIR/runtime.manifest" "$STAGE/.runtime.manifest"
install -m 0755 "$ROOT_DIR/bin/server-security-healthcheck" "$STAGE/bin/server-security-healthcheck"
# A launcher pins the chosen release before executing its matching entrypoint.
{
    printf '#!/usr/bin/env bash\nset -eu\n'
    printf 'release="$(cd -P -- %q && pwd)" || exit 2\n' "$ACTIVE"
    printf 'export SSHC_LIB_DIR="${SSHC_LIB_DIR:-$release}"\nexec "$release/bin/server-security-healthcheck" "$@"\n'
} > "$STAGE/launcher"
chmod 0755 "$STAGE/launcher"

# Preserve extensions unless the previous manifest proves project ownership.
for directory in checks notify bin; do
    for file in "$ACTIVE/$directory"/*; do
        [ -e "$file" ] || [ -L "$file" ] || continue
        relative="$directory/${file##*/}"
        [ ! -e "$STAGE/$relative" ] || continue
        if [ -f "$ACTIVE/.runtime.manifest" ] && grep -Fxq -- "$relative" "$ACTIVE/.runtime.manifest"; then
            continue
        fi
        cp -a -- "$file" "$STAGE/$relative"
    done
done
# Preserve companion files/directories used by local extensions as well.
for file in "$ACTIVE"/* "$ACTIVE"/.[!.]* "$ACTIVE"/..?*; do
    [ -e "$file" ] || [ -L "$file" ] || continue
    [ ! -e "$STAGE/${file##*/}" ] && [ ! -L "$STAGE/${file##*/}" ] || continue
    cp -a -- "$file" "$STAGE/${file##*/}"
done
for required in common.sh checks/apache.sh checks/clamav.sh checks/disk.sh checks/exim.sh checks/lmd.sh checks/lmd_policy.sh checks/pureftpd.sh checks/rspamd.sh notify/telegram.sh; do
    [ -f "$STAGE/$required" ] || { echo "Required staged module missing: $required" >&2; exit 1; }
done
for file in "$STAGE/common.sh" "$STAGE/launcher" "$STAGE/bin/server-security-healthcheck" "$STAGE"/checks/*.sh "$STAGE"/notify/*.sh; do
    [ -f "$file" ] || { echo 'Staged shell input is not regular' >&2; exit 1; }
    bash -n "$file" || { echo 'Staged shell syntax validation failed' >&2; exit 1; }
done
python3 - "$STAGE" <<'PY_VALIDATE'
import ast, os, sys
root = sys.argv[1]
for name in ('bounded_input.py', 'health_data.py', 'lmd_scanner.py'):
    with open(os.path.join(root, 'checks', name), encoding='utf-8') as stream:
        ast.parse(stream.read(), filename=name)
PY_VALIDATE
install -m 0644 "$ROOT_DIR/config/healthcheck.conf.example" /etc/server-security-healthcheck/healthcheck.conf.example
install -m 0600 "$ROOT_DIR/config/telegram.conf.example" /etc/server-security-healthcheck/telegram.conf.example

if [ ! -e /etc/server-security-healthcheck/healthcheck.conf ] && [ ! -L /etc/server-security-healthcheck/healthcheck.conf ]; then
    install -m 0644 "$ROOT_DIR/config/healthcheck.conf.example" \
        /etc/server-security-healthcheck/healthcheck.conf
fi

if [ ! -e /etc/server-security-healthcheck/telegram.conf ] && [ ! -L /etc/server-security-healthcheck/telegram.conf ]; then
    install -m 0600 "$ROOT_DIR/config/telegram.conf.example" \
        /etc/server-security-healthcheck/telegram.conf
fi

install -m 0644 "$ROOT_DIR/systemd/server-security-healthcheck.service" \
    /etc/systemd/system/server-security-healthcheck.service
install -m 0644 "$ROOT_DIR/systemd/server-security-healthcheck.timer" \
    /etc/systemd/system/server-security-healthcheck.timer

# The stable entrypoint resolves the active release for every invocation.
chmod 0755 "$STAGE"
ln -s "$STAGE" "$NEXT"
if [ -d "$ACTIVE" ] && [ ! -L "$ACTIVE" ]; then
    # One-time migration from the pre-manifest layout; rollback covers failure.
    mv -- "$ACTIVE" "$BACKUP"
fi
mv -Tf -- "$NEXT" "$ACTIVE"
ACTIVATED=1
install -m 0755 "$STAGE/launcher" /usr/local/sbin/server-security-healthcheck.next.$$
mv -Tf -- /usr/local/sbin/server-security-healthcheck.next.$$ /usr/local/sbin/server-security-healthcheck

# Keep prior releases/backups for explicit rollback; never recursively delete custom files.

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
