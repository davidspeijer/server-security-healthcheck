# Writing modules

Create a file under:

```text
lib/checks/
```

For example:

```text
lib/checks/mariadb.sh
```

Contents:

```bash
#!/usr/bin/env bash
hc_register_check mariadb

check_mariadb() {
    hc_enabled "${CHECK_MARIADB:-0}" || return 0

    hc_check_service "${MARIADB_SERVICE:-mariadb}" "MariaDB" || true
}
```

Then add defaults to:

```text
config/healthcheck.conf.example
```

For example:

```ini
CHECK_MARIADB=1
MARIADB_SERVICE=mariadb
```

No edit to the main executable is necessary. The module is discovered
automatically.

## Optional components

For software that may or may not be part of a given server's stack (e.g. a
webserver, FTP daemon or spam filter that could be swapped for an
alternative), support a three-way `CHECK_*` value instead of a plain
boolean: `1` (always check), `0` (never check), `auto` (default — only check
when the service is actually detected on this server). Use `hc_mode` and
`hc_service_present` from `common.sh`:

```bash
check_mariadb() {
    local mode
    mode="$(hc_mode "${CHECK_MARIADB:-auto}")"
    [ "$mode" = "off" ] && return 0

    if [ "$mode" = "auto" ] && ! hc_service_present "${MARIADB_SERVICE:-mariadb}" mariadbd mysqld; then
        return 0
    fi

    hc_check_service "${MARIADB_SERVICE:-mariadb}" "MariaDB" || true
}
```

`hc_service_present` treats the software as present if a systemd unit file
exists for it, or if any of the given fallback binaries are on `PATH`. This
avoids false warnings when an alternative (e.g. LiteSpeed instead of Apache,
ProFTPd instead of Pure-FTPd) is installed instead.

## Status and configuration contract (v0.4.0)

Use `hc_status PASS "..."` for a verified success, `hc_detail "..."` for INFO,
`hc_warn "..."` for WARNING, `hc_status CRITICAL "..."` for urgent health findings,
and `hc_status ERROR "..."` when execution is unreliable. Both WARNING and CRITICAL
produce exit 1; ERROR produces exit 2. Do not hide failed discovery/commands behind
empty healthy results. Explicitly check optional dependencies only for enabled,
available integrations. End successful module execution with `return 0` where its
last expression otherwise returns a health condition.

When adding a setting, extend `hc_load_config`'s allowed-name list and validation,
provide a code default, update the example and document it. Configuration is data,
not sourced shell code. Never use eval, source external product configuration or
execute command text from a setting. Preserve existing aliases where appropriate.
Add regression fixtures for parsing and meaningful behavior tests in
`tests/test_healthcheck.py`.
