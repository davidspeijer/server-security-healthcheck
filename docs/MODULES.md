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
