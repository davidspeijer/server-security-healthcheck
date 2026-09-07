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
