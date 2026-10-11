# Writing modules

Checks are registered explicitly in `lib/checks.registry`. The installer and
runtime share its parser and module contract in `lib/common.sh`. An unrelated
`.sh` file under `checks/` is never discovered or executed automatically.

Previously, modules called `hc_register_check`, the runtime sourced `checks/*.sh`,
and a separate hardcoded list linked builtin checks to configuration keys.
The installer copied only `runtime.manifest`; config validation had its own key
allowlist. This permitted an allowed, enabled custom key to survive installation
without its module. The registry now supplies all check mappings and install paths.

## Add a check

1. Create `lib/checks/mariadb.sh` with a registration and a function defined in
   that file:

   ```bash
   #!/usr/bin/env bash
   hc_register_check mariadb

   check_mariadb() {
       hc_check_service mariadb "MariaDB" || true
       return 0
   }
   ```

2. Add exactly one line to `lib/checks.registry`:

   ```text
   mariadb|checks/mariadb.sh|check_mariadb|CHECK_MARIADB|0|custom|-
   ```

   Fields are `name|module|function|enable key|default|kind|dependency`.
   Module paths are relative to `lib`, restricted to `checks/<name>.sh`.
   Names, modules, functions and enable keys must be unique. Kinds are `builtin`,
   `custom`, or `helper`. Check defaults are `0`, `1`, or `auto`. Use `-` for
   no dependency. A dependency names an earlier `helper` entry; helpers have
   `-` for their enable key, default and dependency. The LMD policy module is
   an example. A helper must not call `hc_register_check`.

   This line also registers the enable key with the literal config parser.
   Do not add another enable-key mapping in the entrypoint or `common.sh`.
   Check functions must be defined in their registered module; a function
   supplied by a different helper file does not satisfy this contract.

3. Add the setting to `config/healthcheck.conf.example`, and enable it in the
   installation's configuration when appropriate:

   ```ini
   CHECK_MARIADB=1
   ```

   The runtime gates execution using the registry. Disabled checks need not be
   present at runtime. `1` and `auto` both require a valid, loaded module and
   execution of its function. With `auto`, the function performs discovery
   and may report NOT_APPLICABLE when the component is absent.

4. No additional check-module line belongs in `runtime.manifest`. That file
   lists common code, the registry, Python helpers and notification code.
   The installer derives check module ownership directly from the registry,
   installs those files, and writes the expanded `.runtime.manifest` into
   the release. Registered checks, including custom checks, are project-owned;
   removing an entry removes its previously owned module on upgrade.
   Unregistered companion files are preserved but never automatically sourced.

5. Add regression tests with explicit `SSHC_CONFIG_DIR` and `SSHC_LIB_DIR`,
   notifications disabled or mocked, and service commands mocked. Cover the
   deterministic finding, missing installed module, registration/function
   failures and isolated fresh/upgrade installation. See
   `tests/test_ph11_registry.py` for these fixtures. Check functions must return
   zero after recording findings; nonzero execution means ERROR.

6. Validate without installing on a production host:

   ```bash
   mkdir -p tmp
   PYTHONDONTWRITEBYTECODE=1 TMPDIR="$PWD/tmp" python3.12 -m unittest discover -s tests -v
   bash -n lib/checks/mariadb.sh
   git diff --check
   ```

   The isolated installer fixtures validate the staged contract before
   activation. A real installation also validates every registered module,
   registration and function provenance before switching the active release.
   Runtime checks the expanded ownership manifest against its registry and core
   manifest before execution. Missing or inconsistent required modules,
   registrations, dependencies, functions or execution produce ERROR / exit 2.

## Configuration and compatibility

Unknown configuration keys, including `CHECK_DOES_NOT_EXIST=1`, produce
ERROR / exit 2. Enable keys are accepted only through the registry, with one
existing exception: `CHECK_DIRECTADMIN_WEBROOTS` is a boolean subcheck inside
LMD, not a separate module. `LMD_ENABLED` remains the compatibility override
for `CHECK_LMD`. `CHECK_PUREFTP` remains mapped to `pureftpd` by its registry
entry. `CHECK_DISK` remains a boolean; other check modes accept `0`, `1`, `auto`.

Additional non-enable settings such as a custom service name still require
explicit allowlisting and validation in `hc_load_config`, a code default, an
example setting and tests. Configuration and registry files are literal data:
never use eval, shell expansion or source on them or on product configuration.
A module may explicitly source a trusted helper, but must propagate dependency
failures. Missing helper sources and uncaught command failures are execution
errors, even when a later command succeeds. Hidden companion preservation
(PH07) is unchanged; a missing dependency cannot make a check healthy.

## Optional components

For an `auto` check, use `hc_service_present` to distinguish absent software
from failed discovery:

```bash
check_mariadb() {
    local mode status
    mode="$(hc_mode "${CHECK_MARIADB:-0}")"
    if [ "$mode" = auto ]; then
        if hc_service_present mariadb mariadbd mysqld; then
            :
        else
            status=$?
            [ "$status" != 2 ] || return 1
            return 0
        fi
    fi
    hc_check_service mariadb "MariaDB" || true
    return 0
}
```

Use a conditional for expected nonzero discovery results, as above.
The function detects a unit file or fallback binary and reports discovery
failure as ERROR, rather than treating it as absence.

## Status contract

Use `hc_status PASS` for verified success, `hc_detail` for INFO, `hc_warn` for
WARNING, `hc_status CRITICAL` for urgent findings, and `hc_status ERROR` when
execution is unreliable. WARNING and CRITICAL produce exit 1; ERROR produces
exit 2. Do not hide failed discovery or commands behind empty healthy results.
