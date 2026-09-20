# Architecture

## Core

The main executable is an orchestrator only. It:

1. loads configuration;
2. loads shared helpers;
3. discovers notification modules;
4. discovers check modules;
5. executes registered checks;
6. aggregates warnings and context;
7. sends a notification only when problems exist.

It should not contain service-specific logic.

## Check module contract

A check module:

1. calls `hc_register_check <name>` when loaded;
2. defines a function `check_<name>`;
3. uses `hc_warn` for health problems;
4. uses `hc_detail` for useful context;
5. must not modify system state.

Example:

```bash
hc_register_check example

check_example() {
    hc_enabled "${CHECK_EXAMPLE:-0}" || return 0

    if something_is_wrong; then
        hc_warn "Example: something is wrong"
    fi

    hc_detail "Example value: 123"
}
```

## Notification module contract

Notification backends expose a function such as:

```bash
notify_telegram "message"
```

A notification backend must not depend on configuration from another product.

## Safety boundary

Checks are read-only.

A future remediation system, if ever added, should be a separate program rather
than mixing remediation with health monitoring.

## v0.4.0 execution and safety

Configuration is parsed as literal assignments with allowed names, typed numeric
values and validated policy enums; it is no longer sourced as shell code.
`hc_require_dependencies` checks the generic commands and GNU date. Integration
modules check their own requirements after checking enablement/availability.

`hc_status PASS|INFO|WARNING|CRITICAL|ERROR` emits immediate CLI diagnostics.
WARNING/CRITICAL add notification findings; ERROR increments `HC_ERRORS` and causes
exit 2. `hc_warn` remains a compatibility helper for WARNING; `hc_detail` emits INFO
and adds notification context. INFO/PASS never change the exit status. Modules
must report execution errors explicitly rather than relying on their final shell
command's return code; no global `set -e` is introduced.

LMD session metadata and logs are read as data. No `maldet` process is invoked.
See [LMD parsing](LMD-PARSING.md) for data formats and selection assumptions.
Coverage uses private scratch files; cleanup is restricted to those files.
Telegram truncates large summaries while local output retains full diagnostics.
Installation/removal scripts perform their explicit administrative tasks outside
the read-only check contract and preserve existing user configuration.


LMD policy helpers in `lib/checks/lmd_policy.sh` are loaded with the check modules
but do not register a standalone integration. `check_lmd` calls them only after
LMD enablement/availability checks. Live-file expectations, bounded cron/unit
recognition and historical scan evidence remain distinct. Policy parsing is
read-only, and unknown shell constructs never become a healthy effective value.
