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
