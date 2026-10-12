# Architecture

## Registry and orchestration

The main executable orchestrates configuration, required module loading, check
invocation, result aggregation and notification. Service-specific logic belongs
in check modules. There is no wildcard discovery of check or notification modules:
an unrelated `.sh` file in `checks/` or `notify/` is not automatically sourced.

`lib/checks.registry` is literal declarative data shared by installer and runtime.
Its seven fields are `name|module|function|enable key|default|kind|dependency`.
It maps each check to a module path relative to `lib`, an expected function,
a configuration key and a default (`0`, `1`, or `auto`). Kinds are `builtin`,
`custom`, and `helper`. Names, module paths, functions and enable keys must be
unique. A dependency names an earlier helper; helpers have no enable key or
default, and do not register an executable check. The LMD policy helper is loaded
for its dependent LMD check.

The registry supplies dependency and selection metadata; component discovery
itself belongs to the registered check function. It does not encode or verify
all discovery logic. Installer and runtime use the same registry parser, module
loader and ownership-manifest generator in `lib/common.sh`.

The lifecycle is registry validation → configuration/default resolution →
manifest/install contract → required module loading → function provenance
validation → invocation → execution accounting. Installation is a separate phase
that stages and validates all registered modules before publication. Runtime
resolves configuration and selects the checks required for that invocation.

## Configuration and effective enable state

Configuration is bounded, allowlisted, typed literal data, never sourced or
expanded as shell code. Explicit configuration overrides the registry default;
only an unset enable variable falls back to that default. The effective modes
are `0` (disabled), `1` (required), and `auto` (required check with component
discovery). `CHECK_DISK` remains boolean. `CHECK_DIRECTADMIN_WEBROOTS` is a boolean
LMD subcheck rather than a registry check. `CHECK_PUREFTP` maps to `pureftpd`.
The compatibility alias `LMD_ENABLED` takes priority over `CHECK_LMD`.

Unknown keys, unregistered `CHECK_*` keys (except the explicit subcheck above),
invalid values and malformed registry entries produce ERROR / exit 2. Additional
non-enable module settings still require explicit config-parser validation.

The entrypoint snapshots each effective enable value and publishes it before
loading modules. Immediately before invoking a selected check it reasserts that
value and reads it back; failed publication or restoration is ERROR. Both LMD
variables receive the resolved LMD value. This makes existing module guards
consume the same value used for selection, including registry defaults.

## Check loading and execution contract

A check must have a registry entry matching its module file, expected function
and enable key. Required modules must be regular, readable files, pass `bash -n`,
and source successfully. Each non-helper module calls `hc_register_check` exactly
once with its registered name and defines the expected function in that same
file. Helpers add no check registration. Definition-file provenance is checked
using `hc_function_from`; a function supplied by another file is insufficient.

For normal execution, `1` and `auto` require loading and invocation; `0` skips
the check and need not have a module present at runtime. `--list-checks` also
loads disabled registered checks to list registrations. Required helpers must
load successfully. Before invocation the entrypoint rechecks registration count,
function provenance and effective enable state. A required check that was not
invoked records ERROR. Missing modules, invalid syntax, source failures,
registration mismatches and dependency or provenance failures produce exit 2.

Check functions record findings and return zero after doing so. Nonzero returns
and uncaught command failures are execution errors, even if a later command
succeeds. Expected nonzero discovery results must be handled explicitly. The
orchestrator does not rely on global `set -e`. Execution accounting proves that
a function was invoked; it cannot prove that arbitrary module code performed
its intended semantic work. Registered shell modules remain trusted code sharing
the runtime shell, rather than sandboxed plugins.

Practical authoring steps and examples are in [MODULES.md](MODULES.md).

## Auto discovery

`auto` discovers the component through an already registered and invoked check;
it does not search for module files. Discovery distinguishes PRESENT, ABSENT
(reported as NOT_APPLICABLE), and FAILED. Absence is valid only after successful
discovery; failed or malformed discovery records ERROR / exit 2 rather than
NOT_APPLICABLE or a healthy result.

For service checks, `hc_service_present` accepts a known fallback executable or
a validated unit-file listing as presence. A successful empty listing indicates
absence; unavailable commands, failed queries and malformed listings indicate
failure. Component-specific checks implement their own bounded discovery and
read contracts.

## Notification backend

Telegram is the currently supported selected backend. When `NOTIFY_TELEGRAM=1`
or `--test-notification` is requested, `notify/telegram.sh` is required even on
a healthy run. It must be regular and readable, pass syntax validation and
source successfully, and supply both `notify_telegram` and `notify_test` from
that file. Their provenance is checked after loading check modules and again
after check execution, before using the backend. A missing or broken selected
backend is an execution failure / exit 2.

A Telegram send succeeds only when curl transport succeeds and the bounded JSON
response contains boolean `ok: true`. Empty, malformed or rejected responses
and transport failures fail the send. Credentials are validated, tracing is
suppressed around credential handling, and curl receives credentials through
stdin configuration rather than credential-bearing arguments or temporary files.
Long messages are truncated with a pointer to local diagnostics; failed sends
retain the message on stderr.

Normal runs send notifications when findings or execution errors exist, provided
the selected backend is ready. Healthy runs do not send. `--test-notification`
returns 0 on success and 2 on failure; it does not return the findings status 1.

## Installer and runtime release

The root `runtime.manifest` lists core library files. The installer expands it
with every check-module path from the registry into the staged release's
`.runtime.manifest`, and copies the core manifest as `runtime.manifest`.
Installer and runtime do not maintain independent check-module lists. All
registered source modules must be available for installation, including disabled
and custom checks.

Before activation, the installer validates owned shell syntax, entrypoint and
launcher syntax, Python helper ASTs, all registered module loads, registration
counts, function provenance and the expanded manifest. Validation sources trusted
modules in a subshell but does not invoke check bodies. At startup, an installed
runtime compares its expanded ownership manifest with the shared generator's
output; inconsistent or missing installed metadata is ERROR / exit 2. Direct
source-tree fixtures without an installed entrypoint may omit that metadata,
while retaining the required-module contract.

Staging occurs beside the active runtime. Activation publishes an active-release
symlink by atomic rename; the launcher resolves and pins a release so its
entrypoint and library match. Ordinary and hidden unmanaged files, directories
and symlinks are preserved with `cp -a`, without following symlink targets.
Staged project entries win conflicts, and obsolete entries proven owned by the
previous manifest are omitted. The `checks/`, `notify/` and `bin/` containers
must not themselves be symlinks. Preservation failures block activation.

Handled failures before activation retain the previous runtime. Prior releases
and migration backups are kept for explicit rollback. Migrating a legacy real
runtime directory involves a rename window; this is not an absolute crash or
power-loss guarantee. Configuration examples and systemd units are refreshed
separately before runtime activation, while existing configuration is preserved.
They and launcher publication are not one transaction with the runtime pointer.
Failures after activation leave the validated runtime selected and require retry.

## Results and read-only boundary

`hc_status` reports PASS, INFO, WARNING, CRITICAL or ERROR immediately.
`hc_warn` records WARNING and `hc_detail` adds INFO context. WARNING/CRITICAL
produce findings status 1; execution ERROR takes precedence with status 2.
A normal run without findings or errors returns 0. PASS and INFO do not change
the exit status. Errors do not suppress notification of other findings.

Checks inspect services, bounded configuration/log inputs and validated snapshots;
they must not modify system state. Product configuration is read as data, not
executed. LMD inspection uses logs and metadata and never starts `maldet` or a
scan. Its parser has byte, line and time budgets and private scratch cleanup;
see [LMD-PARSING.md](LMD-PARSING.md). Unknown policy values are not reported as
verified healthy settings. Installer and remover are separate administrative
programs; remediation does not belong in check functions.

These validation boundaries reject missing required checks, malformed registries,
unknown enable keys, unexpected function origins and broken selected backends.
They do not make arbitrary trusted module code safe or prove all component
behavior. The runtime never grants automatic execution to wildcard module files.
