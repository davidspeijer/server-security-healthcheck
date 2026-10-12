# Changelog

## [1.0.0] - 2026-10-12

First official release candidate; not yet tagged or published. Earlier 0.x
versions were internal development milestones, not public releases. The date
records candidate preparation, following the dated-entry style used below.

### Added

- Read-only modular Linux health checks for Apache, Rspamd, PureFTP upload
  scanning, Exim service/queue, disk usage, ClamAV/FreshClam and Linux Malware
  Detect (LMD), with daily systemd scheduling and opt-in DirectAdmin webroot
  coverage comparison.
- LMD realtime process/heartbeat and coverage checks, independent signature and
  program-update health, scan completion/age/runtime and retention diagnostics,
  native/session metadata and audit JSON inspection, scanner reliability and
  exact EICAR test classification. Later verified clean scans can establish
  recovery; incomplete or contradictory evidence cannot.
- Read-only LMD policy inspection for quarantine, updates, scanner mode,
  monitoring, alerts, compatibility migrations, environment/daily overrides and
  bounded cron/unit recognition. No scans, remediation, quarantine or monitored
  service restarts are performed by checks.
- Explicit `checks.registry` contract for builtin/custom checks and helper
  dependencies, shared by installer and runtime. Registered defaults and explicit
  `0`/`1`/`auto` selection support custom checks without a separate install list.

### Security

- Literal, allowlisted and typed configuration parsing without shell execution;
  unknown enable keys and invalid values fail with execution status 2.
- Required-module syntax, source, registration, dependency and function-origin
  validation, followed by invocation accounting. Missing or failed required
  checks cannot silently yield a healthy run. Unregistered shell files are not
  automatically sourced; registered modules remain trusted administrator code.
- Bounded regular-file, gzip, record, event and parsing-time inputs, validated
  private snapshots, special-file and shell-bound NUL rejection, and escaped
  control characters in displayed diagnostics.
- Component discovery distinguishes presence, verified absence and failure;
  failed discovery is ERROR, not NOT_APPLICABLE. Unreliable scanner evidence
  cannot establish a clean result or recovery.

### Changed

- Publish registry defaults before module loading and restore effective enable
  state before invocation; explicit configuration overrides defaults. Preserve
  `LMD_ENABLED` priority over `CHECK_LMD`, the `CHECK_PUREFTP` mapping and boolean
  disk/DirectAdmin subcheck semantics.
- Define stable normal-run exit codes: 0 healthy, 1 findings, 2 execution or
  configuration failure. ERROR takes precedence; systemd accepts findings with
  `SuccessExitStatus=1`. CLI supports version, help, check listing and notification
  testing. These interfaces form the first public compatibility baseline.

### Fixed

- Validate FreshClam database/update evidence, systemd timer/oneshot state, disk
  command results, audit events and service operands before accepting health.
- Resolve supported LMD compatibility migrations without executing configuration;
  preserve modern values, report unsupported constructs, and expose actual
  expected/configured/missing/stale webroot counts without rewriting coverage.
- Keep scanner failures and non-test malware critical despite conflicting
  metadata; handle historical EICAR, causal timestamps, DST and retention evidence
  without turning unknown or unavailable evidence into verified health.

### Performance

- Reuse one bounded scanner snapshot and cache metadata/policy parsing within a
  check invocation; rebuild state for subsequent runs without persistent caches.

### Installer

- Stage all registry-owned modules and core manifest files, validate shell/Python
  syntax, registrations, provenance and manifest consistency before publishing
  the active release pointer. Support fresh installs and upgrades, preserve
  existing configuration, and keep earlier releases for explicit rollback.
- Preserve ordinary/hidden unmanaged files, directories and symlinks; staged
  project entries win conflicts and obsolete files are omitted only with previous
  manifest ownership proof. Reject symlinked custom containers. Handled failure
  before activation retains the previous runtime; legacy-directory migration has
  a documented rename window. Unit/example files are refreshed separately.
- Supply dependency installation for dnf/yum and apt, including `hostname`.
  Require Bash 4+, GNU/Linux utilities and Python 3.6+ standard library; service
  integrations require their documented tools and Telegram requires curl.
  Uninstallation retains configuration and archived releases for manual cleanup.

### Notifications

- Independent opt-in Telegram configuration; validate the selected backend's
  syntax, source, required functions and function origins even on healthy runs.
- Require successful transport and bounded valid JSON with boolean `ok: true`;
  reject empty, malformed or rejected responses. Credentials travel through curl
  stdin configuration with tracing suppressed, rather than arguments or files.
- Notify for findings and execution errors, prioritize critical/error messages,
  bound message length and retain failed-send diagnostics locally.
  `--test-notification` returns 0 on success and 2 on failure.

### Tests

- Offline fixtures and mocked service, package and notification boundaries cover
  runtime contracts, parser budgets, compatibility, custom checks, fresh/upgrade
  installation, preservation and actual pre-activation interruption.
- The pre-version-change release check ran 748 tests: 747 passed, with one known
  Unix-socket sandbox skip, using Python 3.12.15; runtime helpers were also checked
  with Python 3.6.8 and Bash 4.4.20. Historical version assertions still need to be
  aligned with 1.0.0 before the final publication check.

### Documentation

- Document CLI/configuration and severity contracts, runtime requirements,
  registry/custom-module authoring, current architecture, parser assumptions,
  installation/upgrade limits and the read-only boundary. Preserve historical
  audit reports and internal development milestones for traceability.

## Development history (unreleased/internal)

The following entries retain the original dated development notes. Their version
labels and test counts describe internal snapshots, not official releases or the
current public contract; implementation details may have since been superseded.

### v0.5.3 — 2026-10-11

- Bound regular-file, gzip, record, event and parser-time input; reject special
  files and shell-bound NUL records with visible UNKNOWN/ERROR evidence.
- Share one scanner log snapshot across relevant scans; cache metadata fields
  within one invocation while preserving interval and recovery semantics.
- Stage and validate complete runtime releases before atomic activation, preserve
  configuration/custom extensions, and remove obsolete files only with manifest
  ownership proof. Retain old releases for explicit rollback.
- Escape untrusted control characters at console/detail/notification boundaries.
- Require valid Telegram JSON with boolean `ok: true` as well as curl success;
  bound responses and suppress raw API diagnostics and credentials.
- Distinguish PRESENT, NOT_APPLICABLE and DISCOVERY_FAILED; report failures as
  ERROR and include compact execution/discovery counts.
- Strengthen causal DST and real-parser integration tests; retain Python 3.6.8
  runtime compatibility and Python 3.12 tests, with no external Python packages.
- Synchronize severity, parser, notification and installation documentation.

### v0.5.2 — 2026-09-20

- Report expected/configured/missing/stale webroot counts from actual set
  comparisons, including compact mismatch counts in notifications.
- Document independent read-only coverage validation alongside the five-minute
  DirectAdmin webroot synchronizer; the healthcheck never updates or reloads LMD.

### v0.5.1 — 2026-09-20

- Parse LMD policy configuration and compatibility migrations once per check,
  reusing an in-memory snapshot for subsequent settings. Rebuild the snapshot on
  every invocation and retain the existing parsing and safety rules.
- Fixed false LMD configuration-override warnings for the standard conditional
  migrations in `internals/compat.conf` (including untouched `email_alert`).
  Resolve supported legacy mappings without executing shell code; preserve
  nonempty modern values, including `0`, and warn on unsupported constructs.
- Added regression coverage for compatibility migrations, chained values,
  dynamic legacy settings and malformed or executable input.

### v0.5.0 — 2026-09-20

- Updated the example quarantine expectation to enabled, with a separately managed
  LMD policy of no automatic cleaning, account suspension or quarantine on scanner
  error. Existing active configuration and the absent-key default remain unchanged.
- Added read-only live LMD policy validation for quarantine (including on-error),
  signature/program updates, ClamAV mode, monitoring, alerts, imports and hooks.
- Added combined base/compatibility/environment/daily-override evaluation and
  bounded structural inspection of the actual daily script and cron definitions.
- Verify independent signature scheduling and weekly fullscan target/schedule;
  keep operational evidence separate from static configuration.
- Report tuning settings as INFO only, redact sensitive values, and never source
  external config or execute cron scripts. Added production-policy regression tests.
- Prioritize critical findings before warnings in bounded Telegram summaries.

### v0.4.0 — 2026-09-20

- Expanded LMD operational health monitoring, with separate realtime monitor,
  signature updater and weekly fullscan checks.
- Added scan/filter heartbeat age checks and opt-in DirectAdmin webroot set
  comparison with missing/stale paths.
- Replaced report-command/scan-ID date parsing with read-only session metadata
  selection, duplicate-key last-value parsing and completion/age/runtime checks.
- Added LMD TSV hit classification, EICAR test labels, non-test critical findings
  and explicit diagnostics for missing or incomplete hit evidence.
- Added quarantine policy visibility without any quarantine/remediation action.
- Improved signature-update success detection, including already-current checks;
  unresolved recent signature failures are critical.
- Added intentionally disabled/ignored program-update policy; later success clears
  earlier failures when program updates are expected.
- Preserved old config aliases/defaults; deprecated signature file age as a primary
  health indicator. Install refreshes examples while preserving active configs;
  uninstall retains user configuration.
- Added literal, validated configuration loading (no shell execution), explicit
  dependency checks and visible PASS/INFO/WARNING/CRITICAL/ERROR CLI diagnostics.
- Retained ClamAV database/updater checks and added active-timer/failed-oneshot
  detection. Improved audit JSON whitespace handling and disk execution errors.
- Bounded Telegram messages while keeping full local diagnostics and independent
  credentials. Kept exit codes 0/1/2 and systemd `SuccessExitStatus=1`.
- Updated README, architecture, parser notes and example configuration; added
  offline fixture, compatibility, installation and regression tests.
- Review hardening: keep findings notifications when another check errors, reject
  unknown TSV versions, and report failed set comparisons/invalid failure timestamps
  instead of healthy results. Added five regression cases.
- No new malware scan, automatic remediation or service restart introduced.

### v0.3.0

Previous development baseline: modular service, ClamAV, disk and LMD checks,
independent Telegram configuration and systemd scheduling.
