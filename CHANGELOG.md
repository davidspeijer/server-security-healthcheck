# Changelog

## v0.5.1 — 2026-09-20

- Parse LMD policy configuration and compatibility migrations once per check,
  reusing an in-memory snapshot for subsequent settings. Rebuild the snapshot on
  every invocation and retain the existing parsing and safety rules.
- Fixed false LMD configuration-override warnings for the standard conditional
  migrations in `internals/compat.conf` (including untouched `email_alert`).
  Resolve supported legacy mappings without executing shell code; preserve
  nonempty modern values, including `0`, and warn on unsupported constructs.
- Added regression coverage for compatibility migrations, chained values,
  dynamic legacy settings and malformed or executable input.

## v0.5.0 — 2026-09-20

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

## v0.4.0 — 2026-09-20

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

## v0.3.0

Previous development baseline: modular service, ClamAV, disk and LMD checks,
independent Telegram configuration and systemd scheduling.
