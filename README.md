# Server Security Healthcheck

Current version: **v0.5.3**.

Standalone, modular, read-only security healthcheck for Linux servers. It reports
operational problems; it does not scan files for malware, remediate, restart
services, quarantine, delete monitored files, update signatures/software or change
firewall rules. **LMD quarantine is never performed by this tool.** No monthly or
server-wide malware scan is introduced by this release.

All application settings live under `/etc/server-security-healthcheck/`.
Telegram credentials belong to this project, never to LMD or DirectAdmin.
The healthcheck works without either product when its integration is disabled.

## Integrations and requirements

Modules live in `lib/checks/`: disk usage, Apache, Rspamd, PureFTP upload scanner,
Exim queue/service, ClamAV/FreshClam and Linux Malware Detect (LMD). DirectAdmin
webroot discovery is an optional part of LMD monitoring, not a dependency.

Required: Bash 4+, GNU coreutils (including `date` and `stat`), grep, sed, awk,
findutils, and hostname (`hostname` package on EL and Debian-family systems).
Required command availability and GNU date support are
checked before checks run. Service checks need systemd; ClamAV needs journalctl;
LMD realtime monitoring needs procps/pgrep. Python 3.6+ (standard library only) is required at startup for bounded configuration
reading, and for LMD scanner/metadata, ClamAV/FreshClam, audit JSON, systemd
environment and Telegram response parsing. Production uses Python 3.6.8; tests
use Python 3.12. Curl is needed only for Telegram.
Optional application binaries are required only for enabled integrations.

Service integrations support `1` (required), `0` (disabled), or `auto` (check when
detected). An explicitly enabled but absent integration reports a problem. Disk,
DirectAdmin coverage and notifications use `0`/`1`. Fresh installations default
to auto-detection for LMD/ClamAV/Apache/Rspamd/PureFTP, disk enabled, and Exim,
DirectAdmin coverage and Telegram disabled. **Upgrades retain existing choices.**

## Install, update and uninstall

```bash
# Dependency installation is an explicit administrative operation, not a check.
sudo ./install-dependencies.sh
sudo ./install.sh
sudo nano /etc/server-security-healthcheck/healthcheck.conf
sudo nano /etc/server-security-healthcheck/telegram.conf
sudo chmod 600 /etc/server-security-healthcheck/telegram.conf
sudo server-security-healthcheck
```

To update, obtain the new source and rerun `sudo ./install.sh`. It refreshes the
units and `*.conf.example` files, and stages a complete runtime release beside
the active runtime. Shell and Python syntax and required files are validated
before an atomic symlink switch. The launcher pins one release for each run. Existing active config
files (including symlinks) are preserved. Missing new keys receive defaults; users
do not need to replace their config. Compare the installed examples to enable new
options. The installer reloads systemd's unit definitions but does not start the
timer or restart monitored services.

```bash
sudo ./uninstall.sh
```

Uninstall disables/removes this project's timer and program files and reloads
systemd. **All configuration under `/etc/server-security-healthcheck/` remains.**
These administrative installation/removal operations are separate from the
read-only healthcheck.

## Usage, timer and exit status

```bash
server-security-healthcheck --version
server-security-healthcheck --list-checks
sudo server-security-healthcheck
sudo systemctl enable --now server-security-healthcheck.timer
systemctl list-timers server-security-healthcheck.timer
journalctl -u server-security-healthcheck.service
```

The timer runs daily at 07:00 with up to 10 minutes of random delay; `Persistent`
catches up missed runs. It does not schedule LMD scans or updates. A Sunday scan
that is still running at 07:00 is reported as running within its allowed runtime.

| Status | Meaning | Effect |
| --- | --- | --- |
| PASS | Observed check is healthy | No problem |
| INFO | Context, policy, or a legitimate running scan | No problem |
| WARNING | Stale/missing evidence, configuration mismatch, test detections | Exit 1 |
| CRITICAL | Missing required realtime service/process, unresolved recent signature failure, failed/stale-running scan, non-test or unclassified hits | Exit 1 |
| ERROR | Application/configuration/dependency/execution failure | Exit 2 |

Exit **0** means no reported problems; **1** means warnings/critical findings;
**2** means the check could not execute reliably (including notification failure).
The oneshot unit explicitly contains `SuccessExitStatus=1`: findings are a
successful execution, not a systemd failure. `UNKNOWN` denotes unavailable or
untrustworthy evidence: scanner UNKNOWN is CRITICAL, ordinary policy/evidence
UNKNOWN is WARNING, and bounded metadata/audit/configuration read failures are ERROR; it is not another exit code. Any application error takes
precedence over findings in the exit status, but does not suppress notifications
for findings from other checks. Execution errors reported by checks also trigger
notifications when there are no warnings or critical findings; their messages
are included, and exit status remains 2.

## Configuration

See [`config/healthcheck.conf.example`](config/healthcheck.conf.example) for all
settings. Config uses literal `KEY=value`, optionally single/double quoted, with
blank lines and `#` comments. Values are **not shell code**: no sourcing other
files, commands, variable expansion, `export`, or arrays. Unknown names, invalid
numeric settings and invalid enums return exit 2. Existing shipped v0.3 assignments
remain accepted. Custom shell expressions must be replaced with literal values.
Keep configuration writable only by trusted administrators. `DISK_PATHS` retains
its historical whitespace-separated format (mount paths with spaces are not
supported by that setting).

`SSHC_CONFIG_DIR` and `SSHC_LIB_DIR` environment overrides support running a local
checkout without installation. They are for trusted callers; do not accept those
overrides from untrusted users in a privileged wrapper.

### LMD settings and compatibility

| Setting | Default when absent | Purpose |
| --- | --- | --- |
| `LMD_ENABLED` | `CHECK_LMD`, otherwise `0` | Enable/disable/auto; new examples use `auto` |
| `LMD_DIR` | `/usr/local/maldetect` | Installation root |
| `LMD_SERVICE` | `maldet.service` | Realtime unit; old `maldet` value still works |
| `LMD_EVENT_LOG` | `$LMD_DIR/logs/event_log`, then `/var/log/maldet/event_log` | Event source; shown `$LMD_DIR` notation describes a code default, not config expansion |
| `LMD_SESSION_DIR` | `$LMD_DIR/sess` | Fullscan metadata and TSV sessions |
| `LMD_AUDIT` | `/var/log/maldet/audit.log` | JSONL event counts; an explicitly selected missing/unreadable/invalid source is ERROR |
| `LMD_MONITOR_REQUIRED` | `1` | `0` makes realtime monitoring informational |
| `LMD_MONITOR_MAX_IDLE_MINUTES` | `90` | Maximum scan/filter heartbeat idle time |
| `LMD_MONITOR_PROCESS_PATTERN` | `inotifywait.*(--fromfile\|--from-file)` | pgrep extended regex, never executed as a command |
| `LMD_SIGUP_MAX_AGE_HOURS` | `8` | Successful signature check age (6h schedule + 2h margin) |
| `LMD_UPDATE_FAILURE_LOOKBACK_HOURS` | `48` | Recent signature/program failure window |
| `LMD_PROGRAM_UPDATE_EXPECTED` | `disabled` | `enabled`, `disabled`, `ignore` |
| `LMD_FULLSCAN_MAX_AGE_HOURS` | `FULLSCAN_MAX_AGE_DAYS × 24`, otherwise `192` | Weekly completion age, including one day margin |
| `LMD_FULLSCAN_RETENTION_MARGIN_HOURS` | `24` | Positive extra hours required for lifecycle retention above the fullscan age limit |
| `LMD_FULLSCAN_MAX_RUNTIME_HOURS` | `12` | Completed duration / running scan limit |
| `LMD_EXPECTED_FULLSCAN_PATH` | `/home/?/domains/?/public_html/` | Literal LMD scan target |
| `LMD_WEBROOT_LIST` | `LMD_MONITOR_LIST`, otherwise `$LMD_DIR/directadmin-webroots` | Realtime configured paths |
| `CHECK_DIRECTADMIN_WEBROOTS` | `0` | Opt-in discovery/coverage comparison |
| `DIRECTADMIN_HOME` | `/home` | Root for the DirectAdmin directory layout |
| `LMD_EXPECT_QUARANTINE_ENABLED` | `0` | `0`, `1`, `ignore`; compare recorded scan policy; new example explicitly sets `1` |

New keys take precedence over aliases. `CHECK_LMD`, `LMD_MONITOR_LIST` and
`FULLSCAN_MAX_AGE_DAYS` continue working without edits. `LMD_SIG_MAX_AGE_HOURS` is
accepted but deprecated/ignored: unchanged signatures may be healthy when a
recent update check says they are current. Recognized signature files must still
be readable and nonempty. `LMD_BIN` is accepted for compatibility but unused;
the healthcheck no longer invokes `maldet --report` or any other maldet command.

### Realtime monitoring and coverage

These are distinct from the scheduled fullscan. The check verifies the unit
exists, is active and has a matching inotifywait process. It examines the complete
current event log for the last `{mon} scanned ...` or `{mon} filtered ...` event;
`reloaded configuration data` alone does not prove scanning. Missing/old heartbeat
is WARNING even when the service is active. Missing service/process is CRITICAL
when realtime is required. The process regex can be adapted for another layout;
a match proves process presence, not the exact inotify watch list in the kernel.

Enable `CHECK_DIRECTADMIN_WEBROOTS=1` on the described DirectAdmin server. Discovery
finds directories at `/home/*/domains/*/public_html`, excluding `autodiscover.*`,
`autoconfig.*` and `mail.*` domains. Sorted unique sets are compared using the same
bytewise collation. Blank/comment lines and trailing slashes in the configured
list are normalized. Missing and stale/out-of-scope paths are printed, even when
counts match. A mismatch is WARNING. Discovery failure is ERROR rather than a
misleading empty-set success. This compares the configured list, not live kernel
watch state. Symlinked webroots are excluded (`find -type d`, without `-L`).

This selection matches an independent `update-maldet-webroots` synchronizer using
the same DirectAdmin directory depth and exclusions. If that script runs every
five minutes, enable the independent check with:

```ini
CHECK_DIRECTADMIN_WEBROOTS=1
DIRECTADMIN_HOME=/home
LMD_WEBROOT_LIST=/usr/local/maldetect/directadmin-webroots
```

The synchronizer maintains the list and requests an LMD reload. The healthcheck
only regenerates the expected set in private scratch files and compares it with
the configured list. It never runs the synchronizer, replaces the list or requests
a reload. A matching list proves configured coverage, not that a reload succeeded;
the separate monitor heartbeat/process checks remain necessary. Changes between
synchronizer runs can briefly produce a mismatch; the healthcheck does not wait
for or trigger the next synchronization.

```text
  PASS LMD realtime coverage: 77/77 webroots monitored
  INFO LMD coverage counts:
       Expected: 77
       Configured: 77
       Missing: 0
       Stale: 0
```

For mismatches, WARNING includes all four counts (also in Telegram); CLI output
additionally lists the missing and stale/out-of-scope paths. Counts are calculated
from the actual sets, so equal totals cannot hide different paths.

### Signature checks versus program updates

`{sigup} latest signature set already installed` is success, as is
`signature set update completed` and documented equivalent completion wording.
A downloaded version file or a download announcement is **not** success. The
latest check time, local signature version and result (`already current`,
`updated`, or `unknown success status`) are reported. A newer explicit failure
within the lookback window is CRITICAL; a later success clears older failures.
Unparseable/missing evidence is WARNING. An invalid/future failure timestamp
cannot be silently ignored as healthy evidence. Program `{update}` events are evaluated
separately and cannot contaminate signature status.

`LMD_PROGRAM_UPDATE_EXPECTED=disabled` emits INFO and suppresses program-updater
failure/age warnings. For example, an administrator may temporarily disable LMD
program updates because of an upstream checksum/integrity problem. `enabled`
reports unresolved recent failures as WARNING; `ignore` skips the check. This is
**declared policy** for operational log checks. The separate configuration check
also compares the base/override settings and the recognized daily-cron update
section against that policy. No LMD configuration is sourced and no LMD notification
credentials are extracted or used.

### Weekly fullscan metadata and hits

The primary historical sources are `sess/session.index` and the corresponding
`session.tsv.<id>`. The parser checks their identity, timestamps and common fields,
requires TSV alert type `scan` and range `all`, and matches the configured target
**exactly**, including its trailing slash. The `?` characters are literal data.
Monitor sessions, recent-file scans and other paths cannot satisfy the fullscan
check. Metadata is never evaluated or sourced, and mtime is never used for ordering.

**A native report is not proof of successful completion.** LMD 2.0.1 also writes
index/TSV reports when a scan is interrupted. Retained `scan.meta.<id>` lifecycle
data supplies explicit completion or running/failed status. Without completion
evidence the report is displayed with UNKNOWN/WARNING, while detections remain
visible. `session.last` and cron launch output are not success evidence either:
`maldet -b` only starts work in the background.

Upstream normally cleans up completed/killed/stale lifecycle metadata after
48 hours (24-hour fallback when the setting is absent). For a weekly check with
an eight-day maximum age, retaining lifecycle data for **14 days (336 hours)** is
a practical operational choice: `scan_meta_cleanup_age="336"` in LMD's effective
configuration. This keeps completion evidence; it does not change the healthcheck's
eight-day freshness limit or recover already deleted metadata. This project does
not change LMD configuration automatically. See the
[source investigation](docs/LMD-NATIVE-INVESTIGATION.md) for the evidence and limits.

The configuration policy check warns when `scan_meta_cleanup_age` is below
`LMD_FULLSCAN_MAX_AGE_HOURS + LMD_FULLSCAN_RETENTION_MARGIN_HOURS` (default
192 + 24 = **216 hours**). Equality passes; `0` also passes because it disables
lifecycle cleanup. The legacy `FULLSCAN_MAX_AGE_DAYS` age fallback is respected.
Both configured runtime and daily contexts are checked with the existing override
precedence: another scan can trigger cleanup of weekly scan metadata. Missing or
empty settings use the LMD 2.0.1 24-hour fallback; invalid/dynamic/unreadable values
warn as UNKNOWN. This check is included in `LMD_CONFIG_CHECK_ENABLED` and reuses
the read-only configuration snapshot. It does not change retention or scan status.

Without an index, older installations keep the existing lifecycle-only parser.
It reads exact `key=value` records, with the last repeated key winning. Native
records take precedence for indexed IDs, including rejection of partial reports.
Selection uses valid completed/start epochs; malformed or future native metadata
warns and cannot establish completion. Native runtime quarantine state comes from the
historical TSV header, not the current configuration. LMD can change that value
during a scan after a ClamAV error; a historical mismatch does not imply live
configuration drift.

A completed scan requires a valid completed timestamp and must be within the age
limit. Runtime, file count, engine, signature version, hits and quarantine policy
are displayed; missing fields produce diagnostics. Runtime above 12h is WARNING.
A recent running/started/paused scan is INFO while within its runtime limit; it
does not count as a completion. An overdue running scan is CRITICAL. Explicitly
failed/aborted/killed scans are CRITICAL. A new running/failed scan does not hide
hits from the most recent completed fullscan; those findings are reported too.
Unconfirmed native reports with hits are also reported, even if they are not the
latest report. Missing outcome evidence cannot establish that a later clean scan
cleared real malware; old unconfirmed findings can therefore remain visible.
EICAR-only findings from unselected unconfirmed/failed reports are INFO context.
The latest selected report and newest completed report still warn for EICAR.
A later clean completion does not suppress real or unclassified detections from
unconfirmed native reports. Historical runtime quarantine mismatch remains WARNING
for the newest completed report, even with zero hits: a scanner error may have
limited coverage. A running scan with correct policy does not clear it; a newer
completed scan replaces that report. Live configuration is checked independently.
An absent historical TSV outside daily retention (`cron_prune_days`, effective
daily overlays, default 21) is INFO when valid index end metadata places it at
least N+1 whole days ago and outside the fullscan relevance window, with no
remaining lifecycle file. Missing recent TSVs still warn and reported hits remain
CRITICAL. Existing detection details are never hidden by this exception.
No file mtime is used and a pruned report never counts as successful completion.

Available versioned `#LMD:v1` TSV sessions are read as data even when lifecycle hits are zero. The first line is
metadata; the first hit columns are signature, path, quarantine path, detection
type and type label. Empty tab fields are preserved. Only the **signature** is
checked against the exact case-sensitive EICAR allowlist in
[the parsing rules](docs/LMD-PARSING.md#module-loading-and-scan-evidence-f01f06);
an EICAR filename alone is not a test signature. Native hit records require all
11 columns. Unknown signature names are ordinary detections.

- Consistent zero hits with clean scanner evidence: PASS. Unknown or conflicting
  evidence cannot establish a healthy fullscan.
- Only EICAR signatures: WARNING in selected/latest completed reports; INFO in
  older unconfirmed/failed reports, clearly labelled test detections.
- Any non-test signature: CRITICAL; this is a scanner finding, not independently
  confirmed compromise.
- Missing/unknown/truncated hit data or count mismatch: CRITICAL unclassified
  detections, never silently treated as tests or zero hits.

Per-hit output includes signature, complete path, detection type, quarantine path
and current filesystem owner when stat can read it. The current owner may differ
from the owner at detection time. Spaces in paths are preserved; literal tabs or
newlines in paths are not supported by these line/TSV formats.

Quarantine policy comes from `quarantine_enabled` or `options`' `quarantine_hits`.
Disabled quarantine alone is INFO. A historical runtime mismatch is WARNING,
explicitly separated from live configuration. LMD can disable runtime quarantine
for ClamAV errors even with `quarantine_hits=1` in configuration. For
non-test hits with quarantine disabled, output explicitly warns that detected
files may still be accessible. Enabled policy or a stored quarantine path does
not prove that remediation succeeded. This tool never quarantines or removes files.

The example configuration now declares `LMD_EXPECT_QUARANTINE_ENABLED=1` for a
policy of automatically isolating malware detections. The intended companion LMD
settings, managed separately in LMD, are:

```ini
quarantine_hits="1"
quarantine_clean="0"
quarantine_suspend_user="0"
quarantine_on_error="0"
```

This policy requests quarantine for detections, without automatic cleaning or
account suspension, and avoids requesting quarantine solely because of a scanner
error. It is an operational choice to reduce availability impact from scanner
errors; it is not a guarantee that every detection is a true positive.

The healthcheck now verifies the live literal quarantine settings as well as the
quarantine-enabled flag recorded in scan metadata. `quarantine_clean`,
`quarantine_suspend_user` and `quarantine_on_error` are expected to be `0` unless
configured otherwise. The live file check and historical scan policy are reported
separately. No LMD settings are changed.

Upgrades preserve active configuration. To adopt this policy, explicitly set
`LMD_EXPECT_QUARANTINE_ENABLED=1` in the installed healthcheck configuration after
configuring LMD separately. If the key is absent, the compatibility default remains
`0`. Older completed scans can report a mismatch until a scan records the new
policy; their metadata describes the scan-time policy, not today's live settings.

### Live configuration and cron policy

`LMD_CONFIG_CHECK_ENABLED=1` (also the code default) enables read-only checks when
the LMD integration runs. Set it to `0` to skip this policy profile while retaining
all operational checks. The policy resolver remains Bash-only; scanner reliability
uses the Python helper described below. Existing
configuration is preserved on upgrade; missing new settings use the defaults
below. Adapt the expectations for another server layout or update policy.

| Expectation | Default | Enforcement |
| --- | --- | --- |
| `LMD_EXPECT_EMAIL_ALERT` | `1` | WARNING on mismatch |
| `LMD_EXPECT_AUTOUPDATE_SIGNATURES` | `1` | Base `conf.maldet` |
| `LMD_EXPECT_SIGUP_INTERVAL` | `6` | Base interval; derives expected signature schedule |
| `LMD_EXPECT_AUTOUPDATE_VERSION` | `1` | Base `conf.maldet` |
| `LMD_EXPECT_CRON_AUTOUPDATE_VERSION` | `0` | Daily override and combined daily value |
| `LMD_EXPECT_CRON_AUTOUPDATE_SIGNATURES` | `0` | Daily override and combined daily value |
| `LMD_EXPECT_SCAN_CLAMSCAN` | `auto` | Exact expected engine mode (`0`, `1`, `auto`) |
| `LMD_EXPECT_QUARANTINE_CLEAN` | `0` | No automatic cleaning |
| `LMD_EXPECT_QUARANTINE_SUSPEND_USER` | `0` | No automatic account suspension |
| `LMD_EXPECT_QUARANTINE_ON_ERROR` | `0` | No quarantine solely on scanner error |
| `LMD_EXPECT_MONITOR_MODE` | Configured webroot list | Effective monitor target |
| `LMD_EXPECT_INOTIFY_SLEEP` | `15` | Monitor timing |
| `LMD_EXPECT_INOTIFY_RELOADTIME` | `3600` | Monitor reload timing |
| `LMD_EXPECT_IMPORT_CONFIG_URL` | Empty | Unexpected remote import is WARNING |
| `LMD_EXPECT_POST_SCAN_HOOK` | Empty | Unexpected post-scan hook is WARNING |
| `LMD_EXPECT_SCAN_WORKERS` | `auto` | INFO only; preference, not enforced |
| `LMD_EXPECT_CRON_PRUNE_DAYS` | `21` | INFO only; preference, not enforced |
| `LMD_EXPECT_SIGUP_SCHEDULE` | `0 */6 * * *`, derived from interval | Exact five cron fields |
| `LMD_EXPECT_FULLSCAN_SCHEDULE` | `30 0 * * 0` | Sunday 00:30 |

`LMD_EXPECT_QUARANTINE_ENABLED` is shared with the historical scan check, keeping
its compatibility default of `0`; the example explicitly sets it to `1`. Policy
expectations accept `ignore` to skip that comparison. A quoted empty value for
imports/hooks means **must be explicitly empty**, not ignore. Missing or dynamic
values produce WARNING. `scan_hashtype`, `email_addr` and `email_subj` are INFO
only. Recipient/subject values are redacted; hook commands and import URLs are
never printed in mismatch messages. Healthcheck notifications still use only its
own Telegram settings.

The profile reads these locations (each has an optional path override):

| Input | Default | Override key |
| --- | --- | --- |
| Base config | `$LMD_DIR/conf.maldet` | `LMD_CONFIG_FILE` |
| Daily override | `$LMD_DIR/cron/conf.maldet.cron` | `LMD_CRON_CONFIG_FILE` |
| Compatibility overlay | `$LMD_DIR/internals/compat.conf` | `LMD_COMPAT_CONFIG_FILE` |
| Monitor environment | `/etc/sysconfig/maldet` | `LMD_SYSCONFIG_FILE` |
| Alternative environment | `/etc/default/maldet` | `LMD_DEFAULT_FILE` |
| Daily script | `/etc/cron.daily/maldet` | `LMD_DAILY_CRON_FILE` |
| Signature job | `/etc/cron.d/maldet-sigup` | `LMD_SIGUP_CRON_FILE` |
| Weekly scan job | `/etc/cron.d/maldet-fullscan` | `LMD_FULLSCAN_CRON_FILE` |

The `$LMD_DIR` notation describes defaults calculated by code, not expansion in
healthcheck configuration. The bounded daily-script recognizer also reads
`$LMD_DIR/internals/internals.conf` path bindings. If a nonempty daily custom hook
or applicable DTC import is present, additional behavior requires review.

For the supplied setup, base signature/program switches are both `1`, but the
**daily** override sets both to `0`. The recognized daily source order is base →
compatibility overlay → sysconfig (or default when sysconfig is absent) → daily
override. Policy-sensitive overrides are checked too, so a changed quarantine
setting in an overlay cannot silently bypass the base comparison.

Independent signature updates must still be scheduled via:

```cron
0 */6 * * * root /usr/local/maldetect/maldet --cron-sigup >> /dev/null 2>&1
```

The weekly definition must match the configured schedule and fullscan target:

```cron
30 0 * * 0 root /usr/bin/flock -n /var/run/maldet-fullscan.lock /usr/local/maldetect/maldet -b -a '/home/?/domains/?/public_html/' >> /var/log/maldet/fullscan-cron.log 2>&1
```

Thus a daily signature override of `0` is not confused with disabling the separate
six-hour signature job. A base program switch of `1` is not confused with enabled
daily program updates. Missing/commented jobs, different schedules or targets,
extra jobs in the selected files, unexpected commands and removed overrides are
reported. Recognized cron commands are parsed as literal tokens, never executed.

Monitor resolution reads the concatenated unit/drop-ins from `systemctl cat` as
data, including indentation, tabs and continuations. Repeated `Environment=`
assignments use the last value; an empty directive resets its assignments.
`EnvironmentFile=` values override inline assignments and are applied in file
order, regardless of their position among inline directives. Only the literal
sysconfig/default paths are supported; their corresponding configured inspection
paths are used. File-list resets are respected. Absent optional files are skipped;
unreadable files, unsupported escapes/specifiers and ambiguous layouts warn UNKNOWN.
An absent/empty mode falls back to `default_monitor_mode` in the runtime context.
`PassEnvironment=MONITOR_MODE` without a known override is UNKNOWN.
A relevant `UnsetEnvironment=` is also UNKNOWN: unsetting happens after command
argument expansion, so assuming the fallback would be incorrect.

These are **static configuration checks**, not proof that cron is executing or the
running service has reloaded its settings. The daily recognizer compares the
**whole file** against two explicit contracts: the minimal source/update layout
and the complete observed LMD 2.0.1 stock daily script, including its exact flock,
maintenance and platform sections. Blank lines, whole-line comments and indentation
are ignored; other quoting/statements/control flow must match. Extra outer guards,
functions, early exits or altered wrappers yield UNKNOWN/WARNING. Files are never
sourced or executed; `bash -n` only checks syntax. The exact supported forms and
compatibility limits are described in [the audit report](docs/AUDIT-F07-F14.md).
It is not a general shell interpreter or exhaustive audit of other cron files,
user crontabs, systemd timers, executable integrity or cron-daemon health. Schedule
comparison is textual after whitespace normalization; equivalent alternative cron
expressions should be configured explicitly. Cron environment directives, custom
wrappers and percent expansion require review. Operational heartbeats, signature
success logs and scan completion metadata remain independent checks.

Disk checks use `LC_ALL=C df -P -h`. Every record is validated; empty/unusable
successful output and malformed records are ERROR. Full mountpoint text is kept,
including internal/trailing spaces. Repeated records retain the highest percentage
for that mount; threshold equality warns. `DISK_PATHS` remains a legacy whitespace-separated list.

Audit sources are JSON Lines with a string `type` and timezone-qualified ISO `ts`.
Empty valid files mean zero events. Read failures, invalid JSON/duplicate keys or
timestamps mean ERROR with UNKNOWN counts, including when mixed with valid records.
The inclusive interval is `[now - LOOKBACK_HOURS, now]`; future events are errors.
An absent default audit path is optional only when `LMD_AUDIT` was not explicitly
set. Missing monitor commands report ERROR without suppressing independent policy,
audit, updater, coverage and scan findings. ERROR and CRITICAL can coexist; final
execution errors still take exit status 2.

### ClamAV / FreshClam

Retained settings: `CLAM_SIG_MAX_AGE_HOURS=48`, `FRESHCLAM_MAX_AGE_HOURS=36`,
`FRESHCLAM_SERVICE=clamav-freshclam.service`,
`FRESHCLAM_TIMER=clamav-freshclam-once.timer`, and
`FRESHCLAM_ONESHOT_SERVICE=clamav-freshclam-once.service`.

The active database directory comes from the selected clamd unit's supported
`ExecStart ... -c CONFIG` (including `%i`) and its `DatabaseDirectory`. An optional
`CLAMAV_CONFIG_FILE` explicitly selects the config to inspect; keep it aligned
with the service. If the directive is absent, `clamconf` reports the installed
build's default. Missing/ambiguous sources produce ERROR/UNKNOWN; other directories
are never searched for a fresher substitute. Required `daily` and `main` databases
are checked separately in `.cvd`/`.cld` format. Daily alone uses the age threshold;
main releases naturally age. Bytecode is optional and cannot mask daily. Every
present recognized file must be readable, nonempty and have a nonfuture timestamp;
if both formats exist, neither can hide a stale/invalid other file.

FreshClam reads only the selected services' seven-day journal, not rotated log
files. A start followed by successful `daily`, `main`, and `bytecode` installation/
up-to-date records, or an explicit overall completion, proves the supported
attempt complete. `Database test passed` alone never proves completion. Later
failures/new incomplete attempts invalidate older success. Process interleaving,
nonmonotone or invalid timestamps and unavailable journals warn UNKNOWN. All
future timestamps are rejected, including small clock skew; negative ages are
never reported as healthy. A bytecode-disabled/custom update layout without
supported overall completion therefore warns UNKNOWN even if daily is current.
The timer must be enabled **and active**; its oneshot must exist and must not be
failed. A successful inactive oneshot is normal. An enabled active FreshClam daemon
is an alternative updater. This does not run freshclam or update databases.

### Telegram

Set `NOTIFY_TELEGRAM=1` in `healthcheck.conf` and set `TELEGRAM_BOT_TOKEN` and
`TELEGRAM_CHAT_ID` in this project's `telegram.conf` (mode 0600).

```bash
sudo server-security-healthcheck --test-notification
```

`--test-notification` returns 0 on success and 2 for configuration, backend,
transport or Telegram API failures. It never reports a security finding (exit 1).

Warnings, critical findings and execution errors reported by checks trigger normal
notifications when Telegram is enabled. Critical findings come first, followed by
execution errors and then warnings, so policy warnings cannot push errors out of
the message through truncation. Healthy runs do not send notifications. A failed
send leaves the notification text on stderr and returns exit status 2. Success
requires both curl success and valid JSON with boolean `"ok": true`; empty,
malformed, duplicate-key, oversized (>64 KiB) and rejected responses fail. Raw
API bodies/descriptions are never logged. Credentials travel only through curl
configuration on stdin, with shell tracing disabled during credential handling.
Startup failures before notification setup (such as missing/invalid configuration
or missing core dependencies) still return 2 with local diagnostics only. This is
not an external watchdog for crashes or runs that never start.
Messages are plain text, with bounded length; full diagnostics remain in CLI/systemd output. Telegram
is the only intentional network write during a check; enable it only when sending
these operational details is appropriate. Configured LMD secrets are never used.
The bot URL, token, chat ID and message are passed through curl's stdin config,
with literal escaping and no temporary credential file. Token/chat syntax is
validated. Curl stdout/stderr are suppressed and failures receive a generic local
message. Credential loading and sending disable shell tracing while handling
values, restoring the caller's tracing afterward. Response-body `ok:false`
interpretation is unchanged.

## Example output

```text
  PASS LMD realtime service and monitor process active
  PASS LMD realtime monitor activity: 2m ago
  PASS LMD realtime coverage: 77/77 webroots monitored
  PASS LMD signatures: already current; last check 2026-09-20 06:01:00 CEST
  PASS LMD weekly full scan completed: 2026-09-20 08:11:33 CEST
  INFO LMD full scan runtime: 7h 41m (27692 seconds)
  INFO LMD full scan total_files: 915014
  INFO LMD full scan engine: clamdscan
  PASS LMD full scan: no hits
  INFO LMD automatic program update intentionally disabled
  INFO LMD automatic quarantine enabled by scan policy
```

With test detections: `WARNING Full scan contains 2 EICAR/test detections`.
With non-test detections: `CRITICAL LMD full scan found malware`, followed by the
count; per-hit paths/signatures appear immediately before the finding.

## Troubleshooting, assumptions and read-only boundary

- Run as an account that can read LMD sessions/logs and the systemd journal; root
  is the installed oneshot default. Missing evidence is not healthy evidence.
- LMD metadata/TSV parsing targets the supplied 2.x formats without requiring an
  exact LMD version. Older releases without metadata report UNKNOWN/missing-scan
  warnings; there is no unsafe invocation or cron-output fallback.
- Event logs are append-ordered. Legacy timestamps use the server's local timezone;
  ISO timestamps are also accepted. Keep the server clock/timezone correct.
  Only the configured current log is read, not compressed/rotated archives. Retain
  enough current log history for the thresholds or point to an appropriate log.
- Reads are not atomic snapshots. If LMD is appending metadata/hits during a check,
  incomplete evidence can temporarily warn; rerun after the scan completes.
- Program-update disabled and quarantine disabled are policy/context INFO, as are
  runtime/files/engine/signature-version details and a legitimate in-progress
  scan. They do not themselves cause notifications.
- Temporary coverage files are created in a private temporary directory and only
  those scratch files are cleaned up. No monitored/server data is modified.
- For notification errors, check this project's settings and outbound HTTPS access.
  For FreshClam errors inspect the selected timer/service and its journal.

## Tests and module development

Tests use Python 3.12 and its standard library. Runtime uses Python >=3.6;
the server's system Python 3.6.8 remains unchanged.

```bash
python3.12 -m unittest discover -s tests -v
git diff --check
for script in bin/server-security-healthcheck install.sh uninstall.sh install-dependencies.sh \
  lib/common.sh lib/checks/*.sh lib/notify/*.sh; do
  bash -n "$script" || exit
done
# Optional, only if already available:
shellcheck -S style bin/server-security-healthcheck lib/common.sh lib/checks/*.sh \
  lib/notify/*.sh install.sh uninstall.sh install-dependencies.sh
```

The fixture suite uses a fixed clock and mocked service/process/network commands;
it does not run a scan or contact Telegram. Installation tests use a temporary
filesystem prefix with administrative commands replaced by test stubs. Python
>=3.6 is required for all runtime helpers (stdlib/gzip support only; no pip
packages). Bash modules call helpers for bounded reads and strict data contracts.
The parser works with the server's system Python 3.6. On macOS, install Bash, coreutils,
findutils and ShellCheck, prepend their GNU binary paths and set `BASH_BIN` to the
newer Bash. These are portable local tests, not a live Linux/systemd integration
certification. See [architecture](docs/ARCHITECTURE.md), [modules](docs/MODULES.md)
and [parser notes](docs/LMD-PARSING.md) for maintenance details.

### Fail-closed scan evidence and recovery

Configured check modules (including `auto` discovery modules) must load,
register their expected check, and execute; failure is ERROR/exit 2. Disabled
checks do not require missing modules. Available LMD TSV evidence is validated
before accepting lifecycle zero-hit claims, including when the native index is
absent. Malware remains CRITICAL despite contradictory metadata.

Earlier completed malware is superseded only by strictly later, completed,
consistent zero-hit evidence with a clean scanner result. Access errors, UNKNOWN,
running/pending scans and equal completion timestamps cannot establish recovery.
Scanner UNKNOWN remains CRITICAL. EICAR uses an exact case-sensitive allowlist,
not substring matching. Relevant scanner logs can span rotations; unrelated old
corruption is excluded only when interval/metadata evidence proves it irrelevant.
See [LMD parsing rules](docs/LMD-PARSING.md#module-loading-and-scan-evidence-f01f06)
for the native schema, signatures, supported executable/wrapper grammar and
compatibility details.


## F15–F22 input, discovery and upgrade contract

`bounded_input.py` validates regular files before opening and uses nonblocking
open plus `fstat` to close the FIFO replacement race. Existing symlinks may point
to regular files; FIFO, socket and device inputs are rejected. Scanner logs are
read into one bounded snapshot and analyzed independently for each interval.
Lifecycle/native files are copied to a private temporary snapshot; metadata fields
are cached in the parent shell for that check invocation. There is no persistent
scanner/result cache and no writes to LMD's source directories. Shell parsing
loops also check elapsed budgets; timeout cannot validate a partial native adapter.
FreshClam journal output streams directly into its bounded parser.

| Input budget | Default | Test/administrative environment override |
| --- | --- | --- |
| Physical file | 64 MiB | `SSHC_MAX_FILE_BYTES` |
| Expanded file / aggregate scanner or metadata snapshot | 128 MiB | `SSHC_MAX_EXPANDED_BYTES` |
| UTF-8 record | 64 KiB | `SSHC_MAX_RECORD_BYTES` |
| Records per file | 1,000,000 | `SSHC_MAX_RECORDS` |
| Python invocation / Bash parsing scope | 20 seconds | `SSHC_READ_SECONDS` |

Overrides must be positive integers and belong in the trusted invoking environment,
not `healthcheck.conf`. Limit/read failures cannot prove recovery or yield PASS.
NUL in shell-bound records is rejected rather than silently stripped by Bash.
Console/details/notification values escape LF, CR and TAB as `\n`, `\r`, `\t`,
and other C0/DEL bytes as `\xNN`. Printable Unicode and raw classification data
are preserved. Telegram's structural separators remain normal newlines; it uses
plain text without Markdown/HTML parse mode.

Auto-discovery checks a known executable first. Otherwise it requires a successful,
valid `systemctl list-unit-files` response: a matching unit is PRESENT (including
an installed disabled/masked unit); an empty successful listing is NOT_APPLICABLE;
command failure or malformed output is ERROR/DISCOVERY_FAILED. Apache, Rspamd,
PureFTP, Exim and ClamAV share this contract. LMD checks its installation directory.
A compact summary reports invoked checks, disabled integrations, not-applicable
integrations and discovery failures. Explicit service mode checks the requested
service directly. A disabled integration does not run discovery.

`runtime.manifest` owns shipped library files. Upgrades omit old files only when a
previous manifest proves ownership; unknown/custom extensions are copied forward.
A pre-manifest installation cannot prove ownership of an unknown obsolete module,
so that file is retained for manual review. Active configuration, including broken
symlinks, is preserved. Failed staging leaves the old release selected and exits
nonzero. Fresh activation and subsequent upgrades use atomic symlink replacement;
conversion of an old real runtime directory has a short rename/switch interval and
restores its backup on handled pre-activation failure. SIGKILL/power loss in that
one-time migration interval requires manual restoration of `.previous.*`.

Previous releases and migration backups are retained for explicit administrator
rollback; no automatic pruning is performed. Unit/example files are refreshed
individually and are not part of the runtime pointer transaction. Failure after
activation is reported nonzero with the validated release still active; retry the
installer. Uninstall removes the active runtime pointer and launcher but retains
archived releases/backups (which may contain custom files) for manual cleanup.
See [the F15–F22 audit report](docs/AUDIT-F15-F22.md) for measurements and validation.
