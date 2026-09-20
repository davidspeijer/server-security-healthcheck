# Server Security Healthcheck

Current version: **v0.4.0**.

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
findutils, and hostname. Required command availability and GNU date support are
checked before checks run. Service checks need systemd; ClamAV needs journalctl;
LMD realtime monitoring needs procps/pgrep. Curl is needed only for Telegram.
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
executable, libraries, units and `*.conf.example` files. Existing active config
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
successful execution, not a systemd failure. `UNKNOWN` appears in a WARNING when
evidence cannot be parsed; it is not another exit code. Any application error takes
precedence over findings in the exit status, but does not suppress notifications
for findings from other checks.

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
| `LMD_AUDIT` | `/var/log/maldet/audit.log` | Optional JSON event counts |
| `LMD_MONITOR_REQUIRED` | `1` | `0` makes realtime monitoring informational |
| `LMD_MONITOR_MAX_IDLE_MINUTES` | `90` | Maximum scan/filter heartbeat idle time |
| `LMD_MONITOR_PROCESS_PATTERN` | `inotifywait.*(--fromfile\|--from-file)` | pgrep extended regex, never executed as a command |
| `LMD_SIGUP_MAX_AGE_HOURS` | `8` | Successful signature check age (6h schedule + 2h margin) |
| `LMD_UPDATE_FAILURE_LOOKBACK_HOURS` | `48` | Recent signature/program failure window |
| `LMD_PROGRAM_UPDATE_EXPECTED` | `disabled` | `enabled`, `disabled`, `ignore` |
| `LMD_FULLSCAN_MAX_AGE_HOURS` | `FULLSCAN_MAX_AGE_DAYS × 24`, otherwise `192` | Weekly completion age, including one day margin |
| `LMD_FULLSCAN_MAX_RUNTIME_HOURS` | `12` | Completed duration / running scan limit |
| `LMD_EXPECTED_FULLSCAN_PATH` | `/home/?/domains/?/public_html/` | Literal LMD scan target |
| `LMD_WEBROOT_LIST` | `LMD_MONITOR_LIST`, otherwise `$LMD_DIR/directadmin-webroots` | Realtime configured paths |
| `CHECK_DIRECTADMIN_WEBROOTS` | `0` | Opt-in discovery/coverage comparison |
| `DIRECTADMIN_HOME` | `/home` | Root for the DirectAdmin directory layout |
| `LMD_EXPECT_QUARANTINE_ENABLED` | `0` | `0`, `1`, `ignore`; compare recorded scan policy |

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
**declared policy**, not verification of the actual cron/LMD autoupdate setting.
No LMD configuration is sourced and no LMD credentials are read.

### Weekly fullscan metadata and hits

The primary source is `sess/scan.meta.*`, with corresponding `session.tsv.<id>`
for hits. Cron launch output (including `/var/log/maldet/fullscan-cron.log`) does
not prove successful completion: `maldet -b` only starts work in the background.
No success is inferred from that log or from a report filename.

The parser reads exact `key=value` records and uses the **last** occurrence of
repeated keys. Thus `state=running` followed by `state=completed` is completed.
It selects only `scan.meta.*` files whose literal `path` matches the expected path
(ignoring one trailing slash), then orders by valid completed/start epoch; file
mtime and monitor sessions are ignored. Other-path scans cannot make the fullscan
healthy; when no matching scan exists a WARNING includes the expected target.
Metadata is never evaluated or sourced. Invalid/future timestamps produce warnings.

A completed scan requires a valid completed timestamp and must be within the age
limit. Runtime, file count, engine, signature version, hits and quarantine policy
are displayed; missing fields produce diagnostics. Runtime above 12h is WARNING.
A recent running/started/paused scan is INFO while within its runtime limit; it
does not count as a completion. An overdue running scan is CRITICAL. Explicitly
failed/aborted/killed scans are CRITICAL. A new running/failed scan does not hide
hits from the most recent completed fullscan; those findings are reported too.

For `hits > 0`, versioned `#LMD:v1` TSV sessions are read as data. The first line is
metadata; the first hit columns are signature, path, quarantine path, detection
type and type label. Empty tab fields are preserved. Only the **signature** is
checked case-insensitively for `eicar`; an EICAR filename alone is not a test
signature. No other test signatures are currently whitelisted.

- Zero hits: PASS.
- Only EICAR signatures: WARNING, clearly labelled test detections.
- Any non-test signature: CRITICAL; this is a scanner finding, not independently
  confirmed compromise.
- Missing/unknown/truncated hit data or count mismatch: CRITICAL unclassified
  detections, never silently treated as tests or zero hits.

Per-hit output includes signature, complete path, detection type, quarantine path
and current filesystem owner when stat can read it. The current owner may differ
from the owner at detection time. Spaces in paths are preserved; literal tabs or
newlines in paths are not supported by these line/TSV formats.

Quarantine policy comes from `quarantine_enabled` or `options`' `quarantine_hits`.
Disabled quarantine alone is INFO. A configured policy mismatch is WARNING. For
non-test hits with quarantine disabled, output explicitly warns that detected
files may still be accessible. Enabled policy or a stored quarantine path does
not prove that remediation succeeded. This tool never quarantines or removes files.

### ClamAV / FreshClam

Retained settings: `CLAM_SIG_MAX_AGE_HOURS=48`, `FRESHCLAM_MAX_AGE_HOURS=36`,
`FRESHCLAM_SERVICE=clamav-freshclam.service`,
`FRESHCLAM_TIMER=clamav-freshclam-once.timer`, and
`FRESHCLAM_ONESHOT_SERVICE=clamav-freshclam-once.service`.

Checks cover the ClamAV service, newest recognized official database freshness,
FreshClam binary, automatic updater and last successful journal update/check.
The timer must be enabled **and active**; its oneshot must exist and must not be
failed. A successful inactive oneshot is normal. An enabled active FreshClam daemon
is an alternative updater. This does not run freshclam or update databases.

### Telegram

Set `NOTIFY_TELEGRAM=1` in `healthcheck.conf` and set `TELEGRAM_BOT_TOKEN` and
`TELEGRAM_CHAT_ID` in this project's `telegram.conf` (mode 0600).

```bash
sudo server-security-healthcheck --test-notification
```

Only warnings/critical findings trigger normal notifications. Messages are plain
text, with bounded length; full diagnostics remain in CLI/systemd output. Telegram
is the only intentional network write during a check; enable it only when sending
these operational details is appropriate. Configured LMD secrets are never used.

## Example output

```text
  PASS LMD realtime service and monitor process active
  PASS LMD realtime monitor activity: 2m ago
  INFO LMD realtime coverage: 77/77 webroots monitored; configured: 77
  PASS LMD signatures: already current; last check 2026-09-20 06:01:00 CEST
  PASS LMD weekly full scan completed: 2026-09-20 08:11:33 CEST
  INFO LMD full scan runtime: 7h 41m (27692 seconds)
  INFO LMD full scan total_files: 915014
  INFO LMD full scan engine: clamdscan
  PASS LMD full scan: no hits
  INFO LMD automatic program update intentionally disabled
  INFO LMD automatic quarantine disabled by scan policy
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

```bash
python3 tests/test_healthcheck.py
shellcheck -S style bin/server-security-healthcheck lib/common.sh lib/checks/*.sh \
  lib/notify/*.sh install.sh uninstall.sh install-dependencies.sh
```

The fixture suite uses a fixed clock and mocked service/process/network commands;
it does not run a scan or contact Telegram. Installation tests use a temporary
filesystem prefix with administrative commands replaced by test stubs. Python is
only a test dependency, not a runtime dependency. On macOS, install Bash, coreutils,
findutils and ShellCheck, prepend their GNU binary paths and set `BASH_BIN` to the
newer Bash. These are portable local tests, not a live Linux/systemd integration
certification. See [architecture](docs/ARCHITECTURE.md), [modules](docs/MODULES.md)
and [parser notes](docs/LMD-PARSING.md) for maintenance details.
