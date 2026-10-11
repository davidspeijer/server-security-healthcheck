# LMD parser maintenance notes

The healthcheck reads LMD data; it never sources LMD shell/configuration files and
never invokes maldet (even report commands can run initialization routines).

## Scanner reliability (2026-10-11)

Before this change the healthcheck never read `clamscan_log`, scanner exit codes,
or scanner stderr. It reported lifecycle completion and zero hits independently
of scanner reliability. Runtime quarantine mismatch was only an indirect clue to
an error; there was no scanner-log rotation handling. Completion and zero hits
remain separate facts, now accompanied by an explicit scanner result.

`lmd_scanner.py` uses Python >=3.6 stdlib to read current and rotated plain/gzip
logs as data. It performs no filesystem checks on detected/inaccessible paths,
executes no metadata, and writes nothing. Date rotations are ordered by suffix,
numeric rotations by descending generation, and the current log last; mtime is
ignored. Mixed/unknown rotation names, duplicate generations, read/decompression
errors and relevant malformed/nonmonotonic markers or ambiguous DST timestamps
yield UNKNOWN. Irrelevant historical corruption is handled as described below.
No log filename is interpreted as a scan identity.

Only one start/end block wholly within the validated scan start/end epochs is
accepted, with one recorded invocation and matching hostname. Native TSV bounds
take precedence over lifecycle startup timestamps. A block can cross rotations.
Errors before/after it belong to other scans; overlapping/incomplete blocks or
multiple candidate invocations cannot prove a result. Untimestamped stderr is
attributed only inside that unique block. The format has no scan ID and cannot
resolve concurrent scanner invocations reliably: ambiguous evidence fails closed.

| Result | Severity | Meaning |
|---|---|---|
| Running | INFO | Pending; no recovery evidence |
| Exit 0, no diagnostics | INFO | Scanner invocation completed without logged errors; hits are checked separately |
| Exit 1, findings present, no diagnostics | INFO for reliability | Detection outcome, not a clean scan; malware/EICAR classification is unchanged |
| Exit 1 or 2 with only exact access-error records | WARNING | Counted access failures; coverage may be incomplete |
| Exit 2 without access-only evidence, other diagnostics, or conflicting exit/hit data | CRITICAL | Scanner failure or unreliable coverage |
| Missing/malformed/ambiguous logs | CRITICAL / UNKNOWN | Healthy coverage cannot be established |
| Missing Python/helper or failed parser process | ERROR | Healthcheck could not perform the check |
| Older scanner result after verified recovery | INFO | Historical context, not a current scanner problem |

There is no arbitrary numeric threshold. All access-error counts, including
thousands, are shown in the warning; they are never described as benign or
limited. An access-only log does not quantify what fraction was scanned and
cannot prove a daemon-wide failure. Other diagnostics and uncertainty escalate
to CRITICAL regardless of count. A future count/fraction escalation would need
an explicitly chosen, configurable coverage policy and reliable denominator.

The path context recognizes `/tmp/`, `/cache/`, `/upgrade/` and Elementor's
generated CSS directory. It reports *likely* volatile paths only. Neither this
label nor present-day existence proves a race condition, affects severity, or
excludes a path from scanning. Counts are error records, not proven unique files.

The newest completed scan is checked even while a newer scan runs. A later
completed scan with exit 0, no diagnostics and zero hits demotes the immediately
preceding completed scanner result to historical INFO. Running, unconfirmed,
failed or unknown scanner outcomes cannot prove recovery. Scanner-reliability context is bounded to the preceding completion, plus the
newest unselected failed/unconfirmed report. Completed malware findings from
other retained reports remain relevant until consistent healthy recovery. The latter
requires a valid end preceding the healthy scan's start before it can be demoted;
missing end metadata remains UNKNOWN. Runtime-quarantine policy and malware findings retain their existing
independent checks, including CRITICAL unresolved unconfirmed malware.

Read-only production validation found:

- `261004-0030.1135486`: exit 2, exactly three access-error records, all tmp/cache;
  the start/errors are in `clamscan_log-20261004.gz` and the end in
  `clamscan_log-20261011`. Thirty-five earlier errors in the same archive are
  outside this block. This scan had incomplete coverage, despite zero hits.
- `261011-0030.1266935`: exit 0, no access errors or other diagnostics; completed
  2026-10-11 08:24:29 CEST with zero hits and runtime quarantine enabled.

Upstream semantics were checked against installed ClamAV 1.4.6:
[client.c](https://github.com/Cisco-Talos/clamav/blob/clamav-1.4.6/clamdscan/client.c)
returns 1 for infections, otherwise 2 for errors, otherwise 0;
[proto.c](https://github.com/Cisco-Talos/clamav/blob/clamav-1.4.6/clamdscan/proto.c)
increments the error count on `error_stat` / `Can't access file`. A detection exit
can therefore coexist with errors. Neither exit 2 nor the access message proves
why a file was inaccessible.

The installed LMD `_clamd_retry_scan` saves the scanner return code; its
`_scan_run_clamav` disables runtime quarantine for return 2 when
`quarantine_on_error=0` and records the return code in the scanner log. It also
disables quarantine on `no reply from clamd`. LMD can still record completion
after errors. Its 19-field TSV and lifecycle metadata have no dedicated scanner
error/exit field. See also upstream
[lmd_scan.sh](https://github.com/rfxn/linux-malware-detect/blob/master/files/internals/lmd_scan.sh).

The parser cannot reconstruct missing stderr or detect silently edited logs.
This is evidence from retained LMD logs, not an independent coverage attestation.
No production configuration, log, session or webroot was changed.

## Session metadata

`_lmd_meta_get(file, key)` retains the last exact `key=` value via awk. Values may
contain `=`; only the first separator is structural. CRLF is accepted. Duplicate
states are expected in append-only metadata. No arithmetic is performed before
validating an unsigned decimal integer (no leading zeros except zero, <=12 digits).
This also prevents Bash arithmetic from interpreting injected variable/subscript
expressions. Invalid timestamps do not fall back to file mtime.

When `session.index` exists, `_lmd_native_records` reads its 14-field v2 rows
(also accepting older 9/11-field rows) and the corresponding 19-field `#LMD:v1`
TSV headers. Tab splitting preserves empty columns. IDs must have the native
numeric shape before being used in paths. Duplicate IDs warn and invalidate
completion for that record. Only `scan` / `all` records for the exact configured
target enter selection; `?` is literal and trailing slashes are significant.
Index/header common fields must agree. Absolute English dates with numeric
timezone offsets are parsed using GNU date under the C locale; relative dates,
invalid/future timestamps and inconsistent runtimes do not establish completion.
The TSV header supplies engine, signature version and runtime quarantine state at
finalization. This mutable state is not necessarily the original configured policy.
Missing TSV files cannot establish success, even for zero-hit index rows.

Native data is normalized into a private `mktemp` directory for the existing
selector, then removed. No LMD file is modified. Indexed IDs suppress fallback
to their lifecycle file, including when their native report is invalid or partial.
Unindexed lifecycle files remain eligible for running/failed status. With no
index the original lifecycle-only path remains available for compatibility.
Without a TSV this legacy path cannot independently verify native range/type;
when a TSV exists its header, record schema and metadata consistency are checked.

Index/TSV finalization is **not** successful completion: upstream's abort handler
also writes both. A matching lifecycle file must explicitly say `completed` with
a valid start inside the native scan interval and a completion epoch no earlier
than the native end and no later than now. Native end time determines freshness;
lifecycle finalization can occur later, after alert dispatch. Missing completion
evidence gives UNKNOWN/WARNING. An explicit running/failed state remains visible.
Unconfirmed native reports with hits are checked independently of selection so a
newer zero-hit report cannot erase unresolved findings. Existing details can retain old
unconfirmed findings after lifecycle cleanup. EICAR-only findings in unselected
unconfirmed/failed reports are INFO context; selected/latest completed reports
still warn. Real and unclassified detections remain CRITICAL independently of
selection or later clean completion. Absent TSVs outside the resolved daily
retention and fullscan relevance windows are INFO when the index end metadata is
valid and no lifecycle file remains; they do not establish completion. The boundary
is N+1 whole days for GNU find `-mtime +N`, using scan end metadata, never mtime.
Unresolvable retention, malformed dates and recent missing details stay conservative. Invalid reports with nonzero counts
produce unclassified critical findings. Native hit-row counts are checked even
when the header claims zero hits.

See [the pinned 2.0.1 source investigation](LMD-NATIVE-INVESTIGATION.md) for layouts,
abort behavior, cleanup and the limits of durable completion evidence. Retaining
lifecycle metadata for 336 hours is a practical option for the default 192-hour
freshness threshold; this project never changes that LMD setting itself.

Maximum valid completed epoch wins for completed scans;
otherwise the started epoch orders the session. Equal maximum completion epochs
produce CRITICAL ambiguity; every tied report is assessed and none establishes
recovery. Matching files with invalid starts
are excluded with a warning so they cannot silently overwrite trustworthy evidence.
The previous completed scan is retained for hit reporting when the selected scan
is running, failed or unknown. Other scan targets are not fullscan candidates.

A metadata file with a completed state but no valid completion epoch remains a
candidate using its start time and reports a warning if selected. The parser is
conservative about missing evidence and does not claim transaction consistency
while LMD is writing the same files.

## Events

The current event log is streamed with awk, matching a literal component tag and
an outcome regex. The last matching record is retained, then converted with GNU
date. Supported prefixes: `Sep 20 2026 06:01:00`, ISO `2026-09-20T06:01:00+02:00`,
and `2026-09-20 06:01:00`. Legacy timestamps are local time. Reload-only monitor
events, update-start announcements and downloaded version files are not success.

`{sigup}` and `{update}` are separate categories. An explicit recent failure is
unresolved when its epoch is greater than the latest successful outcome's epoch.
At equal second-resolution timestamps, append order breaks ties: only a later
success record clears a failure. Future success timestamps never clear failures.
Unparseable/future success timestamps are unknown, not fresh. An unparseable or
future failure timestamp produces a warning rather than implying recovery. No arbitrary tail
window is applied before filtering. Compressed/rotated archives are not read.

## Hit sessions

An exact `#LMD:v1` first tab-separated field is required (not a prefix match
that could also accept a future `v10` format). Hit records require 11 columns;
the first five are signature, original path, quarantine path, type and type label. This layout was
checked against the upstream 2.0.1 session renderer:

- [LMD session code](https://github.com/rfxn/linux-malware-detect/blob/master/files/internals/lmd_session.sh)
- [LMD update messages](https://github.com/rfxn/linux-malware-detect/blob/master/files/internals/lmd_update.sh)

These are references, not runtime dependencies or a promise that future upstream
formats remain identical. Keep fixtures for each additional format before adding
support. Unknown headers/invalid records cannot produce an EICAR-only verdict.
Tab splitting explicitly preserves empty fields; ordinary Bash `read` with tab
IFS would collapse them. Owner is obtained read-only from `stat -c %U` if the
original file still exists, not from undocumented trailing columns.

Only an exact case-sensitive signature in the documented allowlist denotes a known test. Path names,
quarantine paths and arbitrary descriptions cannot downgrade a non-test finding.
Hit totals must agree with parsed records. Missing records remain unclassified
critical findings. A test match is a scanner-signature classification, not a
forensic verdict about the host.

## Coverage

Discovery follows the configured DirectAdmin root's directory layout without
following symlinks. Both lists are deduplicated using `LC_ALL=C sort -u`; `comm`
uses the identical locale. The configured list strips CR, comments, blank lines
and trailing slashes. Spaces inside a path are preserved. Newline filenames are
outside LMD's newline-list format. A configured entry outside the expected set is
reported as stale/out-of-scope even if the path still physically exists.

## Configuration policy

`lib/checks/lmd_policy.sh` supplies helpers to the registered LMD module; it does
not register another check. The existing installer discovers and installs it.
The module reads selected protection/update/monitor settings as literal data,
without sourcing any external config or executing its contents. The application's
own notification credentials are not taken from LMD. Live policy and historical
scan metadata are separate observations; neither is modified.

`_lmd_config_get` distinguishes missing (1), unsupported/dynamic (2), unreadable
(3), and literal values (0, including empty). It supports comments, whitespace,
CRLF, optional `export`, quoted strings and duplicate unconditional assignments
(last wins). It rejects shell expansion/escape sequences in selected values and
non-assignment statements in config files. It is intentionally not a full shell
configuration interpreter. Unrelated assignments are never printed.

Each configuration check parses the base, environment and cron configuration
files once into a local in-memory snapshot, then resolves compatibility migrations
once. All policy lookups reuse those values and their parse statuses. The snapshot
is discarded when the check returns and rebuilt on the next invocation; no cache
files are written. The same parser serves cached and standalone lookups, preserving
missing/empty/dynamic distinctions, whole-file structural errors and last-assignment
precedence.

Lifecycle retention uses that snapshot and the existing effective-value resolver
for both runtime and daily contexts. It requires `scan_meta_cleanup_age` to be
at least the resolved fullscan age limit plus `LMD_FULLSCAN_RETENTION_MARGIN_HOURS`
(24 hours by default, positive integer). An exact zero disables LMD cleanup and
passes. Missing/empty effective values use upstream 2.0.1's `${scan_meta_cleanup_age:-24}`
fallback; malformed or unresolved values warn as UNKNOWN without printing their
contents. Validate unsigned decimal values before arithmetic. Runtime precedence
is base, compatibility, environment; daily additionally applies the cron override.
These are statically configured contexts, not proof of live process configuration;
the existing daily/cron recognizers separately diagnose unsupported execution paths.

The compatibility overlay uses a separate bounded parser for the standard LMD
legacy fallback blocks and the 2.0.1 hex-depth/worker migrations. It resolves
literal base values and earlier migrations in file order, without sourcing the
file. A nonempty modern value (including `0`) prevents a fallback. Untouched
keys are not reported as overrides. Unknown shell constructs, mismatched or
unfinished blocks still cause a warning; unknown values propagate when needed
to determine the requested setting. Other configuration files retain the strict
literal-only grammar.

Selected protection settings are compared in the base and any present overlays.
The default daily source precedence is base, compatibility overlay, sysconfig (or
its default-file fallback), then cron override. Missing cron switches inherit the
preceding value for effective-value calculation, but the separate expected explicit
override check still warns. For monitor mode, the inspected stock systemd layout
loads both environment files in order; an empty argument uses the base/runtime
`default_monitor_mode`, not the daily-only override.

The daily recognizer checks supported path bindings, source order/file guards and
directly guarded `maldet -d/-u` calls. It accepts the stock upstream update section,
not arbitrary equivalent scripts. Changes produce UNKNOWN rather than assuming
the named override file is actually used. Daily custom commands and applicable DTC
imports need review. This is bounded structural inspection, not a security proof
about arbitrary executable shell code or the scheduler's live state.

Cron definitions require exactly one active root job per configured cron.d file.
Five normalized schedule fields are compared to expectations. The tokenizer keeps
quoted spaces but does no shell expansion. It recognizes the supplied independent
`--cron-sigup` command and the `flock -n ... maldet -b -a TARGET` scan wrapper, plus
simple redirects. Other wrappers, additional arguments, environment directives,
percent expansion or absent final newlines warn. The scan's background launch does
not count as completion. No crontab is installed, changed or executed.

The supplied production configuration and cron commands are regression fixtures.
The source/guard and monitor precedence assumptions were additionally checked
against the upstream layouts:

- [daily script](https://github.com/rfxn/linux-malware-detect/blob/master/cron.daily)
- [path bindings](https://github.com/rfxn/linux-malware-detect/blob/master/files/internals/internals.conf)
- [systemd unit](https://github.com/rfxn/linux-malware-detect/blob/master/files/service/maldet.service)
- [signature schedule](https://github.com/rfxn/linux-malware-detect/blob/master/cron.d.sigup)

These references are not runtime dependencies. Location overrides select the files
being inspected; keep them aligned with the actual installation. Unsupported
packaging/layouts need a separate recognizer before claiming effective behavior.

## Module loading and scan evidence (F01–F06)

Configured integrations require their shipped module, successful syntax/load
validation, registration of the expected function by that module, and execution.
`auto` still requires the module that performs discovery; absence of the service
can subsequently make the integration inapplicable. Disabled integrations do not
require their modules. Discovered extension modules are not mandatory when absent.
The LMD policy helper is a dependency of the LMD integration. Module or execution
failures produce ERROR and exit 2; other independent loaded checks still run.

Available native TSV evidence is inspected even when lifecycle hits are zero or
`session.index` is absent. The supported `#LMD:v1` schema has 19 header fields and
11 hit fields: signature, absolute file path, quarantine path, type, type label,
hash, size, owner, group, mode, and mtime. Empty quarantine paths remain supported;
`-` is the upstream sentinel. Short records, unknown types, or conflicting signature/type prefixes are
unclassified evidence, not valid EICAR hits. Supported native hit types are
`MD5`, `SHA256`, `HEX`, `YARA`, `CSIG`, `SA`, and `CAV`. Header identity, fullscan range/target, timestamps, engine, file totals,
signature version and header/lifecycle/index/record counts must agree. Valid malware records remain CRITICAL even when other metadata conflicts.
Lifecycle-only installations without a TSV retain their existing fallback.

The schema follows upstream LMD 2.0.1 `_session_write_header` and
`_flush_hit_batch` in
[`lmd_session.sh`](https://github.com/rfxn/linux-malware-detect/blob/master/files/internals/lmd_session.sh)
and
[`lmd_quarantine.sh`](https://github.com/rfxn/linux-malware-detect/blob/master/files/internals/lmd_quarantine.sh).
Earlier fixtures with five columns were abbreviated examples, not the supported
native record schema; they have been corrected.

Completed malware findings remain relevant until a strictly later, completed
scan has a clean scanner result, zero hits, consistent available TSV evidence,
and valid required metadata. Access errors, exit 2, UNKNOWN, running/pending,
metadata conflicts, and equal completion timestamps do not establish recovery.
Equal completion times are explicitly CRITICAL and all tied findings remain
visible. Retention exceptions and unconfirmed-scan findings retain their existing
policy; this is not proof that files were removed or quarantined.

EICAR classification uses this exact, case-sensitive allowlist:

- `{HEX}test.test.eicar.1040`
- `{HEX}test.test.eicar`
- `{MD5}test.test.eicar.32555`
- `{MD5}test.test.eicar.32556`
- `{MD5}test.test.eicar.32557`
- `{CAV}Eicar-Test-Signature`
- `{CAV}Win.Test.EICAR_HDB-1`

The five LMD names were verified read-only in the distributed `hex.dat` and
`md5.dat` signature databases. The ClamAV names are documented in the
[ClamAV upstream EICAR report](https://github.com/Cisco-Talos/clamav/issues/1062).
LMD's
[`_process_clamav_hits`](https://github.com/rfxn/linux-malware-detect/blob/master/files/internals/lmd_clamav.sh)
adds `{CAV}` to these ClamAV names and strips `.UNOFFICIAL`. Unknown names,
uppercase variations, suffixes, or arbitrary names containing `eicar` remain
ordinary detections. EICAR never suppresses scanner failures or other malware.

Scanner correlation uses the requested metadata start/end interval. Relevant
markers must be ordered, match the host, and identify exactly one invocation.
Diagnostics can span gzip/plain rotations. Missing boundaries, competing starts,
duplicate invocations, and gaps in numeric rotations carrying the scan remain
UNKNOWN. Date-suffixed rotations are ordered by their explicit suffix; their
rotation frequency is not assumed to be daily.

Malformed timestamp markers are ignored only when their valid calendar portion
proves them outside the interval (with a two-hour margin for ambiguous local
clock representations). An older missing end requires independent finalized
lifecycle metadata proving that invocation ended before the requested scan.
Otherwise possible overlap remains UNKNOWN. All outstanding historical starts
require such proof. The original configured session directory is passed to the
parser even when native records are normalized into scratch metadata. Unreadable
or corrupt gzip files still fail closed when their contents cannot be excluded.

Executed command lines are parsed as data with Python `shlex`, never executed.
Recognized executables are `clamscan` and `clamdscan` at `/usr/bin`, `/bin`,
`/usr/local/bin`, and `/usr/local/cpanel/3rdparty/bin`. Supported upstream wrappers
are optional `cpulimit -l N --`, followed by optional `nice -n N` and optional
`ionice -c2 -n N`, in that order. Wrapper options must match this literal grammar. The scanner must receive a
final `-f` with an absolute file-list path. Supported preceding options are
`--infected`, `--no-summary`, `--fdpass`, `-r`, absolute-path `-c`/`-d`, and
numeric `--max-filesize=`/`--max-scansize=`. Unknown extra options and
`--version`/`--help` invocations cannot establish scan coverage.
Other wrappers, shell constructs, or a scanner name occurring only as an argument
produce UNKNOWN. The grammar follows upstream `_build_nice_command` and the
executed-line writer in
[`lmd.lib.sh`](https://github.com/rfxn/linux-malware-detect/blob/master/files/internals/lmd.lib.sh)
and
[`lmd_scan.sh`](https://github.com/rfxn/linux-malware-detect/blob/master/files/internals/lmd_scan.sh).
Runtime compatibility remains Python 3.6; the tests use Python 3.12.
