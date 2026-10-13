# LMD production parsing investigation (2026-10-13)

The source-tree reproduction used read-only production LMD inputs, with notification
transport disabled and credentials removed from the private configuration copy.
No production configuration, logs, databases, services or installation were changed.

## Root cause

The native adapter starts its `SSHC_READ_SECONDS` clock before resolving retention.
The retention-only path did not populate the existing literal policy cache. Resolving
compatibility migrations consequently reopened and parsed the 603-line base policy
85 times. At 20 elapsed seconds, the adapter failed before processing its first
native session row. The observed index was only 1,454 bytes / ten records, not an
exceptionally large session history. Increasing the budget would conceal the repeated
work and has not been done.

Measured production policy reads before/after: 88/4, 2,171,583/31,683 bytes,
51,429/777 lines. These count repeated policy reads, not unique input size or scanner
snapshot bytes. Direct fullscan execution changed from 20 seconds / ERROR to about
two seconds / no parsing ERROR; ordinary findings retain their original severity.

The four policy sources are base configuration (25,475 bytes / 603 lines),
compatibility rules (5,357 / 150), daily override (385 / 12), and selected environment
override (466 / 12). The largest base record is 144 bytes. A synthetic test reproduces
the base/compatibility/daily sizes and line counts, migration dependencies and a
ten-session history spread across old expired reports and recent completed scans.
It contains no production paths or contents.

An isolated synthetic benchmark with the same four policy sizes measured:

| Metric | Before | After |
|---|---:|---:|
| Policy read calls | 88 | 4 |
| Policy bytes processed | 2,171,583 | 31,683 |
| Policy lines parsed | 51,429 | 777 |
| Native session rows processed | 10 | 10 |
| Wall runtime | 17.122 s | 1.067 s |
| Native phase budget | 20 s | 20 s |

The synthetic pre-fix run completed under the deadline on this run; the actual
production reproduction hit it. Wall time is load-dependent. This benchmark
demonstrates reduced repeated work with unchanged history, not a deterministic
performance guarantee. Peak buffered memory was not measured; the largest single
policy input remained 25,475 bytes and scanner/snapshot buffering was unchanged.

## Resource limits (unchanged)

| Name | Default | Application / purpose | Failure |
|---|---:|---|---|
| SSHC_MAX_FILE_BYTES | 64 MiB | Regular-file preflight, stored input size | Parser rejection, ERROR/2 at native snapshot/retention caller |
| SSHC_MAX_EXPANDED_BYTES | 128 MiB | Per-file decoded input; aggregate metadata/scanner snapshot and scanner read | Whole capture/parser rejection, ERROR/2 |
| SSHC_MAX_RECORD_BYTES | 64 KiB | Bounded readline, including newline | Parser rejection, ERROR/2 |
| SSHC_MAX_RECORDS | 1,000,000 | Lines per input stream, including comments | Parser rejection, ERROR/2 |
| SSHC_READ_SECONDS | 20 seconds | Helper alarm/monotonic deadline; shell policy/native/selection/hit phases | ERROR/2; shell deadline is exclusive: elapsed >= limit fails |

There are no separate numeric maximum-file, gzip-file, event or historical-session
counts. Their work remains bounded by aggregate bytes, stream record limits and
helper/phase deadlines. These are phase budgets, not a single whole-check timeout.
Time failures now report elapsed seconds, configured limit, processed native record
count and the safe source category (including retention policy resolution).

## Functional history

Fullscan selection needs the latest reliable completed scan, pending scans, unsuperseded
failures/hits and strictly newer healthy recovery evidence. The default freshness
window is 192 hours and runtime threshold 12 hours; discarding every older row could
hide unresolved failures. Missing old TSV reports remain context only when validated
index timestamps put them beyond daily retention plus one day and the fullscan
freshness window. Production retention was 21 days. Index records with other targets
are skipped after validation. History selection and recovery logic were not changed.

Monitor activity uses a 90-minute default idle threshold. Audit events use the
24-hour default lookback. Signature updates need the latest update and recovery
ordering, with an eight-hour freshness threshold; update failures have a 48-hour
lookback. Those log checks do not use native session metadata. Scanner evidence must
cover the selected scan's validated start/end interval and relevant historical
recovery intervals, including blocks crossing rotations; a tail-only shortcut would
break attribution.

## Snapshot and execution contracts

The fix reuses invocation-local configuration maps, parsing each literal policy
source once before compatibility resolution. Scanner/native snapshot capture,
inventory and immutable readers are unchanged: no live scanner/metadata reopen or
second glob was added. Resource failure resolving retention is an ERROR, never a
successful default. Boundaries verify the exclusive time deadline at 19/20/21
seconds and file-size acceptance at the limit, with ERROR/2 below required size.

Expected status 1 for absent compatibility keys or an empty custom hook is now
handled in typed conditionals. Such statuses previously fired the inherited ERR
trap, producing a misleading `Check execution failed: lmd`. Unexpected execution
errors and concrete budget failures still retain ERROR accounting and exit 2;
the orchestration error was not globally suppressed.

Policy status handling is context-specific: a key lookup accepts 0 (literal,
including an empty value), 1 (missing key), 2 (unresolvable data) and 3
(unavailable/resource failure). Whole-file capture and compatibility computation
accept only 0, 2 and 3; status 1 there is an unexpected execution failure, not
missing data. Unexpected statuses propagate as internal status 4 and become an
explicit ERROR at the parent configuration/native boundary, including when a
command substitution would otherwise lose severity counters. The concrete ERROR
and existing central accounting preserve process exit 2 without relying solely
on Bash's context-sensitive inherited ERR trap.

## ClamAV context

Read-only `clamconf -n` resolved `/var/lib/clamav`, ClamAV 1.4.6, daily.cld version
28151, main.cvd/main.cld both version 63, bytecode.cvd/bytecode.cld both version 339.
Different file mtimes do not establish different signature versions. The 1.4.6
[loader](https://github.com/Cisco-Talos/clamav/blob/clamav-1.4.6/libclamav/cvd.c)
prefers CLD over equal-version CVD during directory loading. This establishes
on-disk selection, not what an already running daemon has loaded in memory.
The healthcheck reports present files in the resolved database directory and does
not claim each is the loaded daemon database. Main ages are informational and
bytecode is optional. No falsely active-state assertion was established, so ClamAV
code and database files were left unchanged.

## Read-only native input inventory

Only filenames and numeric metadata are included; no report contents or detected
paths. The directory had 36 entries, of which these 31 belong to the native
snapshot inventory (7,304 bytes / 81 lines).

| File | Bytes | Lines | Max record bytes (without newline) | Mtime epoch |
|---|---:|---:|---:|---:|
| `scan.meta.261004-0030.1135486` | 432 | 21 | 53 | 1791098176.2028224 |
| `scan.meta.261011-0030.1266935` | 432 | 21 | 53 | 1791699869.6715016 |
| `session.index` | 1454 | 11 | 164 | 1791699869.6385014 |
| `session.tsv.260921-1606.838` | 180 | 1 | 179 | 1790002392.975321 |
| `session.tsv.260922-1622.838` | 177 | 1 | 176 | 1790169402.8402054 |
| `session.tsv.260923-1517.841` | 146 | 1 | 145 | 1790169426.525248 |
| `session.tsv.260924-1431.841` | 180 | 1 | 179 | 1790255828.487514 |
| `session.tsv.260925-1445.841` | 180 | 1 | 179 | 1790342233.9013898 |
| `session.tsv.260926-1501.841` | 180 | 1 | 179 | 1790428645.495062 |
| `session.tsv.260927-0030.806547` | 237 | 1 | 236 | 1790490899.0808346 |
| `session.tsv.260927-1509.841` | 177 | 1 | 176 | 1790578421.100385 |
| `session.tsv.260928-0854.824` | 152 | 1 | 151 | 1790615737.2637155 |
| `session.tsv.260928-1916.846` | 152 | 1 | 151 | 1790688680.9756722 |
| `session.tsv.260929-1531.853` | 146 | 1 | 145 | 1790688714.7539043 |
| `session.tsv.260930-1513.853` | 181 | 1 | 180 | 1790775124.9377472 |
| `session.tsv.261001-1520.853` | 180 | 1 | 179 | 1790861525.2513187 |
| `session.tsv.261002-1529.853` | 180 | 1 | 179 | 1790947936.516783 |
| `session.tsv.261003-1506.853` | 180 | 1 | 179 | 1791034342.5854173 |
| `session.tsv.261004-0030.1135486` | 238 | 1 | 237 | 1791098176.1598222 |
| `session.tsv.261004-1512.853` | 180 | 1 | 179 | 1791120751.4570994 |
| `session.tsv.261005-1519.853` | 177 | 1 | 176 | 1791229562.4937587 |
| `session.tsv.261005-2146.841` | 146 | 1 | 145 | 1791229597.1002834 |
| `session.tsv.261006-2052.841` | 180 | 1 | 179 | 1791316000.8063827 |
| `session.tsv.261007-2058.841` | 180 | 1 | 179 | 1791402408.8341606 |
| `session.tsv.261008-2108.841` | 180 | 1 | 179 | 1791488816.3184705 |
| `session.tsv.261009-2116.841` | 180 | 1 | 179 | 1791575218.235585 |
| `session.tsv.261010-2123.841` | 180 | 1 | 179 | 1791707174.3982027 |
| `session.tsv.261011-0030.1266935` | 238 | 1 | 237 | 1791699869.6275015 |
| `session.tsv.261011-1026.822` | 152 | 1 | 151 | 1791724071.803918 |
| `session.tsv.261011-1508.828` | 146 | 1 | 145 | 1791724105.6537642 |
| `session.tsv.261012-1426.828` | 181 | 1 | 180 | 1791810507.728564 |

The ten indexed sessions contain seven full-target records, three available TSVs
and four full-target TSVs absent beyond retention. All index rows have 14 columns.
This is legitimate retained index context, not malformed or oversized history.

Scanner inventory (six files, four gzip):

| File | Stored bytes | Expanded bytes | Lines | Max record bytes | Mtime epoch |
|---|---:|---:|---:|---:|---:|
| `clamscan_log` | 167991 | 167991 | 973 | 204 | 1791733138.5887768 |
| `clamscan_log-20260913.gz` | 52308 | 1225385 | 9070 | 195 | 1789236871.0 |
| `clamscan_log-20260920.gz` | 5745 | 125344 | 770 | 232 | 1789884552.0 |
| `clamscan_log-20260927.gz` | 351 | 909 | 8 | 168 | 1790461822.0 |
| `clamscan_log-20261004.gz` | 717 | 6267 | 41 | 177 | 1791098020.0 |
| `clamscan_log-20261011` | 261 | 261 | 3 | 168 | 1791671430.3040128 |

Scanner stored total: 227,373 bytes; expanded total: 1,526,157 bytes / 10,865
lines. None approaches the byte, record or individual record-size ceilings.
The retention-policy repetition occurs before scanner interval analysis.

Policy metadata (read-only, no contents):

| Source | Bytes | Lines | Mtime epoch |
|---|---:|---:|---:|
| Base | 25475 | 603 | 1790786552.059327 |
| Compatibility | 5357 | 150 | 1788610951.642974 |
| Daily | 385 | 12 | 1788863261.224105 |
| Selected environment | 466 | 12 | 1788612547.2597642 |
