# LMD parser maintenance notes

The healthcheck reads LMD data; it never sources LMD shell/configuration files and
never invokes maldet (even report commands can run initialization routines).

## Metadata

`_lmd_meta_get(file, key)` retains the last exact `key=` value via awk. Values may
contain `=`; only the first separator is structural. CRLF is accepted. Duplicate
states are expected in append-only metadata. No arithmetic is performed before
validating an unsigned decimal integer (no leading zeros except zero, <=12 digits).
This also prevents Bash arithmetic from interpreting injected variable/subscript
expressions. Invalid timestamps do not fall back to file mtime.

Only `scan.meta.*` regular files enter selection. Matching uses literal path
identity after removing one trailing slash; `?` in LMD's target is data, not an
expanded shell glob. Maximum valid completed epoch wins for completed scans;
otherwise the started epoch orders the session. Equal epochs break ties by the
last filename encountered in shell glob order. Matching files with invalid starts
are excluded with a warning so they cannot silently overwrite trustworthy evidence.
The previous completed scan is retained for hit reporting when the selected scan
is running or failed. Other scan targets are not fullscan candidates.

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
that could also accept a future `v10` format). The first five columns of subsequent records
are signature, original path, quarantine path, type and type label. This layout was
checked against the upstream 2.0.1 session renderer:

- [LMD session code](https://github.com/rfxn/linux-malware-detect/blob/master/files/internals/lmd_session.sh)
- [LMD update messages](https://github.com/rfxn/linux-malware-detect/blob/master/files/internals/lmd_update.sh)

These are references, not runtime dependencies or a promise that future upstream
formats remain identical. Keep fixtures for each additional format before adding
support. Unknown headers/invalid records cannot produce an EICAR-only verdict.
Tab splitting explicitly preserves empty fields; ordinary Bash `read` with tab
IFS would collapse them. Owner is obtained read-only from `stat -c %U` if the
original file still exists, not from undocumented trailing columns.

Only case-insensitive `eicar` in the signature denotes a known test. Path names,
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

Program-update expectation is deliberately independent of `conf.maldet`/cron:
no LMD config is evaluated, no secrets are read and disabled policy is labelled as
intentional rather than independently verified. Quarantine policy is per-scan
metadata, so it may differ from today's live LMD configuration. Neither is modified.
