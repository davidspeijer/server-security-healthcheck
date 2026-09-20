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
configuration interpreter. Unrelated assignments are not extracted or printed.

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
