# Native LMD 2.0.1 metadata investigation

Inspected upstream tag `v2.0.1`, commit
`88dd694891ac52a11a6e6ac45546545d5b1c813f`, and this repository's installer,
LMD checks, history and fixtures. The production filesystem was not accessible
from the development workspace; the supplied production example is an excerpt,
not a byte-for-byte TSV fixture.

## Why lifecycle metadata disappears

LMD itself creates `sess/scan.meta.<id>` in `_lifecycle_write_meta`, appends state
changes in `_lifecycle_update_meta`, and removes old completed/killed/stale files
in `_lifecycle_cleanup_stale_metas`. The shipped `conf.maldet` specifies
`scan_meta_cleanup_age=48` hours; the function's fallback is 24 hours. Cleanup
runs during subsequent non-hook scans. This is consistent with a Sunday report
remaining available on Wednesday after its lifecycle metadata has disappeared,
but does not establish the actual production cleanup configuration.

This repository only reads these files. Its installer does not create them or
install a producer/wrapper. The original fullscan implementation assumed that
native lifecycle files remained available for the whole weekly age window.
There is no repository evidence of a missing production wrapper.

## Persistent formats

`session.index` is tab-separated, with a `#LMD_INDEX:v2` header. Current rows
have 14 fields; upstream documents older 9- and 11-field rows:

1. Scan ID
2. Start epoch
3. Start date with numeric timezone
4. Elapsed seconds
5. Total files
6. Total hits
7. Total cleaned
8. Total quarantined
9. Literal target
10. Signature version
11. Runtime `quarantine_hits` at finalization
12. End date with numeric timezone
13. Engine
14. Hash type

`session.tsv.<id>` starts with a 19-field header:

1. `#LMD:v1`
2. Alert type (`scan` or `monitor`)
3. Scan ID
4. Hostname
5. Literal target
6. Days/range (`all` for `-a`, numeric for `-r`)
7. Start date
8. End date
9. Elapsed seconds
10. File-list construction seconds
11. Total files
12. Total hits
13. Total cleaned
14. Scanner version
15. Signature version
16. Hash type
17. Engine (`clamav` or `native`, less specific than lifecycle `clamdscan`)
18. Runtime `quarantine_hits` at finalization
19. Host ID

Hit rows have 11 columns in this release; the existing classifier consumes the
first five (signature, original path, quarantine path, type, type label).
`session.last` contains a scan ID, not status or completion evidence, and does
not select a particular target. File mtimes and this pointer are unsuitable for
choosing a successful weekly scan.

## Completion is not encoded in the persistent reports

The normal scan path calls `_scan_finalize_session`, which writes the TSV header,
hits, `session.last` and index row. However, `trap_exit` also sets an end date and
elapsed seconds and calls **the same finalizer after marking a scan killed**.
The persistent report formats have no field recording that distinction.
`clean_exit` can also finalize in-flight hit data. The `total_files` field is the
file-list total, not an independent certificate that every file was processed.

Consequently, index + TSV supply historical times, counts, engine, signatures,
range and runtime quarantine state, but cannot alone certify successful completion.
An interrupted `-a` scan can have the exact expected target, `days=all`, plausible
times, runtime, file count and zero hits. Treating such a row as success would
violate the requirement that partial/failed scans never satisfy fullscan health.
Missing lifecycle files cannot be interpreted as proof of success either:
cleanup removes killed files too.

## Safe design boundary

Read the index and TSV as literal data, cross-check identity and common fields,
require `scan` / `all` and exact target equality, and validate absolute timestamps
without mtime fallback. Use the historical TSV runtime quarantine flag, not today's
configuration, for historical state. It is not proof of the configured policy. Retain lifecycle metadata for explicit
running/failed/completed evidence while available. Absence of completion proof
must remain UNKNOWN/WARNING; report detections independently of success status.
An unproven newer zero-hit report must not clear an older malware finding.

For durable success evidence, a separate design decision is needed. Options are
retaining lifecycle metadata longer than the healthcheck window, or adding a
durable per-scan outcome in LMD/upstream or a carefully designed collector.
Neither change should be silently introduced by this healthcheck patch. Simply
wrapping the current `maldet -b` exit code does not work: it reports background
launch, not completion. Existing human-readable completion logs need explicit
identity/correlation and rotation rules before being accepted as proof.

Existing fixtures remain useful for legacy lifecycle-parser regression tests,
but their `days=-` and `start`/`end` placeholders do not represent native fullscan
headers. Native integration tests need real date fields, `days=all`, index/header
agreement, and an interrupted finalized report as a negative completion case.

## Pinned upstream sources

- [Lifecycle writer, index schema and cleanup](https://github.com/rfxn/linux-malware-detect/blob/88dd694891ac52a11a6e6ac45546545d5b1c813f/files/internals/lmd_lifecycle.sh)
- [TSV header and finalizer](https://github.com/rfxn/linux-malware-detect/blob/88dd694891ac52a11a6e6ac45546545d5b1c813f/files/internals/lmd_session.sh)
- [Abort and exit handlers](https://github.com/rfxn/linux-malware-detect/blob/88dd694891ac52a11a6e6ac45546545d5b1c813f/files/internals/lmd_init.sh)
- [Normal scan path](https://github.com/rfxn/linux-malware-detect/blob/88dd694891ac52a11a6e6ac45546545d5b1c813f/files/internals/lmd_scan.sh)
- [Shipped cleanup setting](https://github.com/rfxn/linux-malware-detect/blob/88dd694891ac52a11a6e6ac45546545d5b1c813f/files/conf.maldet)
- [CLI scan range](https://github.com/rfxn/linux-malware-detect/blob/88dd694891ac52a11a6e6ac45546545d5b1c813f/files/maldet)

## Daily retention and the retained index

Verified in the pinned `cron.daily`, lines 35–70: base config, compatibility,
sysconfig (otherwise default), then `cron/conf.maldet.cron` supply the effective
`cron_prune_days`; empty/unset falls back to 21. The daily job applies GNU find
`-type f -mtime +N -delete` to tmp, sess, quarantine and pub. For N=21, eligibility
starts at 22 whole days since modification, not immediately after 21 days. Zero
is not a disable switch here: it means `-mtime +0`.

The index is **not exempt**, but cleanup deletes files, not individual index
rows. `_session_index_append` refreshes the index on every append, so regular
scans keep historical rows alive while individual TSVs expire. An inactive index
can itself expire. `_session_index_rebuild` can rebuild it from surviving TSVs;
there is no corresponding row-pruning step in daily cleanup.

The healthcheck does not use mtime. For an absent TSV with a 14-field index row,
it cross-checks start epoch, absolute start/end dates and elapsed seconds, requires
valid counts, and uses the end epoch with the conservative N+1 day boundary.
It also requires the scan to be outside the configured fullscan relevance window
and no remaining lifecycle file. Such a row is INFO (including historical hit
count), never proof of successful completion or remediation. This is eligibility
for normal retention, not proof of why a file disappeared. Unknown configuration,
older index formats without an end date, invalid dates, unreadable/present TSVs,
and recent scans retain diagnostics. Existing historical hit details remain
security findings. Daily values are read safely even if policy reporting is off.

`scan_meta_cleanup_age` is separate: `_lifecycle_cleanup_stale_metas` removes only
terminal `scan.meta.*` files using `-mmin +hours*60`, with 24-hour fallback and
48-hour shipped configuration; zero disables this lifecycle cleanup. Daily
cleanup can still remove those files independently. Neither mechanism proves a
successful scan, and neither justifies inferring success from an index alone.

## Exact writer variables and quarantine interpretation

`_scan_finalize_session` calls `_session_write_header` and
`_session_index_append`. The index writer's arguments, in column order, are:

| Column | Finalizer value |
| --- | --- |
| 1 | `_sid` (`scanid`, otherwise `datestamp.$$`) |
| 2 | `scan_start` |
| 3 | `scan_start_hr` |
| 4 | `scan_et` |
| 5 | `tot_files` |
| 6 | `tot_hits` |
| 7 | `tot_cl` |
| 8 | `_tot_quar`, counted from hit rows with nonempty/non-`-` quarantine path |
| 9 | `hrspath` |
| 10 | `_idx_sig_ver`, runtime `sig_version` or signature-version file |
| 11 | `_idx_quar_en`, `${quarantine_hits:-0}` |
| 12 | `scan_end_hr` |
| 13 | `_idx_engine`, `clamav` if `scan_clamscan=1`, otherwise `native` |
| 14 | `_effective_hashtype` |

The TSV header writer's 19 arguments, in order: literal `#LMD:v1`, alert-type
argument, `scanid`/fallback, hostname, `hrspath`, `days`, `scan_start_hr`,
`scan_end_hr`, `scan_et`, `file_list_et`, `tot_files`, `tot_hits`, `tot_cl`,
`lmd_version`, resolved signature version, `_effective_hashtype`, derived engine,
`${quarantine_hits:-0}`, and `hostid`. Unknown context fields generally use `-`.
These mappings were checked against the printf arguments, not inferred from names.

**The existing column mapping was correct.** TSV column 18 and index column 11
are neither hit counts nor quarantine counts. However, they capture a mutable
runtime variable at finalization, not necessarily the original configuration.
In `_scan_run_clamav` (lmd_scan.sh lines 450–462), exit code 2 with
`quarantine_on_error=0`/unset sets `quarantine_hits=0`; a fatal “no reply from
clamd” also sets it to zero. The startup lifecycle writer can therefore record 1
while the final TSV records 0. CLI overrides and other config contexts are also
possible; the supplied header alone does not prove a ClamAV error occurred.

The supplied October 4 sample really records runtime quarantine disabled, with
zero hits and zero cleaned/quarantined files. The healthcheck keeps the historical
mismatch warning, explicitly labels it as runtime state, and points to the scan's
ClamAV log. It does not claim that live config is zero or silently discard this
security-relevant evidence. Current policy continues to be checked separately.

Additional pinned source:
[daily cleanup](https://github.com/rfxn/linux-malware-detect/blob/88dd694891ac52a11a6e6ac45546545d5b1c813f/cron.daily#L35-L70).
