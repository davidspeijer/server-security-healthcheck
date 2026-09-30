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
11. Quarantine enabled
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
18. Quarantine enabled
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
range and quarantine policy, but cannot alone certify successful completion.
An interrupted `-a` scan can have the exact expected target, `days=all`, plausible
times, runtime, file count and zero hits. Treating such a row as success would
violate the requirement that partial/failed scans never satisfy fullscan health.
Missing lifecycle files cannot be interpreted as proof of success either:
cleanup removes killed files too.

## Safe design boundary

Read the index and TSV as literal data, cross-check identity and common fields,
require `scan` / `all` and exact target equality, and validate absolute timestamps
without mtime fallback. Use the historical TSV quarantine flag, not today's
configuration, for historical policy. Retain lifecycle metadata for explicit
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
