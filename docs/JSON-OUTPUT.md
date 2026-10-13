# JSON output (schema 1)

`server-security-healthcheck --json` runs the normal checks and notifications,
but stdout contains exactly one JSON document. Text mode remains the default.
Diagnostics may use stderr. `--json` is a standalone option: combinations with
`--version`, `--test-notification`, help or other arguments fail with exit 2.
These existing standalone options retain their text output.

```json
{
  "schema_version": 1,
  "application": {"name": "server-security-healthcheck", "version": "1.1.0"},
  "run": {
    "started_at": "2026-10-13T07:30:00+00:00",
    "finished_at": "2026-10-13T07:30:01+00:00",
    "duration_ms": 1000,
    "exit_code": 1,
    "status": "warning"
  },
  "host": {"hostname": "fixture.example"},
  "summary": {"pass": 0, "info": 0, "warning": 1, "critical": 0, "error": 0, "total": 1},
  "checks": [{
    "id": "disk", "name": "disk", "status": "warning",
    "started_at": "2026-10-13T07:30:00+00:00",
    "finished_at": "2026-10-13T07:30:01+00:00",
    "duration_ms": 1000,
    "findings": [{"severity": "warning", "message": "Disk usage high", "details": {}}]
  }],
  "findings": [],
  "truncated": false
}
```

`summary` counts calls to the central result reporters, including PASS and INFO,
rather than checks. `total` is their sum. Counts remain complete when finding
messages are truncated. `checks` follows registry order; IDs and initial names
are registry names. Disabled checks are included with `status: skipped`.
Run-level setup/notification findings appear in top-level `findings`. Check
loading/execution findings are associated with the active check. Helper loading failures are top-level setup findings; helpers never create
pseudo-check objects. Real check objects always retain registry order, including
disabled and failed-to-load checks.

| Internal state | JSON check status | Exit effect |
| --- | --- | --- |
| PASS | pass | None |
| INFO / `hc_detail` | info | None |
| WARNING | warning | 1 |
| CRITICAL | critical | 1 |
| ERROR | error | 2, takes precedence |
| Disabled | skipped | None |
| Successful auto discovery of absence | not_applicable | None |
| Discovery failure | error | 2 |

A check with no reported finding has `pass` after successful invocation. A
higher severity takes precedence over lower severities or not-applicable state.
UNKNOWN is evidence semantics, not an extra aggregator severity: it retains the
WARNING, CRITICAL or ERROR level chosen by the existing check. It is not inferred
from message strings. Run status is `pass` for exit 0, `warning` or `critical`
for exit 1, and `error` for exit 2. `run.exit_code` matches the process exit code.

Timestamps are locale-independent ISO 8601 UTC with an explicit offset. Python
`time.monotonic()` measures run and check durations, serialized as nonnegative
integer milliseconds. Wall-clock adjustment cannot make durations negative.
The check clock is sampled immediately around the function call; helper-process
startup/teardown contributes small measurement overhead. Run timing starts after
common/helper validation and scratch initialization. It covers configuration,
dependency checks, registered module loading, invocation and notification, ending
before JSON serialization/cleanup. Fixture performance measurements include the
entire CLI process, including bootstrap and publication.
Unstarted checks have null timestamps and duration 0. Clock failure forces exit 2;
when serialization still works, missing clock samples receive a current fallback
timestamp and unavailable check durations are 0, with an ERROR finding. Physical
journal or renderer failures publish no JSON and return exit 2.

Python stdlib `json` encodes raw centrally reported messages; text escaping remains
unchanged. Invalid UTF-8 is replaced with U+FFFD. `details` is currently an empty
object; checks do not parse prose back into typed fields. Direct module `printf`
presentation is not a finding and is discarded from JSON stdout.

The journal and rendered output live in a private mode-0700 directory, with
mode-0600 files. Shell/Python helper files must be regular/readable. Installer
and runtime share syntax, source, function-origin and Python API/self-test
validation. Required shell functions are `hc_json_init`, `hc_json_record`,
`hc_json_utf8_prefix`, `hc_json_finding`, `hc_json_clock`, and `hc_json_finish`.
Runtime rechecks their origins after module loading and check invocation.

Bounds are enforced before append:

- Whole journal: 4 MiB; individual record: 8 KiB, including four NUL separators.
- Findings stop consuming journal space at 3.75 MiB, reserving 256 KiB for final
  counters, severity states and other structural metadata.
- At most 1,000 retained messages. Each rendered message has at most **1,024
  Unicode codepoints**, independent of locale; this is not a grapheme limit.
- Storage retains at most 4,096 UTF-8 bytes per message, on a safe codepoint
  boundary. This prefix preserves the first 1,024 codepoints; Python performs the
  final codepoint truncation before JSON encoding. Own truncation never creates
  invalid UTF-8. Invalid bytes already present in input become U+FFFD.
- Registry IDs, function names, enable keys and dependencies: 128 ASCII bytes;
  relative module paths: 255 ASCII bytes. Display names currently use the ID.
- Encoded output and the verified in-memory publication buffer: at most 16 MiB.

Omitted or shortened presentation sets `truncated: true`; severity and summary
counters still include omitted findings. Structural metadata that cannot fit,
physical append failure, final-counter/marker failure or a byte-count mismatch
is an execution error: exit 2, no misleading JSON. No writes occur after the
last journal-failure check. Each append opens/writes/closes synchronously; rendering
also checks actual journal length against the writer's byte count.

Finalization is `COLLECTING → FINALIZING → RENDERING → PUBLISHED`: notifications
finish first, then final records are appended and all failures checked. The
renderer writes privately and must exit successfully; a second operation checks
schema/types, summary, application/version and expected process exitcode before
capturing validated JSON. Complete or partial renderer output followed by failure
is never published. Cleanup happens before stdout publication. Handled termination
signals are ignored only during the final byte-bounded stdout write/exit window.
Whenever valid JSON is published, `run.exit_code` equals the process exitcode.
Failure before publication returns 2 and may leave stdout empty; diagnostics use
stderr. This contract does not make external SIGKILL or machine failure observable.

Hostname is limited to 255 characters. No configuration/environment dump,
additional identity metadata or command arguments are exported. Known Telegram
token/chat values are redacted by the shared `hc_redact` presentation boundary
before central reporter storage, text output, stderr summaries, notifications
and journaling. Literal values are replaced longest-first with `[REDACTED]`,
including overlaps. Classification remains the check's raw-data logic.
Custom modules may pass these known credentials to central reporters safely;
unknown passwords are not guessed by a regex. Direct custom stdout/stderr and
shell tracing remain the trusted module's responsibility.

The shared Bash presentation buffers (`HC_WARNINGS`, `HC_ERROR_MESSAGES`,
`HC_DETAILS`) retain only redacted data. They share at most 1,000 presentation
messages and 3.75 MiB, measured as escaped message bytes plus severity and one
separator per message. Each central message first receives a safe 4,096-byte
UTF-8 prefix; this central byte contract is independent of locale. JSON still
applies its stricter 1,024-codepoint display limit. Control escaping can expand
an individual stored text message, but the shared byte budget includes expansion.
Ordinary messages remain unchanged below these limits.

Complete central severity counters are separate from retained messages;
omitted late CRITICAL/ERROR still affects status and exitcode. Shared
`HC_RESULTS_TRUNCATED` propagates into JSON `truncated`, the text summary and
notifications. Summary construction retains at most 16,128 UTF-8 bytes, reserving
space for a notice within a 16 KiB final buffer. Full problem/error totals remain
in the header. Central buffer truncation also places critical/error counters near
the start; summary overflow adds a full-counter notice at the end.
Telegram additionally retains its existing
3,500-byte transport prefix. These bounds limit owned retained data and summary
buffers, not absolute Bash RSS or arbitrary trusted module allocations.

Failures before output initialization (unavailable runtime directory, common
module, Python, invalid/incomplete output helper or scratch allocation) may only produce stderr/exit 2. After
initialization, configuration/module/backend errors normally produce JSON/exit 2.
This is not a watchdog for SIGKILL, crashes or runs that never start.

`schema_version` and application SemVer are independent. Additive compatible
fields may be introduced within schema 1; incompatible field meanings/types or
removals require a schema-version bump. Consumers should ignore unknown fields
and should not depend on object key ordering.
