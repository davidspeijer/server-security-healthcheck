# Performance profiling — v1.1.2 candidate

Baseline: HEAD `6a351c5`, tagged v1.1.1, initially clean. Only internal presentation
and JSON bootstrap work was optimized; no public feature or new dependency.

## Method and limits

Fixtures use isolated commands, literal synthetic configurations and a notification
stub. No production data or services were changed or required. Frozen before/after
runtimes carry the same v1.1.1 version metadata to isolate algorithm costs; the
candidate's v1.1.2 version is checked separately by regression tests.

Each scenario has a discarded warmup. Short scenarios use nine samples, heavier
ones three, alternating old/new order. `/usr/bin/time` measures peak RSS including
children; Python 3.12 measures wall time. These are sandbox measurements, not
production latency guarantees. Scheduling varies substantially; min/max are retained.

ptrace is denied, so subprocess counts use disposable PATH shims. Explicit Python
helper opens/reads, stat, directory iteration and gzip decoding are instrumented.
Counts exclude the instrumentation's own processes. They do **not** enumerate every
kernel syscall, interpreter import-loader read, or Bash source/syntax read. Separate
BASHPID instrumentation counts presenter processes. Instrumented runs are separate
from the untraced timing samples. Child durations in the raw traces include profiling
bootstrap overhead and are estimates; phase microbenchmarks below are untraced.

Raw samples, command purposes/arguments, helper I/O maps and phase measurements are
in ignored `tmp/performance/` (`paired-results.json`, `before-trace.json`,
`after-trace.json`, `phase-results.json`, `fork-results.json`). Instrumentation is
not shipped in runtime code.

## Before / after

All durations below are seconds. Large fixtures contain 1000 findings with 4000-byte
messages; counters also include a late warning. The LMD production-equivalent fixture
has ten index rows, 28 report files, two lifecycle records and production-shaped
policy inputs. Scanner input has six logs, four gzip, 10,865 lines and 1,526,157
expanded bytes. Logs are synthetic, including irrelevant historical informational
lines and three valid scan intervals.

| Scenario | n | Before median | Before min–max | After median | After min–max | Median gain |
|---|---:|---:|---|---:|---|---:|
| healthy_text | 9 | 0.236 | 0.214–0.255 | 0.237 | 0.220–0.256 | -0.7% |
| healthy_json | 9 | 0.765 | 0.674–1.230 | 0.723 | 0.659–1.549 | 5.6% |
| warning_text | 9 | 0.290 | 0.259–0.314 | 0.288 | 0.247–0.321 | 0.4% |
| warning_json | 9 | 0.798 | 0.736–0.860 | 0.742 | 0.663–0.801 | 7.0% |
| lmd_representative | 3 | 1.726 | 1.572–1.781 | 1.769 | 1.697–1.852 | -2.5% |
| lmd_production_equivalent | 3 | 1.780 | 1.720–3.393 | 1.847 | 1.796–2.439 | -3.8% |
| 1000_small | 3 | 3.393 | 3.341–3.429 | 0.831 | 0.818–1.032 | 75.5% |
| 1000_large_text | 3 | 9.029 | 8.010–9.530 | 3.548 | 2.770–3.996 | 60.7% |
| 1000_large_json | 3 | 10.456 | 9.923–13.685 | 4.906 | 4.608–8.553 | 53.1% |
| notification_render | 3 | 9.695 | 9.657–9.916 | 5.382 | 4.476–5.464 | 44.5% |
| service_discovery | 9 | 0.325 | 0.292–0.399 | 0.315 | 0.295–0.363 | 2.8% |
| clamav_metadata | 9 | 0.533 | 0.472–0.600 | 0.504 | 0.480–0.580 | 5.4% |
| service_auto_no_bins | 9 | 0.362 | 0.309–0.435 | 0.349 | 0.337–0.417 | 3.7% |
| healthy_no_checks_text | 9 | 0.299 | 0.271–0.349 | 0.297 | 0.268–0.347 | 0.6% |
| healthy_no_checks_json | 9 | 0.764 | 0.699–1.288 | 0.748 | 0.679–0.982 | 2.2% |

A positive gain is faster. Small changes with overlapping ranges, especially LMD,
service and metadata paths, are not evidence of a production speedup or regression.
The LMD median remains a few seconds, with the same four retention-policy reads,
15 Python helper starts and exclusive 20-second phase deadline. No history filtering,
new cache lifetime, snapshot change or budget increase was introduced.

## Ranking and decisions

| Rank | Bottleneck / evidence | Decision | Risk |
|---|---|---|---|
| 1 | Per-finding command substitution plus 31 escape replacements for ordinary text | Plain reporter values stay in the parent shell; controls retain the original escape route | low/medium, tested for state/capture preservation, escaping, secrets and bounds |
| 2 | Separate Python API preflight and functional self-test at JSON startup | One interpreter parses, checks and executes the same verified AST | medium, script context and bootstrap failure contracts tested |
| 3 | Saturated notification summary still repeatedly copies a bounded 16 KiB prefix | Defer; it is bounded work, not unbounded quadratic growth | medium: UTF-8 boundary slack, truncation state, priority and late errors |
| 4 | Separate per-event clock processes | Defer shared clock / IPC | high: monotonic timestamps, ordering, shutdown and error accounting |
| 5 | Two audit passes, repeated date conversion and two policy resolutions if full policy reporting is enabled | Defer batching / wider LMD cache scope | medium: independent failure domains, effective config lifetime and historical recovery |
| 6 | Renderer and final verifier each decode/serialize data | Keep the independent verification boundary | high: publication and exitcode invariants |

The public `hc_present` implementation is unchanged. The fast path only handles
ordinary reporter values; a fixed redaction marker cannot introduce control bytes.
Values with controls use the original presenter. Detection uses globs so it cannot
clobber caller `BASH_REMATCH` captures. The reporter restores the raw redacted shared
value after producing escaped console/retained text; JSON still receives raw values.
A prototype capture regression was detected by a new test and corrected before the
final validation. No prototype or tracing output remains in production code.

JSON bootstrap still performs AST/API preflight and the functional schema roundtrip.
The verified AST is compiled and executed once with the normal filename, argv,
import path, main module, loader, package/spec and builtins context. Shell source
preflight, parent loading, helper provenance guards, timestamps, renderer, verifier,
cleanup-before-publication and all budgets remain unchanged.

## Subprocesses

Counts are logical external command invocations. Bash command-substitution forks
without exec are reported separately below, not hidden in the external totals.

| Scenario | Python before→after | systemctl | grep/awk/sed | stat/find | date | hostname | Other exec before→after |
|---|---|---:|---:|---:|---:|---:|---|
| healthy_text | 3→3 | 0 | 0 | 0 | 3 | 0 | 4→4 |
| healthy_json | 11→10 | 0 | 0 | 0 | 3 | 1 | 8→8 |
| warning_text | 3→3 | 0 | 0 | 0 | 3 | 1 | 4→4 |
| warning_json | 11→10 | 0 | 0 | 0 | 3 | 2 | 8→8 |
| lmd_representative | 15→15 | 0 | 6 | 0 | 20 | 0 | 11→11 |
| lmd_production_equivalent | 15→15 | 0 | 8 | 0 | 32 | 0 | 11→11 |
| 1000_small | 3→3 | 0 | 0 | 0 | 4 | 1 | 4→4 |
| 1000_large_text | 3→3 | 0 | 0 | 0 | 4 | 1 | 4→4 |
| 1000_large_json | 11→10 | 0 | 0 | 0 | 4 | 2 | 8→8 |
| notification_render | 3→3 | 0 | 0 | 0 | 4 | 1 | 5→5 |
| service_discovery | 3→3 | 3 | 0 | 0 | 3 | 0 | 6→6 |
| clamav_metadata | 5→5 | 3 | 0 | 3 | 7 | 1 | 4→4 |
| service_auto_no_bins | 3→3 | 6 | 0 | 0 | 3 | 0 | 6→6 |
| healthy_no_checks_text | 3→3 | 0 | 0 | 0 | 3 | 0 | 3→3 |
| healthy_no_checks_json | 9→8 | 0 | 0 | 0 | 3 | 1 | 7→7 |

No curl, gzip or zcat commands are started; notification transport is a stub and
gzip decoding happens inside Python. Other commands are primarily bash syntax
validation, dirname, temporary-directory creation and cleanup. Service fixtures
with known executables make three distinct is-active queries. Without known binaries,
auto-discovery makes three list-unit-files plus three is-active queries. These query
types/operands have different meanings and were not combined. ClamAV uses one stat
per present database, never reads database content, and queries updater state separately.

Presenter calls and distinct PIDs (mostly command-substitution children):

| Scenario | Calls before→after | Presenter PIDs before→after |
|---|---|---|
| healthy_text | 3→2 | 3→2 |
| healthy_json | 3→2 | 3→2 |
| 1000_small | 1004→3 | 1004→3 |
| 1000_large_text | 1004→3 | 1004→3 |

The earlier three Python starts for text / nine for JSON are confirmed for all-disabled
healthy fixtures. After optimization those are three/eight. A single executed check
adds two actual clock starts, so healthy one-check JSON is eleven/ten. Additional
checks still add start/end clock calls; no approximate clock replaced monotonic time.

Python purposes: bounded registry/config reads and optional-file state; JSON API
preflight/self-test; per-event wall/monotonic clocks; rendering and independent
verification. LMD adds policy/event/audit/header parsers, immutable native metadata
capture and a batched scanner classifier. The raw trace groups each invocation by
mode, counts, operands and estimated child runtime. Startup batching of config and
registry was considered but deferred: typed file state, credentials, allowlisting,
resource deadlines and parent-shell validation are separate failure boundaries.

## Explicit helper I/O

Data opens exclude `.py` loader/preflight source reads and instrumentation artifacts.
These numbers cover helper data streams, not all OS reads. Files are separated by
identity/path; reading an immutable prepared copy is not a live-source reread.

| Scenario | Data opens before→after | Data bytes before→after | Directory scans | Gzip decompressions |
|---|---|---|---:|---:|
| healthy_text | 2→2 | 778→778 | 0 | 0 |
| healthy_json | 4→4 | 2957→2957 | 0 | 0 |
| warning_text | 2→2 | 778→778 | 0 | 0 |
| warning_json | 4→4 | 2972→2972 | 0 | 0 |
| lmd_representative | 17→17 | 34400→34396 | 6 | 0 |
| lmd_production_equivalent | 53→53 | 1684878→1684874 | 6 | 4 |
| 1000_small | 2→2 | 778→778 | 0 | 0 |
| 1000_large_text | 2→2 | 778→778 | 0 | 0 |
| 1000_large_json | 4→4 | 4983667→4983666 | 0 | 0 |
| notification_render | 2→2 | 860→860 | 0 | 0 |
| service_discovery | 2→2 | 849→849 | 0 | 0 |
| clamav_metadata | 3→3 | 978→976 | 0 | 0 |
| service_auto_no_bins | 2→2 | 849→849 | 0 | 0 |
| healthy_no_checks_text | 2→2 | 794→794 | 0 | 0 |
| healthy_no_checks_json | 4→4 | 2706→2706 | 0 | 0 |

Registry and main configuration are each read once; the Telegram config in these
fixtures is absent and gets one typed state query. Native metadata is captured once
for the native adapter and read from prepared files. The two lifecycle files are
also read by the scanner's separate, identity-checked history capture (two source
opens each); these are not per-interval rereads. Audit is currently parsed twice
for two event types.
Each retention policy source is read once (four reads / 31,683 bytes / 777 lines),
not once per compatibility key. Scanner rotations are captured into immutable tuples;
four gzip sources are decompressed once each and reused across selected intervals.
Output-helper startup reads one verified source instead of separate preflight and
self-test source loads. Renderer and verifier retain their independent input reads.

| Cache / snapshot | Source | Lifetime | Consumers / miss behavior |
|---|---|---|---|
| HC_REGISTRY_READY + maps | checks.registry | shell invocation | Config allowlisting, effective enables, module selection/provenance; first load reads once |
| LMD policy maps + compatibility state | base/environment/cron/compat | policy-resolution invocation | Repeated key lookups and aliases; four source reads, subsequent lookups in memory |
| Prepared native metadata | session inventory | fullscan invocation | Native adapter, selection, hit/recovery evidence; later reads use scratch copies |
| ScannerSnapshot | logs and history | batched helper invocation | Multiple validated intervals; one capture/decompression per source |
| Native metadata / scanner result maps | validated sessions/results | fullscan invocation | Reused lifecycle/scanner lookups, no per-session helper restart |
| JSON rank/count maps | findings | JSON invocation, owner PID only | Constant-size severity accounting independent of omission |

Full policy reporting and native retention still build separate policy-resolution
snapshots: two sets of four reads, not a shared whole-check snapshot. Widening this
lifetime would require a separate consistency/error-contract change and is deferred.

## JSON phases, buffers and redaction

Phase microbenchmarks: nine post-warmup samples for bootstrap/clock/render/verify;
three for 1000-message micro workloads. Render and verify use a synthetic 4,015,121-byte
journal and 1,076,425-byte JSON result. These phase timings are not additive to a
healthy run with a different journal; renderer includes journal parsing/validation,
verifier includes schema/exitcode checks and canonical serialization.

| Phase | n | Before median ms | After median ms | Before min–max ms | After min–max ms |
|---|---:|---:|---:|---|---|
| bootstrap | 9 | 195.11 | 163.10 | 177.51–211.42 | 145.53–186.50 |
| clock | 9 | 64.09 | 58.29 | 53.47–69.47 | 54.94–73.27 |
| render | 9 | 104.30 | 98.39 | 92.71–118.35 | 87.57–106.06 |
| verify | 9 | 101.04 | 81.78 | 87.75–115.22 | 69.55–121.99 |
| controls | 3 | 3521.14 | 3284.30 | 2836.00–3638.86 | 3036.98–3761.22 |
| summary | 3 | 1805.48 | 1646.04 | 1471.33–1852.06 | 1633.97–1945.44 |
| redact_none | 3 | 182.89 | 175.27 | 160.54–217.99 | 162.81–237.05 |
| redact_one | 3 | 246.92 | 277.86 | 241.41–276.11 | 273.93–306.75 |
| redact_overlap | 3 | 353.34 | 409.06 | 330.43–501.87 | 341.15–429.36 |

Redaction itself is unchanged: literal longest-secret-first replacement, before
retained-prefix truncation and escaping. Differences in unchanged redaction/summary
microbenchmarks illustrate timing noise, not an optimization. No unbounded array
joins were introduced. Summary work is linear in record count with a fixed 16 KiB
prefix; its repeated bounded copies remain a future opportunity.

Publication and shell journal/redaction work remain the residual between whole-run
measurements and the independent helper phases; no reliable isolated wall-time
estimate is claimed for each builtin/file append. Every journal append remains
synchronous and bounded, with final write checks before rendering. Scratch/journal
sizes are reported from renderer argv and helper I/O rather than retaining live
production journals. The final payload remains captured and verified before cleanup
and stdout publication; removing that copy or streaming after cleanup is high risk.

Actual after-trace scratch sizes (ordinary pipeline, distinct from the phase fixture):

| Scenario | Journal bytes | Rendered scratch bytes | Published stdout bytes |
|---|---:|---:|---:|
| healthy JSON, one check | 575 | 1,604 | 1,603 |
| 1000 large findings, JSON | 3,930,079 | 1,052,809 | 1,052,808 |

The one-byte difference is the trailing newline removed by command substitution.

Peak RSS (KiB, max across samples; not an absolute memory guarantee):

| Scenario | Before | After |
|---|---:|---:|
| healthy_text | 11636 | 11632 |
| healthy_json | 11664 | 11924 |
| warning_text | 11628 | 11652 |
| warning_json | 12844 | 12040 |
| lmd_representative | 12564 | 12560 |
| lmd_production_equivalent | 14632 | 14704 |
| 1000_small | 11636 | 11592 |
| 1000_large_text | 23456 | 26764 |
| 1000_large_json | 32200 | 25188 |
| notification_render | 23436 | 30580 |
| service_discovery | 11632 | 11632 |
| clamav_metadata | 11696 | 11644 |
| service_auto_no_bins | 11632 | 11624 |
| healthy_no_checks_text | 11680 | 11632 |
| healthy_no_checks_json | 11684 | 12040 |

The parent-shell fast path can change allocator high-water marks. This is a tradeoff,
not an increase to retained-data limits: 1000 messages / 3.75 MiB, 4096-byte raw
presentation prefix, 1024 JSON codepoints, 4 MiB journal and 16 MiB output caps remain
unchanged. Notification payload is still at most 16 KiB. Native file/record/expanded
budgets and the 20-second deadline are unchanged. No double 16 MiB buffering was
removed at the expense of independent validation or the publication invariant.

## Validation and future work

Four permanent tests cover all C0/DEL escaping and printable Unicode, raw redacted
reporter state, caller regex captures and standard self-test script/import context.
Existing JSON/timing/failure-publication, secret/buffer, registry, installer and LMD
suites are rerun, followed by the full suite. The final result is recorded in the
delivery report and ignored test logs. Python runtime remains 3.6.8, tests 3.12.x,
Bash 4.4.20; no dependencies or production profiling flag were added.

| Opportunity | Expected gain | Risk | Suggested scope |
|---|---|---|---|
| Saturated summary copies | Lower large-notification CPU | medium | Future patch with byte/Unicode/late-severity tests |
| Batched audit counts / date normalization | Fewer LMD helper/date starts | medium | Future patch preserving history and failure domains |
| Reuse full-check policy snapshot | Four fewer reads when policy reporting is on | medium | Separate snapshot-lifetime analysis |
| Cache warning hostname capture | One less command on warning JSON | low/medium | Future patch preserving both failure and presentation contracts |
| Shared monotonic clock | Multiple starts per JSON check | high | Report only; no daemon/IPC introduced |
| Merge renderer with verifier / stream publication | One interpreter / less buffering | high | Not recommended without an equally strong independent boundary |
| Batch systemd queries | Fewer CLI calls on many services | medium | Future analysis; no option-injection or positional parsing shortcuts |

Recommended version: v1.1.2 (internal backward-compatible performance changes only).
No commit, push, tag, package installation, real notification or production deployment.
