# Continuous integration

`.github/workflows/ci.yml` runs on pushes to `main`, pull requests targeting `main`
and manual dispatch. No path filter is used: registry, docs, fixtures and workflow
changes can affect release quality. Old runs for the same branch/PR are cancelled.

| Required-check name | Environment | Checks | Timeout |
|---|---|---|---|
| Static checks | Ubuntu 24.04 host | Committed whitespace diff, discovered shell syntax, current version consistency | 5 min |
| Full regression suite | Ubuntu 24.04, setup-python 3.12.x | `python -m unittest discover -s tests -v` | 20 min |
| Runtime compatibility | Ubuntu 24.04 host plus official linux/amd64 Docker images | Python 3.6.8 compile/import/JSON self-test; Bash 4.4.23 syntax and behavior | 10 min |

Jobs are independent. These exact names are suitable for future `main` required
checks; branch protection is not configured by this change. Stable job IDs are
`static`, `tests-python312` and `runtime-compatibility`.

## Coverage and dependencies

The full suite includes production blockers, registry defaults, PH11, maintenance
(PH07–PH10), JSON/timing/publication, secret/buffer, LMD production-budget, LMD
ERR-contract and all healthcheck/installer/performance tests. Verbose unittest
module/class/method names identify the failed contract. There is no separate
security job: those tests already constitute much of the approximately eight-minute
suite, and running them again adds substantial cost without extra coverage.

The baseline is 870 tests, with one Unix-socket-bind skip in the local sandbox.
A hosted runner may execute that test instead; either outcome is acceptable. Test
counts are not hardcoded. Failures/errors retain unittest's nonzero exit status.
No pip packages, pip cache or production dependency installation are needed.
Ubuntu provides Bash and GNU utilities; service/network commands and installer
administrative operations are stubbed in the existing isolated fixtures.
`install.sh` and `install-dependencies.sh` are never run against the CI host.

`TZ=UTC` and `LC_ALL=C.UTF-8` establish the host baseline. Individual fixture tests
retain their own C-locale/timezone settings. Test scratch goes into ignored `tmp/`.

## Static checks and history

The helper discovers Git-tracked and non-ignored new files, selecting `.sh` files
and Bash/sh shebangs, including executable scripts without an extension. It prints
each file. Currently this covers 17 files: the 15 previously listed shell scripts,
`tests/fixtures/maldet.daily` and `.github/ci/bash44.sh`.

Checkout uses depth 2 for static checks, sufficient for a manual run's parent.
For PRs, whitespace validation compares the event base SHA with the checked-out
synthetic merge commit, so base changes are included without deep merge-base
history. For pushes it compares `before` with `HEAD`; initial pushes use the empty
tree. A missing base is explicitly fetched with `--depth=1 --no-tags`, after
validating the event value as a hexadecimal commit ID. Unavailable history fails
the check rather than silently skipping it. Tags/full history are unnecessary.
Working-tree and staged `git diff --check` also run for local use. An initial
branch creation scans the whole tree and currently detects an existing trailing
space in `tests/test_audit_round3.py:64`; ordinary push/PR ranges do not re-lint
unchanged historical lines. No unrelated fixture cleanup is included.

Version validation checks APP_VERSION, actual `--version`, the README current
release line, first numbered changelog release and existing current test
expectations. Historical changelog versions are accepted, and a version bump on
every commit is not required. CI-only infrastructure leaves runtime v1.1.2 intact;
new internal work is recorded under Unreleased.

ShellCheck 0.11.0 was evaluated locally: 29 warning-level findings (SC1090, SC2154,
SC2034, SC2050) in the existing/dynamic-source code and smoke helper. It is not a
required check in this first workflow. No warnings were mass-suppressed or runtime
code rewritten. Workflow structure was separately checked with actionlint 1.7.12;
neither linter adds a CI dependency.

## Pinning and isolation

Only official GitHub actions are used: checkout v7.0.1 and setup-python v7.0.0,
pinned to full commit SHAs. Pins should be deliberately reviewed when updating.
See [checkout releases](https://github.com/actions/checkout/releases) and
[setup-python releases](https://github.com/actions/setup-python/releases).

Compatibility uses Docker Official Images pinned to verified linux/amd64 manifest
digests, not mutable `latest` tags:

- `python:3.6.8-slim-stretch@sha256:342a794da4cb1fd4ecd4b7636544697970daf850a131d8adc334c8719d8ecf44`
- `bash:4.4.23@sha256:71f0399fbec8c6244521ecef72882f55bc2a73dde5f03374d880f659a3db85cb`

Sources: [official Python image](https://hub.docker.com/_/python) and
[official Bash image](https://hub.docker.com/_/bash). Digests and actual interpreter
versions were checked locally. Python runs on Debian Stretch/glibc; Bash runs on
Alpine/musl. The latter tests shell syntax/behavior, not GNU-tool integration.
Bash 4.4.20 also passed locally; the container asserts 4.4.x with patch >=20.

Python discovers every `lib/**/*.py`, compiles to scratch, imports with the runtime
`lib/checks` path and exercises output.py's schema self-test. Currently these are
bounded_input.py, health_data.py, lmd_scanner.py and output.py. Tests themselves run
only under Python 3.12; compatibility checks do not force that harness onto 3.6.
Bash checks all discovered scripts plus indexed/associative arrays, BASH_REMATCH,
reporter/redaction/fallback, ERR traps, command substitution and expansion.

The host pulls images, then runs them without network, with dropped capabilities,
no-new-privileges, a read-only filesystem/checkout and bounded temporary storage.
Official Actions execute on the modern host, avoiding old-image Node/glibc issues.
Python 3.6 and these historical OS images are EOL and used only as isolated
compatibility targets; they do not recommend continued use of obsolete production
runtimes. No automatic production runtime upgrade is performed.

Workflow permissions are only `contents: read`; checkout does not persist its
read token. No secrets, `pull_request_target`, PR-title interpolation, write tokens,
comments, artifacts, releases, tags or deployment are used. Fork PRs need no
credentials. No production configuration, services or server access is required.
The public repository permits the rare explicit base-SHA fetch without persisted
credentials; private-repository reuse would need a reviewed read-only fetch strategy.

## Local reproduction

From the repository root:

```bash
mkdir -p tmp
export PYTHONDONTWRITEBYTECODE=1 TMPDIR="$PWD/tmp"
python3.12 .github/ci/check.py static
python3.12 -m unittest discover -s tests -v
python3.12 .github/ci/check.py shell-list > tmp/ci-shell-files
# With installed Python 3.6.8 and Bash 4.4.20 or later 4.4.x:
python3 .github/ci/check.py runtime
bash .github/ci/bash44.sh tmp/ci-shell-files
```

For exact container parity, run the two `docker run` commands from the workflow
with `GITHUB_WORKSPACE="$PWD"`. Docker must be available; no packages are installed
inside the containers. A local `static` invocation checks working/staged diffs;
committed event ranges are additionally checked in Actions.

Local full-suite timing is roughly eight minutes; static and warm compatibility
commands take seconds. Allow extra time for image downloads and hosted-runner
scheduling. First live GitHub execution remains required to validate runner/action
integration, network pulls and final job timings. No workflow run, branch setting,
commit, push or release operation is initiated by this implementation.
