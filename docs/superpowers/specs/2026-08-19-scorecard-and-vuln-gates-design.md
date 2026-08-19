# Scorecard Alerts, Vuln Gates, and Gold Badge — Design

Date: 2026-08-19
Status: Approved

## Context

The first Scorecard run on `main` uploaded eight code-scanning alerts. They are not
CodeQL findings in a source file. GitHub shows “no file associated with this alert”
because Scorecard scores repository policy and history. The measured scores on commit
`df795ba` were:

| Alert | Score | Cause |
| --- | --- | --- |
| Branch-Protection | 0 | `main` has no ruleset or classic protection |
| Vulnerabilities | 9 | OSV `GO-2026-5932` (`golang.org/x/crypto/openpgp` unmaintained). Every `x/crypto` version is flagged. This repo does not import `openpgp`; `x/crypto` is in the module graph via Sigstore. |
| Fuzzing | 0 | No Go `Fuzz*` tests, no ClusterFuzzLite, not in OSS-Fuzz |
| SAST | 9 | CodeQL is present; 2 of 25 commits predate it |
| Maintained | 0 | Repository created 2026-08-14; Scorecard refuses the check until the repo is 90 days old |
| Code-Review | 0 | 0/9 changesets had a human GitHub approval (self-merges) |
| CII-Best-Practices | 0 | No [bestpractices.dev](https://www.bestpractices.dev) badge |
| CI-Tests | 7 | 3/4 merged PRs had a check whose name matches Scorecard’s heuristic (`test`, `github-actions`, …). PR #1 had none. Job `Check CI` does not match. |

`make check-ci` already runs **call-graph** `govulncheck`. That is why CI is green while
Scorecard still reports `GO-2026-5932`: call-graph mode ignores unused `openpgp`; Scorecard
uses OSV at **module** graph level.

Collaborators `@MichaelSBoop` and `@wallrat1` are in. The owner is `@franchb`. That is
three humans, enough for two required reviews (the author cannot be one of them).

## Goals

1. Chase OpenSSF Scorecard 10 on every check that is physically possible for this repo.
2. Block PRs that introduce a vulnerable or malicious module in `go.mod` / `go.sum`.
3. Raise statement coverage from **25.1%** to **≥90%** and gate it in `task test`.
4. Earn the OpenSSF Best Practices **gold** badge (passing then silver then gold).
5. Walk the bestpractices.dev questionnaire in this same session after the git work is
   on `main`: the user pastes a criterion, the agent returns the exact form text.

## Non-Goals

- Deleting the empty `v0.1.0` GitHub release.
- Applying to OSS-Fuzz.
- ClusterFuzzLite storage-repo, coverage HTML, corpus pruning, or continuous builds.
- Making ClusterFuzzLite or scheduled `vuln.yml` required to merge.
- A Scorecard admin PAT.
- Linear history (merge commits stay allowed).
- Dismissing the Maintained alert.
- Live Yandex Cloud tests.
- Changing GoReleaser / release.yml except documentation.

## Two tracks

```
PR / push
  ├─ Check CI (lint, tests+coverage, call-graph govulncheck, 20s fuzz, zizmor)
  ├─ Test (macos/windows), Analyze (go) / CodeQL, Dependency Review
  ├─ new required: govulncheck (module)
  ├─ new required: OSV Scanner
  └─ ClusterFuzzLite (PR code-change + weekly batch; not required)

main (after the git PR merges)
  └─ ruleset: PR required, 2 approvals, CODEOWNERS, no bypass,
     required status checks, no force-push/delete, dismiss stale

bestpractices.dev (operator, this conversation)
  └─ gold badge — live questionnaire walkthrough
```

**In git:** CODEOWNERS, dual scanner jobs and ignore file, Go fuzz tests, ClusterFuzzLite
config and workflows, coverage tests and threshold, SPDX headers, CONTRIBUTING.md,
security-review note, README/repro notes.

**Not in git:** the GitHub ruleset itself, 2FA on maintainer accounts, enabling Issues,
the badge questionnaire. Those are operator steps in this spec.

**Apply order:** merge the git PR **while self-merge is still allowed**, then create the
ruleset with `gh api`. Turning on “2 approvals + no bypass” before that PR lands would
lock `main`.

## Alert map

| Alert | Target | How |
| --- | --- | --- |
| Branch-Protection | 10 | Ruleset after the git PR; 2 reviews + CODEOWNERS + no bypass + dismiss stale |
| Code-Review | →10 over ~30 commits | Same ruleset; old self-merges age out of Scorecard’s window |
| Vulnerabilities | 10 | `osv-scanner.toml` ignore for unused `openpgp` |
| Fuzzing | 10 | In-tree `Fuzz*` (ClusterFuzzLite keeps them running) |
| SAST | 10 | Already have CodeQL; 2 pre-CodeQL commits age out |
| CI-Tests | 10 | `Test (macos-latest)` and `Test (windows-latest)` already match Scorecard’s name heuristic. Score 7 is 3/4 merged PRs; PR #1 had no CI. The next PRs age that one out. Do **not** rename `Check CI` for this check. |
| CII-Best-Practices | 10 | Gold badge |
| Maintained | 0 until ~2026-11-12 | Leave the alert **open**. Do not dismiss. Revisit after 90 days. |

Scorecard still files an alert below 10 (SAST at 9 already did). Branch-Protection target
is 10 (two reviews, code owners, dismiss stale, no bypass actors). If the next Scorecard
run still reports 9 because `GITHUB_TOKEN` cannot see an admin-only ruleset field, leave
it; do not add bypass actors to chase a point.

## CODEOWNERS and ruleset

Root `CODEOWNERS`:

```
* @franchb @MichaelSBoop @wallrat1
```

The author does not count as a reviewer. A PR from `@franchb` needs approvals from
`@MichaelSBoop` and `@wallrat1` (two reviews and a code-owner review in one step).

**Ruleset** (create via `gh api` after the git PR merges):

- Target: `refs/heads/main`
- Enforcement: Active
- Bypass actors: **none** (any bypass makes Scorecard treat “enforce for admins” as false)
- Block deletions
- Block force pushes
- Require a pull request
- Required approvals: **2**
- Require review from code owners
- Dismiss stale reviews on new commits
- Require approval of the most recent reviewable push
- Require conversation resolution
- Require status checks, branch must be up to date
- Linear history: **off**

**Required checks** (exact check contexts GitHub already reports on PRs, plus the two new jobs; each must run on every `pull_request`):

- `Check CI` — ubuntu `make check-ci`. `release.yml` has a **different** job with this same display name; that job is push-to-main only and is not a PR required check. Leave `release.yml` alone (Non-Goals).
- `Test (macos-latest)`
- `Test (windows-latest)`
- `Analyze (go)` — CodeQL matrix job
- `Dependency Review`
- `Conventional commit title`
- `govulncheck (module)`
- `OSV Scanner`

ClusterFuzzLite is **not** required.

No Scorecard PAT. `GITHUB_TOKEN` already sees rulesets.

Intended `gh api` body (field names follow the repository rulesets API; adjust only if
GitHub rejects a field, not to weaken the rules):

```json
{
  "name": "main",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": {
    "ref_name": {
      "include": ["refs/heads/main"],
      "exclude": []
    }
  },
  "rules": [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 2,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": true,
        "require_last_push_approval": true,
        "required_review_thread_resolution": true
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "required_status_checks": [
          {"context": "Check CI"},
          {"context": "Test (macos-latest)"},
          {"context": "Test (windows-latest)"},
          {"context": "Analyze (go)"},
          {"context": "Dependency Review"},
          {"context": "Conventional commit title"},
          {"context": "govulncheck (module)"},
          {"context": "OSV Scanner"}
        ]
      }
    }
  ]
}
```

Confirm every `context` string against the git PR’s Checks tab **before** creating the
ruleset (matrix jobs sometimes differ by punctuation). Do not guess after the ruleset is live.

**Accepted cost:** `dismiss_stale_reviews_on_push` + `require_last_push_approval` +
strict required checks + 2 approvals + empty bypass list means every new push (including
Dependabot rebases) needs two humans again. Weekly Dependabot stays. Do **not** add a
Dependabot bypass actor; Scorecard treats any bypass as “admins not enforced.” Dep PRs
wait for `@franchb` plus one of the other two, or for both collaborators.

## Dual vuln gates

Three scans. Two of them are required, visible PR jobs.

| Scan | Where | Blocks | Ignore |
| --- | --- | --- | --- |
| `govulncheck ./...` (call graph, default) | stays inside `make check-ci` | reachable Go vulns | none |
| `govulncheck -C pkg/yckms -scan=module` (no package pattern) | new required job `govulncheck (module)` | any Go vuln in the module graph | wrapper (govulncheck cannot silence IDs; Go issue 61211) |
| `osv-scanner scan source --recursive .` | new required job `OSV Scanner` | OSV + GHSA + **MAL-** on `go.mod`/`go.sum` | `osv-scanner.toml` (Scorecard reads this too) |

**Single ignore list**, `osv-scanner.toml` next to `go.mod`:

```toml
[[IgnoredVulns]]
id = "GO-2026-5932"
reason = "golang.org/x/crypto is in the graph via sigstore; this repo does not import golang.org/x/crypto/openpgp. Every x/crypto version is flagged. No bump exists."
```

New ignores need an `id` and a `reason`. No expiry on `GO-2026-5932`.

**Module-scan wrapper** (`ci/scripts/govulncheck_module.py`):

Pinned `govulncheck` **v1.7.0** rejects package patterns in module mode
(`patterns are not accepted for module only scanning`, exit 2). A patternless
scan from the repository root also fails (`no Go files` — the module root is
not a package). Invoke from a package directory with **no** pattern:

```
govulncheck -C pkg/yckms -scan=module -format json
```

`-C pkg/yckms` and `-C cmd/sigstore-kms-yckms` report the same module graph
(verified: both exit 3 in text mode on `GO-2026-5932`). Use `pkg/yckms`.
JSON mode exits 0 even when findings exist; findings are streaming objects
with `finding.osv` (e.g. `"GO-2026-5932"`).

Then:

1. Parse the streaming JSON. Collect each `finding.osv`.
2. Drop IDs (and aliases, if the finding lists them) that have an
   `[[IgnoredVulns]]` entry in `osv-scanner.toml` whose `ignoreUntil` is
   **absent or strictly in the future** (UTC date). An expired
   `ignoreUntil` must **not** suppress the finding — same rule osv-scanner
   uses, so the two required gates cannot diverge on that file.
   Parse the toml with stdlib `tomllib` (Python 3.11+; Ubuntu latest is fine).
3. Exit 1 if any finding remains.
4. Non-zero govulncheck process errors, empty/invalid JSON, or a missing
   `osv-scanner.toml` are hard fails, not skips.

**Wiring**

- Pin `osv-scanner` **v2.5.1** in `.binny.yaml` (`google/osv-scanner`, `github-release`).
- Taskfile: `govulncheck-module`, `osv-scanner`. `check-ci` keeps **call-graph** `govulncheck`
  only (no triple scan on the inner loop).
- `ci.yml`: two new jobs, same harden-runner / `persist-credentials: false` / `setup-go` /
  `go-version-file: go.mod` shape as today. Commands: `make govulncheck-module` and
  `make osv-scanner`.
- `vuln.yml` (Monday schedule + `workflow_dispatch`): run **all three** scans so a new
  advisory against unchanged code still fails without a PR.
- Dependency Review stays as-is (PR **diff** only).

**Failure policy:** fail closed. A new GHSA / MAL- / GO- ID not in `osv-scanner.toml`
blocks merge. Adding an ignore is a reviewed change to that file, not a workflow `continue-on-error`.

## Fuzzing and ClusterFuzzLite

Scorecard Fuzzing looks for native Go `func FuzzXxx(f *testing.F)` in the tree.

**In-tree target:** `pkg/yckms` URI parsers.

```go
func FuzzParseReference(f *testing.F)
```

Seeds: the existing unit-test strings (key-ID form, folder/keyname form, empty, full
`yckms://` scheme). Invariant: **no panic**. Call both `ParseReference` and `ValidReference`.
Do not fuzz `credentials()` (network / instance metadata).

`go test ./...` already executes `f.Add` seeds. Random fuzzing needs `-fuzz`.

**Inner loop:** Task `fuzz` runs
`go test ./pkg/yckms -fuzz=FuzzParseReference -fuzztime=20s`.
`check-ci` calls it.

**ClusterFuzzLite** compiles the **same** native test with OSS-Fuzz
`compile_native_go_fuzzer` (not a second go-fuzz `Fuzz([]byte) int` API).

`.clusterfuzzlite/`:

| File | Role |
| --- | --- |
| `project.yaml` | `language: go` |
| `Dockerfile` | `FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:<digest>` — **digest-pin**, not the floating tag. Scorecard Pinned-Dependencies inspects Dockerfiles; an unpinned `FROM` is a new Medium alert this repo does not have today. Copy the repo. `GOTOOLCHAIN=auto` so `go.mod`’s `toolchain go1.26.6` is honored. Resolve the digest at implementation time (`crane digest` / `docker buildx imagetools`). |
| `build.sh` | `compile_native_go_fuzzer github.com/franchb/sigstore-kms-yckms/pkg/yckms FuzzParseReference fuzz_parse_reference` |

Add a Dependabot `docker` ecosystem with `directory: "/.clusterfuzzlite"`,
`commit-message.prefix: chore(deps)`, weekly Monday, 7-day cooldown, so the
digest does not rot.

**Workflows** (SHA-pin `google/clusterfuzzlite/actions/build_fuzzers` and `run_fuzzers` to a
commit; never `@v1`. `permissions: {}` at workflow level. Each CFL job sets
`contents: read` (the actions check out the repo) and `security-events: write`
(SARIF). Harden-runner like the rest, unless it blocks CFL’s Docker builder —
in that case omit harden-runner on the two CFL workflows only and say so in the
workflow comment. ASan only.):

| File | When | Mode | Duration | Required? |
| --- | --- | --- | --- | --- |
| `.github/workflows/cflite_pr.yml` | `pull_request` | `code-change` | 180s | **No** |
| `.github/workflows/cflite_batch.yml` | weekly cron | `batch` | 600s | n/a |

Crashes are GitHub Actions artifacts. No storage-repo PAT.

## Coverage (25.1% → ≥90%)

Today (`go test -covermode=atomic ./...`): **25.1%** statements overall, **26.8%** in
`pkg/yckms`, **0.0%** in `cmd/sigstore-kms-yckms`. `task test` gates with
`COVERAGE_THRESHOLD: 0`. Gold requires ≥90% statement coverage.

**Gate:** set `COVERAGE_THRESHOLD` to `90`. `ci/scripts/coverage.py` already fails `task test`
when `go tool cover -func` total is below the threshold. `check-ci` already runs `task test`.

**Branch coverage:** Go’s `go tool cover` measures statements, not branches. Gold criterion
`test_branch_coverage80` is **N/A** with that justification. Do not add a second coverage
toolchain.

**How we get to 90% (unit tests, fakes, no live Yandex Cloud):**

1. **`cmd/sigstore-kms-yckms`:** extract `run` (or equivalent) from `main` so `os.Exit` is
   not on the unit-tested path. Test missing argv, wrong protocol version, handler/
   dispatcher error paths with fake stdin/stdout. `main` stays a one-line `os.Exit(run(...))`.
2. **`pkg/yckms` parsers and errors:** table-test remaining `ParseReference` / `ValidReference`
   / `verifierForAlgorithm` / sentinel error wrapping branches.
3. **`credentials`:** IAM token, OAuth token, valid and invalid service-account JSON file,
   missing sources (already tested).
4. **KMS client / signer:** introduce the smallest fake or interface that lets
   `LoadSignerVerifier`, create-key, public-key, sign, and verify run without a real SDK
   connection. Cover algorithm map, RSA vs ECDSA verifier construction, cache miss/hit,
   uninitialized signer, and error wrapping. Do not mock more than the package already
   calls.

Tests stay `t.Parallel()` where they do not mutate process-wide env; `t.Setenv` tests do not
run in parallel with each other. No coverage of generated protobuf or third-party modules.

This refactor exists **only** to make those paths unit-testable. No unrelated API changes.

## SPDX, CONTRIBUTING, security review, Issues

Gold / silver MUST items that are files in this repo:

- **SPDX + copyright** on every `.go` file (they already have an Apache copyright header).
  Add `SPDX-License-Identifier: Apache-2.0` in that header. Do not SPDX-tag generated or
  third-party files we do not own; we have none today.
- **`CONTRIBUTING.md`:** how to run `make check-ci`, conventional-commit PR titles, **two**
  approving reviews, code owners, no self-approval, what a reviewer must check (tests,
  scanners, no secrets).
- **Security review** paragraph in `SECURITY.md`: trust boundary is this plugin and the
  local handling of YC credentials and KMS URIs; Yandex Cloud KMS itself and Sigstore
  libraries are out of scope (already stated). Date the review (2026-08).
- **Reproducible release:** README already has verify-release instructions. Add a short
  “reproduce a snapshot archive locally” note pointing at `task snapshot` and `-trimpath` /
  `CGO_ENABLED=0`.
- **Small tasks:** operator enables GitHub Issues (currently off) and keeps at least one
  `good first issue`. Not a file in the first PR, but required before gold.

README gold badge image is a **follow-up** after bestpractices.dev grants gold. Passing or
silver badge in the meantime is allowed.

## CII gold and the questionnaire session

Scorecard’s CII check is 10 only for **gold**. Gold requires passing, then silver, then gold.

**Operator, GitHub (not the questionnaire):**

- All three maintainers enable GitHub 2FA (TOTP or WebAuthn, not SMS-only).
- Enable Issues; one `good first issue`.
- Bus factor / unassociated contributors: `@franchb`, `@MichaelSBoop`, `@wallrat1`.

**Operator, this conversation, after the git PR is on `main`:**

1. User registers the GitHub repo on [bestpractices.dev](https://www.bestpractices.dev).
2. User works **passing → silver → gold** in that order.
3. User pastes **one criterion** (or a tight group from the same page).
4. Agent replies with: Met / N/A / Unmet, the justification text to paste, and the URL to
   cite (repo file, workflow, release, settings). No invented URLs. If Unmet, say what is
   still missing in git or in GitHub settings.
5. Repeat until gold.

The spec does **not** pre-fill 180 answers. They go stale. The session is the source of
truth.

TLS / “we are a server”: N/A — this is a KMS plugin; the Yandex SDK uses HTTPS.
Hardened site: cite GitHub.com’s headers on `github.com/franchb/sigstore-kms-yckms`.
Dynamic analysis: existing `go test -race` plus ClusterFuzzLite.

## Verification

Git work is not done until:

- `make check-ci` is green, including **≥90%** statement coverage and the 20s
  `FuzzParseReference` run.
- `make govulncheck-module` is green with only `GO-2026-5932` ignored; **removing** that
  ignore must fail. The task must invoke
  `govulncheck -C pkg/yckms -scan=module` **without** a package pattern
  (`./...` exits 2 on v1.7.0).
- `make osv-scanner` is green.
- Native `FuzzParseReference` exists in `pkg/yckms`.
- New CI job names match the required-check list (`Check CI` stays).
- `.clusterfuzzlite/Dockerfile` uses `FROM ...@sha256:...`, not a floating tag.
- `task validate-actions` (actionlint + zizmor) is green, including SHA-pinned CFL actions.

After merge:

- Create the ruleset. A trivial follow-up PR must be blocked until two humans approve.
- Next Scorecard run: Fuzzing 10, Vulnerabilities 10, Branch-Protection 10. Code-Review
  and CI-Tests move as new reviewed PRs replace old history. SAST ages out. Maintained
  stays 0 until ~2026-11-12.
- Then the bestpractices.dev walkthrough in this session.

ClusterFuzzLite PR workflow may fail without blocking merge.

## Out of scope (repeat)

See Non-Goals. In particular: no CFL storage repo, no OSS-Fuzz, no Maintained dismissal,
no live YC, no release-pipeline rewrite.
