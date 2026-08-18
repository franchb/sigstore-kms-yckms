# CI Hardening and Release Publishing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade dependencies to Go 1.26.6, adopt the `embedded-clickhouse` linter configuration, add supply-chain security CI, and publish signed, attested, multi-platform releases driven by go-semantic-release.

**Architecture:** `Taskfile.yaml` stays the single source of truth for every check and `.binny.yaml` for every tool version; GitHub workflows are thin callers of `make <target>` plus the GitHub-hosted analyses Task cannot run (CodeQL, Scorecard, dependency review) and release publishing. Release flows in two stages: go-semantic-release derives a version from conventional-commit subjects on `main` and creates the tag, then GoReleaser builds, signs, and attests the artifacts for that tag.

**Tech Stack:** Go 1.26.6, Task v3, binny, golangci-lint v2.12.2, GoReleaser v2, cosign (keyless/OIDC), syft, go-semantic-release, zizmor, actionlint, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-08-18-ci-and-publishing-design.md`

## Global Constraints

- `go.mod` MUST use `go 1.26.0` plus `toolchain go1.26.6`. Never a patch-level `go` directive — `pkg/yckms` is a published library and a patch directive taxes every consumer.
- Workflows MUST resolve Go via `go-version-file: go.mod`. No hardcoded version strings.
- Every `uses:` MUST be pinned to a full 40-character commit SHA with a trailing `# vX.Y.Z` comment. The exact SHAs are given in each task; they were resolved against the GitHub API and verified to match their tags.
- Every workflow MUST declare `permissions: {}` at workflow level and grant minimal explicit permissions per job.
- Every `actions/checkout` MUST set `persist-credentials: false`.
- Every job MUST set `timeout-minutes`.
- `step-security/harden-runner` with `egress-policy: audit` MUST be the first step of every **Linux** job. It does not support macOS or Windows runners — omit it there.
- Every tool version lives in `.binny.yaml`. Workflows MUST NOT `go install` or otherwise inline-pin a tool version.
- Commit subjects MUST follow conventional commits (`feat:`, `fix:`, `chore:`, `docs:`, `ci:`, `refactor:`, `test:`). go-semantic-release parses them to derive versions; an unparseable subject silently produces no release.
- The binary inside every release archive MUST be named exactly `sigstore-kms-yckms`. Sigstore plugin discovery resolves plugins by filename on `PATH`.

## Pull Request Split

Two branches off `main`:

- **PR 1 — infrastructure (Tasks 1–7).** No Go source changes.
- **PR 2 — linters (Tasks 8–12).** The only Go source changes. Branch is intentionally red between Tasks 8 and 12; Task 12 restores green.

## File Structure

**Created:**

| File | Responsibility |
| --- | --- |
| `.github/workflows/codeql.yml` | CodeQL Go analysis |
| `.github/workflows/scorecards.yml` | OSSF Scorecard, SARIF upload |
| `.github/workflows/dependency-review.yml` | Blocks PRs adding vulnerable deps |
| `.github/workflows/validate-github-actions.yaml` | zizmor lint over `.github` |
| `.github/workflows/vuln.yml` | Scheduled-only govulncheck |
| `.github/workflows/pr-title.yml` | Conventional-commit PR title check |
| `.github/workflows/release.yml` | semantic-release → GoReleaser |
| `.github/zizmor.yml` | zizmor rule config |
| `.github/dependabot.yml` | gomod + github-actions updates |
| `SECURITY.md` | Vulnerability reporting policy (Scorecard checks for it) |
| `.goreleaser.yaml` | Build, archive, checksum, sign, SBOM |
| `pkg/yckms/errors.go` | Every package sentinel error, in one place |

**Modified:** `go.mod`, `go.sum`, `.gitignore`, `.binny.yaml`, `Taskfile.yaml`, `.github/workflows/ci.yml`, `.golangci.yml`, `README.md`, `pkg/yckms/client.go`, `pkg/yckms/credentials.go`, `pkg/yckms/reference.go`, `pkg/yckms/signer.go`, `pkg/yckms/signer_test.go`, `cmd/sigstore-kms-yckms/main.go`, `cmd/sigstore-kms-yckms/main_test.go`

**Deleted:** `goreleaser.yml` (replaced by `.goreleaser.yaml`)

---

# PR 1 — Infrastructure

### Task 1: Dependency and Go toolchain upgrade

This upgrade was verified end-to-end on a scratch copy before this plan was written: it builds and tests clean with **zero source changes**. If you see compile errors, stop and report — do not start patching source.

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`

**Interfaces:**
- Consumes: nothing.
- Produces: a `go.mod` whose `toolchain` line every later workflow reads via `go-version-file: go.mod`.

- [ ] **Step 1: Record the current test baseline**

```bash
go test ./... 2>&1 | tee /tmp/baseline-tests.txt
```

Expected: `ok` for `cmd/sigstore-kms-yckms` and `pkg/yckms`.

- [ ] **Step 2: Upgrade all dependencies**

```bash
go get -u ./...
go mod tidy
```

- [ ] **Step 3: Verify the resulting direct dependency versions exactly match**

```bash
go list -m -f '{{if not .Indirect}}{{.Path}} {{.Version}}{{end}}' all | grep -v '^$'
```

Expected exactly these five direct dependencies:

```
github.com/jellydator/ttlcache/v3 v3.4.1
github.com/sigstore/sigstore v1.10.9
github.com/yandex-cloud/go-genproto v0.113.0
github.com/yandex-cloud/go-sdk v0.33.0
google.golang.org/grpc v1.83.0
```

If a version is *higher* than listed, a newer release landed after this plan was written — that is fine, note it in the commit body. If *lower*, `go get -u` did not run.

- [ ] **Step 4: Set the Go directive and toolchain**

Edit `go.mod` so the top of the file reads exactly:

```
module github.com/franchb/sigstore-kms-yckms

go 1.26.0

toolchain go1.26.6
```

Replace the existing single `go 1.26.3` line. Do **not** write `go 1.26.6`.

- [ ] **Step 5: Verify build and tests**

```bash
go build ./... && go test ./...
```

Expected: build silent, both packages `ok`.

- [ ] **Step 6: Verify the toolchain actually resolves**

```bash
go version
```

Expected: `go1.26.6` (GOTOOLCHAIN=auto downloads it if the local toolchain is older). If this reports an older version and the build still succeeded, `GOTOOLCHAIN` is pinned locally — record that in the commit body and continue.

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum
git commit -m "chore(deps): upgrade dependencies and move to Go 1.26.6

Direct: ttlcache v3.4.1, sigstore v1.10.9, yc-go-genproto v0.113.0,
yc-go-sdk v0.33.0, grpc v1.83.0. No source changes required.

Uses go 1.26.0 + toolchain go1.26.6 rather than a patch-level go
directive, so consumers of pkg/yckms are not forced onto >=1.26.6."
```

---

### Task 2: Tool pins and the local verification harness

Build the local verification tooling *before* the workflows, so every later task can validate its own workflow files locally instead of discovering breakage on push. All three new tools were confirmed installable via binny (including zizmor, whose Rust-triple asset names binny resolves correctly).

**Files:**
- Modify: `.binny.yaml`
- Modify: `Taskfile.yaml`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: nothing.
- Produces: `task validate-actions` and `task snapshot` targets, plus `.tool/zizmor`, `.tool/actionlint`, `.tool/goreleaser`. Tasks 3–7 depend on `validate-actions`; Task 6 depends on `snapshot`.

- [ ] **Step 1: Update the stale pins and add the three new tools in `.binny.yaml`**

Change `govulncheck`'s `want` from `v1.3.0` to `v1.7.0`, `binny`'s from `v0.13.1` to `v0.13.2`, `task`'s from `v3.51.1` to `v3.53.1`, and `betteralign`'s from `v0.11.0` to `v0.14.4`. Leave `golangci-lint` at `v2.12.2` and `gosimports` at `v0.3.8` — both are current.

Append these three entries to the `tools:` list:

```yaml
  - name: goreleaser
    version:
      want: v2.17.1
    method: github-release
    with:
      repo: goreleaser/goreleaser

  - name: actionlint
    version:
      want: v1.7.12
    method: github-release
    with:
      repo: rhysd/actionlint

  - name: zizmor
    version:
      want: v1.29.0
    method: github-release
    with:
      repo: zizmorcore/zizmor
```

- [ ] **Step 2: Install and verify all three tools resolve**

```bash
rm -rf .tool && make tools
.tool/goreleaser --version && .tool/actionlint --version && .tool/zizmor --version
```

Expected: `goreleaser` banner, `1.7.12`, `zizmor 1.29.0`.

- [ ] **Step 3: Add `/dist/` to `.gitignore`**

Under the `# Editor/IDE and local tooling` block, alongside `/.tool/` and `/.tmp/`, add:

```
/dist/
```

This is required: `task snapshot` (next step) writes `dist/`, and `check-ci` runs `verify-no-diff`, which would fail on the untracked output.

- [ ] **Step 4: Add the two verification targets to `Taskfile.yaml`**

Append to the `tasks:` map:

```yaml
  validate-actions:
    desc: Lint GitHub Actions workflows for syntax and security issues
    deps: [ tools ]
    cmds:
      - "{{ .TOOL_DIR }}/actionlint"
      - "{{ .TOOL_DIR }}/zizmor --config .github/zizmor.yml .github"

  snapshot:
    desc: Build a full release locally without publishing or signing
    deps: [ tools ]
    cmds:
      - "{{ .TOOL_DIR }}/goreleaser release --snapshot --clean"
```

`validate-actions` references `.github/zizmor.yml`, created in Task 4. Until then it fails on the missing config file — that is expected and Task 4's verification covers it.

- [ ] **Step 5: Verify actionlint passes against the current workflow**

```bash
.tool/actionlint
```

Expected: no output (exit 0). `.github/workflows/ci.yml` is the only workflow present and is valid today.

- [ ] **Step 6: Verify `verify-no-diff` still passes**

```bash
task verify-no-diff
```

Expected: no output. If `.tool/` or `dist/` appears, the `.gitignore` edit is wrong.

- [ ] **Step 7: Commit**

```bash
git add .binny.yaml Taskfile.yaml .gitignore
git commit -m "ci: pin goreleaser, actionlint, zizmor and add verification targets

Refreshes stale pins (govulncheck v1.3.0 -> v1.7.0, betteralign v0.11.0
-> v0.14.4, binny, task) and adds task validate-actions / task snapshot
so workflow and release-config changes are verifiable locally."
```

---

### Task 3: Harden `ci.yml` and split the platform matrix

**Files:**
- Modify: `.github/workflows/ci.yml` (full replacement)

**Interfaces:**
- Consumes: `make check-ci` and `make ci-bootstrap-go` from `Makefile`; `go-version-file: go.mod` from Task 1.
- Produces: the `check-ci` and `test` job names other tasks do not depend on. Removes the `release` job that Task 7 replaces.

- [ ] **Step 1: Confirm the release job you are about to delete is the one that exists**

```bash
grep -n "tags:\|release:\|goreleaser" .github/workflows/ci.yml
```

Expected: a `tags: - 'v*'` trigger and a `release:` job using `goreleaser/goreleaser-action@v6`. Both are removed in this task — Task 7 supersedes them. Leaving the tag trigger in place would make semantic-release's tag fire a second, competing release.

- [ ] **Step 2: Replace `.github/workflows/ci.yml` entirely**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions: {}

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  check-ci:
    name: Check CI
    runs-on: ubuntu-latest
    timeout-minutes: 20
    permissions:
      contents: read
    steps:
      - name: Harden Runner
        uses: step-security/harden-runner@b09bb98e06d4d774595224525879c09bc6e98c40 # v2.20.1
        with:
          egress-policy: audit

      - name: Checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Install Go
        uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version-file: go.mod

      - name: Bootstrap Go modules
        run: make ci-bootstrap-go

      - name: Run check-ci
        run: make check-ci

  test:
    name: Test (${{ matrix.os }})
    runs-on: ${{ matrix.os }}
    timeout-minutes: 15
    permissions:
      contents: read
    strategy:
      fail-fast: false
      matrix:
        os: [macos-latest, windows-latest]
    steps:
      - name: Checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Install Go
        uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version-file: go.mod

      - name: Run unit tests
        run: go test -race -count=1 ./...
```

Three deliberate choices, do not "fix" them:
- `check-ci` is ubuntu-only. It shells out to `/bin/bash ci/scripts/diff.sh` and `ci/scripts/coverage.py`; making that portable to Windows is out of scope.
- The `test` job has no `harden-runner` step — it does not support macOS or Windows runners.
- There is no `oldstable` matrix leg. With a `1.26` directive, `oldstable` resolves to 1.25 and fails outright.

- [ ] **Step 3: Verify the workflow lints**

```bash
.tool/actionlint
```

Expected: no output (exit 0).

- [ ] **Step 4: Verify the full gate still passes locally**

```bash
make check-ci
```

Expected: ends with `CI checks passed`.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: harden CI workflow and split the platform matrix

SHA-pins every action, drops workflow-level permissions to {}, sets
persist-credentials: false, adds harden-runner and job timeouts, and
resolves Go from go.mod instead of a hardcoded version.

Adds a macOS/Windows unit-test job since releases now ship binaries for
those platforms, and removes the tag trigger and release job, which
release.yml supersedes."
```

---

### Task 4: Security analysis workflows

**Files:**
- Create: `.github/zizmor.yml`
- Create: `.github/workflows/validate-github-actions.yaml`
- Create: `.github/workflows/codeql.yml`
- Create: `.github/workflows/scorecards.yml`
- Create: `.github/workflows/dependency-review.yml`
- Create: `.github/workflows/vuln.yml`
- Create: `SECURITY.md`
- Modify: `Taskfile.yaml`

**Interfaces:**
- Consumes: `task validate-actions` from Task 2; `make govulncheck` from `Taskfile.yaml`.
- Produces: nothing later tasks consume.

- [ ] **Step 1: Create `.github/zizmor.yml`**

```yaml
rules:
  unpinned-uses:
    ignore: []
```

- [ ] **Step 2: Verify `task validate-actions` now passes**

```bash
task validate-actions
```

Expected: `actionlint` silent, then zizmor reporting no findings against `.github`. This is the step that closes the gap Task 2 left open.

- [ ] **Step 3: Create `.github/workflows/validate-github-actions.yaml`**

```yaml
name: "Validate GitHub Actions"

on:
  pull_request:
    paths:
      - '.github/workflows/**'
      - '.github/actions/**'
  push:
    branches: [main]
    paths:
      - '.github/workflows/**'
      - '.github/actions/**'

permissions: {}

jobs:
  zizmor:
    name: Lint
    runs-on: ubuntu-latest
    timeout-minutes: 5
    permissions:
      contents: read
      security-events: write
    steps:
      - name: Harden Runner
        uses: step-security/harden-runner@b09bb98e06d4d774595224525879c09bc6e98c40 # v2.20.1
        with:
          egress-policy: audit

      - name: Checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Run zizmor
        uses: zizmorcore/zizmor-action@3dc1ecc9bcb9e94e9b2c709687979e1298497054 # v0.6.2
        with:
          config-file: .github/zizmor.yml
          sarif-upload: true
          inputs: .github
```

- [ ] **Step 4: Create `.github/workflows/codeql.yml`**

```yaml
name: "CodeQL"

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: "0 0 * * 1"

permissions: {}

jobs:
  analyze:
    name: Analyze
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      actions: read
      contents: read
      security-events: write
    strategy:
      fail-fast: false
      matrix:
        language: ["go"]
    steps:
      - name: Harden Runner
        uses: step-security/harden-runner@b09bb98e06d4d774595224525879c09bc6e98c40 # v2.20.1
        with:
          egress-policy: audit

      - name: Checkout repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Initialize CodeQL
        uses: github/codeql-action/init@5595ccaf912efad79be6eef63a5619ff05969be3 # v4.37.6
        with:
          languages: ${{ matrix.language }}

      - name: Autobuild
        uses: github/codeql-action/autobuild@5595ccaf912efad79be6eef63a5619ff05969be3 # v4.37.6

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@5595ccaf912efad79be6eef63a5619ff05969be3 # v4.37.6
        with:
          category: "/language:${{ matrix.language }}"
```

- [ ] **Step 5: Create `.github/workflows/scorecards.yml`**

```yaml
name: Scorecard supply-chain security

on:
  branch_protection_rule:
  schedule:
    - cron: '20 7 * * 2'
  push:
    branches: [main]

permissions: read-all

jobs:
  analysis:
    name: Scorecard analysis
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      security-events: write
      id-token: write
      contents: read
      actions: read
    steps:
      - name: Harden Runner
        uses: step-security/harden-runner@b09bb98e06d4d774595224525879c09bc6e98c40 # v2.20.1
        with:
          egress-policy: audit

      - name: Checkout code
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Run analysis
        uses: ossf/scorecard-action@2d1146689b8cda280b9bc96326124645441f03bc # v2.4.4
        with:
          results_file: results.sarif
          results_format: sarif
          publish_results: true

      - name: Upload artifact
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: SARIF file
          path: results.sarif
          retention-days: 5

      - name: Upload to code-scanning
        uses: github/codeql-action/upload-sarif@5595ccaf912efad79be6eef63a5619ff05969be3 # v4.37.6
        with:
          sarif_file: results.sarif
```

`permissions: read-all` at workflow level is intentional here and is the documented Scorecard configuration; it is the one exception to the `permissions: {}` constraint.

- [ ] **Step 6: Create `.github/workflows/dependency-review.yml`**

```yaml
name: 'Dependency Review'

on: [pull_request]

permissions: {}

jobs:
  dependency-review:
    name: Dependency Review
    runs-on: ubuntu-latest
    timeout-minutes: 5
    permissions:
      contents: read
    steps:
      - name: Harden Runner
        uses: step-security/harden-runner@b09bb98e06d4d774595224525879c09bc6e98c40 # v2.20.1
        with:
          egress-policy: audit

      - name: Checkout Repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Dependency Review
        uses: actions/dependency-review-action@a1d282b36b6f3519aa1f3fc636f609c47dddb294 # v5.0.0
```

- [ ] **Step 7: Create `.github/workflows/vuln.yml`**

```yaml
name: vuln

on:
  schedule:
    - cron: '0 10 * * 1'
  workflow_dispatch:

permissions: {}

jobs:
  run:
    name: Vuln
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: read
    steps:
      - name: Harden Runner
        uses: step-security/harden-runner@b09bb98e06d4d774595224525879c09bc6e98c40 # v2.20.1
        with:
          egress-policy: audit

      - name: Checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Install Go
        uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version-file: go.mod

      - name: Run govulncheck
        run: make govulncheck
```

Two deliberate choices: there is **no** push or pull_request trigger (`check-ci` already runs govulncheck on every change; the schedule exists to catch newly published advisories against unchanged code), and it runs `make govulncheck` so the version comes from `.binny.yaml` rather than an inline `go install ...@vX.Y.Z`. Do not add an inline pin — that is the exact drift this design exists to avoid.

- [ ] **Step 8: Create `SECURITY.md`**

```markdown
# Security Policy

## Supported Versions

Only the latest released version of `sigstore-kms-yckms` receives security fixes.

## Reporting a Vulnerability

Report security vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/franchb/sigstore-kms-yckms/security/advisories/new).

Please do not open a public issue for a security report.

Include, where possible: the affected version, a description of the impact, and
steps to reproduce. You will receive an acknowledgement within seven days.

## Scope

This project is a Yandex Cloud KMS provider for Sigstore. Vulnerabilities in the
Yandex Cloud KMS service itself should be reported to Yandex Cloud; vulnerabilities
in Sigstore libraries should be reported to the [Sigstore project](https://github.com/sigstore/sigstore/security).

## Release Verification

Release artifacts are signed with [cosign](https://github.com/sigstore/cosign)
keyless signatures and carry SLSA build provenance. See the Verifying releases
section of `README.md`.
```

- [ ] **Step 9: Add `validate-actions` to the `check-ci` gate in `Taskfile.yaml`**

In the `check-ci` task's `cmds:` list, insert `- task: validate-actions` immediately after the existing `- task: lint` entry, so the list reads:

```yaml
    cmds:
      - task: lint
      - task: validate-actions
      - task: verify-no-diff
      - task: test
      - task: verify-no-diff
      - task: govulncheck
      - echo "CI checks passed"
```

- [ ] **Step 10: Verify everything passes**

```bash
task validate-actions && make check-ci
```

Expected: zizmor and actionlint clean across all six workflows, then `CI checks passed`.

- [ ] **Step 11: Commit**

```bash
git add .github/zizmor.yml .github/workflows/ SECURITY.md Taskfile.yaml
git commit -m "ci: add CodeQL, Scorecard, dependency review, zizmor and vuln scan

Adds the supply-chain analyses Task cannot run locally, plus SECURITY.md
which Scorecard checks for. vuln.yml is schedule-only and calls
make govulncheck so the pin stays in .binny.yaml.

Wires validate-actions into the check-ci gate."
```

---

### Task 5: Dependabot and conventional-commit PR titles

**Files:**
- Create: `.github/dependabot.yml`
- Create: `.github/workflows/pr-title.yml`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing later tasks consume. Both exist to protect the Task 7 release flow.

- [ ] **Step 1: Create `.github/dependabot.yml`**

```yaml
version: 2
updates:
  - package-ecosystem: "gomod"
    commit-message:
      prefix: "chore(deps)"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "12:00"
      timezone: "UTC"
    cooldown:
      default-days: 3
      semver-major-days: 7

  - package-ecosystem: "github-actions"
    commit-message:
      prefix: "chore(deps)"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "12:00"
      timezone: "UTC"
    cooldown:
      default-days: 3
    groups:
      github-actions:
        patterns:
          - "*"
```

⚠️ The prefix MUST be `chore(deps)`. `embedded-clickhouse` uses `deps:`, which is **not** a valid conventional-commit type — with go-semantic-release live, every Dependabot merge would be unparseable and silently produce no release. Do not copy ec's value.

- [ ] **Step 2: Create `.github/workflows/pr-title.yml`**

```yaml
name: PR Title

on:
  pull_request_target:
    types: [opened, edited, reopened, synchronize]

permissions: {}

jobs:
  conventional-commit:
    name: Conventional commit title
    runs-on: ubuntu-latest
    timeout-minutes: 5
    permissions:
      pull-requests: read
    steps:
      - name: Check PR title
        uses: amannn/action-semantic-pull-request@48f256284bd46cdaab1048c3721360e808335d50 # v6.1.1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          types: |
            feat
            fix
            chore
            docs
            ci
            refactor
            test
            perf
            build
            revert
```

This uses `pull_request_target` because `pull_request` does not expose a token with `pull-requests` access for forked PRs. The job checks out **no code** and runs only the pinned action, so the elevated trigger carries no code-execution risk. Do not add a checkout step to this workflow.

- [ ] **Step 3: Verify both files lint**

```bash
task validate-actions
```

Expected: clean. zizmor specifically checks `pull_request_target` workflows for dangerous checkouts; a finding here means a checkout step was added — remove it.

- [ ] **Step 4: Commit**

```bash
git add .github/dependabot.yml .github/workflows/pr-title.yml
git commit -m "ci: add Dependabot and conventional-commit PR title check

Dependabot uses a chore(deps) prefix so go-semantic-release can parse
dependency merges. The PR title check guards the commit subject that
squash-merge puts on main, which is what semantic-release reads."
```

---

### Task 6: GoReleaser configuration

**Files:**
- Create: `.goreleaser.yaml`
- Delete: `goreleaser.yml`

**Interfaces:**
- Consumes: `task snapshot` from Task 2; `/dist/` in `.gitignore` from Task 2.
- Produces: a config Task 7's `release.yml` invokes with `goreleaser release --clean`. Task 7 relies on `dist/` containing `*.tar.gz`, `*.zip`, and `sigstore-kms-yckms_*_checksums.txt`.

- [ ] **Step 1: Create `.goreleaser.yaml`**

```yaml
version: 2

project_name: sigstore-kms-yckms

env:
  - CGO_ENABLED=0

builds:
  - id: sigstore-kms-yckms
    main: ./cmd/sigstore-kms-yckms
    binary: sigstore-kms-yckms
    goos:
      - linux
      - darwin
      - windows
    goarch:
      - amd64
      - arm64
    flags:
      - -trimpath
    ldflags:
      - -s -w

archives:
  - id: sigstore-kms-yckms
    formats:
      - tar.gz
    name_template: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"
    format_overrides:
      - goos: windows
        formats:
          - zip
    files:
      - LICENSE
      - README.md

checksum:
  name_template: '{{ .ProjectName }}_{{ .Version }}_checksums.txt'
  algorithm: sha256

sboms:
  - artifacts: archive

signs:
  - cmd: cosign
    artifacts: checksum
    output: true
    args:
      - sign-blob
      - --yes
      - --bundle=${signature}
      - ${artifact}
    signature: ${artifact}.sigstore.json

release:
  mode: append
  name_template: "v{{ .Version }}"

changelog:
  disable: true

snapshot:
  version_template: '{{ .Version }}-next'
```

Four deliberate choices, do not "improve" them:
- **No `-X` version ldflags.** `cmd/sigstore-kms-yckms/main.go` rejects any `argv[1]` other than `v1`, so there is no `--version` path to stamp. An injected variable would be unreferenced and fight `gochecknoglobals` in PR 2.
- **`binary: sigstore-kms-yckms`** is explicit and load-bearing. Sigstore plugin discovery resolves plugins by filename on `PATH`, so the file inside each archive must carry exactly this name.
- **`release: mode: append`** — go-semantic-release creates the GitHub release first; GoReleaser adds assets to it rather than creating its own.
- **`changelog: disable: true`** — semantic-release owns release notes.

- [ ] **Step 2: Delete the old config**

```bash
git rm goreleaser.yml
```

- [ ] **Step 3: Verify the config parses**

```bash
.tool/goreleaser check
```

Expected: `1 configuration file(s) validated` with no errors. Deprecation warnings about `formats` vs `format` mean the pinned GoReleaser is older than expected — stop and report rather than reverting to the singular key.

- [ ] **Step 4: Build a full snapshot release locally**

```bash
task snapshot
```

Expected: exit 0. This exercises builds, archives, checksums, and SBOM generation. Signing is skipped in snapshot mode because there is no OIDC token — that is expected.

- [ ] **Step 5: Verify the artifact set and the binary name inside an archive**

```bash
ls dist/*.tar.gz dist/*.zip dist/*checksums.txt dist/*.sbom.json 2>/dev/null
tar -tzf dist/sigstore-kms-yckms_*_linux_amd64.tar.gz
```

Expected: six archives (linux/darwin/windows × amd64/arm64, zip for the two Windows ones), one checksums file, and one SBOM per archive. The `tar -tzf` listing MUST include a top-level entry named exactly `sigstore-kms-yckms`, plus `LICENSE` and `README.md`. If the binary has any other name, fix `binary:` before continuing — this is the failure that breaks plugin discovery for every user.

- [ ] **Step 6: Verify the snapshot output did not dirty the tree**

```bash
task verify-no-diff
```

Expected: no output. If `dist/` shows up, Task 2's `.gitignore` edit is missing.

- [ ] **Step 7: Commit**

```bash
git add .goreleaser.yaml
git commit -m "feat: build signed multi-platform release artifacts

Replaces the single unsigned linux/amd64 binary with linux, darwin and
windows on amd64 and arm64, packaged as tar.gz (zip on windows) with
sha256 checksums, a syft SBOM per archive, and a keyless cosign
sign-blob signature over the checksum file.

The archived binary is explicitly named sigstore-kms-yckms because
sigstore resolves KMS plugins by filename on PATH."
```

---

### Task 7: Release workflow

**Files:**
- Create: `.github/workflows/release.yml`
- Modify: `README.md`

**Interfaces:**
- Consumes: `.goreleaser.yaml` from Task 6; the absence of a tag trigger in `ci.yml` from Task 3.
- Produces: the published release flow. Nothing later consumes it.

- [ ] **Step 1: Confirm the current latest tag, which determines the next version**

```bash
git tag --sort=-v:refname | head -3
```

Expected: `v0.1.0` at the top. This matters for the next step: without `allow-initial-development-versions`, go-semantic-release treats the first `feat:` after v0.1.0 as v1.0.0 rather than v0.2.0.

- [ ] **Step 2: Create `.github/workflows/release.yml`**

```yaml
name: Release

on:
  push:
    branches: [main]

permissions: {}

concurrency:
  group: release
  cancel-in-progress: false

jobs:
  semver:
    name: Determine version
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: write
    outputs:
      version: ${{ steps.semver.outputs.version }}
    steps:
      - name: Harden Runner
        uses: step-security/harden-runner@b09bb98e06d4d774595224525879c09bc6e98c40 # v2.20.1
        with:
          egress-policy: audit

      - name: Checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false

      - name: Run go-semantic-release
        id: semver
        uses: go-semantic-release/action@2e9dc4247a6004f8377781bef4cb9dad273a741f # v1.24.1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          allow-initial-development-versions: true

  goreleaser:
    name: Publish release
    runs-on: ubuntu-latest
    timeout-minutes: 30
    needs: semver
    if: needs.semver.outputs.version != ''
    permissions:
      contents: write
      id-token: write
      attestations: write
    steps:
      - name: Harden Runner
        uses: step-security/harden-runner@b09bb98e06d4d774595224525879c09bc6e98c40 # v2.20.1
        with:
          egress-policy: audit

      - name: Checkout release tag
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          ref: v${{ needs.semver.outputs.version }}
          persist-credentials: false

      - name: Install Go
        uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version-file: go.mod

      - name: Install cosign
        uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2

      - name: Install syft
        uses: anchore/sbom-action/download-syft@e22c389904149dbc22b58101806040fa8d37a610 # v0.24.0

      - name: Run GoReleaser
        uses: goreleaser/goreleaser-action@f06c13b6b1a9625abc9e6e439d9c05a8f2190e94 # v7.2.3
        with:
          version: "~> v2"
          args: release --clean
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Attest build provenance
        uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2
        with:
          subject-path: |
            dist/*.tar.gz
            dist/*.zip
            dist/*_checksums.txt
```

Three things that fail only at release time, in public, if changed:
- `id-token: write` is required for keyless cosign **and** for provenance attestation. The old release job lacked it.
- `attestations: write` is required by `attest-build-provenance`.
- `allow-initial-development-versions: true` keeps the project in `0.x`. Removing it publishes v1.0.0 on the next `feat:`.

`concurrency: cancel-in-progress: false` is deliberate: cancelling a half-published release is worse than queueing.

- [ ] **Step 3: Verify the workflow lints**

```bash
task validate-actions
```

Expected: clean across all eight workflows.

- [ ] **Step 4: Add a release-verification section to `README.md`**

Insert after the `## Install` section:

````markdown
## Verifying releases

Release archives carry a keyless [cosign](https://github.com/sigstore/cosign)
signature over the checksum file, plus SLSA build provenance.

Verify the checksums:

```sh
cosign verify-blob \
  --bundle sigstore-kms-yckms_<version>_checksums.txt.sigstore.json \
  --certificate-identity-regexp 'https://github.com/franchb/sigstore-kms-yckms/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  sigstore-kms-yckms_<version>_checksums.txt
```

Then verify an archive against those checksums, and its build provenance:

```sh
sha256sum --check --ignore-missing sigstore-kms-yckms_<version>_checksums.txt
gh attestation verify sigstore-kms-yckms_<version>_linux_amd64.tar.gz \
  --repo franchb/sigstore-kms-yckms
```

Each archive also ships a [syft](https://github.com/anchore/syft) SBOM alongside it.
````

- [ ] **Step 5: Verify the full gate**

```bash
make check-ci
```

Expected: `CI checks passed`.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/release.yml README.md
git commit -m "feat: publish releases via go-semantic-release and GoReleaser

Merges to main derive a version from conventional-commit subjects, tag
it, then build, sign and attest artifacts for that tag.

Grants id-token: write for keyless cosign and attestations: write for
SLSA provenance, and sets allow-initial-development-versions so the
project stays on 0.x rather than jumping to v1.0.0.

Documents cosign verify-blob and gh attestation verify in the README."
```

- [ ] **Step 7: Open PR 1**

```bash
git push -u origin feat/ci-and-publishing
gh pr create --title "ci: harden CI and add signed release publishing" --body "$(cat <<'BODY'
Implements Phases 1, 3, 4 and 5 of
`docs/superpowers/specs/2026-08-18-ci-and-publishing-design.md`.

- Dependencies upgraded; Go 1.26.0 directive + 1.26.6 toolchain
- Tool pins refreshed; goreleaser, actionlint, zizmor added to binny
- CI hardened: SHA pins, minimal permissions, harden-runner, timeouts
- macOS/Windows unit-test job added
- CodeQL, Scorecard, dependency review, zizmor, scheduled govulncheck
- Dependabot + conventional-commit PR title check
- Signed, attested, multi-platform releases via semantic-release + GoReleaser

Phase 2 (linter adoption) ships separately.

**Note:** merging this arms release.yml. The first `feat:`/`fix:` merge
after it will publish v0.2.0.
BODY
)"
```

Expected: all eight workflows green. If the release workflow runs on this merge, it should produce no release — the commits are `chore:`/`ci:`/`feat:` mixed, so confirm the version bump is what you intend before merging.

---

# PR 2 — Linter adoption

Start from a fresh branch off updated `main`:

```bash
git checkout main && git pull
git checkout -b refactor/adopt-strict-linters
```

### Task 8: Adopt the strict linter configuration

**Files:**
- Modify: `.golangci.yml` (full replacement, sourced from `../embedded-clickhouse/.golangci.yml`)
- Modify: `Taskfile.yaml`

**Interfaces:**
- Consumes: nothing.
- Produces: a red `task lint`. Tasks 9–12 drive it to green. No Go symbols.

- [ ] **Step 1: Copy the source configuration**

```bash
cp ../embedded-clickhouse/.golangci.yml .golangci.yml
```

If that path does not exist, the file is `.golangci.yml` at the root of `github.com/franchb/embedded-clickhouse`.

- [ ] **Step 2: Re-point the repo-specific settings**

Apply these four edits to `.golangci.yml`. Everything else in the file is correct as copied.

Under `linters.settings.exhaustruct.exclude`, replace the three `embedded-clickhouse` entries with:

```yaml
    exhaustruct:
      exclude:
        # stdlib types where partial init is idiomatic.
        - '.*\.Client$'
        - '.*\.Server$'
        - '.*syscall\.SysProcAttr$'
        # Anonymous structs (table-driven test cases).
        - '.*<anonymous>$'
        # Internal types built up field-by-field or relying on zero values.
        - '.*yckms\.ycKmsClient$'
        - '.*yckms\.SignerVerifier$'
        - '.*ycsdk\.Config$'
```

Under `linters.settings.testpackage`:

```yaml
    testpackage:
      allow-packages:
        - yckms
```

Replace the whole `linters.settings.gosec` block with an empty exclusion list. ec's exclusions (G301, G302, G306, G304, G204, G115, G104, G704) exist because it downloads, extracts and executes binaries; none of that happens here:

```yaml
    gosec:
      excludes: []
```

Add an `ireturn` allow-list. `credentials()` in `pkg/yckms/credentials.go` returns `ycsdk.Credentials`, which is an interface by the SDK's design:

```yaml
    ireturn:
      allow:
        - error
        - empty
        - stdlib
        - github.com/yandex-cloud/go-sdk.Credentials
```

Replace ec's `varnamelen.ignore-names` list with this repo's short names:

```yaml
    varnamelen:
      min-name-length: 2
      ignore-names:
        - y
        - c
        - ok
        - tt
        - op
```

- [ ] **Step 3: Stop excluding tests from linting in `Taskfile.yaml`**

In the `lint` task, change:

```
      - "{{ .TOOL_DIR }}/golangci-lint run --tests=false"
```

to:

```
      - "{{ .TOOL_DIR }}/golangci-lint run"
```

And in the `lint-fix` task, change:

```
      - "{{ .TOOL_DIR }}/golangci-lint run --tests=false --fix"
```

to:

```
      - "{{ .TOOL_DIR }}/golangci-lint run --fix"
```

The `--tests=false` flag contradicted `.golangci.yml`'s `tests: true` and hid every finding in `_test.go`. ec's config already relaxes `gosec`, `errcheck`, `cyclop`, `forcetypeassert`, `noctx` and `lll` for test files.

- [ ] **Step 4: Record the baseline**

```bash
.tool/golangci-lint run ./... 2>&1 | tee /tmp/lint-baseline.txt | grep -oE '\(([a-z_0-9]+)\)$' | sort | uniq -c | sort -rn
```

Expected, approximately (exact counts may shift slightly with the dependency versions from Task 1):

```
     12 (err113)
     10 (exhaustruct)
      9 (wrapcheck)
      3 (protogetter)
      3 (nolintlint)
      3 (lll)
      3 (errcheck)
      2 (mnd)
      2 (gochecknoglobals)
      1 (testpackage)
      1 (nonamedreturns)
      1 (ireturn)
      1 (cyclop)
```

Total ~51. If it is dramatically larger (say >150), the config edits in Step 2 did not apply — re-check before proceeding.

If `ireturn` still reports `credentials()`, the allow-list entry in Step 2 is wrong; fix it here rather than in Task 12.

- [ ] **Step 5: Verify tests still pass and commit the red baseline**

```bash
go test ./...
```

Expected: both packages `ok`. Linting is red; tests are not.

```bash
git add .golangci.yml Taskfile.yaml
git commit -m "ci: adopt the strict golangci-lint configuration

Ports embedded-clickhouse's ~90-linter config, re-pointed at this repo's
types, and stops passing --tests=false, which contradicted the config's
tests: true and hid every finding in _test.go.

Lint is red until the follow-up commits in this branch; tests pass
throughout."
```

---

### Task 9: Extract the verifier constructor and add sentinel errors

The largest task. It creates `pkg/yckms/errors.go`, collapses six near-identical `switch` arms in `getYcSignatureKey` into one helper, and resolves `err113` ×10 plus `cyclop` ×1 plus `exhaustruct` ×1 in one coherent change.

`gochecknoglobals` permits `var` blocks whose type is `error` and whose name starts with `err`/`Err`, so the sentinels themselves will not be flagged.

**Files:**
- Create: `pkg/yckms/errors.go`
- Modify: `pkg/yckms/client.go`
- Modify: `pkg/yckms/reference.go`
- Modify: `pkg/yckms/signer.go`
- Test: `pkg/yckms/errors_test.go`

**Interfaces:**
- Consumes: the red baseline from Task 8.
- Produces:
  - `pkg/yckms/errors.go` exporting `ErrKMSReference`, `ErrPublicKeyNotRSA`, `ErrPublicKeyNotECDSA`, `ErrUnsupportedAlgorithm`, `ErrUnknownAlgorithm`, `ErrCreateKeyReference`, `ErrNoCredentials` and unexported `errUninitializedSignerVerifier`, `errSignatureKeyCacheEmpty`, `errUnexpectedCreateKeyResponse` — all of type `error`.
  - `func verifierForAlgorithm(alg asymkms.AsymmetricSignatureAlgorithm, pubKey crypto.PublicKey) (signature.Verifier, crypto.Hash, error)` in `client.go`, used only by `getYcSignatureKey`.
  - Task 10 wraps errors returned by these paths; Task 12 leaves them alone.

- [ ] **Step 1: Write the failing test**

Create `pkg/yckms/errors_test.go`:

```go
//
// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package yckms //nolint:testpackage // exercises unexported sentinels and verifierForAlgorithm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	asymkms "github.com/yandex-cloud/go-genproto/yandex/cloud/kms/v1/asymmetricsignature"
)

func TestVerifierForAlgorithmRejectsMismatchedKeyType(t *testing.T) {
	t.Parallel()

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}

	// An RSA algorithm with an ECDSA key must report ErrPublicKeyNotRSA.
	_, _, err = verifierForAlgorithm(
		asymkms.AsymmetricSignatureAlgorithm_RSA_2048_SIGN_PSS_SHA_256,
		ecdsaKey.Public(),
	)
	if !errors.Is(err, ErrPublicKeyNotRSA) {
		t.Fatalf("verifierForAlgorithm() error = %v, want ErrPublicKeyNotRSA", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	// An ECDSA algorithm with an RSA key must report ErrPublicKeyNotECDSA.
	_, _, err = verifierForAlgorithm(
		asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P256_SHA_256,
		rsaKey.Public(),
	)
	if !errors.Is(err, ErrPublicKeyNotECDSA) {
		t.Fatalf("verifierForAlgorithm() error = %v, want ErrPublicKeyNotECDSA", err)
	}
}

func TestVerifierForAlgorithmRejectsUnsupportedAlgorithm(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	_, _, err = verifierForAlgorithm(
		asymkms.AsymmetricSignatureAlgorithm_ASYMMETRIC_SIGNATURE_ALGORITHM_UNSPECIFIED,
		rsaKey.Public(),
	)
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("verifierForAlgorithm() error = %v, want ErrUnsupportedAlgorithm", err)
	}
}

func TestVerifierForAlgorithmReturnsExpectedHash(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	verifier, hashFunc, err := verifierForAlgorithm(
		asymkms.AsymmetricSignatureAlgorithm_RSA_3072_SIGN_PSS_SHA_384,
		rsaKey.Public(),
	)
	if err != nil {
		t.Fatalf("verifierForAlgorithm() unexpected error: %v", err)
	}

	if verifier == nil {
		t.Fatal("verifierForAlgorithm() returned a nil verifier")
	}

	if hashFunc != crypto.SHA384 {
		t.Fatalf("verifierForAlgorithm() hash = %v, want %v", hashFunc, crypto.SHA384)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
go test ./pkg/yckms/ -run TestVerifierForAlgorithm -v
```

Expected: FAIL — `undefined: verifierForAlgorithm`, `undefined: ErrPublicKeyNotRSA`, `undefined: ErrPublicKeyNotECDSA`, `undefined: ErrUnsupportedAlgorithm`.

- [ ] **Step 3: Create `pkg/yckms/errors.go`**

```go
//
// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package yckms

import "errors"

var (
	// ErrKMSReference is returned when a provider-stripped yckms resource ID is invalid.
	ErrKMSReference = errors.New("yckms specification should be in the format " +
		"yckms://[ENDPOINT]/KEY_ID or yckms://[ENDPOINT]/folder/FOLDER_ID/keyname/KEY_NAME; " +
		"pass resource IDs without yckms:// into pkg/yckms")

	// ErrCreateKeyReference is returned when key creation is requested without a folder and key name.
	ErrCreateKeyReference = errors.New("generate yckms key specification should be in the format " +
		"yckms://[ENDPOINT]/folder/FOLDER/keyname/KEYNAME")

	// ErrPublicKeyNotRSA is returned when the KMS reports an RSA algorithm but serves a non-RSA public key.
	ErrPublicKeyNotRSA = errors.New("public key is not RSA")

	// ErrPublicKeyNotECDSA is returned when the KMS reports an ECDSA algorithm but serves a non-ECDSA public key.
	ErrPublicKeyNotECDSA = errors.New("public key is not ECDSA")

	// ErrUnsupportedAlgorithm is returned when the KMS key uses an algorithm this package cannot verify.
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm specified by KMS")

	// ErrUnknownAlgorithm is returned when a requested algorithm name is not one of SupportedAlgorithms.
	ErrUnknownAlgorithm = errors.New("unknown algorithm requested")

	// ErrNoCredentials is returned when no Yandex Cloud credential source is configured.
	ErrNoCredentials = errors.New("no Yandex Cloud credentials configured")

	errUninitializedSignerVerifier = errors.New("yckms signer verifier is not initialized")
	errSignatureKeyCacheEmpty      = errors.New("signature key cache returned nil item")
	errUnexpectedCreateKeyResponse = errors.New("unexpected response type from yckms key create")
)
```

- [ ] **Step 4: Remove the now-duplicated declarations**

In `pkg/yckms/reference.go`, delete the `ErrKMSReference` declaration from the `var` block, leaving only the two regexps:

```go
var (
	createReferenceRE = regexp.MustCompile(`^([^/]*)/folder/([^/]+)/keyname/([^/]+)$`)
	keyIDReferenceRE  = regexp.MustCompile(`^([^/]*)/([^/]+)$`)
)
```

Then drop `"errors"` from that file's import block — it is no longer used.

In `pkg/yckms/signer.go`, delete the `errUninitializedSignerVerifier` line from the `var` block, leaving:

```go
var ycSupportedHashFuncs = []crypto.Hash{
	crypto.SHA256,
	crypto.SHA512,
	crypto.SHA384,
}
```

(`ycSupportedHashFuncs` becomes a function in Task 12; leave it a `var` for now.) Drop `"errors"` from `signer.go`'s imports if nothing else in the file uses it.

- [ ] **Step 5: Add `verifierForAlgorithm` to `pkg/yckms/client.go`**

Insert this function immediately before `getYcSignatureKey`:

```go
// verifierForAlgorithm returns a local verifier and digest algorithm for a KMS signature algorithm.
func verifierForAlgorithm(
	alg asymkms.AsymmetricSignatureAlgorithm,
	pubKey crypto.PublicKey,
) (signature.Verifier, crypto.Hash, error) {
	var hashFunc crypto.Hash

	switch alg {
	case asymkms.AsymmetricSignatureAlgorithm_RSA_2048_SIGN_PSS_SHA_256,
		asymkms.AsymmetricSignatureAlgorithm_RSA_3072_SIGN_PSS_SHA_256,
		asymkms.AsymmetricSignatureAlgorithm_RSA_4096_SIGN_PSS_SHA_256:
		hashFunc = crypto.SHA256
	case asymkms.AsymmetricSignatureAlgorithm_RSA_2048_SIGN_PSS_SHA_384,
		asymkms.AsymmetricSignatureAlgorithm_RSA_3072_SIGN_PSS_SHA_384,
		asymkms.AsymmetricSignatureAlgorithm_RSA_4096_SIGN_PSS_SHA_384:
		hashFunc = crypto.SHA384
	case asymkms.AsymmetricSignatureAlgorithm_RSA_2048_SIGN_PSS_SHA_512,
		asymkms.AsymmetricSignatureAlgorithm_RSA_3072_SIGN_PSS_SHA_512,
		asymkms.AsymmetricSignatureAlgorithm_RSA_4096_SIGN_PSS_SHA_512:
		hashFunc = crypto.SHA512
	case asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P256_SHA_256:
		return ecdsaVerifier(pubKey, crypto.SHA256)
	case asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P384_SHA_384:
		return ecdsaVerifier(pubKey, crypto.SHA384)
	case asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P521_SHA_512:
		return ecdsaVerifier(pubKey, crypto.SHA512)
	case asymkms.AsymmetricSignatureAlgorithm_ASYMMETRIC_SIGNATURE_ALGORITHM_UNSPECIFIED,
		asymkms.AsymmetricSignatureAlgorithm_ECDSA_SECP256_K1_SHA_256:
		return nil, 0, ErrUnsupportedAlgorithm
	default:
		return nil, 0, ErrUnsupportedAlgorithm
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, 0, ErrPublicKeyNotRSA
	}

	verifier, err := signature.LoadRSAPSSVerifier(rsaPubKey, hashFunc, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("initializing internal RSA-PSS verifier: %w", err)
	}

	return verifier, hashFunc, nil
}

// ecdsaVerifier returns a local ECDSA verifier for pubKey at the given digest algorithm.
func ecdsaVerifier(pubKey crypto.PublicKey, hashFunc crypto.Hash) (signature.Verifier, crypto.Hash, error) {
	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, 0, ErrPublicKeyNotECDSA
	}

	verifier, err := signature.LoadECDSAVerifier(ecdsaPubKey, hashFunc)
	if err != nil {
		return nil, 0, fmt.Errorf("initializing internal ECDSA verifier: %w", err)
	}

	return verifier, hashFunc, nil
}
```

- [ ] **Step 6: Replace the body of `getYcSignatureKey`**

Replace everything from `signatureKey := ycSignatureKey{SignatureKey: asymKey}` through the closing `return &signatureKey, nil` with:

```go
	verifier, hashFunc, err := verifierForAlgorithm(asymKey.GetSignatureAlgorithm(), pubKey)
	if err != nil {
		return nil, err
	}

	return &ycSignatureKey{
		SignatureKey: asymKey,
		Verifier:     verifier,
		HashFunc:     hashFunc,
	}, nil
```

This also resolves the `protogetter` finding at the old line 119 and the `exhaustruct` finding on `ycSignatureKey`.

- [ ] **Step 7: Replace the remaining inline `errors.New` calls in `client.go`**

- In `getSK`, `errors.New("signature key cache returned nil item")` → `errSignatureKeyCacheEmpty`
- In `createKey`, `errors.New("generate yckms key specification should be in the format ...")` → `ErrCreateKeyReference`
- In `createKey`, `errors.New("unknown algorithm requested")` → `ErrUnknownAlgorithm`
- In `createKey`, `errors.New("failed to cast response to *asymkms.AsymmetricSignatureKey")` → `errUnexpectedCreateKeyResponse`

Then drop `"errors"` from `client.go`'s import block — no call sites remain.

- [ ] **Step 8: Replace the credentials error**

In `pkg/yckms/credentials.go`, replace the final return with a wrapped sentinel:

```go
	return nil, fmt.Errorf("%w: set one of %s, %s, %s",
		ErrNoCredentials, EnvYcIAMToken, EnvYcOAuthToken, EnvYcServiceAccountKeyFile)
```

- [ ] **Step 9: Run the tests to verify they pass**

```bash
go test ./pkg/yckms/ -run TestVerifierForAlgorithm -v
go test ./...
```

Expected: the three new tests PASS, and both packages `ok`.

- [ ] **Step 10: Verify the targeted findings are gone**

```bash
.tool/golangci-lint run ./... 2>&1 | grep -cE '\(err113\)|\(cyclop\)'
```

Expected: `0`.

- [ ] **Step 11: Commit**

```bash
git add pkg/yckms/errors.go pkg/yckms/errors_test.go pkg/yckms/client.go pkg/yckms/credentials.go pkg/yckms/reference.go pkg/yckms/signer.go
git commit -m "refactor(yckms): add sentinel errors and extract verifier construction

Collects every package sentinel in errors.go and exports the ones
consumers can act on, so callers can errors.Is against key-type and
algorithm failures instead of matching strings.

Collapses six near-identical switch arms in getYcSignatureKey into
verifierForAlgorithm, which drops the function under the complexity
limit and removes the partial-struct construction."
```

---

### Task 10: Wrap errors crossing package boundaries

**Files:**
- Modify: `pkg/yckms/client.go`
- Modify: `pkg/yckms/credentials.go`
- Modify: `pkg/yckms/signer.go`

**Interfaces:**
- Consumes: the sentinels from Task 9.
- Produces: no new symbols. Error *messages* gain prefixes; the wrapped sentinels stay `errors.Is`-compatible.

- [ ] **Step 1: List the exact remaining sites**

```bash
.tool/golangci-lint run ./... 2>&1 | grep '(wrapcheck)'
```

Expected: 9 findings across `client.go` (6), `credentials.go` (1), `signer.go` (2).

- [ ] **Step 2: Wrap each site in `client.go`**

- `getYcSignatureKey`, the `...AsymmetricSignatureKey().Get(...)` error:

```go
	asymKey, err := y.client.KMSAsymmetricSignature().AsymmetricSignatureKey().Get(ctx, getRequest)
	if err != nil {
		return nil, fmt.Errorf("fetching yckms signature key %q: %w", y.keyID, err)
	}
```

- `createKey`, the `GetPublicKey` error:

```go
	pubKey, err := y.client.KMSAsymmetricSignatureCrypto().AsymmetricSignatureCrypto().GetPublicKey(ctx, getPubKeyRequest)
	if err != nil {
		return nil, fmt.Errorf("fetching public key for created yckms key: %w", err)
	}
```

- `createKey`, the trailing unmarshal:

```go
	publicKey, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(pubKey.GetPublicKey()))
	if err != nil {
		return nil, fmt.Errorf("parsing PEM public key for created yckms key: %w", err)
	}

	return publicKey, nil
```

- `verify`, the verifier call:

```go
	if err := signatureKey.Verifier.VerifySignature(sig, message, opts...); err != nil {
		return fmt.Errorf("verifying yckms signature: %w", err)
	}

	return nil
```

- `fetchPublicKey`, the `GetPublicKey` error:

```go
	pubKey, err := y.client.KMSAsymmetricSignatureCrypto().AsymmetricSignatureCrypto().GetPublicKey(ctx, getPubKeyRequest)
	if err != nil {
		return nil, fmt.Errorf("fetching yckms public key for key %q: %w", y.keyID, err)
	}
```

- `fetchPublicKey`, the trailing unmarshal:

```go
	publicKey, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(pubKey.GetPublicKey()))
	if err != nil {
		return nil, fmt.Errorf("parsing yckms PEM public key: %w", err)
	}

	return publicKey, nil
```

- [ ] **Step 3: Wrap the site in `credentials.go`**

```go
		creds, err := ycsdk.ServiceAccountKey(key)
		if err != nil {
			return nil, fmt.Errorf("building service account key credentials: %w", err)
		}

		return creds, nil
```

- [ ] **Step 4: Wrap the two sites in `signer.go`**

- In `SignMessage`, the digest computation:

```go
		digest, hashFunc, err = signature.ComputeDigestForSigning(message, hashFunc, ycSupportedHashFuncs, opts...)
		if err != nil {
			return nil, fmt.Errorf("computing digest for signing: %w", err)
		}
```

- In `PublicKey`, the verifier call:

```go
	publicKey, err := signatureKey.Verifier.PublicKey(opts...)
	if err != nil {
		return nil, fmt.Errorf("reading public key from internal verifier: %w", err)
	}

	return publicKey, nil
```

- [ ] **Step 5: Verify the findings are gone and tests pass**

```bash
.tool/golangci-lint run ./... 2>&1 | grep -c '(wrapcheck)'
go test ./...
```

Expected: `0`, then both packages `ok`.

- [ ] **Step 6: Commit**

```bash
git add pkg/yckms/client.go pkg/yckms/credentials.go pkg/yckms/signer.go
git commit -m "refactor(yckms): wrap errors crossing package boundaries

Every error from the Yandex Cloud SDK, sigstore libraries and internal
verifiers now carries context about the operation that produced it.
Wrapping preserves errors.Is against the sentinels from the previous
commit."
```

---

### Task 11: Proto getters and redundant nolint directives

**Files:**
- Modify: `pkg/yckms/client.go`
- Modify: `pkg/yckms/credentials_test.go`
- Modify: `pkg/yckms/reference_test.go`
- Modify: `pkg/yckms/signer_test.go`

**Interfaces:**
- Consumes: `testpackage.allow-packages: [yckms]` from Task 8, which is what makes the `//nolint:testpackage` directives redundant.
- Produces: no new symbols.

- [ ] **Step 1: List the remaining sites**

```bash
.tool/golangci-lint run ./... 2>&1 | grep -E '\(protogetter\)|\(nolintlint\)'
```

Expected: 2 `protogetter` (Task 9 already fixed the third) and 3 `nolintlint`.

- [ ] **Step 2: Replace direct proto field access in `client.go`**

- In `createKey`: `KeyId: key.Id` → `KeyId: key.GetId()`
- In `sign`: `return signResponse.Signature, nil` → `return signResponse.GetSignature(), nil`

- [ ] **Step 3: Remove the three redundant directives**

Delete the trailing `//nolint:testpackage // ...` comment from the `package yckms` line in each of `pkg/yckms/credentials_test.go`, `pkg/yckms/reference_test.go`, and `pkg/yckms/signer_test.go`, leaving a bare `package yckms`.

Keep the directive in `pkg/yckms/errors_test.go` from Task 9 — it is on the same allow-listed package, so if `nolintlint` flags it too, remove it there as well and re-run.

- [ ] **Step 4: Verify and test**

```bash
.tool/golangci-lint run ./... 2>&1 | grep -cE '\(protogetter\)|\(nolintlint\)'
go test ./...
```

Expected: `0`, then both packages `ok`.

- [ ] **Step 5: Commit**

```bash
git add pkg/yckms/
git commit -m "refactor(yckms): use generated proto getters and drop dead nolint directives

Direct proto field access is nil-unsafe; the generated getters are not.
The testpackage directives became redundant once the linter config
allow-listed the yckms package."
```

---

### Task 12: Remaining findings and the green gate

Closes out `lll`, `errcheck`, `mnd`, `gochecknoglobals`, `testpackage`, `nonamedreturns`, and whatever the earlier tasks shook loose. Ends with a fully green `make check-ci`.

**Files:**
- Modify: `pkg/yckms/client.go`
- Modify: `pkg/yckms/reference.go`
- Modify: `pkg/yckms/signer.go`
- Modify: `pkg/yckms/signer_test.go`
- Modify: `cmd/sigstore-kms-yckms/main.go`
- Modify: `cmd/sigstore-kms-yckms/main_test.go`

**Interfaces:**
- Consumes: everything from Tasks 8–11.
- Produces: `func algorithmMap() map[string]asymkms.AsymmetricSignatureAlgorithm` and `func ycSupportedHashFuncs() []crypto.Hash`, replacing the same-named package variables. Every call site becomes a call: `algorithmMap()[algorithm]`, `len(algorithmMap())`, `range algorithmMap()`, `ycSupportedHashFuncs()`.

- [ ] **Step 1: List what is left**

```bash
.tool/golangci-lint run ./... 2>&1 | grep -E '\.go:[0-9]+:'
```

Work through everything reported. The steps below cover the known baseline; if a finding appears that is not listed here, fix it in the same spirit and note it in the commit body.

- [ ] **Step 2: Name the two magic numbers**

Do this before Step 3, which uses `minPluginArgs`.

In `cmd/sigstore-kms-yckms/main.go`, replace the lone `expectedProtocolVersion` const with:

```go
const (
	expectedProtocolVersion = "v1"

	// minPluginArgs is the argv length required to carry a protocol version.
	minPluginArgs = 2
)
```

In `pkg/yckms/client.go`, above `getSK`:

```go
// signatureKeyTTL bounds how long a fetched KMS signature key is cached.
const signatureKeyTTL = 5 * time.Minute
```

and change the loader body to `return cache.Set(key, *signatureKey, signatureKeyTTL)`.

- [ ] **Step 3: Handle the three unchecked `handler.WriteErrorResponse` returns in `cmd/sigstore-kms-yckms/main.go`**

The plugin protocol writes its error response to stdout and exits non-zero. If that write itself fails there is nowhere left to report it, so the correct handling is an explicit discard with a reason. Add this helper and route all three sites through it:

```go
// writeError reports err over the plugin protocol on stdout and exits non-zero.
// A failed write is unreportable — stdout is the only channel the protocol has.
func writeError(err error) {
	_ = handler.WriteErrorResponse(os.Stdout, err)

	os.Exit(1)
}
```

Then replace each of the three pairs:

```go
	if len(os.Args) < minPluginArgs {
		writeError(errors.New("missing protocol version"))
	}

	if protocolVersion := os.Args[1]; protocolVersion != expectedProtocolVersion {
		writeError(fmt.Errorf("expected protocol version %s, got %s", expectedProtocolVersion, protocolVersion))
	}

	pluginArgs, err := handler.GetPluginArgs(os.Args)
	if err != nil {
		writeError(err)
	}

	signerVerifier, err := yckms.LoadSignerVerifier(context.Background(), pluginArgs.InitOptions.KeyResourceID)
	if err != nil {
		writeError(err)
	}
```

- [ ] **Step 4: Fill in the one struct the config excludes do not cover**

`exhaustruct` flags `kms.CreateAsymmetricSignatureKeyRequest` in `createKey`. Unlike `ycKmsClient`, `SignerVerifier` and `ycsdk.Config`, this is not an internal type built up field by field, so it gets explicit fields rather than a config exclusion:

```go
	createKeyRequest := &asymkms.CreateAsymmetricSignatureKeyRequest{
		SignatureAlgorithm: signatureAlgorithm,
		FolderId:           y.folderID,
		Name:               y.keyName,
		Description:        "Created by sigstore",
		Labels:             nil,
		DeletionProtection: false,
	}
```

Do not add this type to `exhaustruct.exclude` — stating the defaults explicitly is the point for a request sent to a remote API.

- [ ] **Step 5: Convert the two flagged globals to functions**

In `pkg/yckms/client.go`, change `var algorithmMap = map[string]...{...}` to:

```go
// algorithmMap maps this package's algorithm names to Yandex Cloud KMS algorithms.
func algorithmMap() map[string]asymkms.AsymmetricSignatureAlgorithm {
	return map[string]asymkms.AsymmetricSignatureAlgorithm{
		AlgorithmECDSANISTP256SHA256:  asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P256_SHA_256,
		AlgorithmECDSANISTP384SHA384:  asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P384_SHA_384,
		AlgorithmECDSANISTP521SHA512:  asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P521_SHA_512,
		AlgorithmRSA2048SignPSSSHA256: asymkms.AsymmetricSignatureAlgorithm_RSA_2048_SIGN_PSS_SHA_256,
		AlgorithmRSA2048SignPSSSHA384: asymkms.AsymmetricSignatureAlgorithm_RSA_2048_SIGN_PSS_SHA_384,
		AlgorithmRSA2048SignPSSSHA512: asymkms.AsymmetricSignatureAlgorithm_RSA_2048_SIGN_PSS_SHA_512,
		AlgorithmRSA3072SignPSSSHA256: asymkms.AsymmetricSignatureAlgorithm_RSA_3072_SIGN_PSS_SHA_256,
		AlgorithmRSA3072SignPSSSHA384: asymkms.AsymmetricSignatureAlgorithm_RSA_3072_SIGN_PSS_SHA_384,
		AlgorithmRSA3072SignPSSSHA512: asymkms.AsymmetricSignatureAlgorithm_RSA_3072_SIGN_PSS_SHA_512,
		AlgorithmRSA4096SignPSSSHA256: asymkms.AsymmetricSignatureAlgorithm_RSA_4096_SIGN_PSS_SHA_256,
		AlgorithmRSA4096SignPSSSHA384: asymkms.AsymmetricSignatureAlgorithm_RSA_4096_SIGN_PSS_SHA_384,
		AlgorithmRSA4096SignPSSSHA512: asymkms.AsymmetricSignatureAlgorithm_RSA_4096_SIGN_PSS_SHA_512,
	}
}
```

In `pkg/yckms/signer.go`, change the `ycSupportedHashFuncs` var to:

```go
// ycSupportedHashFuncs lists the digest algorithms Yandex Cloud KMS signing supports.
func ycSupportedHashFuncs() []crypto.Hash {
	return []crypto.Hash{
		crypto.SHA256,
		crypto.SHA512,
		crypto.SHA384,
	}
}
```

Update all five call sites — these are the complete set, verified by grep:

- `client.go` in `createKey`: `algorithmMap[algorithm]` → `algorithmMap()[algorithm]`
- `signer.go` in `SupportedAlgorithms`: `make([]string, 0, len(algorithmMap))` → `make([]string, 0, len(algorithmMap()))`, and `for algorithm := range algorithmMap` → `for algorithm := range algorithmMap()`
- `signer.go` in `SignMessage`: `ycSupportedHashFuncs` → `ycSupportedHashFuncs()`
- `signer_test.go` lines ~77–83: `len(ycSupportedHashFuncs)` → `len(ycSupportedHashFuncs())` and `ycSupportedHashFuncs[index]` → `ycSupportedHashFuncs()[index]`

- [ ] **Step 6: Drop the named returns in `reference.go`**

```go
// ParseReference parses a provider-stripped yckms resource ID into endpoint and key creation fields.
func ParseReference(reference string) (string, string, string, string, error) {
```

The function's `return` statements already supply all five values positionally, so no body changes are needed.

- [ ] **Step 7: Move `cmd` tests to an external test package**

Change the package line in `cmd/sigstore-kms-yckms/main_test.go` from `package main` to `package main_test`. If any test references an unexported identifier from `main.go`, the compile will fail — in that case revert this file to `package main` and add `main` to `testpackage.allow-packages` in `.golangci.yml` instead.

- [ ] **Step 8: Wrap the three over-length lines**

Reformat the lines `lll` reports (originally `client.go:243`, `reference.go:37`, `signer.go:189`; line numbers will have shifted). For example, the `WrapOperation` call in `createKey`:

```go
	createResponse := y.client.KMSAsymmetricSignature().AsymmetricSignatureKey().Create(ctx, createKeyRequest)

	op, err := y.client.WrapOperation(createResponse)
	if err != nil {
		return nil, fmt.Errorf("yckms key create error: %w", err)
	}
```

`reference.go:37` is the `ErrKMSReference` string, already wrapped across three lines by Task 9 — confirm it no longer reports.

- [ ] **Step 9: Format, then verify the gate is fully green**

```bash
task format
.tool/golangci-lint run ./...
go test ./...
```

Expected: `golangci-lint` produces **no output** and exits 0; both packages `ok`.

- [ ] **Step 10: Run the complete CI gate**

```bash
make check-ci
```

Expected: ends with `CI checks passed`. This is the gate for the whole PR — do not commit until it passes.

- [ ] **Step 11: Commit**

```bash
git add pkg/yckms/ cmd/sigstore-kms-yckms/
git commit -m "refactor: resolve remaining strict-linter findings

Names magic numbers, converts the algorithm map and supported-hash list
from package variables to functions, drops named returns from
ParseReference, moves cmd tests to an external test package, wraps long
lines, and routes plugin error responses through a single writeError
helper that documents why a failed stdout write is unreportable.

golangci-lint is now clean under the strict configuration."
```

- [ ] **Step 12: Open PR 2**

```bash
git push -u origin refactor/adopt-strict-linters
gh pr create --title "refactor: adopt strict linter configuration" --body "$(cat <<'BODY'
Implements Phase 2 of
`docs/superpowers/specs/2026-08-18-ci-and-publishing-design.md`.

Adopts embedded-clickhouse's ~90-linter golangci-lint configuration and
resolves the ~51 resulting findings.

The substantive change is error handling: `pkg/yckms` now exports
sentinel errors (`ErrPublicKeyNotRSA`, `ErrUnsupportedAlgorithm`,
`ErrNoCredentials`, …) that consumers can `errors.Is` against, where it
previously raised every error inline via `errors.New`. Errors crossing
into the package from the Yandex Cloud SDK and sigstore libraries are
now wrapped with operation context.

`getYcSignatureKey` loses six near-identical switch arms to a new
`verifierForAlgorithm` helper, with unit tests covering key-type
mismatch and unsupported-algorithm paths.

No behavioural change beyond error messages gaining context.
BODY
)"
```

---

## Verification Summary

| Task | Verification command | Expected |
| --- | --- | --- |
| 1 | `go build ./... && go test ./...` | build silent, both packages `ok` |
| 2 | `.tool/goreleaser --version && .tool/actionlint --version && .tool/zizmor --version` | all three report versions |
| 3 | `.tool/actionlint && make check-ci` | silent, then `CI checks passed` |
| 4 | `task validate-actions && make check-ci` | zizmor+actionlint clean, `CI checks passed` |
| 5 | `task validate-actions` | clean, no dangerous-checkout finding |
| 6 | `task snapshot && tar -tzf dist/*linux_amd64.tar.gz` | 6 archives + SBOMs; inner binary named `sigstore-kms-yckms` |
| 7 | `task validate-actions && make check-ci` | clean, `CI checks passed` |
| 8 | `.tool/golangci-lint run ./...` | ~51 findings (intentionally red); `go test ./...` passes |
| 9 | `go test ./pkg/yckms/ -run TestVerifierForAlgorithm -v` | 3 tests PASS; 0 `err113`/`cyclop` findings |
| 10 | `.tool/golangci-lint run ./... \| grep -c '(wrapcheck)'` | `0` |
| 11 | `.tool/golangci-lint run ./... \| grep -cE '(protogetter)\|(nolintlint)'` | `0` |
| 12 | `make check-ci` | `CI checks passed`, golangci-lint silent |

## Post-Merge Verification

The one thing no local step can exercise is keyless signing, which needs a real OIDC token. After the first release publishes:

```bash
gh release download v<version> --pattern '*checksums*'
cosign verify-blob \
  --bundle sigstore-kms-yckms_<version>_checksums.txt.sigstore.json \
  --certificate-identity-regexp 'https://github.com/franchb/sigstore-kms-yckms/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  sigstore-kms-yckms_<version>_checksums.txt

gh release download v<version> --pattern '*linux_amd64.tar.gz'
gh attestation verify sigstore-kms-yckms_<version>_linux_amd64.tar.gz \
  --repo franchb/sigstore-kms-yckms
```

Both must succeed before announcing the release. Also confirm the published version is `v0.2.0` and not `v1.0.0` — if it is the latter, `allow-initial-development-versions` did not take effect.
