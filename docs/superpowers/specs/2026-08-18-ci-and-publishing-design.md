# CI Hardening and Release Publishing — Design

Date: 2026-08-18
Status: Approved

## Context

`sigstore-kms-yckms` ships two things: `pkg/yckms`, an importable Go package implementing
`kms.SignerVerifier`, and `cmd/sigstore-kms-yckms`, a Sigstore CLI KMS plugin. Today it has a
single-job `ci.yml` and a four-stanza `goreleaser.yml` that produces one unsigned `linux/amd64`
binary. For a project inside the Sigstore ecosystem, shipping unsigned release artifacts is the
gap that matters most.

Two sibling repositories set the target. `franchb/embedded-clickhouse` supplies the CI and
supply-chain security model: CodeQL, OSSF Scorecard, dependency review, zizmor action linting,
Dependabot, SHA-pinned actions, and a maximalist `.golangci.yml`. `kypello-io/kc` supplies the
publishing model: go-semantic-release driving GoReleaser, cosign signing, and SBOM generation.

The two repositories disagree on where CI logic lives. `embedded-clickhouse` is workflow-native:
jobs carry inline steps and their own tool pins, which have already drifted — its `vuln.yml`
installs `govulncheck@v1.1.4` while its `.binny.yaml` pins `v1.3.0`. This repository is
anchore-style: `.binny.yaml` pins every tool, `Taskfile.yaml` owns the `check-ci` target, and CI
is a thin caller. **This design keeps the Taskfile as the single source of truth** and adds
workflows only for work Task genuinely cannot do — scheduled runs, GitHub-hosted analyses, and
release publishing. Every tool version continues to live in `.binny.yaml`.

## Goals

1. Upgrade all dependencies and move to Go 1.26.6.
2. Adopt `embedded-clickhouse`'s linter configuration and fix the resulting findings.
3. Add supply-chain and security CI without creating a second source of truth for tool versions.
4. Publish signed, attested, multi-platform releases driven by go-semantic-release.
5. Make every new workflow verifiable locally, so the first tag push is not the first test.

## Non-Goals

- OS packages (`nfpm` deb/rpm/apk). A cosign KMS plugin is placed on `PATH`, not installed via a
  package manager.
- Container images (`ko`). Reconsider if signing-inside-containers becomes a real use case.
- Unrelated refactoring of `pkg/yckms` beyond what the linter configuration requires.

## Phase 1 — Dependencies and Go version

Verified end to end on a scratch copy: `go get -u ./... && go mod tidy && go build ./... &&
go test ./...` passes with **zero source changes**. The `yandex-cloud/go-genproto` jump of 69
minor versions was the risk and it lands clean.

Direct dependencies:

| Module | From | To |
| --- | --- | --- |
| `github.com/jellydator/ttlcache/v3` | v3.4.0 | v3.4.1 |
| `github.com/sigstore/sigstore` | v1.10.8 | v1.10.9 |
| `github.com/yandex-cloud/go-genproto` | v0.44.0 | v0.113.0 |
| `github.com/yandex-cloud/go-sdk` | v0.30.0 | v0.33.0 |
| `google.golang.org/grpc` | v1.78.0 | v1.83.0 |

Indirects move accordingly: `go-containerregistry` v0.20.7→v0.21.9, `sigstore/protobuf-specs`
v0.5.0→v0.5.1, `protobuf` v1.36.11→v1.36.12, the `golang.org/x/*` set, and the `genproto` triple to
`v0.0.0-20260817212433-ac3dfec99bb1`.

### Go directive shape

`go.mod` becomes:

```
go 1.26.0

toolchain go1.26.6
```

Not `go 1.26.6`. `pkg/yckms` is a published library, and a patch-level `go` directive forces every
consumer onto a toolchain ≥1.26.6 or a toolchain download. The `toolchain` line carries the same
"build with 1.26.6" meaning without that cost. This also matches sibling convention:
`embedded-clickhouse` is `go 1.25.0`, `kc` is `go 1.26.0`. Go 1.26.6 is confirmed published on the
toolchain module proxy.

Workflows read the version via `go-version-file: go.mod`, replacing the hardcoded `'1.26.3'` that
appears twice in today's `ci.yml`.

### Tool pins

`.binny.yaml` updates:

- `govulncheck`: v1.3.0 → **v1.7.0** (stale by four minor versions).
- Run `task update-tools` to refresh `binny`, `task`, `golangci-lint`, `gosimports`, and
  `betteralign` to current releases, then commit the resulting `.binny.yaml`.

## Phase 2 — Maximalist linter configuration

This is the only phase that modifies Go source. It ships as its own pull request.

### Configuration

Replace `.golangci.yml` with `embedded-clickhouse`'s (~90 linters, `version: "2"`, `gofumpt`
formatter), re-pointed at this repository:

- `exhaustruct.exclude`: replace the `embedded-clickhouse.*` entries with
  `.*yckms\.ycKmsClient$`, `.*yckms\.SignerVerifier$`, `.*ycsdk\.Config$`, keeping
  `.*<anonymous>$` for table-driven test cases.
- `testpackage.allow-packages`: `[yckms]`.
- `gosec.excludes`: trim ec's list. G301/G302/G306/G304/G204/G704 exist because ec downloads and
  extracts binaries and launches subprocesses; none of that happens here. Start with an empty
  exclusion list and add back only what an actual run demands.
- `varnamelen.ignore-names`: derive from this repository's identifiers, not ec's.
- `depguard` denying `log`: retained. Neither package imports `log` today.

### Task and config alignment

`Taskfile.yaml` currently runs `golangci-lint run --tests=false` while `.golangci.yml` declares
`tests: true`. That contradiction hides all findings in `_test.go` files. Remove `--tests=false`
from both the `lint` and `lint-fix` tasks and rely on ec's `_test.go` exclusion rules, which
already relax `gosec`, `errcheck`, `cyclop`, `forcetypeassert`, `noctx`, and `lll` for tests.

### Measured impact

Measured with the pinned `golangci-lint v2.12.2` against the Phase 1 dependency set, tests
included: **51 findings** across 1005 lines.

| Linter | Count | Resolution |
| --- | --- | --- |
| `err113` | 12 | Package-level sentinel errors, wrapped at raise sites |
| `exhaustruct` | 10 | Config excludes cover `ycKmsClient`, `SignerVerifier`, `ycsdk.Config`; `ycSignatureKey` and `kms.CreateAsymmetricSignatureKeyRequest` get explicit zero fields |
| `wrapcheck` | 9 | `fmt.Errorf("...: %w", err)` at external-package boundaries |
| `protogetter` | 3 | `GetSignatureAlgorithm()`, `GetId()`, `GetSignature()` — autofixable |
| `nolintlint` | 3 | Remove `//nolint:testpackage` directives made redundant by `allow-packages` |
| `lll` | 3 | Wrap lines in `client.go:243`, `reference.go:37`, `signer.go:189` |
| `errcheck` | 3 | Handle `handler.WriteErrorResponse` returns in `cmd/.../main.go` |
| `mnd` | 2 | Named constants for `main.go:31` and `client.go:207` |
| `gochecknoglobals` | 2 | Convert `algorithmMap` and `ycSupportedHashFuncs` to functions returning the value |
| `testpackage` | 1 | Move `cmd/.../main_test.go` to `package main_test` |
| `nonamedreturns` | 1 | `reference.go:53` — drop the named return `endpoint` |
| `ireturn` | 1 | `credentials()` returns `ycsdk.Credentials`; add that type to `ireturn.allow` |
| `cyclop` | 1 | `getYcSignatureKey` complexity 17 vs max 16 |

The `err113` work is the most valuable outcome: `pkg/yckms` currently raises every error via
`errors.New` at the call site, so consumers cannot `errors.Is` against anything. Exporting
sentinels such as `ErrPublicKeyNotRSA`, `ErrPublicKeyNotECDSA`, and `ErrUnsupportedAlgorithm`
turns this into a usable library API. These are additive and do not break existing consumers.

Where a finding is genuinely a false positive for this codebase, prefer a scoped configuration
exclusion over an inline `//nolint` — `nolintlint` is enabled and will flag unused directives.

## Phase 3 — CI hardening

### `ci.yml`

The `check-ci` job remains a thin caller of `make check-ci`; the Taskfile stays the gate.
Hardening applied to every job in every workflow in this design:

- `permissions: {}` at workflow level, minimal explicit grants per job
- Every `uses:` pinned to a full commit SHA with a trailing `# vX.Y.Z` comment
- `actions/checkout` with `persist-credentials: false`
- `step-security/harden-runner` with `egress-policy: audit` on Linux runners
- `timeout-minutes` on every job
- A concurrency group with `cancel-in-progress` keyed on workflow and ref

Job structure:

- **`check-ci`** — `ubuntu-latest` only. It shells out to `/bin/bash ci/scripts/diff.sh` and
  `ci/scripts/coverage.py`; making that portable to Windows is work this design does not fund.
- **`test`** — matrix over `macos-latest` and `windows-latest`, running `go test -race -count=1
  ./...` directly. Windows coverage matters because Phase 4 ships Windows binaries.

No `oldstable` matrix leg. With a `1.26` directive, `oldstable` resolves to 1.25 and fails
outright; `embedded-clickhouse` can run that matrix only because its directive is `1.25.0`.

**The `tags: 'v*'` push trigger and the entire `release` job are deleted from `ci.yml`.** Phase 4
moves release to its own workflow; leaving the tag trigger in place would make semantic-release's
tag fire a second, competing release.

### New workflows

Ported from `embedded-clickhouse`, each doing something Task cannot:

| File | Purpose |
| --- | --- |
| `codeql.yml` | CodeQL Go analysis on push, PR, and weekly cron |
| `scorecards.yml` | OSSF Scorecard with SARIF upload to code scanning |
| `dependency-review.yml` | Blocks PRs introducing vulnerable dependencies |
| `validate-github-actions.yaml` | zizmor lint over `.github`, with `.github/zizmor.yml` |
| `vuln.yml` | **Scheduled-only** govulncheck |

`vuln.yml` runs `make govulncheck`, using the `.binny.yaml` pin. It deliberately does *not* copy
ec's inline `go install golang.org/x/vuln/cmd/govulncheck@v1.1.4`, which is the exact pin-drift
this design exists to avoid. It carries no push or pull_request trigger, because `check-ci`
already runs govulncheck on every change; the schedule exists to catch newly published advisories
against unchanged code.

### Dependabot

`.github/dependabot.yml` covers `gomod` and `github-actions`, weekly, with a cooldown and an
`github-actions` group — following ec's shape with one required change:

> **`commit-message.prefix` must be `chore(deps)`, not ec's `deps:`.** With go-semantic-release
> parsing commit subjects, `deps:` is not a valid conventional-commit type. Every Dependabot merge
> would be silently unparseable and produce no release.

### Commit-message enforcement

Add a PR-title check (`amannn/action-semantic-pull-request` or equivalent, SHA-pinned) validating
the title against conventional-commit format. Combined with squash-merge, the PR title becomes the
commit subject on `main`, which is what semantic-release reads. Individual work-in-progress commits
stay unconstrained.

### `SECURITY.md`

Added at the repository root. Scorecard checks for it and this repository has none.

## Phase 4 — Release and publishing

### `.goreleaser.yaml`

Renamed from `goreleaser.yml` to the conventional dotted name.

- **Builds**: `linux`, `darwin`, `windows` × `amd64`, `arm64`. `CGO_ENABLED=0`, flags `-trimpath`,
  ldflags `-s -w`.
  **No `-X` version ldflags.** The plugin protocol rejects any `argv[1]` other than `v1`
  (`cmd/sigstore-kms-yckms/main.go`), so there is no `--version` path to stamp; an injected
  variable would be unreferenced and fight `gochecknoglobals`.
- **Archives**: `tar.gz`, `zip` override for Windows. The binary inside the archive must be named
  exactly `sigstore-kms-yckms` — Sigstore plugin discovery resolves plugins by filename on `PATH`.
  This replaces today's `format: binary`; bare binaries are friendlier to download-and-chmod, but
  per-archive SBOM generation requires archives.
- **Checksum**: sha256.
- **Signs**: cosign `sign-blob` over the checksum file, keyless, `--yes --bundle=${signature}`,
  producing `${artifact}.sigstore.json`.
- **SBOMs**: syft, `artifacts: archive`.
- **Release**: `mode: append` — go-semantic-release has already created the GitHub release. The
  `github.owner`/`github.name` fields are set explicitly rather than inferred from the git remote,
  so `goreleaser check` works in a fresh worktree.
- **Changelog**: `disable: true` — semantic-release owns release notes.

### `release.yml`

Triggered on `push` to `main`, two jobs mirroring `kc`:

1. **`semver`** — checkout with `fetch-depth: 0`, run go-semantic-release, expose `version` as a
   job output.
2. **`goreleaser`** — `needs: semver`, guarded by `if: needs.semver.outputs.version != ''`.
   Checks out `ref: v${{ needs.semver.outputs.version }}`, sets up Go from `go.mod`, installs
   cosign and syft, then runs `goreleaser release --clean`. A final
   `actions/attest-build-provenance` step attests the archives and checksum file in `dist/`.

Three details that would otherwise fail only at release time, in public:

- **Permissions** must be `contents: write`, **`id-token: write`**, and **`attestations: write`**.
  Today's release job grants only `contents: write` and `packages: write`; keyless cosign and
  provenance attestation both require `id-token: write`.
- **`allow-initial-development-versions: true`** on the semantic-release action. The latest tag is
  `v0.1.0`; without this flag the first `feat:` commit publishes **v1.0.0** rather than v0.2.0.
- `ci.yml`'s tag trigger and release job must already be removed (Phase 3).

### Accepted trade-off

Adopting go-semantic-release means adopting conventional commits repository-wide. Current history
does not follow them (`change .gitignore`, `Adopt fork under franchb namespace`). The PR-title
check in Phase 3 is the mitigation. This was raised during design and chosen deliberately over
continuing with tag-triggered releases.

## Phase 5 — Local verification

New entries in `.binny.yaml`: `zizmor`, `actionlint`, `goreleaser`.

New `Taskfile.yaml` targets:

- **`validate-actions`** — runs `actionlint` and `zizmor` against `.github/`.
- **`snapshot`** — runs `goreleaser release --snapshot --clean --skip=sign,sbom`, exercising
  builds, archives and checksums locally without publishing. The skip flags are required:
  GoReleaser runs the `signs` and `sboms` stages in snapshot mode too, so the target otherwise
  fails on a missing `cosign` binary. Signing and SBOM generation are exercised only in CI, where
  `cosign-installer` and `download-syft` put both tools on `PATH`.

`check-ci` gains `validate-actions` so workflow regressions are caught by the same gate as
everything else.

## Verification

| Phase | How it is verified |
| --- | --- |
| 1 | `go build ./... && go test ./...` pass; `go.mod` diff matches the table above |
| 2 | `golangci-lint run ./...` clean under the pinned v2.12.2 with tests included; `go test ./...` still passes |
| 3 | `task validate-actions` clean; workflows green on the implementing PR |
| 4 | `task snapshot` produces archives, checksums, and SBOMs; `zizmor` clean on `release.yml`; first real release verified with `cosign verify-blob` and `gh attestation verify` |
| 5 | `make check-ci` green locally and in CI |

## Risks

- **First real release is only fully exercised in production.** `task snapshot` covers builds,
  archives and checksums, but neither SBOM generation nor keyless signing nor attestation — those
  need cosign, syft and a real OIDC token, so they run for the first time in CI. Mitigated by
  verifying the first published release with `cosign verify-blob` and `gh attestation verify`
  before announcing it.
- **Semantic-release fires on every merge to `main`.** A mis-typed `feat:` publishes a minor
  version. Conventional-commit PR-title enforcement reduces but does not eliminate this.
- **Windows and darwin binaries are built but only smoke-tested.** The Phase 3 `test` job runs unit
  tests on those platforms; no end-to-end plugin invocation against real Yandex Cloud KMS occurs on
  any platform, which is unchanged from today.

## Sequencing

Two pull requests:

1. **Infrastructure** — Phases 1, 3, 4, 5. No Go source changes.
2. **Linters** — Phase 2. Isolated so the ~51 mechanical fixes are reviewable on their own.
