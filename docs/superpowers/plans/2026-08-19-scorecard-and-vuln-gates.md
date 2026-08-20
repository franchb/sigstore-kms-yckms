# Scorecard Alerts, Vuln Gates, and Gold Badge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close Scorecard alerts that code can close, block vulnerable and malicious modules on every PR, raise statement coverage to ≥90%, and leave a two-reviewer ruleset plus a bestpractices.dev gold walkthrough as operator steps after merge.

**Architecture:** Taskfile stays the source of truth for checks; `.binny.yaml` pins tools. Two new required CI jobs call `make govulncheck-module` (patternless `-C pkg/yckms -scan=module` plus a Python filter that shares `osv-scanner.toml` with OSV-Scanner and Scorecard) and `make osv-scanner`. Native `FuzzParseReference` is what Scorecard Fuzzing sees; ClusterFuzzLite compiles that same function. Coverage is gated by the existing `ci/scripts/coverage.py` once tests with a `kmsBackend` fake bring the total to 90%. The GitHub ruleset is applied **after** this PR merges, while self-merge is still allowed.

**Tech Stack:** Go 1.26.6, Task, binny, govulncheck v1.7.0, osv-scanner v2.5.1, ClusterFuzzLite actions `@v1` (`884713a6c30a92e5e8544c39945cd7cb630abcd1`), Python 3.11+ `tomllib`.

**Spec:** `docs/superpowers/specs/2026-08-19-scorecard-and-vuln-gates-design.md`

## Global Constraints

- Conventional-commit subjects only (`feat:`, `fix:`, `chore:`, `docs:`, `ci:`, `refactor:`, `test:`).
- Workflows: `permissions: {}` at workflow level; job-level grants only; `persist-credentials: false`; `timeout-minutes` on every job; harden-runner first on Linux (`b09bb98e06d4d774595224525879c09bc6e98c40` # v2.20.1).
- Every `uses:` is a 40-character SHA with `# vX.Y.Z`. CFL actions: `google/clusterfuzzlite/actions/build_fuzzers@884713a6c30a92e5e8544c39945cd7cb630abcd1` # v1 and the same SHA for `run_fuzzers`.
- `govulncheck -scan=module` MUST be invoked as `govulncheck -C pkg/yckms -scan=module` with **no** package pattern. `./...` exits 2 on v1.7.0; a patternless scan from the module root exits 1 (`no Go files`).
- Do **not** rename the `Check CI` job. Do **not** edit `.github/workflows/release.yml`.
- Do **not** add ClusterFuzzLite or `vuln.yml` as required status checks.
- Do **not** dismiss the Maintained code-scanning alert.
- No live Yandex Cloud. No `gochecknoglobals` package-level function variables.
- Do **not** apply the ruleset until this PR is on `main`.

## File Structure

**Created:**

| File | Responsibility |
| --- | --- |
| `CODEOWNERS` | `* @franchb @MichaelSBoop @wallrat1` |
| `CONTRIBUTING.md` | Review rules (2 approvals, code owners) |
| `osv-scanner.toml` | Shared ignore list (`GO-2026-5932`) |
| `ci/scripts/govulncheck_module.py` | Run module scan + filter ignores |
| `ci/scripts/govulncheck_module_test.py` | Unit tests for ignore/`ignoreUntil` |
| `.clusterfuzzlite/project.yaml` | `language: go` |
| `.clusterfuzzlite/Dockerfile` | Digest-pinned `base-builder-go` |
| `.clusterfuzzlite/build.sh` | `compile_native_go_fuzzer` for `FuzzParseReference` |
| `.github/workflows/cflite_pr.yml` | PR code-change fuzz, not required |
| `.github/workflows/cflite_batch.yml` | Weekly batch fuzz |

**Modified:** `Taskfile.yaml`, `.binny.yaml`, `.github/workflows/ci.yml`, `.github/workflows/vuln.yml`, `.github/dependabot.yml`, `README.md`, `SECURITY.md`, `cmd/sigstore-kms-yckms/main.go`, `cmd/sigstore-kms-yckms/main_test.go`, `pkg/yckms/*.go` (SPDX, `kmsBackend`, tests, fuzz).

**Unchanged:** `.github/workflows/release.yml`.

## Pull Request

One branch off `main`: `feat/scorecard-and-vuln-gates` (Tasks 1–11). Merge while self-merge still works. Task 12 is operator-only after merge.

---

### Task 1: SPDX-License-Identifier on every `.go` file

**Files:**
- Modify: every existing `*.go` under `cmd/` and `pkg/` (11 files today). New `.go` files in later tasks must use the same header.

- [ ] **Step 1: Insert SPDX immediately after the copyright line**

In each file the header currently starts:

```
// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
```

Change it to:

```
// Copyright 2023 The Sigstore Authors.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
```

Do not SPDX Python or YAML. Do not change the Apache license text.

- [ ] **Step 2: Confirm every Go file has the identifier**

Run:

```sh
git ls-files '*.go' | while read -r f; do
  grep -q 'SPDX-License-Identifier: Apache-2.0' "$f" || echo "MISSING $f"
done
```

Expected: no `MISSING` lines.

- [ ] **Step 3: Commit**

```sh
git add cmd pkg
git commit -m "chore: add SPDX-License-Identifier to Go sources"
```

---

### Task 2: CODEOWNERS, CONTRIBUTING, security review, snapshot docs

**Files:**
- Create: `CODEOWNERS`
- Create: `CONTRIBUTING.md`
- Modify: `SECURITY.md`
- Modify: `README.md`

- [ ] **Step 1: Write `CODEOWNERS`**

```
* @franchb @MichaelSBoop @wallrat1
```

Root path (not `.github/CODEOWNERS`). GitHub accepts either; the spec requires root.

- [ ] **Step 2: Write `CONTRIBUTING.md`**

```markdown
# Contributing

## Development

```sh
make check-ci
```

That runs format checks, golangci-lint, actionlint, zizmor, unit tests with coverage, a 20s Go fuzz of `FuzzParseReference`, and call-graph `govulncheck`.

PR CI also runs `govulncheck (module)` and `OSV Scanner`. Those fail on any OSV/GHSA/MAL advisory in the module graph except IDs listed with a reason in `osv-scanner.toml`.

## Pull requests

- Title must be a [conventional commit](https://www.conventionalcommits.org/) subject (`feat:`, `fix:`, `chore:`, `docs:`, `ci:`, `refactor:`, `test:`). The title becomes the merge-commit subject on `main` and drives releases.
- Two approving reviews are required. The author cannot be one of them.
- A code owner must approve (`CODEOWNERS`).
- New pushes dismiss stale approvals; the latest push must be re-approved.
- Do not merge your own PR.

## Reviewer checklist

- Tests cover the change; `make check-ci` is green.
- No secrets in the tree or logs.
- New dependencies have a reason; module-scan and OSV Scanner are green.
- Do not add `osv-scanner.toml` ignores without an `id` and a `reason`.
```

- [ ] **Step 3: Append a security-review section to `SECURITY.md`**

After the existing `## Scope` section, add:

```markdown
## Security review (2026-08)

Reviewed 2026-08 as part of OpenSSF Best Practices gold work.

Trust boundary: this repository's plugin and `pkg/yckms` handling of
`yckms://` resource IDs and Yandex Cloud credentials (`YC_IAM_TOKEN`,
`YC_OAUTH_TOKEN`, `YC_SERVICE_ACCOUNT_KEY_FILE`). The plugin is a local
CLI helper; it is not a network server.

Out of scope for this review (report upstream): Yandex Cloud KMS itself,
and Sigstore libraries (`github.com/sigstore/sigstore`). See Scope above.
```

- [ ] **Step 4: Add a local snapshot note to `README.md`**

After the Verifying releases section, add:

```markdown
## Reproducing a release archive locally

Release binaries are built with `CGO_ENABLED=0` and `-trimpath` (see
`.goreleaser.yaml`). A snapshot of the same six platform archives, without
publishing or signing:

```sh
task snapshot
```

Artifacts land in `dist/`. Checksums in a snapshot are not release-signed;
use the Verifying releases commands on a published GitHub Release.
```

- [ ] **Step 5: Commit**

```sh
git add CODEOWNERS CONTRIBUTING.md SECURITY.md README.md
git commit -m "docs: add CODEOWNERS, review rules, and security review note"
```

---

### Task 3: Native Go fuzz target and `task fuzz`

**Files:**
- Create: `pkg/yckms/reference_fuzz_test.go`
- Modify: `Taskfile.yaml` (`fuzz` task; `check-ci` calls it)

- [ ] **Step 1: Write `FuzzParseReference`**

```go
// Copyright 2023 The Sigstore Authors.
//
// SPDX-License-Identifier: Apache-2.0
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

import "testing"

func FuzzParseReference(f *testing.F) {
	f.Add("/key-id-123")
	f.Add("kms.yandexcloud.net/folder/folder-1/keyname/releases")
	f.Add("")
	f.Add("yckms:///key-id-123")
	f.Fuzz(func(_ *testing.T, ref string) {
		_, _, _, _, _ = ParseReference(ref)
		_ = ValidReference(ref)
	})
}
```

Invariant: no panic.

- [ ] **Step 2: Run seed corpus via `go test` (seeds run without `-fuzz`)**

```sh
go test ./pkg/yckms -run FuzzParseReference -count=1
```

Expected: PASS.

- [ ] **Step 3: Add Taskfile `fuzz` and call it from `check-ci`**

Insert after the `govulncheck` task:

```yaml
  fuzz:
    desc: Run native Go fuzz of ParseReference for 20s
    deps: [ tools ]
    cmds:
      - "go test ./pkg/yckms -fuzz=FuzzParseReference -fuzztime=20s"
```

In `check-ci` `cmds`, after `task: test` and before the second `verify-no-diff`:

```yaml
      - task: fuzz
```

- [ ] **Step 4: Run the fuzz task once**

```sh
make fuzz
```

Expected: ends with `PASS` and no crash files under `pkg/yckms/testdata`. If a crash appears, fix `ParseReference`/`ValidReference` before continuing — do not skip.

- [ ] **Step 5: Commit**

```sh
git add pkg/yckms/reference_fuzz_test.go Taskfile.yaml
git commit -m "test: fuzz ParseReference and ValidReference"
```

---

### Task 4: Shared ignore file and govulncheck module wrapper

**Files:**
- Create: `osv-scanner.toml`
- Create: `ci/scripts/govulncheck_module.py`
- Create: `ci/scripts/govulncheck_module_test.py`

`govulncheck` v1.7.0 JSON is concatenated objects (not NDJSON). Findings look like `{"finding":{"osv":"GO-2026-5932","trace":[...]}}`. `-format json` exits 0 even when findings exist.

- [ ] **Step 1: Write failing unit tests for the filter**

`ci/scripts/govulncheck_module_test.py`:

```python
#!/usr/bin/env python3
import datetime
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import govulncheck_module as gvm


def finding(osv, aliases=None):
    body = {"osv": osv}
    if aliases:
        body["aliases"] = aliases
    return {"finding": body}


class IgnoreIDsTests(unittest.TestCase):
    def test_unexpired_and_missing_until_are_ignored(self):
        toml = """
[[IgnoredVulns]]
id = "GO-2026-5932"
reason = "unused openpgp"

[[IgnoredVulns]]
id = "GO-2099-0001"
ignoreUntil = "2099-01-01"
reason = "future"

[[IgnoredVulns]]
id = "GO-2000-0001"
ignoreUntil = "2000-01-01"
reason = "expired"
"""
        path = Path(tempfile.mkstemp(suffix=".toml")[1])
        path.write_text(toml, encoding="utf-8")
        ids = gvm.ignored_ids(path, now=datetime.date(2026, 8, 19))
        self.assertIn("GO-2026-5932", ids)
        self.assertIn("GO-2099-0001", ids)
        self.assertNotIn("GO-2000-0001", ids)

    def test_remaining_drops_ignored_id_and_alias(self):
        ignored = {"GO-2026-5932"}
        text = json.dumps(finding("GO-2026-5932")) + json.dumps(
            finding("GO-2024-0001", aliases=["GO-2026-5932"])
        ) + json.dumps(finding("GO-2025-0002"))
        remaining = gvm.remaining_findings(text, ignored)
        self.assertEqual(remaining, ["GO-2025-0002"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests — expect fail (module missing)**

```sh
python3 -m unittest ci/scripts/govulncheck_module_test.py -v
```

Expected: import error for `govulncheck_module` until Step 3.

- [ ] **Step 3: Implement `ci/scripts/govulncheck_module.py`**

```python
#!/usr/bin/env python3
"""Run govulncheck -scan=module and fail on findings not ignored in osv-scanner.toml."""

from __future__ import annotations

import datetime
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def ignored_ids(toml_path: Path, now: datetime.date | None = None) -> set[str]:
    if now is None:
        now = datetime.datetime.now(datetime.UTC).date()
    if not toml_path.is_file():
        raise FileNotFoundError(toml_path)
    data = tomllib.loads(toml_path.read_text(encoding="utf-8"))
    ignored: set[str] = set()
    for entry in data.get("IgnoredVulns", []):
        vuln_id = entry.get("id")
        if not vuln_id:
            continue
        until = entry.get("ignoreUntil")
        if until:
            if isinstance(until, datetime.datetime):
                until_date = until.date()
            elif isinstance(until, datetime.date):
                until_date = until
            else:
                until_date = datetime.date.fromisoformat(str(until))
            if until_date <= now:
                continue
        ignored.add(str(vuln_id))
    return ignored


def remaining_findings(json_text: str, ignored: set[str]) -> list[str]:
    decoder = json.JSONDecoder()
    remaining: list[str] = []
    i = 0
    text = json_text
    n = len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        obj, end = decoder.raw_decode(text, i)
        i = end
        finding = obj.get("finding")
        if not isinstance(finding, dict):
            continue
        osv_id = finding.get("osv")
        aliases = finding.get("aliases") or []
        ids = []
        if isinstance(osv_id, str):
            ids.append(osv_id)
        ids.extend(a for a in aliases if isinstance(a, str))
        if ids and any(item in ignored for item in ids):
            continue
        if osv_id:
            remaining.append(osv_id)
    return remaining


def main() -> int:
    root = repo_root()
    toml_path = root / "osv-scanner.toml"
    govulncheck = os.environ.get("GOVULNCHECK", str(root / ".tool" / "govulncheck"))
    try:
        ignored = ignored_ids(toml_path)
    except FileNotFoundError:
        print(f"missing {toml_path}", file=sys.stderr)
        return 1
    proc = subprocess.run(
        [govulncheck, "-C", "pkg/yckms", "-scan=module", "-format", "json"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        sys.stderr.write(proc.stdout)
        print(
            f"govulncheck exited {proc.returncode} (json mode should exit 0)",
            file=sys.stderr,
        )
        return 1
    if not proc.stdout.strip():
        print("govulncheck produced empty JSON", file=sys.stderr)
        return 1
    try:
        leftover = remaining_findings(proc.stdout, ignored)
    except json.JSONDecodeError as err:
        print(f"invalid govulncheck JSON: {err}", file=sys.stderr)
        return 1
    if leftover:
        print("unignored module vulnerabilities:", ", ".join(leftover), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

`ignoreUntil` with no time is a TOML date; `tomllib` may yield `datetime.date`. Treat `until_date <= now` as expired (osv-scanner: ignore only while until is in the future).

- [ ] **Step 4: Re-run unit tests from the repo root**

```sh
python3 -m unittest ci/scripts/govulncheck_module_test.py -v
```

Expected: `OK`.

- [ ] **Step 5: Write `osv-scanner.toml` at the repo root (next to `go.mod`)**

```toml
[[IgnoredVulns]]
id = "GO-2026-5932"
reason = "golang.org/x/crypto is in the graph via sigstore; this repo does not import golang.org/x/crypto/openpgp. Every x/crypto version is flagged. No bump exists."
```

No `ignoreUntil` on this ID.

- [ ] **Step 6: Commit**

```sh
git add osv-scanner.toml ci/scripts/govulncheck_module.py ci/scripts/govulncheck_module_test.py
git commit -m "ci: filter govulncheck module findings with osv-scanner.toml"
```

---

### Task 5: Pin osv-scanner and wire Taskfile

**Files:**
- Modify: `.binny.yaml`
- Modify: `Taskfile.yaml`

- [ ] **Step 1: Add osv-scanner to `.binny.yaml` after the `govulncheck` stanza**

```yaml
  - name: osv-scanner
    version:
      want: v2.5.1
    method: github-release
    with:
      repo: google/osv-scanner
```

- [ ] **Step 2: Install**

```sh
make tools
.tool/binny check -v
.tool/osv-scanner --version
```

Expected: version line containing `2.5.1`. If binny cannot find the asset, stop and report — do not `go install` a floating version.

- [ ] **Step 3: Add Taskfile tasks**

After `govulncheck`:

```yaml
  govulncheck-module:
    desc: Fail on Go module-graph vulns except osv-scanner.toml ignores
    deps: [ tools ]
    cmds:
      - "python3 -m unittest ci/scripts/govulncheck_module_test.py"
      - cmd: "python3 ci/scripts/govulncheck_module.py"
        env:
          GOVULNCHECK: "{{ .TOOL_DIR }}/govulncheck"

  osv-scanner:
    desc: Scan go.mod/go.sum against OSV, GHSA, and MAL advisories
    deps: [ tools ]
    cmds:
      - "{{ .TOOL_DIR }}/osv-scanner scan source --recursive ."
```

`check-ci` keeps **only** call-graph `govulncheck`. Do not add `govulncheck-module` or `osv-scanner` to `check-ci`.

`govulncheck_module_test.py` inserts `ci/scripts` on `sys.path`, so `python3 -m unittest ci/scripts/govulncheck_module_test.py` works from the repo root.

- [ ] **Step 4: Run both gates**

```sh
make govulncheck-module
make osv-scanner
```

Expected: both exit 0. `govulncheck-module` without the toml ignore must fail — verify:

```sh
mv osv-scanner.toml osv-scanner.toml.bak
make govulncheck-module; echo exit:$?
mv osv-scanner.toml.bak osv-scanner.toml
```

Expected: non-zero exit (`missing .../osv-scanner.toml` or unignored `GO-2026-5932`). Restore the file.

Also confirm the wrapper does not pass `./...`:

```sh
grep -n 'scan=module' ci/scripts/govulncheck_module.py Taskfile.yaml
```

Expected: `-C pkg/yckms` only; no `./...`.

- [ ] **Step 5: Commit**

```sh
git add .binny.yaml Taskfile.yaml ci/scripts/govulncheck_module_test.py
git commit -m "ci: pin osv-scanner and add module-graph vuln tasks"
```

---

### Task 6: Required PR jobs and scheduled triple scan

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/vuln.yml`

Reuse the same Go/checkout/harden SHAs as existing jobs.

- [ ] **Step 1: Append two jobs to `.github/workflows/ci.yml`**

```yaml
  govulncheck-module:
    name: govulncheck (module)
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

      - name: Bootstrap Go modules
        run: make ci-bootstrap-go

      - name: Run govulncheck module scan
        run: make govulncheck-module

  osv-scanner:
    name: OSV Scanner
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

      - name: Bootstrap Go modules
        run: make ci-bootstrap-go

      - name: Run OSV Scanner
        run: make osv-scanner
```

Do not rename `check-ci.name`. It stays `Check CI`.

- [ ] **Step 2: Expand `.github/workflows/vuln.yml` to three steps in the existing job**

Replace the single `Run govulncheck` step with:

```yaml
      - name: Run call-graph govulncheck
        run: make govulncheck

      - name: Run govulncheck module scan
        run: make govulncheck-module

      - name: Run OSV Scanner
        run: make osv-scanner
```

Keep `workflow_dispatch` and the Monday cron. Bump `timeout-minutes` from 10 to 15.

- [ ] **Step 3: Lint workflows**

```sh
make validate-actions
```

Expected: actionlint exit 0, zizmor `No findings to report`.

- [ ] **Step 4: Commit**

```sh
git add .github/workflows/ci.yml .github/workflows/vuln.yml
git commit -m "ci: require module govulncheck and OSV Scanner on PRs"
```

---

### Task 7: ClusterFuzzLite (not required) and Dependabot docker

**Files:**
- Create: `.clusterfuzzlite/project.yaml`
- Create: `.clusterfuzzlite/Dockerfile`
- Create: `.clusterfuzzlite/build.sh`
- Create: `.github/workflows/cflite_pr.yml`
- Create: `.github/workflows/cflite_batch.yml`
- Modify: `.github/dependabot.yml`

CFL action commit (peeled `v1` tag): `884713a6c30a92e5e8544c39945cd7cb630abcd1`.

`base-builder-go:latest` digest resolved 2026-08-19:

`sha256:e5e5ecf4fb18a2f47bf0462c37e35728e8f6023ee4b7ff8bc5f903e6acba46da`

Re-check at implement time:

```sh
skopeo inspect --format '{{.Digest}}' docker://gcr.io/oss-fuzz-base/base-builder-go:latest
```

If it changed, use the new digest and mention it in the commit body. Never use the floating tag.

- [ ] **Step 1: Write `.clusterfuzzlite/project.yaml`**

```yaml
language: go
```

- [ ] **Step 2: Write `.clusterfuzzlite/Dockerfile`**

```dockerfile
FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:e5e5ecf4fb18a2f47bf0462c37e35728e8f6023ee4b7ff8bc5f903e6acba46da
COPY . $SRC/sigstore-kms-yckms
WORKDIR $SRC/sigstore-kms-yckms
COPY .clusterfuzzlite/build.sh $SRC/
ENV GOTOOLCHAIN=auto
```

- [ ] **Step 3: Write `.clusterfuzzlite/build.sh`**

```sh
#!/bin/bash -eu
compile_native_go_fuzzer github.com/franchb/sigstore-kms-yckms/pkg/yckms FuzzParseReference fuzz_parse_reference
```

```sh
chmod +x .clusterfuzzlite/build.sh
```

- [ ] **Step 4: Write `.github/workflows/cflite_pr.yml`**

```yaml
name: ClusterFuzzLite PR fuzzing

on:
  pull_request:

permissions: {}

jobs:
  PR:
    name: ClusterFuzzLite (PR)
    runs-on: ubuntu-latest
    timeout-minutes: 20
    permissions:
      contents: read
      security-events: write
    concurrency:
      group: ${{ github.workflow }}-${{ github.ref }}
      cancel-in-progress: true
    steps:
      - name: Harden Runner
        uses: step-security/harden-runner@b09bb98e06d4d774595224525879c09bc6e98c40 # v2.20.1
        with:
          egress-policy: audit

      - name: Build Fuzzers
        id: build
        uses: google/clusterfuzzlite/actions/build_fuzzers@884713a6c30a92e5e8544c39945cd7cb630abcd1 # v1
        with:
          language: go
          github-token: ${{ secrets.GITHUB_TOKEN }}
          sanitizer: address

      - name: Run Fuzzers
        id: run
        uses: google/clusterfuzzlite/actions/run_fuzzers@884713a6c30a92e5e8544c39945cd7cb630abcd1 # v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fuzz-seconds: 180
          mode: code-change
          sanitizer: address
          output-sarif: true
```

If harden-runner blocks CFL's Docker builder, remove **only** the Harden Runner step from the two CFL workflows and add a comment: `# harden-runner omitted: blocks ClusterFuzzLite docker builder`. Do not drop `contents: read`.

- [ ] **Step 5: Write `.github/workflows/cflite_batch.yml`**

```yaml
name: ClusterFuzzLite batch fuzzing

on:
  schedule:
    - cron: "0 6 * * 1"
  workflow_dispatch:

permissions: {}

jobs:
  BatchFuzzing:
    name: ClusterFuzzLite (batch)
    runs-on: ubuntu-latest
    timeout-minutes: 25
    permissions:
      contents: read
      security-events: write
    steps:
      - name: Harden Runner
        uses: step-security/harden-runner@b09bb98e06d4d774595224525879c09bc6e98c40 # v2.20.1
        with:
          egress-policy: audit

      - name: Build Fuzzers
        id: build
        uses: google/clusterfuzzlite/actions/build_fuzzers@884713a6c30a92e5e8544c39945cd7cb630abcd1 # v1
        with:
          language: go
          github-token: ${{ secrets.GITHUB_TOKEN }}
          sanitizer: address

      - name: Run Fuzzers
        id: run
        uses: google/clusterfuzzlite/actions/run_fuzzers@884713a6c30a92e5e8544c39945cd7cb630abcd1 # v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fuzz-seconds: 600
          mode: batch
          sanitizer: address
          output-sarif: true
```

- [ ] **Step 6: Add Dependabot docker updates for the digest**

Append to `.github/dependabot.yml`:

```yaml
  - package-ecosystem: "docker"
    commit-message:
      prefix: "chore(deps)"
    directory: "/.clusterfuzzlite"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "12:00"
      timezone: "UTC"
    cooldown:
      default-days: 7
```

- [ ] **Step 7: Lint**

```sh
make validate-actions
```

Expected: exit 0. Confirm Dockerfile is digest-pinned:

```sh
grep '^FROM ' .clusterfuzzlite/Dockerfile
```

Expected: contains `@sha256:` and does not end with `:latest` without a digest.

- [ ] **Step 8: Commit**

```sh
git add .clusterfuzzlite .github/workflows/cflite_pr.yml .github/workflows/cflite_batch.yml .github/dependabot.yml
git commit -m "ci: add ClusterFuzzLite for FuzzParseReference"
```

---

### Task 8: Extract `run` from `main` and test the plugin entrypoint

**Files:**
- Modify: `cmd/sigstore-kms-yckms/main.go`
- Modify: `cmd/sigstore-kms-yckms/main_test.go`

`handler.GetPluginArgs` requires ≥3 argv entries; argv[2] is JSON `common.PluginArgs`. `DefaultAlgorithm` and `SupportedAlgorithms` on `*yckms.SignerVerifier` do not need a live KMS client.

- [ ] **Step 1: Write failing tests in `main_test.go`**

Replace the file with the SPDX header (same as Task 1) plus:

```go
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"

	"github.com/franchb/sigstore-kms-yckms/pkg/yckms"
)

func TestRunMissingProtocolVersion(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	code := run([]string{"sigstore-kms-yckms"}, bytes.NewReader(nil), &stdout, yckms.LoadSignerVerifier)
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if !strings.Contains(stdout.String(), errMissingProtocolVersion.Error()) {
		t.Fatalf("stdout = %q, want %q", stdout.String(), errMissingProtocolVersion)
	}
}

func TestRunWrongProtocolVersion(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	code := run([]string{"sigstore-kms-yckms", "v0"}, bytes.NewReader(nil), &stdout, yckms.LoadSignerVerifier)
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if !strings.Contains(stdout.String(), errExpectedProtocolVersion.Error()) {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunInvalidPluginJSON(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	code := run([]string{"sigstore-kms-yckms", "v1", "{"}, bytes.NewReader(nil), &stdout, yckms.LoadSignerVerifier)
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if stdout.Len() == 0 {
		t.Fatal("expected plugin error JSON on stdout")
	}
}

func TestRunLoadSignerVerifierError(t *testing.T) {
	t.Parallel()

	payload, err := json.Marshal(common.PluginArgs{
		InitOptions: &common.InitOptions{
			ProtocolVersion: "v1",
			KeyResourceID:   "invalid",
		},
		MethodArgs: &common.MethodArgs{
			MethodName:       common.DefaultAlgorithmMethodName,
			DefaultAlgorithm: &common.DefaultAlgorithmArgs{},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var stdout bytes.Buffer
	code := run(
		[]string{"sigstore-kms-yckms", "v1", string(payload)},
		bytes.NewReader(nil),
		&stdout,
		yckms.LoadSignerVerifier,
	)
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if !strings.Contains(stdout.String(), yckms.ErrKMSReference.Error()) {
		t.Fatalf("stdout = %q, want ErrKMSReference", stdout.String())
	}
}

func TestRunDefaultAlgorithmWithoutKMS(t *testing.T) {
	t.Parallel()

	payload, err := json.Marshal(common.PluginArgs{
		InitOptions: &common.InitOptions{
			ProtocolVersion: "v1",
			KeyResourceID:   "/key-id-123",
		},
		MethodArgs: &common.MethodArgs{
			MethodName:       common.DefaultAlgorithmMethodName,
			DefaultAlgorithm: &common.DefaultAlgorithmArgs{},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	load := func(context.Context, string) (*yckms.SignerVerifier, error) {
		return &yckms.SignerVerifier{}, nil
	}

	var stdout bytes.Buffer
	code := run(
		[]string{"sigstore-kms-yckms", "v1", string(payload)},
		bytes.NewReader(nil),
		&stdout,
		load,
	)
	if code != 0 {
		t.Fatalf("run() = %d, stdout=%s", code, stdout.String())
	}
	if !strings.Contains(stdout.String(), yckms.AlgorithmECDSANISTP256SHA256) {
		t.Fatalf("stdout = %q, want default algorithm", stdout.String())
	}
}

func TestExpectedProtocolVersion(t *testing.T) {
	t.Parallel()

	if expectedProtocolVersion != "v1" {
		t.Fatalf("expectedProtocolVersion = %q, want v1", expectedProtocolVersion)
	}
}

func TestRunLoaderError(t *testing.T) {
	t.Parallel()

	payload, err := json.Marshal(common.PluginArgs{
		InitOptions: &common.InitOptions{
			ProtocolVersion: "v1",
			KeyResourceID:   "/key-id-123",
		},
		MethodArgs: &common.MethodArgs{
			MethodName:       common.DefaultAlgorithmMethodName,
			DefaultAlgorithm: &common.DefaultAlgorithmArgs{},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	want := errors.New("loader boom")
	load := func(context.Context, string) (*yckms.SignerVerifier, error) {
		return nil, want
	}

	var stdout bytes.Buffer
	code := run(
		[]string{"sigstore-kms-yckms", "v1", string(payload)},
		bytes.NewReader(nil),
		&stdout,
		load,
	)
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if !strings.Contains(stdout.String(), want.Error()) {
		t.Fatalf("stdout = %q", stdout.String())
	}
}
```

If `DefaultAlgorithmArgs` is not a named type in this sigstore version, use whatever the compiler reports (`struct{}` placeholder is wrong — fix to the real type from `common`).

- [ ] **Step 2: Run tests — expect fail (`run` undefined)**

```sh
go test ./cmd/sigstore-kms-yckms -count=1
```

Expected: FAIL `undefined: run`.

- [ ] **Step 3: Implement `run` in `main.go`**

Keep the SPDX header. Replace the functions after the `var` block:

```go
func main() {
	os.Exit(run(os.Args, os.Stdin, os.Stdout, yckms.LoadSignerVerifier))
}

func run(
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	load func(context.Context, string) (*yckms.SignerVerifier, error),
) int {
	if len(args) < minPluginArgs {
		return writeError(stdout, errMissingProtocolVersion)
	}

	if protocolVersion := args[1]; protocolVersion != expectedProtocolVersion {
		return writeError(stdout, fmt.Errorf("%w %s, got %s", errExpectedProtocolVersion, expectedProtocolVersion, protocolVersion))
	}

	pluginArgs, err := handler.GetPluginArgs(args)
	if err != nil {
		return writeError(stdout, err)
	}

	signerVerifier, err := load(context.Background(), pluginArgs.InitOptions.KeyResourceID)
	if err != nil {
		return writeError(stdout, err)
	}

	if _, err := handler.Dispatch(stdout, stdin, pluginArgs, signerVerifier); err != nil {
		return 1
	}

	return 0
}

func writeError(stdout io.Writer, err error) int {
	_ = handler.WriteErrorResponse(stdout, err)

	return 1
}
```

Add imports: `"io"`. Remove unused `"os"` only if `os.Args`/`os.Stdin`/`os.Stdout`/`os.Exit` remain (they do, in `main`).

- [ ] **Step 4: Run tests**

```sh
go test ./cmd/sigstore-kms-yckms -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add cmd/sigstore-kms-yckms/main.go cmd/sigstore-kms-yckms/main_test.go
git commit -m "refactor: extract plugin run for unit tests"
```

---

### Task 9: Credentials and reference table tests

**Files:**
- Modify: `pkg/yckms/credentials_test.go`
- Modify: `pkg/yckms/reference_test.go`

- [ ] **Step 1: Add credential tests (no `t.Parallel` — they use `t.Setenv`)**

Append to `credentials_test.go`:

```go
func TestCredentialsIAMToken(t *testing.T) {
	t.Setenv(EnvYcIAMToken, "iam-test-token")
	t.Setenv(EnvYcOAuthToken, "")
	t.Setenv(EnvYcServiceAccountKeyFile, "")

	creds, err := credentials(t.Context())
	if err != nil {
		t.Fatalf("credentials() error = %v", err)
	}
	if creds == nil {
		t.Fatal("credentials() returned nil")
	}
}

func TestCredentialsOAuthToken(t *testing.T) {
	t.Setenv(EnvYcIAMToken, "")
	t.Setenv(EnvYcOAuthToken, "oauth-test-token")
	t.Setenv(EnvYcServiceAccountKeyFile, "")

	creds, err := credentials(t.Context())
	if err != nil {
		t.Fatalf("credentials() error = %v", err)
	}
	if creds == nil {
		t.Fatal("credentials() returned nil")
	}
}

func TestCredentialsInvalidServiceAccountFile(t *testing.T) {
	t.Setenv(EnvYcIAMToken, "")
	t.Setenv(EnvYcOAuthToken, "")
	t.Setenv(EnvYcServiceAccountKeyFile, t.TempDir()+"/missing.json")

	_, err := credentials(t.Context())
	if err == nil {
		t.Fatal("credentials() succeeded with missing service-account file")
	}
}

func TestCredentialsValidServiceAccountFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/sa.json"
	// Minimal JSON iamkey.ReadFromJSONFile accepts: service_account_id, id, private_key.
	body := `{
  "id": "key-id",
  "service_account_id": "sa-id",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n"
}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	t.Setenv(EnvYcIAMToken, "")
	t.Setenv(EnvYcOAuthToken, "")
	t.Setenv(EnvYcServiceAccountKeyFile, path)

	_, err := credentials(t.Context())
	// Parse success or PEM parse failure both exercise the file branch; only missing-file is forbidden.
	if err != nil && !strings.Contains(err.Error(), "building service account key credentials") &&
		!strings.Contains(err.Error(), "read service account key file") {
		t.Fatalf("credentials() unexpected error = %v", err)
	}
}
```

Add imports `"os"` and `"strings"` if needed.

If `iamkey.ReadFromJSONFile` requires a real PKCS#8 key, generating one in the test is better than a dummy PEM:

```go
func writeSAFile(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	body, err := json.Marshal(map[string]string{
		"id":                 "key-id",
		"service_account_id": "sa-id",
		"private_key":        string(pemBytes),
	})
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/sa.json"
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
```

Use that helper in `TestCredentialsValidServiceAccountFile` and require `err == nil`.

- [ ] **Step 2: Add reference table tests**

Append to `reference_test.go`:

```go
func TestParseReferenceRejectsMalformed(t *testing.T) {
	t.Parallel()

	cases := []string{
		"",
		"only-one-segment",
		"/folder/x/keyname/y/extra",
		"host/folder/only",
	}
	for _, ref := range cases {
		if _, _, _, _, err := ParseReference(ref); err == nil {
			t.Fatalf("ParseReference(%q) succeeded", ref)
		}
		if err := ValidReference(ref); err == nil {
			t.Fatalf("ValidReference(%q) succeeded", ref)
		}
	}
}

func TestParseReferenceEmptyEndpointKeyID(t *testing.T) {
	t.Parallel()

	endpoint, keyID, folderID, keyName, err := ParseReference("/abc")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "" || keyID != "abc" || folderID != "" || keyName != "" {
		t.Fatalf("got %q %q %q %q", endpoint, keyID, folderID, keyName)
	}
}
```

- [ ] **Step 3: Run tests**

```sh
go test ./pkg/yckms -count=1
```

Expected: PASS.

- [ ] **Step 4: Commit**

```sh
git add pkg/yckms/credentials_test.go pkg/yckms/reference_test.go
git commit -m "test: cover credentials sources and malformed references"
```

---

### Task 10: `kmsBackend` fake and SignerVerifier/client coverage

**Files:**
- Modify: `pkg/yckms/client.go` (interface + `sdkBackend`; `ycKmsClient` uses `backend` instead of calling `*ycsdk.SDK` methods)
- Create: `pkg/yckms/client_test.go`
- Modify: `pkg/yckms/signer_test.go`

This refactor exists only so Sign/Verify/CreateKey/PublicKey/cache can run without Yandex Cloud. Do not change exported APIs.

- [ ] **Step 1: Write tests against a fake backend (same package, unexported fields OK)**

`pkg/yckms/client_test.go` (SPDX header, then):

```go
package yckms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/jellydator/ttlcache/v3"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	asymkms "github.com/yandex-cloud/go-genproto/yandex/cloud/kms/v1/asymmetricsignature"
)

type fakeBackend struct {
	priv       *ecdsa.PrivateKey
	pem        string
	keyID      string
	alg        asymkms.AsymmetricSignatureAlgorithm
	getKeyErr  error
	signErr    error
	createID   string
	createPEM  string
	createErr  error
}

func (f *fakeBackend) getKey(context.Context, string) (*asymkms.AsymmetricSignatureKey, error) {
	if f.getKeyErr != nil {
		return nil, f.getKeyErr
	}
	return &asymkms.AsymmetricSignatureKey{Id: f.keyID, SignatureAlgorithm: f.alg}, nil
}

func (f *fakeBackend) getPublicKeyPEM(context.Context, string) (string, error) {
	return f.pem, nil
}

func (f *fakeBackend) signHash(_ context.Context, _ string, digest []byte) ([]byte, error) {
	if f.signErr != nil {
		return nil, f.signErr
	}
	return ecdsa.SignASN1(rand.Reader, f.priv, digest)
}

func (f *fakeBackend) createKey(context.Context, string, string, asymkms.AsymmetricSignatureAlgorithm) (string, string, error) {
	if f.createErr != nil {
		return "", "", f.createErr
	}
	return f.createID, f.createPEM, nil
}

func newTestClient(t *testing.T, backend kmsBackend, resourceID string) *ycKmsClient {
	t.Helper()
	if err := ValidReference(resourceID); err != nil {
		t.Fatal(err)
	}
	endpoint, keyID, folderID, keyName, err := ParseReference(resourceID)
	if err != nil {
		t.Fatal(err)
	}
	cache := ttlcache.New[string, ycSignatureKey](
		ttlcache.WithDisableTouchOnHit[string, ycSignatureKey](),
	)
	return &ycKmsClient{
		backend:  backend,
		skCache:   cache,
		endpoint:  endpoint,
		refString: resourceID,
		folderID:  folderID,
		keyID:     keyID,
		keyName:   keyName,
	}
}

func ecdsaFake(t *testing.T) *fakeBackend {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return &fakeBackend{
		priv:  priv,
		pem:   string(pemBytes),
		keyID: "key-1",
		alg:   asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P256_SHA_256,
	}
}

func TestSignAndVerifyWithFakeBackend(t *testing.T) {
	t.Parallel()

	fake := ecdsaFake(t)
	client := newTestClient(t, fake, "/key-1")
	sv := &SignerVerifier{client: client}

	message := []byte("hello-yckms")
	sig, err := sv.SignMessage(bytes.NewReader(message))
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	if err := sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(message)); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	pub, err := sv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if _, err := cryptoutils.MarshalPublicKeyToPEM(pub); err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
}

func TestSignMessageUninitialized(t *testing.T) {
	t.Parallel()

	var sv *SignerVerifier
	_, err := sv.SignMessage(bytes.NewReader(nil))
	if !errors.Is(err, errUninitializedSignerVerifier) {
		t.Fatalf("error = %v", err)
	}
	if err := sv.VerifySignature(bytes.NewReader(nil), bytes.NewReader(nil)); !errors.Is(err, errUninitializedSignerVerifier) {
		t.Fatalf("error = %v", err)
	}
	if _, err := sv.PublicKey(); !errors.Is(err, errUninitializedSignerVerifier) {
		t.Fatalf("error = %v", err)
	}
	if _, err := sv.CreateKey(t.Context(), AlgorithmECDSANISTP256SHA256); !errors.Is(err, errUninitializedSignerVerifier) {
		t.Fatalf("error = %v", err)
	}
	if _, _, err := sv.CryptoSigner(t.Context(), nil); !errors.Is(err, errUninitializedSignerVerifier) {
		t.Fatalf("error = %v", err)
	}
}

func TestCreateKeyRequiresFolderAndName(t *testing.T) {
	t.Parallel()

	fake := ecdsaFake(t)
	sv := &SignerVerifier{client: newTestClient(t, fake, "/key-1")}
	if _, err := sv.CreateKey(t.Context(), AlgorithmECDSANISTP256SHA256); !errors.Is(err, ErrCreateKeyReference) {
		t.Fatalf("error = %v, want ErrCreateKeyReference", err)
	}
}

func TestCreateKeyUnknownAlgorithm(t *testing.T) {
	t.Parallel()

	fake := ecdsaFake(t)
	sv := &SignerVerifier{client: newTestClient(t, fake, "host/folder/folder-1/keyname/k")}
	if _, err := sv.CreateKey(t.Context(), "not-an-alg"); !errors.Is(err, ErrUnknownAlgorithm) {
		t.Fatalf("error = %v, want ErrUnknownAlgorithm", err)
	}
}

func TestCreateKeySuccess(t *testing.T) {
	t.Parallel()

	fake := ecdsaFake(t)
	fake.createID = "new-key"
	fake.createPEM = fake.pem
	sv := &SignerVerifier{client: newTestClient(t, fake, "host/folder/folder-1/keyname/k")}
	pub, err := sv.CreateKey(t.Context(), AlgorithmECDSANISTP256SHA256)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if pub == nil {
		t.Fatal("nil public key")
	}
}

func TestGetSKBackendError(t *testing.T) {
	t.Parallel()

	fake := ecdsaFake(t)
	fake.getKeyErr = errors.New("kms down")
	sv := &SignerVerifier{client: newTestClient(t, fake, "/key-1")}
	if _, err := sv.PublicKey(); err == nil {
		t.Fatal("expected error")
	}
}

func TestCryptoSignerSignsDigest(t *testing.T) {
	t.Parallel()

	fake := ecdsaFake(t)
	sv := &SignerVerifier{client: newTestClient(t, fake, "/key-1")}
	cs, opts, err := sv.CryptoSigner(t.Context(), func(error) {})
	if err != nil {
		t.Fatalf("CryptoSigner: %v", err)
	}
	sum := sha256.Sum256([]byte("digest-me"))
	sig, err := cs.Sign(nil, sum[:], opts)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}
	if cs.Public() == nil {
		t.Fatal("Public() nil")
	}
}

func TestAlgorithmMapCoversSupportedAlgorithms(t *testing.T) {
	t.Parallel()

	got := algorithmMap()
	for _, name := range (&SignerVerifier{}).SupportedAlgorithms() {
		if _, ok := got[name]; !ok {
			t.Fatalf("algorithmMap missing %s", name)
		}
	}
}

func TestVerifierForAlgorithmECDSAHashFuncs(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		alg  asymkms.AsymmetricSignatureAlgorithm
		hash crypto.Hash
	}{
		{asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P256_SHA_256, crypto.SHA256},
		{asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P384_SHA_384, crypto.SHA384},
		{asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P521_SHA_512, crypto.SHA512},
	}
	for _, tc := range cases {
		_, hashFunc, err := verifierForAlgorithm(tc.alg, priv.Public())
		if err != nil {
			t.Fatalf("alg %v: %v", tc.alg, err)
		}
		if hashFunc != tc.hash {
			t.Fatalf("hash = %v, want %v", hashFunc, tc.hash)
		}
	}
}

func TestVerifierForAlgorithmSecp256k1Unsupported(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = verifierForAlgorithm(
		asymkms.AsymmetricSignatureAlgorithm_ECDSA_SECP256_K1_SHA_256,
		priv.Public(),
	)
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("error = %v", err)
	}
}

func TestRSAHashVariants(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, hashFunc, err := verifierForAlgorithm(
		asymkms.AsymmetricSignatureAlgorithm_RSA_2048_SIGN_PSS_SHA_512,
		rsaKey.Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if hashFunc != crypto.SHA512 {
		t.Fatalf("hash = %v, want SHA512", hashFunc)
	}
}
```

Add `"crypto/rsa"` to the import block (used by `TestRSAHashVariants`). ECDSA P-256 is enough for the hash-func table; `verifierForAlgorithm` only type-asserts `*ecdsa.PublicKey`, not the curve.

These tests will not compile until `kmsBackend` exists on `ycKmsClient`.

- [ ] **Step 2: Run tests — expect compile fail**

```sh
go test ./pkg/yckms -count=1
```

Expected: `ycKmsClient` has no field `backend` / `kmsBackend` undefined.

- [ ] **Step 3: Add `kmsBackend` and route client methods through it**

In `pkg/yckms/client.go`, add:

```go
type kmsBackend interface {
	getKey(ctx context.Context, keyID string) (*asymkms.AsymmetricSignatureKey, error)
	getPublicKeyPEM(ctx context.Context, keyID string) (string, error)
	signHash(ctx context.Context, keyID string, digest []byte) ([]byte, error)
	createKey(ctx context.Context, folderID, name string, alg asymkms.AsymmetricSignatureAlgorithm) (keyID, publicKeyPEM string, err error)
}

type sdkBackend struct {
	sdk *ycsdk.SDK
}
```

Implement `sdkBackend` with the current SDK calls (Get, GetPublicKey, SignHash, Create+WrapOperation+Wait+Response). Wrap those errors with `%w` as today.

Change `ycKmsClient` to:

```go
type ycKmsClient struct {
	backend  kmsBackend
	skCache   *ttlcache.Cache[string, ycSignatureKey]
	endpoint  string
	refString string
	folderID  string
	keyID     string
	keyName   string
}
```

Drop the `client *ycsdk.SDK` field. In `newYcKmsClient`, after `ycsdk.Build`:

```go
	sdk, err := ycsdk.Build(ctx, conf, opts...)
	if err != nil {
		return nil, fmt.Errorf("new yc kms client: %w", err)
	}
	y.backend = sdkBackend{sdk: sdk}
```

Rewrite `getYcSignatureKey`, `sign`, `fetchPublicKey`, and `createKey` to call `y.backend.*` only. `createKey` still checks folder/name and `algorithmMap()`, then `backend.createKey`, then `cryptoutils.UnmarshalPEMToPublicKey`.

- [ ] **Step 4: Run tests**

```sh
go test ./pkg/yckms ./cmd/sigstore-kms-yckms -count=1
```

Expected: PASS. If wrapcheck or other linters fire, fix them before committing.

```sh
make lint
```

Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add pkg/yckms/client.go pkg/yckms/client_test.go pkg/yckms/signer_test.go
git commit -m "test: fake KMS backend to cover sign, verify, and create"
```

---

### Task 11: Raise the coverage gate to 90%

**Files:**
- Modify: `Taskfile.yaml` (`COVERAGE_THRESHOLD`)
- Possibly more tests if the measurement is still below 90.

- [ ] **Step 1: Measure**

```sh
go test -covermode=atomic -coverprofile=/tmp/yckms-cov.out ./...
go tool cover -func=/tmp/yckms-cov.out | tail -1
```

Expected: `total:` line **≥90.0%**. If not, add tests for the uncovered functions listed by `go tool cover -func` (do not lower the spec). Typical leftovers: `newYcKmsClient` SDK build (needs credentials — `TestLoadSignerVerifierRejectsInvalidReference` already covers the ValidReference branch; empty-env credentials cover the creds branch). Hit `sdkBackend` error-wrap lines with a tiny stub only if still short; do not call live YC.

- [ ] **Step 2: Set the gate**

In `Taskfile.yaml` `test.vars`:

```yaml
      COVERAGE_THRESHOLD: 90
```

- [ ] **Step 3: Run full local CI**

```sh
make check-ci
make govulncheck-module
make osv-scanner
```

Expected: all three pass. `check-ci` includes the 20s fuzz.

- [ ] **Step 4: Commit**

```sh
git add Taskfile.yaml pkg/yckms
git commit -m "test: gate unit coverage at 90 percent"
```

---

### Task 12: Operator steps after merge (not git)

Do **not** run these until Tasks 1–11 are on `main`.

- [ ] **Step 1: Confirm PR check contexts**

On the merged-from PR, copy the exact check names. They must include:

- `Check CI`
- `Test (macos-latest)`
- `Test (windows-latest)`
- `Analyze (go)`
- `Dependency Review`
- `Conventional commit title`
- `govulncheck (module)`
- `OSV Scanner`

ClusterFuzzLite may be present and red; it is not required.

- [ ] **Step 2: Create the ruleset**

Write `/tmp/main-ruleset.json` from the spec JSON (required_status_checks contexts from Step 1). Then:

```sh
gh api --method POST repos/franchb/sigstore-kms-yckms/rulesets --input /tmp/main-ruleset.json
```

`bypass_actors` must be `[]`. If GitHub rejects a field, fix the payload without adding bypass actors or dropping the second approval.

- [ ] **Step 3: Prove the ruleset**

Open a trivial docs PR. Merging without two human approvals (not the author) must be blocked. Dependabot PRs will wait the same way — accepted cost, no bot bypass.

- [ ] **Step 4: GitHub product settings**

- Enable Issues. Open one issue labeled `good first issue` (e.g. README typo or extra fuzz seed).
- All three maintainers (`franchb`, `MichaelSBoop`, `wallrat1`): GitHub 2FA with TOTP or WebAuthn, not SMS-only.
- Leave the Maintained code-scanning alert open until ~2026-11-12.

- [ ] **Step 5: bestpractices.dev walkthrough**

Register https://github.com/franchb/sigstore-kms-yckms on https://www.bestpractices.dev. Fill **passing → silver → gold**. Paste each criterion into the implementation session; the agent returns Met/N/A/Unmet, justification text, and a real URL. Do not invent URLs.

- [ ] **Step 6: Badge follow-up**

When gold is granted, add the badge image to `README.md` in a small `docs:` PR (now subject to two reviews).

---

## Self-review (spec coverage)

| Spec requirement | Task |
| --- | --- |
| SPDX on `.go` files | 1 |
| CODEOWNERS three humans | 2 |
| CONTRIBUTING 2-review rules | 2 |
| Security review 2026-08 | 2 |
| `task snapshot` README note | 2 |
| `FuzzParseReference` + 20s in check-ci | 3 |
| `osv-scanner.toml` GO-2026-5932 | 4 |
| Wrapper `-C pkg/yckms`, no pattern, `ignoreUntil` | 4–5 |
| osv-scanner v2.5.1 binny pin | 5 |
| Required CI jobs; `Check CI` not renamed | 6 |
| `vuln.yml` all three scans | 6 |
| `release.yml` untouched | 6 (constraint) |
| CFL digest-pinned Dockerfile | 7 |
| CFL `contents: read` | 7 |
| Dependabot docker `/.clusterfuzzlite` | 7 |
| CFL not required | 7 |
| `run` extract + cmd tests | 8 |
| credentials / reference tests | 9 |
| `kmsBackend` fake, no live YC | 10 |
| Coverage gate 90% | 11 |
| Ruleset after merge, no bypass | 12 |
| Issues + 2FA + questionnaire | 12 |
| Do not dismiss Maintained | 12 |
