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
