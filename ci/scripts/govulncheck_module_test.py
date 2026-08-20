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

    def test_remaining_drops_alias_from_osv_record(self):
        # govulncheck v1.7.0 puts aliases on top-level osv objects, not findings.
        ignored = {"GHSA-xxxx-yyyy-zzzz"}
        text = json.dumps(
            {"osv": {"id": "GO-2025-0002", "aliases": ["GHSA-xxxx-yyyy-zzzz"]}}
        ) + json.dumps(finding("GO-2025-0002")) + json.dumps(finding("GO-2025-0003"))
        remaining = gvm.remaining_findings(text, ignored)
        self.assertEqual(remaining, ["GO-2025-0003"])


if __name__ == "__main__":
    unittest.main()
