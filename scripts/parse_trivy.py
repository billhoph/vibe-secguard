#!/usr/bin/env python3
"""Parse `trivy fs --format json` output into compact one-line findings."""
import json
import sys

try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)

order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
rows = []
for res in d.get("Results", []) or []:
    for v in res.get("Vulnerabilities", []) or []:
        rows.append(v)

rows.sort(key=lambda v: order.get(v.get("Severity", "LOW"), 9))
for v in rows[:10]:
    fixed = v.get("FixedVersion", "")
    fix = f" → fix: {fixed}" if fixed else " (no fix yet)"
    print(
        f"  [{v.get('Severity')}] {v.get('PkgName')}@{v.get('InstalledVersion')}: "
        f"{v.get('VulnerabilityID')}{fix}"
    )
