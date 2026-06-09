---
description: Run a full project security scan — Secrets + SAST + SCA across the whole repo.
argument-hint: "[path]  (optional, defaults to current project)"
allowed-tools: Bash(bash:*), Bash(docker:*)
---

Run a full static security sweep of the project (secret scanning, SAST, and dependency/SCA scanning).

Execute this and report the results:

```bash
bash "${CLAUDE_PLUGIN_ROOT}/scripts/full_scan.sh" $ARGUMENTS
```

Then produce a prioritized summary: group findings by severity (Critical → High → Medium), and for the top issues propose the specific code or dependency fix. Offer to apply the fixes.
