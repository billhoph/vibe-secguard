---
description: Check which vibe-secguard scanners are available (native vs Docker) and how to enable the rest.
allowed-tools: Bash(bash:*), Bash(docker:*)
---

Diagnose the vibe-secguard environment.

Run this:

```bash
bash "${CLAUDE_PLUGIN_ROOT}/scripts/doctor.sh"
```

Then briefly tell the user which of SCA / Secrets / SAST / DAST are ready, and give the one-line install command for anything missing.
