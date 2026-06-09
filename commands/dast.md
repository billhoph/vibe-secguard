---
description: Run an OWASP ZAP DAST baseline scan against the running app (auto-detects the dev server URL).
argument-hint: "[url]  (optional, e.g. http://localhost:5173)"
allowed-tools: Bash(bash:*), Bash(curl:*), Bash(docker:*)
---

Run a dynamic application security test (DAST) against the live app using OWASP ZAP.

Execute this and report the results:

```bash
bash "${CLAUDE_PLUGIN_ROOT}/scripts/dast.sh" $ARGUMENTS
```

After it runs:
1. Summarize the High/Medium risk alerts ZAP found.
2. For each, explain the risk in one line and the concrete fix in the code.
3. Point the user to the saved HTML report path.
If no server was detected, tell the user to start their dev server (or pass a URL like `/dast http://localhost:3000`).
