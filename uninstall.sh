#!/usr/bin/env bash
# vibe-secguard uninstaller — removes the hook + commands from your config.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
SETTINGS="$CLAUDE_DIR/settings.json"

python3 - "$SETTINGS" "$ROOT/scripts/scan_file.sh" <<'PY'
import json, os, sys
sp, script = sys.argv[1], sys.argv[2]
if not os.path.exists(sp):
    sys.exit(0)
try:
    d = json.load(open(sp))
except Exception:
    sys.exit(0)
pt = d.get("hooks", {}).get("PostToolUse", [])
for b in list(pt):
    b["hooks"] = [h for h in b.get("hooks", []) if h.get("command") != script]
    if not b["hooks"]:
        pt.remove(b)
if "hooks" in d and not pt:
    d["hooks"].pop("PostToolUse", None)
json.dump(d, open(sp, "w"), indent=2)
print("  ✓ hook removed from", sp)
PY

for c in secscan dast secguard-doctor; do
  rm -f "$CLAUDE_DIR/commands/$c.md"
done
echo "  ✓ commands removed"
echo "✅ vibe-secguard uninstalled (open /hooks or restart to apply)."
