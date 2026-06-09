#!/usr/bin/env bash
# vibe-secguard installer (manual / no-/plugin path).
# Wires the scan hook + slash commands into your Claude Code config.
# Portable: derives its own path, no hardcoded user directories.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
SETTINGS="$CLAUDE_DIR/settings.json"
CMD_DIR="$CLAUDE_DIR/commands"

echo "🛡️  Installing vibe-secguard from: $ROOT"
mkdir -p "$CLAUDE_DIR" "$CMD_DIR"
chmod +x "$ROOT"/scripts/*.sh "$ROOT"/scripts/*.py 2>/dev/null || true

# 1) Merge the PostToolUse hook into settings.json (idempotent) -------------
python3 - "$SETTINGS" "$ROOT/scripts/scan_file.sh" <<'PY'
import json, os, sys
settings_path, script = sys.argv[1], sys.argv[2]
data = {}
if os.path.exists(settings_path):
    try:
        data = json.load(open(settings_path))
    except Exception:
        print("  ! existing settings.json is invalid JSON — aborting to avoid clobbering it")
        sys.exit(1)
matcher = "Write|Edit|MultiEdit|NotebookEdit"
entry = {"type": "command", "command": script, "timeout": 120,
         "statusMessage": "vibe-secguard: scanning edited file…"}
pt = data.setdefault("hooks", {}).setdefault("PostToolUse", [])
block = next((b for b in pt if b.get("matcher") == matcher), None)
if block is None:
    block = {"matcher": matcher, "hooks": []}
    pt.append(block)
block.setdefault("hooks", [])
if not any(h.get("command") == script for h in block["hooks"]):
    block["hooks"].append(entry)
json.dump(data, open(settings_path, "w"), indent=2)
print("  ✓ hook merged into", settings_path)
PY

# 2) Install slash commands with the plugin-root placeholder resolved -------
for c in secscan dast secguard-doctor; do
  sed "s#\${CLAUDE_PLUGIN_ROOT}#$ROOT#g" "$ROOT/commands/$c.md" > "$CMD_DIR/$c.md"
done
echo "  ✓ commands installed: /secscan /dast /secguard-doctor"

echo ""
echo "✅ Done. One more step: open the /hooks menu once (or restart Claude Code)"
echo "   so the config watcher picks up the new hook."
echo "   Then run  /secguard-doctor  to confirm your scanners are ready."
