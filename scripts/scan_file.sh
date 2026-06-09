#!/usr/bin/env bash
# vibe-secguard :: PostToolUse hook
# Runs incremental SECRET + SAST scans on the just-edited file, and SCA when a
# dependency manifest changed. Emits findings back to Claude as non-blocking
# additionalContext (warn mode) so the agent can fix issues without halting.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

# --- read hook payload from stdin -------------------------------------------
PAYLOAD="$(cat)"

read_field() {  # read_field <python-expr-on-`d`>
  printf '%s' "$PAYLOAD" | python3 -c "import sys,json
try: d=json.load(sys.stdin)
except Exception: print(''); sys.exit()
print($1)" 2>/dev/null
}

FILE="$(read_field "d.get('tool_input',{}).get('file_path') or d.get('tool_input',{}).get('notebook_path') or ''")"
export SECGUARD_PROJECT_ROOT="$(read_field "d.get('cwd') or ''")"
[ -z "$SECGUARD_PROJECT_ROOT" ] && SECGUARD_PROJECT_ROOT="$(pwd)"

# Nothing to scan / not a real file -> exit quietly.
[ -z "$FILE" ] && exit 0
[ -f "$FILE" ] || exit 0

# --- filters: skip noise -----------------------------------------------------
case "$FILE" in
  *node_modules/*|*/.git/*|*/dist/*|*/build/*|*/.venv/*|*/vendor/*|*/.next/*|*/__pycache__/*)
    exit 0 ;;
  *.lock|*.min.js|*.min.css|*.map|*.png|*.jpg|*.jpeg|*.gif|*.svg|*.ico|*.pdf|*.zip|*.woff*|*.ttf)
    exit 0 ;;
esac
# Skip files larger than 2MB.
if [ "$(wc -c < "$FILE" 2>/dev/null || echo 0)" -gt 2097152 ]; then exit 0; fi

REL="${FILE#"$SECGUARD_PROJECT_ROOT"/}"   # path relative to project root
FINDINGS=""
add() { FINDINGS+="$1"$'\n'; }

# Track which scanners (and engine) actually ran on THIS file, plus per-stage
# finding counts, so we can report "scanned <file> with <what>" even when clean.
SCANNED_DETAIL=""
note_scanner() { SCANNED_DETAIL+="${SCANNED_DETAIL:+, }$1"; }
count_lines() { printf '%s' "$1" | grep -cve '^[[:space:]]*$'; }
secret_n=0; sast_n=0; sca_n=0

# ============================================================================
# 1) SECRET SCAN
# ============================================================================
SECRET_HITS=""
case "$(secrets_engine)" in
  native)
    # gitleaks on a single file via stdin-less dir trick: scan the file path.
    OUT="$(gitleaks detect --no-git --no-banner --redact \
            --source "$FILE" --report-format json --report-path /dev/stdout 2>/dev/null)"
    SECRET_HITS="$(printf '%s' "$OUT" | python3 -c "import sys,json
try: arr=json.load(sys.stdin)
except Exception: arr=[]
for x in arr[:10]:
    print(f\"  L{x.get('StartLine','?')}: {x.get('RuleID','secret')} ({x.get('Match','')[:40]})\")" 2>/dev/null)"
    ;;
  docker)
    OUT="$(run_in_docker "$SECGUARD_GITLEAKS_IMAGE" detect --no-git --no-banner --redact \
            --source "/src/$REL" --report-format json --report-path /dev/stdout 2>/dev/null)"
    SECRET_HITS="$(printf '%s' "$OUT" | python3 -c "import sys,json
try: arr=json.load(sys.stdin)
except Exception: arr=[]
for x in arr[:10]:
    print(f\"  L{x.get('StartLine','?')}: {x.get('RuleID','secret')} ({x.get('Match','')[:40]})\")" 2>/dev/null)"
    ;;
esac
# Always run the built-in regex net too (catches things, works offline).
REGEX_HITS="$(python3 "$HERE/regex_secrets.py" "$FILE" 2>/dev/null | head -10 \
              | sed 's/^/  L/; s/:/ — /; s/:/ : /')"
[ -n "$REGEX_HITS" ] && SECRET_HITS="${SECRET_HITS}"$'\n'"${REGEX_HITS}"

# record which secret engine ran (regex net always runs)
__seng="$(secrets_engine)"
if [ "$__seng" = none ]; then note_scanner "secrets:regex"; else note_scanner "secrets:gitleaks(${__seng})+regex"; fi

if [ -n "${SECRET_HITS// /}" ]; then
  secret_n="$(count_lines "$SECRET_HITS")"
  add "🔑 SECRETS in $REL  [$secret_n hit(s), via secrets:gitleaks/${__seng}+regex]:"
  add "$SECRET_HITS"
fi

# ============================================================================
# 2) SAST  (Semgrep)
# ============================================================================
case "$FILE" in
  *.py|*.js|*.jsx|*.ts|*.tsx|*.go|*.java|*.rb|*.php|*.c|*.cpp|*.cs|*.rs|*.sh|*.tf|*.yaml|*.yml|*.json)
    SAST_HITS=""
    __asteng="$(sast_engine)"
    if [ "$__asteng" = none ]; then note_scanner "sast:skipped(no-engine)"; else note_scanner "sast:semgrep(${__asteng})"; fi
    case "$(sast_engine)" in
      native)
        OUT="$(semgrep scan --config auto --quiet --json --timeout 60 "$FILE" 2>/dev/null)"
        ;;
      docker)
        OUT="$(run_in_docker "$SECGUARD_SEMGREP_IMAGE" semgrep scan --config auto \
                --quiet --json --timeout 60 "/src/$REL" 2>/dev/null)"
        ;;
      *) OUT="" ;;
    esac
    if [ -n "$OUT" ]; then
      SAST_HITS="$(printf '%s' "$OUT" | python3 -c "import sys,json
try: d=json.load(sys.stdin)
except Exception: d={}
res=d.get('results',[])
order={'ERROR':0,'WARNING':1,'INFO':2}
res.sort(key=lambda r: order.get(r.get('extra',{}).get('severity','INFO'),3))
for r in res[:8]:
    sev=r.get('extra',{}).get('severity','INFO')
    line=r.get('start',{}).get('line','?')
    msg=(r.get('extra',{}).get('message','') or r.get('check_id','')).strip().replace(chr(10),' ')[:120]
    cid=r.get('check_id','').split('.')[-1]
    print(f'  [{sev}] L{line}: {msg} ({cid})')" 2>/dev/null)"
    fi
    if [ -n "${SAST_HITS// /}" ]; then
      sast_n="$(count_lines "$SAST_HITS")"
      add "🐞 SAST in $REL  [$sast_n finding(s), via semgrep/${__asteng}]:"
      add "$SAST_HITS"
    fi
    ;;
esac

# ============================================================================
# 3) SCA  (only when a dependency manifest changed)
# ============================================================================
case "$(basename "$FILE")" in
  package.json|package-lock.json|yarn.lock|pnpm-lock.yaml|requirements.txt|Pipfile.lock|poetry.lock|go.mod|go.sum|pom.xml|build.gradle|Gemfile.lock|composer.lock|Cargo.lock)
    DIR="$(dirname "$REL")"; [ "$DIR" = "." ] && DIR=""
    SCA_HITS=""
    __scaeng="$(sca_engine)"
    note_scanner "sca:${__scaeng}"
    case "$(sca_engine)" in
      trivy-native)
        OUT="$(trivy fs --scanners vuln --severity HIGH,CRITICAL --quiet --format json "$(dirname "$FILE")" 2>/dev/null)"
        SCA_HITS="$(printf '%s' "$OUT" | python3 "$HERE/parse_trivy.py" 2>/dev/null)" ;;
      trivy-docker)
        OUT="$(run_in_docker "$SECGUARD_TRIVY_IMAGE" fs --scanners vuln --severity HIGH,CRITICAL \
                --quiet --format json "/src/${DIR}" 2>/dev/null)"
        SCA_HITS="$(printf '%s' "$OUT" | python3 "$HERE/parse_trivy.py" 2>/dev/null)" ;;
      grype-native)
        OUT="$(grype "dir:$(dirname "$FILE")" -o json --quiet 2>/dev/null)"
        SCA_HITS="$(printf '%s' "$OUT" | python3 -c "import sys,json
try: d=json.load(sys.stdin)
except Exception: d={}
sev={'Critical':0,'High':1}
ms=[m for m in d.get('matches',[]) if m.get('vulnerability',{}).get('severity') in sev]
ms.sort(key=lambda m: sev.get(m['vulnerability']['severity'],9))
for m in ms[:8]:
    v=m['vulnerability']; a=m.get('artifact',{})
    print(f\"  [{v.get('severity')}] {a.get('name')}@{a.get('version')}: {v.get('id')}\")" 2>/dev/null)" ;;
    esac
    if [ -n "${SCA_HITS// /}" ]; then
      sca_n="$(count_lines "$SCA_HITS")"
      add "📦 SCA (vulnerable deps) in $REL  [$sca_n High/Critical, via ${__scaeng}]:"
      add "$SCA_HITS"
    fi
    ;;
esac

# ============================================================================
# emit results
# ============================================================================
total=$(( secret_n + sast_n + sca_n ))
[ -z "$SCANNED_DETAIL" ] && SCANNED_DETAIL="secrets:regex"

# --- audit log: one line per scanned file, clean or not --------------------
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
LOGDIR="$SECGUARD_PROJECT_ROOT/.secguard"
mkdir -p "$LOGDIR" 2>/dev/null \
  && printf '%s  %-50s  scanned-with[%s]  findings{secrets=%d,sast=%d,sca=%d}\n' \
       "$TS" "$REL" "$SCANNED_DETAIL" "$secret_n" "$sast_n" "$sca_n" >> "$LOGDIR/scan.log" 2>/dev/null

# --- user-facing one-liner (shown every edit unless SECGUARD_SILENT_CLEAN) --
if [ "$total" -eq 0 ]; then
  USERMSG="🛡️ vibe-secguard · scanned ${REL} · [${SCANNED_DETAIL}] · clean ✓"
else
  USERMSG="⚠️ vibe-secguard · ${total} issue(s) in ${REL} · [${SCANNED_DETAIL}] · secrets=${secret_n} sast=${sast_n} sca=${sca_n}"
fi

# Clean file: optionally stay silent for the model, but still show the user
# which file was scanned with what (set SECGUARD_SILENT_CLEAN=1 to suppress).
if [ "$total" -eq 0 ]; then
  if [ "${SECGUARD_SILENT_CLEAN:-0}" = "1" ]; then exit 0; fi
  python3 -c "import json,sys; print(json.dumps({'systemMessage': sys.argv[1], 'suppressOutput': True}))" "$USERMSG"
  exit 0
fi

HEADER="⚠️  vibe-secguard found potential security issues in the file you just changed. Please review and fix before continuing."
SCANLINE="Scanned: ${REL}  —  with [${SCANNED_DETAIL}]"
CONTEXT="${HEADER}"$'\n'"${SCANLINE}"$'\n\n'"${FINDINGS}"$'\n'"(Engines: secrets=$(secrets_engine), sast=$(sast_engine), sca=$(sca_engine). Full audit log: .secguard/scan.log · Run /secscan for a full project scan.)"

# Non-blocking: feed findings to Claude as additionalContext, and show the user
# a one-line summary of what was scanned.
python3 -c "import json,sys
print(json.dumps({
  'systemMessage': sys.argv[2],
  'hookSpecificOutput': {
    'hookEventName': 'PostToolUse',
    'additionalContext': sys.argv[1]
  }
}))" "$CONTEXT" "$USERMSG"
exit 0
