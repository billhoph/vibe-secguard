#!/usr/bin/env bash
# vibe-secguard :: DAST runner (OWASP ZAP baseline)
# Detects the running dev server (or takes an explicit URL), then runs a ZAP
# baseline scan (passive + spider) against it. Requires Docker.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib.sh"

TARGET="${1:-}"

# --- discover a target URL if none was given -------------------------------
COMMON_PORTS=(3000 5173 4173 8080 8000 5000 3001 4200 8888 9000)
detect_url() {
  for p in "${COMMON_PORTS[@]}"; do
    if curl -s -o /dev/null --max-time 1 "http://localhost:$p" 2>/dev/null; then
      echo "http://localhost:$p"; return 0
    fi
  done
  return 1
}

if [ -z "$TARGET" ]; then
  TARGET="$(detect_url)" || {
    echo "❌ No running app detected on common ports (${COMMON_PORTS[*]})."
    echo "   Start your dev server, or pass a URL:  /dast http://localhost:PORT"
    exit 1
  }
fi
echo "🎯 DAST target: $TARGET"

if ! docker_ok; then
  echo "❌ Docker is required for the OWASP ZAP DAST scan and isn't available."
  echo "   Install/start Docker Desktop and retry."
  exit 1
fi

# On mac/win localhost on the host must be reached via host.docker.internal
ZAP_TARGET="$TARGET"
case "$TARGET" in
  *localhost*|*127.0.0.1*)
    ZAP_TARGET="$(printf '%s' "$TARGET" | sed -E 's#(localhost|127\.0\.0\.1)#'"$DOCKER_HOST_GW"'#')" ;;
esac

REPORT_DIR="${SECGUARD_PROJECT_ROOT:-$(pwd)}/.secguard"
mkdir -p "$REPORT_DIR"
STAMP="$(date +%Y%m%d-%H%M%S)"

echo "🕷️  Running OWASP ZAP baseline (spider + passive scan)…"
echo "    Reaching host as: $ZAP_TARGET"

# zap-baseline.py returns: 0 = clean, 1 = fail (alerts at FAIL level),
# 2 = warnings only. Treat 1/2 as "findings", not script error.
docker run --rm \
  --add-host="$DOCKER_HOST_GW:host-gateway" \
  -v "$REPORT_DIR:/zap/wrk:rw" \
  "$SECGUARD_ZAP_IMAGE" zap-baseline.py \
    -t "$ZAP_TARGET" \
    -r "zap-report-$STAMP.html" \
    -J "zap-report-$STAMP.json" \
    -I -m 2 -T 5
ZRC=$?

echo ""
echo "📄 Reports written to: $REPORT_DIR/zap-report-$STAMP.{html,json}"
if [ -f "$REPORT_DIR/zap-report-$STAMP.json" ]; then
  echo ""
  echo "===== TOP ALERTS ====="
  python3 -c "import json,sys
d=json.load(open('$REPORT_DIR/zap-report-$STAMP.json'))
sites=d.get('site',[])
risk={'High':0,'Medium':1,'Low':2,'Informational':3}
alerts=[]
for s in sites:
    for a in s.get('alerts',[]):
        alerts.append(a)
alerts.sort(key=lambda a: risk.get(a.get('riskdesc','').split(' ')[0],9))
for a in alerts[:15]:
    print(f\"[{a.get('riskdesc','?')}] {a.get('alert','')} (instances: {a.get('count','?')})\")
" 2>/dev/null || echo "(could not parse JSON report)"
fi

echo ""
echo "(ZAP exit code: $ZRC — 0=clean, 2=warnings, 1=failures)"
exit 0
