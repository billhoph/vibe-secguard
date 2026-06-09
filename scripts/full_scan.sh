#!/usr/bin/env bash
# vibe-secguard :: full project scan (Secrets + SAST + SCA across the repo)
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib.sh"

export SECGUARD_PROJECT_ROOT="${1:-$(pwd)}"
cd "$SECGUARD_PROJECT_ROOT" || exit 1
echo "🔍 vibe-secguard full scan :: $SECGUARD_PROJECT_ROOT"
echo "    engines -> secrets=$(secrets_engine)  sast=$(sast_engine)  sca=$(sca_engine)"
echo ""

# ---- Secrets ---------------------------------------------------------------
echo "===== 🔑 SECRET SCAN ====="
case "$(secrets_engine)" in
  native) gitleaks detect --no-git --no-banner --redact --source "$SECGUARD_PROJECT_ROOT" --verbose 2>&1 | tail -40 || true ;;
  docker) run_in_docker "$SECGUARD_GITLEAKS_IMAGE" detect --no-git --no-banner --redact --source /src --verbose 2>&1 | tail -40 || true ;;
  none)   echo "(no engine; running built-in regex net)"
          find . -type f -not -path '*/node_modules/*' -not -path '*/.git/*' -not -path '*/dist/*' \
            \( -name '*.js' -o -name '*.ts' -o -name '*.py' -o -name '*.env*' -o -name '*.json' -o -name '*.yml' -o -name '*.yaml' \) 2>/dev/null \
            | while read -r f; do python3 "$HERE/regex_secrets.py" "$f" | sed "s#^#$f L#"; done ;;
esac
echo ""

# ---- SAST ------------------------------------------------------------------
echo "===== 🐞 SAST (Semgrep) ====="
case "$(sast_engine)" in
  native) semgrep scan --config auto --quiet --error 2>&1 | tail -60 || true ;;
  docker) run_in_docker "$SECGUARD_SEMGREP_IMAGE" semgrep scan --config auto --quiet 2>&1 | tail -60 || true ;;
  none)   echo "(no Semgrep / Docker available — skipping SAST)" ;;
esac
echo ""

# ---- SCA -------------------------------------------------------------------
echo "===== 📦 SCA (dependency vulnerabilities) ====="
case "$(sca_engine)" in
  trivy-native) trivy fs --scanners vuln --severity HIGH,CRITICAL --quiet "$SECGUARD_PROJECT_ROOT" 2>&1 | tail -60 || true ;;
  trivy-docker) run_in_docker "$SECGUARD_TRIVY_IMAGE" fs --scanners vuln --severity HIGH,CRITICAL --quiet /src 2>&1 | tail -60 || true ;;
  grype-native) grype "dir:$SECGUARD_PROJECT_ROOT" --quiet 2>&1 | tail -60 || true ;;
  none)         echo "(no Trivy / Grype / Docker available — skipping SCA)" ;;
esac
echo ""
echo "✅ Full scan complete."
