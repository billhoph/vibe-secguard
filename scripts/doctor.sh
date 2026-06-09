#!/usr/bin/env bash
# vibe-secguard :: environment diagnostics
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib.sh"

echo "===== vibe-secguard doctor ====="
echo ""
printf "Docker available: "; docker_ok && echo "yes ✅" || echo "no ❌ (Docker enables every scanner with zero installs)"
echo ""
echo "Engine resolution (native binary preferred, else Docker image):"
printf "  Secrets (gitleaks) : %s\n" "$(secrets_engine)"
printf "  SAST    (semgrep)  : %s\n" "$(sast_engine)"
printf "  SCA     (trivy)    : %s\n" "$(sca_engine)"
printf "  DAST    (owasp zap): %s\n" "$(docker_ok && echo docker || echo 'none — needs Docker')"
echo ""
echo "Native binaries detected:"
for t in semgrep gitleaks trivy grype bandit nuclei; do
  printf "  %-10s %s\n" "$t" "$(have "$t" && echo "✅ $(command -v "$t")" || echo "—")"
done
echo ""
echo "Built-in regex secret net: ✅ always on (no install needed)"
echo ""
echo "To install native tools (optional — Docker covers all of them):"
echo "  brew install semgrep gitleaks trivy   # macOS"
echo "  pipx install semgrep                  # cross-platform SAST"
echo ""
echo "Tip: native binaries are faster per-edit than Docker (no container start-up)."
