#!/usr/bin/env bash
# Shared helpers for vibe-secguard scanners.
# Strategy: prefer a native binary if installed; otherwise fall back to a
# pinned Docker image so the user doesn't have to install each scanner.

# ---- generic helpers --------------------------------------------------------

have() { command -v "$1" >/dev/null 2>&1; }

docker_ok() { have docker && docker info >/dev/null 2>&1; }

# host.docker.internal works on Docker Desktop (mac/win). On Linux we add a
# host-gateway mapping when launching containers that need to reach the host.
DOCKER_HOST_GW="host.docker.internal"

# Pinned images (override via env in settings if desired).
: "${SECGUARD_SEMGREP_IMAGE:=semgrep/semgrep:1.95.0}"
: "${SECGUARD_GITLEAKS_IMAGE:=zricethezav/gitleaks:v8.21.2}"
: "${SECGUARD_TRIVY_IMAGE:=aquasec/trivy:0.57.0}"
: "${SECGUARD_ZAP_IMAGE:=ghcr.io/zaproxy/zaproxy:stable}"

# run a docker scanner with the project mounted read-only at /src
# usage: run_in_docker <image> <args...>
run_in_docker() {
  local image="$1"; shift
  docker run --rm \
    -v "${SECGUARD_PROJECT_ROOT}:/src:ro" \
    -w /src \
    "$image" "$@"
}

# ---- engine selection -------------------------------------------------------
# Each returns one of: native | docker | none

secrets_engine() {
  if have gitleaks; then echo native
  elif docker_ok;   then echo docker
  else echo none; fi
}

sast_engine() {
  if have semgrep; then echo native
  elif docker_ok;  then echo docker
  else echo none; fi
}

sca_engine() {
  if have trivy;  then echo trivy-native
  elif have grype; then echo grype-native
  elif docker_ok; then echo trivy-docker
  else echo none; fi
}

# ---- logging ----------------------------------------------------------------
log() { printf '%s\n' "$*" >&2; }
