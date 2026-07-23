#!/usr/bin/env bash
# Build eudi-srv-statuslist locally (no published GHCR image).
# Skips when the image tag already exists unless FORCE_EUDI_STATUSLIST_BUILD=1.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOCKER_DIR="$ROOT/deployment/helm/charts/eudi-statuslist/docker"
IMAGE="${EUDI_STATUSLIST_IMAGE:-eudi-srv-statuslist:v0.9.0}"
VERSION="${EUDI_STATUSLIST_VERSION:-v0.9.0}"

if [[ "${FORCE_EUDI_STATUSLIST_BUILD:-0}" != "1" ]]; then
  if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "EUDI statuslist image already present: $IMAGE (skip build; set FORCE_EUDI_STATUSLIST_BUILD=1 to rebuild)"
    exit 0
  fi
fi

echo "Building $IMAGE (upstream tag $VERSION)..."
docker build \
  --build-arg "VERSION=$VERSION" \
  -t "$IMAGE" \
  "$DOCKER_DIR"

echo "Built $IMAGE"
