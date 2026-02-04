#!/bin/bash
# Build War Chat Docker image for AMD64 and ARM64
# Usage: ./scripts/build-docker.sh [tag] [--load|--push]
#   --load: build amd64 only, load into local docker
#   --push: build both platforms and push to registry (default when no --load)
# Example: ./scripts/build-docker.sh mhb8898/war-chat:1.0
# Example: ./scripts/build-docker.sh war-chat:latest --load

set -e

TAG="${1:-war-chat:latest}"
MODE="${2:---push}"
if [ "$2" = "--load" ]; then
  MODE="--load"
fi

ensure_multiarch_builder() {
  if ! docker buildx inspect multiarch &>/dev/null; then
    echo "Creating multiarch builder..."
    docker buildx create --name multiarch --driver docker-container --use
  else
    docker buildx use multiarch 2>/dev/null || true
  fi
}

if [ "$MODE" = "--load" ]; then
  echo "Building war-chat for linux/amd64 (load to local docker)..."
  docker buildx build \
    --platform linux/amd64 \
    --provenance=false \
    --sbom=false \
    -t "$TAG" \
    --load \
    .
else
  ensure_multiarch_builder
  echo "Building war-chat for linux/amd64,linux/arm64..."
  echo "Tag: $TAG (pushing to registry)"
  docker buildx build \
    --platform linux/amd64,linux/arm64 \
    --provenance=false \
    --sbom=false \
    -t "$TAG" \
    --push \
    .
fi

echo ""
echo "Done: $TAG"
echo ""
echo "Run: docker run -d -p 8080:8080 -v war-chat-data:/data $TAG"
