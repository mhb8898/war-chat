# syntax=docker/dockerfile:1
# Build: ./scripts/build-docker.sh war-chat:latest

ARG BUILDPLATFORM=linux/amd64
ARG TARGETARCH=amd64

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
ENV GOTOOLCHAIN=local
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -ldflags="-s -w" -o /war-chat ./cmd/server

# Minimal final image - scratch has zero OS surface (no shell, no packages)
# Server makes no outbound HTTPS calls, so no ca-certificates needed
FROM scratch

# Run as non-root (nobody) for better security posture in scans.
# Ensure the /data volume is writable by UID 65534, e.g.:
#   docker run -v war-chat-data:/data ... (named volume) or
#   chown 65534:65534 ./data && docker run -v $(pwd)/data:/data ...
USER 65534:65534

COPY --from=builder /war-chat /war-chat

ENV PORT=8080
ENV DATA_DIR=/data

EXPOSE 8080
VOLUME /data

# OCI labels for image metadata and registries
LABEL org.opencontainers.image.source="https://github.com/war-chat/war-chat" \
      org.opencontainers.image.description="E2E encrypted chat server"

HEALTHCHECK --interval=10s --timeout=5s --retries=3 --start-period=5s \
  CMD ["/war-chat", "-healthcheck"]

ENTRYPOINT ["/war-chat"]
