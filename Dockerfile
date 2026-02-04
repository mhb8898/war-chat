# syntax=docker/dockerfile:1
# Build: ./scripts/build-docker.sh war-chat:latest

ARG BUILDPLATFORM=linux/amd64
ARG TARGETARCH=amd64

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -ldflags="-s -w" -o /war-chat ./cmd/server

# Minimal final image - scratch has zero vulnerabilities (no OS, no packages)
# Server makes no outbound HTTPS calls, so no ca-certificates needed
FROM scratch
COPY --from=builder /war-chat /war-chat

ENV PORT=8080
ENV DATA_DIR=/data

EXPOSE 8080
VOLUME /data

HEALTHCHECK --interval=10s --timeout=5s --retries=3 --start-period=5s \
  CMD ["/war-chat", "-healthcheck"]

ENTRYPOINT ["/war-chat"]
