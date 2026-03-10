# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Go (Backend)
```bash
go run ./cmd/server          # Run server locally
go test ./...                # Run all Go tests
go test ./internal/server/   # Run server package tests only
golangci-lint run            # Lint Go code (v2.6, see .golangci.yml)
```

### JavaScript (Frontend)
```bash
npm test                     # Unit tests with Vitest
npm run e2e                  # Playwright E2E tests (headless)
npm run e2e:ui               # Playwright E2E in UI mode
npm run e2e:headed           # Playwright E2E in headed mode
npm run e2e:install          # Install Playwright browsers
```

### Docker
```bash
docker compose up -d         # Run via Docker Compose (mounts ./data:/data)
./scripts/build-docker.sh [tag] [--load|--push]  # Multi-platform build (AMD64 + ARM64)
```

## Architecture

**War Chat** is a minimal, end-to-end encrypted chat server with zero external service dependencies. Messages are encrypted client-side; the server only stores public keys and queues ciphertext for offline delivery.

### Request Flow

```
Browser → HTTP routes (internal/server/http.go)
        → WebSocket upgrade at /ws (internal/server/websocket.go)
        → Hub multiplexer → queued in ./data/offline/ if recipient offline

Browser → HRT WebSocket at /hrt/v1 (internal/server/hrt.go)
        → Room-based binary streaming for video chat
```

### Key Components

**Backend** (`internal/server/`):
- `server.go` — Initializes routes, serves embedded frontend via `go:embed`
- `http.go` — REST handlers: `/register`, `/deregister`, `/users`, `/keys/{username}`, `/admin/{token}`
- `websocket.go` — WebSocket client management and Hub for message routing
- `hrt.go` — HRT protocol: custom binary frame streaming for video (room-based, pooled buffers)
- `store.go` — File-based persistence: `./data/keys.json` (users), `./data/offline/` (queued messages), `./data/groups/` (group metadata)

**Protocol** (`internal/protocol/messages.go`):
- Client→Server: `RegisterMsg`, `AuthMsg`, `SendMsg`, `FetchKeysMsg`, `DeliveredMsg`
- Server→Client: `OfflineMessagesMsg`, `KeysResponseMsg`, `ErrorMsg`, `IncomingMsg`

**Frontend** (`internal/server/web/js/`):
- Vanilla JavaScript with Web Components — no build step, no framework
- `crypto.js` — ECDH key exchange, AES-GCM encryption, PBKDF2, mnemonic generation
- `db.js` / `crypto-storage.js` — IndexedDB abstraction with client-side encryption
- `auth.js` / `passkey.js` — WebAuthn (passkey) + 12-word mnemonic recovery
- `app.js` — Main chat UI logic and WebSocket state sync
- `groups.js` — Group chat logic
- `hrt.js` — Client-side HRT video streaming
- `state.js` — Global app state
- `components/` — Web Components (modal, chat bubbles, profile, etc.)

### Data Storage
- **Server**: JSON files under `./data/` (no database)
- **Client**: IndexedDB, with payloads encrypted using a key derived from the user's mnemonic via PBKDF2

### Authentication
Users authenticate via WebAuthn passkeys or a 12-word BIP39 mnemonic recovery phrase. The server stores only public keys — it cannot decrypt any messages.

### Configuration
Server reads from environment variables:
- `PORT` — HTTP listen port (default: 8080)
- `DATA_DIR` — Directory for persistent data (default: `./data`)
- `ADMIN_TOKEN` — Token for `/admin/{token}` reset endpoint

### Testing Notes
- Playwright config (`playwright.config.js`) starts the Go server automatically during E2E runs, or reuses an existing server if already running
- Vitest runs only `*.test.js` files in the `node` environment
- Go linting uses `errcheck`, `govet`, `staticcheck`, `goimports` (see `.golangci.yml`)
