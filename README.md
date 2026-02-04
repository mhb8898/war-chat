# War Chat

Minimal E2E-encrypted chat server. [فارسی (Persian) →](README.fa.md) HTTP + WebSocket only. End-to-end encryption between users; server stores only username→pubkey and temporary offline queue (deleted after delivery). Everything else on client. Works fully offline—no external scripts or CDNs.

## Features

- **End-to-end encryption** — Messages encrypted between clients; server never sees plain text
- **Passkey or recovery phrase** — Sign in with passkey (WebAuthn) or 12-word mnemonic
- **Encrypted local storage** — Messages in IndexedDB encrypted with key derived from your credentials
- **User directory** — Browse and search registered users to start chats
- **Shareable links** — Share `/u/username` so others can message you directly
- **QR code** — Profile QR for easy sharing (bundled locally, no internet)
- **Mobile-friendly** — Responsive layout, notifications
- **Multi-account** — Multiple accounts per browser; messages scoped per user
- **Offline-first** — All assets bundled; works in air-gapped or restricted networks

## Quick Start

### Docker

```bash
docker compose up -d
```

Open http://localhost:8080

### Local

```bash
go run ./cmd/server
```

## Usage

1. **Setup** — Sign in with passkey or enter a 12-word recovery phrase (or generate one) and click Continue
2. **Register** — Choose a username and register
3. **New chat** — Click "New chat" to browse users, search, and start a conversation
4. **Share** — Copy your chat link (e.g. `http://localhost:8080/u/alice`) or share the QR code from Profile
5. **Chat** — Messages are E2E encrypted; only you and the recipient can read them

## Configuration

- `PORT` (default: 8080)
- `DATA_DIR` (default: `./data` or `/data` in Docker)

## Docker

### Multi-platform build (AMD64 + ARM64)

```bash
# Build and push both platforms (for K8s, Docker Hub, etc.)
./scripts/build-docker.sh YOUR_USERNAME/war-chat:latest

# Local build (amd64 only, load into docker)
./scripts/build-docker.sh war-chat:latest --load
```

### Docker Hub

```bash
# Log in first (one-time)
docker login

# Build and push (replace YOUR_USERNAME with your Docker Hub username)
./scripts/build-docker.sh YOUR_USERNAME/war-chat:latest
```

Pull and run:

```bash
docker run -d -p 8080:8080 -v war-chat-data:/data YOUR_USERNAME/war-chat:latest
```

> **Kubernetes**: The build uses `--provenance=false` so the manifest contains only amd64 and arm64 images. This avoids "exec format error" from K8s pulling attestation manifests by mistake.

### Security

The image uses a minimal `scratch` base (no OS, no packages) for zero vulnerabilities. Run `docker scout quickview war-chat:latest` to verify.
