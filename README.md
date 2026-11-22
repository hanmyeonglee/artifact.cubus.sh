# artifact.cubus.sh

MCP-powered artifact publishing and read-only web viewer service for `cubus.sh`. AI agents upload HTML, PDF, Markdown, SVG, and image artifacts over Streamable HTTP MCP with OAuth 2.1, and users view them in a sandboxed browser UI.

## Features

- **Streamable HTTP MCP (`/mcp`)** with self-hosted **OAuth 2.1** (`PKCE S256`, Dynamic Client Registration, Protected Resource Metadata, RFC 8707 resource indicators, refresh-token rotation + reuse detection, RFC 7009 revocation).
- **Supported formats:** `text/html`, `application/pdf`, `text/markdown`, `image/svg+xml`, `image/png`, `image/jpeg`, `image/webp`.
- **Visibility:** `private` (default, owner-only with uniform `404` for unauthorized requests) or `public` (anyone with `/v/{id}` link, `noindex`).
- **Two upload paths:**
  - `publish_artifact` / `update_artifact` for inline UTF-8 text (≤ 4 MiB) or small base64 binaries (≤ 1 MiB).
  - `create_upload` → 5-minute single-use `PUT /upload/{token}` for PDFs and larger files (up to `max_upload_mb`, default 20 MiB).
- **Sandboxed viewer:** HTML renders inside `<iframe sandbox="allow-scripts">` with strict CSP (`connect-src 'none'`, curated CDN allowlist, zero `cubus.sh` cookies). Markdown renders server-side with `goldmark` + `bluemonday`.
- **PostgreSQL-backed & stateless container:** All metadata, blobs, sessions, and OAuth tokens live in PostgreSQL (`db-broker` in `cubus.sh`, or local `postgres` in standalone mode).
- **Optional Internal Admin API (`:9090`):** Disabled unless `ADMIN_API_TOKEN` is set; binds strictly to the `ADMIN_BIND_CIDR` interface (or `127.0.0.1` locally) for future `admin.cubus.sh` integration.

## MCP Tools

| Tool | Required Scope | Description |
| :--- | :--- | :--- |
| `publish_artifact` | `artifacts:write` | Publish inline HTML/Markdown/SVG (≤ 4 MiB) or base64 binary (≤ 1 MiB). |
| `create_upload` | `artifacts:write` | Mint a 5-minute single-use `PUT /upload/{token}` URL for PDFs/binaries (or in-place replacement via `artifact_id`). |
| `update_artifact` | `artifacts:write` | Update title, visibility, and/or inline content in place (`version++`). |
| `list_artifacts` | `artifacts:read` | List caller's ready artifacts with visibility, content-type, and title filters. |
| `get_artifact` | `artifacts:read` | Retrieve metadata and optional inline text content (≤ 512 KiB). |
| `delete_artifact` | `artifacts:write` | Permanently delete an owned artifact. |

## Environment Variables

Copy `.env.example` to `.env` before starting:

```sh
cp .env.example .env
```

| Variable | Required | Description |
| :--- | :--- | :--- |
| `BOOTSTRAP_ADMIN_USERNAME` | First boot only | Initial active admin username (`^[a-z0-9._-]{3,64}$`). Skipped automatically once any admin exists in DB. |
| `BOOTSTRAP_ADMIN_PASSWORD` | First boot only | Initial admin password (`12..128` bytes, cannot be a `replace-with-*` placeholder). |
| `ADMIN_API_TOKEN` | No | Optional Bearer token (`≥ 16` bytes) enabling the internal-only `:9090` Admin API. Leave unset to keep `:9090` disabled. |

Additional runtime variables injected by `docker-compose.yml` (standalone) or root `cubus.sh`:

- `DB_BROKER_URL` (production via `cubus.sh`) or `DATABASE_URL` (standalone dev) — `DB_BROKER_URL` takes precedence.
- `PUBLIC_BASE_URL` — canonical origin (e.g. `https://artifact.cubus.sh`; `http://` is permitted only for loopback hosts).
- `ADMIN_BIND_CIDR` — optional CIDR (`172.31.0.0/24` in `cubus.sh`) restricting the `:9090` bind IP and accepted client peers.
- `LISTEN_ADDR` — default `:8000`.
- `ADMIN_PORT` — default `9090`.

## Local Standalone Development

```sh
cp .env.example .env
# Edit .env with a strong BOOTSTRAP_ADMIN_PASSWORD
docker compose up --build
```

- Web UI: `http://127.0.0.1:8000/`
- MCP Endpoint: `http://127.0.0.1:8000/mcp`
- Healthcheck: `http://127.0.0.1:8000/healthz`

Run tests locally (requires Go 1.27+):

```sh
go vet ./...
go test -v -race ./...
```

## Connecting an MCP Client

Point any OAuth 2.1-capable MCP client (Claude, ChatGPT, Codex, MCP Inspector, etc.) to:

```text
https://artifact.cubus.sh/mcp
```

The client automatically discovers `/.well-known/oauth-protected-resource/mcp` → `/.well-known/oauth-authorization-server`, registers via `/oauth/register`, opens `/oauth/authorize` for sign-in and consent, and exchanges PKCE codes at `/oauth/token`.

## Deployment Contract (`cubus.sh`)

- `compose.service.yml` defines the service build, `expose: ["8000"]`, `read_only: true`, hardened capabilities, `.env` loading, and `-healthcheck`.
- Root `cubus.sh/docker-compose.yml` wires `VIRTUAL_HOST`, `VIRTUAL_PORT`, `PUBLIC_BASE_URL`, `DB_BROKER_URL`, `ADMIN_BIND_CIDR`, and the `web`, `db`, and `admin` networks via `extends`.
- `cubus.sh/config/vhost.d/artifact.cubus.sh_location` configures `client_max_body_size 55m;` for binary `PUT /upload/{token}` uploads.
