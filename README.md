# MCP Payload Firewall

An edge-deployed reverse proxy that intercepts [Model Context Protocol](https://modelcontextprotocol.io) traffic, scans every request and response for PII and credentials, and redacts or blocks matching content before it reaches an AI agent's context.

Built with Next.js 15, deployed on Vercel Edge Runtime, with a control-plane dashboard for managing DLP rules and viewing audit logs.

## How it works

```
MCP Client → /api/proxy/* → [DLP Firewall] → Upstream MCP Server
                                   ↓
                            Audit Log (Postgres)
```

Every request and response transits the firewall. Rules are stored in Postgres and synced to Vercel Edge Config for sub-millisecond reads on the hot path. Three severity levels:

- **block** — reject the entire request with a JSON-RPC 403 error; nothing reaches upstream
- **redact** — replace matched text with a configurable replacement string (default `[REDACTED]`)
- **warn** — log the match to the audit trail; payload passes through unchanged

## Stack

| Layer | Technology |
|-------|-----------|
| Framework | Next.js 15 (App Router) |
| Edge Proxy | Vercel Edge Runtime |
| Rule store (hot path) | Vercel Edge Config |
| Database | Neon Postgres + Drizzle ORM |
| Auth | Auth.js v5 (GitHub OAuth) |
| UI | Tailwind CSS + shadcn/ui |

## Proxy usage

Point your MCP client at `/api/proxy/*` instead of the upstream server directly. Pass the upstream URL in the `X-MCP-Target` header:

```http
POST https://your-deployment.vercel.app/api/proxy/messages
Content-Type: application/json
X-MCP-Target: https://your-mcp-server.example.com

{"role":"user","content":"Here is my key: sk-abc123..."}
```

The path after `/api/proxy` is forwarded verbatim. Query strings are preserved. You can also set a default upstream via the `UPSTREAM_MCP_URL` environment variable and omit the header.

### Quick test

```powershell
Invoke-WebRequest -Uri "https://your-deployment.vercel.app/api/proxy/post" `
  -Method POST `
  -Headers @{ "Content-Type" = "application/json"; "X-MCP-Target" = "https://httpbin.org" } `
  -Body '{"key":"sk-abc123secretkey"}'
# → "data": "{\"key\":\"[REDACTED]\"}"
```

## Dashboard

The control plane lives at `/dashboard` and is protected by GitHub OAuth. Only the email address in `ADMIN_EMAIL` can sign in.

- **Rules** — create, edit, enable/disable, or delete DLP rules. Changes sync to Edge Config immediately.
- **Logs** — paginated audit trail of every firewall event: severity, matched path, matched text, and rule name.
- **Dashboard** — stats overview: total rules, active rules, blocked streams, redacted payloads.

### Suggested starter rules

| Name | Pattern | Severity |
|------|---------|----------|
| OpenAI API Key | `sk-[a-zA-Z0-9]+` | redact |
| Anthropic API Key | `sk-ant-[A-Za-z0-9_-]+` | redact |
| GitHub Token | `gh[pousr]_[A-Za-z0-9]{36,}` | redact |
| AWS Access Key | `AKIA[0-9A-Z]{16}` | block |
| Private Key (PEM) | `-----BEGIN( RSA)? PRIVATE KEY-----` | block |
| JWT Token | `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` | redact |
| DB Connection String | `(postgres\|mysql\|mongodb)://[^:]+:[^@]+@` | redact |
| US Social Security # | `\b\d{3}-\d{2}-\d{4}\b` | redact |
| Email Address | `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}` | warn |

## Local development

```bash
pnpm install
cp .env.local.example .env.local   # fill in all values
pnpm db:push                        # push schema to Neon
pnpm dev
```

The edge proxy runs as a Node.js route in local dev (Edge Runtime blocks outbound fetch locally). Use the `/api/echo` endpoint as a local upstream for testing — it echoes the request body back:

```powershell
Invoke-WebRequest -Uri "http://localhost:3000/api/proxy/api/echo" `
  -Method POST `
  -Headers @{ "Content-Type" = "application/json"; "X-MCP-Target" = "http://localhost:3000" } `
  -Body '{"key":"sk-abc123"}'
```

## Deployment

### 1. Neon Postgres

Create a project at [neon.tech](https://neon.tech). Copy the pooled and unpooled connection strings.

### 2. GitHub OAuth App

Create an OAuth App at [github.com/settings/developers](https://github.com/settings/developers):
- Homepage URL: `https://your-deployment.vercel.app`
- Callback URL: `https://your-deployment.vercel.app/api/auth/callback/github`

### 3. Vercel Edge Config

Create an Edge Config store in your Vercel project under **Storage → Edge Config**. Connect it to your project to get the `EDGE_CONFIG` connection string.

### 4. Environment variables

Set all of the following in Vercel → **Settings → Environment Variables**:

```bash
DATABASE_URL=              # Neon pooled connection string
DATABASE_URL_UNPOOLED=     # Neon unpooled (for migrations only)
AUTH_SECRET=               # openssl rand -base64 32
AUTH_GITHUB_ID=            # GitHub OAuth App client ID
AUTH_GITHUB_SECRET=        # GitHub OAuth App client secret
ADMIN_EMAIL=               # GitHub account email allowed to sign in
EDGE_CONFIG=               # Vercel Edge Config connection string
VERCEL_EDGE_CONFIG_TOKEN=  # Vercel API token with Edge Config write access
UPSTREAM_MCP_URL=          # Default upstream MCP server URL
FIREWALL_INTERNAL_KEY=     # Random secret shared between edge proxy and /api/logs
```

Generate secrets:
```bash
openssl rand -base64 32    # AUTH_SECRET
openssl rand -hex 32       # FIREWALL_INTERNAL_KEY
```

### 5. Deploy

Push to your connected GitHub repository. Vercel builds and deploys automatically.

After the first deploy, add at least one DLP rule from the dashboard — this triggers the initial Edge Config sync.

## Architecture notes

**Why Edge Config instead of a database on the hot path?**
Vercel Edge Config is an in-process key-value store — reads are under 1ms with no network round-trip. The edge proxy reads the full rule set from Edge Config on every request. Drizzle ORM cannot run in the Edge Runtime (no TCP), so the proxy delegates all DB writes to the Node.js `/api/logs` route via an internal HTTP call.

**Why buffer responses instead of streaming through a TransformStream?**
For standard JSON-RPC responses (the MCP norm), buffering lets the firewall return a clean JSON-RPC error when a block-severity rule fires — the HTTP status and headers are not committed until the full body is scanned. SSE responses (`text/event-stream`) still use a streaming TransformStream, where a block aborts the stream rather than returning a clean error.

**Why regex instead of Aho-Corasick WASM?**
The compiled regex engine in V8 is fast enough for DLP rule counts in the tens. The Rust/WASM Aho-Corasick engine described in the original plan is the right upgrade path once rule counts grow into the hundreds.
