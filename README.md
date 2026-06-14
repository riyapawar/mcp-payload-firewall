# MCP Payload Firewall

A reverse proxy that intercepts [Model Context Protocol](https://modelcontextprotocol.io) traffic and scans every payload for credentials, PII, and sensitive data before it reaches an AI agent's context — or before your agent sends it to an external server.

**Live demo:** [mcp-payload-firewall.vercel.app](https://mcp-payload-firewall.vercel.app)  
**Dashboard:** [mcp-payload-firewall.vercel.app/dashboard](https://mcp-payload-firewall.vercel.app/dashboard)

---

## The problem

MCP servers connect AI agents to real systems — filesystems, databases, internal APIs. Those systems often return (or receive) sensitive data: API keys, database credentials, PII, internal tokens. Without a filter layer, that data lands directly in the agent's context or gets sent to third-party MCP servers.

The firewall sits between your MCP client and the upstream server and applies DLP rules to every payload in both directions.

```
Without firewall:
  MCP Client ──────────────────────────► MCP Server
                (API key in plaintext)

With firewall:
  MCP Client ──► firewall.vercel.app ──► MCP Server
                    │
                    ├─ auth: verify Bearer token
                    ├─ request: matches "sk-..." rule → "[REDACTED]"
                    ├─ request: matches "RSA key" rule → 403 blocked
                    ├─ response: scan MCP server's reply too
                    └─ audit log: direction, server name, matched rule
```

---

## Security model

Three mechanisms work together:

**API token authentication** — every proxy request must include a `Bearer` token generated in the dashboard. Tokens are never stored; only their SHA-256 hash is persisted. If no tokens exist yet, the proxy is open (useful during setup); once the first token is created, auth is enforced on all traffic.

**Named server registry** — upstream MCP servers are registered by name in the dashboard. The proxy resolves `X-MCP-Server: production` to the stored URL. Free-form `X-MCP-Target` URLs are rejected once a registry exists, eliminating SSRF.

**DLP rule engine** — two detection layers run on every request and response payload:
- **Regex** — exact pattern matching, sub-millisecond, no external calls
- **AI (semantic)** — GPT-4o-mini classifies each payload against a plain-English description, catching novel formats and context-dependent data that regex can't know about (~300ms added latency)

---

## Severity levels

| Level | Behavior |
|-------|----------|
| **block** | Reject the entire request with a JSON-RPC error. Nothing reaches upstream. |
| **redact** | Replace the matched text inline with a configurable replacement string. |
| **warn** | Log the match to the audit trail. Payload passes through unchanged. |

---

## How to integrate

### 1. Register your MCP server

In the dashboard → **MCP Servers → Register server**:

| Field | Example |
|-------|---------|
| Name | `production` |
| URL | `https://your-mcp-server.example.com` |

### 2. Create an API token

In the dashboard → **API Tokens → Create**. Copy the token when it appears — it is shown once.

### 3. Point your MCP client at the proxy

Replace the upstream URL with the firewall's proxy endpoint. Pass the registered server name and your token:

```
POST https://your-deployment.vercel.app/api/proxy/messages
Authorization: Bearer mcpfw_...
X-MCP-Server: production
Content-Type: application/json
```

The path after `/api/proxy` is forwarded verbatim to the registered server.

### Claude Desktop

In `~/.config/claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "my-server": {
      "url": "https://your-deployment.vercel.app/api/proxy/mcp",
      "headers": {
        "Authorization": "Bearer mcpfw_...",
        "X-MCP-Server": "production"
      }
    }
  }
}
```

---

## Starter DLP rules

Add these from **Dashboard → DLP Rules**:

| Name | Detection | Pattern / Description | Severity |
|------|-----------|----------------------|----------|
| OpenAI API Key | Regex | `sk-[a-zA-Z0-9]{20,}` | redact |
| Anthropic API Key | Regex | `sk-ant-[A-Za-z0-9_-]+` | redact |
| GitHub Token | Regex | `gh[pousr]_[A-Za-z0-9]{36,}` | redact |
| AWS Access Key | Regex | `AKIA[0-9A-Z]{16}` | block |
| Private Key (PEM) | Regex | `-----BEGIN( RSA)? PRIVATE KEY-----` | block |
| JWT Token | Regex | `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` | redact |
| DB Connection String | Regex | `(postgres\|mysql\|mongodb)://[^:]+:[^@]+@` | block |
| SSN | Regex | `\b\d{3}-\d{2}-\d{4}\b` | redact |
| Internal API tokens | AI | "API keys, tokens, and credentials of any format" | redact |
| Email Address | Regex | `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}` | warn |

---

## Demo

Run against the live deployment (no auth required on demo — no tokens configured):

```powershell
$base = "https://mcp-payload-firewall.vercel.app/api/proxy/post"
$h = @{ "Content-Type" = "application/json"; "X-MCP-Target" = "https://httpbin.org" }

# REDACT — OpenAI key (regex rule)
Invoke-WebRequest -Uri $base -Method POST -Headers $h `
  -Body '{"prompt":"use key sk-abc123secretkeyABCDEFGHIJ to call the API"}' -UseBasicParsing |
  ConvertFrom-Json | Select-Object -ExpandProperty data
# → {"prompt":"use key [REDACTED] to call the API"}

# REDACT — novel internal token (AI semantic rule)
Invoke-WebRequest -Uri $base -Method POST -Headers $h `
  -Body '{"auth":"my-internal-token-xK9mPqR3vN7wL2jY"}' -UseBasicParsing |
  ConvertFrom-Json | Select-Object -ExpandProperty data
# → {"auth":"[REDACTED]"}

# BLOCK — RSA private key
try {
  Invoke-WebRequest -Uri $base -Method POST -Headers $h `
    -Body '{"key":"-----BEGIN RSA PRIVATE KEY-----"}' -UseBasicParsing
} catch {
  $_.Exception.Response.GetResponseStream() |
    ForEach-Object { [System.IO.StreamReader]::new($_).ReadToEnd() }
}
# → {"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Request payload blocked by DLP rule: RSA Private Key"}}
```

Or run the bundled script: `powershell -ExecutionPolicy Bypass -File demo.ps1`

---

## Deployment

### 1. Neon Postgres

Create a project at [neon.tech](https://neon.tech) (free tier works). Copy:
- Pooled connection string → `DATABASE_URL`
- Unpooled connection string → `DATABASE_URL_UNPOOLED`

### 2. GitHub OAuth App

At [github.com/settings/developers](https://github.com/settings/developers) → **OAuth Apps → New**:
- Homepage URL: `https://your-deployment.vercel.app`
- Callback URL: `https://your-deployment.vercel.app/api/auth/callback/github`

If you use a custom domain, add a second callback: `https://your-domain.com/api/auth/callback/github`

Copy **Client ID** → `AUTH_GITHUB_ID` and generate **Client Secret** → `AUTH_GITHUB_SECRET`.

### 3. Deploy to Vercel

Fork/push this repo and import at [vercel.com/new](https://vercel.com/new). Vercel detects Next.js automatically.

### 4. Vercel Edge Config

In your Vercel project → **Storage → Edge Config → Create**. Connect the store to your project (generates `EDGE_CONFIG`). Then **Settings → Tokens → Create** with Edge Config write scope → `VERCEL_EDGE_CONFIG_TOKEN`.

### 5. Environment variables

In Vercel → **Settings → Environment Variables**:

```bash
# Database (Neon)
DATABASE_URL=              # pooled connection string
DATABASE_URL_UNPOOLED=     # unpooled (for drizzle-kit migrations)

# Auth.js
AUTH_SECRET=               # openssl rand -base64 32
AUTH_GITHUB_ID=
AUTH_GITHUB_SECRET=
ADMIN_EMAIL=               # GitHub account email allowed to sign in

# Vercel Edge Config
EDGE_CONFIG=               # connection string from Storage → Edge Config
VERCEL_EDGE_CONFIG_TOKEN=  # Vercel API token with Edge Config write access

# Proxy
UPSTREAM_MCP_URL=          # optional single-server fallback (used without X-MCP-Server)
FIREWALL_INTERNAL_KEY=     # openssl rand -hex 32
OPENAI_API_KEY=            # required for AI-type rules; omit to use regex only
```

### 6. Run migrations

```bash
pnpm db:push
```

### 7. First-time setup

1. Sign in at `/dashboard` with the GitHub account matching `ADMIN_EMAIL`.
2. **MCP Servers** → register your upstream server.
3. **DLP Rules** → add rules. Saving triggers an automatic Edge Config sync.
4. **API Tokens** → create a token. Copy it — it won't be shown again.
5. Update your MCP client config to use the proxy URL, token, and server name.

---

## Local development

```bash
git clone https://github.com/yourusername/mcp-payload-firewall
cd mcp-payload-firewall
pnpm install
cp .env.local.example .env.local   # fill in all values
pnpm db:push
pnpm dev
```

Test against httpbin (no registered servers needed in local dev — `X-MCP-Target` still works):

```powershell
Invoke-WebRequest -Uri "http://localhost:3000/api/proxy/post" `
  -Method POST `
  -Headers @{ "Content-Type" = "application/json"; "X-MCP-Target" = "https://httpbin.org" } `
  -Body '{"key":"sk-abc123secretkey"}'
```

---

## Architecture

```
Request ──► Edge Proxy (Vercel Edge Runtime)
                │
                ├── Verify Bearer token (SHA-256 hash in Edge Config)
                ├── Resolve X-MCP-Server name → URL (Edge Config registry)
                ├── Load DLP rules from Edge Config (< 1ms, in-process)
                │
                ├── Scan request body
                │     ├── Regex rules → V8 RegExp engine
                │     └── AI rules → GPT-4o-mini (8s AbortController timeout)
                │
                ├── Forward to upstream MCP server
                │
                └── Scan response body (same pipeline)
                        │
                        ├── block  → JSON-RPC error {"code":-32600}
                        ├── redact → replace match, return to client
                        └── warn   → log to /api/logs (Node runtime, Neon Postgres)

Dashboard (Next.js, Node runtime)
    ├── /api/rules   → CRUD rules in Neon, sync to Edge Config
    ├── /api/servers → CRUD server registry, sync to Edge Config
    ├── /api/tokens  → create/revoke tokens, sync SHA-256 hashes to Edge Config
    └── /api/logs    → audit log reads (direction: request|response, server name)
```

**Why Edge Config?** In-process key-value store — reads under 1ms, no network round-trip. Drizzle ORM (Neon) can't open TCP in Edge Runtime, so all DB writes are delegated to the Node.js API routes via an authenticated internal HTTP call.

**Why buffer instead of streaming?** For standard JSON-RPC responses, buffering lets the firewall return a clean JSON-RPC error on block — HTTP headers aren't committed until the full body is scanned. SSE (`text/event-stream`) streams through a TransformStream, where a block aborts the stream.

**Why is token auth opt-in?** If no tokens exist, the proxy passes all traffic — same behavior as before. The moment you create the first token from the dashboard, auth is enforced globally. This avoids a footgun where someone deploys, adds a token, and locks themselves out.

---

## Stack

| Layer | Technology |
|-------|-----------|
| Framework | Next.js 15 (App Router) |
| Edge proxy | Vercel Edge Runtime |
| Rule/server/token store (hot path) | Vercel Edge Config |
| Database | Neon Postgres + Drizzle ORM |
| AI detection | OpenAI GPT-4o-mini |
| Auth | Auth.js v5 (GitHub OAuth) |
| UI | Tailwind CSS + shadcn/ui |
