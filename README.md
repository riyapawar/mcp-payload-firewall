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
                    └─ matches "sk-..." rule → "[REDACTED]"
                    └─ matches "RSA key" rule → 403 blocked
                    └─ Audit log written to Postgres
```

---

## Detection methods

Rules use one of two detection backends — mix and match as needed:

**Regex** — exact pattern matching, sub-millisecond, no external calls. Right for known credential formats: OpenAI keys, AWS access keys, PEM headers.

**AI (semantic)** — GPT-4o-mini classifies each payload against a plain-English description you write. Right for anything that doesn't have a fixed format: internal tokens, context-dependent PII, novel credential schemes. Adds ~300ms per request.

---

## How to integrate

The firewall exposes `/api/proxy/*` as a transparent reverse proxy. To route an MCP connection through it:

1. Change your MCP client's server URL from the upstream address to the firewall's proxy endpoint.
2. Add an `X-MCP-Target` header pointing at the real upstream server.

The path after `/api/proxy` is forwarded verbatim. Headers and query strings pass through unchanged.

### Claude Desktop

In `~/.config/claude/claude_desktop_config.json` (or the Windows equivalent in `%APPDATA%\Claude\`):

```json
{
  "mcpServers": {
    "my-server": {
      "url": "https://your-deployment.vercel.app/api/proxy/mcp",
      "headers": {
        "X-MCP-Target": "https://actual-mcp-server.example.com"
      }
    }
  }
}
```

### Any HTTP MCP client

```
Before: POST https://actual-mcp-server.example.com/messages
After:  POST https://your-deployment.vercel.app/api/proxy/messages
        X-MCP-Target: https://actual-mcp-server.example.com
```

### Default upstream

If all your traffic goes to one MCP server, set `UPSTREAM_MCP_URL` in your environment variables instead of passing the header on every request.

---

## Severity levels

| Level | Behavior |
|-------|----------|
| **block** | Reject the entire request with a JSON-RPC error. Nothing reaches upstream. |
| **redact** | Replace the matched text inline with a configurable replacement string. |
| **warn** | Log the match to the audit trail. Payload passes through unchanged. |

---

## Starter rules

Add these from the dashboard to be protected immediately:

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

For AI rules, the pattern field is a plain-English description of what GPT-4o-mini should detect. It will match credential formats, contextual PII, or anything you can describe in a sentence — even tokens with no fixed format.

---

## Live demo

Run these from a PowerShell terminal against the live deployment:

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
# → {"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Blocked by DLP rule: RSA Private Key"}}

# WARN — email passes through but is logged
Invoke-WebRequest -Uri $base -Method POST -Headers $h `
  -Body '{"contact":"user@example.com"}' -UseBasicParsing |
  ConvertFrom-Json | Select-Object -ExpandProperty data
# → {"contact":"user@example.com"}   (visible in audit log at /dashboard/logs)
```

Or run the bundled script: `powershell -ExecutionPolicy Bypass -File demo.ps1`

---

## Deployment

### 1. Neon Postgres

1. Create a project at [neon.tech](https://neon.tech) (free tier works).
2. From the connection details page, copy:
   - **Pooled connection string** → `DATABASE_URL`
   - **Unpooled connection string** → `DATABASE_URL_UNPOOLED`

### 2. GitHub OAuth App

1. Go to [github.com/settings/developers](https://github.com/settings/developers) → **OAuth Apps → New OAuth App**.
2. Set:
   - Homepage URL: `https://your-deployment.vercel.app`
   - Callback URL: `https://your-deployment.vercel.app/api/auth/callback/github`
3. If you use a custom domain, add it as a second callback URL: `https://your-domain.com/api/auth/callback/github`
4. Copy the **Client ID** → `AUTH_GITHUB_ID` and generate a **Client Secret** → `AUTH_GITHUB_SECRET`.

### 3. Deploy to Vercel

1. Fork or push this repo to GitHub.
2. Import the project in [vercel.com/new](https://vercel.com/new).
3. Vercel detects Next.js automatically — no build config needed.

### 4. Vercel Edge Config

1. In your Vercel project, go to **Storage → Edge Config → Create**.
2. **Connect** the store to your project (this generates the `EDGE_CONFIG` connection string).
3. Go to **Settings → Tokens → Create Token** with Edge Config write scope → `VERCEL_EDGE_CONFIG_TOKEN`.

### 5. Environment variables

In Vercel → **Settings → Environment Variables**, add all of these:

```bash
# Database (Neon)
DATABASE_URL=              # pooled connection string
DATABASE_URL_UNPOOLED=     # unpooled (used by drizzle-kit for migrations)

# Auth.js
AUTH_SECRET=               # generate: openssl rand -base64 32
AUTH_GITHUB_ID=            # GitHub OAuth App client ID
AUTH_GITHUB_SECRET=        # GitHub OAuth App client secret
ADMIN_EMAIL=               # the GitHub account email allowed to sign in

# Vercel Edge Config
EDGE_CONFIG=               # connection string from Storage → Edge Config
VERCEL_EDGE_CONFIG_TOKEN=  # Vercel API token with Edge Config write access

# Proxy
UPSTREAM_MCP_URL=          # optional default upstream if you skip the X-MCP-Target header
FIREWALL_INTERNAL_KEY=     # generate: openssl rand -hex 32
OPENAI_API_KEY=            # required for AI-type rules; skip if you only use regex
```

### 6. Run migrations

After adding environment variables, open a terminal and run:

```bash
pnpm db:push
```

This creates the `dlp_rules` and `audit_logs` tables in your Neon database.

### 7. Add your first rule

1. Open `/dashboard` and sign in with the GitHub account matching `ADMIN_EMAIL`.
2. Go to **Rules → New Rule**. Add at least one rule and save it.
3. Saving a rule triggers an automatic sync to Edge Config — the proxy is now live.

---

## Local development

```bash
git clone https://github.com/yourusername/mcp-payload-firewall
cd mcp-payload-firewall
pnpm install
cp .env.local.example .env.local   # fill in all values
pnpm db:push                        # create tables in Neon
pnpm dev                            # http://localhost:3000
```

Test locally using httpbin as a stand-in upstream:

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
                ├── Load rules from Edge Config (< 1ms, in-process)
                ├── Regex rules → V8 RegExp engine
                ├── AI rules → GPT-4o-mini (AbortController, 8s timeout)
                │
                ├── block  → JSON-RPC error {"code":-32600}
                ├── redact → replace match inline, forward to upstream
                └── warn   → log to /api/logs (Node runtime) via internal HTTP
                                │
                                └── Writes to Neon Postgres (audit_logs table)

Dashboard (Next.js, Node runtime)
    ├── /api/rules  → CRUD rules in Neon, sync to Edge Config after each write
    └── /api/logs   → paginated audit log reads from Neon
```

**Why Edge Config instead of a database on the hot path?**  
Edge Config is an in-process key-value store — reads are under 1ms with no network round-trip. Drizzle ORM (Neon) cannot open TCP connections in the Edge Runtime, so the proxy reads rules exclusively from Edge Config and delegates all writes to the Node.js `/api/logs` route via an authenticated internal HTTP call.

**Why buffer the response instead of streaming through a TransformStream?**  
For standard JSON-RPC responses, buffering lets the firewall return a clean JSON-RPC error when a block rule fires — HTTP status and headers aren't committed until the full body is scanned. SSE responses (`text/event-stream`) still stream through a TransformStream, where a block aborts the stream.

---

## Stack

| Layer | Technology |
|-------|-----------|
| Framework | Next.js 15 (App Router) |
| Edge proxy | Vercel Edge Runtime |
| Rule store (hot path) | Vercel Edge Config |
| Database | Neon Postgres + Drizzle ORM |
| AI detection | OpenAI GPT-4o-mini |
| Auth | Auth.js v5 (GitHub OAuth) |
| UI | Tailwind CSS + shadcn/ui |
