# ReconForge — Deployment Guide

Deploy ReconForge to **Cloudflare Pages + Functions** in minutes.

## Prerequisites

- [Node.js](https://nodejs.org/) 18+ and npm
- A [Cloudflare account](https://dash.cloudflare.com/sign-up) (free tier works)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) (installed via npm)

## Quick Start (Local)

```bash
# 1. Install dependencies
npm install

# 2. Copy environment template (optional for simulation mode)
cp .env.example .dev.vars

# 3. Authenticate with Cloudflare
npx wrangler login

# 4. Build CSS + application
npm run build

# 5. Preview locally (mirrors production)
npm run preview
```

Open `http://localhost:8788` and launch a scan against any domain (e.g. `example.com`).

### Development with Hot Reload

```bash
npm run dev
```

This runs Vite watch, Tailwind watch, and Wrangler Pages dev concurrently.

## Deploy to Cloudflare Pages

### Option A: CLI Deploy (Fastest)

```bash
npm run deploy
```

Wrangler builds and deploys `dist/` to Cloudflare Pages. You'll get a `*.pages.dev` URL.

### Option B: Git Integration (Recommended for Production)

1. Push this repository to GitHub or GitLab
2. In [Cloudflare Dashboard](https://dash.cloudflare.com/) → **Workers & Pages** → **Create** → **Pages** → **Connect to Git**
3. Select your repository
4. Configure build settings:

| Setting | Value |
|---------|-------|
| **Framework preset** | None |
| **Build command** | `npm run build` |
| **Build output directory** | `dist` |
| **Root directory** | `/` |
| **Node.js version** | 18 or 20 |

5. Click **Save and Deploy**

### Custom Domain

1. Go to your Pages project → **Custom domains**
2. Add your domain (e.g. `reconforge.yourdomain.com`)
3. Cloudflare auto-configures DNS if the domain is on Cloudflare

## Environment Variables & Secrets

Simulation mode works out of the box with no configuration.

For future live integrations, set secrets via Wrangler:

```bash
# Pages secrets (production)
npx wrangler pages secret put SHODAN_API_KEY --project-name reconforge
npx wrangler pages secret put NVD_API_KEY --project-name reconforge
```

For local development, add keys to `.dev.vars` (never commit this file):

```bash
cp .env.example .dev.vars
# Edit .dev.vars with your API keys
```

## Project Architecture

```
reconforge/
├── public/
│   ├── index.html          # Frontend SPA
│   └── static/
│       ├── app.js          # Client-side logic
│       └── style.css       # Compiled Tailwind CSS
├── src/
│   ├── index.tsx           # Hono app entry (Cloudflare Functions)
│   ├── api/recon.ts        # API route handlers
│   ├── services/simulation.ts  # Mock recon engine
│   └── lib/                # Domain, mindmap, report utilities
├── wrangler.toml           # Cloudflare configuration
├── vite.config.ts          # Vite + Hono Pages plugin
└── tailwind.config.js      # Tailwind theme
```

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/recon/health` | Service health check |
| `POST` | `/api/recon/scan` | SSE stream — full 5-phase recon pipeline |
| `POST` | `/api/recon/mindmap` | Regenerate mindmap layout |
| `POST` | `/api/recon/report` | Instant report generation |

### Scan Request Body

```json
{
  "target": "https://example.com",
  "keywords": "acme, acme-corp",
  "depth": "quick",
  "simulation": true
}
```

## Extending to Live Recon

The simulation engine in `src/services/simulation.ts` has clear extension points:

| Phase | Simulation | Production Integration |
|-------|-----------|----------------------|
| OSINT | Mock social intel | Hunter.io, LinkedIn API, Google dorks |
| Subdomains | Generated list | crt.sh, SecurityTrails, subfinder |
| Fingerprinting | Random tech stack | Wappalyzer, httpx, whatweb |
| CVEs | Curated CVE DB | NVD API, OSV, Vulners |
| Synthesis | Rule-based | LLM summarization via Workers AI |

Replace the generator functions in `simulation.ts` with real API calls, gated by `simulation: false`.

## Troubleshooting

### Build fails with TypeScript errors

```bash
npm run typecheck
```

### CSS not loading

Ensure Tailwind build runs before Vite:

```bash
npm run build:css && npm run build
```

### API returns 404

Verify the Hono app is bundled — check `dist/_worker.js` exists after build.

### SSE stream disconnects

Cloudflare Pages supports streaming responses. If issues occur on free tier, reduce scan depth to "quick".

### View production logs

```bash
npx wrangler pages deployment tail --project-name reconforge
```

## Security Notice

ReconForge is designed for **authorized security assessments only**. Simulation mode generates synthetic data. When enabling live integrations:

- Obtain written authorization before scanning targets
- Respect rate limits and robots.txt
- Comply with applicable laws and regulations
- Never store or expose real credentials in reports

## Support

- [Cloudflare Pages Docs](https://developers.cloudflare.com/pages/)
- [Hono Documentation](https://hono.dev/docs/)
- [Wrangler CLI Reference](https://developers.cloudflare.com/workers/wrangler/)
