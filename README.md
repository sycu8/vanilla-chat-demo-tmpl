# ReconForge

**Autonomous Security Reconnaissance & Pentesting Platform** — built on Cloudflare Pages + Hono.

![ReconForge](https://img.shields.io/badge/Cloudflare-Pages-F38020?style=flat-square&logo=cloudflare)
![Hono](https://img.shields.io/badge/Hono-4.x-E36002?style=flat-square)
![Tailwind](https://img.shields.io/badge/Tailwind-3.4-38B2AC?style=flat-square&logo=tailwindcss)

ReconForge delivers a professional 5-phase reconnaissance pipeline with live streaming logs, interactive Mermaid mindmaps, and exportable security reports — fully functional in simulation mode out of the box.

## Features

- **5-Phase Recon Pipeline** — OSINT, subdomain enumeration, tech fingerprinting, CVE matching, intelligence synthesis
- **Live SSE Streaming** — Real-time phase progress and terminal-style logs
- **Interactive Mindmap** — Mermaid.js visualization with zoom, click, regenerate, and PNG export
- **Professional Reports** — Markdown, HTML, and PDF export with risk scoring dashboard
- **Simulation Mode** — Realistic mock data for any domain — safe for demos and training
- **Dark Cybersecurity UI** — Responsive Tailwind design, toast notifications, loading states

## Quick Start

```bash
npm install
npx wrangler login
npm run build
npm run preview
```

Open `http://localhost:8788`, enter a target domain, and click **Launch Recon**.

## Deploy

```bash
npm run deploy
```

See [DEPLOYMENT.md](./DEPLOYMENT.md) for full Cloudflare Pages setup, Git integration, secrets, and production extension guide.

## Project Structure

```
├── public/index.html       # Frontend SPA
├── public/static/app.js    # Client application
├── src/index.tsx           # Hono entry point
├── src/api/recon.ts        # API routes
├── src/services/simulation.ts  # Recon engine (mock + extension points)
├── src/lib/                # Domain, mindmap, report utilities
├── wrangler.toml           # Cloudflare config
└── .env.example            # Environment template
```

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/recon/health` | GET | Health check |
| `/api/recon/scan` | POST | SSE recon pipeline |
| `/api/recon/mindmap` | POST | Regenerate mindmap |
| `/api/recon/report` | POST | Instant report |

## Tech Stack

- **Backend:** [Hono](https://hono.dev) on Cloudflare Pages Functions
- **Frontend:** HTML + Tailwind CSS + Vanilla JS
- **Visualization:** [Mermaid.js](https://mermaid.js.org) mindmaps
- **Export:** jsPDF, browser-native downloads

## License

For authorized security testing and educational use only.
