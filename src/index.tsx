/**
 * ReconForge — Autonomous Security Reconnaissance Platform
 * Hono application entry point for Cloudflare Pages + Functions
 */

import { Hono } from "hono";
import { serveStatic } from "hono/cloudflare-pages";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import reconRoutes from "./api/recon";

type Bindings = {
  ASSETS: Fetcher;
  // Future: API keys for live recon integrations
  CRT_SH_API?: string;
  SHODAN_API_KEY?: string;
  NVD_API_KEY?: string;
};

const app = new Hono<{ Bindings: Bindings }>();

app.use("*", logger());
app.use(
  "/api/*",
  cors({
    origin: "*",
    allowMethods: ["GET", "POST", "OPTIONS"],
  })
);

// API routes
app.route("/api/recon", reconRoutes);

// Health at root API level
app.get("/api/health", (c) => {
  return c.json({ status: "ok", app: "ReconForge" });
});

// Serve SPA — vite-cloudflare-pages only wires /static/* and /favicon.ico by default
const serveAsset = serveStatic();

app.get("/", serveAsset);
app.get("/index.html", serveAsset);

export default app;
