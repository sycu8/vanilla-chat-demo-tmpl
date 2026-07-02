/**
 * ReconForge — Autonomous Security Reconnaissance Platform
 * Hono application entry point for Cloudflare Pages + Functions
 */

import { Hono } from "hono";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import reconRoutes from "./api/recon";

type Bindings = {
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

export default app;
