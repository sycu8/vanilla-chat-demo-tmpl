/**
 * ReconForge Hono application — routes and static assets.
 */

import { Hono } from "hono";
import { serveStatic } from "hono/cloudflare-pages";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import reconRoutes from "./api/recon";
import type { ReconEnv } from "./lib/env";

const app = new Hono<{ Bindings: ReconEnv }>();

app.use("*", logger());
app.use(
  "/api/*",
  cors({
    origin: "*",
    allowMethods: ["GET", "POST", "OPTIONS"],
  })
);

app.route("/api/recon", reconRoutes);

app.get("/api/health", (c) => {
  return c.json({ status: "ok", app: "ReconForge", version: "2.0.0" });
});

const serveAsset = serveStatic();
app.get("/", serveAsset);
app.get("/index.html", serveAsset);

export default app;
