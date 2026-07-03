/**
 * Recon API routes — scan streaming, mindmap regeneration, health check.
 */

import { Hono } from "hono";
import { streamSSE } from "hono/streaming";
import { extractDomain, isValidDomain } from "../lib/domain";
import { regenerateMindmap } from "../lib/mindmap";
import { enrichReport } from "../lib/report";
import { buildReportFromRequest, runReconScan } from "../services/simulation";
import type { ReconReport, ScanRequest } from "../lib/types";

const recon = new Hono();

/** Health / status endpoint */
recon.get("/health", (c) => {
  return c.json({
    status: "operational",
    service: "ReconForge",
    version: "1.0.0",
    mode: "simulation-ready",
    timestamp: new Date().toISOString(),
  });
});

/** Validate and normalize scan request body */
function parseScanRequest(body: unknown): ScanRequest | { error: string } {
  if (!body || typeof body !== "object") {
    return { error: "Invalid request body" };
  }

  const raw = body as Record<string, unknown>;
  const target = String(raw.target || "").trim();
  const domain = extractDomain(target);

  if (!domain || !isValidDomain(domain)) {
    return { error: "Invalid target URL or domain" };
  }

  const keywordsRaw = String(raw.keywords || "");
  const keywords = keywordsRaw
    .split(",")
    .map((k) => k.trim())
    .filter(Boolean);

  const depth = raw.depth === "deep" ? "deep" : "quick";
  const simulation = raw.simulation !== false;

  return { target, keywords, depth, simulation };
}

/**
 * POST /api/recon/scan
 * Streams recon pipeline via Server-Sent Events.
 * Events: phase | log | complete
 */
recon.post("/scan", async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Malformed JSON body" }, 400);
  }

  const parsed = parseScanRequest(body);
  if ("error" in parsed) {
    return c.json({ error: parsed.error }, 400);
  }

  return streamSSE(c, async (stream) => {
    try {
      for await (const event of runReconScan(parsed)) {
        await stream.writeSSE({
          event: event.type,
          data: JSON.stringify(event.data),
        });
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : "Scan failed";
      await stream.writeSSE({
        event: "error",
        data: JSON.stringify({ message }),
      });
    }
  });
});

/**
 * POST /api/recon/mindmap
 * Regenerate mindmap with optional layout variant.
 */
recon.post("/mindmap", async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Malformed JSON body" }, 400);
  }

  const raw = body as Record<string, unknown>;
  const variant = Number(raw.variant) || 0;

  if (raw.report && typeof raw.report === "object") {
    const report = raw.report as ReconReport;
    const mindmap = regenerateMindmap(report, variant);
    return c.json({ mindmap });
  }

  const parsed = parseScanRequest(body);
  if ("error" in parsed) {
    return c.json({ error: parsed.error }, 400);
  }

  const report = await buildReportFromRequest(parsed);
  const mindmap = regenerateMindmap(report, variant);

  return c.json({ mindmap, report });
});

/**
 * POST /api/recon/enrich
 * Add markdown/html to an existing scan report (no re-scan).
 */
recon.post("/enrich", async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Malformed JSON body" }, 400);
  }

  const raw = body as Record<string, unknown>;
  if (!raw.report || typeof raw.report !== "object") {
    return c.json({ error: "Missing report object" }, 400);
  }

  const report = enrichReport(raw.report as ReconReport);
  return c.json({ report });
});

/**
 * POST /api/recon/report
 * Generate full report without streaming (instant).
 */
recon.post("/report", async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Malformed JSON body" }, 400);
  }

  const parsed = parseScanRequest(body);
  if ("error" in parsed) {
    return c.json({ error: parsed.error }, 400);
  }

  const report = await buildReportFromRequest(parsed);
  return c.json({ report });
});

export default recon;
