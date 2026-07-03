/**
 * Recon API routes — scan streaming, history, exports, scheduling.
 */

import { Hono } from "hono";
import { streamSSE } from "hono/streaming";
import { extractDomain, isValidDomain } from "../lib/domain";
import { requireAuth } from "../lib/auth";
import { checkRateLimit, clientRateKey } from "../lib/rate-limit";
import { validateScopeTarget } from "../lib/scope";
import { diffReports } from "../lib/diff";
import { exportJson, exportSarif } from "../lib/export";
import { regenerateMindmap } from "../lib/mindmap";
import { enrichReport } from "../lib/report";
import { getScan, listScans, saveScan } from "../lib/storage";
import { buildReportFromRequest, runReconScan } from "../services/simulation";
import type { ReconEnv } from "../lib/env";
import type { ReconReport, ScanRequest, ScanScope } from "../lib/types";

const recon = new Hono<{ Bindings: ReconEnv }>();

function parseScope(raw: Record<string, unknown>): ScanScope | undefined {
  const include = Array.isArray(raw.scopeInclude)
    ? raw.scopeInclude.map(String)
    : String(raw.scopeInclude || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
  const exclude = Array.isArray(raw.scopeExclude)
    ? raw.scopeExclude.map(String)
    : String(raw.scopeExclude || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);

  if (!include.length && !exclude.length) return undefined;
  return { include: include.length ? include : undefined, exclude: exclude.length ? exclude : undefined };
}

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
  const scope = parseScope(raw);

  const scopeErr = validateScopeTarget(domain, scope);
  if (scopeErr) return { error: scopeErr };

  return { target, keywords, depth, simulation, scope };
}

recon.use("*", async (c, next) => {
  const authResp = requireAuth(c.req.raw, c.env);
  if (authResp) return authResp;
  await next();
});

recon.get("/health", (c) => {
  return c.json({
    status: "operational",
    service: "ReconForge",
    version: "2.0.0",
    features: ["live-recon", "d1-history", "kv-cache", "nvd", "templates", "sarif"],
    timestamp: new Date().toISOString(),
  });
});

recon.post("/scan", async (c) => {
  const rate = await checkRateLimit(c.env, clientRateKey(c.req.raw));
  if (!rate.allowed) return c.json({ error: "Rate limit exceeded", remaining: 0 }, 429);

  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Malformed JSON body" }, 400);
  }

  const parsed = parseScanRequest(body);
  if ("error" in parsed) return c.json({ error: parsed.error }, 400);

  return streamSSE(c, async (stream) => {
    try {
      for await (const event of runReconScan(parsed, c.env)) {
        await stream.writeSSE({ event: event.type, data: JSON.stringify(event.data) });
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : "Scan failed";
      await stream.writeSSE({ event: "error", data: JSON.stringify({ message }) });
    }
  });
});

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
    return c.json({ mindmap: regenerateMindmap(raw.report as ReconReport, variant) });
  }

  const parsed = parseScanRequest(body);
  if ("error" in parsed) return c.json({ error: parsed.error }, 400);

  const report = await buildReportFromRequest(parsed, c.env);
  return c.json({ mindmap: regenerateMindmap(report, variant), report });
});

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
  await saveScan(c.env, report).catch(() => {});
  return c.json({ report });
});

recon.post("/report", async (c) => {
  const rate = await checkRateLimit(c.env, clientRateKey(c.req.raw));
  if (!rate.allowed) return c.json({ error: "Rate limit exceeded" }, 429);

  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Malformed JSON body" }, 400);
  }

  const raw = body as Record<string, unknown>;
  if (raw.scanId && typeof raw.scanId === "string") {
    const cached = await getScan(c.env, raw.scanId);
    if (cached) return c.json({ report: enrichReport(cached) });
  }

  const parsed = parseScanRequest(body);
  if ("error" in parsed) return c.json({ error: parsed.error }, 400);

  const report = await buildReportFromRequest(parsed, c.env);
  return c.json({ report });
});

recon.get("/history", async (c) => {
  const domain = c.req.query("domain");
  const limit = Number(c.req.query("limit") || "25");
  const scans = await listScans(c.env, domain || undefined, limit);
  return c.json({ scans });
});

recon.get("/scan/:id", async (c) => {
  const report = await getScan(c.env, c.req.param("id"));
  if (!report) return c.json({ error: "Scan not found" }, 404);
  return c.json({ report: enrichReport(report) });
});

recon.post("/diff", async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Malformed JSON body" }, 400);
  }

  const raw = body as Record<string, unknown>;
  const baseId = String(raw.baseId || "");
  const compareId = String(raw.compareId || "");
  if (!baseId || !compareId) return c.json({ error: "baseId and compareId required" }, 400);

  const [base, compare] = await Promise.all([getScan(c.env, baseId), getScan(c.env, compareId)]);
  if (!base || !compare) return c.json({ error: "One or both scans not found" }, 404);

  return c.json({ diff: diffReports(base, compare) });
});

recon.get("/export/:id", async (c) => {
  const id = c.req.param("id") ?? "";
  const format = c.req.query("format") || "json";
  const report = await getScan(c.env, id);
  if (!report) return c.json({ error: "Scan not found" }, 404);

  if (format === "sarif") {
    return new Response(exportSarif(enrichReport(report)), {
      headers: {
        "Content-Type": "application/sarif+json",
        "Content-Disposition": `attachment; filename="reconforge-${report.domain}.sarif.json"`,
      },
    });
  }

  return new Response(exportJson(enrichReport(report)), {
    headers: {
      "Content-Type": "application/json",
      "Content-Disposition": `attachment; filename="reconforge-${report.domain}.json"`,
    },
  });
});

recon.post("/schedule", async (c) => {
  if (!c.env.DB) return c.json({ error: "Scheduling requires D1 database" }, 503);

  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Malformed JSON body" }, 400);
  }

  const parsed = parseScanRequest(body);
  if ("error" in parsed) return c.json({ error: parsed.error }, 400);

  const id = `sched-${Date.now().toString(36)}`;
  const domain = extractDomain(parsed.target);
  await c.env.DB.prepare(
    `INSERT INTO scheduled_targets (id, target, domain, depth, simulation, keywords, enabled, created_at)
     VALUES (?, ?, ?, ?, ?, ?, 1, ?)`
  )
    .bind(id, parsed.target, domain, parsed.depth, parsed.simulation ? 1 : 0, parsed.keywords.join(","), new Date().toISOString())
    .run();

  return c.json({ id, message: "Target scheduled for daily scan at 06:00 UTC" });
});

export default recon;
