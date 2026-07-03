/**
 * Scheduled daily re-scan of enabled targets (Phase 5).
 */

import type { ReconEnv } from "../lib/env";
import { saveScan } from "../lib/storage";
import { buildReportFromRequest } from "../services/simulation";
import type { ScanRequest } from "../lib/types";

export async function scheduledScan(
  _event: ScheduledEvent,
  env: ReconEnv,
  _ctx: ExecutionContext
): Promise<void> {
  if (!env.DB) return;

  const { results } = await env.DB.prepare(
    "SELECT id, target, domain, depth, simulation, keywords FROM scheduled_targets WHERE enabled = 1 LIMIT 5"
  ).all<{
    id: string;
    target: string;
    domain: string;
    depth: string;
    simulation: number;
    keywords: string;
  }>();

  for (const row of results || []) {
    const request: ScanRequest = {
      target: row.target,
      keywords: row.keywords ? row.keywords.split(",").map((k) => k.trim()).filter(Boolean) : [],
      depth: row.depth === "deep" ? "deep" : "quick",
      simulation: row.simulation !== 0,
    };

    try {
      const report = await buildReportFromRequest(request, env);
      await saveScan(env, report);
      await env.DB.prepare("UPDATE scheduled_targets SET last_run_at = ? WHERE id = ?")
        .bind(new Date().toISOString(), row.id)
        .run();

      if (env.WEBHOOK_URL) {
        await fetch(env.WEBHOOK_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            event: "scheduled_scan_complete",
            domain: report.domain,
            riskScore: report.riskScore,
            scanId: report.id,
          }),
        }).catch(() => {});
      }
    } catch {
      // continue with next target
    }
  }
}
