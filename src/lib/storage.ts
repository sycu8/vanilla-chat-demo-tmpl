/**
 * Scan persistence — D1 history + KV cache.
 */

import type { ReconReport } from "./types";
import type { ReconEnv } from "./env";

export interface ScanSummary {
  id: string;
  domain: string;
  target: string;
  depth: string;
  riskScore: number;
  riskLevel: string;
  subdomainCount: number;
  vulnCount: number;
  exposureCount: number;
  createdAt: string;
}

const CACHE_TTL = 86400; // 24h

export async function cacheReport(env: ReconEnv, report: ReconReport): Promise<void> {
  if (!env.SCAN_CACHE) return;
  const slim = { ...report };
  await env.SCAN_CACHE.put(`scan:${report.id}`, JSON.stringify(slim), { expirationTtl: CACHE_TTL });
}

export async function getCachedReport(env: ReconEnv, id: string): Promise<ReconReport | null> {
  if (!env.SCAN_CACHE) return null;
  const raw = await env.SCAN_CACHE.get(`scan:${id}`);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as ReconReport;
  } catch {
    return null;
  }
}

export async function saveScan(env: ReconEnv, report: ReconReport): Promise<void> {
  await cacheReport(env, report);
  if (!env.DB) return;

  await env.DB.prepare(
    `INSERT OR REPLACE INTO scans
     (id, domain, target, depth, simulation, risk_score, risk_level, subdomain_count, vuln_count, exposure_count, report_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      report.id,
      report.domain,
      report.target,
      report.depth,
      report.simulation ? 1 : 0,
      report.riskScore,
      report.riskLevel,
      report.subdomains.length,
      report.vulnerabilities.length,
      report.securityFindings.length,
      JSON.stringify(report),
      report.completedAt
    )
    .run();
}

export async function getScan(env: ReconEnv, id: string): Promise<ReconReport | null> {
  const cached = await getCachedReport(env, id);
  if (cached) return cached;

  if (!env.DB) return null;
  const row = await env.DB.prepare("SELECT report_json FROM scans WHERE id = ?").bind(id).first<{ report_json: string }>();
  if (!row?.report_json) return null;
  try {
    return JSON.parse(row.report_json) as ReconReport;
  } catch {
    return null;
  }
}

export async function listScans(env: ReconEnv, domain?: string, limit = 25): Promise<ScanSummary[]> {
  if (!env.DB) return [];

  const query = domain
    ? "SELECT id, domain, target, depth, risk_score, risk_level, subdomain_count, vuln_count, exposure_count, created_at FROM scans WHERE domain = ? ORDER BY created_at DESC LIMIT ?"
    : "SELECT id, domain, target, depth, risk_score, risk_level, subdomain_count, vuln_count, exposure_count, created_at FROM scans ORDER BY created_at DESC LIMIT ?";

  const stmt = domain
    ? env.DB.prepare(query).bind(domain, limit)
    : env.DB.prepare(query).bind(limit);

  const { results } = await stmt.all<{
    id: string;
    domain: string;
    target: string;
    depth: string;
    risk_score: number;
    risk_level: string;
    subdomain_count: number;
    vuln_count: number;
    exposure_count: number;
    created_at: string;
  }>();

  return (results || []).map((r) => ({
    id: r.id,
    domain: r.domain,
    target: r.target,
    depth: r.depth,
    riskScore: r.risk_score,
    riskLevel: r.risk_level,
    subdomainCount: r.subdomain_count,
    vulnCount: r.vuln_count,
    exposureCount: r.exposure_count,
    createdAt: r.created_at,
  }));
}
