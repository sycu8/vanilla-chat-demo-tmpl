/**
 * Lightweight directory brute-force (ffuf-style, Workers-safe).
 */

import type { SecurityFinding } from "../lib/types";

const TIMEOUT_MS = 8_000;

const PATHS = [
  "/admin",
  "/login",
  "/api",
  "/api/v1",
  "/backup",
  "/config",
  "/console",
  "/dashboard",
  "/graphql",
  "/health",
  "/metrics",
  "/status",
  "/.well-known/security.txt",
  "/security.txt",
];

async function probePath(host: string, path: string): Promise<{ status: number; body: string }> {
  try {
    const res = await fetch(`https://${host}${path}`, {
      method: "GET",
      redirect: "manual",
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { "User-Agent": "ReconForge/2.0" },
    });
    return { status: res.status, body: (await res.text()).slice(0, 2048) };
  } catch {
    return { status: 0, body: "" };
  }
}

export async function bruteDirectories(hosts: string[], depth: "quick" | "deep"): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];
  const pathLimit = depth === "deep" ? PATHS.length : 8;
  const hostLimit = depth === "deep" ? 5 : 3;
  const paths = PATHS.slice(0, pathLimit);

  for (const host of hosts.slice(0, hostLimit)) {
    for (const path of paths) {
      const { status, body } = await probePath(host, path);
      if (status === 403) {
        findings.push({
          id: `dir-forbidden-${path}-${host}`.replace(/[^a-z0-9-]/gi, "-"),
          host,
          category: "exposure",
          severity: "info",
          title: `Restricted path discovered (${path})`,
          description: `${host}${path} returns HTTP 403 — path exists but access denied`,
          remediation: "Verify authentication protects sensitive paths; remove if unused.",
        });
        continue;
      }
      if (status < 200 || status >= 400) continue;

      const interesting =
        /login|admin|dashboard|graphql|backup|config|metrics/i.test(path) ||
        /graphql|swagger|openapi|admin|login|password/i.test(body);

      if (!interesting && path !== "/.well-known/security.txt" && path !== "/security.txt") continue;

      findings.push({
        id: `dir-found-${path}-${host}`.replace(/[^a-z0-9-]/gi, "-"),
        host,
        category: "exposure",
        severity: path.includes("admin") || path.includes("backup") ? "medium" : "info",
        title: `Discovered path: ${path}`,
        description: `${host}${path} returned HTTP ${status}`,
        remediation: "Review exposed endpoints and enforce authentication where required.",
      });
    }
  }

  return findings;
}
