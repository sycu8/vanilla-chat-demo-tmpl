/**
 * Nuclei-style probe templates for Workers.
 */

import type { RiskLevel, SecurityFinding, TechFingerprint } from "../lib/types";

const PROBE_TIMEOUT_MS = 8_000;

export interface ProbeTemplate {
  id: string;
  name: string;
  category: SecurityFinding["category"];
  severity: RiskLevel;
  path: string;
  match: (status: number, body: string, headers: Headers) => boolean;
  remediation: string;
}

export const PROBE_TEMPLATES: ProbeTemplate[] = [
  {
    id: "git-exposed",
    name: "Git repository exposed",
    category: "exposure",
    severity: "high",
    path: "/.git/HEAD",
    match: (s, b) => s === 200 && /^ref: refs\//m.test(b),
    remediation: "Block .git/ at CDN or web server.",
  },
  {
    id: "env-exposed",
    name: "Environment file exposed",
    category: "exposure",
    severity: "high",
    path: "/.env",
    match: (s, b) => s === 200 && /(?:SECRET|PASSWORD|API_KEY|DB_)=/i.test(b),
    remediation: "Remove .env from web root and rotate secrets.",
  },
  {
    id: "swagger-ui",
    name: "Swagger UI exposed",
    category: "exposure",
    severity: "medium",
    path: "/swagger",
    match: (s, b) => s === 200 && /swagger|openapi/i.test(b),
    remediation: "Restrict API docs to authenticated users.",
  },
  {
    id: "phpinfo",
    name: "phpinfo() exposed",
    category: "exposure",
    severity: "high",
    path: "/phpinfo.php",
    match: (s, b) => s === 200 && /phpinfo|PHP Version/i.test(b),
    remediation: "Delete phpinfo files from production.",
  },
  {
    id: "actuator",
    name: "Spring Actuator exposed",
    category: "exposure",
    severity: "high",
    path: "/actuator/env",
    match: (s, b) => s === 200 && /"propertySources"|spring/i.test(b),
    remediation: "Disable or protect Spring Boot actuator endpoints.",
  },
  {
    id: "wp-config",
    name: "WordPress config backup",
    category: "exposure",
    severity: "high",
    path: "/wp-config.php.bak",
    match: (s, b) => s === 200 && /DB_NAME|DB_PASSWORD/i.test(b),
    remediation: "Remove backup config files from web root.",
  },
  {
    id: "cors-wildcard",
    name: "CORS wildcard origin",
    category: "misconfig",
    severity: "medium",
    path: "/",
    match: (_s, _b, h) => h.get("access-control-allow-origin") === "*",
    remediation: "Restrict Access-Control-Allow-Origin to trusted domains.",
  },
  {
    id: "server-tokens",
    name: "Detailed server token disclosure",
    category: "misconfig",
    severity: "info",
    path: "/",
    match: (_s, _b, h) => /nginx\/\d|apache\/\d/i.test(h.get("server") || ""),
    remediation: "Strip version tokens from Server header.",
  },
];

async function probe(host: string, path: string): Promise<{ status: number; body: string; headers: Headers }> {
  try {
    const res = await fetch(`https://${host}${path}`, {
      method: "GET",
      redirect: "manual",
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
      headers: { "User-Agent": "ReconForge/2.0" },
    });
    return { status: res.status, body: (await res.text()).slice(0, 4096), headers: res.headers };
  } catch {
    return { status: 0, body: "", headers: new Headers() };
  }
}

export async function runTemplateProbes(
  fingerprints: TechFingerprint[],
  depth: "quick" | "deep"
): Promise<SecurityFinding[]> {
  const limit = depth === "deep" ? 10 : 6;
  const hosts = fingerprints.filter((fp) => fp.headers[0] !== "probe-failed").slice(0, depth === "deep" ? 10 : 6);
  const templates = PROBE_TEMPLATES.slice(0, limit);
  const findings: SecurityFinding[] = [];

  for (const fp of hosts) {
    for (const tpl of templates) {
      const { status, body, headers } = await probe(fp.host, tpl.path);
      if (!tpl.match(status, body, headers)) continue;

      findings.push({
        id: `${tpl.id}-${fp.host}`,
        host: fp.host,
        category: tpl.category,
        severity: tpl.severity,
        title: tpl.name,
        description: `${fp.host}${tpl.path} matched template ${tpl.id} (HTTP ${status})`,
        remediation: tpl.remediation,
      });
    }
  }

  return findings;
}
