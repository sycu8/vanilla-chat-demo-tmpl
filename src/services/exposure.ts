/**
 * Exposure & misconfiguration checks — Nuclei-inspired templates for Workers.
 * Security headers, sensitive paths, info disclosure.
 */

import type { DnsRecord, RiskLevel, SecurityFinding, TechFingerprint } from "../lib/types";

const PROBE_TIMEOUT_MS = 10_000;

const REQUIRED_HEADERS: { name: string; title: string; severity: RiskLevel; remediation: string }[] = [
  {
    name: "strict-transport-security",
    title: "Missing HSTS",
    severity: "medium",
    remediation: "Add Strict-Transport-Security with max-age ≥31536000; includeSubDomains for apex domains.",
  },
  {
    name: "content-security-policy",
    title: "Missing Content-Security-Policy",
    severity: "medium",
    remediation: "Define a CSP restricting script-src, frame-ancestors, and connect-src to trusted origins.",
  },
  {
    name: "x-frame-options",
    title: "Missing X-Frame-Options / frame-ancestors",
    severity: "medium",
    remediation: "Set X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors directive.",
  },
  {
    name: "x-content-type-options",
    title: "Missing X-Content-Type-Options",
    severity: "info",
    remediation: "Set X-Content-Type-Options: nosniff on all HTML/API responses.",
  },
];

/** Sensitive paths commonly checked by Nuclei / ffuf recon templates */
const EXPOSURE_PATHS: {
  path: string;
  title: string;
  severity: RiskLevel;
  match: (status: number, body: string) => boolean;
  remediation: string;
}[] = [
  {
    path: "/.git/HEAD",
    title: "Git repository exposed",
    severity: "high",
    match: (s, b) => s === 200 && /^ref: refs\//m.test(b),
    remediation: "Block .git/ at the web server or CDN. Rotate any secrets ever committed to the repo.",
  },
  {
    path: "/.env",
    title: "Environment file exposed",
    severity: "high",
    match: (s, b) => s === 200 && /(?:API_KEY|SECRET|PASSWORD|DB_)=/i.test(b),
    remediation: "Remove .env from web root, rotate all exposed credentials, add WAF rules blocking dotfiles.",
  },
  {
    path: "/robots.txt",
    title: "robots.txt discloses paths",
    severity: "info",
    match: (s, b) => s === 200 && /disallow:/i.test(b),
    remediation: "Review disallowed paths — attackers use robots.txt as a discovery map.",
  },
  {
    path: "/sitemap.xml",
    title: "Sitemap exposes URL structure",
    severity: "info",
    match: (s, b) => s === 200 && /<urlset|<sitemapindex/i.test(b),
    remediation: "Ensure sitemap only lists public pages; remove admin/staging URLs.",
  },
  {
    path: "/swagger",
    title: "Swagger UI exposed",
    severity: "medium",
    match: (s, b) => s === 200 && /swagger|openapi/i.test(b),
    remediation: "Restrict API documentation to authenticated users or internal networks.",
  },
  {
    path: "/api/docs",
    title: "API documentation exposed",
    severity: "medium",
    match: (s, b) => s === 200 && /openapi|swagger|redoc/i.test(b),
    remediation: "Require authentication for API docs in production environments.",
  },
  {
    path: "/debug",
    title: "Debug endpoint reachable",
    severity: "high",
    match: (s) => s === 200 || s === 401,
    remediation: "Disable debug routes in production; restrict by IP allowlist if required internally.",
  },
  {
    path: "/server-status",
    title: "Server status page exposed",
    severity: "medium",
    match: (s, b) => s === 200 && /server status|apache/i.test(b),
    remediation: "Disable mod_status or restrict to localhost / management VPN only.",
  },
];

async function probePath(host: string, path: string): Promise<{ status: number; body: string }> {
  const url = `https://${host}${path}`;
  try {
    const res = await fetch(url, {
      method: "GET",
      redirect: "manual",
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
      headers: { "User-Agent": "ReconForge/1.0 (security-recon)" },
    });
    const body = (await res.text()).slice(0, 4096);
    return { status: res.status, body };
  } catch {
    return { status: 0, body: "" };
  }
}

function headerFindings(fp: TechFingerprint): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const missing = fp.missingHeaders || [];

  for (const rule of REQUIRED_HEADERS) {
    if (!missing.includes(rule.name)) continue;

    findings.push({
      id: `hdr-${rule.name}-${fp.host}`,
      host: fp.host,
      category: "headers",
      severity: rule.severity,
      title: rule.title,
      description: `${fp.host} is missing the ${rule.name} response header.`,
      remediation: rule.remediation,
    });
  }

  if (fp.securityScore !== undefined && fp.securityScore < 40) {
    findings.push({
      id: `hdr-score-${fp.host}`,
      host: fp.host,
      category: "headers",
      severity: "medium",
      title: "Weak security header posture",
      description: `${fp.host} security header score: ${fp.securityScore}/100`,
      remediation: "Implement HSTS, CSP, X-Frame-Options, and X-Content-Type-Options on all public endpoints.",
    });
  }

  if (fp.server && /nginx\/[\d.]+|apache\/[\d.]+/i.test(fp.server)) {
    findings.push({
      id: `info-server-${fp.host}`,
      host: fp.host,
      category: "misconfig",
      severity: "info",
      title: "Server version disclosure",
      description: `Server header reveals: ${fp.server}`,
      remediation: "Strip or genericize the Server / X-Powered-By headers at the reverse proxy.",
    });
  }

  return findings;
}

async function pathFindings(host: string, maxChecks: number): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];
  const checks = EXPOSURE_PATHS.slice(0, maxChecks);

  for (const template of checks) {
    const { status, body } = await probePath(host, template.path);
    if (!template.match(status, body)) continue;

    findings.push({
      id: `path-${template.path}-${host}`.replace(/[^a-z0-9-]/gi, "-"),
      host,
      category: "exposure",
      severity: template.severity,
      title: template.title,
      description: `${host}${template.path} returned HTTP ${status}`,
      remediation: template.remediation,
    });
  }

  return findings;
}

function dnsFindings(records: DnsRecord[], domain: string): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  const spf = records.find((r) => r.type === "TXT" && r.value.toLowerCase().includes("v=spf1"));
  if (!spf) {
    findings.push({
      id: `dns-spf-${domain}`,
      host: domain,
      category: "dns",
      severity: "medium",
      title: "Missing SPF record",
      description: `No SPF TXT record found for ${domain}`,
      remediation: "Publish an SPF record limiting authorized senders; combine with DKIM and DMARC.",
    });
  } else if (spf.risk === "high") {
    findings.push({
      id: `dns-spf-permissive-${domain}`,
      host: domain,
      category: "dns",
      severity: "high",
      title: "Permissive SPF (+all)",
      description: "SPF record allows any sender (+all)",
      remediation: "Replace +all with ~all or -all after validating all legitimate mail sources.",
    });
  }

  const dmarc = records.find(
    (r) => r.type === "DMARC" || r.value.toLowerCase().includes("v=dmarc1")
  );
  if (!dmarc) {
    findings.push({
      id: `dns-dmarc-${domain}`,
      host: domain,
      category: "dns",
      severity: "medium",
      title: "Missing DMARC record",
      description: `No DMARC policy at _dmarc.${domain}`,
      remediation: "Add DMARC with p=none initially, monitor reports, then tighten to quarantine/reject.",
    });
  } else if (dmarc.risk === "medium" && dmarc.value.toLowerCase().includes("p=none")) {
    findings.push({
      id: `dns-dmarc-none-${domain}`,
      host: domain,
      category: "dns",
      severity: "medium",
      title: "DMARC policy p=none",
      description: "DMARC is monitor-only and does not block spoofed email",
      remediation: "Graduate to p=quarantine or p=reject after reviewing aggregate DMARC reports.",
    });
  }

  return findings;
}

export type ExposureStreamEvent =
  | { kind: "status"; message: string }
  | { kind: "finding"; entry: SecurityFinding };

/** Run exposure checks across fingerprinted hosts (Nuclei-style, Workers-safe). */
export async function* scanExposureStream(
  fingerprints: TechFingerprint[],
  dnsRecords: DnsRecord[],
  domain: string,
  depth: "quick" | "deep"
): AsyncGenerator<ExposureStreamEvent> {
  const pathChecks = depth === "deep" ? 6 : 4;
  const hosts = fingerprints.filter((fp) => fp.headers[0] !== "probe-failed").slice(0, depth === "deep" ? 15 : 8);

  yield { kind: "status", message: `Running exposure checks on ${hosts.length} host(s) (${pathChecks} paths each)...` };

  for (const record of dnsFindings(dnsRecords, domain)) {
    yield { kind: "finding", entry: record };
  }

  for (const fp of hosts) {
    for (const finding of headerFindings(fp)) {
      yield { kind: "finding", entry: finding };
    }
    for (const finding of await pathFindings(fp.host, pathChecks)) {
      yield { kind: "finding", entry: finding };
    }
  }

  yield { kind: "status", message: "Exposure scanning complete" };
}

export async function scanExposure(
  fingerprints: TechFingerprint[],
  dnsRecords: DnsRecord[],
  domain: string,
  depth: "quick" | "deep"
): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];
  for await (const event of scanExposureStream(fingerprints, dnsRecords, domain, depth)) {
    if (event.kind === "finding") findings.push(event.entry);
  }
  return findings;
}

export function countExposureBySeverity(findings: SecurityFinding[]): Record<RiskLevel, number> {
  return findings.reduce(
    (acc, f) => {
      acc[f.severity]++;
      return acc;
    },
    { high: 0, medium: 0, info: 0 } as Record<RiskLevel, number>
  );
}
