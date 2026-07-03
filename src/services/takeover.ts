/**
 * Subdomain takeover detection via CNAME dangling checks.
 */

import type { SecurityFinding } from "../lib/types";

const TIMEOUT_MS = 10_000;
const DNS_URL = "https://cloudflare-dns.com/dns-query";

const TAKEOVER_FINGERPRINTS: { pattern: RegExp; service: string; severity: "high" | "medium" }[] = [
  { pattern: /\.github\.io$/i, service: "GitHub Pages", severity: "high" },
  { pattern: /\.herokudns\.com$/i, service: "Heroku", severity: "high" },
  { pattern: /\.s3\.amazonaws\.com$/i, service: "AWS S3", severity: "high" },
  { pattern: /\.azurewebsites\.net$/i, service: "Azure App Service", severity: "high" },
  { pattern: /\.cloudfront\.net$/i, service: "CloudFront", severity: "medium" },
  { pattern: /\.fastly\.net$/i, service: "Fastly", severity: "medium" },
  { pattern: /\.shopify\.com$/i, service: "Shopify", severity: "medium" },
];

async function resolveCname(host: string): Promise<string | null> {
  const url = `${DNS_URL}?name=${encodeURIComponent(host)}&type=CNAME`;
  try {
    const res = await fetch(url, {
      headers: { Accept: "application/dns-json" },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { Answer?: { type: number; data: string }[] };
    const cname = data.Answer?.find((a) => a.type === 5)?.data?.replace(/\.$/, "");
    return cname || null;
  } catch {
    return null;
  }
}

export async function detectTakeoverCandidates(hosts: string[]): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];

  for (const host of hosts.slice(0, 15)) {
    const cname = await resolveCname(host);
    if (!cname) continue;

    for (const fp of TAKEOVER_FINGERPRINTS) {
      if (!fp.pattern.test(cname)) continue;

      findings.push({
        id: `takeover-${host}`,
        host,
        category: "misconfig",
        severity: fp.severity,
        title: `Potential subdomain takeover (${fp.service})`,
        description: `${host} CNAME → ${cname} — verify ${fp.service} resource exists`,
        remediation: `Claim or remove dangling CNAME to ${cname}, or delete unused DNS record for ${host}.`,
      });
      break;
    }
  }

  return findings;
}
