/**
 * NVD CVE API — live vulnerability enrichment.
 */

import type { RiskLevel, TechFingerprint, Vulnerability } from "../lib/types";

const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const TIMEOUT_MS = 15_000;

interface NvdCveItem {
  cve?: {
    id?: string;
    descriptions?: { lang: string; value: string }[];
    metrics?: {
      cvssMetricV31?: { cvssData?: { baseScore?: number; baseSeverity?: string } }[];
      cvssMetricV30?: { cvssData?: { baseScore?: number; baseSeverity?: string } }[];
    };
  };
}

function mapSeverity(sev?: string): RiskLevel {
  const s = (sev || "").toUpperCase();
  if (s === "HIGH" || s === "CRITICAL") return "high";
  if (s === "MEDIUM") return "medium";
  return "info";
}

function techKeywords(fp: TechFingerprint): string[] {
  const keys = [fp.framework, fp.cms, fp.server?.split("/")[0], fp.version].filter(Boolean) as string[];
  return [...new Set(keys.map((k) => k.toLowerCase()))];
}

/** Fetch recent CVEs from NVD matching detected technology keywords. */
export async function fetchNvdCves(
  fingerprints: TechFingerprint[],
  apiKey?: string,
  maxPerHost = 2
): Promise<Vulnerability[]> {
  const results: Vulnerability[] = [];
  const seen = new Set<string>();

  const hosts = fingerprints.filter((fp) => fp.headers[0] !== "probe-failed").slice(0, 6);

  for (const fp of hosts) {
    const keywords = techKeywords(fp);
    if (!keywords.length) continue;

    for (const keyword of keywords.slice(0, 2)) {
      if (results.length >= 12) break;

      const url = `${NVD_URL}?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=5`;
      try {
        const headers: Record<string, string> = {
          Accept: "application/json",
          "User-Agent": "ReconForge/2.0",
        };
        if (apiKey) headers["apiKey"] = apiKey;

        const res = await fetch(url, { headers, signal: AbortSignal.timeout(TIMEOUT_MS) });
        if (!res.ok) continue;

        const data = (await res.json()) as { vulnerabilities?: NvdCveItem[] };
        for (const item of data.vulnerabilities || []) {
          const cve = item.cve;
          if (!cve?.id) continue;
          const key = `${cve.id}:${fp.host}`;
          if (seen.has(key)) continue;

          const desc = cve.descriptions?.find((d) => d.lang === "en")?.value || "No description";
          const descLower = desc.toLowerCase();
          const kwLower = keyword.toLowerCase();
          // Require keyword in description to reduce false positives from broad NVD search
          if (!descLower.includes(kwLower)) continue;

          const metric = cve.metrics?.cvssMetricV31?.[0]?.cvssData || cve.metrics?.cvssMetricV30?.[0]?.cvssData;
          const severity = mapSeverity(metric?.baseSeverity);
          const cvss = metric?.baseScore || 0;
          // Skip low-confidence NVD hits (informational with no CVSS signal)
          if (severity === "info" && cvss < 4) continue;

          results.push({
            cve: cve.id,
            severity,
            host: fp.host,
            technology: [fp.framework, fp.cms, fp.server].filter(Boolean).join(" / ") || keyword,
            description: desc.slice(0, 280),
            cvss,
            remediation: `Review NVD advisory ${cve.id} and patch ${keyword} on ${fp.host}.`,
          });
          seen.add(key);
          if ([...seen].filter((k) => k.endsWith(`:${fp.host}`)).length >= maxPerHost) break;
        }
      } catch {
        // skip failed NVD query
      }
    }
  }

  return results;
}

/** Merge catalog CVEs with NVD results, dedupe by cve+host. */
export function mergeVulnerabilities(catalog: Vulnerability[], nvd: Vulnerability[]): Vulnerability[] {
  const map = new Map<string, Vulnerability>();
  for (const v of [...catalog, ...nvd]) {
    map.set(`${v.cve}:${v.host}`, v);
  }
  return [...map.values()];
}
