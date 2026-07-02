/**
 * Live subdomain enumeration — Certificate Transparency + DNS + HTTP probes.
 * Runs on Cloudflare Workers (fetch-only, no shell tools).
 */

import type { ScanDepth, SubdomainEntry } from "../lib/types";

const CRT_SH_URL = "https://crt.sh/";
const HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/";
const DNS_QUERY_URL = "https://cloudflare-dns.com/dns-query";

const SERVICE_HINTS: Record<string, string[]> = {
  api: ["REST API", "HTTPS"],
  admin: ["Admin Panel", "HTTPS"],
  app: ["Web Application", "HTTPS"],
  ask: ["Q&A / Assistant", "HTTPS"],
  auth: ["Authentication", "HTTPS"],
  beta: ["Beta Environment", "HTTPS"],
  blog: ["Blog / CMS", "HTTPS"],
  cdn: ["CDN", "HTTPS"],
  dev: ["Development", "HTTPS"],
  docs: ["Documentation", "HTTPS"],
  kb: ["Knowledge Base", "HTTPS"],
  mail: ["Mail", "SMTP"],
  portal: ["Portal", "HTTPS"],
  staging: ["Staging", "HTTPS"],
  status: ["Status Page", "HTTPS"],
  upload: ["File Upload", "HTTPS"],
  vpn: ["VPN", "HTTPS"],
  www: ["WWW", "HTTPS"],
};

type DnsAnswer = { type: number; data: string };

interface DnsJson {
  Status: number;
  Answer?: DnsAnswer[];
}

function inferServices(host: string, domain: string): string[] {
  const sub = host === domain ? "root" : host.slice(0, -(domain.length + 1));
  const label = sub.includes(".") ? sub.split(".")[0] : sub;
  if (label === "root") return ["Primary Website", "HTTPS"];
  return SERVICE_HINTS[label] || ["HTTPS", "HTTP"];
}

function normalizeHost(value: string, domain: string): string | null {
  let host = value.trim().toLowerCase();
  if (!host) return null;

  host = host.replace(/^\*\./, "");
  if (host.startsWith("www.") && host === `www.${domain}`) return host;
  if (host.endsWith(`.${domain}`) || host === domain) {
    if (host.includes(" ") || host.includes("*") || host.includes(",")) return null;
    return host;
  }
  return null;
}

function parseCrtShHosts(rows: unknown, domain: string): Set<string> {
  const hosts = new Set<string>();
  if (!Array.isArray(rows)) return hosts;

  for (const row of rows) {
    const nameValue = typeof row?.name_value === "string" ? row.name_value : "";
    const commonName = typeof row?.common_name === "string" ? row.common_name : "";
    for (const part of `${nameValue}\n${commonName}`.split("\n")) {
      const host = normalizeHost(part, domain);
      if (host) hosts.add(host);
    }
  }
  return hosts;
}

function parseHackerTargetHosts(text: string, domain: string): Set<string> {
  const hosts = new Set<string>();
  for (const line of text.split("\n")) {
    const host = normalizeHost(line.split(",")[0] || "", domain);
    if (host) hosts.add(host);
  }
  return hosts;
}

async function fetchCrtShHosts(domain: string): Promise<Set<string>> {
  const url = `${CRT_SH_URL}?q=${encodeURIComponent(domain)}&output=json`;
  const res = await fetch(url, {
    headers: { Accept: "application/json", "User-Agent": "ReconForge/1.0" },
    signal: AbortSignal.timeout(25_000),
  });
  if (!res.ok) return new Set();
  try {
    return parseCrtShHosts(await res.json(), domain);
  } catch {
    return new Set();
  }
}

async function fetchHackerTargetHosts(domain: string): Promise<Set<string>> {
  const url = `${HACKERTARGET_URL}?q=${encodeURIComponent(domain)}`;
  const res = await fetch(url, {
    headers: { "User-Agent": "ReconForge/1.0" },
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) return new Set();
  const text = await res.text();
  if (text.toLowerCase().includes("error") && text.length < 120) return new Set();
  return parseHackerTargetHosts(text, domain);
}

async function resolveDns(host: string): Promise<string | null> {
  for (const type of ["A", "AAAA"] as const) {
    const url = `${DNS_QUERY_URL}?name=${encodeURIComponent(host)}&type=${type}`;
    try {
      const res = await fetch(url, {
        headers: { Accept: "application/dns-json" },
        signal: AbortSignal.timeout(8_000),
      });
      if (!res.ok) continue;
      const data = (await res.json()) as DnsJson;
      const answer = data.Answer?.find((a) => a.type === 1 || a.type === 28);
      if (answer?.data) return answer.data;
    } catch {
      // try next record type
    }
  }
  return null;
}

async function probeHttp(host: string): Promise<number> {
  const url = `https://${host}`;
  for (const method of ["HEAD", "GET"] as const) {
    try {
      const res = await fetch(url, {
        method,
        redirect: "manual",
        signal: AbortSignal.timeout(8_000),
      });
      if (res.status > 0) return res.status;
    } catch {
      // try GET after HEAD failure
    }
  }
  return 0;
}

async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<R>
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let index = 0;

  async function worker() {
    while (index < items.length) {
      const i = index++;
      results[i] = await fn(items[i]);
    }
  }

  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, () => worker()));
  return results;
}

function sortHosts(hosts: string[], domain: string): string[] {
  const rank = (host: string) => {
    if (host === domain) return 0;
    if (host === `www.${domain}`) return 1;
    return 2;
  };
  return [...hosts].sort((a, b) => {
    const dr = rank(a) - rank(b);
    return dr !== 0 ? dr : a.localeCompare(b);
  });
}

export interface EnumerateOptions {
  depth: ScanDepth;
  onCandidate?: (message: string) => void;
  onVerified?: (entry: SubdomainEntry) => void;
}

/**
 * Discover subdomains from CT logs, verify DNS resolution, and probe HTTP status.
 * Only returns hosts that resolve in DNS (alive at the network layer).
 */
export async function enumerateSubdomains(
  domain: string,
  options: EnumerateOptions
): Promise<SubdomainEntry[]> {
  const maxHosts = options.depth === "deep" ? 60 : 25;
  const candidates = new Set<string>([domain, `www.${domain}`]);

  options.onCandidate?.(`Querying Certificate Transparency (crt.sh) for ${domain}...`);
  const crtHosts = await fetchCrtShHosts(domain);
  for (const host of crtHosts) candidates.add(host);

  if (candidates.size < 5) {
    options.onCandidate?.(`Supplementing with passive DNS (hackertarget)...`);
    const htHosts = await fetchHackerTargetHosts(domain);
    for (const host of htHosts) candidates.add(host);
  }

  const sorted = sortHosts([...candidates], domain).slice(0, maxHosts * 3);
  options.onCandidate?.(`Verifying ${sorted.length} candidate hosts via DNS + HTTP...`);

  const verified = await mapWithConcurrency(sorted, 6, async (host) => {
    const ip = await resolveDns(host);
    if (!ip) return null;

    const status = await probeHttp(host);
    const entry: SubdomainEntry = {
      host,
      ip,
      status: status || 200,
      services: inferServices(host, domain),
    };
    options.onVerified?.(entry);
    return entry;
  });

  const alive = verified.filter((e): e is SubdomainEntry => e !== null);
  return alive.slice(0, maxHosts);
}
