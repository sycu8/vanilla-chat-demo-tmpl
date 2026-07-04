/**
 * Live subdomain enumeration — passive sources only (CT, CertSpotter, passive DNS, Wayback).
 * Only returns hosts discovered in historical/intelligence sources that still resolve in DNS.
 * No DNS wordlist brute force or synthetic permutations (avoids wildcard-DNS false positives).
 */

import type { ScanDepth, SubdomainEntry } from "../lib/types";

const CRT_SH_URL = "https://crt.sh/";
const HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/";
const CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances";
const WAYBACK_CDX_URL = "https://web.archive.org/cdx/search/cdx";
const DNS_PROVIDERS = [
  "https://cloudflare-dns.com/dns-query",
  "https://dns.google/resolve",
];

const TIMEOUTS = {
  crtSh: 45_000,
  certSpotter: 25_000,
  hackerTarget: 35_000,
  wayback: 20_000,
  dns: 12_000,
  http: 15_000,
};

const LIMITS = {
  quick: { maxAlive: 80, maxCandidates: 300, concurrency: 10, httpProbe: true },
  deep: { maxAlive: 150, maxCandidates: 500, concurrency: 12, httpProbe: true },
};

const TWO_PART_TLDS = new Set([
  "co.uk",
  "com.au",
  "co.jp",
  "com.vn",
  "net.vn",
  "org.uk",
  "ac.uk",
  "gov.uk",
]);

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

interface CertSpotterIssuance {
  dns_names?: string[];
}

export function getApexDomain(host: string): string {
  const parts = host.toLowerCase().split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");

  const lastTwo = parts.slice(-2).join(".");
  if (TWO_PART_TLDS.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

export function isApexDomain(host: string): boolean {
  return host.toLowerCase() === getApexDomain(host);
}

function inferServices(host: string, domain: string): string[] {
  const sub = host === domain ? "root" : host.slice(0, -(domain.length + 1));
  const label = sub.includes(".") ? sub.split(".")[0] : sub;
  if (label === "root") return ["Primary Website", "HTTPS"];
  return SERVICE_HINTS[label] || ["HTTPS", "HTTP"];
}

/** RFC 1035-ish hostname validation */
function isValidSubdomainHost(host: string): boolean {
  if (!host || host.length > 253) return false;
  const labels = host.split(".");
  if (labels.length < 2) return false;
  return labels.every(
    (label) =>
      label.length >= 1 &&
      label.length <= 63 &&
      /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(label)
  );
}

function normalizeHost(value: string, domain: string): string | null {
  let host = value.trim().toLowerCase();
  if (!host) return null;

  host = host.replace(/^\*\./, "");
  if (host.startsWith("www.") && host === `www.${domain}`) return host;
  if (host.endsWith(`.${domain}`) || host === domain) {
    if (host.includes(" ") || host.includes("*") || host.includes(",")) return null;
    if (!isValidSubdomainHost(host)) return null;
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

function parseCertSpotterHosts(rows: unknown, domain: string): Set<string> {
  const hosts = new Set<string>();
  if (!Array.isArray(rows)) return hosts;

  for (const row of rows as CertSpotterIssuance[]) {
    for (const name of row.dns_names || []) {
      const host = normalizeHost(name, domain);
      if (host) hosts.add(host);
    }
  }
  return hosts;
}

async function fetchJsonWithTimeout(url: string, timeoutMs: number): Promise<unknown | null> {
  try {
    const res = await fetch(url, {
      headers: { Accept: "application/json", "User-Agent": "ReconForge/2.0" },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

async function fetchCrtShHosts(domain: string, wildcard = false): Promise<Set<string>> {
  const query = wildcard ? `%.${domain}` : domain;
  const url = `${CRT_SH_URL}?q=${encodeURIComponent(query)}&output=json`;

  for (let attempt = 0; attempt < 2; attempt++) {
    const data = await fetchJsonWithTimeout(url, TIMEOUTS.crtSh);
    if (data) return parseCrtShHosts(data, domain);
    await new Promise((r) => setTimeout(r, 800 * (attempt + 1)));
  }
  return new Set();
}

async function fetchCertSpotterHosts(domain: string): Promise<Set<string>> {
  const url =
    `${CERTSPOTTER_URL}?domain=${encodeURIComponent(domain)}` +
    "&include_subdomains=true&expand=dns_names";
  const data = await fetchJsonWithTimeout(url, TIMEOUTS.certSpotter);
  return parseCertSpotterHosts(data, domain);
}

async function fetchHackerTargetHosts(domain: string): Promise<Set<string>> {
  const url = `${HACKERTARGET_URL}?q=${encodeURIComponent(domain)}`;
  try {
    const res = await fetch(url, {
      headers: { "User-Agent": "ReconForge/2.0" },
      signal: AbortSignal.timeout(TIMEOUTS.hackerTarget),
    });
    if (!res.ok) return new Set();
    const text = await res.text();
    if (text.toLowerCase().includes("error") && text.length < 120) return new Set();
    if (text.toLowerCase().includes("api count exceeded")) return new Set();
    return parseHackerTargetHosts(text, domain);
  } catch {
    return new Set();
  }
}

function parseWaybackHosts(rows: unknown, domain: string): Set<string> {
  const hosts = new Set<string>();
  if (!Array.isArray(rows)) return hosts;

  for (const row of rows.slice(1)) {
    const url = Array.isArray(row) ? row[0] : row;
    if (typeof url !== "string") continue;
    try {
      const host = new URL(url).hostname.toLowerCase();
      const normalized = normalizeHost(host, domain);
      if (normalized) hosts.add(normalized);
    } catch {
      // skip malformed archive URLs
    }
  }
  return hosts;
}

async function fetchWaybackHosts(domain: string, limit: number): Promise<Set<string>> {
  const url =
    `${WAYBACK_CDX_URL}?url=${encodeURIComponent(`*.${domain}/*`)}` +
    `&output=json&fl=original&collapse=urlkey&limit=${limit}`;
  const data = await fetchJsonWithTimeout(url, TIMEOUTS.wayback);
  return parseWaybackHosts(data, domain);
}

async function resolveDns(host: string): Promise<string | null> {
  for (const base of DNS_PROVIDERS) {
    for (const type of ["A", "AAAA", "CNAME"] as const) {
      const url = `${base}?name=${encodeURIComponent(host)}&type=${type}`;
      try {
        const res = await fetch(url, {
          headers: { Accept: "application/dns-json" },
          signal: AbortSignal.timeout(TIMEOUTS.dns),
        });
        if (!res.ok) continue;
        const data = (await res.json()) as DnsJson;
        const answer = data.Answer?.find((a) => a.type === 1 || a.type === 5 || a.type === 28);
        if (answer?.data) return answer.data.replace(/\.$/, "");
      } catch {
        // try next resolver / record type
      }
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
        signal: AbortSignal.timeout(TIMEOUTS.http),
        headers: { "User-Agent": "ReconForge/2.0" },
      });
      if (res.status > 0) return res.status;
    } catch {
      // try GET after HEAD failure
    }
  }
  return 0;
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

async function verifyHost(
  host: string,
  domain: string,
  httpProbe: boolean
): Promise<SubdomainEntry | null> {
  const ip = await resolveDns(host);
  if (!ip) return null;

  let status = 0;
  if (httpProbe) {
    status = await probeHttp(host);
  }

  return {
    host,
    ip,
    status,
    services: inferServices(host, domain),
  };
}

async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let index = 0;

  async function worker() {
    while (index < items.length) {
      const i = index++;
      results[i] = await fn(items[i], i);
    }
  }

  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, () => worker()));
  return results;
}

export interface EnumerateOptions {
  depth: ScanDepth;
  onCandidate?: (message: string) => void;
  onVerified?: (entry: SubdomainEntry) => void;
  onProgress?: (current: number, total: number, host: string, state: "checking" | "alive" | "dead") => void;
}

export type SubdomainStreamEvent =
  | { kind: "status"; message: string }
  | { kind: "progress"; current: number; total: number; host: string; state: "checking" | "alive" | "dead" }
  | { kind: "verified"; entry: SubdomainEntry };

/** Collect passive-only candidates from CT, CertSpotter, HackerTarget, and Wayback. */
async function collectPassiveCandidates(
  apex: string,
  depth: ScanDepth
): Promise<{ candidates: Set<string>; sourceCounts: Record<string, number> }> {
  const candidates = new Set<string>([apex, `www.${apex}`]);
  const waybackLimit = depth === "deep" ? 400 : 200;

  const [crtHosts, crtWildcardHosts, certSpotterHosts, htHosts, waybackHosts] = await Promise.all([
    fetchCrtShHosts(apex),
    fetchCrtShHosts(apex, true),
    fetchCertSpotterHosts(apex),
    fetchHackerTargetHosts(apex),
    fetchWaybackHosts(apex, waybackLimit),
  ]);

  for (const host of crtHosts) candidates.add(host);
  for (const host of crtWildcardHosts) candidates.add(host);
  for (const host of certSpotterHosts) candidates.add(host);
  for (const host of htHosts) candidates.add(host);
  for (const host of waybackHosts) candidates.add(host);

  return {
    candidates,
    sourceCounts: {
      crtSh: crtHosts.size,
      crtWildcard: crtWildcardHosts.size,
      certSpotter: certSpotterHosts.size,
      hackerTarget: htHosts.size,
      wayback: waybackHosts.size,
    },
  };
}

/** Stream subdomain discovery with incremental progress events. */
export async function* enumerateSubdomainsStream(
  domain: string,
  options: Pick<EnumerateOptions, "depth">
): AsyncGenerator<SubdomainStreamEvent> {
  const apex = getApexDomain(domain);
  const limits = options.depth === "deep" ? LIMITS.deep : LIMITS.quick;

  // Always include the user's exact target if it's a valid in-scope host
  const seedHosts = new Set<string>([apex, `www.${apex}`]);
  const normalizedTarget = normalizeHost(extractTargetHost(domain), apex);
  if (normalizedTarget) seedHosts.add(normalizedTarget);

  yield {
    kind: "status",
    message: `Querying passive sources (crt.sh, certspotter, passive DNS, wayback) for ${apex}...`,
  };

  const { candidates: passiveCandidates, sourceCounts } = await collectPassiveCandidates(
    apex,
    options.depth
  );

  for (const host of seedHosts) passiveCandidates.add(host);

  yield {
    kind: "status",
    message:
      `Passive sources: crt.sh=${sourceCounts.crtSh}, wildcard=${sourceCounts.crtWildcard}, ` +
      `certspotter=${sourceCounts.certSpotter}, passive DNS=${sourceCounts.hackerTarget}, ` +
      `wayback=${sourceCounts.wayback} → ${passiveCandidates.size} unique candidates (no wordlist brute force)`,
  };

  const sorted = sortHosts([...passiveCandidates], apex).slice(0, limits.maxCandidates);
  const total = sorted.length;

  yield {
    kind: "status",
    message: `Verifying ${total} passive-sourced hosts (${limits.concurrency} parallel, DNS ${TIMEOUTS.dns / 1000}s)...`,
  };

  const alive: SubdomainEntry[] = [];
  let checked = 0;

  for (let offset = 0; offset < sorted.length && alive.length < limits.maxAlive; offset += limits.concurrency) {
    const batch = sorted.slice(offset, offset + limits.concurrency);

    for (const host of batch) {
      checked++;
      yield { kind: "progress", current: checked, total, host, state: "checking" };
    }

    const results = await mapWithConcurrency(batch, limits.concurrency, (host) =>
      verifyHost(host, apex, limits.httpProbe)
    );

    for (let i = 0; i < batch.length; i++) {
      const host = batch[i];
      const entry = results[i];
      if (!entry) {
        yield { kind: "progress", current: checked - batch.length + i + 1, total, host, state: "dead" };
        continue;
      }
      alive.push(entry);
      yield { kind: "progress", current: checked - batch.length + i + 1, total, host, state: "alive" };
      yield { kind: "verified", entry };
      if (alive.length >= limits.maxAlive) break;
    }
  }

  yield { kind: "status", message: `Enumeration complete — ${alive.length} verified live host(s) from passive sources` };
}

function extractTargetHost(domain: string): string {
  return domain.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0] || domain;
}

/**
 * Discover subdomains from passive intelligence sources, verify DNS resolution.
 * Only returns hosts with historical evidence (CT / passive DNS / archive) that still resolve.
 */
export async function enumerateSubdomains(
  domain: string,
  options: EnumerateOptions
): Promise<SubdomainEntry[]> {
  const entries: SubdomainEntry[] = [];
  for await (const event of enumerateSubdomainsStream(domain, options)) {
    if (event.kind === "status") options.onCandidate?.(event.message);
    if (event.kind === "progress") options.onProgress?.(event.current, event.total, event.host, event.state);
    if (event.kind === "verified") {
      entries.push(event.entry);
      options.onVerified?.(event.entry);
    }
  }
  return entries;
}
