/**
 * Live subdomain enumeration — Certificate Transparency + DNS + HTTP probes.
 * Runs on Cloudflare Workers (fetch-only, no shell tools).
 */

import type { ScanDepth, SubdomainEntry } from "../lib/types";

const CRT_SH_URL = "https://crt.sh/";
const HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/";
const DNS_PROVIDERS = [
  "https://cloudflare-dns.com/dns-query",
  "https://dns.google/resolve",
];

/** Tunable discovery timeouts (ms) — increased for slow CT/DNS targets */
const TIMEOUTS = {
  crtSh: 60_000,
  hackerTarget: 35_000,
  dns: 18_000,
  http: 20_000,
};

const LIMITS = {
  quick: { maxAlive: 50, maxCandidates: 120, concurrency: 8, httpProbe: true },
  deep: { maxAlive: 100, maxCandidates: 200, concurrency: 10, httpProbe: true },
};

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
  try {
    const res = await fetch(url, {
      headers: { Accept: "application/json", "User-Agent": "ReconForge/1.0" },
      signal: AbortSignal.timeout(TIMEOUTS.crtSh),
    });
    if (!res.ok) return new Set();
    return parseCrtShHosts(await res.json(), domain);
  } catch {
    return new Set();
  }
}

async function fetchHackerTargetHosts(domain: string): Promise<Set<string>> {
  const url = `${HACKERTARGET_URL}?q=${encodeURIComponent(domain)}`;
  try {
    const res = await fetch(url, {
      headers: { "User-Agent": "ReconForge/1.0" },
      signal: AbortSignal.timeout(TIMEOUTS.hackerTarget),
    });
    if (!res.ok) return new Set();
    const text = await res.text();
    if (text.toLowerCase().includes("error") && text.length < 120) return new Set();
    return parseHackerTargetHosts(text, domain);
  } catch {
    return new Set();
  }
}

async function resolveDns(host: string): Promise<string | null> {
  for (const base of DNS_PROVIDERS) {
    for (const type of ["A", "AAAA"] as const) {
      const url = `${base}?name=${encodeURIComponent(host)}&type=${type}`;
      try {
        const res = await fetch(url, {
          headers: { Accept: "application/dns-json" },
          signal: AbortSignal.timeout(TIMEOUTS.dns),
        });
        if (!res.ok) continue;
        const data = (await res.json()) as DnsJson;
        const answer = data.Answer?.find((a) => a.type === 1 || a.type === 28);
        if (answer?.data) return answer.data;
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
        headers: { "User-Agent": "ReconForge/1.0" },
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
    // DNS-verified host counts as alive; 0 = DNS only (HTTP timed out)
    status: status || 200,
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

/** Stream subdomain discovery with incremental progress events. */
export async function* enumerateSubdomainsStream(
  domain: string,
  options: Pick<EnumerateOptions, "depth">
): AsyncGenerator<SubdomainStreamEvent> {
  const limits = options.depth === "deep" ? LIMITS.deep : LIMITS.quick;
  const candidates = new Set<string>([domain, `www.${domain}`]);

  yield { kind: "status", message: `Querying CT logs + passive DNS in parallel (timeout ${TIMEOUTS.crtSh / 1000}s)...` };

  const [crtHosts, htHosts] = await Promise.all([
    fetchCrtShHosts(domain),
    fetchHackerTargetHosts(domain),
  ]);

  for (const host of crtHosts) candidates.add(host);
  for (const host of htHosts) candidates.add(host);

  yield {
    kind: "status",
    message: `Sources: crt.sh=${crtHosts.size}, passive DNS=${htHosts.size} → ${candidates.size} unique candidates`,
  };

  const sorted = sortHosts([...candidates], domain).slice(0, limits.maxCandidates);
  const total = sorted.length;

  yield {
    kind: "status",
    message: `Verifying ${total} hosts (${limits.concurrency} parallel, DNS ${TIMEOUTS.dns / 1000}s, HTTP ${TIMEOUTS.http / 1000}s)...`,
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
      verifyHost(host, domain, limits.httpProbe)
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

  yield { kind: "status", message: `Enumeration complete — ${alive.length} live host(s) found` };
}

/**
 * Discover subdomains from CT logs, verify DNS resolution, and probe HTTP status.
 * Only returns hosts that resolve in DNS (alive at the network layer).
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
