/**
 * Live subdomain enumeration — Certificate Transparency + passive DNS + wordlist brute force.
 * Runs on Cloudflare Workers (fetch-only, no shell tools).
 */

import type { ScanDepth, SubdomainEntry } from "../lib/types";

const CRT_SH_URL = "https://crt.sh/";
const HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/";
const CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances";
const DNS_PROVIDERS = [
  "https://cloudflare-dns.com/dns-query",
  "https://dns.google/resolve",
];

/** Tunable discovery timeouts (ms) */
const TIMEOUTS = {
  crtSh: 45_000,
  certSpotter: 25_000,
  hackerTarget: 35_000,
  dns: 12_000,
  http: 15_000,
};

const LIMITS = {
  quick: { maxAlive: 60, maxCandidates: 220, concurrency: 10, httpProbe: true },
  deep: { maxAlive: 120, maxCandidates: 400, concurrency: 12, httpProbe: true },
};

/** Extra headroom when the user scans an apex/root domain (not a single subdomain). */
const ROOT_DOMAIN_BONUS = {
  quick: { maxCandidates: 80, bruteLabels: 140 },
  deep: { maxCandidates: 150, bruteLabels: 220 },
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

/** High-yield labels for DNS brute force on apex domains */
const BRUTE_FORCE_LABELS = [
  "www",
  "mail",
  "webmail",
  "smtp",
  "pop",
  "imap",
  "mx",
  "mx1",
  "mx2",
  "ns",
  "ns1",
  "ns2",
  "dns",
  "dns1",
  "dns2",
  "api",
  "api2",
  "api-v2",
  "admin",
  "administrator",
  "panel",
  "cpanel",
  "whm",
  "app",
  "apps",
  "portal",
  "dashboard",
  "console",
  "manage",
  "backend",
  "frontend",
  "dev",
  "development",
  "staging",
  "stage",
  "uat",
  "qa",
  "test",
  "testing",
  "beta",
  "alpha",
  "demo",
  "sandbox",
  "preview",
  "blog",
  "news",
  "cms",
  "wiki",
  "kb",
  "docs",
  "doc",
  "help",
  "support",
  "status",
  "cdn",
  "static",
  "assets",
  "media",
  "img",
  "images",
  "files",
  "file",
  "upload",
  "downloads",
  "storage",
  "s3",
  "git",
  "gitlab",
  "github",
  "bitbucket",
  "jenkins",
  "ci",
  "cd",
  "build",
  "deploy",
  "registry",
  "docker",
  "k8s",
  "kubernetes",
  "grafana",
  "prometheus",
  "monitor",
  "monitoring",
  "metrics",
  "log",
  "logs",
  "logging",
  "elastic",
  "kibana",
  "sentry",
  "auth",
  "login",
  "sso",
  "oauth",
  "identity",
  "account",
  "accounts",
  "my",
  "secure",
  "ssl",
  "vpn",
  "remote",
  "rdp",
  "cloud",
  "aws",
  "azure",
  "gcp",
  "db",
  "database",
  "mysql",
  "postgres",
  "redis",
  "mongo",
  "search",
  "shop",
  "store",
  "m",
  "mobile",
  "intranet",
  "extranet",
  "hr",
  "crm",
  "erp",
  "sap",
  "chat",
  "meet",
  "video",
  "stream",
  "live",
  "forum",
  "community",
  "ask",
  "onboarding",
  "onboarding-uat",
  "omc",
  "mcp",
  "mcp-workers",
  "bhxh",
  "stocknews",
  "wcstat",
  "wcstat-uat",
  "yo",
  "rag-test",
  "autodiscover",
  "owa",
  "exchange",
  "calendar",
  "drive",
  "share",
  "old",
  "new",
  "v1",
  "v2",
  "v3",
  "internal",
  "external",
  "public",
  "private",
  "proxy",
  "gateway",
  "lb",
  "loadbalancer",
  "origin",
  "edge",
  "worker",
  "workers",
  "service",
  "services",
  "micro",
  "microservice",
  "web",
  "web1",
  "web2",
  "server",
  "host",
  "node",
  "cluster",
  "backup",
  "bak",
  "archive",
  "legacy",
  "prod",
  "production",
  "preprod",
  "pre-prod",
  "canary",
  "release",
  "rc",
];

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
      headers: { Accept: "application/json", "User-Agent": "ReconForge/1.0" },
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

function buildBruteForceHosts(apex: string, labelLimit: number): Set<string> {
  const hosts = new Set<string>();
  for (const label of BRUTE_FORCE_LABELS.slice(0, labelLimit)) {
    const host = normalizeHost(`${label}.${apex}`, apex);
    if (host) hosts.add(host);
  }
  return hosts;
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
        headers: { "User-Agent": "ReconForge/1.0" },
      });
      if (res.status > 0) return res.status;
    } catch {
      // try GET after HEAD failure
    }
  }
  return 0;
}

function sortHosts(hosts: string[], domain: string, passiveFirst: Set<string>): string[] {
  const rank = (host: string) => {
    if (host === domain) return 0;
    if (host === `www.${domain}`) return 1;
    if (passiveFirst.has(host)) return 2;
    return 3;
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
  const apex = getApexDomain(domain);
  const scanApex = isApexDomain(domain);
  const baseLimits = options.depth === "deep" ? LIMITS.deep : LIMITS.quick;
  const rootBonus = options.depth === "deep" ? ROOT_DOMAIN_BONUS.deep : ROOT_DOMAIN_BONUS.quick;
  const limits = {
    ...baseLimits,
    maxCandidates: baseLimits.maxCandidates + (scanApex ? rootBonus.maxCandidates : 0),
  };

  const candidates = new Set<string>([domain, apex, `www.${apex}`]);
  const passiveHosts = new Set<string>();

  const sourceParts = ["crt.sh", "crt.sh wildcard", "certspotter", "passive DNS"];
  if (scanApex) sourceParts.push("DNS wordlist");

  yield {
    kind: "status",
    message: `Querying ${sourceParts.join(" + ")} for ${apex}${scanApex ? " (root domain — expanded discovery)" : ""}...`,
  };

  const [crtHosts, crtWildcardHosts, certSpotterHosts, htHosts] = await Promise.all([
    fetchCrtShHosts(apex),
    fetchCrtShHosts(apex, true),
    fetchCertSpotterHosts(apex),
    fetchHackerTargetHosts(apex),
  ]);

  for (const host of crtHosts) {
    candidates.add(host);
    passiveHosts.add(host);
  }
  for (const host of crtWildcardHosts) {
    candidates.add(host);
    passiveHosts.add(host);
  }
  for (const host of certSpotterHosts) {
    candidates.add(host);
    passiveHosts.add(host);
  }
  for (const host of htHosts) {
    candidates.add(host);
    passiveHosts.add(host);
  }

  let bruteCount = 0;
  if (scanApex) {
    const bruteHosts = buildBruteForceHosts(apex, rootBonus.bruteLabels);
    bruteCount = bruteHosts.size;
    for (const host of bruteHosts) candidates.add(host);
  }

  yield {
    kind: "status",
    message:
      `Sources: crt.sh=${crtHosts.size}, wildcard=${crtWildcardHosts.size}, ` +
      `certspotter=${certSpotterHosts.size}, passive DNS=${htHosts.size}` +
      (scanApex ? `, wordlist=${bruteCount}` : "") +
      ` → ${candidates.size} unique candidates`,
  };

  const sorted = sortHosts([...candidates], apex, passiveHosts).slice(0, limits.maxCandidates);
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
