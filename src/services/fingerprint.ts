/**
 * Live technology fingerprinting — HTTP headers + HTML signatures.
 */

import type { ScanDepth, TechFingerprint } from "../lib/types";

const BODY_LIMIT = 48_000;
const PROBE_TIMEOUT_MS = 18_000;
const SECURITY_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
];

function extractTitle(body: string): string | undefined {
  const match = body.match(/<title[^>]*>([^<]{1,120})<\/title>/i);
  return match?.[1]?.trim().replace(/\s+/g, " ");
}

function scoreSecurityHeaders(headers: Headers): { score: number; missing: string[] } {
  let score = 0;
  const missing: string[] = [];
  const weights: Record<string, number> = {
    "strict-transport-security": 25,
    "content-security-policy": 25,
    "x-frame-options": 20,
    "x-content-type-options": 15,
    "referrer-policy": 10,
    "permissions-policy": 5,
  };

  for (const [name, weight] of Object.entries(weights)) {
    if (headers.has(name)) score += weight;
    else missing.push(name);
  }

  return { score, missing };
}

export type FingerprintStreamEvent =
  | { kind: "status"; message: string }
  | { kind: "progress"; current: number; total: number; host: string }
  | { kind: "fingerprint"; entry: TechFingerprint };

interface ProbeResult {
  status: number;
  headers: Headers;
  body: string;
  finalUrl: string;
}

async function probeHost(host: string): Promise<ProbeResult | null> {
  const url = `https://${host}`;
  try {
    const res = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
      headers: {
        Accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        "User-Agent": "ReconForge/1.0 (security-recon)",
      },
    });
    const body = await res.text();
    return {
      status: res.status,
      headers: res.headers,
      body: body.slice(0, BODY_LIMIT),
      finalUrl: res.url || url,
    };
  } catch {
    return null;
  }
}

function header(headers: Headers, name: string): string | undefined {
  const value = headers.get(name);
  return value?.trim() || undefined;
}

function extractVersion(text: string, pattern: RegExp): string | undefined {
  const match = text.match(pattern);
  return match?.[1]?.trim();
}

function detectFromHtml(body: string): {
  framework?: string;
  cms?: string;
  version?: string;
  signals: string[];
} {
  const signals: string[] = [];
  let framework: string | undefined;
  let cms: string | undefined;
  let version: string | undefined;

  const generator = extractVersion(body, /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i)
    || extractVersion(body, /content=["']([^"']+)["'][^>]+name=["']generator["']/i);
  if (generator) {
    signals.push(`generator:${generator}`);
    if (/astro/i.test(generator)) {
      framework = "Astro";
      version = extractVersion(generator, /v?(\d+\.\d+(?:\.\d+)?)/i);
    } else if (/wordpress/i.test(generator)) {
      cms = "WordPress";
      version = extractVersion(generator, /(\d+\.\d+(?:\.\d+)?)/);
    } else if (/next\.js/i.test(generator)) {
      framework = "Next.js";
      version = extractVersion(generator, /(\d+\.\d+(?:\.\d+)?)/);
    } else if (/hugo/i.test(generator)) {
      framework = "Hugo";
      version = extractVersion(generator, /(\d+\.\d+(?:\.\d+)?)/);
    } else if (/ghost/i.test(generator)) {
      cms = "Ghost";
      version = extractVersion(generator, /(\d+\.\d+(?:\.\d+)?)/);
    }
  }

  if (body.includes("__NEXT_DATA__") || body.includes("/_next/static/")) {
    framework = framework || "Next.js";
    signals.push("html:nextjs");
  }
  if (body.includes("/_astro/") || body.includes("astro-view-transitions")) {
    framework = framework || "Astro";
    signals.push("html:astro");
  }
  if (body.includes("/wp-content/") || body.includes("/wp-includes/")) {
    cms = cms || "WordPress";
    signals.push("html:wordpress");
  }
  if (body.includes("react-root") || body.includes("__REACT_DEVTOOLS")) {
    framework = framework || "React";
    signals.push("html:react");
  }
  if (body.includes("ng-version") || body.includes("ng-app")) {
    framework = framework || "Angular";
    signals.push("html:angular");
  }
  if (body.includes("data-v-") || body.includes("/assets/index-")) {
    if (!framework) framework = "Vue";
    signals.push("html:vue");
  }
  if (/cdn\.tailwindcss\.com/i.test(body)) {
    signals.push("html:tailwind-cdn");
  }
  if (body.includes("cloudflare-static/rocket-loader")) {
    signals.push("html:cloudflare-rocket-loader");
  }
  if (/Cloudflare Compass/i.test(body)) {
    framework = framework || "Cloudflare Workers (static)";
    signals.push("html:cloudflare-compass");
  }

  return { framework, cms, version, signals };
}

function detectFromHeaders(headers: Headers): {
  server?: string;
  framework?: string;
  cms?: string;
  cdn?: string;
  notable: string[];
} {
  const notable: string[] = [];
  const server = header(headers, "server");
  const poweredBy = header(headers, "x-powered-by");
  const via = header(headers, "via");
  const cfRay = header(headers, "cf-ray");
  const cfCache = header(headers, "cf-cache-status");

  let framework: string | undefined;
  let cms: string | undefined;
  let cdn: string | undefined;

  if (cfRay || (server && /cloudflare/i.test(server))) {
    cdn = "Cloudflare";
    notable.push("cf-ray");
  }
  if (cfCache) notable.push("cf-cache-status");
  if (header(headers, "x-nextjs-prerender") || header(headers, "x-next-cache-tags")) {
    framework = "Next.js";
    notable.push("x-nextjs");
  }
  if (poweredBy) {
    notable.push("x-powered-by");
    if (/express/i.test(poweredBy)) framework = "Express";
    else if (/php/i.test(poweredBy)) framework = "PHP";
    else if (/asp\.net/i.test(poweredBy)) framework = "ASP.NET";
    else framework = poweredBy;
  }
  if (via && /cloudfront/i.test(via)) cdn = "Amazon CloudFront";
  if (server) {
    if (/nginx/i.test(server)) notable.push("nginx");
    if (/apache/i.test(server)) notable.push("apache");
    if (/caddy/i.test(server)) notable.push("caddy");
  }

  for (const name of SECURITY_HEADERS) {
    if (headers.has(name)) notable.push(name);
  }

  return { server, framework, cms, cdn, notable };
}

export function buildFingerprint(host: string, probe: ProbeResult): TechFingerprint {
  const fromHeaders = detectFromHeaders(probe.headers);
  const fromHtml = detectFromHtml(probe.body);
  const { score, missing } = scoreSecurityHeaders(probe.headers);

  const framework = fromHtml.framework || fromHeaders.framework;
  const cms = fromHtml.cms || fromHeaders.cms;
  const server = [fromHeaders.server, fromHeaders.cdn].filter(Boolean).join(" / ") || undefined;
  const version = fromHtml.version;
  const title = extractTitle(probe.body);

  const headers = [...new Set([...fromHeaders.notable, ...fromHtml.signals])].slice(0, 12);

  return {
    host,
    server,
    framework,
    cms,
    version,
    headers,
    title,
    contentLength: probe.body.length,
    finalUrl: probe.finalUrl !== `https://${host}` && probe.finalUrl !== `https://${host}/` ? probe.finalUrl : undefined,
    securityScore: score,
    missingHeaders: missing,
  };
}

export async function fingerprintHost(host: string): Promise<TechFingerprint | null> {
  const probe = await probeHost(host);
  if (!probe || probe.status >= 500) return null;
  return buildFingerprint(host, probe);
}

/** Stream live fingerprinting with per-host progress. */
export async function* fingerprintHostsStream(
  hosts: string[],
  depth: ScanDepth
): AsyncGenerator<FingerprintStreamEvent> {
  const limit = depth === "deep" ? hosts.length : Math.min(hosts.length, 12);
  const targets = hosts.slice(0, limit);
  const total = targets.length;

  yield { kind: "status", message: `Fingerprinting ${total} live host(s) via HTTP headers + HTML...` };

  for (let i = 0; i < targets.length; i++) {
    const host = targets[i];
    yield { kind: "progress", current: i + 1, total, host };

    const fp = await fingerprintHost(host);
    if (fp) {
      yield { kind: "fingerprint", entry: fp };
    } else {
      yield {
        kind: "fingerprint",
        entry: { host, headers: ["probe-failed"] },
      };
    }
  }

  yield { kind: "status", message: "Technology fingerprinting complete" };
}

export async function fingerprintHosts(hosts: string[], depth: ScanDepth): Promise<TechFingerprint[]> {
  const results: TechFingerprint[] = [];
  for await (const event of fingerprintHostsStream(hosts, depth)) {
    if (event.kind === "fingerprint") results.push(event.entry);
  }
  return results;
}

export function formatFingerprint(fp: TechFingerprint): string {
  const parts = [fp.server, fp.framework, fp.cms, fp.version].filter(Boolean);
  const title = fp.title ? `"${fp.title.slice(0, 40)}"` : "";
  const sec = fp.securityScore !== undefined ? `sec:${fp.securityScore}` : "";
  const meta = [title, sec].filter(Boolean).join(" ");
  if (parts.length) return meta ? `${parts.join(" | ")} (${meta})` : parts.join(" | ");
  if (fp.headers.length) return `headers: ${fp.headers.slice(0, 4).join(", ")}`;
  return "no signatures detected";
}
