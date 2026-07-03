/**
 * Live DNS intelligence — MX, TXT, SPF, DMARC, NS via DNS-over-HTTPS.
 * Inspired by Amass / theHarvester DNS recon modules.
 */

import type { DnsRecord, RiskLevel } from "../lib/types";

const DNS_PROVIDERS = [
  "https://cloudflare-dns.com/dns-query",
  "https://dns.google/resolve",
];

const TIMEOUT_MS = 12_000;

interface DnsAnswer {
  type: number;
  data: string;
  name?: string;
}

interface DnsJson {
  Status: number;
  Answer?: DnsAnswer[];
  Authority?: DnsAnswer[];
}

const TYPE_MAP: Record<string, number> = {
  A: 1,
  NS: 2,
  CNAME: 5,
  MX: 15,
  TXT: 16,
  AAAA: 28,
};

async function queryDns(name: string, type: string): Promise<string[]> {
  const typeNum = TYPE_MAP[type];
  if (!typeNum) return [];

  for (const base of DNS_PROVIDERS) {
    const url = `${base}?name=${encodeURIComponent(name)}&type=${type}`;
    try {
      const res = await fetch(url, {
        headers: { Accept: "application/dns-json" },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (!res.ok) continue;
      const data = (await res.json()) as DnsJson;
      const answers = [...(data.Answer || []), ...(data.Authority || [])];
      const values = answers
        .filter((a) => a.type === typeNum)
        .map((a) => a.data.replace(/\.$/, "").replace(/^"|"$/g, ""));
      if (values.length) return values;
    } catch {
      // try next resolver
    }
  }
  return [];
}

function assessTxtRisk(value: string): RiskLevel {
  const lower = value.toLowerCase();
  if (lower.includes("v=spf1") && lower.includes("+all")) return "high";
  if (lower.includes("v=spf1") && lower.includes("~all")) return "medium";
  if (lower.includes("v=dmarc1") && lower.includes("p=none")) return "medium";
  if (lower.includes("v=dmarc1") && (lower.includes("p=reject") || lower.includes("p=quarantine"))) {
    return "info";
  }
  if (/password|secret|api[_-]?key|token/i.test(value)) return "high";
  return "info";
}

function assessMxRisk(values: string[]): RiskLevel {
  if (!values.length) return "medium";
  const joined = values.join(" ").toLowerCase();
  if (joined.includes("google") || joined.includes("outlook") || joined.includes("proton")) return "info";
  return "info";
}

/** Enumerate DNS records for apex domain and derive OSINT-style findings. */
export async function enumerateDnsRecords(domain: string): Promise<DnsRecord[]> {
  const records: DnsRecord[] = [];

  const [ns, mx, txt, a] = await Promise.all([
    queryDns(domain, "NS"),
    queryDns(domain, "MX"),
    queryDns(domain, "TXT"),
    queryDns(domain, "A"),
  ]);

  for (const value of ns) {
    records.push({ type: "NS", name: domain, value, risk: "info" });
  }
  for (const value of mx) {
    records.push({ type: "MX", name: domain, value, risk: assessMxRisk(mx) });
  }
  for (const value of txt) {
    records.push({ type: "TXT", name: domain, value: value.slice(0, 200), risk: assessTxtRisk(value) });
  }
  for (const value of a) {
    records.push({ type: "A", name: domain, value, risk: "info" });
  }

  const dmarcHost = `_dmarc.${domain}`;
  const dmarc = await queryDns(dmarcHost, "TXT");
  for (const value of dmarc) {
    records.push({
      type: "DMARC",
      name: dmarcHost,
      value: value.slice(0, 200),
      risk: assessTxtRisk(value),
    });
  }

  return records;
}

export function dnsRecordsToOsint(records: DnsRecord[]): { category: string; detail: string; risk: RiskLevel }[] {
  const findings: { category: string; detail: string; risk: RiskLevel }[] = [];
  const mx = records.filter((r) => r.type === "MX");
  const txt = records.filter((r) => r.type === "TXT" || r.type === "DMARC");
  const ns = records.filter((r) => r.type === "NS");

  if (mx.length) {
    findings.push({
      category: "Mail Infrastructure",
      detail: `MX records: ${mx.map((r) => r.value).join(", ")}`,
      risk: "info",
    });
  } else {
    findings.push({
      category: "Mail Infrastructure",
      detail: "No MX records found — domain may not receive email directly",
      risk: "info",
    });
  }

  const spf = txt.find((r) => r.value.toLowerCase().includes("v=spf1"));
  if (spf) {
    findings.push({
      category: "SPF Record",
      detail: spf.value.slice(0, 120),
      risk: spf.risk,
    });
  } else {
    findings.push({
      category: "SPF Record",
      detail: "No SPF TXT record detected — email spoofing risk",
      risk: "medium",
    });
  }

  const dmarc = txt.find((r) => r.type === "DMARC" || r.value.toLowerCase().includes("v=dmarc1"));
  if (dmarc) {
    findings.push({
      category: "DMARC Policy",
      detail: dmarc.value.slice(0, 120),
      risk: dmarc.risk,
    });
  } else {
    findings.push({
      category: "DMARC Policy",
      detail: "No DMARC record at _dmarc — phishing protection incomplete",
      risk: "medium",
    });
  }

  if (ns.length) {
    findings.push({
      category: "Name Servers",
      detail: ns.map((r) => r.value).join(", "),
      risk: "info",
    });
  }

  const riskyTxt = txt.filter((r) => r.risk === "high");
  for (const r of riskyTxt) {
    findings.push({
      category: "DNS Secret Exposure",
      detail: `Suspicious TXT content on ${r.name}`,
      risk: "high",
    });
  }

  return findings;
}
