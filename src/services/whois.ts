/**
 * RDAP/WHOIS lookup via public RDAP servers.
 */

import type { OsintFinding } from "../lib/types";

const TIMEOUT_MS = 12_000;

interface RdapEntity {
  vcardArray?: unknown[];
  roles?: string[];
}

interface RdapResponse {
  handle?: string;
  ldhName?: string;
  status?: string[];
  events?: { eventAction: string; eventDate: string }[];
  entities?: RdapEntity[];
  nameservers?: { ldhName: string }[];
}

export async function fetchWhoisIntel(domain: string): Promise<OsintFinding[]> {
  const findings: OsintFinding[] = [];
  const url = `https://rdap.org/domain/${encodeURIComponent(domain)}`;

  try {
    const res = await fetch(url, {
      headers: { Accept: "application/rdap+json", "User-Agent": "ReconForge/2.0" },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) {
      findings.push({
        category: "WHOIS/RDAP",
        detail: `RDAP lookup returned HTTP ${res.status} for ${domain}`,
        risk: "info",
      });
      return findings;
    }

    const data = (await res.json()) as RdapResponse;
    if (data.ldhName) {
      findings.push({ category: "WHOIS/RDAP", detail: `Registered domain: ${data.ldhName}`, risk: "info" });
    }
    if (data.status?.length) {
      findings.push({
        category: "Domain Status",
        detail: data.status.join(", "),
        risk: data.status.some((s) => /hold|pending|redemption/i.test(s)) ? "medium" : "info",
      });
    }
    const registration = data.events?.find((e) => e.eventAction === "registration");
    if (registration?.eventDate) {
      findings.push({
        category: "Registration Date",
        detail: `Domain registered: ${registration.eventDate.slice(0, 10)}`,
        risk: "info",
      });
    }
    if (data.nameservers?.length) {
      findings.push({
        category: "WHOIS Nameservers",
        detail: data.nameservers.map((n) => n.ldhName).join(", "),
        risk: "info",
      });
    }
  } catch {
    findings.push({
      category: "WHOIS/RDAP",
      detail: `RDAP lookup timed out for ${domain}`,
      risk: "info",
    });
  }

  return findings;
}
