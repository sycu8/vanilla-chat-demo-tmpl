/**
 * Live OSINT enrichment — WHOIS + email patterns + optional Shodan hints.
 */

import type { OsintFinding } from "../lib/types";
import { fetchWhoisIntel } from "./whois";
import { getApexDomain } from "./subdomain";

export async function gatherLiveOsint(
  domain: string,
  keywords: string[],
  shodanKey?: string
): Promise<OsintFinding[]> {
  const apex = getApexDomain(domain);
  const findings: OsintFinding[] = [];

  const whois = await fetchWhoisIntel(apex);
  findings.push(...whois);

  findings.push({
    category: "Email Pattern",
    detail: `Common corporate formats: firstname.lastname@${apex}, f.lastname@${apex}`,
    risk: "info",
  });

  if (keywords.length) {
    findings.push({
      category: "Keyword Intelligence",
      detail: `Tracked keywords: [${keywords.join(", ")}] — use in dorking and breach monitoring`,
      risk: "info",
    });
  }

  if (shodanKey) {
    try {
      const res = await fetch(`https://api.shodan.io/dns/domain/${encodeURIComponent(apex)}?key=${shodanKey}`, {
        signal: AbortSignal.timeout(12_000),
      });
      if (res.ok) {
        const data = (await res.json()) as { subdomains?: string[] };
        if (data.subdomains?.length) {
          findings.push({
            category: "Shodan DNS",
            detail: `${data.subdomains.length} subdomain(s) indexed by Shodan passive DNS`,
            risk: "info",
          });
        }
      }
    } catch {
      findings.push({ category: "Shodan DNS", detail: "Shodan lookup timed out", risk: "info" });
    }
  }

  findings.push({
    category: "Google Dork Helpers",
    detail: `site:${apex} ext:pdf | site:${apex} inurl:admin | site:${apex} "password" filetype:log`,
    risk: "info",
  });

  return findings;
}
