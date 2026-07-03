/**
 * Curated CVE catalog with remediation guidance.
 */

import type { ScanDepth, TechFingerprint, Vulnerability } from "./types";

export interface CveCatalogEntry {
  cve: string;
  severity: Vulnerability["severity"];
  description: string;
  cvss: number;
  tags: string[];
  remediation: string;
}

export const CVE_CATALOG: CveCatalogEntry[] = [
  {
    cve: "CVE-2023-44487",
    severity: "high",
    description: "HTTP/2 Rapid Reset attack — denial of service via stream cancellation",
    cvss: 7.5,
    tags: ["cloudflare", "nginx", "next.js", "http", "astro"],
    remediation:
      "Keep Cloudflare proxy enabled (orange-to-cloud) so edge mitigations apply. Patch origin web servers (nginx ≥1.25.3, Apache ≥2.4.58) if they terminate HTTP/2 directly. Enable rate limiting and monitor for abnormal HTTP/2 connection churn.",
  },
  {
    cve: "CVE-2024-23897",
    severity: "high",
    description: "Jenkins arbitrary file read via CLI",
    cvss: 9.8,
    tags: ["jenkins"],
    remediation:
      "Upgrade Jenkins to ≥2.426.3 LTS or ≥2.442. Immediately restrict Jenkins to internal VPN/IP allowlist. Disable anonymous CLI access, enforce MFA for admins, and audit build artifacts for exposed secrets.",
  },
  {
    cve: "CVE-2023-22515",
    severity: "medium",
    description: "Atlassian Confluence broken access control (unauthenticated RCE chain)",
    cvss: 7.3,
    tags: ["confluence", "atlassian"],
    remediation:
      "Upgrade Confluence to a vendor-patched version. Remove public internet exposure; require SSO/VPN. Review plugin surface and delete unused macros. Scan for webshell indicators in Confluence home directories.",
  },
  {
    cve: "CVE-2024-27198",
    severity: "high",
    description: "JetBrains TeamCity authentication bypass",
    cvss: 9.8,
    tags: ["teamcity", "jetbrains"],
    remediation:
      "Upgrade TeamCity to the latest security release. Place TeamCity behind VPN or IP allowlist. Rotate CI/CD secrets and review pipeline logs for unauthorized builds or credential exfiltration.",
  },
  {
    cve: "CVE-2023-7028",
    severity: "info",
    description: "GitLab account takeover via password reset",
    cvss: 6.5,
    tags: ["gitlab"],
    remediation:
      "Upgrade GitLab to ≥16.7.7 / 16.8.2 / 16.9.1. Enforce 2FA for all users, restrict self-registration, and audit password-reset email routing. Review audit logs for suspicious account changes.",
  },
  {
    cve: "CVE-2023-4966",
    severity: "high",
    description: "Citrix Bleed — sensitive memory disclosure in NetScaler ADC/Gateway",
    cvss: 9.4,
    tags: ["citrix"],
    remediation:
      "Apply Citrix security patches immediately. Invalidate all active sessions and rotate VPN/SSO credentials. Monitor for lateral movement from VPN entry points.",
  },
  {
    cve: "CVE-2024-3400",
    severity: "high",
    description: "Palo Alto PAN-OS GlobalProtect command injection",
    cvss: 10.0,
    tags: ["palo", "pan-os"],
    remediation:
      "Upgrade PAN-OS to vendor-fixed release. Restrict GlobalProtect portal to managed devices. Hunt for IoCs (unusual cron jobs, unknown admin users) and rotate firewall management credentials.",
  },
  {
    cve: "CVE-2023-38545",
    severity: "medium",
    description: "curl SOCKS5 heap buffer overflow",
    cvss: 7.5,
    tags: ["curl"],
    remediation:
      "Upgrade curl/libcurl to ≥8.4.0 on build agents and servers. Rebuild container images that bundle curl. Review CI pipelines that proxy traffic through SOCKS.",
  },
  {
    cve: "CVE-2024-1086",
    severity: "medium",
    description: "Linux kernel netfilter use-after-free (local privilege escalation)",
    cvss: 7.8,
    tags: ["linux"],
    remediation:
      "Patch kernel to vendor-fixed version (≥6.1.76 / 6.6.15 / 6.7.3 or distro equivalent). Reboot nodes after patching. Restrict unprivileged user namespaces if immediate patch is not possible.",
  },
  {
    cve: "CVE-2024-21413",
    severity: "medium",
    description: "Microsoft Outlook MonikerLink remote code execution",
    cvss: 8.8,
    tags: ["microsoft", "exchange", "outlook"],
    remediation:
      "Apply Microsoft security updates for Office/Outlook. Block suspicious external MonikerLink handlers via email gateway rules. Run phishing awareness training focused on calendar/meeting invite lures.",
  },
  {
    cve: "CVE-2024-46982",
    severity: "high",
    description: "Next.js cache poisoning / authorization bypass in some deployments",
    cvss: 7.5,
    tags: ["next.js", "nextjs"],
    remediation:
      "Upgrade Next.js to the latest patched release for your major version. Review middleware auth checks on all dynamic routes. Disable public caching for authenticated pages and validate CDN cache keys.",
  },
  {
    cve: "CVE-2024-34351",
    severity: "medium",
    description: "Next.js Server Actions SSRF in misconfigured setups",
    cvss: 6.5,
    tags: ["next.js", "nextjs"],
    remediation:
      "Upgrade Next.js to a patched version. Restrict Server Actions to trusted origins. Validate outbound fetch URLs and block metadata/IP endpoints (169.254.169.254) from application servers.",
  },
];

function stackLabel(fp: TechFingerprint): string {
  return [fp.framework, fp.cms, fp.server, fp.version].filter(Boolean).join(" / ") || "Unknown Stack";
}

function stackHaystack(fp: TechFingerprint): string {
  return `${fp.host} ${stackLabel(fp)} ${fp.headers.join(" ")}`.toLowerCase();
}

/** Match CVEs to detected technology stack and attach remediation guidance. */
export function matchVulnerabilities(
  fingerprints: TechFingerprint[],
  depth: ScanDepth
): Vulnerability[] {
  const max = depth === "deep" ? 10 : 6;
  const matched: Vulnerability[] = [];
  const seen = new Set<string>();

  for (const fp of fingerprints) {
    const haystack = stackHaystack(fp);
    const tech = stackLabel(fp);

    for (const entry of CVE_CATALOG) {
      if (seen.has(entry.cve)) continue;
      const hit = entry.tags.some((tag) => haystack.includes(tag));
      if (hit) {
        const { tags: _tags, ...cve } = entry;
        matched.push({ ...cve, technology: tech });
        seen.add(entry.cve);
      }
    }
  }

  // HTTP/2 Rapid Reset applies to most modern HTTPS stacks on Cloudflare
  if (!seen.has("CVE-2023-44487") && fingerprints.length) {
    const { tags: _tags, ...cve } = CVE_CATALOG[0];
    matched.push({ ...cve, technology: stackLabel(fingerprints[0]) });
  }

  return matched.slice(0, max);
}
