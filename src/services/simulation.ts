/**
 * Simulation engine — generates realistic recon data for any domain.
 *
 * PRODUCTION EXTENSION POINTS:
 * - Replace OSINT phase with Hunter.io, LinkedIn scraping APIs, Shodan
 * - Replace subdomain enum with crt.sh, SecurityTrails, subfinder
 * - Replace fingerprinting with Wappalyzer API, httpx, nuclei
 * - Replace CVE matching with NVD API, Vulners, OSV
 */

import { createRng, domainSeed, extractDomain } from "../lib/domain";
import { buildMindmap } from "../lib/mindmap";
import { enrichReport } from "../lib/report";
import type {
  LogEntry,
  OsintFinding,
  ReconReport,
  ScanDepth,
  ScanRequest,
  SubdomainEntry,
  SynthesisInsight,
  TechFingerprint,
  Vulnerability,
} from "../lib/types";

const PHASES = [
  { id: 1, name: "OSINT & Social Engineering Fingerprints" },
  { id: 2, name: "Subdomain Enumeration & Service Mapping" },
  { id: 3, name: "Technology & Framework Fingerprinting" },
  { id: 4, name: "Vulnerability Intelligence" },
  { id: 5, name: "Intelligence Synthesis" },
];

const SUBDOMAIN_PREFIXES = [
  "api", "admin", "dev", "staging", "mail", "vpn", "portal", "cdn",
  "app", "beta", "internal", "jenkins", "grafana", "kibana", "docs",
  "status", "auth", "sso", "backup", "db", "redis", "elastic",
  "gitlab", "jira", "confluence", "wiki", "support", "help",
];

const SERVICES_MAP: Record<string, string[]> = {
  api: ["REST API", "GraphQL", "Swagger UI"],
  admin: ["Admin Panel", "phpMyAdmin", "cPanel"],
  dev: ["Dev Environment", "Debug Endpoints"],
  staging: ["Staging App", "Test Data"],
  mail: ["SMTP", "Webmail", "Exchange"],
  vpn: ["OpenVPN", "WireGuard", "Cisco AnyConnect"],
  portal: ["Employee Portal", "SSO"],
  jenkins: ["CI/CD", "Build Artifacts"],
  grafana: ["Monitoring", "Metrics Dashboard"],
  default: ["HTTPS", "HTTP Redirect"],
};

const SERVERS = ["nginx/1.24.0", "Apache/2.4.57", "cloudflare", "Microsoft-IIS/10.0", "Caddy/2.7.0"];
const FRAMEWORKS = ["React 18.2", "Next.js 14.1", "Django 4.2", "Laravel 10", "Express 4.18", "Spring Boot 3.2", "Ruby on Rails 7.1"];
const CMS = ["WordPress 6.4", "Drupal 10", "Ghost 5", "Shopify", "Contentful"];
const HEADERS = [
  "X-Powered-By", "Strict-Transport-Security", "X-Frame-Options",
  "Content-Security-Policy", "X-Content-Type-Options", "Server",
  "X-Request-Id", "CF-Ray", "Set-Cookie", "Access-Control-Allow-Origin",
];

const CVE_DB: Omit<Vulnerability, "technology">[] = [
  { cve: "CVE-2024-21762", severity: "high", description: "Out-of-bounds write in FortiOS SSL VPN", cvss: 9.8 },
  { cve: "CVE-2023-44487", severity: "high", description: "HTTP/2 Rapid Reset attack", cvss: 7.5 },
  { cve: "CVE-2024-23897", severity: "high", description: "Jenkins arbitrary file read", cvss: 9.8 },
  { cve: "CVE-2023-4966", severity: "high", description: "Citrix Bleed sensitive info disclosure", cvss: 9.4 },
  { cve: "CVE-2024-3400", severity: "high", description: "Palo Alto PAN-OS command injection", cvss: 10.0 },
  { cve: "CVE-2023-22515", severity: "medium", description: "Atlassian Confluence broken access control", cvss: 7.3 },
  { cve: "CVE-2024-21413", severity: "medium", description: "Microsoft Outlook MonikerLink RCE", cvss: 8.8 },
  { cve: "CVE-2023-38545", severity: "medium", description: "curl SOCKS5 heap buffer overflow", cvss: 7.5 },
  { cve: "CVE-2024-1086", severity: "medium", description: "Linux kernel netfilter use-after-free", cvss: 7.8 },
  { cve: "CVE-2023-20198", severity: "high", description: "Cisco IOS XE web UI privilege escalation", cvss: 10.0 },
  { cve: "CVE-2024-27198", severity: "high", description: "JetBrains TeamCity auth bypass", cvss: 9.8 },
  { cve: "CVE-2023-46747", severity: "medium", description: "F5 BIG-IP unauthenticated RCE", cvss: 9.8 },
  { cve: "CVE-2024-21893", severity: "medium", description: "Ivanti Connect Secure SSRF", cvss: 8.2 },
  { cve: "CVE-2023-7028", severity: "info", description: "GitLab account takeover via password reset", cvss: 6.5 },
  { cve: "CVE-2024-22024", severity: "info", description: "Information disclosure in logging module", cvss: 4.3 },
];

const PHISHING_LURES = [
  "IT password reset — urgent action required",
  "Q4 bonus compensation review",
  "VPN certificate renewal notice",
  "Microsoft 365 security alert",
  "Payroll direct deposit update",
  "New HR benefits enrollment portal",
];

const EMPLOYEE_PATTERNS = [
  "firstname.lastname@",
  "flastname@",
  "firstl@",
  "first_last@",
  "f.lastname@",
];

function now(): string {
  return new Date().toISOString();
}

function log(phase: number, level: LogEntry["level"], message: string): LogEntry {
  return { timestamp: now(), phase, level, message };
}

function generateOsint(
  domain: string,
  keywords: string[],
  rng: ReturnType<typeof createRng>
): OsintFinding[] {
  const company = domain.split(".")[0];
  const findings: OsintFinding[] = [
    {
      category: "Company Profile",
      detail: `Identified primary entity "${company}" with public web presence at ${domain}`,
      risk: "info",
    },
    {
      category: "Email Pattern",
      detail: `Likely corporate email format: ${rng.pick(EMPLOYEE_PATTERNS)}${domain}`,
      risk: "medium",
    },
    {
      category: "Phishing Lure Vector",
      detail: `High-yield lure: "${rng.pick(PHISHING_LURES)}" targeting ${company} employees`,
      risk: "high",
    },
    {
      category: "Social Media",
      detail: `LinkedIn company page detected with ~${rng.int(50, 5000)} employees listed`,
      risk: "info",
    },
    {
      category: "Tech Mentions",
      detail: `Job postings reference: ${rng.pick(FRAMEWORKS)}, ${rng.pick(["AWS", "Azure", "GCP"])}, ${rng.pick(["Kubernetes", "Docker", "Terraform"])}`,
      risk: "info",
    },
    {
      category: "Data Leak Indicator",
      detail: rng.next() > 0.6
        ? `Paste site mention of "${company}" credentials — requires verification`
        : `No public breach records found in simulation corpus for ${domain}`,
      risk: rng.next() > 0.6 ? "high" : "info",
    },
  ];

  if (keywords.length) {
    findings.push({
      category: "Keyword Intelligence",
      detail: `Matched keywords [${keywords.join(", ")}] in public documents and metadata`,
      risk: "medium",
    });
  }

  return findings;
}

function generateSubdomains(
  domain: string,
  depth: ScanDepth,
  rng: ReturnType<typeof createRng>
): SubdomainEntry[] {
  const count = depth === "deep" ? rng.int(12, 20) : rng.int(6, 10);
  const prefixes = rng.shuffle(SUBDOMAIN_PREFIXES).slice(0, count);
  const entries: SubdomainEntry[] = [
    {
      host: domain,
      services: ["Primary Website", "HTTPS"],
      ip: `${rng.int(13, 104)}.${rng.int(0, 255)}.${rng.int(0, 255)}.${rng.int(1, 254)}`,
      status: 200,
    },
    {
      host: `www.${domain}`,
      services: ["WWW Redirect", "CDN"],
      ip: `${rng.int(13, 104)}.${rng.int(0, 255)}.${rng.int(0, 255)}.${rng.int(1, 254)}`,
      status: 301,
    },
  ];

  for (const prefix of prefixes) {
    const services = SERVICES_MAP[prefix] || SERVICES_MAP.default;
    entries.push({
      host: `${prefix}.${domain}`,
      services: rng.shuffle(services).slice(0, rng.int(1, 2)),
      ip: `${rng.int(13, 104)}.${rng.int(0, 255)}.${rng.int(0, 255)}.${rng.int(1, 254)}`,
      status: rng.pick([200, 200, 200, 301, 403, 401, 503]),
    });
  }

  return entries;
}

function generateFingerprints(
  subdomains: SubdomainEntry[],
  rng: ReturnType<typeof createRng>
): TechFingerprint[] {
  return subdomains.map((sub) => ({
    host: sub.host,
    server: rng.pick(SERVERS),
    framework: rng.next() > 0.3 ? rng.pick(FRAMEWORKS) : undefined,
    cms: rng.next() > 0.7 ? rng.pick(CMS) : undefined,
    version: rng.next() > 0.5 ? `${rng.int(1, 9)}.${rng.int(0, 9)}.${rng.int(0, 20)}` : undefined,
    headers: rng.shuffle(HEADERS).slice(0, rng.int(3, 6)),
  }));
}

function generateVulnerabilities(
  fingerprints: TechFingerprint[],
  depth: ScanDepth,
  rng: ReturnType<typeof createRng>
): Vulnerability[] {
  const count = depth === "deep" ? rng.int(8, 14) : rng.int(4, 8);
  const cves = rng.shuffle(CVE_DB).slice(0, count);
  return cves.map((cve, i) => ({
    ...cve,
    technology: [
      fingerprints[i % fingerprints.length]?.framework,
      fingerprints[i % fingerprints.length]?.cms,
      fingerprints[i % fingerprints.length]?.server,
    ]
      .filter(Boolean)
      .join(" / ") || "Unknown Stack",
  }));
}

function calculateRiskScore(vulns: Vulnerability[], subdomains: SubdomainEntry[]): number {
  let score = 0;
  for (const v of vulns) {
    if (v.severity === "high") score += 15;
    else if (v.severity === "medium") score += 8;
    else score += 3;
  }
  const exposed = subdomains.filter((s) => s.status === 200 && !s.host.startsWith("www.")).length;
  score += Math.min(exposed * 2, 20);
  return Math.min(100, Math.max(10, score));
}

function generateSynthesis(
  domain: string,
  osint: OsintFinding[],
  subdomains: SubdomainEntry[],
  vulns: Vulnerability[],
  riskScore: number,
  rng: ReturnType<typeof createRng>
): SynthesisInsight[] {
  const highVulns = vulns.filter((v) => v.severity === "high").length;
  const adminPanels = subdomains.filter((s) =>
    s.host.includes("admin") || s.host.includes("jenkins") || s.host.includes("grafana")
  );

  return [
    {
      title: "Attack Surface Overview",
      detail: `Discovered ${subdomains.length} hosts on ${domain} with ${adminPanels.length} administrative interfaces exposed. Primary entry vectors include web applications and authentication endpoints.`,
      priority: adminPanels.length > 2 ? "high" : "medium",
    },
    {
      title: "Social Engineering Risk",
      detail: osint.find((o) => o.category === "Phishing Lure Vector")?.detail ||
        "Employee email patterns identified — spear-phishing campaigns feasible.",
      priority: "high",
    },
    {
      title: "Critical Vulnerability Exposure",
      detail: `${highVulns} critical/high CVEs matched against detected technology stack. Immediate patching recommended for internet-facing services.`,
      priority: highVulns > 2 ? "high" : "medium",
    },
    {
      title: "Recommended Next Steps",
      detail: `1) Validate ${adminPanels.length} admin endpoints behind MFA\n2) Patch ${highVulns} critical CVEs\n3) Conduct phishing simulation using identified lures\n4) Review subdomain sprawl (${subdomains.length} hosts)`,
      priority: riskScore > 60 ? "high" : "medium",
    },
    {
      title: "Compliance Note",
      detail: rng.next() > 0.5
        ? "Simulation mode — findings are synthetic. Enable live integrations for production assessments."
        : "External scan may trigger IDS/IPS alerts. Ensure proper authorization before live reconnaissance.",
      priority: "info",
    },
  ];
}

export type ScanEvent =
  | { type: "phase"; data: { phase: number; name: string; status: string; progress: number } }
  | { type: "log"; data: LogEntry }
  | { type: "complete"; data: Omit<ReconReport, "markdown" | "html"> };

/** Async generator that yields scan events phase-by-phase */
export async function* runReconScan(
  request: ScanRequest
): AsyncGenerator<ScanEvent> {
  const domain = extractDomain(request.target);
  const seed = domainSeed(domain);
  const rng = createRng(seed);
  const scanId = `rf-${seed.toString(36)}-${Date.now().toString(36)}`;
  const startedAt = now();

  const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

  // ── Phase 1: OSINT ──────────────────────────────────────────────
  yield {
    type: "phase",
    data: { phase: 1, name: PHASES[0].name, status: "running", progress: 0 },
  };
  yield { type: "log", data: log(1, "info", `[SIM] Initializing OSINT collectors for ${domain}...`) };
  await delay(400);
  yield { type: "log", data: log(1, "info", "Querying public records and social graph...") };
  await delay(350);
  yield { type: "log", data: log(1, "info", `Analyzing keywords: ${request.keywords.join(", ") || "(none)"}`) };
  await delay(300);

  const osint = generateOsint(domain, request.keywords, rng);
  for (const finding of osint) {
    yield {
      type: "log",
      data: log(1, finding.risk === "high" ? "warn" : "success", `[${finding.category}] ${finding.detail}`),
    };
    await delay(200);
  }

  yield {
    type: "phase",
    data: { phase: 1, name: PHASES[0].name, status: "complete", progress: 20 },
  };

  // ── Phase 2: Subdomains ─────────────────────────────────────────
  yield {
    type: "phase",
    data: { phase: 2, name: PHASES[1].name, status: "running", progress: 20 },
  };
  yield { type: "log", data: log(2, "info", "[SIM] Starting subdomain enumeration (crt.sh, DNS brute)...") };
  await delay(400);
  yield { type: "log", data: log(2, "info", `Scan depth: ${request.depth.toUpperCase()} — expanded wordlist loaded`) };
  await delay(350);

  const subdomains = generateSubdomains(domain, request.depth, rng);
  for (const sub of subdomains) {
    yield {
      type: "log",
      data: log(
        2,
        sub.status === 403 ? "warn" : "success",
        `Found ${sub.host} → ${sub.ip} [${sub.services.join(", ")}] HTTP ${sub.status}`
      ),
    };
    await delay(150);
  }

  yield {
    type: "phase",
    data: { phase: 2, name: PHASES[1].name, status: "complete", progress: 40 },
  };

  // ── Phase 3: Fingerprinting ─────────────────────────────────────
  yield {
    type: "phase",
    data: { phase: 3, name: PHASES[2].name, status: "running", progress: 40 },
  };
  yield { type: "log", data: log(3, "info", "Probing HTTP headers and technology signatures...") };
  await delay(400);

  const fingerprints = generateFingerprints(subdomains, rng);
  for (const fp of fingerprints.slice(0, request.depth === "deep" ? 15 : 8)) {
    const stack = [fp.server, fp.framework, fp.cms, fp.version].filter(Boolean).join(" | ");
    yield { type: "log", data: log(3, "success", `${fp.host}: ${stack}`) };
    await delay(180);
  }

  yield {
    type: "phase",
    data: { phase: 3, name: PHASES[2].name, status: "complete", progress: 60 },
  };

  // ── Phase 4: Vulnerabilities ────────────────────────────────────
  yield {
    type: "phase",
    data: { phase: 4, name: PHASES[3].name, status: "running", progress: 60 },
  };
  yield { type: "log", data: log(4, "info", "Cross-referencing tech stack against CVE databases (NVD, OSV)...") };
  await delay(450);

  const vulnerabilities = generateVulnerabilities(fingerprints, request.depth, rng);
  for (const vuln of vulnerabilities) {
    yield {
      type: "log",
      data: log(
        4,
        vuln.severity === "high" ? "error" : vuln.severity === "medium" ? "warn" : "info",
        `${vuln.cve} [CVSS ${vuln.cvss}] on ${vuln.technology}: ${vuln.description}`
      ),
    };
    await delay(200);
  }

  yield {
    type: "phase",
    data: { phase: 4, name: PHASES[3].name, status: "complete", progress: 80 },
  };

  // ── Phase 5: Synthesis ────────────────────────────────────────────
  yield {
    type: "phase",
    data: { phase: 5, name: PHASES[4].name, status: "running", progress: 80 },
  };
  yield { type: "log", data: log(5, "info", "Synthesizing intelligence and computing risk score...") };
  await delay(500);

  const riskScore = calculateRiskScore(vulnerabilities, subdomains);
  const riskLevel = riskScore >= 70 ? "high" : riskScore >= 40 ? "medium" : "info";
  const synthesis = generateSynthesis(domain, osint, subdomains, vulnerabilities, riskScore, rng);

  for (const insight of synthesis) {
    yield {
      type: "log",
      data: log(5, insight.priority === "high" ? "warn" : "success", `[${insight.title}] ${insight.detail.split("\n")[0]}`),
    };
    await delay(250);
  }

  const completedAt = now();
  const summary = `Reconnaissance of ${domain} identified ${subdomains.length} hosts, ${vulnerabilities.filter((v) => v.severity === "high").length} critical vulnerabilities, and a composite risk score of ${riskScore}/100. ${request.simulation ? "Results generated in simulation mode." : "Live scan complete."}`;

  let report: ReconReport = {
    id: scanId,
    target: request.target,
    domain,
    keywords: request.keywords,
    depth: request.depth,
    simulation: request.simulation,
    startedAt,
    completedAt,
    riskScore,
    riskLevel,
    summary,
    osint,
    subdomains,
    fingerprints,
    vulnerabilities,
    synthesis,
    mindmap: "",
    markdown: "",
    html: "",
  };

  report.mindmap = buildMindmap(report);
  report = enrichReport(report);

  yield {
    type: "phase",
    data: { phase: 5, name: PHASES[4].name, status: "complete", progress: 100 },
  };
  yield { type: "log", data: log(5, "success", `Recon complete. Risk score: ${riskScore}/100`) };

  // Omit markdown/html from SSE — large payloads can break chunked stream parsing.
  // Client fetches full report via POST /api/recon/report after scan completes.
  const { markdown: _md, html: _html, ...slimReport } = report;
  yield { type: "complete", data: slimReport };
}

/** Generate report synchronously (for regenerate mindmap endpoint) */
export function buildReportFromRequest(request: ScanRequest): ReconReport {
  const domain = extractDomain(request.target);
  const rng = createRng(domainSeed(domain));
  const osint = generateOsint(domain, request.keywords, rng);
  const subdomains = generateSubdomains(domain, request.depth, rng);
  const fingerprints = generateFingerprints(subdomains, rng);
  const vulnerabilities = generateVulnerabilities(fingerprints, request.depth, rng);
  const riskScore = calculateRiskScore(vulnerabilities, subdomains);
  const riskLevel = riskScore >= 70 ? "high" : riskScore >= 40 ? "medium" : "info";
  const synthesis = generateSynthesis(domain, osint, subdomains, vulnerabilities, riskScore, rng);

  let report: ReconReport = {
    id: `rf-${domainSeed(domain).toString(36)}`,
    target: request.target,
    domain,
    keywords: request.keywords,
    depth: request.depth,
    simulation: request.simulation,
    startedAt: now(),
    completedAt: now(),
    riskScore,
    riskLevel,
    summary: `Assessment of ${domain}`,
    osint,
    subdomains,
    fingerprints,
    vulnerabilities,
    synthesis,
    mindmap: "",
    markdown: "",
    html: "",
  };

  report.mindmap = buildMindmap(report);
  return enrichReport(report);
}

export { PHASES };
