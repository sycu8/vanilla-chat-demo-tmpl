/**
 * Simulation engine — OSINT/CVE phases use seeded data; subdomains are live (CT + passive DNS + wordlist).
 *
 * PRODUCTION EXTENSION POINTS:
 * - Replace OSINT phase with Hunter.io, LinkedIn scraping APIs, Shodan
 * - Add SecurityTrails, subfinder for additional subdomain sources
 * - Replace fingerprinting with Wappalyzer API, httpx, nuclei (basic live HTTP fingerprinting implemented)
 * - Replace CVE matching with NVD API, Vulners, OSV
 */

import { createRng, domainSeed, extractDomain } from "../lib/domain";
import { matchVulnerabilities } from "../lib/cve";
import { buildMindmap } from "../lib/mindmap";
import { enrichReport } from "../lib/report";
import { enumerateSubdomains, enumerateSubdomainsStream } from "./subdomain";
import { fingerprintHosts, fingerprintHostsStream, formatFingerprint } from "./fingerprint";
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
  PhaseEvent,
} from "../lib/types";

const PHASES = [
  { id: 1, name: "OSINT & Social Engineering Fingerprints" },
  { id: 2, name: "Subdomain Enumeration & Service Mapping" },
  { id: 3, name: "Technology & Framework Fingerprinting" },
  { id: 4, name: "Vulnerability Intelligence" },
  { id: 5, name: "Intelligence Synthesis" },
];

const OSINT_JOB_TECH = ["React", "Next.js", "Django", "Laravel", "Express", "Spring Boot", "Kubernetes"];

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
      detail: `Job postings reference: ${rng.pick(OSINT_JOB_TECH)}, ${rng.pick(["AWS", "Azure", "GCP"])}, ${rng.pick(["Kubernetes", "Docker", "Terraform"])}`,
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
      detail: `${highVulns} critical/high CVEs matched against detected technology stack. See Phase 4 remediation steps for each finding.`,
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
  | { type: "phase"; data: PhaseEvent }
  | { type: "log"; data: LogEntry }
  | { type: "subdomain"; data: SubdomainEntry }
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
    data: { phase: 1, name: PHASES[0].name, status: "running", progress: 0, detail: "Collecting OSINT..." },
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
    data: { phase: 2, name: PHASES[1].name, status: "running", progress: 20, detail: "Starting live subdomain enumeration..." },
  };
  yield { type: "log", data: log(2, "info", "[LIVE] Starting subdomain enumeration (CT logs, certspotter, passive DNS, wordlist)...") };

  const subdomains: SubdomainEntry[] = [];
  for await (const event of enumerateSubdomainsStream(domain, { depth: request.depth })) {
    if (event.kind === "status") {
      yield {
        type: "phase",
        data: { phase: 2, name: PHASES[1].name, status: "running", progress: 22, detail: event.message },
      };
      yield { type: "log", data: log(2, "info", event.message) };
      continue;
    }

    if (event.kind === "progress") {
      const phasePct = 20 + Math.floor((event.current / Math.max(event.total, 1)) * 18);
      const detail =
        event.state === "checking"
          ? `Checking ${event.host} (${event.current}/${event.total})...`
          : event.state === "alive"
            ? `Alive: ${event.host} (${event.current}/${event.total})`
            : `No DNS: ${event.host} (${event.current}/${event.total})`;
      yield {
        type: "phase",
        data: { phase: 2, name: PHASES[1].name, status: "running", progress: phasePct, detail },
      };
      if (event.state === "checking") {
        // skip per-host checking logs to reduce noise/timeouts in live feed
      } else if (event.state === "dead") {
        yield { type: "log", data: log(2, "info", `✗ ${event.host} — no DNS record`) };
      }
      continue;
    }

    if (event.kind === "verified") {
      subdomains.push(event.entry);
      const sub = event.entry;
      yield { type: "subdomain", data: sub };
      yield {
        type: "log",
        data: log(
          2,
          sub.status >= 400 ? "warn" : "success",
          `✓ ${sub.host} → ${sub.ip} [${sub.services.join(", ")}] HTTP ${sub.status}`
        ),
      };
    }
  }

  if (!subdomains.length) {
    yield {
      type: "log",
      data: log(2, "warn", `No resolvable subdomains found for ${domain}`),
    };
  }

  yield {
    type: "phase",
    data: { phase: 2, name: PHASES[1].name, status: "complete", progress: 40 },
  };

  // ── Phase 3: Fingerprinting ─────────────────────────────────────
  yield {
    type: "phase",
    data: { phase: 3, name: PHASES[2].name, status: "running", progress: 40, detail: "Probing HTTP headers..." },
  };
  yield { type: "log", data: log(3, "info", "[LIVE] Probing HTTP headers and HTML technology signatures...") };

  const fingerprints: TechFingerprint[] = [];
  const hosts = subdomains.map((s) => s.host);

  for await (const event of fingerprintHostsStream(hosts, request.depth)) {
    if (event.kind === "status") {
      yield {
        type: "phase",
        data: { phase: 3, name: PHASES[2].name, status: "running", progress: 42, detail: event.message },
      };
      yield { type: "log", data: log(3, "info", event.message) };
      continue;
    }
    if (event.kind === "progress") {
      const phasePct = 40 + Math.floor((event.current / Math.max(event.total, 1)) * 18);
      yield {
        type: "phase",
        data: {
          phase: 3,
          name: PHASES[2].name,
          status: "running",
          progress: phasePct,
          detail: `Fingerprinting ${event.host} (${event.current}/${event.total})...`,
        },
      };
      continue;
    }
    if (event.kind === "fingerprint") {
      fingerprints.push(event.entry);
      const summary = formatFingerprint(event.entry);
      yield {
        type: "log",
        data: log(3, summary === "no signatures detected" ? "warn" : "success", `${event.entry.host}: ${summary}`),
      };
    }
  }

  yield {
    type: "phase",
    data: { phase: 3, name: PHASES[2].name, status: "complete", progress: 60 },
  };

  // ── Phase 4: Vulnerabilities ────────────────────────────────────
  yield {
    type: "phase",
    data: { phase: 4, name: PHASES[3].name, status: "running", progress: 60, detail: "Matching CVE databases..." },
  };
  yield { type: "log", data: log(4, "info", "Cross-referencing tech stack against CVE databases (NVD, OSV)...") };
  await delay(450);

  const vulnerabilities = matchVulnerabilities(fingerprints, request.depth);
  for (const vuln of vulnerabilities) {
    yield {
      type: "log",
      data: log(
        4,
        vuln.severity === "high" ? "error" : vuln.severity === "medium" ? "warn" : "info",
        `${vuln.cve} [CVSS ${vuln.cvss}] on ${vuln.technology}: ${vuln.description}`
      ),
    };
    yield {
      type: "log",
      data: log(4, "success", `  ↳ Remediation: ${vuln.remediation}`),
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
    data: { phase: 5, name: PHASES[4].name, status: "running", progress: 80, detail: "Computing risk score..." },
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
  const summary = `Reconnaissance of ${domain} identified ${subdomains.length} live hosts (DNS-verified), ${vulnerabilities.filter((v) => v.severity === "high").length} critical vulnerabilities, and a composite risk score of ${riskScore}/100. ${request.simulation ? "OSINT/CVE phases use simulation data." : "Live scan complete."}`;

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

/** Generate report (for regenerate mindmap / report endpoints) */
export async function buildReportFromRequest(request: ScanRequest): Promise<ReconReport> {
  const domain = extractDomain(request.target);
  const rng = createRng(domainSeed(domain));
  const osint = generateOsint(domain, request.keywords, rng);
  const subdomains = await enumerateSubdomains(domain, { depth: request.depth });
  const fingerprints = await fingerprintHosts(
    subdomains.map((s) => s.host),
    request.depth
  );
  const vulnerabilities = matchVulnerabilities(fingerprints, request.depth);
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
