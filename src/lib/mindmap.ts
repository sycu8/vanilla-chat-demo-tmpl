/**
 * Mermaid mindmap generator for recon visualization.
 * Produces syntax compatible with Mermaid v11+ mindmap diagrams.
 */

import type {
  ReconReport,
  RiskLevel,
  SubdomainEntry,
  TechFingerprint,
  Vulnerability,
} from "./types";

function riskEmoji(risk: RiskLevel): string {
  switch (risk) {
    case "high":
      return "🔴";
    case "medium":
      return "🟡";
    default:
      return "🟢";
  }
}

function sanitize(label: string): string {
  return label.replace(/[()[\]{}]/g, "").replace(/"/g, "'").slice(0, 48);
}

/** Build interactive mindmap Mermaid source from recon report data */
export function buildMindmap(report: ReconReport): string {
  const root = sanitize(report.domain);
  const lines: string[] = [
    "mindmap",
    `  root((${root}))`,
    "    OSINT Intel",
  ];

  for (const finding of report.osint.slice(0, 6)) {
    lines.push(
      `      ${riskEmoji(finding.risk)} ${sanitize(finding.category)}`
    );
  }

  lines.push("    Subdomains");
  for (const sub of report.subdomains.slice(0, 8)) {
    const services = sub.services.slice(0, 2).join(", ");
    lines.push(`      ${sanitize(sub.host)}`);
    if (services) {
      lines.push(`        ${sanitize(services)}`);
    }
  }

  lines.push("    Tech Stack");
  const uniqueTech = new Map<string, TechFingerprint>();
  for (const fp of report.fingerprints) {
    const key = `${fp.framework || fp.cms || fp.server}-${fp.version || ""}`;
    if (!uniqueTech.has(key)) uniqueTech.set(key, fp);
  }
  for (const fp of [...uniqueTech.values()].slice(0, 6)) {
    const label = [fp.framework, fp.cms, fp.server, fp.version]
      .filter(Boolean)
      .join(" ");
    lines.push(`      ${sanitize(label || fp.host)}`);
  }

  lines.push("    Vulnerabilities");
  for (const vuln of report.vulnerabilities.slice(0, 6)) {
    lines.push(
      `      ${riskEmoji(vuln.severity)} ${sanitize(vuln.cve)} ${sanitize(vuln.technology)}`
    );
  }

  lines.push("    Risk Score");
  lines.push(`      ${report.riskScore}/100 ${riskEmoji(report.riskLevel)}`);

  return lines.join("\n");
}

/** Regenerate mindmap with optional layout variation */
export function regenerateMindmap(
  report: ReconReport,
  variant = 0
): string {
  const base = buildMindmap(report);
  if (variant === 0) return base;

  // Alternate grouping: cluster by risk
  const lines: string[] = [
    "mindmap",
    `  root((${sanitize(report.domain)}))`,
  ];

  const highVulns = report.vulnerabilities.filter((v) => v.severity === "high");
  const medVulns = report.vulnerabilities.filter((v) => v.severity === "medium");
  const infoVulns = report.vulnerabilities.filter((v) => v.severity === "info");

  lines.push(`    High Risk ${riskEmoji("high")}`);
  for (const v of highVulns.slice(0, 4)) {
    lines.push(`      ${sanitize(v.cve)} on ${sanitize(v.technology)}`);
  }

  lines.push(`    Medium Risk ${riskEmoji("medium")}`);
  for (const v of medVulns.slice(0, 4)) {
    lines.push(`      ${sanitize(v.cve)}`);
  }

  lines.push(`    Attack Surface`);
  for (const sub of report.subdomains.slice(0, 6)) {
    lines.push(`      ${sanitize(sub.host)}`);
  }

  lines.push(`    Informational ${riskEmoji("info")}`);
  for (const v of infoVulns.slice(0, 3)) {
    lines.push(`      ${sanitize(v.cve)}`);
  }

  return lines.join("\n");
}
