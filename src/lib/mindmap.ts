/**
 * Mermaid mindmap generator for recon visualization.
 * Produces syntax compatible with Mermaid v11+ mindmap diagrams.
 */

import type { ReconReport, RiskLevel } from "./types";

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

/** Format node labels — quote text that breaks Mermaid parsing (dots, slashes, etc.) */
function mermaidLabel(label: string): string {
  const clean = label.replace(/"/g, "'").slice(0, 48);
  if (/[.:/\\@#&|<>]/.test(clean) || /\s{2,}/.test(clean)) {
    return `"${clean}"`;
  }
  return clean;
}

/** Circle root node for domain — always quoted since domains contain dots */
function mermaidRoot(domain: string): string {
  const clean = domain.replace(/"/g, "").slice(0, 64);
  return `(("${clean}"))`;
}

/** Build interactive mindmap Mermaid source from recon report data */
export function buildMindmap(report: ReconReport): string {
  const lines: string[] = [
    "mindmap",
    `  root${mermaidRoot(report.domain)}`,
    "    OSINT Intel",
  ];

  for (const finding of report.osint.slice(0, 6)) {
    lines.push(
      `      ${riskEmoji(finding.risk)} ${mermaidLabel(finding.category)}`
    );
  }

  lines.push("    Subdomains");
  for (const sub of report.subdomains.slice(0, 8)) {
    const services = sub.services.slice(0, 2).join(", ");
    lines.push(`      ${mermaidLabel(sub.host)}`);
    if (services) {
      lines.push(`        ${mermaidLabel(services)}`);
    }
  }

  lines.push("    Tech Stack");
  const uniqueTech = new Map<string, string>();
  for (const fp of report.fingerprints) {
    const key = `${fp.framework || fp.cms || fp.server}-${fp.version || ""}`;
    if (!uniqueTech.has(key)) {
      const label = [fp.framework, fp.cms, fp.server, fp.version]
        .filter(Boolean)
        .join(" ");
      uniqueTech.set(key, label || fp.host);
    }
  }
  for (const label of [...uniqueTech.values()].slice(0, 6)) {
    lines.push(`      ${mermaidLabel(label)}`);
  }

  lines.push("    Vulnerabilities");
  for (const vuln of report.vulnerabilities.slice(0, 6)) {
    lines.push(
      `      ${riskEmoji(vuln.severity)} ${mermaidLabel(`${vuln.cve} ${vuln.technology}`)}`
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
  if (variant === 0) return buildMindmap(report);

  const lines: string[] = [
    "mindmap",
    `  root${mermaidRoot(report.domain)}`,
  ];

  const highVulns = report.vulnerabilities.filter((v) => v.severity === "high");
  const medVulns = report.vulnerabilities.filter((v) => v.severity === "medium");
  const infoVulns = report.vulnerabilities.filter((v) => v.severity === "info");

  lines.push(`    High Risk ${riskEmoji("high")}`);
  for (const v of highVulns.slice(0, 4)) {
    lines.push(`      ${mermaidLabel(`${v.cve} on ${v.technology}`)}`);
  }

  lines.push(`    Medium Risk ${riskEmoji("medium")}`);
  for (const v of medVulns.slice(0, 4)) {
    lines.push(`      ${mermaidLabel(v.cve)}`);
  }

  lines.push("    Attack Surface");
  for (const sub of report.subdomains.slice(0, 6)) {
    lines.push(`      ${mermaidLabel(sub.host)}`);
  }

  lines.push(`    Informational ${riskEmoji("info")}`);
  for (const v of infoVulns.slice(0, 3)) {
    lines.push(`      ${mermaidLabel(v.cve)}`);
  }

  return lines.join("\n");
}
