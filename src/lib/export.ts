/**
 * JSON and SARIF export formats.
 */

import type { ReconReport, SecurityFinding, Vulnerability } from "./types";

export function exportJson(report: ReconReport): string {
  const { markdown: _m, html: _h, ...data } = report;
  return JSON.stringify(data, null, 2);
}

function sarifLevel(severity: string): "error" | "warning" | "note" {
  if (severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

function vulnToResult(v: Vulnerability) {
  return {
    ruleId: v.cve,
    level: sarifLevel(v.severity),
    message: { text: `${v.description} (${v.technology})` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: `https://${v.host}` },
        },
      },
    ],
    properties: {
      cvss: v.cvss,
      remediation: v.remediation,
      host: v.host,
    },
  };
}

function exposureToResult(f: SecurityFinding) {
  return {
    ruleId: f.id,
    level: sarifLevel(f.severity),
    message: { text: f.description },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: `https://${f.host}` },
        },
      },
    ],
    properties: {
      category: f.category,
      remediation: f.remediation,
    },
  };
}

export function exportSarif(report: ReconReport): string {
  const rules = new Map<string, { id: string; name: string; shortDescription: { text: string } }>();

  for (const v of report.vulnerabilities) {
    rules.set(v.cve, { id: v.cve, name: v.cve, shortDescription: { text: v.description } });
  }
  for (const f of report.securityFindings) {
    rules.set(f.id, { id: f.id, name: f.title, shortDescription: { text: f.description } });
  }

  const sarif = {
    version: "2.1.0",
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "ReconForge",
            version: "2.0.0",
            informationUri: "https://reconforge.sycu-lee.workers.dev",
            rules: [...rules.values()],
          },
        },
        results: [
          ...report.vulnerabilities.map(vulnToResult),
          ...report.securityFindings.filter((f) => f.severity !== "info").map(exposureToResult),
        ],
        properties: {
          domain: report.domain,
          riskScore: report.riskScore,
          scanId: report.id,
        },
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
