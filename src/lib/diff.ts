/**
 * Scan diff — compare two recon reports.
 */

import type { ReconReport } from "./types";

export interface ScanDiff {
  baseId: string;
  compareId: string;
  domain: string;
  riskScoreDelta: number;
  newSubdomains: string[];
  removedSubdomains: string[];
  newCves: string[];
  resolvedCves: string[];
  newExposures: string[];
  resolvedExposures: string[];
}

export function diffReports(base: ReconReport, compare: ReconReport): ScanDiff {
  const baseHosts = new Set(base.subdomains.map((s) => s.host));
  const compareHosts = new Set(compare.subdomains.map((s) => s.host));

  const baseCves = new Set(base.vulnerabilities.map((v) => `${v.cve}@${v.host}`));
  const compareCves = new Set(compare.vulnerabilities.map((v) => `${v.cve}@${v.host}`));

  const baseExp = new Set(base.securityFindings.map((f) => f.id));
  const compareExp = new Set(compare.securityFindings.map((f) => f.id));

  return {
    baseId: base.id,
    compareId: compare.id,
    domain: compare.domain,
    riskScoreDelta: compare.riskScore - base.riskScore,
    newSubdomains: [...compareHosts].filter((h) => !baseHosts.has(h)).sort(),
    removedSubdomains: [...baseHosts].filter((h) => !compareHosts.has(h)).sort(),
    newCves: [...compareCves].filter((c) => !baseCves.has(c)).sort(),
    resolvedCves: [...baseCves].filter((c) => !compareCves.has(c)).sort(),
    newExposures: [...compareExp].filter((e) => !baseExp.has(e)).sort(),
    resolvedExposures: [...baseExp].filter((e) => !compareExp.has(e)).sort(),
  };
}
