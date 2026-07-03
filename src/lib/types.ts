/** Shared types for ReconForge reconnaissance pipeline */

export type ScanDepth = "quick" | "deep";
export type LogLevel = "info" | "warn" | "error" | "success";
export type RiskLevel = "info" | "medium" | "high";

export interface ScanScope {
  include?: string[];
  exclude?: string[];
}

export interface ScanRequest {
  target: string;
  keywords: string[];
  depth: ScanDepth;
  simulation: boolean;
  scope?: ScanScope;
}

export interface LogEntry {
  timestamp: string;
  phase: number;
  level: LogLevel;
  message: string;
}

export interface OsintFinding {
  category: string;
  detail: string;
  risk: RiskLevel;
}

export interface SubdomainEntry {
  host: string;
  services: string[];
  ip: string;
  status: number;
  /** Page title from HTTP probe (httpx-style) */
  title?: string;
}

export interface DnsRecord {
  type: string;
  name: string;
  value: string;
  risk: RiskLevel;
}

export interface TechFingerprint {
  host: string;
  server?: string;
  framework?: string;
  cms?: string;
  version?: string;
  headers: string[];
  /** httpx-style metadata */
  title?: string;
  contentLength?: number;
  finalUrl?: string;
  /** Security header score 0–100 (higher = better) */
  securityScore?: number;
  missingHeaders?: string[];
  /** WAF/CDN detected in front of origin */
  waf?: string;
  /** TLS certificate subject (when available) */
  tlsIssuer?: string;
}

export interface SecurityFinding {
  id: string;
  host: string;
  category: "headers" | "exposure" | "dns" | "misconfig";
  severity: RiskLevel;
  title: string;
  description: string;
  remediation: string;
}

export interface Vulnerability {
  cve: string;
  severity: RiskLevel;
  /** Subdomain / host where the vulnerable stack was detected */
  host: string;
  technology: string;
  description: string;
  cvss: number;
  /** Actionable remediation / mitigation steps */
  remediation: string;
}

export interface SynthesisInsight {
  title: string;
  detail: string;
  priority: RiskLevel;
}

export interface ReconReport {
  id: string;
  target: string;
  domain: string;
  keywords: string[];
  depth: ScanDepth;
  simulation: boolean;
  startedAt: string;
  completedAt: string;
  riskScore: number;
  riskLevel: RiskLevel;
  summary: string;
  osint: OsintFinding[];
  dnsRecords: DnsRecord[];
  subdomains: SubdomainEntry[];
  fingerprints: TechFingerprint[];
  vulnerabilities: Vulnerability[];
  securityFindings: SecurityFinding[];
  synthesis: SynthesisInsight[];
  mindmap: string;
  markdown: string;
  html: string;
}

export interface PhaseEvent {
  phase: number;
  name: string;
  status: "pending" | "running" | "complete" | "error";
  progress: number;
  /** Short activity line shown while phase is running (e.g. "Verifying host 3/25") */
  detail?: string;
}
