/** Shared types for ReconForge reconnaissance pipeline */

export type ScanDepth = "quick" | "deep";
export type LogLevel = "info" | "warn" | "error" | "success";
export type RiskLevel = "info" | "medium" | "high";

export interface ScanRequest {
  target: string;
  keywords: string[];
  depth: ScanDepth;
  simulation: boolean;
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
}

export interface TechFingerprint {
  host: string;
  server?: string;
  framework?: string;
  cms?: string;
  version?: string;
  headers: string[];
}

export interface Vulnerability {
  cve: string;
  severity: RiskLevel;
  technology: string;
  description: string;
  cvss: number;
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
  subdomains: SubdomainEntry[];
  fingerprints: TechFingerprint[];
  vulnerabilities: Vulnerability[];
  synthesis: SynthesisInsight[];
  mindmap: string;
  markdown: string;
  html: string;
}

export interface PhaseEvent {
  phase: number;
  name: string;
  status: "running" | "complete";
  progress: number;
}
