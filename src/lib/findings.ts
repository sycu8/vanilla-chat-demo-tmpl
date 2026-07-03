/**
 * Security finding merge and deduplication.
 */

import type { SecurityFinding } from "./types";

/** Stable key for deduping overlapping probes (exposure vs templates). */
export function findingDedupeKey(f: SecurityFinding): string {
  const title = f.title.toLowerCase().replace(/\s+/g, " ").trim();
  return `${f.host.toLowerCase()}:${f.category}:${title}`;
}

export function mergeSecurityFindings(...groups: SecurityFinding[][]): SecurityFinding[] {
  const merged = new Map<string, SecurityFinding>();
  for (const group of groups) {
    for (const f of group) {
      const key = findingDedupeKey(f);
      if (!merged.has(key)) merged.set(key, f);
    }
  }
  return [...merged.values()];
}
