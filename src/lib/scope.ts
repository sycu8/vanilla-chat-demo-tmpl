/**
 * Scan scope — include/exclude host patterns.
 */

import { getApexDomain } from "../services/subdomain";

export interface ScanScope {
  include?: string[];
  exclude?: string[];
}

function patternToRegex(pattern: string): RegExp {
  const escaped = pattern.trim().toLowerCase().replace(/\./g, "\\.").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`, "i");
}

function matchesAny(host: string, patterns: string[]): boolean {
  return patterns.some((p) => patternToRegex(p).test(host));
}

/** Filter hosts to those in scope for the target apex. */
export function filterHostsInScope(hosts: string[], apex: string, scope?: ScanScope): string[] {
  if (!scope?.include?.length && !scope?.exclude?.length) return hosts;

  return hosts.filter((host) => {
    const h = host.toLowerCase();
    if (scope.exclude?.length && matchesAny(h, scope.exclude)) return false;
    if (scope.include?.length) return matchesAny(h, scope.include);
    return h === apex || h.endsWith(`.${apex}`);
  });
}

export function validateScopeTarget(target: string, scope?: ScanScope): string | null {
  const apex = getApexDomain(target);
  if (scope?.include?.length) {
    const allowed = scope.include.some(
      (p) => patternToRegex(p).test(apex) || patternToRegex(p).test(target)
    );
    if (!allowed) return `Target ${target} not in scope include list`;
  }
  if (scope?.exclude?.length && matchesAny(target, scope.exclude)) {
    return `Target ${target} is excluded by scope rules`;
  }
  return null;
}
