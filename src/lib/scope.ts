/**
 * Scan scope — include/exclude host patterns.
 */

import type { ScanScope } from "./types";
import { getApexDomain } from "../services/subdomain";

export type { ScanScope };

function patternToRegex(pattern: string): RegExp {
  const escaped = pattern.trim().toLowerCase().replace(/\./g, "\\.").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`, "i");
}

function matchesAny(host: string, patterns: string[]): boolean {
  return patterns.some((p) => patternToRegex(p).test(host));
}

/** True when apex is implied by a wildcard include like *.example.com */
function includeCoversApex(include: string[], apex: string): boolean {
  const a = apex.toLowerCase();
  return include.some((p) => {
    const norm = p.trim().toLowerCase();
    return norm === a || norm === `*.${a}` || norm === "*";
  });
}

function hostMatchesInclude(host: string, include: string[], apex: string): boolean {
  const h = host.toLowerCase();
  if (matchesAny(h, include)) return true;
  if (h === apex.toLowerCase() && includeCoversApex(include, apex)) return true;
  return false;
}

/** Filter hosts to those in scope for the target apex. */
export function filterHostsInScope(hosts: string[], apex: string, scope?: ScanScope): string[] {
  if (!scope?.include?.length && !scope?.exclude?.length) return hosts;

  return hosts.filter((host) => {
    const h = host.toLowerCase();
    if (scope.exclude?.length && matchesAny(h, scope.exclude)) return false;
    if (scope.include?.length) return hostMatchesInclude(h, scope.include, apex);
    return h === apex.toLowerCase() || h.endsWith(`.${apex.toLowerCase()}`);
  });
}

export function isHostInScope(host: string, apex: string, scope?: ScanScope): boolean {
  return filterHostsInScope([host], apex, scope).length > 0;
}

export function validateScopeTarget(target: string, scope?: ScanScope): string | null {
  const apex = getApexDomain(target);
  const t = target.toLowerCase();
  if (scope?.include?.length) {
    const allowed =
      hostMatchesInclude(t, scope.include, apex) ||
      hostMatchesInclude(apex, scope.include, apex);
    if (!allowed) return `Target ${target} not in scope include list`;
  }
  if (scope?.exclude?.length && matchesAny(t, scope.exclude)) {
    return `Target ${target} is excluded by scope rules`;
  }
  return null;
}

export function serializeScope(scope?: ScanScope): { include: string; exclude: string } {
  return {
    include: scope?.include?.join(",") || "",
    exclude: scope?.exclude?.join(",") || "",
  };
}

export function deserializeScope(include: string, exclude: string): ScanScope | undefined {
  const inc = include.split(",").map((s) => s.trim()).filter(Boolean);
  const exc = exclude.split(",").map((s) => s.trim()).filter(Boolean);
  if (!inc.length && !exc.length) return undefined;
  return {
    include: inc.length ? inc : undefined,
    exclude: exc.length ? exc : undefined,
  };
}
