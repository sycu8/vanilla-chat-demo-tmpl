/**
 * KV-backed rate limiting for scan endpoints.
 */

import type { ReconEnv } from "./env";

const HOURLY_LIMIT = 20;

export async function checkRateLimit(env: ReconEnv, key: string): Promise<{ allowed: boolean; remaining: number }> {
  if (!env.SCAN_CACHE) return { allowed: true, remaining: HOURLY_LIMIT };

  const hour = new Date().toISOString().slice(0, 13);
  const cacheKey = `ratelimit:${key}:${hour}`;

  const current = Number((await env.SCAN_CACHE.get(cacheKey)) || "0");
  if (current >= HOURLY_LIMIT) return { allowed: false, remaining: 0 };

  await env.SCAN_CACHE.put(cacheKey, String(current + 1), { expirationTtl: 7200 });
  return { allowed: true, remaining: HOURLY_LIMIT - current - 1 };
}

export function clientRateKey(request: Request): string {
  return request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "anonymous";
}
