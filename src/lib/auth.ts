/**
 * Optional API key authentication.
 */

import type { ReconEnv } from "./env";

export function requireAuth(request: Request, env: ReconEnv): Response | null {
  if (!env.RECON_API_KEY) return null;

  const key = request.headers.get("X-Recon-API-Key") || request.headers.get("Authorization")?.replace(/^Bearer\s+/i, "");
  if (key !== env.RECON_API_KEY) {
    return new Response(JSON.stringify({ error: "Unauthorized — invalid or missing API key" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }
  return null;
}
