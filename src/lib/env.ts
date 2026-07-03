/** Cloudflare Worker bindings and environment */

export interface ReconEnv {
  ASSETS: Fetcher;
  DB?: D1Database;
  SCAN_CACHE?: KVNamespace;
  RECON_API_KEY?: string;
  SHODAN_API_KEY?: string;
  NVD_API_KEY?: string;
  URLSCAN_API_KEY?: string;
  WEBHOOK_URL?: string;
}
