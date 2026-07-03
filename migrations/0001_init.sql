CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  domain TEXT NOT NULL,
  target TEXT NOT NULL,
  depth TEXT NOT NULL,
  simulation INTEGER NOT NULL DEFAULT 1,
  risk_score INTEGER NOT NULL,
  risk_level TEXT NOT NULL,
  subdomain_count INTEGER NOT NULL,
  vuln_count INTEGER NOT NULL,
  exposure_count INTEGER NOT NULL,
  report_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);

CREATE TABLE IF NOT EXISTS scheduled_targets (
  id TEXT PRIMARY KEY,
  target TEXT NOT NULL,
  domain TEXT NOT NULL,
  depth TEXT NOT NULL DEFAULT 'quick',
  simulation INTEGER NOT NULL DEFAULT 1,
  keywords TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  last_run_at TEXT,
  created_at TEXT NOT NULL
);
