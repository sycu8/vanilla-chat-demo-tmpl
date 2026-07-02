#!/usr/bin/env node
/**
 * Integration test for ReconForge using orangecloud.vn as target.
 * Run: node scripts/test-orangecloud.mjs [baseUrl]
 */

const BASE = process.argv[2] || "http://localhost:8788";
const TARGET = "orangecloud.vn";
/** Known live subdomains for orangecloud.vn (from CT / passive DNS) */
const KNOWN_LIVE_HOSTS = ["ask.orangecloud.vn", "blog.orangecloud.vn", "kb.orangecloud.vn"];
const PAYLOAD = {
  target: TARGET,
  keywords: "orange,cloud,vietnam",
  depth: "quick",
  simulation: true,
};

let passed = 0;
let failed = 0;

function ok(name) {
  passed++;
  console.log(`  ✓ ${name}`);
}

function fail(name, detail) {
  failed++;
  console.error(`  ✗ ${name}: ${detail}`);
}

async function testHealth() {
  const res = await fetch(`${BASE}/api/recon/health`);
  if (!res.ok) return fail("health", `HTTP ${res.status}`);
  const data = await res.json();
  if (data.status !== "operational") return fail("health", `status=${data.status}`);
  ok("GET /api/recon/health");
}

async function testIndex() {
  const res = await fetch(`${BASE}/`);
  if (!res.ok) return fail("index", `HTTP ${res.status}`);
  const html = await res.text();
  if (!html.includes("ReconForge")) return fail("index", "missing ReconForge title");
  ok("GET / (index.html)");
}

async function testReport() {
  const res = await fetch(`${BASE}/api/recon/report`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(PAYLOAD),
  });
  if (!res.ok) return fail("report", `HTTP ${res.status}`);
  const { report } = await res.json();
  if (report.domain !== TARGET) return fail("report", `domain=${report.domain}`);
  if (!report.mindmap?.includes("orangecloud.vn")) return fail("report", "mindmap missing domain");
  if (!report.markdown?.includes("orangecloud.vn")) return fail("report", "markdown missing domain");
  if (!report.html?.includes("orangecloud.vn")) return fail("report", "html missing domain");
  if (report.subdomains.length < 2) return fail("report", "too few live subdomains");
  const hosts = report.subdomains.map((s) => s.host);
  const hasKnown = KNOWN_LIVE_HOSTS.some((h) => hosts.includes(h));
  if (!hasKnown) {
    return fail("report", `expected known live host in [${hosts.join(", ")}]`);
  }
  const fakeOnly = hosts.every((h) => /^(api|admin|jenkins|grafana)\./.test(h));
  if (fakeOnly) return fail("report", "subdomains look simulated, not live");
  for (const sub of report.subdomains) {
    if (!sub.ip || sub.ip === "0.0.0.0") return fail("report", `${sub.host} missing IP`);
  }
  ok(`POST /api/recon/report (${report.subdomains.length} live subdomains, risk ${report.riskScore})`);
  return report;
}

async function testMindmap(report) {
  const res = await fetch(`${BASE}/api/recon/mindmap`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...PAYLOAD, variant: 1 }),
  });
  if (!res.ok) return fail("mindmap", `HTTP ${res.status}`);
  const data = await res.json();
  if (!data.mindmap?.includes("mindmap")) return fail("mindmap", "invalid mermaid");
  if (!data.mindmap.includes('"orangecloud.vn"') && !data.mindmap.includes("orangecloud.vn")) {
    return fail("mindmap", "domain not in mindmap");
  }
  ok("POST /api/recon/mindmap (variant 1)");
}

async function testScan() {
  const res = await fetch(`${BASE}/api/recon/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(PAYLOAD),
  });
  if (!res.ok) return fail("scan", `HTTP ${res.status}`);

  const text = await res.text();
  const phases = (text.match(/^event: phase$/gm) || []).length;
  const logs = (text.match(/^event: log$/gm) || []).length;
  const complete = text.includes("event: complete");
  const hasDomain = text.includes("orangecloud.vn");

  if (phases < 10) return fail("scan", `only ${phases} phase events`);
  if (logs < 10) return fail("scan", `only ${logs} log events`);
  if (!complete) return fail("scan", "missing complete event");
  if (!hasDomain) return fail("scan", "domain not in stream");
  if (text.includes('"markdown"')) return fail("scan", "SSE should not include markdown blob");

  ok(`POST /api/recon/scan (${phases} phases, ${logs} logs, complete event)`);
}

async function main() {
  console.log(`\nReconForge integration test — target: ${TARGET}`);
  console.log(`Base URL: ${BASE}\n`);

  try {
    await testHealth();
    await testIndex();
    const report = await testReport();
    await testMindmap(report);
    await testScan();
  } catch (err) {
    fail("unexpected", err.message);
  }

  console.log(`\n${passed} passed, ${failed} failed\n`);
  process.exit(failed > 0 ? 1 : 0);
}

main();
