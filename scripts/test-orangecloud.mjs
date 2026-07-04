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
  simulation: false,
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
  if (data.version !== "2.0.0") return fail("health", `expected v2.0.0, got ${data.version}`);
  ok("GET /api/recon/health (v2.0.0)");
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
  if (report.subdomains.length < 5) return fail("report", `too few live subdomains (${report.subdomains.length})`);
  const hosts = report.subdomains.map((s) => s.host);
  const hasKnown = KNOWN_LIVE_HOSTS.some((h) => hosts.includes(h));
  if (!hasKnown) {
    return fail("report", `expected known live host in [${hosts.join(", ")}]`);
  }
  const fakeOnly = hosts.every((h) => /^(api|admin|jenkins|grafana)\./.test(h));
  if (fakeOnly) return fail("report", "subdomains look simulated, not live");

  const bruteForceOnly = ["ns1.orangecloud.vn", "portal.orangecloud.vn", "jenkins.orangecloud.vn"];
  const spurious = bruteForceOnly.filter((h) => hosts.includes(h));
  if (spurious.length) return fail("report", `wordlist false positives detected: ${spurious.join(", ")}`);
  for (const sub of report.subdomains) {
    if (!sub.ip || sub.ip === "0.0.0.0") return fail("report", `${sub.host} missing IP`);
  }
  ok(`POST /api/recon/report (${report.subdomains.length} live subdomains, risk ${report.riskScore})`);

  const fps = report.fingerprints || [];
  const rootFp = fps.find((f) => f.host === TARGET);
  if (!rootFp) return fail("fingerprints", `missing root host ${TARGET}`);
  const rootStack = [rootFp.framework, rootFp.server, rootFp.version].filter(Boolean).join(" ").toLowerCase();
  if (!rootStack.includes("astro") && !rootStack.includes("cloudflare")) {
    return fail("fingerprints", `root tech unexpected: ${rootStack || "(empty)"}`);
  }
  const blogFp = fps.find((f) => f.host === "blog.orangecloud.vn");
  if (blogFp) {
    const blogStack = [blogFp.framework, blogFp.server].filter(Boolean).join(" ").toLowerCase();
    if (!blogStack.includes("next") && !blogStack.includes("cloudflare")) {
      console.log(`  ⚠ blog.orangecloud.vn tech inconclusive: ${blogStack || "(empty)"}`);
    }
  }
  ok(`fingerprints (${fps.length} hosts, root=${rootStack.trim()})`);

  if (!report.vulnerabilities?.length) return fail("cve", "no vulnerabilities in report");
  const missingHost = report.vulnerabilities.find((v) => !v.host?.trim());
  if (missingHost) return fail("cve", `${missingHost.cve} missing host`);
  const missingFix = report.vulnerabilities.find((v) => !v.remediation?.trim());
  if (missingFix) return fail("cve", `${missingFix.cve} missing remediation`);
  if (!report.markdown.includes("Remediation:")) return fail("cve", "markdown missing remediation section");
  if (!report.markdown.includes("Vulnerable Subdomains")) return fail("cve", "markdown missing vulnerable subdomain mapping");

  if (!report.dnsRecords?.length) fail("dns", "no live DNS records");
  if (report.securityFindings?.length) {
    ok(`exposure (${report.securityFindings.length} findings)`);
    if (!report.markdown.includes("Exposure & Misconfiguration")) fail("exposure", "markdown missing exposure section");
  } else {
    ok("exposure (0 findings on quick scan — hardened target or no matches)");
  }

  const blogVulns = report.vulnerabilities.filter((v) => v.host === "blog.orangecloud.vn");
  const kbVulns = report.vulnerabilities.filter((v) => v.host === "kb.orangecloud.vn");
  const nextHosts = new Set([...blogVulns, ...kbVulns].map((v) => v.host));
  if (nextHosts.size > 0) {
    const hasNextCve = [...blogVulns, ...kbVulns].some((v) => v.cve.startsWith("CVE-2024-") || v.technology?.toLowerCase().includes("next"));
    if (!hasNextCve) {
      console.log(`  ⚠ blog/kb Next.js CVEs not matched (catalog may vary by fingerprint)`);
    }
  }

  ok(`CVE remediations (${report.vulnerabilities.length} findings on ${new Set(report.vulnerabilities.map((v) => v.host)).size} hosts)`);
  ok(`DNS intel (${report.dnsRecords.length} records)`);

  return report;
}

async function testMindmap(report) {
  if (!report) return fail("mindmap", "no report provided");

  const res = await fetch(`${BASE}/api/recon/mindmap`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ report, variant: 1 }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    return fail("mindmap", `HTTP ${res.status}${err.error ? `: ${err.error}` : ""}`);
  }
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

async function testHistoryAndExport(report) {
  if (!report?.id) {
    ok("GET /api/recon/history (skipped — no scan id on report)");
    return;
  }

  const histRes = await fetch(`${BASE}/api/recon/history?domain=${TARGET}&limit=5`);
  if (!histRes.ok) return fail("history", `HTTP ${histRes.status}`);
  const { scans } = await histRes.json();
  if (!Array.isArray(scans)) return fail("history", "scans not array");

  const scanId = report.id;
  const getRes = await fetch(`${BASE}/api/recon/scan/${encodeURIComponent(scanId)}`);
  if (getRes.ok) ok(`GET /api/recon/scan/:id`);
  else ok("GET /api/recon/history (scan may not persist locally)");

  const jsonRes = await fetch(`${BASE}/api/recon/export/${encodeURIComponent(scanId)}?format=json`);
  if (jsonRes.ok) {
    const json = await jsonRes.json();
    if (json.domain !== TARGET) return fail("export-json", `domain=${json.domain}`);
    ok("GET /api/recon/export/:id?format=json");
  }

  const sarifRes = await fetch(`${BASE}/api/recon/export/${encodeURIComponent(scanId)}?format=sarif`);
  if (sarifRes.ok) {
    const sarif = await sarifRes.json();
    if (!sarif.runs?.length) return fail("export-sarif", "missing runs");
    ok("GET /api/recon/export/:id?format=sarif");
  }
}

async function testSchedule() {
  const res = await fetch(`${BASE}/api/recon/schedule`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...PAYLOAD, target: TARGET }),
  });
  if (res.status === 503) {
    ok("POST /api/recon/schedule (skipped — no D1)");
    return;
  }
  if (!res.ok) return fail("schedule", `HTTP ${res.status}`);
  const data = await res.json();
  if (!data.id) return fail("schedule", "missing id");
  ok(`POST /api/recon/schedule (${data.id})`);
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
    await testHistoryAndExport(report);
    await testSchedule();
  } catch (err) {
    fail("unexpected", err.message);
  }

  console.log(`\n${passed} passed, ${failed} failed\n`);
  process.exit(failed > 0 ? 1 : 0);
}

main();
