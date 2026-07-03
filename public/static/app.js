/**
 * ReconForge Frontend Application
 * Handles scan orchestration, SSE streaming, mindmap rendering, and report export.
 */

// ── State ───────────────────────────────────────────────────────────
let currentReport = null;
let lastScanPayload = null;
let mindmapVariant = 0;
let scanRunning = false;
let currentRunningPhase = 0;
let logEventCount = 0;
let scanStartedAt = 0;
let elapsedTimer = null;
let activityTimer = null;
let lastEventAt = 0;

const PHASE_STATUS = {
  pending: { label: "pending", className: "phase-status-pending" },
  running: { label: "running", className: "phase-status-running" },
  complete: { label: "done", className: "phase-status-complete" },
  error: { label: "error", className: "phase-status-error" },
};

const PHASES = [
  { id: 1, name: "OSINT & Social Engineering", icon: "🔍" },
  { id: 2, name: "Subdomain Enumeration", icon: "🌐" },
  { id: 3, name: "Tech Fingerprinting", icon: "⚙️" },
  { id: 4, name: "Vulnerability Intel", icon: "🚨" },
  { id: 5, name: "Intelligence Synthesis", icon: "🧠" },
];

// ── DOM References ──────────────────────────────────────────────────
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const sectionInput = $("#section-input");
const sectionPipeline = $("#section-pipeline");
const sectionMindmap = $("#section-mindmap");
const sectionReport = $("#section-report");
const scanForm = $("#scan-form");
const targetInput = $("#target");
const domainPreview = $("#domain-preview");
const logTerminal = $("#log-terminal");
const phaseIndicators = $("#phase-indicators");
const mindmapContainer = $("#mindmap-container");
const reportContent = $("#report-content");
const riskDashboard = $("#risk-dashboard");
const statusBadge = $("#status-badge");
const btnNewScan = $("#btn-new-scan");
const scanActivityStatus = $("#scan-activity-status");
const scanActivityDot = $("#scan-activity-dot");
const scanElapsed = $("#scan-elapsed");
const logCount = $("#log-count");
const logWaiting = $("#log-waiting");
const progressFill = $("#scan-progress-fill");
const subdomainList = $("#subdomain-list");
const subdomainCount = $("#subdomain-count");
const subdomainEmptyRow = $("#subdomain-empty-row");

let liveSubdomains = [];

// ── Mermaid Init ────────────────────────────────────────────────────
if (typeof mermaid !== "undefined") {
  mermaid.initialize({
    startOnLoad: false,
    theme: "dark",
    themeVariables: {
      primaryColor: "#1a2332",
      primaryTextColor: "#e2e8f0",
      primaryBorderColor: "#00ff88",
      lineColor: "#38bdf8",
      secondaryColor: "#111827",
      tertiaryColor: "#0a0e17",
      fontFamily: "Inter, system-ui, sans-serif",
    },
    mindmap: {
      padding: 20,
      useMaxWidth: true,
    },
    securityLevel: "loose",
  });
}

// ── Utilities ─────────────────────────────────────────────────────
function extractDomain(input) {
  let value = input.trim().toLowerCase();
  if (!value) return "";
  if (!value.startsWith("http")) value = `https://${value}`;
  try {
    let host = new URL(value).hostname;
    if (host.startsWith("www.")) host = host.slice(4);
    return host;
  } catch {
    const m = input.trim().match(/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    return m ? m[1].toLowerCase() : "";
  }
}

function showToast(message, type = "info") {
  const container = $("#toast-container");
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(1rem)";
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

function formatTime(iso) {
  return new Date(iso).toLocaleTimeString("en-US", { hour12: false });
}

function riskBadgeClass(level) {
  return `risk-badge-${level}`;
}

// ── Phase UI ────────────────────────────────────────────────────────
function initPhaseIndicators() {
  phaseIndicators.innerHTML = PHASES.map(
    (p) => `
    <div class="phase-indicator pending" id="phase-${p.id}" data-phase="${p.id}">
      <span class="phase-icon text-lg" aria-hidden="true">${p.icon}</span>
      <div class="flex-1 min-w-0">
        <div class="text-xs text-forge-muted">Phase ${p.id}</div>
        <div class="text-sm font-medium truncate phase-name">${p.name}</div>
        <div class="text-xs text-forge-muted truncate phase-detail hidden"></div>
      </div>
      <span class="phase-status phase-status-pending text-xs">pending</span>
    </div>`
  ).join("");
}

function updatePhase(phaseId, status, detail = "") {
  const el = $(`#phase-${phaseId}`);
  if (!el) return;

  el.classList.remove("pending", "active", "complete", "error");
  const statusEl = el.querySelector(".phase-status");
  const detailEl = el.querySelector(".phase-detail");
  const iconEl = el.querySelector(".phase-icon");
  const meta = PHASE_STATUS[status] || PHASE_STATUS.pending;

  if (status === "pending") {
    el.classList.add("pending");
    statusEl.textContent = "pending";
    statusEl.className = "phase-status phase-status-pending text-xs";
    if (iconEl) iconEl.innerHTML = PHASES[phaseId - 1]?.icon || "○";
    if (detailEl) detailEl.classList.add("hidden");
  } else if (status === "running") {
    el.classList.add("active");
    currentRunningPhase = phaseId;
    statusEl.innerHTML = `<span class="inline-flex items-center gap-1.5">${meta.label}<span class="phase-spinner"></span></span>`;
    statusEl.className = "phase-status phase-status-running text-xs";
    if (iconEl) iconEl.innerHTML = '<span class="phase-spinner"></span>';
    if (detailEl) {
      detailEl.textContent = detail;
      detailEl.classList.toggle("hidden", !detail);
    }
  } else if (status === "complete") {
    el.classList.add("complete");
    statusEl.textContent = "✓ done";
    statusEl.className = "phase-status phase-status-complete text-xs";
    if (iconEl) iconEl.textContent = "✓";
    if (detailEl) detailEl.classList.add("hidden");
  } else if (status === "error") {
    el.classList.add("error");
    statusEl.textContent = "✗ error";
    statusEl.className = "phase-status phase-status-error text-xs";
    if (iconEl) iconEl.textContent = "✗";
    if (detailEl) {
      detailEl.textContent = detail || "Phase failed";
      detailEl.classList.remove("hidden");
    }
  }
}

function setAllPhasesPending() {
  PHASES.forEach((p) => updatePhase(p.id, "pending"));
}

function setScanActivity(message, active = true) {
  if (scanActivityStatus) scanActivityStatus.textContent = message;
  scanActivityDot?.classList.toggle("hidden", !active);
  logWaiting?.classList.toggle("hidden", !active);
  progressFill?.classList.toggle("indeterminate", active && scanRunning);
}

function touchActivity() {
  lastEventAt = Date.now();
}

function startScanTimers() {
  scanStartedAt = Date.now();
  scanElapsed?.classList.remove("hidden");
  if (elapsedTimer) clearInterval(elapsedTimer);
  elapsedTimer = setInterval(() => {
    if (!scanRunning) return;
    const sec = Math.floor((Date.now() - scanStartedAt) / 1000);
    const m = Math.floor(sec / 60);
    const s = String(sec % 60).padStart(2, "0");
    if (scanElapsed) scanElapsed.textContent = `${m}:${s}`;
  }, 1000);

  if (activityTimer) clearInterval(activityTimer);
  activityTimer = setInterval(() => {
    if (!scanRunning) return;
    const idleMs = Date.now() - lastEventAt;
    if (idleMs > 5000 && currentRunningPhase > 0) {
      const phase = PHASES[currentRunningPhase - 1];
      setScanActivity(`Still working on Phase ${currentRunningPhase}: ${phase?.name || "pipeline"}... (${Math.floor(idleMs / 1000)}s)`);
    }
  }, 1000);
}

function stopScanTimers() {
  if (elapsedTimer) clearInterval(elapsedTimer);
  if (activityTimer) clearInterval(activityTimer);
  elapsedTimer = null;
  activityTimer = null;
}

function appendLog(entry) {
  const div = document.createElement("div");
  div.className = `log-entry log-${entry.level}`;
  const time = formatTime(entry.timestamp);
  div.innerHTML = `<span class="text-forge-muted">[${time}]</span> <span class="text-forge-muted">P${entry.phase}</span> ${escapeHtml(entry.message)}`;
  if (logWaiting && logTerminal.contains(logWaiting)) {
    logTerminal.insertBefore(div, logWaiting);
  } else {
    logTerminal.appendChild(div);
  }
  logEventCount++;
  if (logCount) logCount.textContent = `${logEventCount} event${logEventCount === 1 ? "" : "s"}`;
  logTerminal.scrollTop = logTerminal.scrollHeight;
  touchActivity();
}

function escapeHtml(str) {
  const d = document.createElement("div");
  d.textContent = str;
  return d.innerHTML;
}

function resetSubdomainList() {
  liveSubdomains = [];
  if (subdomainCount) subdomainCount.textContent = "0 hosts";
  if (subdomainList) {
    subdomainList.innerHTML = `
      <tr id="subdomain-empty-row">
        <td colspan="5" class="p-4 text-center text-forge-muted">Subdomains will appear during Phase 2...</td>
      </tr>`;
  }
}

function statusClass(code) {
  if (!code || code === 0) return "text-forge-muted";
  if (code >= 200 && code < 400) return "text-forge-safe";
  if (code >= 400 && code < 500) return "text-forge-warn";
  return "text-forge-danger";
}

function buildVulnMap(vulnerabilities) {
  const map = new Map();
  for (const vuln of vulnerabilities || []) {
    const list = map.get(vuln.host) || [];
    list.push(vuln);
    map.set(vuln.host, list);
  }
  return map;
}

function formatHostCves(host, vulnMap) {
  const vulns = vulnMap?.get(host) || [];
  if (!vulns.length) return `<span class="text-forge-muted">—</span>`;
  return vulns
    .slice(0, 3)
    .map((v) => {
      const color =
        v.severity === "high" ? "text-forge-danger" :
        v.severity === "medium" ? "text-forge-warn" : "text-forge-muted";
      return `<span class="${color}" title="${escapeHtml(v.description)}">${escapeHtml(v.cve)}</span>`;
    })
    .join(", ");
}

function redrawSubdomainTable(vulnMap = buildVulnMap(currentReport?.vulnerabilities)) {
  if (!subdomainList) return;
  subdomainList.innerHTML = liveSubdomains
    .map(
      (s) => `
    <tr class="border-t border-forge-border/50 hover:bg-forge-surface/50">
      <td class="p-2 text-forge-accent2">${escapeHtml(s.host)}</td>
      <td class="p-2 text-forge-muted">${escapeHtml(s.ip)}</td>
      <td class="p-2 ${statusClass(s.status)}">${s.status || "DNS"}</td>
      <td class="p-2 text-forge-muted">${escapeHtml((s.services || []).join(", "))}</td>
      <td class="p-2 text-xs">${formatHostCves(s.host, vulnMap)}</td>
    </tr>`
    )
    .join("");
}

function appendSubdomainRow(entry) {
  if (!subdomainList) return;
  const empty = subdomainList.querySelector("#subdomain-empty-row");
  if (empty) empty.remove();

  const exists = liveSubdomains.some((s) => s.host === entry.host);
  if (exists) return;

  liveSubdomains.push(entry);
  liveSubdomains.sort((a, b) => a.host.localeCompare(b.host));
  redrawSubdomainTable();

  if (subdomainCount) {
    subdomainCount.textContent = `${liveSubdomains.length} host${liveSubdomains.length === 1 ? "" : "s"}`;
  }
}

function renderSubdomainTable(subdomains, vulnerabilities) {
  if (!subdomains?.length) {
    resetSubdomainList();
    if (subdomainList) {
      subdomainList.innerHTML = `
        <tr><td colspan="5" class="p-4 text-center text-forge-warn">No live subdomains found — try Deep Scan or check target DNS.</td></tr>`;
    }
    return;
  }
  liveSubdomains = [...subdomains].sort((a, b) => a.host.localeCompare(b.host));
  redrawSubdomainTable(buildVulnMap(vulnerabilities));
  if (subdomainCount) {
    subdomainCount.textContent = `${liveSubdomains.length} host${liveSubdomains.length === 1 ? "" : "s"}`;
  }
}

function setProgress(pct) {
  progressFill.style.width = `${pct}%`;
  progressFill.classList.remove("indeterminate");
  $("#scan-progress-text").textContent = `${pct}%`;
}

// ── Domain Auto-detect ──────────────────────────────────────────────
targetInput.addEventListener("input", () => {
  const domain = extractDomain(targetInput.value);
  if (domain) {
    domainPreview.classList.remove("hidden");
    domainPreview.querySelector("span").textContent = domain;
  } else {
    domainPreview.classList.add("hidden");
  }
});

// ── Simulation Badge ──────────────────────────────────────────────
$("#simulation").addEventListener("change", (e) => {
  if (e.target.checked) {
    statusBadge.textContent = "● SIMULATION MODE";
    statusBadge.className = "text-xs font-mono px-3 py-1 rounded-full bg-forge-safe/10 text-forge-safe border border-forge-safe/30";
  } else {
    statusBadge.textContent = "● LIVE MODE";
    statusBadge.className = "text-xs font-mono px-3 py-1 rounded-full bg-forge-danger/10 text-forge-danger border border-forge-danger/30";
    showToast("Live mode selected — ensure you have authorization", "warn");
  }
});

// ── Scan Launch ─────────────────────────────────────────────────────
scanForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  await launchScan();
});

async function launchScan() {
  const target = targetInput.value.trim();
  const keywords = $("#keywords").value.trim();
  const depth = document.querySelector('input[name="depth"]:checked')?.value || "quick";
  const simulation = $("#simulation").checked;

  if (!extractDomain(target)) {
    showToast("Please enter a valid URL or domain", "error");
    return;
  }

  // Reset UI
  currentReport = null;
  mindmapVariant = 0;
  logEventCount = 0;
  currentRunningPhase = 0;
  logTerminal.innerHTML = "";
  if (logWaiting) logTerminal.appendChild(logWaiting);
  if (logCount) logCount.textContent = "0 events";
  initPhaseIndicators();
  setAllPhasesPending();
  resetSubdomainList();
  setProgress(0);
  setScanActivity("Connecting to recon pipeline...", true);
  scanRunning = true;
  startScanTimers();
  touchActivity();

  sectionInput.classList.add("hidden");
  sectionPipeline.classList.remove("hidden");
  sectionMindmap.classList.add("hidden");
  sectionReport.classList.add("hidden");
  btnNewScan.classList.remove("hidden");

  $("#scan-target-label").textContent = extractDomain(target);
  $("#btn-launch").disabled = true;

  const payload = { target, keywords, depth, simulation };
  lastScanPayload = payload;

  try {
    await streamScan(payload);
  } catch (err) {
    showToast(err.message || "Scan failed", "error");
    if (currentRunningPhase > 0) {
      updatePhase(currentRunningPhase, "error", err.message);
    }
    setScanActivity(`Scan failed: ${err.message || "Unknown error"}`, false);
    appendLog({
      timestamp: new Date().toISOString(),
      phase: currentRunningPhase || 0,
      level: "error",
      message: `FATAL: ${err.message}`,
    });
  } finally {
    scanRunning = false;
    stopScanTimers();
    logWaiting?.classList.add("hidden");
    progressFill?.classList.remove("indeterminate");
    $("#btn-launch").disabled = false;
  }
}

/** Parse a single SSE event block */
function parseSSEEvent(raw) {
  let eventType = "message";
  const dataLines = [];

  for (const line of raw.split("\n")) {
    if (line.startsWith("event:")) {
      eventType = line.slice(6).trim();
    } else if (line.startsWith("data:")) {
      dataLines.push(line.slice(5).trimStart());
    }
  }

  if (!dataLines.length) return;

  try {
    const data = JSON.parse(dataLines.join("\n"));
    handleScanEvent(eventType, data);
  } catch (err) {
    console.warn("[ReconForge] SSE parse error:", err.message);
  }
}

/** Stream recon scan via SSE */
async function streamScan(payload) {
  setScanActivity("Starting scan stream...", true);
  const response = await fetch("/api/recon/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.error || `HTTP ${response.status}`);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  touchActivity();
  setScanActivity("Pipeline connected — receiving live events...", true);

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });

    let boundary;
    while ((boundary = buffer.indexOf("\n\n")) !== -1) {
      const rawEvent = buffer.slice(0, boundary);
      buffer = buffer.slice(boundary + 2);
      if (rawEvent.trim()) parseSSEEvent(rawEvent);
    }
  }

  if (buffer.trim()) parseSSEEvent(buffer);
}

function handleScanEvent(type, data) {
  touchActivity();
  switch (type) {
    case "phase":
      if (data.status === "running") {
        updatePhase(data.phase, "running", data.detail || "");
        if (typeof data.progress === "number") {
          progressFill.style.width = `${data.progress}%`;
          $("#scan-progress-text").textContent = `${data.progress}%`;
        }
        const phase = PHASES[data.phase - 1];
        setScanActivity(data.detail || `Phase ${data.phase}: ${phase?.name || "Running"}...`, true);
      } else if (data.status === "complete") {
        updatePhase(data.phase, "complete");
        setProgress(data.progress);
        setScanActivity(`Phase ${data.phase} complete`, true);
      } else if (data.status === "error") {
        updatePhase(data.phase, "error", data.detail);
        setScanActivity(data.detail || `Phase ${data.phase} failed`, false);
      } else if (data.status === "pending") {
        updatePhase(data.phase, "pending");
      }
      break;
    case "log":
      appendLog(data);
      break;
    case "subdomain":
      appendSubdomainRow(data);
      break;
    case "complete":
      onScanComplete(data);
      break;
    case "error":
      if (currentRunningPhase > 0) updatePhase(currentRunningPhase, "error", data.message);
      setScanActivity(data.message || "Scan error", false);
      showToast(data.message, "error");
      break;
  }
}

async function onScanComplete(slimReport) {
  scanRunning = false;
  stopScanTimers();
  setScanActivity("Scan complete — generating report...", false);
  showToast("Reconnaissance complete!", "success");
  setProgress(100);

  // Fetch full report (markdown + html) — SSE omits large fields for reliability
  try {
    const res = await fetch("/api/recon/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(lastScanPayload),
    });
    if (res.ok) {
      const { report } = await res.json();
      currentReport = report;
    } else {
      currentReport = slimReport;
      showToast("Full report fetch failed — exports may be limited", "warn");
    }
  } catch {
    currentReport = slimReport;
    showToast("Full report fetch failed — exports may be limited", "warn");
  }

  sectionMindmap.classList.remove("hidden");
  renderSubdomainTable(currentReport.subdomains || liveSubdomains, currentReport.vulnerabilities);
  await renderMindmap(currentReport.mindmap);

  sectionReport.classList.remove("hidden");
  renderDashboard(currentReport);
  renderReport(currentReport);

  setScanActivity(`Complete — ${currentReport.subdomains?.length || 0} live hosts, risk ${currentReport.riskScore}/100`, false);
  sectionMindmap.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ── Mindmap ─────────────────────────────────────────────────────────
async function renderMindmap(source) {
  if (!source) {
    mindmapContainer.innerHTML = '<p class="text-forge-muted">No mindmap data available.</p>';
    return;
  }
  if (typeof mermaid === "undefined") {
    mindmapContainer.innerHTML = '<p class="text-forge-danger">Mermaid.js failed to load. Check your network connection.</p>';
    return;
  }

  mindmapContainer.innerHTML = '<div class="text-forge-muted animate-pulse">Rendering mindmap...</div>';
  try {
    const id = `mindmap-${Date.now()}`;
    await mermaid.parse(source);
    const { svg } = await mermaid.render(id, source);
    mindmapContainer.innerHTML = svg;

    // Make nodes feel interactive
    mindmapContainer.querySelectorAll(".node").forEach((node) => {
      node.style.cursor = "pointer";
      node.addEventListener("click", () => {
        node.style.filter = "brightness(1.3)";
        setTimeout(() => (node.style.filter = ""), 400);
      });
    });
  } catch (err) {
    mindmapContainer.innerHTML = `<p class="text-forge-danger">Mindmap render error: ${escapeHtml(err.message)}</p>`;
    console.error("Mermaid error:", err);
  }
}

$("#btn-regenerate").addEventListener("click", async () => {
  if (!currentReport) return;
  mindmapVariant = (mindmapVariant + 1) % 2;
  showToast("Regenerating mindmap layout...", "info");

  try {
    const res = await fetch("/api/recon/mindmap", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target: currentReport.target,
        keywords: currentReport.keywords.join(", "),
        depth: currentReport.depth,
        simulation: currentReport.simulation,
        variant: mindmapVariant,
      }),
    });
    const data = await res.json();
    if (data.mindmap) {
      currentReport.mindmap = data.mindmap;
      await renderMindmap(data.mindmap);
      showToast("Mindmap regenerated", "success");
    }
  } catch {
    showToast("Failed to regenerate mindmap", "error");
  }
});

$("#btn-export-png").addEventListener("click", async () => {
  const svg = mindmapContainer.querySelector("svg");
  if (!svg) {
    showToast("No mindmap to export", "error");
    return;
  }

  try {
    let svgData = new XMLSerializer().serializeToString(svg);
    if (!svgData.includes("xmlns=")) {
      svgData = svgData.replace("<svg", '<svg xmlns="http://www.w3.org/2000/svg"');
    }
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");
    const img = new Image();
    const blob = new Blob([svgData], { type: "image/svg+xml;charset=utf-8" });
    const url = URL.createObjectURL(blob);

    img.onload = () => {
      const w = img.naturalWidth || img.width || 1200;
      const h = img.naturalHeight || img.height || 800;
      canvas.width = w * 2;
      canvas.height = h * 2;
      ctx.fillStyle = "#0a0e17";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      URL.revokeObjectURL(url);

      const a = document.createElement("a");
      a.download = `reconforge-mindmap-${currentReport?.domain || "export"}.png`;
      a.href = canvas.toDataURL("image/png");
      a.click();
      showToast("Mindmap exported as PNG", "success");
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      showToast("PNG export failed — try screenshot instead", "error");
    };
    img.src = url;
  } catch (err) {
    showToast("PNG export failed: " + err.message, "error");
  }
});

// ── Report Dashboard ────────────────────────────────────────────────
function renderDashboard(report) {
  const highVulns = report.vulnerabilities.filter((v) => v.severity === "high").length;
  const medVulns = report.vulnerabilities.filter((v) => v.severity === "medium").length;
  const scoreColor =
    report.riskLevel === "high" ? "text-forge-danger" :
    report.riskLevel === "medium" ? "text-forge-warn" : "text-forge-safe";

  riskDashboard.innerHTML = `
    <div class="forge-card text-center">
      <div class="text-xs text-forge-muted uppercase tracking-wider mb-1">Risk Score</div>
      <div class="text-4xl font-extrabold ${scoreColor}">${report.riskScore}</div>
      <div class="text-xs text-forge-muted mt-1">/ 100</div>
    </div>
    <div class="forge-card text-center">
      <div class="text-xs text-forge-muted uppercase tracking-wider mb-1">Subdomains</div>
      <div class="text-4xl font-extrabold text-forge-accent2">${report.subdomains.length}</div>
      <div class="text-xs text-forge-muted mt-1">hosts discovered</div>
    </div>
    <div class="forge-card text-center">
      <div class="text-xs text-forge-muted uppercase tracking-wider mb-1">Critical CVEs</div>
      <div class="text-4xl font-extrabold text-forge-danger">${highVulns}</div>
      <div class="text-xs text-forge-muted mt-1">${medVulns} medium</div>
    </div>
    <div class="forge-card text-center">
      <div class="text-xs text-forge-muted uppercase tracking-wider mb-1">OSINT Findings</div>
      <div class="text-4xl font-extrabold text-forge-accent">${report.osint.length}</div>
      <div class="text-xs text-forge-muted mt-1">intel items</div>
    </div>`;
}

function renderReport(report) {
  if (typeof marked !== "undefined" && report.markdown) {
    reportContent.innerHTML = marked.parse(report.markdown);
  } else {
    reportContent.innerHTML = `<pre class="text-sm text-forge-muted whitespace-pre-wrap">${escapeHtml(report.markdown || report.summary)}</pre>`;
  }
}

// ── Downloads ───────────────────────────────────────────────────────
function downloadFile(content, filename, mime) {
  const blob = new Blob([content], { type: mime });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

$("#btn-download-md").addEventListener("click", () => {
  if (!currentReport?.markdown) return showToast("No report available", "error");
  downloadFile(currentReport.markdown, `reconforge-${currentReport.domain}.md`, "text/markdown");
  showToast("Markdown report downloaded", "success");
});

$("#btn-download-html").addEventListener("click", () => {
  if (!currentReport?.html) return showToast("No report available", "error");
  downloadFile(currentReport.html, `reconforge-${currentReport.domain}.html`, "text/html");
  showToast("HTML report downloaded", "success");
});

$("#btn-download-pdf").addEventListener("click", () => {
  if (!currentReport) return showToast("No report available", "error");

  try {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });

    // Header
    doc.setFillColor(10, 14, 23);
    doc.rect(0, 0, 210, 40, "F");
    doc.setTextColor(0, 255, 136);
    doc.setFontSize(22);
    doc.text("ReconForge Security Report", 14, 20);
    doc.setTextColor(148, 163, 184);
    doc.setFontSize(10);
    doc.text(`Target: ${currentReport.domain} | ${currentReport.completedAt}`, 14, 30);

    // Risk score
    doc.setTextColor(226, 232, 240);
    doc.setFontSize(14);
    doc.text(`Risk Score: ${currentReport.riskScore}/100 (${currentReport.riskLevel.toUpperCase()})`, 14, 50);

    // Summary
    doc.setFontSize(10);
    doc.setTextColor(100, 116, 139);
    const summaryLines = doc.splitTextToSize(currentReport.summary, 180);
    doc.text(summaryLines, 14, 60);

    let y = 60 + summaryLines.length * 5 + 10;

    // Vulnerabilities table
    doc.setTextColor(56, 189, 248);
    doc.setFontSize(12);
    doc.text("Top Vulnerabilities", 14, y);
    y += 8;

    doc.setFontSize(8);
    doc.setTextColor(226, 232, 240);
    for (const v of currentReport.vulnerabilities.slice(0, 15)) {
      if (y > 260) {
        doc.addPage();
        y = 20;
      }
      const line = `${v.cve} [${v.severity.toUpperCase()}] CVSS ${v.cvss} — ${v.host} (${v.technology})`;
      const wrapped = doc.splitTextToSize(line, 180);
      doc.text(wrapped, 14, y);
      y += wrapped.length * 4 + 2;
      if (v.remediation) {
        doc.setTextColor(34, 197, 94);
        const fix = doc.splitTextToSize(`Remediation: ${v.remediation}`, 176);
        doc.text(fix, 16, y);
        y += fix.length * 4 + 3;
        doc.setTextColor(226, 232, 240);
      }
    }

    // Footer
    const pageCount = doc.internal.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      doc.setFontSize(8);
      doc.setTextColor(100, 116, 139);
      doc.text(`ReconForge — Page ${i}/${pageCount} — Authorized testing only`, 14, 290);
    }

    doc.save(`reconforge-${currentReport.domain}.pdf`);
    showToast("PDF report downloaded", "success");
  } catch (err) {
    showToast("PDF export failed — try browser print instead", "error");
    console.error(err);
  }
});

// ── New Scan ────────────────────────────────────────────────────────
btnNewScan.addEventListener("click", () => {
  sectionInput.classList.remove("hidden");
  sectionPipeline.classList.add("hidden");
  sectionMindmap.classList.add("hidden");
  sectionReport.classList.add("hidden");
  btnNewScan.classList.add("hidden");
  currentReport = null;
  window.scrollTo({ top: 0, behavior: "smooth" });
});

// ── Init ────────────────────────────────────────────────────────────
initPhaseIndicators();

// Health check on load
fetch("/api/recon/health")
  .then((r) => r.json())
  .then((data) => console.log("[ReconForge] API status:", data.status))
  .catch(() => console.warn("[ReconForge] API health check failed — will retry on scan"));
