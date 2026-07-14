/* ────────────────────────────────────────────────────────────
   main.js — SSE-based scan orchestration with live log stream
   ──────────────────────────────────────────────────────────── */

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
const ATTACK_LABEL = {
  sqli: "SQL Injection",
  xss: "Cross-Site Scripting (XSS)",
  prompt: "Prompt Injection",
  data_leakage: "Data Leakage"
};

let lastScanData = null;
let activeSource = null;

// ── DOM refs ──────────────────────────────────────────────────────────────────
const form        = document.getElementById("scan-form");
const urlInput    = document.getElementById("target-url");
const btnScan     = document.getElementById("btn-scan");
const btnNewScan  = document.getElementById("btn-new-scan");
const btnReport   = document.getElementById("btn-report");
const modelStatus = document.getElementById("model-status");
const scanningUrl = document.getElementById("scanning-url");
const consoleEl   = document.getElementById("console");
const vulnList    = document.getElementById("vuln-list");
const noVuln      = document.getElementById("no-vuln");
const scanMeta    = document.getElementById("scan-meta");

const secHero     = document.getElementById("section-hero");
const secProgress = document.getElementById("section-progress");
const secResults  = document.getElementById("section-results");

const sumTotal  = document.getElementById("sum-total");
const sumSqli   = document.getElementById("sum-sqli");
const sumXss    = document.getElementById("sum-xss");
const sumPrompt = document.getElementById("sum-prompt");
const sumData   = document.getElementById("sum-data");

const steps = {
  crawl:  document.getElementById("step-crawl"),
  inject: document.getElementById("step-inject"),
  ml:     document.getElementById("step-ml"),
  llm:    document.getElementById("step-llm"),
};

// ── Model status ──────────────────────────────────────────────────────────────
async function checkModelStatus() {
  try {
    const res = await fetch("/api/metrics");
    if (res.ok) {
      const d = await res.json();
      modelStatus.textContent = `Model Ready (${(d.accuracy * 100).toFixed(1)}% acc)`;
      modelStatus.className = "badge badge-green";
    }
  } catch {
    modelStatus.textContent = "Model Training...";
    modelStatus.className = "badge badge-blue";
  }
}
checkModelStatus();

// ── Console logger ────────────────────────────────────────────────────────────
function logLine(message, level = "info") {
  const el = document.createElement("div");
  el.className = `clog ${level}`;
  const t = new Date().toLocaleTimeString("en-US", { hour12: false });
  const icon = { info: "›", warning: "⚠", error: "✕", success: "✓" }[level] || "›";
  el.textContent = `[${t}] ${icon} ${message}`;
  consoleEl.appendChild(el);
  consoleEl.scrollTop = consoleEl.scrollHeight;
}
function clearConsole() { consoleEl.innerHTML = ""; }

// ── Pipeline steps ────────────────────────────────────────────────────────────
function setStep(name, state) {
  const el = steps[name]; if (!el) return;
  el.classList.remove("active", "done");
  if (state) el.classList.add(state);
}
function resetSteps() { Object.keys(steps).forEach(k => steps[k].classList.remove("active", "done")); }

// Infer which step to activate from log message content
function inferStep(msg) {
  const m = msg.toLowerCase();
  if (m.includes("step 1") || m.includes("crawl"))   { setStep("crawl", "active"); }
  if (m.includes("step 2") || m.includes("inject"))  { setStep("crawl", "done"); setStep("inject", "active"); }
  if (m.includes("step 3") || m.includes("classif")) { setStep("inject", "done"); setStep("ml", "active"); }
  if (m.includes("step 4") || m.includes("samba") || m.includes("ai explan")) { setStep("ml", "done"); setStep("llm", "active"); }
  if (m.includes("scan complete")) { ["crawl","inject","ml","llm"].forEach(s => setStep(s, "done")); }
}

// ── View helpers ──────────────────────────────────────────────────────────────
function showSection(name) {
  secHero.style.display     = name === "hero"     ? "" : "none";
  secProgress.style.display = name === "progress" ? "" : "none";
  secResults.style.display  = name === "results"  ? "" : "none";
}

// ── Scan using SSE (EventSource) ──────────────────────────────────────────────
form.addEventListener("submit", (e) => {
  e.preventDefault();
  const url = urlInput.value.trim();
  if (!url) return;

  // Cancel any existing stream
  if (activeSource) { activeSource.close(); activeSource = null; }

  lastScanData = null;
  clearConsole();
  resetSteps();
  vulnList.innerHTML = "";
  noVuln.style.display = "none";

  scanningUrl.textContent = url;
  btnScan.disabled = true;
  showSection("progress");

  setStep("crawl", "active");
  logLine(`Connecting to scanner...`);

  const source = new EventSource(`/api/scan-stream?url=${encodeURIComponent(url)}`);
  activeSource = source;

  source.onmessage = (e) => {
    let evt;
    try { evt = JSON.parse(e.data); } catch { return; }

    if (evt.type === "log") {
      logLine(evt.message, evt.level || "info");
      inferStep(evt.message);
    }

    if (evt.type === "error") {
      logLine(evt.message, "error");
      source.close();
      btnScan.disabled = false;
      setTimeout(() => showSection("hero"), 2000);
    }

    if (evt.type === "result") {
      lastScanData = evt.data;
    }

    if (evt.type === "done") {
      source.close();
      activeSource = null;
      btnScan.disabled = false;
      if (lastScanData) {
        setTimeout(() => renderResults(lastScanData), 500);
      }
    }
  };

  source.onerror = () => {
    logLine("Stream connection lost.", "error");
    source.close();
    activeSource = null;
    btnScan.disabled = false;
    if (lastScanData) renderResults(lastScanData);
    else setTimeout(() => showSection("hero"), 2000);
  };
});

// ── Render results ────────────────────────────────────────────────────────────
function renderResults(data) {
  const vulns = data.vulnerabilities || [];
  const summary = data.summary || {};

  sumTotal.textContent  = summary.total  ?? 0;
  sumSqli.textContent   = summary.sqli   ?? 0;
  sumXss.textContent    = summary.xss    ?? 0;
  sumPrompt.textContent = summary.prompt ?? 0;
  sumData.textContent   = summary.data_leakage ?? 0;

  // Calculate Vulnerability Risk Index Score
  let score = 0;
  vulns.forEach(v => {
    const sev = v.explanation?.severity || "INFO";
    if (sev === "CRITICAL") score += 35;
    else if (sev === "HIGH")     score += 25;
    else if (sev === "MEDIUM")   score += 15;
    else if (sev === "LOW")      score += 5;
  });

  const finalPct = Math.min(100, score);
  const riskBar = document.getElementById("risk-bar");
  const riskPct = document.getElementById("risk-pct");
  const riskStatus = document.getElementById("risk-status");

  // Animate the bar width
  riskBar.style.width = `${finalPct}%`;
  riskPct.textContent = `${finalPct}%`;

  // Set colors and status messages based on severity
  if (finalPct === 0) {
    riskBar.style.background = "var(--success)";
    riskStatus.textContent = "Secure / No Vulnerabilities";
    riskStatus.style.color = "var(--success)";
    riskPct.style.color = "var(--success)";
  } else if (finalPct <= 20) {
    riskBar.style.background = "var(--primary)";
    riskStatus.textContent = "Low Risk";
    riskStatus.style.color = "var(--primary2)";
    riskPct.style.color = "var(--primary2)";
  } else if (finalPct <= 50) {
    riskBar.style.background = "var(--warning)";
    riskStatus.textContent = "Medium Risk";
    riskStatus.style.color = "var(--warning)";
    riskPct.style.color = "var(--warning)";
  } else {
    riskBar.style.background = "var(--danger)";
    riskStatus.textContent = "High Risk / Vulnerable";
    riskStatus.style.color = "var(--danger)";
    riskPct.style.color = "var(--danger)";
  }

  scanMeta.textContent = [
    `Target: ${data.target}`,
    `Pages crawled: ${data.crawled_pages}`,
    `Forms found: ${data.forms_found}`,
    `Chatbot endpoints: ${data.chatbots_found}`,
  ].join("  |  ");

  vulnList.innerHTML = "";
  noVuln.style.display = vulns.length ? "none" : "";

  const sorted = [...vulns].sort((a, b) =>
    (SEV_ORDER[a.explanation?.severity] ?? 99) - (SEV_ORDER[b.explanation?.severity] ?? 99)
  );
  sorted.forEach((v, i) => vulnList.appendChild(buildVulnCard(v, i + 1)));

  showSection("results");
}

function buildVulnCard(v, num) {
  const ex = v.explanation || {};
  const ml = v.ml_result || {};
  const sev = ex.severity || "INFO";
  const issue = ex.issue || ATTACK_LABEL[v.attack_type] || v.attack_type;

  const card = document.createElement("div");
  card.className = "vuln-card";
  card.innerHTML = `
    <div class="vuln-card-header" id="vcard-${num}">
      <span class="vuln-badge sev-${sev}">${sev}</span>
      <span class="vuln-name">${esc(issue)}</span>
      <span class="vuln-field">field: <span class="mono">${esc(v.input_field)}</span></span>
      <span class="vuln-conf">${ml.confidence ?? 0}% · ${esc(ml.detection_method || "ML")}</span>
      <svg class="chevron" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <polyline points="6 9 12 15 18 9"/>
      </svg>
    </div>
    <div class="vuln-body">
      <div class="meta-row"><span class="meta-lbl">Target URL</span><code>${esc(v.target_url)}</code></div>
      <div class="meta-row"><span class="meta-lbl">Input Field</span><code>${esc(v.input_field)}</code></div>
      <div class="meta-row"><span class="meta-lbl">Attack Type</span><code>${esc(ATTACK_LABEL[v.attack_type] || v.attack_type)}</code></div>
      <div class="meta-row"><span class="meta-lbl">Payload Used</span><code class="payload-code">${esc(v.payload)}</code></div>
      <div class="meta-row"><span class="meta-lbl">HTTP Status</span><code>${v.status_code}</code></div>
      <div class="meta-row"><span class="meta-lbl">ML Probabilities</span><div style="display:flex;flex-wrap:wrap;gap:.4rem">${renderProbs(ml.probabilities)}</div></div>
      <div class="meta-row"><span class="meta-lbl">Response</span>
        <div class="response-snippet" onclick="this.classList.toggle('expanded')" title="Click to expand">${esc(v.response_snippet || "—")}</div>
      </div>
      <div class="divider"></div>
      <div class="section-label">Impact</div>
      <div class="explanation-text">${esc(ex.impact || "N/A")}</div>
      <div class="section-label" style="margin-top:1rem">Root Cause</div>
      <div class="explanation-text">${esc(ex.reason || "N/A")}</div>
      <div class="section-label" style="margin-top:1rem">Remediation Fix</div>
      <div class="explanation-text">${esc(ex.fix || "N/A")}</div>
      <div class="code-grid">
        <div><div class="code-lbl red">❌ Vulnerable Code</div><pre class="code-block">${esc(ex.vulnerable_code || "N/A")}</pre></div>
        <div><div class="code-lbl green">✅ Secure Code</div><pre class="code-block">${esc(ex.secure_code || "N/A")}</pre></div>
      </div>
      <div class="source-label">AI Explanation by: ${esc(ex.source || "Local Knowledge Base")}</div>
    </div>`;

  card.querySelector(".vuln-card-header").addEventListener("click", () => card.classList.toggle("open"));
  if (num === 1) card.classList.add("open");
  return card;
}

function renderProbs(probs) {
  if (!probs) return "";
  return Object.entries(probs).map(([k, v]) =>
    `<span style="background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:4px;padding:.15rem .5rem;font-size:.72rem;font-family:var(--mono,monospace)">${esc(k)}: ${v}%</span>`
  ).join("");
}

// ── Report download ───────────────────────────────────────────────────────────
btnReport.addEventListener("click", async () => {
  if (!lastScanData) return;
  btnReport.disabled = true;
  btnReport.textContent = "Generating...";
  try {
    const res = await fetch("/api/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_data: lastScanData })
    });
    const d = await res.json();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([d.html], { type: "text/html" }));
    a.download = `vuln-report-${new Date().toISOString().slice(0,19).replace(/:/g,"-")}.html`;
    a.click();
  } catch (err) {
    alert("Report error: " + err.message);
  } finally {
    btnReport.disabled = false;
    btnReport.textContent = "Download Report";
  }
});

// ── New Scan ──────────────────────────────────────────────────────────────────
btnNewScan.addEventListener("click", () => {
  if (activeSource) { activeSource.close(); activeSource = null; }
  lastScanData = null;
  urlInput.value = "";
  showSection("hero");
  clearConsole();
  resetSteps();
  urlInput.focus();
  checkModelStatus();
});

// ── HTML escape ───────────────────────────────────────────────────────────────
function esc(s) {
  return String(s ?? "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
