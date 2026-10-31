const API_BASE = "http://10.80.58.202:8900";
const USE_MOCK = false;

let currentJobId = null;
let hasAnalysis = false;
let mockDataPromise;
let mockIngestStartedAt = 0;
let mockIngestRepo = "";
let activeTab = "overview";
let analyzeProgress = 0;

async function mockData() {
  if (!mockDataPromise) mockDataPromise = fetch("mock-data.json").then(response => response.json());
  return mockDataPromise;
}

async function request(path, options = {}, mockKey) {
  if (USE_MOCK) {
    const data = await mockData();
    return data[mockKey];
  }
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const body = await response.json();
      detail = body.detail || body.note || detail;
    } catch (error) {
      // Keep the HTTP status when the backend does not return JSON.
    }
    const requestError = new Error(detail);
    requestError.status = response.status;
    throw requestError;
  }
  return response.json();
}

async function health() { return request("/api/health", {}, "health"); }
async function ingest(repo_url) {
  if (USE_MOCK) {
    mockIngestStartedAt = Date.now();
    mockIngestRepo = repo_url;
    const data = await mockData();
    return { ...data.ingest, job_id: "mockjob", repo: repo_url, status: "started" };
  }
  return request("/api/ingest", { method: "POST", body: JSON.stringify({ repo_url }) }, "ingest");
}
async function ingestStatus(job_id = currentJobId) {
  if (USE_MOCK && job_id === "mockjob") {
    const data = await mockData();
    const complete = Date.now() - mockIngestStartedAt >= 2000;
    return {
      ...data.ingestStatus,
      job_id,
      status: complete ? "done" : "running",
      repo: mockIngestRepo,
      commit: data.ingestStatus.commit,
      error: null,
    };
  }
  return request(`/api/ingest/${encodeURIComponent(job_id)}`, {}, "ingestStatus");
}
async function cbom(job_id = currentJobId) {
  return request(`/api/cbom?job_id=${encodeURIComponent(job_id)}`, {}, "cbom");
}
async function risk(job_id = currentJobId) {
  return request(`/api/risk?job_id=${encodeURIComponent(job_id)}`, {}, "risk");
}
async function quantum(job_id = currentJobId) {
  return request(`/api/quantum?job_id=${encodeURIComponent(job_id)}`, {}, "quantum");
}
async function compare(asset_id, job_id = currentJobId) {
  if (USE_MOCK) return request(`/api/compare?asset_id=${encodeURIComponent(asset_id)}&job_id=${encodeURIComponent(job_id)}`, {}, "compare");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 240000);
  try {
    const response = await fetch(`${API_BASE}/api/compare?asset_id=${encodeURIComponent(asset_id)}&job_id=${encodeURIComponent(job_id)}`, {
      headers: { "Content-Type": "application/json" },
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
  } catch (error) {
    if (error.name === "AbortError") throw new Error("request timed out after 240 seconds");
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}
async function approve(asset_id, job_id, chosen_algorithm) {
  return request("/api/approve", {
    method: "POST",
    body: JSON.stringify({ asset_id, job_id, chosen_algorithm }),
  }, "approve");
}
async function evidence(asset_id, job_id = currentJobId) {
  return request(`/api/evidence/${encodeURIComponent(asset_id)}?job_id=${encodeURIComponent(job_id)}`, {}, "evidence");
}

function setConnection(state, message = "") {
  const banner = document.querySelector("#backend-message");
  banner.textContent = message;
  banner.className = `backend-message ${message ? "visible" : ""} ${state.toLowerCase()}`;
}

function setActiveTab(tab) {
  activeTab = tab;
  document.querySelectorAll(".tab").forEach(button => {
    const selected = button.dataset.tab === tab;
    button.classList.toggle("active", selected);
    button.setAttribute("aria-selected", selected ? "true" : "false");
  });
  const sectionByTab = { overview: "overview-section", cbom: "cbom-section", risk: "risk-section", quantum: "quantum-section", fixes: "fix-section", approval: "approval-section" };
  document.querySelectorAll("#dashboard-sections > section").forEach(section => {
    section.hidden = !hasAnalysis || section.id !== sectionByTab[tab];
  });
}

function updateAnalyzeProgress(percent, label) {
  analyzeProgress = Math.max(0, Math.min(100, percent));
  document.querySelector("#analyze-progress").hidden = false;
  document.querySelector("#analyze-progress-label").textContent = label;
  document.querySelector("#analyze-progress-percent").textContent = `${analyzeProgress}%`;
  document.querySelector("#analyze-progress-fill").style.width = `${analyzeProgress}%`;
}

function hideAnalyzeProgress() {
  document.querySelector("#analyze-progress").hidden = true;
}

function renderOverview(status, assets, quantumPayload) {
  document.querySelector("#overview-section")?.remove();
  const assetList = assets?.assets || [];
  const quantumAtRisk = (quantumPayload?.assessments || []).filter(assessment => assessment.mosca_at_risk).length;
  const riskAssessments = window.currentRiskAssessments || [];
  const bands = ["Low", "Moderate", "High", "Critical"];
  const bandCounts = Object.fromEntries(bands.map(band => [band, riskAssessments.filter(assessment => assessment.band === band).length]));
  const highestBand = [...bands].reverse().find(band => bandCounts[band] > 0) || "None";
  const repo = status?.repo || "—";
  const repoName = repo.split("/").filter(Boolean).pop() || repo;
  document.querySelector("#repo-context").textContent = status?.repo ? `${repoName} · ${String(status.commit || "—").slice(0, 7)}` : "";
  const section = document.createElement("section");
  section.id = "overview-section";
  section.className = "dashboard-section";
  section.innerHTML = `<div class="section-heading"><h2>Overview</h2></div>
    <p class="overview-repo">${escapeHtml(repoName)} · ${escapeHtml(String(status?.commit || "—").slice(0, 7))}</p>
    <div class="overview-stats">
      <div><strong>${assetList.length}</strong><span>Crypto assets</span></div>
      <div><strong>${assetList.filter(asset => asset.is_weak).length}</strong><span>Weak assets</span></div>
      <div><strong>${quantumAtRisk}</strong><span>Quantum at risk</span></div>
      <div><strong>${escapeHtml(highestBand)}</strong><span>Highest risk band</span></div>
    </div>
    <div class="severity-breakdown">${bands.map(band => `<div><strong>${bandCounts[band]}</strong><span>${band}</span></div>`).join("")}</div>`;
  document.querySelector("#dashboard-sections").insertAdjacentElement("afterbegin", section);
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[character]));
}

let assetDetailsById = new Map();

function registerAssets(assets) {
  assetDetailsById = new Map(assets.map((asset, index) => [asset.asset_id, { ...asset, index: index + 1 }]));
}

function assetLabel(assetId, algorithm = "Asset") {
  const asset = assetDetailsById.get(assetId);
  if (!asset) return `${algorithm} — ${assetId}`;
  return `${asset.algorithm || algorithm} #${asset.index} — ${asset.file_path}:${asset.line}`;
}

function assetReadableLabel(assetId, algorithm = "Asset") {
  const asset = assetDetailsById.get(assetId);
  return `${asset?.algorithm || algorithm} #${asset?.index || "?"}`;
}

function assetTrace(assetId) {
  return `<span class="asset-trace mono">${escapeHtml(assetId)}</span>`;
}

function testResult(value) {
  return `<span class="test-result ${value ? "pass" : "fail"}">${value ? "✓ pass" : "failed"}</span>`;
}

function shortPatchHash(candidate) {
  return candidate.patch_hash_short || String(candidate.patch_hash || "").slice(0, 12);
}

function renderCbom(payload) {
  const assets = payload.assets || [];
  registerAssets(assets);
  document.querySelector("#asset-count").textContent = `${assets.length} ASSET${assets.length === 1 ? "" : "S"}`;
  document.querySelector("#cbom-body").innerHTML = assets.length ? assets.map(asset => `<tr>
    <td><span class="algorithm">${escapeHtml(assetReadableLabel(asset.asset_id))}</span></td>
    <td class="mono asset-id">${escapeHtml(asset.asset_id)}</td>
    <td class="mono">${escapeHtml(asset.file_path)}:${escapeHtml(asset.line)}</td>
    <td>${escapeHtml(asset.operation)}</td>
    <td>${asset.is_weak ? `<span class="weakness weak" title="${escapeHtml(asset.weak_reason)}">Weak</span><small class="weak-reason">${escapeHtml(asset.weak_reason)}</small>` : `<span class="weakness strong">Strong</span>`}</td>
  </tr>`).join("") : `<tr><td colspan="5" class="empty-state">No cryptographic assets found.</td></tr>`;
}

function renderRisk(payload) {
  document.querySelector("#risk-section")?.remove();
  const assessments = payload?.assessments || [];
  window.currentRiskAssessments = assessments;
  if (!assessments.length) return;

  const section = document.createElement("section");
  section.id = "risk-section";
  section.className = "dashboard-section";
  section.innerHTML = `<div class="section-heading"><h2>Risk Assessment</h2><span class="section-meta">${assessments.length} ASSESSMENT${assessments.length === 1 ? "" : "S"}</span></div>
    <div class="table-panel"><div class="table-panel-header">Risk Board</div><div class="table-wrap"><table class="risk-table">
      <thead><tr><th>Algorithm</th><th>Asset ID</th><th>File:Line</th><th>Score</th><th>Band</th><th>Factors / Rationale</th></tr></thead>
      <tbody>${assessments.map(assessment => `<tr>
        <td><span class="algorithm">${escapeHtml(assetReadableLabel(assessment.asset_id, assessment.algorithm))}</span></td>
        <td class="mono asset-id">${escapeHtml(assessment.asset_id)}</td>
        <td class="mono">${escapeHtml(assetDetailsById.get(assessment.asset_id)?.file_path || "—")}:${escapeHtml(assetDetailsById.get(assessment.asset_id)?.line || "—")}</td>
        <td><span class="risk-score">${escapeHtml(assessment.score)}</span></td>
        <td><span class="risk-band ${escapeHtml(String(assessment.band).toLowerCase())}">${escapeHtml(assessment.band)}</span></td>
        <td class="rationale"><div class="factor-breakdown">${Object.entries(assessment.factors || {}).map(([factor, value]) => `${escapeHtml(factor)} ${escapeHtml(value)}`).join(" · ")}</div>${escapeHtml(assessment.rationale)}</td>
      </tr>`).join("")}</tbody>
    </table></div></div><p class="risk-caption">Weighted 0-100 model: weakness 35%, exposure 20%, data sensitivity 15%, lifetime 15%, feasibility 20%.</p>`;
  document.querySelector("#cbom-section").insertAdjacentElement("afterend", section);
}

function renderQuantum(payload) {
  document.querySelector("#quantum-section")?.remove();
  const assessments = payload?.assessments || [];
  if (!assessments.length) return;

  const section = document.createElement("section");
  section.id = "quantum-section";
  section.className = "dashboard-section";
  section.innerHTML = `<div class="section-heading"><h2>Quantum Risk (Mosca's Inequality)</h2><span class="section-meta">${assessments.length} ASSESSMENT${assessments.length === 1 ? "" : "S"}</span></div>
    <div class="table-panel"><div class="table-panel-header">Quantum Exposure</div><div class="table-wrap"><table class="quantum-table">
      <thead><tr><th>Algorithm</th><th>Asset ID</th><th>File:Line</th><th>Quantum Threat</th><th>X+Y vs Z</th><th>Urgency</th><th>Recommended PQC</th></tr></thead>
      <tbody>${assessments.map(assessment => {
        const threat = assessment.shor_broken
          ? `<span class="quantum-threat shor">Shor (broken)</span>`
          : assessment.grover_weakened
            ? `<span class="quantum-threat grover">Grover (weakened)</span>`
            : `<span class="quantum-threat none">—</span>`;
        const comparison = `${assessment.mosca_x}+${assessment.mosca_y} ${assessment.mosca_x + assessment.mosca_y > assessment.mosca_z ? ">" : "<="} ${assessment.mosca_z}`;
        return `<tr class="${assessment.mosca_at_risk ? "at-risk" : ""}">
          <td><span class="algorithm">${escapeHtml(assetReadableLabel(assessment.asset_id, assessment.algorithm))}</span></td>
          <td class="mono asset-id">${escapeHtml(assessment.asset_id)}</td>
          <td class="mono">${escapeHtml(assetDetailsById.get(assessment.asset_id)?.file_path || "—")}:${escapeHtml(assetDetailsById.get(assessment.asset_id)?.line || "—")}</td>
          <td>${threat}</td>
          <td class="mono">${escapeHtml(comparison)}</td>
          <td><span class="urgency ${escapeHtml(String(assessment.urgency).toLowerCase())}">${escapeHtml(assessment.urgency)}</span></td>
          <td class="recommended-pqc">${escapeHtml(assessment.recommended_pqc)}</td>
        </tr>`;
      }).join("")}</tbody>
    </table></div></div>`;
  const riskSection = document.querySelector("#risk-section");
  (riskSection || document.querySelector("#cbom-section")).insertAdjacentElement("afterend", section);
}

function candidateTable(asset, comparison) {
  return `<div class="table-panel"><div class="table-panel-header">Fix Candidates</div><div class="table-wrap"><table class="fix-table">
    <thead><tr><th>Candidate</th><th>Asset ID</th><th>File:Line</th><th>Builds</th><th>Crash fixed</th><th>Regression</th><th>Crypto verified</th><th>Risk Before → After</th><th>Drop</th><th>Review / Approve</th></tr></thead>
    <tbody>${comparison.candidates.map(candidate => `<tr class="${candidate.target_algorithm === comparison.recommended ? "recommended" : ""}">
      <td><span class="algorithm">${escapeHtml(candidate.target_algorithm)}</span>${candidate.target_algorithm === comparison.recommended ? ` <span class="recommended-badge">Recommended</span>` : ""}${candidate.simulated ? ` <span class="simulated-badge">simulated</span>` : ""}${candidate.execution_failed ? `<small class="execution-note">execution failed</small>` : ""}${shortPatchHash(candidate) ? `<small class="patch-hash mono">${escapeHtml(shortPatchHash(candidate))}</small>` : ""}</td>
      <td class="mono asset-id">${escapeHtml(asset.asset_id)}</td>
      <td class="mono">${escapeHtml(asset.file_path)}:${escapeHtml(asset.line)}</td>
      <td>${testResult(candidate.builds)}</td>
      <td>${testResult(candidate.crash_fixed)}</td>
      <td>${testResult(candidate.regression_pass)}</td>
      <td>${testResult(candidate.crypto_verified)}</td>
      <td class="mono risk-transition">${escapeHtml(candidate.risk_before)} → ${escapeHtml(candidate.risk_after)}</td>
      <td class="risk-drop">-${escapeHtml(Math.abs(candidate.risk_drop))}</td>
      <td><button class="view-tests" type="button" data-asset-id="${escapeHtml(asset.asset_id)}" data-algorithm="${escapeHtml(candidate.target_algorithm)}">View tests</button>${candidate.validates ? `<button class="approve-button" type="button" data-asset-id="${escapeHtml(asset.asset_id)}" data-algorithm="${escapeHtml(candidate.target_algorithm)}">Approve</button>` : ""}</td>
    </tr>`).join("")}</tbody>
  </table></div></div>
  <p class="approval-message" aria-live="polite"></p>`;
}

function attachApprovalButtons(container) {
  container.querySelectorAll(".approve-button").forEach(button => button.addEventListener("click", handleApproval));
  container.querySelectorAll(".view-tests").forEach(button => button.addEventListener("click", handleEvidenceDetail));
}

async function loadComparison(asset, article, button, status) {
  button.disabled = true;
  status.className = "compare-status loading";
  status.textContent = "Generating and validating fixes…";
  const progress = article.querySelector(".compare-progress");
  const fill = progress.querySelector(".progress-fill");
  const percent = article.querySelector(".compare-percent");
  const startedAt = Date.now();
  progress.hidden = false;
  percent.hidden = false;
  const update = () => {
    const value = Math.min(90, Math.round(90 * (1 - Math.exp(-(Date.now() - startedAt) / 30000))));
    fill.style.width = `${value}%`;
    percent.textContent = `${value}%`;
  };
  update();
  const timer = setInterval(update, 1000);
  try {
    const comparison = await compare(asset.asset_id);
    if (!comparison?.candidates?.length) throw new Error("no candidates returned");
    clearInterval(timer);
    fill.style.width = "100%";
    percent.textContent = "100%";
    status.textContent = "";
    status.className = "compare-status";
    progress.hidden = true;
    percent.hidden = true;
    let evidencePayload = null;
    if (comparison.recommended) {
      try { evidencePayload = await evidence(asset.asset_id); } catch (error) { /* comparison remains usable */ }
    }
    fillComparisonCard(asset, comparison, evidencePayload);
  } catch (error) {
    clearInterval(timer);
    progress.hidden = true;
    percent.hidden = true;
    status.className = "compare-status failed";
    status.textContent = `Fix generation failed — ${error.message || "request could not be completed"}`;
    button.disabled = false;
  }
}

function renderFixComparisons(payload) {
  document.querySelector("#fix-section")?.remove();
  const assets = (payload?.assets || []).filter(asset => asset.is_weak);
  if (!assets.length) return;

  const section = document.createElement("section");
  section.id = "fix-section";
  section.className = "dashboard-section";
  section.innerHTML = `<div class="section-heading"><h2>Fix Alternatives</h2><span class="section-meta">${assets.length} WEAK ASSET${assets.length === 1 ? "" : "S"}</span></div>
    ${assets.map(asset => `<article class="fix-asset" data-asset-id="${escapeHtml(asset.asset_id)}">
      <h3>${escapeHtml(assetReadableLabel(asset.asset_id))} <span>— ${escapeHtml(asset.file_path)}:${escapeHtml(asset.line)} · ${assetTrace(asset.asset_id)} · candidate fixes</span></h3>
      <div class="compare-controls"><button class="compare-button" type="button">Compare fixes</button><span class="compare-status" aria-live="polite"></span><span class="compare-percent" hidden>0%</span></div>
      <div class="progress-track compare-progress" hidden><div class="progress-fill"></div></div>
      <div class="compare-results"></div>
    </article>`).join("")}`;
  section.querySelectorAll(".fix-asset").forEach((article, index) => {
    const button = article.querySelector(".compare-button");
    const status = article.querySelector(".compare-status");
    button.addEventListener("click", () => loadComparison(assets[index], article, button, status));
  });
  document.querySelector("#quantum-section")?.insertAdjacentElement("afterend", section) || document.querySelector("#cbom-section").insertAdjacentElement("afterend", section);
}

function fillComparisonCard(asset, comparison, evidencePayload = null) {
  const article = document.querySelector(`.fix-asset[data-asset-id="${CSS.escape(asset.asset_id)}"]`);
  if (!article) return;
  const button = article.querySelector(".compare-button");
  button.hidden = true;
  article.querySelector(".compare-status").textContent = "";
  article.querySelector(".compare-results").innerHTML = candidateTable(asset, comparison);
  attachApprovalButtons(article);
  if (comparison.recommended && evidencePayload) renderApprovalReview(asset, evidencePayload, comparison);
}

async function restorePersistedComparisons(payload) {
  const assets = (payload?.assets || []).filter(asset => asset.is_weak);
  await Promise.all(assets.map(async asset => {
    try {
      const evidencePayload = await evidence(asset.asset_id);
      const comparison = evidencePayload?.comparison;
      if (comparison?.candidates?.length) fillComparisonCard(asset, comparison, evidencePayload);
    } catch (error) {
      // Missing evidence means this asset has not been compared yet.
    }
  }));
}

async function handleEvidenceDetail(event) {
  const button = event.currentTarget;
  const asset = assetBlockAsset(button.dataset.assetId);
  button.disabled = true;
  button.textContent = "Loading tests";
  try {
    const evidencePayload = await evidence(asset.asset_id);
    renderFixDetail(asset, evidencePayload);
  } catch (error) {
    button.disabled = false;
    button.textContent = "View tests";
  }
}

async function handleApproval(event) {
  const button = event.currentTarget;
  const assetId = button.dataset.assetId;
  const algorithm = button.dataset.algorithm;
  const assetBlock = button.closest(".fix-asset");
  const message = assetBlock.querySelector(".approval-message");
  button.disabled = true;
  try {
    const result = await approve(assetId, currentJobId, algorithm);
    if (result.status === "approved") {
      message.className = "approval-message approved";
      message.textContent = `Approved ${algorithm} — risk ${result.risk_before} -> ${result.risk_after}`;
      assetBlock.querySelectorAll(".approve-button").forEach(candidateButton => {
        candidateButton.disabled = candidateButton !== button;
      });
      button.textContent = "Approved";
      try {
        renderApprovalReview(assetBlockAsset(assetId), await evidence(assetId), null);
      } catch (error) {
        // Keep the approval confirmation visible if evidence is temporarily unavailable.
      }
    } else {
      message.className = "approval-message refused";
      message.textContent = `Approval refused: ${result.note || "the backend refused this patch"}`;
      button.disabled = false;
    }
  } catch (error) {
    message.className = "approval-message refused";
    message.textContent = error.status === 400
      ? `Approval refused: ${error.message}`
      : "Backend unreachable — approval could not be completed.";
    button.disabled = false;
  }
}

function assetBlockAsset(assetId) {
  return assetDetailsById.get(assetId) || { asset_id: assetId, algorithm: "Asset" };
}

function evidenceReviewMarkup(asset, evidencePayload, comparison) {
  const diagnosis = evidencePayload?.diagnosis || {};
  const patch = evidencePayload?.patch || {};
  const validation = evidencePayload?.validation || {};
  const selectedAlgorithm = evidencePayload?.approval?.chosen_algorithm || comparison?.recommended || "—";
  const selectedCandidate = (evidencePayload?.comparison?.candidates || comparison?.candidates || []).find(candidate => candidate.target_algorithm === selectedAlgorithm);
  const simulated = selectedCandidate?.simulated ?? validation.simulated;
  return `<div class="review-block"><h3>Diagnosis</h3><p><strong>Root cause</strong> ${escapeHtml(diagnosis.root_cause || "—")}</p><p><strong>Vulnerability class</strong> ${escapeHtml(diagnosis.vulnerability_class || "—")}</p></div>
    <details class="reasoning-block"><summary>Reasoning trace</summary><pre>${escapeHtml(diagnosis.reasoning_trace || "—")}</pre></details>
    <div class="review-block"><h3>Patch — ${escapeHtml(selectedAlgorithm)}</h3><div class="patch-columns"><div><h4>Original code</h4><pre>${escapeHtml(patch.original_code || "—")}</pre></div><div><h4>Patched code</h4><pre>${escapeHtml(patch.patched_code || "—")}</pre></div></div></div>
    <div class="review-block"><h3>Validation</h3><div class="review-tests"><span>Builds ${testResult(validation.builds)}</span><span>Crash fixed ${testResult(validation.crash_fixed)}</span><span>Regression ${testResult(validation.regression_pass)}</span><span>Crypto verified ${testResult(selectedCandidate?.crypto_verified ?? false)}</span>${simulated ? `<span class="simulated-badge">simulated</span>` : ""}</div></div>`;
}

function renderApprovalReview(asset, evidencePayload, comparison) {
  document.querySelector("#approval-section")?.remove();
  const section = document.createElement("section");
  section.id = "approval-section";
  section.className = "dashboard-section";
  section.innerHTML = `<div class="section-heading"><h2>Approval Review</h2><span class="section-meta">${escapeHtml(assetLabel(asset.asset_id, asset.algorithm))}</span></div><p class="approval-note">A human reviews the generated fix and its test evidence, then approves it; the system refuses fixes that are not genuinely validated.</p>${evidenceReviewMarkup(asset, evidencePayload, comparison)}`;
  document.querySelector("#dashboard-sections").appendChild(section);
  setActiveTab(activeTab);
}

function renderFixDetail(asset, evidencePayload) {
  document.querySelector("#fix-detail-section")?.remove();
  const comparison = evidencePayload?.comparison || {};
  const section = document.createElement("section");
  section.id = "fix-detail-section";
  section.className = "dashboard-section";
  section.innerHTML = `<button class="detail-back" type="button">← Back to Fixes</button><div class="section-heading"><h2>Fix Test Detail</h2><span class="section-meta">${escapeHtml(assetLabel(asset.asset_id, asset.algorithm))}</span></div>${evidenceReviewMarkup(asset, evidencePayload, comparison)}`;
  document.querySelector("#dashboard-sections").appendChild(section);
  section.querySelector(".detail-back").addEventListener("click", () => {
    section.remove();
    document.querySelector("#fix-section").hidden = false;
    setActiveTab("fixes");
  });
  setActiveTab("fixes");
  document.querySelector("#fix-section").hidden = true;
  section.hidden = false;
}

function wait(milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
}

async function pollIngest(jobId, repo) {
  while (true) {
    const status = await ingestStatus(jobId);
    if (status.status === "done") {
      currentJobId = status.job_id || jobId;
      const loaded = await loadDashboard(true);
      if (!loaded) return;
      updateAnalyzeProgress(100, "Analysis complete");
      hideAnalyzeProgress();
      const shortCommit = status.commit ? ` @ ${String(status.commit).slice(0, 7)}` : "";
      setConnection(USE_MOCK ? "MOCK" : "LIVE", `Analyzed ${status.repo || repo}${shortCommit}`);
      return;
    }
    if (status.status === "error") {
      updateAnalyzeProgress(analyzeProgress, "Analysis failed");
      setConnection("ERROR", `Analysis failed — ${status.error || "unknown error"}`);
      return;
    }
    updateAnalyzeProgress(25, "Repository accepted; waiting for scan…");
    setConnection("INGESTING", `Cloning and scanning ${status.repo || repo}…`);
    await wait(1500);
  }
}

async function loadDashboard(withProgress = false) {
  setConnection("CONNECTING");
  try {
    const [healthData, status, assets] = await Promise.all([health(), ingestStatus(), cbom()]);
    hasAnalysis = true;
    document.querySelector("#tab-bar").hidden = false;
    document.querySelector("#initial-state").hidden = true;
    renderCbom(assets);
    if (withProgress) updateAnalyzeProgress(50, "CBOM loaded");
    let riskPayload = { assessments: [] };
    try {
      riskPayload = await risk();
      renderRisk(riskPayload);
    } catch (error) {
      renderRisk({ assessments: [] });
    }
    if (withProgress) updateAnalyzeProgress(75, "Risk loaded");
    let quantumPayload = { assessments: [] };
    try {
      quantumPayload = await quantum();
      renderQuantum(quantumPayload);
    } catch (error) {
      renderQuantum({ assessments: [] });
    }
    renderFixComparisons(assets);
    restorePersistedComparisons(assets);
    renderOverview(status, assets, quantumPayload);
    setActiveTab(activeTab);
    if (withProgress) updateAnalyzeProgress(100, "Quantum loaded");
    setConnection(USE_MOCK ? "MOCK" : "LIVE");
    return true;
  } catch (error) {
    if (withProgress) updateAnalyzeProgress(analyzeProgress, "Analysis failed");
    setConnection("OFFLINE", "Backend unreachable — start the Kali API or set USE_MOCK = true for local demo data.");
    document.querySelector("#cbom-body").innerHTML = `<tr><td colspan="5" class="empty-state error-state">CBOM unavailable while backend is unreachable.</td></tr>`;
    renderRisk({ assessments: [] });
    renderQuantum({ assessments: [] });
    renderFixComparisons({ assets: [] });
    return false;
  }
}

async function startIngest(event) {
  event.preventDefault();
  const url = document.querySelector("#repo-url").value.trim();
  if (!url) return setConnection("READY", "Enter a GitHub URL to start analysis.");
  if (!/^https?:\/\/\S+$/i.test(url)) return setConnection("READY", "Enter a valid repository URL.");
  updateAnalyzeProgress(0, "Starting analysis");
  setConnection("INGESTING", `Cloning and scanning ${url}…`);
  try {
    const started = await ingest(url);
    if (!started.job_id) throw new Error("ingest did not return a job_id");
    await pollIngest(started.job_id, started.repo || url);
  } catch (error) {
    setConnection("OFFLINE", "Backend unreachable — the ingest request could not be completed.");
  }
}

document.querySelector("#ingest-form").addEventListener("submit", startIngest);
document.querySelectorAll(".tab").forEach(button => button.addEventListener("click", () => setActiveTab(button.dataset.tab)));
setActiveTab("overview");
