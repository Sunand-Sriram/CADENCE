const API_BASE = "http://localhost:8900";
const USE_MOCK = true;

let currentJobId = "default";
let mockDataPromise;

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
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

async function health() { return request("/api/health", {}, "health"); }
async function ingest(repo_url) {
  return request("/api/ingest", { method: "POST", body: JSON.stringify({ repo_url }) }, "ingest");
}
async function ingestStatus(job_id = currentJobId) {
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
  return request(`/api/compare?asset_id=${encodeURIComponent(asset_id)}&job_id=${encodeURIComponent(job_id)}`, {}, "compare");
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

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[character]));
}

function renderCbom(payload) {
  const assets = payload.assets || [];
  document.querySelector("#asset-count").textContent = `${assets.length} ASSET${assets.length === 1 ? "" : "S"}`;
  document.querySelector("#cbom-body").innerHTML = assets.length ? assets.map(asset => `<tr>
    <td><span class="algorithm">${escapeHtml(asset.algorithm)}</span></td>
    <td class="mono asset-id">${escapeHtml(asset.asset_id)}</td>
    <td class="mono">${escapeHtml(asset.file_path)}:${escapeHtml(asset.line)}</td>
    <td>${escapeHtml(asset.operation)}</td>
    <td>${asset.is_weak ? `<span class="badge weak" title="${escapeHtml(asset.weak_reason)}">WEAK</span>` : `<span class="badge safe">CLEAR</span>`}</td>
  </tr>`).join("") : `<tr><td colspan="5" class="empty-state">No cryptographic assets found.</td></tr>`;
}

function renderRisk(payload) {
  document.querySelector("#risk-section")?.remove();
  const assessments = payload?.assessments || [];
  if (!assessments.length) return;

  const section = document.createElement("section");
  section.id = "risk-section";
  section.innerHTML = `<div class="section-heading"><h2>Risk Assessment</h2><span class="section-meta">${assessments.length} ASSESSMENT${assessments.length === 1 ? "" : "S"}</span></div>
    <div class="table-wrap"><table class="risk-table">
      <thead><tr><th>Algorithm</th><th>Score</th><th>Band</th><th>Rationale</th></tr></thead>
      <tbody>${assessments.map(assessment => `<tr>
        <td><span class="algorithm">${escapeHtml(assessment.algorithm)}</span></td>
        <td><span class="risk-score">${escapeHtml(assessment.score)}</span></td>
        <td><span class="risk-band ${escapeHtml(String(assessment.band).toLowerCase())}">${escapeHtml(assessment.band)}</span></td>
        <td class="rationale">${escapeHtml(assessment.rationale)}</td>
      </tr>`).join("")}</tbody>
    </table></div>`;
  document.querySelector("#cbom-section").insertAdjacentElement("afterend", section);
}

function renderQuantum(payload) {
  document.querySelector("#quantum-section")?.remove();
  const assessments = payload?.assessments || [];
  if (!assessments.length) return;

  const section = document.createElement("section");
  section.id = "quantum-section";
  section.innerHTML = `<div class="section-heading"><h2>Quantum Risk (Mosca's Inequality)</h2><span class="section-meta">${assessments.length} ASSESSMENT${assessments.length === 1 ? "" : "S"}</span></div>
    <div class="table-wrap"><table class="quantum-table">
      <thead><tr><th>Algorithm</th><th>Quantum Threat</th><th>X+Y vs Z</th><th>Urgency</th><th>Recommended PQC</th></tr></thead>
      <tbody>${assessments.map(assessment => {
        const threat = assessment.shor_broken
          ? `<span class="quantum-threat shor">Shor (broken)</span>`
          : assessment.grover_weakened
            ? `<span class="quantum-threat grover">Grover (weakened)</span>`
            : `<span class="quantum-threat none">—</span>`;
        const comparison = `${assessment.mosca_x}+${assessment.mosca_y} ${assessment.mosca_x + assessment.mosca_y > assessment.mosca_z ? ">" : "<="} ${assessment.mosca_z}`;
        return `<tr class="${assessment.mosca_at_risk ? "at-risk" : ""}">
          <td><span class="algorithm">${escapeHtml(assessment.algorithm)}</span></td>
          <td>${threat}</td>
          <td class="mono">${escapeHtml(comparison)}</td>
          <td><span class="urgency ${escapeHtml(String(assessment.urgency).toLowerCase())}">${escapeHtml(assessment.urgency)}</span></td>
          <td class="recommended-pqc">${escapeHtml(assessment.recommended_pqc)}</td>
        </tr>`;
      }).join("")}</tbody>
    </table></div>`;
  const riskSection = document.querySelector("#risk-section");
  (riskSection || document.querySelector("#cbom-section")).insertAdjacentElement("afterend", section);
}

function renderFixComparisons(items) {
  document.querySelector("#fix-section")?.remove();
  const available = items.filter(item => item.comparison?.candidates?.length);
  if (!available.length) return;

  const section = document.createElement("section");
  section.id = "fix-section";
  section.innerHTML = `<div class="section-heading"><h2>Fix Alternatives</h2><span class="section-meta">${available.length} WEAK ASSET${available.length === 1 ? "" : "S"}</span></div>
    ${available.map(({ asset, comparison }) => `<article class="fix-asset" data-asset-id="${escapeHtml(asset.asset_id)}">
      <h3>${escapeHtml(asset.algorithm)} <span>— candidate fixes</span></h3>
      <div class="table-wrap"><table class="fix-table">
        <thead><tr><th>Candidate</th><th>Validates</th><th>Risk Before → After</th><th>Drop</th><th>Action</th></tr></thead>
        <tbody>${comparison.candidates.map(candidate => `<tr class="${candidate.target_algorithm === comparison.recommended ? "recommended" : ""}">
          <td><span class="algorithm">${escapeHtml(candidate.target_algorithm)}</span>${candidate.target_algorithm === comparison.recommended ? ` <span class="recommended-badge">Recommended</span>` : ""}</td>
          <td><span class="validation ${candidate.validates ? "valid" : "failed"}">${candidate.validates ? "✓ valid" : "failed"}</span></td>
          <td class="mono risk-transition">${escapeHtml(candidate.risk_before)} → ${escapeHtml(candidate.risk_after)}</td>
          <td class="risk-drop">-${escapeHtml(Math.abs(candidate.risk_drop))}</td>
          <td>${candidate.validates ? `<button class="approve-button" type="button" data-asset-id="${escapeHtml(asset.asset_id)}" data-algorithm="${escapeHtml(candidate.target_algorithm)}">Approve</button>` : ""}</td>
        </tr>`).join("")}</tbody>
      </table></div>
      <p class="approval-message" aria-live="polite"></p>
    </article>`).join("")}`;
  section.querySelectorAll(".approve-button").forEach(button => button.addEventListener("click", handleApproval));
  document.querySelector("#quantum-section")?.insertAdjacentElement("afterend", section) || document.querySelector("#cbom-section").insertAdjacentElement("afterend", section);
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
    } else {
      message.className = "approval-message refused";
      message.textContent = "Approval refused";
      button.disabled = false;
    }
  } catch (error) {
    message.className = "approval-message refused";
    message.textContent = "Backend unreachable — approval could not be completed.";
    button.disabled = false;
  }
}

async function loadFixComparisons(assets) {
  const weakAssets = (assets.assets || []).filter(asset => asset.is_weak);
  if (!weakAssets.length) {
    renderFixComparisons([]);
    return;
  }
  const results = await Promise.all(weakAssets.map(async asset => {
    try {
      return { asset, comparison: await compare(asset.asset_id) };
    } catch (error) {
      if (!USE_MOCK) setConnection("OFFLINE", "Backend unreachable — fix comparisons are unavailable.");
      return { asset, comparison: null };
    }
  }));
  renderFixComparisons(results);
}

async function loadDashboard() {
  setConnection("CONNECTING");
  try {
    const [healthData, status, assets] = await Promise.all([health(), ingestStatus(), cbom()]);
    renderCbom(assets);
    try {
      renderRisk(await risk());
    } catch (error) {
      renderRisk({ assessments: [] });
    }
    try {
      renderQuantum(await quantum());
    } catch (error) {
      renderQuantum({ assessments: [] });
    }
    await loadFixComparisons(assets);
    setConnection(USE_MOCK ? "MOCK" : "LIVE");
  } catch (error) {
    setConnection("OFFLINE", "Backend unreachable — start the Kali API or set USE_MOCK = true for local demo data.");
    document.querySelector("#cbom-body").innerHTML = `<tr><td colspan="5" class="empty-state error-state">CBOM unavailable while backend is unreachable.</td></tr>`;
    renderRisk({ assessments: [] });
    renderQuantum({ assessments: [] });
    renderFixComparisons([]);
  }
}

async function startIngest(event) {
  event.preventDefault();
  const url = document.querySelector("#repo-url").value.trim();
  if (!url) return setConnection("READY", "Enter a GitHub URL to start analysis.");
  setConnection("INGESTING", "Cloning repository and starting crypto analysis…");
  try {
    const started = await ingest(url);
    currentJobId = started.job_id || "default";
    await ingestStatus(currentJobId);
    setConnection("LIVE", `Analysis started for ${started.repo || url}.`);
    await loadDashboard();
  } catch (error) {
    setConnection("OFFLINE", "Backend unreachable — the ingest request could not be completed.");
  }
}

document.querySelector("#ingest-form").addEventListener("submit", startIngest);
loadDashboard();
