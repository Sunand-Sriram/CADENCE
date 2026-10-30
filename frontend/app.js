const API_BASE = "http://localhost:8900";
const USE_MOCK = false;

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
  const pill = document.querySelector("#connection-pill");
  const banner = document.querySelector("#backend-message");
  pill.textContent = state;
  pill.className = `connection-pill ${state.toLowerCase()}`;
  banner.textContent = message;
  banner.className = `backend-message ${message ? "visible" : ""}`;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[character]));
}

function renderRepo(status, healthData) {
  const fields = [
    ["STATUS", status.status || "unknown", status.status === "done" ? "good" : ""],
    ["REPOSITORY", status.repo || "default", ""],
    ["COMMIT", status.commit || "—", "mono"],
    ["LLM MODE", healthData.llm_mode || "—", "mono"],
  ];
  document.querySelector("#repo-status").innerHTML = fields.map(([label, value, className]) => `<div class="status-item"><span>${label}</span><strong class="${className}">${escapeHtml(value)}</strong></div>`).join("");
  document.querySelector("#job-id").textContent = currentJobId;
}

function renderCbom(payload) {
  const assets = payload.assets || [];
  document.querySelector("#asset-count").textContent = `${assets.length} ASSET${assets.length === 1 ? "" : "S"}`;
  document.querySelector("#cbom-body").innerHTML = assets.length ? assets.map(asset => `<tr>
    <td><span class="algorithm">${escapeHtml(asset.algorithm)}</span></td>
    <td class="mono">${escapeHtml(asset.file_path)}:${escapeHtml(asset.line)}</td>
    <td>${escapeHtml(asset.operation)}</td>
    <td>${asset.is_weak ? `<span class="badge weak" title="${escapeHtml(asset.weak_reason)}">WEAK</span>` : `<span class="badge safe">CLEAR</span>`}</td>
  </tr>`).join("") : `<tr><td colspan="4" class="empty-state">No cryptographic assets found.</td></tr>`;
}

async function loadDashboard() {
  setConnection("CONNECTING");
  try {
    const [healthData, status, assets] = await Promise.all([health(), ingestStatus(), cbom()]);
    renderRepo(status, healthData);
    renderCbom(assets);
    setConnection(USE_MOCK ? "MOCK" : "LIVE");
  } catch (error) {
    setConnection("OFFLINE", "Backend unreachable — start the Kali API or set USE_MOCK = true for local demo data.");
    document.querySelector("#repo-status").innerHTML = `<div class="empty-state error-state">Unable to load repository status.</div>`;
    document.querySelector("#cbom-body").innerHTML = `<tr><td colspan="4" class="empty-state error-state">CBOM unavailable while backend is unreachable.</td></tr>`;
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
    document.querySelector("#job-id").textContent = currentJobId;
    const status = await ingestStatus(currentJobId);
    renderRepo(status, await health());
    setConnection("LIVE", `Analysis started for ${started.repo || url}.`);
    await loadDashboard();
  } catch (error) {
    setConnection("OFFLINE", "Backend unreachable — the ingest request could not be completed.");
  }
}

document.querySelector("#ingest-form").addEventListener("submit", startIngest);
loadDashboard();
