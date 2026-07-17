const state = { selected: null, after: 0, timer: null };
const token = document.querySelector("#token");
token.value = sessionStorage.getItem("templar-token") ?? "";
token.addEventListener("input", () => sessionStorage.setItem("templar-token", token.value));

async function api(url, options = {}) {
  const headers = new Headers(options.headers);
  if (token.value) headers.set("Authorization", `Bearer ${token.value}`);
  const response = await fetch(url, { ...options, headers });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error?.message ?? `HTTP ${response.status}`);
  return data;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function refreshRuns() {
  const runs = await api("/api/runs");
  const list = document.querySelector("#run-list");
  list.innerHTML = runs.length === 0 ? '<p class="muted">No durable runs yet.</p>' : "";
  for (const run of runs) {
    const button = document.createElement("button");
    button.className = "run-card";
    button.innerHTML = `<strong>${escapeHtml(run.workflow ?? "workflow")}</strong><span class="status">${escapeHtml(run.status)}</span><span class="run-meta">${escapeHtml(run.runId)} · ${run.totalTokens} tokens</span>`;
    button.addEventListener("click", () => selectRun(run.runId));
    list.append(button);
  }
}

async function selectRun(runId) {
  state.selected = runId;
  state.after = 0;
  document.querySelector("#timeline").innerHTML = "";
  await refreshDetail();
}

async function refreshDetail() {
  if (!state.selected) return;
  const run = await api(`/api/runs/${encodeURIComponent(state.selected)}`);
  document.querySelector("#detail-title").textContent = run.runId;
  const summary = document.querySelector("#run-summary");
  summary.innerHTML = [
    ["Status", run.status],
    ["Rounds", run.rounds],
    ["Agent turns", run.agentTurns],
    ["Agents", run.totalAgents],
    ["Tokens", run.totalTokens],
    ["Selected", run.selectedCandidateId ?? "—"],
  ]
    .map(([key, value]) => `<div><span>${escapeHtml(key)}</span>${escapeHtml(value)}</div>`)
    .join("");
  const active = run.status === "queued" || run.status === "running";
  document.querySelector("#cancel").hidden = !active;
  const events = await api(
    `/api/runs/${encodeURIComponent(state.selected)}/events?after=${state.after}`,
  );
  const timeline = document.querySelector("#timeline");
  for (const event of events) {
    state.after = Math.max(state.after, event.sequence);
    const item = document.createElement("li");
    item.innerHTML = `<time>${escapeHtml(event.at)} · #${event.sequence}</time><strong>${escapeHtml(event.type)}</strong>`;
    timeline.append(item);
  }
  if (run.status === "accepted" && run.applied) {
    const output = await api(`/api/runs/${encodeURIComponent(state.selected)}/result`);
    const promotion = output.promotion;
    const audit = output.evaluationAudit;
    document.querySelector("#acknowledge").hidden =
      !promotion.requiresHumanAcknowledgment || promotion.acknowledged;
    document.querySelector("#final-output").innerHTML =
      `<h3>Accepted result</h3><pre>${escapeHtml(JSON.stringify(output.result, null, 2))}</pre><h3>Audit findings</h3><pre>${escapeHtml(JSON.stringify(audit, null, 2))}</pre><h3>Promotion gate</h3><pre>${escapeHtml(JSON.stringify(promotion, null, 2))}</pre><h3>Report</h3><pre>${escapeHtml(output.report)}</pre>`;
  } else {
    document.querySelector("#acknowledge").hidden = true;
  }
}

document.querySelector("#incident-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const status = document.querySelector("#form-status");
  status.textContent = "Starting…";
  try {
    const file = document.querySelector("#pcap").files[0];
    let artifact;
    if (file)
      artifact = await api("/api/artifacts/pcap", {
        method: "POST",
        headers: { "Content-Type": "application/vnd.tcpdump.pcap" },
        body: file,
      });
    const body = { schema_version: "1", request: document.querySelector("#request").value };
    const ticket = document.querySelector("#ticket").value.trim();
    if (ticket) body.ticket_ref = ticket;
    if (artifact) body.pcap_artifact_id = artifact.artifact_id;
    const submitted = await api("/api/incidents", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    status.textContent = `Started ${submitted.run_id}`;
    await refreshRuns();
    await selectRun(submitted.run_id);
  } catch (error) {
    status.textContent = error.message;
  }
});
document
  .querySelector("#refresh")
  .addEventListener("click", () => refreshRuns().catch(console.error));
document.querySelector("#cancel").addEventListener("click", async () => {
  if (state.selected) {
    await api(`/api/runs/${encodeURIComponent(state.selected)}/cancel`, { method: "POST" });
    await refreshDetail();
  }
});
document.querySelector("#acknowledge").addEventListener("click", async () => {
  if (!state.selected) return;
  const rationale = window.prompt(
    "Why is this high-impact or manually audited result safe to promote?",
  );
  if (rationale) {
    await api(`/api/runs/${encodeURIComponent(state.selected)}/acknowledge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rationale }),
    });
    await refreshDetail();
  }
});
refreshRuns().catch((error) => {
  document.querySelector("#run-list").textContent = error.message;
});
state.timer = setInterval(() => {
  refreshRuns().catch(() => {});
  refreshDetail().catch(() => {});
}, 2500);
