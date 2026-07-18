const state = { selected: null, selectedWorkflow: null, after: 0, timer: null };
const token = document.querySelector("#token");
const workflow = document.querySelector("#workflow");
token.value = sessionStorage.getItem("templar-token") ?? "";
token.addEventListener("input", () => sessionStorage.setItem("templar-token", token.value));

async function api(url, options = {}) {
  const headers = new Headers(options.headers);
  if (token.value) headers.set("Authorization", `Bearer ${token.value}`);
  const response = await fetch(url, { ...options, headers });
  const data = await response.json();
  if (!response.ok) {
    const error = new Error(data.error?.message ?? `HTTP ${response.status}`);
    error.status = response.status;
    throw error;
  }
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
  state.selectedWorkflow = run.workflow ?? null;
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
    const evaluation = output.evaluation;
    let verification = null;
    if (run.workflow === "source_security_fix") {
      try {
        verification = await api(`/api/runs/${encodeURIComponent(state.selected)}/verification`);
      } catch (error) {
        if (error.status !== 404 && error.status !== 503) throw error;
      }
    }
    document.querySelector("#acknowledge").hidden =
      !promotion.requiresHumanAcknowledgment || promotion.acknowledged;
    document.querySelector("#verify").hidden =
      run.workflow !== "source_security_fix" || !promotion.acknowledged || verification !== null;
    document.querySelector("#final-output").innerHTML =
      `<h3>Accepted result</h3><pre>${escapeHtml(JSON.stringify(output.result, null, 2))}</pre><h3>Evaluation</h3><pre>${escapeHtml(JSON.stringify(evaluation, null, 2))}</pre><h3>Promotion gate</h3><pre>${escapeHtml(JSON.stringify(promotion, null, 2))}</pre>${verification === null ? "" : `<h3>Drone validation</h3><pre>${escapeHtml(JSON.stringify(verification, null, 2))}</pre>`}<h3>Report</h3><pre>${escapeHtml(output.report)}</pre>`;
  } else {
    document.querySelector("#acknowledge").hidden = true;
    document.querySelector("#verify").hidden = true;
  }
}

document.querySelector("#incident-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const status = document.querySelector("#form-status");
  status.textContent = "Starting…";
  try {
    const file = document.querySelector("#pcap").files[0];
    const securityTriage = workflow.value === "pcap_security_triage";
    const exerciseSolve = workflow.value === "exercise_solve";
    const sourceAudit = workflow.value === "source_security_audit";
    const sourceFix = workflow.value === "source_security_fix";
    if (securityTriage && !file) throw new Error("PCAP security triage requires a capture.");
    let artifact;
    if (file && !exerciseSolve && !sourceAudit && !sourceFix)
      artifact = await api("/api/artifacts/pcap", {
        method: "POST",
        headers: { "Content-Type": "application/vnd.tcpdump.pcap" },
        body: file,
      });
    const body = sourceFix
      ? {
          schema_version: "1",
          audit_run_id: document.querySelector("#source-audit-run").value.trim(),
        }
      : sourceAudit
        ? {
            schema_version: "1",
            source_snapshot_id: document.querySelector("#source-snapshot").value.trim(),
          }
        : exerciseSolve
          ? {
              schema_version: "1",
              exercise_snapshot_id: document.querySelector("#exercise-snapshot").value.trim(),
            }
          : securityTriage
            ? { schema_version: "1", pcap_artifact_id: artifact.artifact_id }
            : { schema_version: "1", request: document.querySelector("#request").value };
    if (!securityTriage && !exerciseSolve && !sourceAudit && !sourceFix) {
      const ticket = document.querySelector("#ticket").value.trim();
      if (ticket) body.ticket_ref = ticket;
      if (artifact) body.pcap_artifact_id = artifact.artifact_id;
    }
    const submitted = await api(`/api/workflows/${workflow.value}/runs`, {
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
workflow.addEventListener("change", () => {
  const securityTriage = workflow.value === "pcap_security_triage";
  const exerciseSolve = workflow.value === "exercise_solve";
  const sourceAudit = workflow.value === "source_security_audit";
  const sourceFix = workflow.value === "source_security_fix";
  document.querySelector("#request").disabled =
    securityTriage || exerciseSolve || sourceAudit || sourceFix;
  document.querySelector("#request").required =
    !securityTriage && !exerciseSolve && !sourceAudit && !sourceFix;
  document.querySelector("#ticket-field").hidden =
    securityTriage || exerciseSolve || sourceAudit || sourceFix;
  document.querySelector("#exercise-field").hidden = !exerciseSolve;
  document.querySelector("#exercise-snapshot").required = exerciseSolve;
  document.querySelector("#source-field").hidden = !sourceAudit;
  document.querySelector("#source-snapshot").required = sourceAudit;
  document.querySelector("#source-audit-field").hidden = !sourceFix;
  document.querySelector("#source-audit-run").required = sourceFix;
  document.querySelector("#pcap-field").hidden = exerciseSolve || sourceAudit || sourceFix;
  document.querySelector("#pcap").disabled = exerciseSolve || sourceAudit || sourceFix;
  document.querySelector("#workflow-description").textContent = sourceFix
    ? "Create isolated patch candidates and regressions for one accepted source audit."
    : sourceAudit
      ? "Audit a bounded source snapshot through recon, scoped hunts, and adversarial falsification."
      : exerciseSolve
        ? "Solve a bounded static-analysis exercise from an opaque evidence snapshot."
        : securityTriage
          ? "Passively triage one locally staged classic PCAP through scoped Agent Blocks agents."
          : "Investigate a bounded telecom incident.";
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
  const rationale = window.prompt("Why should this gated result be promoted?");
  if (rationale) {
    await api(`/api/runs/${encodeURIComponent(state.selected)}/acknowledge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rationale }),
    });
    await refreshDetail();
  }
});
document.querySelector("#verify").addEventListener("click", async () => {
  if (!state.selected || state.selectedWorkflow !== "source_security_fix") return;
  const rationale = window.prompt("Why should this accepted fix run in the configured Drone lab?");
  if (rationale) {
    await api(`/api/runs/${encodeURIComponent(state.selected)}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ schema_version: "1", rationale }),
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
