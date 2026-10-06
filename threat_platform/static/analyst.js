"use strict";
const $ = id => document.getElementById(id);
let selected = null, offset = 0, total = 0, assessing = false, reviewing = false;
const limit = 20;
function message(text, error = false) { $("message").textContent = text; $("message").className = error ? "error" : ""; }
async function request(url, options = {}) {
  const response = await fetch(url, {cache: "no-store", ...options});
  const data = await response.json();
  if (!response.ok) {
    const detail = Array.isArray(data.detail) ? data.detail.map(e => e.loc.join(".") + ": " + e.msg).join("; ") : data.detail;
    throw new Error(detail || "Request failed (" + response.status + ")");
  }
  return data;
}
async function run(action) { try { await action(); } catch (error) { message(error.message, true); } }
function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function newEvent() { $("event-id").value = crypto.randomUUID ? crypto.randomUUID() : "demo-" + Date.now(); }
async function serviceStatus() {
  const status = await request("/analyst/status");
  $("service").textContent = (status.model_ready ? "Model ready" : "Model unavailable") + " · " +
    (status.case_storage_ready ? "Case storage ready" : "Case storage unavailable");
  $("assess-button").disabled = !status.model_ready || !status.case_storage_ready;
}
async function queue() {
  const params = new URLSearchParams({limit, offset, review: $("review-filter").value, alert_only: $("alert-filter").checked});
  const result = await request("/cases?" + params);
  total = result.total;
  $("queue-count").textContent = total + " matching case" + (total === 1 ? "" : "s");
  $("queue").replaceChildren();
  if (!result.cases.length) $("queue").append(element("p", "No matching cases. Assess a flow or change the filters.", "muted"));
  for (const item of result.cases) {
    const button = element("button", undefined, "case-item" + (selected && selected.id === item.id ? " selected" : ""));
    button.type = "button";
    button.append(element("strong", item.event_id),
      element("small", "Score " + item.prediction.suspicious_score.toFixed(4) + " · Version " + item.prediction.model_version),
      element("span", item.prediction.alert ? "ALERT" : "BELOW THRESHOLD", "tag" + (item.prediction.alert ? " alert" : "")),
      element("small", "Review: " + item.review));
    button.addEventListener("click", () => run(async () => { await openCase(item.id); await queue(); }));
    $("queue").append(button);
  }
  $("previous").disabled = offset === 0;
  $("next").disabled = offset + limit >= total;
  $("page-info").textContent = total ? (offset + 1) + "–" + Math.min(offset + limit, total) + " of " + total : "0 cases";
}
function renderCase(data) {
  const changed = !selected || selected.id !== data.id;
  selected = data;
  if (changed) $("note").value = "";
  $("empty-detail").hidden = true;
  $("case-detail").hidden = false;
  $("case-title").textContent = data.event_id;
  $("score").textContent = data.prediction.suspicious_score.toFixed(4);
  $("threshold").textContent = data.prediction.threshold.toFixed(4);
  $("decision").textContent = data.prediction.alert ? "Alert" : "Below threshold";
  $("model-meta").textContent = "Version " + data.prediction.model_version + " · " + data.prediction.feature_version +
    " · CPU · Bundle " + data.prediction.bundle_sha256.slice(0, 16) + "…";
  $("flow-detail").textContent = JSON.stringify(data.flow_display || data.flow, null, 2);
  const explanation = data.explanation;
  const maximum = Math.max(1e-9, ...explanation.contributions.map(c => Math.abs(c.contribution)));
  $("contributions").replaceChildren();
  for (const contribution of explanation.contributions) {
    const row = element("div", undefined, "contribution" + (contribution.contribution < 0 ? " negative" : ""));
    const name = element("span", contribution.feature);
    name.title = "Encoded feature value: " + contribution.value;
    const bar = document.createElement("progress");
    bar.max = maximum; bar.value = Math.abs(contribution.contribution);
    bar.setAttribute("aria-label", contribution.feature + " absolute contribution");
    row.append(name, bar, element("span", (contribution.contribution >= 0 ? "+" : "") + contribution.contribution.toFixed(4)));
    $("contributions").append(row);
  }
  $("explanation-summary").textContent = "Bias " + explanation.bias.toFixed(4) + " + contributions = margin " +
    explanation.raw_margin.toFixed(4) + ". Additivity verified; reconstructed score " + explanation.reconstructed_score.toFixed(4) + ".";
  $("history").replaceChildren();
  if (!data.feedback.length) $("history").append(element("p", "No analyst reviews yet.", "muted"));
  for (const review of data.feedback) {
    const entry = element("div", undefined, "history-entry");
    entry.append(element("strong", review.verdict + " · " + review.reviewer),
      element("small", " · Revision " + review.revision + " · " + review.created_at_utc),
      element("p", review.note || "No note provided."));
    $("history").append(entry);
  }
  $("verdict").value = data.feedback.length ? data.feedback[data.feedback.length - 1].verdict : "uncertain";
}
async function openCase(id) { renderCase(await request("/cases/" + encodeURIComponent(id))); }
$("assess-form").addEventListener("submit", event => {
  event.preventDefault();
  if (assessing) return;
  run(async () => {
    const flow = {duration_us: Number($("duration").value), packets: Number($("packets").value),
      bytes: Number($("bytes").value), protocol: $("protocol").value};
    if (![flow.duration_us, flow.packets, flow.bytes].every(n => Number.isSafeInteger(n) && n >= 0))
      throw new Error("Measurements must be nonnegative safe integers for the browser form.");
    assessing = true; $("assess-button").disabled = true;
    try {
      const data = await request("/cases", {method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({event_id: $("event-id").value, flow})});
      renderCase(data); offset = 0; await queue(); newEvent();
      message("Case saved. Review its model explanation before recording a verdict.");
    } finally { assessing = false; $("assess-button").disabled = false; }
  });
});
$("feedback-form").addEventListener("submit", event => {
  event.preventDefault();
  if (!selected || reviewing) return;
  run(async () => {
    reviewing = true; $("feedback-button").disabled = true;
    try {
      const data = await request("/cases/" + encodeURIComponent(selected.id) + "/feedback", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({expected_revision: selected.revision, reviewer: $("reviewer").value,
          verdict: $("verdict").value, note: $("note").value})});
      renderCase(data); $("note").value = ""; await queue();
      message("Review saved. The original model decision is unchanged.");
    } finally { reviewing = false; $("feedback-button").disabled = false; }
  });
});
$("refresh").addEventListener("click", () => run(async () => { await serviceStatus(); await queue(); if (selected) await openCase(selected.id); }));
for (const id of ["review-filter", "alert-filter"]) $(id).addEventListener("change", () => run(async () => { offset = 0; await queue(); }));
$("previous").addEventListener("click", () => run(async () => { offset = Math.max(0, offset - limit); await queue(); }));
$("next").addEventListener("click", () => run(async () => { offset += limit; await queue(); }));
$("export").addEventListener("click", () => run(async () => {
  if (!selected) return;
  const response = await fetch("/cases/" + encodeURIComponent(selected.id), {cache: "no-store"});
  if (!response.ok) throw new Error("Case export failed");
  const url = URL.createObjectURL(new Blob([await response.text()], {type: "application/json"}));
  const link = document.createElement("a"); link.href = url; link.download = "case-" + selected.id + ".json";
  link.click(); URL.revokeObjectURL(url);
}));
newEvent();
run(async () => { await serviceStatus(); await queue(); });
