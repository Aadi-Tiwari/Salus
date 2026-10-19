const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
const say = (text) => { $("message").textContent = text; };
async function api(path, input) {
  const response = await fetch(path, input ? { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(input) } : {});
  if (!response.headers.get("content-type")?.includes("application/json")) throw new Error("Start the local server with npm start to use this page.");
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || "The request failed.");
  return value;
}
const reportLink = (scan) => `<a href="/scanner.html?scan=${encodeURIComponent(scan.id)}">${esc(scan.target_host)}</a>`;
let scans = [], sources = [], selectedFiles = [], activeRun, polling;
let findingRequest = 0, runRequest = 0;

async function refreshSources() {
  sources = await api("/api/sources");
  $("source").innerHTML = '<option value="">Choose attached source</option>' + sources.map((source) =>
    `<option value="${source.id}">${esc(source.files.map((file) => file.path).join(", "))} (${esc(new Date(source.created_at).toLocaleString())})</option>`).join("");
}

function showSource() {
  const source = sources.find((item) => item.id === $("source").value);
  $("manifest").textContent = source ? source.files.map((file) => `${file.path} (${file.bytes} bytes)\nSHA-256 ${file.sha256}`).join("\n\n") : "Choose a snapshot to see its file hashes.";
}

async function showFindings() {
  const sequence = ++findingRequest;
  $("findings").textContent = "Loading findings...";
  if (!$("scan").value) { $("findings").textContent = "Choose a finished scan."; return; }
  const report = await api("/api/scans/" + $("scan").value);
  if (sequence !== findingRequest) return;
  $("findings").innerHTML = report.findings.filter((finding) => finding.evidence).map((finding) =>
    `<label class="check"><input type="checkbox" name="finding" value="${esc(finding.id)}" checked><span>${esc(finding.title)}</span></label>`).join("") || "This scan has no findings with evidence to send to the agent.";
}

async function refreshRuns() {
  const runs = await api("/api/runs");
  $("runs").innerHTML = runs.map((run) => `<div class="record"><b>${esc(run.status.replaceAll("_", " "))}</b><p>${esc(new Date(run.created_at).toLocaleString())}</p><button data-run="${run.id}">View run</button></div>`).join("") || '<p class="empty">No agent runs yet. A run starts only when you submit the form above.</p>';
  $("runs").querySelectorAll("[data-run]").forEach((button) => button.addEventListener("click", () => showRun(button.dataset.run).catch((error) => say(error.message))));
}

async function showRun(id) {
  const sequence = ++runRequest;
  clearTimeout(polling);
  const run = await api("/api/runs/" + id);
  if (sequence !== runRequest) return;
  activeRun = run;
  $("run-detail").hidden = false;
  $("run-title").textContent = activeRun.status.replaceAll("_", " ");
  $("run-summary").textContent = activeRun.error || activeRun.summary || "Codex is processing the selected evidence and source.";
  $("run-validation").textContent = activeRun.validation || "No patch has been validated yet.";
  $("run-events").textContent = activeRun.events.map((event) => `${event.at}  ${event.type}${event.item_type ? " / " + event.item_type : ""}`).join("\n") || "Waiting for runtime events.";
  $("manual-steps").textContent = (activeRun.manual_steps || []).join("\n");
  $("patch").textContent = activeRun.patch || "No patch available.";
  $("download").hidden = !activeRun.patch;
  $("run-id").textContent = "Run " + activeRun.id;
  if (["queued", "running"].includes(activeRun.status)) polling = setTimeout(() => showRun(id).catch((error) => say(error.message)), 1500);
  else await refreshRuns();
}

async function consolePage() {
  const status = await api("/api/agent");
  $("runtime").textContent = status.message;
  $("run-agent").disabled = !status.available;
  scans = await api("/api/scans");
  $("scan").innerHTML = '<option value="">Choose a finished scan</option>' + scans.filter((scan) => ["done", "partial"].includes(scan.status)).map((scan) =>
    `<option value="${scan.id}">${esc(scan.target_host)} · ${esc(new Date(scan.created_at).toLocaleString())} · ${esc(scan.status)}</option>`).join("");
  const requested = new URLSearchParams(location.search).get("scan");
  if (scans.some((scan) => scan.id === requested)) $("scan").value = requested;
  await refreshSources();
  await showFindings();
  await refreshRuns();
  const run = new URLSearchParams(location.search).get("run");
  if (run) await showRun(run);
  $("scan").addEventListener("change", () => showFindings().catch((error) => say(error.message)));
  $("source").addEventListener("change", showSource);
  $("files").addEventListener("change", () => {
    selectedFiles = [...$("files").files];
    $("file-paths").innerHTML = selectedFiles.map((file, index) => `<div class="source-row"><label for="path-${index}">Project-relative path for ${esc(file.name)}</label><input id="path-${index}" value="${esc(file.name)}" required></div>`).join("");
  });
  $("attach-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    $("attach").disabled = true;
    try {
      if (!selectedFiles.length || selectedFiles.length > 20 || selectedFiles.reduce((size, file) => size + file.size, 0) > 262144) throw new Error("Choose 1 to 20 text files, totaling at most 256 KiB.");
      const files = await Promise.all(selectedFiles.map(async (file, index) => ({ path: $("path-" + index).value.trim(), content: await file.text() })));
      const source = await api("/api/sources", { files });
      await refreshSources();
      $("source").value = source.id;
      showSource();
      say("Source snapshot saved locally. Nothing has been sent to the model.");
    } catch (error) { say(error.message); }
    finally { $("attach").disabled = false; }
  });
  $("agent-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    $("run-agent").disabled = true;
    try {
      const run = await api("/api/runs", { scan_id: $("scan").value, source_id: $("source").value, consent: $("model-consent").checked,
        finding_ids: [...document.querySelectorAll('input[name="finding"]:checked')].map((input) => input.value) });
      history.replaceState(null, "", "?run=" + run.id);
      await showRun(run.id);
      $("run-detail").scrollIntoView({ behavior: "instant", block: "start" });
    } catch (error) { say(error.message); }
    finally { $("run-agent").disabled = !status.available; }
  });
  $("download").addEventListener("click", () => {
    if (!activeRun?.patch) return;
    const url = URL.createObjectURL(new Blob([activeRun.patch], { type: "text/x-patch" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = "salus-" + activeRun.id + ".patch";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
}

async function reportsPage() {
  scans = await api("/api/scans");
  $("reports").innerHTML = scans.map((scan) => `<div class="record">${reportLink(scan)}<p>${esc(scan.status)} · ${esc(new Date(scan.created_at).toLocaleString())}</p><small>${esc(scan.target_url)}</small></div>`).join("") || '<p class="empty">No saved reports. Start a scan to create one.</p>';
  for (const id of ["before", "after"]) $(id).innerHTML = '<option value="">Choose a report</option>' + scans.map((scan) => `<option value="${scan.id}">${esc(scan.target_host)} · ${esc(scan.created_at)}</option>`).join("");
  $("compare-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const before = await api("/api/scans/" + $("before").value), after = await api("/api/scans/" + $("after").value);
      if (before.scan.id === after.scan.id || before.scan.target_url !== after.scan.target_url) throw new Error("Choose different reports for the same recorded target URL.");
      if (![before, after].every((report) => ["done", "partial"].includes(report.scan.status))) throw new Error("Both scans must finish before comparison.");
      $("comparison").innerHTML = '<p>Comparison covers only these recorded checks. URL query values are redacted; confirm both scans used the same input. A clean check is not a security certification.</p><div class="table-scroll"><table><thead><tr><th>Check</th><th>Before</th><th>After</th></tr></thead><tbody>' +
        [...new Set([...before.check_results, ...after.check_results].map((check) => check.check))].map((key) => `<tr><td>${esc(key)}</td><td>${esc(before.check_results.find((check) => check.check === key)?.state || "not selected")}</td><td>${esc(after.check_results.find((check) => check.check === key)?.state || "not selected")}</td></tr>`).join("") + '</tbody></table></div>';
      say("Comparison loaded from saved scan evidence.");
    } catch (error) { say(error.message); }
  });
}

if (document.body.dataset.page === "console") consolePage().catch((error) => say(error.message));
if (document.body.dataset.page === "reports") reportsPage().catch((error) => say(error.message));
