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
let verificationConfig, verificationPolling, retryVerification;

async function refreshScans(selected) {
  scans = await api("/api/scans");
  $("scan").innerHTML = '<option value="">Choose a finished scan</option>' + scans.filter((scan) => ["done", "partial"].includes(scan.status)).map((scan) =>
    `<option value="${scan.id}">${esc(scan.target_host)} · ${esc(new Date(scan.created_at).toLocaleString())} · ${esc(scan.status)}</option>`).join("");
  if (scans.some((scan) => scan.id === selected)) $("scan").value = selected;
}

async function showVerifications(run, sequence) {
  const attempts = (await api("/api/verifications")).filter((attempt) => attempt.run_id === run.id);
  if (sequence !== runRequest) return;
  const pending = attempts.some((attempt) => ["queued", "running"].includes(attempt.status));
  $("verify-repair").disabled = !verificationConfig?.available || run.status !== "draft_ready" || pending;
  $("verifications").innerHTML = attempts.map((attempt) => `<article class="record"><h3>${esc(attempt.status === "passed" ? "Recorded checks passed" : attempt.status)}</h3>
    <p>${esc(attempt.error || attempt.scope)}</p><p>${esc(new Date(attempt.created_at).toLocaleString())}</p>
    <ul><li>Source before tests: ${esc(attempt.source_before?.state || "not checked")}</li><li>Configured command: ${esc(attempt.tests?.state || "not run")}${attempt.tests ? ` (exit ${esc(attempt.tests.exit_code ?? "unavailable")})` : ""}</li>
    <li>Source after checks: ${esc(attempt.source_after?.state || "not checked")}</li>
    ${(attempt.checks || []).map((check) => `<li>${esc(check.check)}: ${esc(check.before)} → ${esc(check.after)} (${esc(check.state)})</li>`).join("")}
    ${(attempt.resources || []).map((probe) => `<li>${esc(probe.locator)}: ${esc(probe.detail)} (${esc(probe.state)})</li>`).join("")}</ul>
    <div class="actions"><a class="button" href="/scanner.html?scan=${encodeURIComponent(attempt.before_scan_id)}">Original report</a>${attempt.after_scan_id ? `<a class="button" href="/scanner.html?scan=${encodeURIComponent(attempt.after_scan_id)}">Fresh report</a>` : ""}
    <button type="button" data-evidence="${attempt.id}">Download evidence</button>
    ${["failed", "inconclusive"].includes(attempt.status) && attempt.after_scan_id ? `<button type="button" data-retry="${attempt.id}">Prepare another draft</button>` : ""}</div>
    <details><summary>Recorded evidence</summary><pre>${esc(JSON.stringify(attempt, null, 2))}</pre></details></article>`).join("") || '<p class="empty">No verification attempts yet. A downloadable patch has only passed an applicability check.</p>';
  $("verifications").querySelectorAll("[data-evidence]").forEach((button) => button.addEventListener("click", () => {
    const attempt = attempts.find((item) => item.id === button.dataset.evidence);
    download("salus-verification-" + attempt.id + ".json", JSON.stringify(attempt, null, 2), "application/json");
  }));
  $("verifications").querySelectorAll("[data-retry]").forEach((button) => button.addEventListener("click", async () => {
    try {
      const attempt = attempts.find((item) => item.id === button.dataset.retry);
      const report = await api("/api/scans/" + attempt.after_scan_id);
      if (!["done", "partial"].includes(report.scan.status)) throw new Error("The fresh scan did not finish. Resolve its coverage errors and scan again.");
      retryVerification = attempt;
      await refreshScans(attempt.after_scan_id);
      await showFindings();
      $("source").value = ""; showSource();
      $("model-consent").checked = false;
      $("retry-context").hidden = false;
      $("retry-context").textContent = "Retry after verification " + attempt.id + ". Attach current source and relevant tests. The draft receives failure status, not raw test logs. If the fresh scan is clean, the original findings provide repair context.";
      $("attach-form").scrollIntoView({ behavior: "instant", block: "start" });
      say("Attach current source, review the new findings, and consent before running another draft.");
    } catch (error) { say(error.message); }
  }));
  if (pending) verificationPolling = setTimeout(() => showVerifications(run, sequence).catch((error) => say(error.message)), 1000);
}

function download(name, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a");
  link.href = url; link.download = name; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

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
  let report = await api("/api/scans/" + $("scan").value);
  if (!report.findings.length && retryVerification?.after_scan_id === report.scan.id) report = await api("/api/scans/" + retryVerification.before_scan_id);
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
  clearTimeout(verificationPolling);
  $("verify-repair").disabled = true;
  $("verify-consent").checked = false;
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
  await showVerifications(run, sequence);
  if (sequence !== runRequest) return;
  if (["queued", "running"].includes(activeRun.status)) polling = setTimeout(() => showRun(id).catch((error) => say(error.message)), 1500);
  else await refreshRuns();
}

async function consolePage() {
  const status = await api("/api/agent");
  $("runtime").textContent = status.message;
  $("run-agent").disabled = !status.available;
  verificationConfig = await api("/api/verification-config");
  $("verification-config").textContent = verificationConfig.available
    ? `Project: ${verificationConfig.project_dir}\nTarget: ${verificationConfig.target_url}\nTest command: ${JSON.stringify(verificationConfig.test_command)}`
    : verificationConfig.message;
  const requested = new URLSearchParams(location.search).get("scan");
  await refreshScans(requested);
  await refreshSources();
  await showFindings();
  await refreshRuns();
  const run = new URLSearchParams(location.search).get("run");
  if (run) await showRun(run);
  $("scan").addEventListener("change", () => {
    if (retryVerification?.after_scan_id !== $("scan").value) { retryVerification = null; $("retry-context").hidden = true; }
    showFindings().catch((error) => say(error.message));
  });
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
        finding_ids: [...document.querySelectorAll('input[name="finding"]:checked')].map((input) => input.value), retry_verification_id: retryVerification?.id });
      history.replaceState(null, "", "?run=" + run.id);
      await showRun(run.id);
      $("run-detail").scrollIntoView({ behavior: "instant", block: "start" });
    } catch (error) { say(error.message); }
    finally { $("run-agent").disabled = !status.available; }
  });
  $("download").addEventListener("click", () => {
    if (!activeRun?.patch) return;
    download("salus-" + activeRun.id + ".patch", activeRun.patch, "text/x-patch");
  });
  $("verify-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const run = activeRun, sequence = runRequest;
    $("verify-repair").disabled = true;
    try {
      await api("/api/verifications", { run_id: run.id, consent: $("verify-consent").checked });
      if (sequence !== runRequest) return;
      clearTimeout(verificationPolling);
      await showVerifications(run, sequence);
      say("Verification started. The evidence will show what actually ran.");
    } catch (error) { say(error.message); if (sequence === runRequest) $("verify-repair").disabled = !verificationConfig.available; }
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
