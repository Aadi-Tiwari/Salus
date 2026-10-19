import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, readdir, realpath, rename, writeFile } from "node:fs/promises";
import { isAbsolute, join, relative, sep } from "node:path";
import { localTarget, recheckResources, reportUrl, targetIdentity } from "./scan.mjs";

const hash = (value) => createHash("sha256").update(value).digest("hex");

export async function loadVerificationConfig(path) {
  if (!path) return { available: false, message: "Set SALUS_VERIFY_CONFIG to a private local configuration file, then restart Salus. See the guide." };
  try {
    const config = JSON.parse(await readFile(path, "utf8"));
    if (!isAbsolute(config.project_dir) || !Array.isArray(config.test_command) || !config.test_command.length ||
        config.test_command.some((arg) => typeof arg !== "string" || !arg || arg.includes("\0")) || /\.(?:cmd|bat)$/i.test(config.test_command[0])) {
      throw new Error("Use an absolute project_dir and a test_command array starting with a native executable, such as node.");
    }
    const project = await realpath(config.project_dir);
    const target = localTarget(config.target_url).href;
    const timeout = config.timeout_ms ?? 120_000;
    if (!Number.isInteger(timeout) || timeout < 100 || timeout > 300_000) throw new Error("timeout_ms must be between 100 and 300000.");
    return { available: true, project_dir: project, target_url: target, test_command: config.test_command, timeout_ms: timeout,
      identity: hash(JSON.stringify([project, target, config.test_command, timeout])) };
  } catch (error) {
    return { available: false, message: error.code || error instanceof SyntaxError ? "The verification configuration could not be loaded." : error.message };
  }
}

export async function checkSource(project, expected) {
  const files = [];
  for (const file of expected) {
    try {
      const path = await realpath(join(project, file.path));
      const rel = relative(project, path);
      if (isAbsolute(rel) || rel === ".." || rel.startsWith(".." + sep)) throw new Error("outside project");
      const actual = hash(await readFile(path));
      files.push({ path: file.path, expected_sha256: file.sha256, actual_sha256: actual, state: actual === file.sha256 ? "passed" : "failed" });
    } catch { files.push({ path: file.path, expected_sha256: file.sha256, state: "failed", detail: "File is missing, unreadable, or outside the configured project." }); }
  }
  return { state: files.length && files.every((file) => file.state === "passed") ? "passed" : "failed", files };
}

export function runTests(config) {
  return new Promise((resolve) => {
    const started = Date.now(), digest = createHash("sha256");
    let bytes = 0, stopped, finished = false, cutoff, cleanup = "not_needed";
    const env = { ...process.env };
    // A nested Node test runner otherwise skips the project's suite and exits zero.
    delete env.NODE_TEST_CONTEXT;
    const child = spawn(config.test_command[0], config.test_command.slice(1), {
      cwd: config.project_dir, env, shell: false, windowsHide: true, detached: process.platform !== "win32", stdio: ["ignore", "pipe", "pipe"],
    });
    const finish = (exitCode, signal, error) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      clearTimeout(cutoff);
      child.stdout?.destroy(); child.stderr?.destroy(); child.unref();
      resolve({ state: stopped || signal || error ? "unavailable" : exitCode === 0 ? "passed" : "failed",
        exit_code: exitCode, signal: signal || null, reason: stopped || (error ? "The configured executable could not start." : signal ? "The test process ended by signal." : "The configured command exited."),
        cleanup, duration_ms: Date.now() - started, output_bytes: bytes, output_sha256: digest.digest("hex") });
    };
    const stop = (reason) => {
      if (stopped || finished) return;
      stopped = reason;
      cleanup = "unconfirmed";
      if (child.pid) {
        if (process.platform === "win32") {
          const killer = spawn(join(process.env.SystemRoot || "C:\\Windows", "System32", "taskkill.exe"), ["/PID", String(child.pid), "/T", "/F"], { windowsHide: true, shell: false, stdio: "ignore" });
          killer.on("error", () => { cleanup = "failed"; child.kill(); });
          killer.on("close", (code) => { cleanup = code === 0 ? "completed" : "failed"; finish(null, null); });
          killer.unref();
        } else {
          try { process.kill(-child.pid, "SIGKILL"); cleanup = "completed"; } catch { cleanup = "failed"; child.kill(); }
        }
      }
      cutoff = setTimeout(() => finish(null, null), 2000);
    };
    const timer = setTimeout(() => stop("The configured command exceeded its time limit."), config.timeout_ms);
    for (const stream of [child.stdout, child.stderr]) stream.on("data", (chunk) => {
      if (finished || stopped) return;
      bytes += chunk.length;
      digest.update(chunk);
      if (bytes > 262_144) stop("The configured command exceeded its output limit.");
    });
    child.on("error", (error) => finish(null, null, error));
    child.on("close", (code, signal) => { if (cleanup !== "unconfirmed") finish(code, signal); });
  });
}

function compareChecks(before, after, findings) {
  return [...new Set(findings.map((finding) => finding.check_key))].map((key) => {
    const previous = before.check_results.find((check) => check.check === key);
    const current = after.check_results.find((check) => check.check === key);
    return { check: key, before: previous?.state || "not selected", after: current?.state || "not selected",
      state: current?.state === "found" ? "failed" : previous?.state === "found" && current?.state === "clean" ? "passed" : "inconclusive",
      reason: current?.reason || after.scan.error || "No completed check." };
  });
}

export async function createVerificationStore({ directory, config, agents, reports, reserve, release, runScan }) {
  const folder = join(directory, "verifications"), attempts = new Map();
  let cleanupBlocked = false;
  await mkdir(folder, { recursive: true });
  const save = async (attempt) => {
    const path = join(folder, attempt.id + ".json");
    await writeFile(path + ".tmp", JSON.stringify(attempt, null, 2));
    await rename(path + ".tmp", path);
  };
  for (const name of await readdir(folder)) {
    if (!/^[0-9a-f-]{36}\.json$/.test(name)) continue;
    const attempt = JSON.parse(await readFile(join(folder, name), "utf8"));
    if (["queued", "running"].includes(attempt.status)) {
      attempt.status = "inconclusive";
      attempt.error = "Salus stopped before verification finished. Run a new attempt.";
      await save(attempt);
    }
    attempts.set(attempt.id, attempt);
  }
  async function verify(attempt, run, before) {
    try {
      attempt.status = "running";
      attempt.source_before = await checkSource(config.project_dir, run.expected_files);
      await save(attempt);
      if (attempt.source_before.state !== "passed") {
        attempt.status = "failed";
        attempt.error = "The attached source does not match the proposed repair. Apply the reviewed patch or create a new draft from current source.";
        return;
      }
      attempt.tests = await runTests(config);
      if (["failed", "unconfirmed"].includes(attempt.tests.cleanup)) cleanupBlocked = true;
      await save(attempt);
      const after = { scan: { id: randomUUID(), target_url: reportUrl(config.target_url), target_identity: targetIdentity(config.target_url),
        target_host: new URL(config.target_url).host, checks: before.scan.checks, status: "queued", authorized: true,
        created_at: new Date().toISOString(), verification_id: attempt.id }, findings: [], check_results: [] };
      attempt.after_scan_id = after.scan.id;
      await save(attempt);
      await runScan(after, config.target_url);
      const selected = run.repair_findings || before.findings.filter((finding) => run.finding_ids.includes(finding.id));
      const keys = new Set(selected.map((finding) => finding.check_key));
      const findings = [...new Map([...before.findings.filter((finding) => keys.has(finding.check_key)), ...selected].map((finding) => [finding.id, finding])).values()];
      attempt.checks = compareChecks(before, after, selected);
      attempt.resources = await recheckResources(findings, config.target_url);
      attempt.response = { state: after.observation && before.observation &&
        after.observation.target_identity === before.observation.target_identity &&
        after.observation.http_status === before.observation.http_status &&
        after.observation.content_type === before.observation.content_type && after.observation.bytes > 0 ? "passed" : "inconclusive",
        before: before.observation, after: after.observation };
      attempt.source_after = await checkSource(config.project_dir, run.expected_files);
      const states = [attempt.source_before, attempt.source_after, attempt.tests, attempt.response, ...attempt.checks, ...attempt.resources].map((stage) => stage.state);
      attempt.status = states.includes("failed") ? "failed" : states.every((state) => state === "passed") ? "passed" : "inconclusive";
    } catch {
      attempt.status = "inconclusive";
      attempt.error = "Verification could not finish. Check the configured project and local app before trying again.";
    } finally {
      attempt.finished_at = new Date().toISOString();
      try { await save(attempt); } finally { release(); }
    }
  }
  return {
    configuration: () => config.available ? { ...config, target_url: reportUrl(config.target_url) } : config,
    get: (id) => attempts.get(id),
    list: () => [...attempts.values()].reverse(),
    async start(input) {
      if (!config.available) throw new Error("Configure local verification and restart Salus first.");
      if (cleanupBlocked) throw new Error("Test process cleanup was not confirmed. Inspect remaining project processes, stop them if needed, then restart Salus before another verification.");
      if (input.consent !== true) throw new Error("Confirm the patch was reviewed and applied, the target restarted, and the configured test command may run.");
      const run = agents.getRun(input.run_id), before = run && reports.get(run.baseline_scan_id || run.scan_id);
      if (run?.status !== "draft_ready" || !run.expected_files?.length || !before?.scan.target_identity || !before.observation) throw new Error("Choose a new completed draft with recorded source and target identities. Older drafts need a new scan and run.");
      if (before.scan.target_identity !== targetIdentity(config.target_url)) throw new Error("The configured verification URL does not match the original scan, including its query parameters.");
      if (!reserve()) throw Object.assign(new Error("A scan or verification is already running."), { status: 409 });
      const attempt = { id: randomUUID(), run_id: run.id, before_scan_id: before.scan.id, status: "queued", created_at: new Date().toISOString(),
        config_identity: config.identity, target_url: reportUrl(config.target_url), project_dir: config.project_dir, test_command: config.test_command,
        patch_sha256: hash(run.patch), scope: "Attached source correspondence, owner-configured tests, and selected local security checks. Server-to-source identity and whole-application security are not established." };
      try { await save(attempt); } catch (error) { release(); throw error; }
      attempts.set(attempt.id, attempt);
      verify(attempt, run, before).catch(() => console.error("Could not save verification evidence."));
      return attempt;
    },
  };
}
