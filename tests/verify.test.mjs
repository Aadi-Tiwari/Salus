import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { createLocalServer } from "../server.mjs";
import { scan, recheckResources, targetIdentity } from "../local/scan.mjs";
import { checkSource, createVerificationStore, loadVerificationConfig, runTests } from "../local/verify.mjs";

const digest = (value) => createHash("sha256").update(value).digest("hex");
const listen = (server) => new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${server.address().port}/`)));
const close = (server) => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); });
const post = (base, path, value) => fetch(base + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(value) });
async function waitFor(base, id) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    const attempt = await (await fetch(base + "api/verifications/" + id)).json();
    if (!["queued", "running"].includes(attempt.status)) {
      // The API updates in memory before the atomic save finishes.
      await new Promise((resolve) => setTimeout(resolve, 30));
      return attempt;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.fail("Verification did not finish");
}
async function baseline(target, checks) {
  const report = { scan: { id: randomUUID(), target_url: target, target_identity: targetIdentity(target), target_host: new URL(target).host, checks, status: "queued", created_at: new Date().toISOString() }, findings: [], check_results: [] };
  await scan(report, async () => {}, target);
  return report;
}

test("real configured tests, fresh scan, exact source and target binding, failure, and restart evidence", async () => {
  const directory = await mkdtemp(join(tmpdir(), "salus-verify-"));
  const project = join(directory, "project"), reports = join(directory, "reports");
  await mkdir(project); await mkdir(join(reports, "runs"), { recursive: true });
  const source = join(project, "app.js"), repaired = "export const repaired = true;\n";
  await writeFile(source, "export const repaired = false;\n");
  let wrongDestination = false;
  const target = createServer(async (_req, res) => {
    res.setHeader("content-type", wrongDestination ? "application/json" : "text/html");
    if ((await readFile(source, "utf8")).includes("= true")) {
      res.setHeader("content-security-policy", "default-src 'self'"); res.setHeader("x-content-type-options", "nosniff");
      res.setHeader("x-frame-options", "DENY"); res.setHeader("referrer-policy", "no-referrer");
    }
    res.end("<h1>Fixture app</h1>");
  });
  const targetUrl = await listen(target);
  const before = await baseline(targetUrl + "?mode=one", ["headers"]);
  assert.equal(before.check_results[0].state, "found");
  await writeFile(join(reports, before.scan.id + ".json"), JSON.stringify(before));
  const run = { id: randomUUID(), status: "draft_ready", scan_id: before.scan.id, source_id: randomUUID(), finding_ids: before.findings.map((finding) => finding.id),
    events: [], patch: "reviewed fixture patch", expected_files: [{ path: "app.js", sha256: digest(repaired) }] };
  await writeFile(join(reports, "runs", run.id + ".json"), JSON.stringify(run));
  await writeFile(join(project, "check.test.mjs"), `import assert from 'node:assert/strict'; import { readFile } from 'node:fs/promises'; import { test } from 'node:test'; test('application response remains available', async () => { const response = await fetch(${JSON.stringify(targetUrl)}); assert.equal(response.status, 200); assert.match(await response.text(), /Fixture app/); }); test('project regression', async () => assert.equal(await readFile('test-state.txt','utf8'), 'pass')); console.log('private test output must not be saved');`);
  await writeFile(join(project, "test-state.txt"), "pass");
  const configPath = join(directory, "verify.json");
  const config = { project_dir: project, target_url: targetUrl + "?mode=two", test_command: [process.execPath, "--test", "check.test.mjs"] };
  await writeFile(configPath, JSON.stringify(config));
  let server = await createLocalServer({ directory: reports, verificationConfig: configPath }), base = await listen(server);
  const input = { run_id: run.id, consent: true };
  try {
    assert.equal((await post(base, "api/verifications", input)).status, 400, "redacted display URLs cannot hide a different query");
    await close(server);
    config.target_url = before.scan.target_url;
    await writeFile(configPath, JSON.stringify(config));
    server = await createLocalServer({ directory: reports, verificationConfig: configPath }); base = await listen(server);
    assert.equal((await post(base, "api/verifications", { ...input, consent: false })).status, 400);
    let response = await post(base, "api/verifications", input);
    assert.equal(response.status, 202);
    const mismatch = await waitFor(base, (await response.json()).id);
    assert.equal(mismatch.status, "failed"); assert.equal(mismatch.tests, undefined);
    await writeFile(source, repaired);
    response = await post(base, "api/verifications", input);
    const id = (await response.json()).id;
    assert.equal((await post(base, "api/verifications", input)).status, 409);
    assert.equal((await post(base, "api/scans", { target_url: targetUrl, checks: ["headers"], authorized: true })).status, 409);
    const passed = await waitFor(base, id);
    assert.equal(passed.status, "passed", JSON.stringify(passed));
    assert.equal(passed.tests.exit_code, 0);
    assert.equal(passed.checks[0].after, "clean");
    assert.equal(passed.source_after.state, "passed");
    assert.ok(passed.tests.output_bytes > 0);
    assert.ok(!JSON.stringify(passed).includes("private test output"));
    await writeFile(join(project, "test-state.txt"), "fail");
    const failed = await waitFor(base, (await (await post(base, "api/verifications", input)).json()).id);
    assert.equal(failed.status, "failed"); assert.notEqual(failed.tests.exit_code, 0);
    assert.equal(failed.checks[0].state, "passed", "passing security checks cannot hide a failing project test");
    await writeFile(join(project, "test-state.txt"), "pass"); wrongDestination = true;
    const changed = await waitFor(base, (await (await post(base, "api/verifications", input)).json()).id);
    assert.equal(changed.status, "inconclusive"); assert.equal(changed.response.state, "inconclusive");
    await close(server);
    const interrupted = { id: randomUUID(), run_id: run.id, status: "running" };
    await writeFile(join(reports, "verifications", interrupted.id + ".json"), JSON.stringify(interrupted));
    server = await createLocalServer({ directory: reports, verificationConfig: configPath }); base = await listen(server);
    assert.deepEqual(await (await fetch(base + "api/verifications/" + id)).json(), passed);
    const reopened = await (await fetch(base + "api/verifications/" + interrupted.id)).json();
    assert.equal(reopened.status, "inconclusive"); assert.match(reopened.error, /stopped/);
  } finally { await close(server); await close(target); await rm(directory, { recursive: true, force: true }); }
});

test("unlinked source maps and leaked scripts are rechecked at their original locations", async () => {
  let linked = true, removed = false;
  const target = createServer((req, res) => {
    if (req.url === "/app.js.map") {
      if (removed) { res.writeHead(404); return res.end(); }
      return res.end(JSON.stringify({ version: 3, sources: ["app.ts"], sourcesContent: ["private source"] }));
    }
    if (req.url === "/app.js") return res.end("const key = 'sb_secret_" + "x".repeat(32) + "';\n//# sourceMappingURL=/app.js.map");
    res.end(linked ? '<script src="/app.js"></script>' : "<p>No linked scripts</p>");
  });
  const targetUrl = await listen(target);
  try {
    const before = await baseline(targetUrl, ["source-maps", "exposed-keys"]);
    linked = false;
    const after = await baseline(targetUrl, ["source-maps", "exposed-keys"]);
    assert.ok(after.check_results.every((check) => check.state === "clean"));
    const probes = await recheckResources(before.findings, targetUrl);
    assert.ok(probes.every((probe) => probe.state === "failed"));
    removed = true;
    const removedProbe = await recheckResources(before.findings.filter((finding) => finding.check_key === "source-maps"), targetUrl);
    assert.equal(removedProbe[0].state, "passed"); assert.equal(removedProbe[0].http_status, 404);
    const redacted = await recheckResources([{ ...before.findings[0], locator: targetUrl + "?redacted" }], targetUrl);
    assert.equal(redacted[0].state, "inconclusive");
  } finally { await close(target); }
});

test("test execution is bounded and does not expose stdout or stderr", async () => {
  const project = await mkdtemp(join(tmpdir(), "salus-tests-"));
  try {
    const config = { project_dir: project, test_command: [process.execPath, "-e", "setInterval(()=>{},1000)"], timeout_ms: 100 };
    const timed = await runTests(config);
    assert.equal(timed.state, "unavailable"); assert.match(timed.reason, /time limit/);
    assert.equal(timed.cleanup, "completed");
    const flooded = await runTests({ ...config, timeout_ms: 3000, test_command: [process.execPath, "-e", "process.stdout.write('x'.repeat(300000));setInterval(()=>{},1000)"] });
    assert.equal(flooded.state, "unavailable"); assert.match(flooded.reason, /output limit/);
    const missing = await runTests({ ...config, test_command: [join(project, "absent.exe")] });
    assert.equal(missing.state, "unavailable"); assert.equal(missing.exit_code, null);
    const configFile = join(project, "config.json");
    await writeFile(configFile, JSON.stringify({ project_dir: project, target_url: "https://external.invalid", test_command: [process.execPath] }));
    assert.equal((await loadVerificationConfig(configFile)).available, false);
    assert.equal((await loadVerificationConfig()).available, false);
  } finally { await rm(project, { recursive: true, force: true }); }
});

test("encoded resource identities and unselected leaks cannot produce a passing verification", async () => {
  const directory = await mkdtemp(join(tmpdir(), "salus-resource-identity-"));
  await writeFile(join(directory, "app.js"), "repaired");
  let linked = true;
  const secret = "const key = 'sb_secret_" + "x".repeat(32) + "';";
  const target = createServer((req, res) => {
    res.setHeader("content-type", "text/html");
    if (req.url === "/") return res.end(linked ? '<script src="/app%252F.js"></script><script src="/other.js"></script>' : '<p>App</p>');
    if (req.url === "/app%252F.js" || req.url === "/other.js") return res.end(secret);
    res.writeHead(404); res.end();
  });
  const url = await listen(target);
  try {
    const before = await baseline(url, ["exposed-keys"]);
    const encoded = before.findings.find((finding) => finding.locator.includes("%2F"));
    assert.ok(encoded);
    assert.equal((await recheckResources([encoded], url))[0].state, "inconclusive");
    assert.equal((await fetch(url + "app%252F.js")).status, 200);
    const run = { id: randomUUID(), status: "draft_ready", scan_id: before.scan.id, finding_ids: [encoded.id],
      expected_files: [{ path: "app.js", sha256: digest("repaired") }], patch: "fixture patch" };
    const store = await createVerificationStore({ directory, config: { available: true, project_dir: directory, target_url: url,
      test_command: [process.execPath, "-e", "process.exit(0)"], timeout_ms: 3000 }, agents: { getRun: () => run },
      reports: new Map([[before.scan.id, before]]), reserve: () => true, release: () => {}, runScan: (report, target) => scan(report, async () => {}, target) });
    linked = false;
    const attempt = await store.start({ run_id: run.id, consent: true });
    const deadline = Date.now() + 10_000;
    while (["queued", "running"].includes(attempt.status) && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(attempt.status, "failed");
    assert.equal(attempt.checks[0].after, "clean");
    assert.ok(attempt.resources.some((probe) => probe.locator.endsWith("/other.js") && probe.state === "failed"));
    await new Promise((resolve) => setTimeout(resolve, 30));
  } finally { await close(target); await rm(directory, { recursive: true, force: true }); }
});

test("source correspondence rejects changes, missing files, and junction escapes", async () => {
  const directory = await mkdtemp(join(tmpdir(), "salus-source-check-"));
  const project = join(directory, "project"), outside = join(directory, "outside");
  await mkdir(project); await mkdir(outside);
  await writeFile(join(outside, "app.js"), "expected");
  await symlink(outside, join(project, "linked"), process.platform === "win32" ? "junction" : "dir");
  try {
    assert.equal((await checkSource(project, [{ path: "linked/app.js", sha256: digest("expected") }])).state, "failed");
    await writeFile(join(project, "app.js"), "changed");
    assert.equal((await checkSource(project, [{ path: "app.js", sha256: digest("expected") }])).state, "failed");
    assert.equal((await checkSource(project, [{ path: "missing.js", sha256: digest("expected") }])).state, "failed");
  } finally { await rm(directory, { recursive: true, force: true }); }
});
