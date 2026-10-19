import assert from "node:assert/strict";
import { createServer, request } from "node:http";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { createLocalServer } from "../server.mjs";
import { CHECKS, localTarget } from "../local/scan.mjs";
import { auditHeaders, detectSecrets } from "../supabase/functions/scan/engine.ts";

const listen = (server) => new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${server.address().port}`)));
const close = (server) => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); });

async function complete(base, target, checks = CHECKS) {
  const response = await fetch(base + "/api/scans", { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ target_url: target, checks, authorized: true }) });
  assert.equal(response.status, 202, await response.clone().text());
  const started = await response.json();
  const deadline = Date.now() + 12_000;
  while (Date.now() < deadline) {
    const report = await (await fetch(base + "/api/scans/" + started.scan.id)).json();
    if (!["running", "queued"].includes(report.scan.status)) return report;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  assert.fail("The fixture scan did not finish");
}

test("scan, redacted evidence, complete coverage, and saved reports survive a restart", async () => {
  const secret = "sb_secret_" + "x".repeat(32);
  const target = createServer((req, res) => {
    if (req.url === "/app.js") return res.end(`const key = '${secret}';\n//# sourceMappingURL=/app.js.map`);
    if (req.url === "/app.js.map") return res.end(JSON.stringify({ version: 3, sources: ["app.ts"], sourcesContent: [null] }));
    res.end('<script src="/app.js"></script>');
  });
  const targetUrl = await listen(target);
  const directory = await mkdtemp(join(tmpdir(), "salus-reports-"));
  let server = await createLocalServer({ directory });
  let base = await listen(server);
  try {
    const report = await complete(base, targetUrl);
    assert.equal(report.scan.status, "done");
    assert.deepEqual(report.check_results.map((check) => check.check), CHECKS);
    const keys = report.findings.find((finding) => finding.check_key === "exposed-keys");
    assert.ok(keys.evidence.includes("********"));
    assert.ok(!JSON.stringify(report).includes(secret));
    const map = report.findings.find((finding) => finding.check_key === "source-maps");
    assert.equal(map.title, "Source map lists source filenames");
    const stored = JSON.parse(await readFile(join(directory, report.scan.id + ".json"), "utf8"));
    assert.deepEqual(stored, report);
    await close(server);
    server = await createLocalServer({ directory });
    base = await listen(server);
    const reopened = await (await fetch(base + "/api/scans/" + report.scan.id)).json();
    assert.deepEqual(reopened, report);
    assert.equal((await (await fetch(base + "/api/scans")).json()).length, 1);
  } finally { await close(server); await close(target); }
});

test("missing, external, oversized, and redirected resources cannot produce a clean scan", async () => {
  let outsideRequests = 0;
  const outside = createServer((_req, res) => { outsideRequests++; res.end("outside"); });
  const outsideUrl = await listen(outside);
  const target = createServer((req, res) => {
    if (req.url === "/missing.js") { res.writeHead(404); return res.end(); }
    if (req.url === "/big.js") return res.end("x".repeat(2_000_001));
    if (req.url === "/redirect.js") { res.writeHead(302, { location: outsideUrl }); return res.end(); }
    if (req.url === "/safe-redirect") { res.writeHead(302, { location: "/clean" }); return res.end(); }
    if (req.url === "/clean") return res.end("<p>A local page</p>");
    res.end(`<script src="/missing.js"></script><script src="/big.js"></script><script src="/redirect.js"></script><script src="${outsideUrl}/app.js"></script>`);
  });
  const targetUrl = await listen(target);
  const server = await createLocalServer({ directory: await mkdtemp(join(tmpdir(), "salus-coverage-")) });
  const base = await listen(server);
  try {
    const report = await complete(base, targetUrl, ["exposed-keys", "source-maps"]);
    assert.equal(report.scan.status, "partial");
    assert.ok(report.check_results.every((check) => check.state === "partial"));
    assert.match(report.check_results[0].reason, /404/);
    assert.match(report.check_results[0].reason, /2 MB/);
    assert.equal(outsideRequests, 0);
    const clean = await complete(base, targetUrl + "/safe-redirect", ["exposed-keys", "source-maps"]);
    assert.equal(clean.scan.status, "done");
    assert.ok(clean.check_results.every((check) => check.state === "clean"));
  } finally { await close(server); await close(target); await close(outside); }
});

test("local server denies cross-origin access, unexpected hosts, secrets, and unsupported scans", async () => {
  const server = await createLocalServer({ directory: await mkdtemp(join(tmpdir(), "salus-boundary-")) });
  const base = await listen(server);
  try {
    assert.equal((await fetch(base + "/", { headers: { "sec-fetch-site": "cross-site" } })).status, 200);
    assert.equal((await fetch(base + "/api/scans", { headers: { "sec-fetch-site": "cross-site" } })).status, 403);
    assert.equal((await fetch(base + "/api/scans", { headers: { origin: "https://outside.invalid" } })).status, 403);
    const hostStatus = await new Promise((resolve) => {
      request(base + "/api/health", { headers: { host: "outside.invalid" } }, (res) => { res.resume(); resolve(res.statusCode); }).end();
    });
    assert.equal(hostStatus, 403);
    const malformedStatus = await new Promise((resolve) => {
      request(base, { path: "//[", method: "GET" }, (res) => { res.resume(); resolve(res.statusCode); }).end();
    });
    assert.equal(malformedStatus, 400);
    assert.equal((await fetch(base + "/api/health")).status, 200);
    for (const path of ["/.git/config", "/.salus/reports", "/server.mjs", "/%2e%2e/package.json"]) {
      assert.equal((await fetch(base + path)).status, 404);
    }
    for (const input of [
      { target_url: "http://external.invalid", authorized: true, checks: ["headers"] },
      { target_url: "http://127.0.0.1:3000", authorized: false, checks: ["headers"] },
      { target_url: "http://127.0.0.1:3000", authorized: true, checks: ["backend-defaults"] },
    ]) {
      assert.equal((await fetch(base + "/api/scans", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(input) })).status, 400);
    }
  } finally { await close(server); }
});

test("an interrupted saved scan reopens as failed", async () => {
  const directory = await mkdtemp(join(tmpdir(), "salus-interrupted-"));
  const id = "00000000-0000-4000-8000-000000000000";
  await writeFile(join(directory, id + ".json"), JSON.stringify({
    scan: { id, status: "running" }, findings: [], check_results: [],
  }));
  const server = await createLocalServer({ directory });
  const base = await listen(server);
  try {
    const report = await (await fetch(base + "/api/scans/" + id)).json();
    assert.equal(report.scan.status, "failed");
    assert.match(report.scan.error, /stopped/);
    assert.equal(JSON.parse(await readFile(join(directory, id + ".json"), "utf8")).scan.status, "failed");
  } finally { await close(server); }
});

test("local target validation uses exact hosts and rejects credentials and non-HTTP schemes", () => {
  for (const url of ["http://localhost.evil.invalid", "http://127.0.0.1.evil.invalid", "file:///etc/passwd", "http://name:secret@localhost"]) {
    assert.throws(() => localTarget(url));
  }
  assert.equal(localTarget("http://localhost:3000").hostname, "127.0.0.1");
});

test("JWT role and CORS findings do not overstate the evidence", () => {
  const jwt = (payload) => [Buffer.from('{"alg":"HS256"}').toString("base64url"), Buffer.from(JSON.stringify(payload)).toString("base64url"), "x".repeat(20)].join(".");
  assert.deepEqual(detectSecrets(jwt({ role: "anon", note: "service_role" })), []);
  assert.equal(detectSecrets(jwt({ role: "service_role" }))[0].kind, "supabase_service_role");
  const cors = auditHeaders({ "access-control-allow-origin": "*", "access-control-allow-credentials": "true" }).find((issue) => issue.header === "access-control-allow-origin");
  assert.equal(cors.severity, "medium");
  assert.match(cors.issue, /block/);
});

test("document base URLs are honored and report URLs omit credentials", async () => {
  const secret = "sb_secret_" + "z".repeat(32);
  const visited = [];
  const target = createServer((req, res) => {
    visited.push(req.url);
    if (req.url.startsWith("/assets/app.js?")) return res.end(`const key = '${secret}';`);
    if (req.url.startsWith("/app.js")) return res.end("// wrong bundle");
    res.end(`<base href="/assets/"><script src="app.js?token=${secret}"></script>`);
  });
  const targetUrl = await listen(target);
  const directory = await mkdtemp(join(tmpdir(), "salus-urls-"));
  const server = await createLocalServer({ directory });
  const base = await listen(server);
  try {
    const report = await complete(base, targetUrl + "?token=" + secret, ["exposed-keys"]);
    assert.equal(report.check_results[0].state, "found");
    assert.ok(visited.includes("/assets/app.js?token=" + secret));
    assert.ok(!visited.some((url) => url.startsWith("/app.js")));
    assert.ok(!JSON.stringify(report).includes(secret));
    assert.ok(!(await readFile(join(directory, report.scan.id + ".json"), "utf8")).includes(secret));
  } finally { await close(server); await close(target); }
});

test("HTML-encoded resource URLs produce partial coverage", async () => {
  const target = createServer((req, res) => res.end('<script src="/app.js?a=1&amp;b=2"></script>'));
  const targetUrl = await listen(target);
  const server = await createLocalServer({ directory: await mkdtemp(join(tmpdir(), "salus-entities-")) });
  const base = await listen(server);
  try {
    const report = await complete(base, targetUrl + "/%FF", ["exposed-keys"]);
    assert.equal(report.scan.status, "partial");
    assert.equal(report.check_results[0].state, "partial");
    assert.match(report.check_results[0].reason, /HTML-encoded/);
  } finally { await close(server); await close(target); }
});
