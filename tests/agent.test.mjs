import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { buildPatch, createAgentStore, runtimeStatus, validateFiles } from "../local/agent.mjs";
import { createLocalServer } from "../server.mjs";

test("source snapshots reject traversal, credentials, duplicate paths, binary content, and excess size", () => {
  for (const path of ["../server.js", "a/../../server.js", "C:/server.js", "src\\server.js", ".env.json", "node_modules/code.js", "secrets.json", "a:b.js"]) {
    assert.throws(() => validateFiles([{ path, content: "text" }]));
  }
  for (const content of ["\0", "x".repeat(262145), "const key = 'sb_secret_" + "x".repeat(32) + "';"]) {
    assert.throws(() => validateFiles([{ path: "server.js", content }]));
  }
  assert.throws(() => validateFiles([{ path: "server.js", content: "a" }, { path: "SERVER.js", content: "b" }]));
  const [file] = validateFiles([{ path: "src/server.js", content: "const title = 'Hello';" }]);
  assert.match(file.sha256, /^[0-9a-f]{64}$/);
});

test("patches apply to the original text snapshot and cannot introduce unattached paths or secrets", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "salus-patch-test-"));
  const files = validateFiles([{ path: "src/server.js", content: "const name = 'before';\n" }]);
  try {
    const patch = await buildPatch(files, { summary: "Rename", manual_steps: [], changes: [{ path: "src/server.js", content: "const name = 'after';\n", reason: "Test change" }] }, cwd);
    assert.match(patch, /^diff --git a\/src\/server.js b\/src\/server.js/m);
    assert.match(patch, /-const name = 'before';/);
    assert.match(patch, /\+const name = 'after';/);
    assert.equal(await readFile(join(cwd, "before/src/server.js"), "utf8"), files[0].content);
    await assert.rejects(buildPatch(files, { summary: "Invalid", manual_steps: [], changes: [{ path: "elsewhere.js", content: "x", reason: "" }] }, cwd), /unattached/);
    await assert.rejects(buildPatch([...files, { path: "other.js", content: "" }], { summary: "Ambiguous", manual_steps: [], changes: [
      { path: "src/server.js", content: files[0].content, reason: "unchanged" },
      { path: "src/server.js", content: "const name = 'changed';", reason: "changed" },
    ] }, cwd), /duplicate/);
    await assert.rejects(buildPatch(files, { summary: "Invalid", manual_steps: [], changes: [{ path: "src/server.js", content: "const token = 'sb_secret_" + "x".repeat(32) + "';", reason: "" }] }, cwd), /credential/);
  } finally { await rm(cwd, { recursive: true, force: true }); }
});

test("source manifests survive restart without exposing full source in lists, interrupted runs fail", async () => {
  const directory = await mkdtemp(join(tmpdir(), "salus-store-test-"));
  try {
    let store = await createAgentStore(directory);
    const source = await store.attach([{ path: "app.js", content: "const privateSource = true;" }]);
    assert.equal(source.files[0].content, undefined);
    const id = "00000000-0000-4000-8000-000000000001";
    await writeFile(join(directory, "runs", id + ".json"), JSON.stringify({ id, status: "running", events: [] }));
    store = await createAgentStore(directory);
    assert.equal(store.listSources()[0].id, source.id);
    assert.equal(store.getRun(id).status, "failed");
    await assert.rejects(store.start({ source_id: source.id, consent: false }, null), /consent/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("an unavailable executable and a nonzero runtime exit remain failures without a patch", async () => {
  const directory = await mkdtemp(join(tmpdir(), "salus-runtime-test-"));
  const previous = process.env.SALUS_CODEX_BIN;
  try {
    process.env.SALUS_CODEX_BIN = join(directory, "missing-runtime.exe");
    assert.equal((await runtimeStatus()).available, false);
    // Node rejects Codex flags; this exercises a real child-process failure without model inference.
    process.env.SALUS_CODEX_BIN = process.execPath;
    const store = await createAgentStore(directory);
    const source = await store.attach([{ path: "app.js", content: "const value = 1;" }]);
    const report = { scan: { id: "scan", status: "done" }, findings: [{ id: "finding", evidence: "Missing header" }] };
    const input = { source_id: source.id, consent: true, finding_ids: ["finding"] };
    const run = await store.start(input, report);
    await assert.rejects(store.start(input, report), /already in progress/);
    const deadline = Date.now() + 10_000;
    while (["queued", "running"].includes(store.getRun(run.id).status) && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(store.getRun(run.id).status, "failed");
    assert.notEqual(store.getRun(run.id).exit_code, 0);
    assert.equal(store.getRun(run.id).patch, undefined);
    // Let the completed run finish its atomic disk write before cleanup.
    let saved;
    while (Date.now() < deadline) {
      saved = JSON.parse(await readFile(join(directory, "runs", run.id + ".json"), "utf8"));
      if (saved.status === "failed") break;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.equal(saved.status, "failed");
  } finally {
    if (previous === undefined) delete process.env.SALUS_CODEX_BIN;
    else process.env.SALUS_CODEX_BIN = previous;
    await rm(directory, { recursive: true, force: true });
  }
});

test("landing, console, reports, guide, scanner, and their local assets are served without missing links", async () => {
  const directory = await mkdtemp(join(tmpdir(), "salus-pages-test-"));
  const server = await createLocalServer({ directory });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    for (const page of ["/", "/index.html", "/app.html", "/reports.html", "/docs.html", "/scanner.html", "/signin.html"]) {
      const response = await fetch(base + page);
      assert.equal(response.status, 200, page);
      assert.equal(response.headers.get("x-frame-options"), "DENY");
      assert.equal(response.headers.get("content-security-policy"), "frame-ancestors 'none'");
      const html = await response.text();
      if (page === "/") assert.match(html, /Find the evidence/);
      const paths = [...html.matchAll(/(?:href|src)="(\/[^"?#]*)(?:[?#][^"]*)?"/g)].map((match) => match[1]);
      for (const path of new Set(paths)) assert.equal((await fetch(base + path)).status, 200, `${page} -> ${path}`);
    }
    const response = await fetch(base + "/api/sources", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ files: [{ path: "app.js", content: "const value = 1;" }] }) });
    assert.equal(response.status, 201);
    assert.equal((await (await fetch(base + "/api/sources")).json()).length, 1);
    assert.equal((await fetch(base + "/api/sources", { method: "POST", headers: { origin: "https://outside.invalid", "content-type": "application/json" }, body: "{}" })).status, 403);
    assert.equal((await fetch(base + "/api/runs", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" })).status, 400);
  } finally {
    await new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); });
    await rm(directory, { recursive: true, force: true });
  }
});
