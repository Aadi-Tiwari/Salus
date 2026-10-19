import { createServer } from "node:http";
import { mkdir, readFile, readdir, rename, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { CHECKS, localTarget, reportUrl, scan } from "./local/scan.mjs";

const root = dirname(fileURLToPath(import.meta.url));
const assets = new Set(["scanner.html", "app.html", "index.html", "signin.html", "auth.css", "fixes.js", "github.js", "navigation.js"]);
const idPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export async function createLocalServer({ directory = join(root, ".salus", "reports") } = {}) {
  await mkdir(directory, { recursive: true });
  const reports = new Map();
  const save = async (report) => {
    const path = join(directory, `${report.scan.id}.json`);
    await writeFile(path + ".tmp", JSON.stringify(report, null, 2));
    await rename(path + ".tmp", path);
  };
  for (const name of await readdir(directory)) {
    if (!name.endsWith(".json") || !idPattern.test(name.slice(0, -5))) continue;
    const report = JSON.parse(await readFile(join(directory, name), "utf8"));
    if (["queued", "running"].includes(report.scan.status)) {
      report.scan.status = "failed";
      report.scan.error = "The server stopped before this scan finished. Run a new scan.";
      await save(report);
    }
    reports.set(report.scan.id, report);
  }
  let busy = false;
  const server = createServer(async (request, response) => {
    const send = (status, value) => {
      response.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", "x-content-type-options": "nosniff" });
      response.end(JSON.stringify(value));
    };
    const port = server.address().port;
    const origins = [`http://127.0.0.1:${port}`, `http://localhost:${port}`];
    let url;
    try { url = new URL(request.url, origins[0]); }
    catch { return send(400, { error: "Invalid request URL" }); }
    if (!origins.includes(`http://${request.headers.host}`) ||
        (request.headers.origin && !origins.includes(request.headers.origin)) ||
        (request.headers["sec-fetch-site"] === "cross-site" && url.pathname.startsWith("/api/"))) return send(403, { error: "Local requests only" });
    try {
      if (request.method === "GET" && url.pathname === "/api/health") return send(200, { service: "salus-local", checks: CHECKS });
      if (request.method === "GET" && url.pathname === "/api/scans") {
        return send(200, [...reports.values()].map(({ scan }) => scan).reverse());
      }
      if (request.method === "GET" && url.pathname.startsWith("/api/scans/")) {
        const id = url.pathname.slice("/api/scans/".length);
        const report = idPattern.test(id) && reports.get(id);
        return report ? send(200, report) : send(404, { error: "Report not found" });
      }
      if (request.method === "POST" && url.pathname === "/api/scans") {
        if (busy) return send(409, { error: "A scan is already running. Wait for its report." });
        if (request.headers["content-type"]?.split(";")[0] !== "application/json") return send(415, { error: "Send JSON" });
        let body = "";
        for await (const chunk of request) {
          body += chunk.toString();
          if (body.length > 16_384) return send(413, { error: "Request is too large" });
        }
        let input, target;
        try {
          input = JSON.parse(body);
          target = localTarget(input.target_url);
        } catch { return send(400, { error: "Enter a local HTTP target without credentials." }); }
        if (input.authorized !== true) return send(400, { error: "Confirm that you own or may test this app." });
        if (!Array.isArray(input.checks) || !input.checks.length || input.checks.some((check) => !CHECKS.includes(check))) {
          return send(400, { error: "Select supported local checks" });
        }
        if (busy) return send(409, { error: "A scan is already running. Wait for its report." });
        const report = { scan: { id: randomUUID(), target_url: reportUrl(target.href), target_host: target.host,
          checks: [...new Set(input.checks)], status: "queued", authorized: true, created_at: new Date().toISOString() },
          findings: [], check_results: [] };
        busy = true;
        try { await save(report); }
        catch (error) { busy = false; throw error; }
        reports.set(report.scan.id, report);
        send(202, report);
        scan(report, () => save(report), target.href).catch(async () => {
          report.scan.status = "failed";
          report.scan.error = "The scan could not finish. Check the local server and retry.";
          await save(report);
        }).catch((error) => console.error("Could not save the scan report:", error.message))
          .finally(() => { busy = false; });
        return;
      }
      if (request.method !== "GET") return send(405, { error: "Method not supported" });
      if (url.pathname === "/config.js") {
        response.writeHead(200, { "content-type": "text/javascript", "cache-control": "no-store" });
        return response.end("window.SALUS_CONFIG = {}; window.SALUS_LOCAL = true;");
      }
      const name = url.pathname === "/" ? "scanner.html" : url.pathname.slice(1);
      if (!assets.has(name)) return send(404, { error: "Not found" });
      response.writeHead(200, { "content-type": name.endsWith(".js") ? "text/javascript" : name.endsWith(".css") ? "text/css" : "text/html; charset=utf-8",
        "cache-control": "no-store", "x-content-type-options": "nosniff" });
      response.end(await readFile(join(root, name)));
    } catch {
      if (!response.headersSent) send(500, { error: "Local storage or request processing failed" });
      else response.end();
    }
  });
  server.requestTimeout = 15_000;
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const server = await createLocalServer();
  server.listen(Number(process.env.PORT || 8787), "127.0.0.1", () => {
    console.log(`Salus: http://127.0.0.1:${server.address().port}`);
  });
}
