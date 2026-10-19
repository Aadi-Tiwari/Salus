import { randomUUID } from "node:crypto";
import {
  auditHeaders, detectSecrets, extractScriptUrls, fingerprintGenerator, redactSecrets, secretLabel, sourceMapUrl,
} from "../supabase/functions/scan/engine.ts";

export const CHECKS = ["exposed-keys", "source-maps", "headers", "fingerprint"];
const MAX_BYTES = 2_000_000;
const MAX_SCRIPTS = 6;

export function localTarget(value) {
  const url = new URL(value);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password ||
      !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) {
    throw new Error("Use an HTTP URL on localhost, 127.0.0.1, or [::1], without credentials.");
  }
  if (url.hostname === "localhost") url.hostname = "127.0.0.1";
  url.hash = "";
  return url;
}

export function reportUrl(value) {
  const url = new URL(value);
  if (url.search) url.search = "redacted";
  url.hash = "";
  try { return redactSecrets(decodeURI(url.href)); }
  catch { return url.origin + "/[unreadable-path]" + url.search; }
}

function reader(origin) {
  let requests = 0;
  return async function read(value) {
    let url = localTarget(value);
    for (let redirects = 0; redirects <= 3; redirects++) {
      if (url.origin !== origin) throw new Error("Resource is outside the selected origin");
      if (++requests > 24) throw new Error("Scan request limit reached");
      const response = await fetch(url, {
        redirect: "manual", signal: AbortSignal.timeout(8000),
        headers: { "user-agent": "SalusLocal/1.0" },
      });
      if (response.status >= 300 && response.status < 400) {
        await response.body?.cancel();
        const location = response.headers.get("location");
        if (!location) throw new Error("Redirect has no destination");
        url = localTarget(new URL(location, url).href);
        continue;
      }
      if (!response.ok) {
        await response.body?.cancel();
        throw new Error(`Resource returned HTTP ${response.status}`);
      }
      const chunks = [];
      let size = 0;
      for await (const chunk of response.body || []) {
        size += chunk.byteLength;
        if (size > MAX_BYTES) throw new Error("Resource exceeds the 2 MB scan limit");
        chunks.push(chunk);
      }
      return { url: url.href, body: Buffer.concat(chunks).toString("utf8"), headers: Object.fromEntries(response.headers) };
    }
    throw new Error("Redirect limit reached");
  };
}

export async function scan(report, save, target = report.scan.target_url) {
  const read = reader(new URL(target).origin);
  const findings = report.findings;
  const add = (check, title, evidence, locator, severity = "medium", affected = 1) => {
    findings.push({ id: randomUUID(), check_key: check, title, evidence, locator: reportUrl(locator),
      severity, affected, status: "done", position: findings.length,
      blast: "Review the evidence in the context of your application before making changes.", steps: [] });
  };
  report.scan.status = "running";
  await save();
  let page;
  try {
    page = await read(target);
  } catch (error) {
    report.scan.status = "failed";
    report.scan.error = error.message;
    report.check_results = report.scan.checks.map((check) => ({ check, state: "blocked", reason: error.message, inspected: 0 }));
    report.scan.finished_at = new Date().toISOString();
    await save();
    return;
  }

  const scripts = [];
  const missed = [];
  if (report.scan.checks.some((check) => check !== "headers")) {
    const base = page.body.match(/<base\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/i);
    let scriptBase = page.url;
    if (base) {
      try { scriptBase = new URL(base[1] ?? base[2] ?? base[3], page.url).href; }
      catch { missed.push("Document base URL could not be resolved"); }
    }
    const urls = extractScriptUrls(page.body, scriptBase);
    if (/<(?:script|base)\b[^>]*&(?:#x[\da-f]+|#\d+|[a-z]+);/i.test(page.body)) missed.push("HTML-encoded resource URLs may not resolve; inspect those resources manually");
    if (/<script\b[^>]*\bsrc\s*=\s*["']?data:/i.test(page.body)) missed.push("Inline data scripts are not inspected");
    for (const url of urls.slice(0, MAX_SCRIPTS)) {
      try { scripts.push(await read(url)); }
      catch (error) { missed.push(error.message); }
    }
    if (urls.length > MAX_SCRIPTS) missed.push(`${urls.length - MAX_SCRIPTS} scripts exceeded the scan limit`);
  }

  for (const check of report.scan.checks) {
    const before = findings.length;
    const incomplete = check === "headers" ? [] : [...missed];
    let inspected = 1 + (check === "headers" ? 0 : scripts.length);
    if (check === "headers") {
      const issues = auditHeaders(page.headers, page.url.startsWith("https:"));
      if (issues.length) add(check, "Response header configuration", issues.map((issue) => `${issue.header}: ${issue.issue}`).join("\n"), page.url, "medium", issues.length);
    } else if (check === "fingerprint") {
      const fingerprint = fingerprintGenerator(page.body, page.headers, scripts.map((script) => script.url));
      if (fingerprint) add(check, `Possible ${fingerprint.name} fingerprint`, fingerprint.signals.join("\n"), page.url, "context");
    } else if (check === "exposed-keys") {
      for (const resource of [page, ...scripts]) {
        const hits = detectSecrets(resource.body);
        if (hits.length) add(check, "Possible exposed credentials", hits.map((hit) => `${secretLabel(hit.kind)}: ${hit.match}`).join("\n") + "\nPattern matches only. Credential validity was not tested.", resource.url, "high", hits.length);
      }
    } else if (check === "source-maps") {
      inspected = 0;
      for (const script of scripts) {
        if (/sourceMappingURL\s*=\s*data:/i.test(script.body)) {
          incomplete.push("Inline source maps are not inspected");
          continue;
        }
        const url = sourceMapUrl(script.body, script.url);
        if (!url) {
          if (/sourceMappingURL\s*=/.test(script.body)) incomplete.push("Source map URL could not be resolved");
          continue;
        }
        try {
          const resource = await read(url);
          const map = JSON.parse(resource.body);
          if (map.version !== 3 || !Array.isArray(map.sources)) throw new Error("Response is not a supported source map");
          inspected++;
          const content = Array.isArray(map.sourcesContent) && map.sourcesContent.some((value) => typeof value === "string" && value.trim());
          add(check, content ? "Source map includes original source text" : "Source map lists source filenames",
            content ? "The linked source map contains nonempty sourcesContent. Source text was not saved in this report."
              : "The linked source map exposes filenames, but no original source text was confirmed.",
            resource.url, content ? "medium" : "context", map.sources.length);
        } catch (error) { incomplete.push(error.message); }
      }
    }
    report.check_results.push({ check,
      state: incomplete.length ? "partial" : findings.length > before ? "found" : "clean",
      reason: incomplete.length ? [...new Set(incomplete)].join("; ") : "Completed within the documented local scan scope.",
      inspected,
    });
    await save();
  }
  report.scan.status = report.check_results.some((check) => check.state === "partial") ? "partial" : "done";
  report.scan.finished_at = new Date().toISOString();
  await save();
}
