import assert from "node:assert/strict";
import { test } from "node:test";
import { safeReturnPath } from "../navigation.js";
import { detectSecrets, redact } from "../supabase/functions/scan/engine.ts";

test("login keeps same-origin paths and query parameters", () => {
  assert.equal(safeReturnPath("/scanner.html?scan=example#report", "https://app.example"), "/scanner.html?scan=example#report");
});

test("login rejects scheme-relative and backslash redirects", () => {
  for (const path of ["//outside.example", "/\\outside.example", "https://outside.example", "javascript:alert(1)", null]) {
    assert.equal(safeReturnPath(path, "https://app.example"), "/app.html");
  }
});

test("publishable keys are not reported as privileged secrets", () => {
  const publishable = "sb_publishable_" + "x".repeat(32);
  assert.deepEqual(detectSecrets(publishable), []);
});

test("normalized return paths cannot become an external URL when parsed again", () => {
  const origin = "https://app.example";
  for (const path of ["/.//outside.example", "/a/..//outside.example", "/%2e//outside.example", "/%2e%2e//outside.example"]) {
    const destination = safeReturnPath(path, origin);
    assert.equal(destination, "/app.html");
    assert.equal(new URL(destination, origin).origin, origin);
  }
});

test("redaction removes the body of a detected credential", () => {
  const secret = "sb_secret_" + "x".repeat(32);
  const hits = detectSecrets(secret);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].kind, "supabase_secret_key");
  assert.ok(!redact(secret).includes("x".repeat(10)));
});
