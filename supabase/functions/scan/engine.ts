// Tier 1 check logic. Pure string work only: no fetch, no Deno globals, no
// imports, so the same functions run under a plain Node test runner.

export type SecretKind =
  | "supabase_service_role"
  | "supabase_secret_key"
  | "aws_access_key_id"
  | "google_api_key"
  | "stripe_live_key"
  | "openai_key"
  | "github_token"
  | "postgres_url"
  | "private_key";

export interface SecretHit {
  kind: SecretKind;
  match: string;
  index: number;
}

export interface Fingerprint {
  name: string;
  confidence: number;
  signals: string[];
}

export interface HeaderIssue {
  header: string;
  issue: string;
  severity: "high" | "medium";
}

export interface BackendRefs {
  supabaseUrl: string | null;
  supabaseKey: string | null;
  firebaseDbUrl: string | null;
}

export interface BackendProbe {
  kind: "supabase" | "firebase";
  label: string;
  url: string;
  headers: Record<string, string>;
}

export const SECRET_LABELS: Record<SecretKind, string> = {
  supabase_service_role: "Supabase service_role key",
  supabase_secret_key: "Supabase secret key",
  aws_access_key_id: "AWS access key id",
  google_api_key: "Google API key",
  stripe_live_key: "Stripe live secret key",
  openai_key: "OpenAI API key",
  github_token: "GitHub token",
  postgres_url: "Postgres connection string with a password",
  private_key: "Private key file",
};

// Breach is reserved for a key that reads or writes the app's own data or
// money on its own. A key that still needs a second half, or that is normally
// domain restricted, is high instead.
const BREACH_KINDS: SecretKind[] = [
  "supabase_service_role",
  "supabase_secret_key",
  "postgres_url",
  "private_key",
  "stripe_live_key",
];

const MASK = "********";

const SECRET_PATTERNS: Array<{ kind: SecretKind; re: RegExp }> = [
  { kind: "supabase_secret_key", re: /sb_secret_[A-Za-z0-9_-]{16,}/g },
  { kind: "aws_access_key_id", re: /AKIA[0-9A-Z]{16}/g },
  { kind: "google_api_key", re: /AIza[0-9A-Za-z\-_]{35}/g },
  { kind: "stripe_live_key", re: /sk_live_[A-Za-z0-9]{16,}/g },
  { kind: "openai_key", re: /sk-[A-Za-z0-9_-]{40,}/g },
  { kind: "github_token", re: /gh[pos]_[A-Za-z0-9]{36,}/g },
  {
    kind: "postgres_url",
    re: /postgres(?:ql)?:\/\/[^\s:@/"'`]+:[^\s:@/"'`]+@[^\s/"'`]+/g,
  },
  {
    kind: "private_key",
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
  },
];

const JWT_RE = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;

export function redact(value: string): string {
  if (value.length <= 12) return MASK;
  return value.slice(0, 6) + MASK + value.slice(-4);
}

export function decodeJwtPayload(token: string): string | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  try {
    return atob(padded);
  } catch {
    return null;
  }
}

export function detectSecrets(source: string): SecretHit[] {
  const hits: SecretHit[] = [];
  const seen: string[] = [];

  const push = (kind: SecretKind, raw: string, index: number) => {
    if (seen.indexOf(raw) !== -1) return;
    seen.push(raw);
    hits.push({ kind, match: redact(raw), index });
  };

  for (const { kind, re } of SECRET_PATTERNS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(source)) !== null) push(kind, m[0], m.index);
  }

  JWT_RE.lastIndex = 0;
  let jwt: RegExpExecArray | null;
  while ((jwt = JWT_RE.exec(source)) !== null) {
    const payload = decodeJwtPayload(jwt[0]);
    if (payload && payload.indexOf("service_role") !== -1) {
      push("supabase_service_role", jwt[0], jwt.index);
    }
  }

  return hits.sort((a, b) => a.index - b.index);
}

export function classifySecret(kind: SecretKind): "breach" | "high" {
  return BREACH_KINDS.indexOf(kind) === -1 ? "high" : "breach";
}

export function secretLabel(kind: SecretKind): string {
  return SECRET_LABELS[kind] || kind;
}

export function lowerKeys(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const key of Object.keys(headers || {})) {
    out[key.toLowerCase()] = String(headers[key] ?? "");
  }
  return out;
}

export function metaGenerator(html: string): string {
  const named = /<meta[^>]*\bname\s*=\s*["']generator["'][^>]*>/i.exec(html);
  if (!named) return "";
  const content = /\bcontent\s*=\s*["']([^"']*)["']/i.exec(named[0]);
  return content ? content[1].toLowerCase() : "";
}

type SignalSource = "generator" | "html" | "script" | string;

const GENERATOR_RULES: Array<{
  name: string;
  host: boolean;
  signals: Array<{ label: string; source: SignalSource; pattern: RegExp }>;
}> = [
  {
    name: "Lovable",
    host: false,
    signals: [
      { label: "generator meta tag names Lovable", source: "generator", pattern: /lovable/ },
      { label: "page loads the gptengineer script", source: "html", pattern: /gpteng\.co\/gptengineer/i },
      { label: "open graph image points at lovable.dev", source: "html", pattern: /lovable\.dev\/opengraph/i },
      { label: "bundles are served from a lovable.app host", source: "script", pattern: /\.lovable\.app\//i },
      { label: "gptengineer bundle in the script list", source: "script", pattern: /gptengineer/i },
    ],
  },
  {
    name: "Bolt",
    host: false,
    signals: [
      { label: "generator meta tag names Bolt", source: "generator", pattern: /bolt/ },
      { label: "page references bolt.new", source: "html", pattern: /bolt\.new/i },
      { label: "StackBlitz WebContainer runtime in the markup", source: "html", pattern: /webcontainer|stackblitz/i },
      { label: "bundles are served from a bolt host", source: "script", pattern: /bolt\.(new|host)\//i },
    ],
  },
  {
    name: "v0",
    host: false,
    signals: [
      { label: "generator meta tag names v0", source: "generator", pattern: /\bv0\b/ },
      { label: "page references v0.dev", source: "html", pattern: /v0\.dev/i },
      { label: "deployment host follows the v0 naming pattern", source: "html", pattern: /https?:\/\/v0-[a-z0-9-]+\.vercel\.app/i },
    ],
  },
  {
    name: "Replit",
    host: false,
    signals: [
      { label: "generator meta tag names Replit", source: "generator", pattern: /replit/ },
      { label: "page references a Replit host", source: "html", pattern: /replit\.(com|dev)|\.repl\.co/i },
      { label: "Replit dev banner script in the markup", source: "html", pattern: /replit-dev-banner|__replco/i },
      { label: "Replit cluster header on the response", source: "header:x-replit-cluster", pattern: /.+/ },
    ],
  },
  {
    name: "Cursor",
    host: false,
    signals: [
      { label: "generator meta tag names Cursor", source: "generator", pattern: /cursor/ },
      { label: "page references cursor.com tooling", source: "html", pattern: /cursor\.(com|sh)\/[a-z]/i },
    ],
  },
  {
    name: "Base44",
    host: false,
    signals: [
      { label: "generator meta tag names Base44", source: "generator", pattern: /base44/ },
      { label: "page references a base44 host", source: "html", pattern: /base44\.(app|com)/i },
      { label: "bundles are served from a base44 host", source: "script", pattern: /base44\.(app|com)\//i },
      { label: "base44 SDK in the script list", source: "script", pattern: /base44-sdk|@base44/i },
    ],
  },
  {
    name: "Vercel",
    host: true,
    signals: [
      { label: "x-vercel-id response header", source: "header:x-vercel-id", pattern: /.+/ },
      { label: "server header reports Vercel", source: "header:server", pattern: /vercel/i },
      { label: "assets served from a vercel.app host", source: "script", pattern: /\.vercel\.app\//i },
    ],
  },
  {
    name: "Netlify",
    host: true,
    signals: [
      { label: "x-nf-request-id response header", source: "header:x-nf-request-id", pattern: /.+/ },
      { label: "server header reports Netlify", source: "header:server", pattern: /netlify/i },
      { label: "assets served from a netlify.app host", source: "script", pattern: /\.netlify\.app\//i },
    ],
  },
];

export function fingerprintGenerator(
  html: string,
  headers: Record<string, string>,
  scriptUrls: string[],
): Fingerprint | null {
  const h = lowerKeys(headers);
  const generator = metaGenerator(html);
  const scripts = (scriptUrls || []).join(" ");

  const matches: Array<{ name: string; host: boolean; signals: string[] }> = [];

  for (const rule of GENERATOR_RULES) {
    const signals: string[] = [];
    for (const signal of rule.signals) {
      let hay = "";
      if (signal.source === "generator") hay = generator;
      else if (signal.source === "html") hay = html || "";
      else if (signal.source === "script") hay = scripts;
      else hay = h[signal.source.slice(7)] || "";
      if (hay && signal.pattern.test(hay)) signals.push(signal.label);
    }
    if (signals.length) matches.push({ name: rule.name, host: rule.host, signals });
  }

  if (!matches.length) return null;

  // A builder answers the question the check asks. Vercel and Netlify only say
  // where it is hosted, so they win only when no builder matched.
  const builders = matches.filter((m) => !m.host);
  const pool = builders.length ? builders : matches;
  pool.sort((a, b) => b.signals.length - a.signals.length);
  const best = pool[0];

  return {
    name: best.name,
    confidence: Math.min(0.95, 0.5 + 0.15 * best.signals.length),
    signals: best.signals,
  };
}

export function auditHeaders(
  headers: Record<string, string>,
  isHttps = true,
): HeaderIssue[] {
  const h = lowerKeys(headers);
  const issues: HeaderIssue[] = [];
  const csp = h["content-security-policy"] || "";

  if (!csp) {
    issues.push({
      header: "content-security-policy",
      issue: "No content security policy is set, so the browser will run any script that reaches the page.",
      severity: "medium",
    });
  } else if (/default-src\s+\*/i.test(csp) || /'unsafe-inline'|'unsafe-eval'/i.test(csp)) {
    issues.push({
      header: "content-security-policy",
      issue: "The policy allows inline or evaluated script, which is most of what a policy is meant to stop.",
      severity: "medium",
    });
  }

  if (
    (h["access-control-allow-origin"] || "").trim() === "*" &&
    (h["access-control-allow-credentials"] || "").trim().toLowerCase() === "true"
  ) {
    issues.push({
      header: "access-control-allow-origin",
      issue: "Any origin is allowed to send credentialed requests, so another site can read logged in responses.",
      severity: "high",
    });
  }

  if ((h["x-content-type-options"] || "").trim().toLowerCase() !== "nosniff") {
    issues.push({
      header: "x-content-type-options",
      issue: "Missing nosniff, so a browser may guess a file is script when it is not.",
      severity: "medium",
    });
  }

  if (isHttps && !h["strict-transport-security"]) {
    issues.push({
      header: "strict-transport-security",
      issue: "No HSTS, so a first visit can be pushed back to plain http.",
      severity: "medium",
    });
  }

  if (!h["x-frame-options"] && !/frame-ancestors/i.test(csp)) {
    issues.push({
      header: "x-frame-options",
      issue: "Nothing stops another site framing your app and collecting the clicks meant for you.",
      severity: "medium",
    });
  }

  return issues;
}

export function extractScriptUrls(html: string, baseUrl: string): string[] {
  const re = /<script\b[^>]*\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s"'=<>`]+))/gi;
  const out: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(html || "")) !== null) {
    const raw = (m[1] || m[2] || m[3] || "").trim();
    if (!raw || raw.slice(0, 5).toLowerCase() === "data:") continue;
    try {
      const abs = new URL(raw, baseUrl).toString();
      if (out.indexOf(abs) === -1) out.push(abs);
    } catch {
      // An src that will not resolve is not something the browser fetched
      // either, so there is nothing to scan.
    }
  }
  return out;
}

export function sourceMapUrl(bundleSource: string, bundleUrl: string): string | null {
  const re = /[#@]\s*sourceMappingURL\s*=\s*([^\s'"*]+)/g;
  let last: string | null = null;
  let m: RegExpExecArray | null;
  while ((m = re.exec(bundleSource || "")) !== null) last = m[1];
  if (!last) return null;
  // An inline data: map is already in the bundle, so there is no second file
  // to prove reachable.
  if (last.slice(0, 5).toLowerCase() === "data:") return null;
  try {
    return new URL(last, bundleUrl).toString();
  } catch {
    return null;
  }
}

// Fixed list, checked once each. No fuzzing and no guessed variations.
export const ADMIN_ROUTES: string[] = [
  "/admin",
  "/admin/login",
  "/api/admin",
  "/api/debug",
  "/debug",
  "/__debug",
  "/.env",
  "/.env.local",
  "/api/seed",
  "/api/users",
  "/api/config",
  "/api/keys",
  "/graphql",
  "/.git/config",
  "/backup.sql",
];

// The schema listing comes first: it names every table the API exposes, which
// is stronger proof than any single table guess.
export const SUPABASE_PROBES: string[] = [
  "/rest/v1/",
  "/rest/v1/profiles?select=*&limit=1",
  "/rest/v1/users?select=*&limit=1",
  "/rest/v1/customers?select=*&limit=1",
  "/rest/v1/orders?select=*&limit=1",
  "/rest/v1/messages?select=*&limit=1",
  "/rest/v1/subscriptions?select=*&limit=1",
  "/rest/v1/leads?select=*&limit=1",
];

// text is any page or bundle body worth searching. The project URL is usually
// in the markup, the publishable key usually in a bundle.
export function findBackendRefs(text: string, scriptUrls: string[]): BackendRefs {
  const hay = (text || "") + " " + (scriptUrls || []).join(" ");

  const supa = /https?:\/\/([a-z0-9]{16,40})\.supabase\.co/i.exec(hay);
  const fire = /https?:\/\/[a-z0-9-]+\.(?:firebaseio\.com|[a-z0-9-]+\.firebasedatabase\.app)/i.exec(hay);

  let key: string | null = null;
  const publishable = /sb_publishable_[A-Za-z0-9_-]{16,}/.exec(hay);
  if (publishable) key = publishable[0];
  if (!key) {
    JWT_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = JWT_RE.exec(hay)) !== null) {
      const payload = decodeJwtPayload(m[0]);
      if (payload && payload.indexOf('"anon"') !== -1) {
        key = m[0];
        break;
      }
    }
  }

  return {
    supabaseUrl: supa ? "https://" + supa[1] + ".supabase.co" : null,
    supabaseKey: key,
    firebaseDbUrl: fire ? fire[0].replace(/\/$/, "") : null,
  };
}

export function buildBackendProbes(html: string, scriptUrls: string[]): BackendProbe[] {
  const refs = findBackendRefs(html, scriptUrls);
  const probes: BackendProbe[] = [];

  if (refs.supabaseUrl && refs.supabaseKey) {
    for (const path of SUPABASE_PROBES) {
      probes.push({
        kind: "supabase",
        label: path,
        url: refs.supabaseUrl + path,
        headers: { apikey: refs.supabaseKey, authorization: "Bearer " + refs.supabaseKey },
      });
    }
  }

  if (refs.firebaseDbUrl) {
    probes.push({
      kind: "firebase",
      label: "/.json?shallow=true",
      url: refs.firebaseDbUrl + "/.json?shallow=true",
      headers: {},
    });
  }

  return probes;
}
