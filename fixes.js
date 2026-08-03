/* ---------------------------------------------------------------------------
   Salus fix generator.

   Turns a proven finding into concrete files. This is deliberately
   deterministic rather than a language model writing arbitrary code: every
   patch below is one Salus can state the effect of, and a reviewer can read
   the whole thing before merging. Where a flaw cannot be closed by a file
   change, the generator says so and emits a runbook instead of pretending.

   generateFix(finding) -> null | {
     key, title, summary, files:[{path, contents, why}], manual:[string],
     closes: boolean            // false when the files help but a human must finish
   }
--------------------------------------------------------------------------- */

const HEADERS = [
  ["Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"],
  ["X-Content-Type-Options", "nosniff"],
  ["Referrer-Policy", "strict-origin-when-cross-origin"],
  ["X-Frame-Options", "DENY"],
  ["Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"],
  ["Permissions-Policy", "camera=(), microphone=(), geolocation=()"],
];

/* The generator fingerprint decides which build file a fix belongs in. An
   unknown generator falls back to the host-level config, which works whatever
   the framework is. */
function stackOf(finding) {
  const g = (finding.generator || "").toLowerCase();
  if (g.includes("v0") || g.includes("vercel") || g.includes("next")) return "next";
  if (g.includes("bolt") || g.includes("vite") || g.includes("stackblitz")) return "vite";
  if (g.includes("lovable")) return "vite";
  return "host";
}

function headerFix(finding) {
  const stack = stackOf(finding);
  const files = [];

  if (stack === "next") {
    // Declared as a fragment rather than a whole file: the source-map fix also
    // lives in next.config, and two fixes writing the same path independently
    // would produce a file with two default exports.
    files.push({
      path: "next.config.mjs",
      why: "Next.js serves these on every route, so the browser gets them before any of your code runs.",
      merge: "next",
      part: "headers",
    });
  } else {
    files.push({
      path: "vercel.json",
      why: "Applied at the edge, so it covers static files and functions alike without touching app code.",
      contents:
JSON.stringify({
  $schema: "https://openapi.vercel.sh/vercel.json",
  headers: [{
    source: "/(.*)",
    headers: HEADERS.map(([key, value]) => ({ key, value })),
  }],
}, null, 2) + "\n",
    });
    files.push({
      path: "netlify.toml",
      why: "The same rules for a Netlify deploy. Delete whichever host you do not use.",
      contents:
`# Added by Salus.
[[headers]]
  for = "/*"
  [headers.values]
${HEADERS.map(([k, v]) => `    ${k} = ${JSON.stringify(v)}`).join("\n")}
`,
    });
  }

  return {
    key: "headers",
    title: "Add the missing security headers",
    summary: "Sets the six headers a browser relies on to refuse injected scripts, framing and MIME sniffing.",
    files,
    manual: [
      "The content security policy starts strict. If a third-party script or font is genuinely needed, add that origin rather than widening the policy to a wildcard.",
    ],
    closes: true,
  };
}

function sourceMapFix(finding) {
  const stack = stackOf(finding);
  if (stack === "next") {
    return {
      key: "source-maps",
      title: "Stop shipping source maps to production",
      summary: "Turns off production browser source maps, so the deployed bundle stops carrying your original code.",
      files: [{
        path: "next.config.mjs",
        why: "productionBrowserSourceMaps defaults to false, so an explicit false also documents the decision.",
        merge: "next",
        part: "sourcemaps",
      }],
      manual: [
        "Redeploy after merging. The maps already published stay reachable until the next deploy replaces them.",
      ],
      closes: true,
    };
  }
  return {
    key: "source-maps",
    title: "Stop shipping source maps to production",
    summary: "Turns the build's sourcemap output off, so the deployed bundle stops carrying your original code.",
    files: [{
      path: "vite.config.js",
      why: "build.sourcemap false keeps the maps on your machine and out of the deploy.",
      contents:
`// Added by Salus. A production build should not hand out its own source.
import { defineConfig } from "vite";

export default defineConfig({
  build: {
    sourcemap: false,
  },
});
`,
    }],
    manual: [
      "If you already have a vite.config file, merge the build.sourcemap line into it rather than replacing the file.",
      "Redeploy after merging. The maps already published stay reachable until the next deploy replaces them.",
    ],
    closes: true,
  };
}

function rlsFix(finding) {
  const stamp = "20260101000000";
  return {
    key: "backend-defaults",
    title: "Switch row-level security on and scope every row to its owner",
    summary: "A migration that enables RLS on your public tables and adds owner-only policies, so an anonymous caller stops receiving rows.",
    files: [{
      path: "supabase/migrations/" + stamp + "_salus_enable_rls.sql",
      why: "Runs as a migration so the change is reviewable, repeatable and versioned with the schema.",
      contents:
`-- Added by Salus.
--
-- Enabling row-level security with no policy denies everything, which is the
-- safe direction to fail. The owner policies below then hand each row back to
-- the account that owns it. Check the owner column name against your schema
-- before merging: this assumes user_id.

do $$
declare t record;
begin
  for t in
    select tablename
    from pg_tables
    where schemaname = 'public'
  loop
    execute format('alter table public.%I enable row level security', t.tablename);
  end loop;
end $$;

-- Owner-only access, per table. Repeat this block for each table that has a
-- user_id column, and delete it for any table that is genuinely public.
--
-- create policy "owner reads own rows" on public.your_table
--   for select using (auth.uid() = user_id);
-- create policy "owner writes own rows" on public.your_table
--   for insert with check (auth.uid() = user_id);
-- create policy "owner updates own rows" on public.your_table
--   for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
`,
    }],
    manual: [
      "Name the owner column your schema actually uses. This migration assumes user_id.",
      "Enabling RLS with no policy blocks reads your app may rely on. Add the owner policies for each table in the same merge, not afterwards.",
      "Run it against a branch database first and confirm your app still works before it reaches production.",
    ],
    closes: false,
  };
}

function adminRouteFix(finding) {
  const locator = (finding.locator || "").trim();
  const paths = locator ? locator.split(/[,\s]+/).filter(Boolean) : ["/admin", "/debug"];
  return {
    key: "admin-routes",
    title: "Put a session check in front of the admin and debug routes",
    summary: "Middleware that refuses the reachable admin paths unless a session is present, so the route stops answering strangers.",
    files: [{
      path: "middleware.ts",
      why: "Middleware runs before the route does, so the guard cannot be skipped by a page that forgot to check.",
      contents:
`// Added by Salus.
//
// The interface was guarding these paths; the routes behind it were not. This
// runs before the route, so a page that forgets its own check is still covered.
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

const GUARDED = [
${paths.map((p) => "  " + JSON.stringify(p) + ",").join("\n")}
];

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  if (!GUARDED.some((p) => pathname === p || pathname.startsWith(p + "/"))) {
    return NextResponse.next();
  }

  // Replace this with your own session lookup. Refusing by default is the
  // point: an unknown caller must not fall through to the route.
  const session = request.cookies.get("sb-access-token") || request.cookies.get("session");
  if (!session) {
    return new NextResponse("Not authorized", { status: 401 });
  }
  return NextResponse.next();
}

export const config = {
  matcher: [${paths.map((p) => JSON.stringify((p.endsWith("/") ? p.slice(0, -1) : p) + "/:path*")).join(", ")}],
};
`,
    }],
    manual: [
      "Swap the cookie check for whatever your app actually uses to prove a session.",
      "A signed-in visitor is not necessarily an admin. If these routes need a role, check the role here too.",
    ],
    closes: false,
  };
}

function exposedKeyFix(finding) {
  const locator = finding.locator || "the bundle";
  return {
    key: "exposed-keys",
    title: "Get the exposed key out of the bundle and rotate it",
    summary: "A key that shipped to the browser is already public. No file change can un-publish it, so this rotates it and stops the next one shipping.",
    files: [
      {
        path: ".env.example",
        why: "Names the variables without holding any value, so the real ones live only in your host's environment settings.",
        contents:
`# Added by Salus. Copy to .env.local and fill in from your host's dashboard.
# Never commit the filled-in copy.

# Safe to expose. Enforced by row-level security on the database side.
NEXT_PUBLIC_SUPABASE_URL=
NEXT_PUBLIC_SUPABASE_ANON_KEY=

# Server only. This one bypasses row-level security, so it must never appear
# in a NEXT_PUBLIC_ variable, in client code, or in this repository.
SUPABASE_SERVICE_ROLE_KEY=
`,
      },
      {
        path: "SALUS-ROTATE-KEYS.md",
        why: "The order matters. Rotating before the code stops reading the old value takes the app down.",
        contents:
`# Rotate the exposed key

Salus found a key served to the browser at \`${locator}\`. Anyone who loaded
your app already has it, so treat it as public from now on.

Do these in order.

1. **Issue a replacement first.** In the provider's dashboard, create the new
   key before revoking anything. Revoking first takes your app down.
2. **Put the new value in your host's environment settings.** Vercel, Netlify
   and Supabase all have a project-level settings page for this. Not in the
   repository.
3. **Stop the code reading the old one.** Any key that a browser needs must be
   safe to expose. Anything that is not safe to expose has to move behind a
   server route or an edge function.
4. **Redeploy, confirm the app works on the new key, then revoke the old one.**
5. **Check what the old key could reach.** If it was a service-role or admin
   key, assume the data it could read has been read, and work out what that
   means for the people in it.

## Why no code change is attached

Salus will not guess which call sites are safe to rewrite. Moving a key out of
the client changes where the work happens, and that is a decision about your
architecture rather than a mechanical edit.
`,
      },
    ],
    manual: [
      "Rotate the key. The patch does not do this, and the old key stays valid until you revoke it.",
      "If the exposed key was a service-role key, the database behind it should be treated as read.",
    ],
    closes: false,
  };
}

const GENERATORS = {
  "headers": headerFix,
  "source-maps": sourceMapFix,
  "backend-defaults": rlsFix,
  "admin-routes": adminRouteFix,
  "exposed-keys": exposedKeyFix,
};

/* Returns null when there is nothing to write. Fingerprint is context, not a
   flaw, and a finding with no evidence has not been proven, so patching
   against it would be acting on a guess. */
export function generateFix(finding) {
  if (!finding || finding.status === "pending" || finding.status === "running") return null;
  if (!finding.evidence) return null;
  const make = GENERATORS[finding.check_key];
  if (!make) return null;
  const fix = make(finding);
  fix.findingId = finding.id;
  fix.findingTitle = finding.title;
  fix.severity = finding.severity;
  return fix;
}

export function fixableFindings(findings) {
  return (findings || []).map(generateFix).filter(Boolean);
}

/* Renders next.config.mjs once, carrying whichever concerns were selected.
   Written here rather than in each fix so two fixes cannot both claim the
   file and produce something that will not parse. */
function renderNextConfig(parts) {
  const wantsHeaders = parts.has("headers");
  const wantsSourcemaps = parts.has("sourcemaps");
  const body = [];
  if (wantsSourcemaps) body.push("  productionBrowserSourceMaps: false,");
  if (wantsHeaders) {
    body.push("  async headers() {");
    body.push('    return [{ source: "/:path*", headers: securityHeaders }];');
    body.push("  },");
  }
  return (
`/** Added by Salus. */
${wantsHeaders ? `const securityHeaders = [
${HEADERS.map(([k, v]) => `  { key: ${JSON.stringify(k)}, value: ${JSON.stringify(v)} },`).join("\n")}
];

` : ""}export default {
${body.join("\n")}
};
`);
}

const MERGERS = { next: renderNextConfig };

/* The single source of truth for what a set of fixes writes. Both the patch
   and the pull request go through this, so the file you download and the file
   that lands in the branch are the same bytes. */
export function materialise(fixes) {
  const plain = new Map();
  const merged = new Map(); // path -> { kind, parts:Set }

  fixes.forEach((fix) => {
    fix.files.forEach((file) => {
      if (file.merge) {
        const entry = merged.get(file.path) || { kind: file.merge, parts: new Set() };
        entry.parts.add(file.part);
        merged.set(file.path, entry);
        return;
      }
      if (plain.has(file.path)) {
        plain.set(file.path, plain.get(file.path) + "\n" + file.contents);
      } else {
        plain.set(file.path, file.contents);
      }
    });
  });

  merged.forEach((entry, path) => {
    const render = MERGERS[entry.kind];
    if (render) plain.set(path, render(entry.parts));
  });

  return plain;
}

/* ------------------------------------------------------------ patch file ---
   A unified diff of new files, which `git apply` accepts directly. Written by
   hand rather than pulled from a library so the download stays dependency
   free and the output is readable before anyone applies it.
--------------------------------------------------------------------------- */
export function buildPatch(fixes, scan) {
  const when = new Date().toISOString();
  const head =
`From: Salus <noreply@salus.local>
Subject: [PATCH] Close ${fixes.length} finding${fixes.length === 1 ? "" : "s"} from the Salus scan of ${scan?.target_host || "your app"}

Generated ${when}.

Every hunk below creates a file. Apply with:

    git apply salus-fixes.patch

${fixes.map((f, i) => (i + 1) + ". " + f.title).join("\n")}

Read the notes at the end before merging. Some of these need a decision that a
patch cannot make for you.
---
`;

  const body = [...materialise(fixes)].map(([path, contents]) => {
    const lines = contents.replace(/\n$/, "").split("\n");
    return (
`diff --git a/${path} b/${path}
new file mode 100644
--- /dev/null
+++ b/${path}
@@ -0,0 +1,${lines.length} @@
${lines.map((l) => "+" + l).join("\n")}
`);
  }).join("");

  const notes = fixes
    .filter((f) => f.manual && f.manual.length)
    .map((f) => "## " + f.title + "\n" + f.manual.map((m) => "- " + m).join("\n"))
    .join("\n\n");

  return head + body + (notes ? "\n-- \nNotes\n\n" + notes + "\n" : "");
}

/* Files keyed by path, for the pull-request route. Same composer as the patch,
   so what you download and what lands in the branch are the same bytes. */
export function filesFor(fixes) {
  return materialise(fixes);
}
