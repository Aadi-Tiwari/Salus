/* ---------------------------------------------------------------------------
   Opening a pull request with the GitHub token the console already holds.

   Salus never pushes to a default branch. Every run creates its own branch,
   writes the files there, and opens a pull request, so nothing lands until a
   human merges it. That is the whole promise the landing page makes, so it is
   enforced here rather than left to a convention.
--------------------------------------------------------------------------- */

const API = "https://api.github.com";

async function gh(token, path, init = {}) {
  const res = await fetch(API + path, {
    ...init,
    headers: {
      Authorization: "Bearer " + token,
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json",
      ...(init.headers || {}),
    },
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = body.message || res.statusText;
    const err = new Error(detail);
    err.status = res.status;
    throw err;
  }
  return body;
}

/* Accepts github.com/owner/repo, the bare owner/repo, or a clone URL. */
export function parseRepo(input) {
  if (!input) return null;
  let s = String(input).trim().replace(/\.git$/, "");
  s = s.replace(/^https?:\/\//, "").replace(/^git@github\.com:/, "").replace(/^github\.com\//, "");
  const parts = s.split("/").filter(Boolean);
  if (parts.length < 2) return null;
  return { owner: parts[0], repo: parts[1] };
}

/* base64 that survives non-ASCII. btoa alone throws on anything above U+00FF,
   and these files carry typographic quotes. */
function toBase64(text) {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  bytes.forEach((b) => { binary += String.fromCharCode(b); });
  return btoa(binary);
}

/**
 * files: Map<path, contents>
 * onStep: (message) => void, so the page can show progress as it happens
 * Returns the pull request URL.
 */
export async function openPullRequest({ token, repo, files, title, body, onStep }) {
  const target = parseRepo(repo);
  if (!target) throw new Error("That does not look like a GitHub repository.");
  if (!token) throw new Error("No GitHub token is held. Sign in with GitHub again from the console.");
  if (!files || !files.size) throw new Error("There are no files to commit.");

  const say = onStep || (() => {});
  const slug = target.owner + "/" + target.repo;

  say("Reading " + slug);
  const info = await gh(token, "/repos/" + slug);
  if (info.archived) throw new Error("That repository is archived, so it cannot take a pull request.");
  if (!info.permissions || !info.permissions.push) {
    throw new Error("This token cannot push to " + slug + ". It needs repo scope on an account with write access.");
  }
  const base = info.default_branch;

  say("Branching from " + base);
  const baseRef = await gh(token, "/repos/" + slug + "/git/ref/heads/" + encodeURIComponent(base));
  const baseSha = baseRef.object.sha;

  // A timestamp keeps a second run from colliding with the first.
  const branch = "salus/fixes-" + new Date().toISOString().replace(/[-:T.]/g, "").slice(0, 14);
  await gh(token, "/repos/" + slug + "/git/refs", {
    method: "POST",
    body: JSON.stringify({ ref: "refs/heads/" + branch, sha: baseSha }),
  });

  /* Contents API, one file at a time. A tree would be fewer calls, but this
     way a failure halfway through leaves a branch holding the files that did
     land, which is far easier to reason about than a half-built tree. */
  let n = 0;
  for (const [path, contents] of files) {
    n++;
    say("Writing " + path + " (" + n + " of " + files.size + ")");

    // An existing file needs its blob sha, or the write is rejected.
    let sha;
    try {
      const existing = await gh(token, "/repos/" + slug + "/contents/" + encodeURI(path) + "?ref=" + encodeURIComponent(branch));
      sha = existing.sha;
    } catch (err) {
      if (err.status !== 404) throw err;
    }

    await gh(token, "/repos/" + slug + "/contents/" + encodeURI(path), {
      method: "PUT",
      body: JSON.stringify({
        message: "Salus: " + path,
        content: toBase64(contents),
        branch,
        ...(sha ? { sha } : {}),
      }),
    });
  }

  say("Opening the pull request");
  const pr = await gh(token, "/repos/" + slug + "/pulls", {
    method: "POST",
    body: JSON.stringify({ title, body, head: branch, base }),
  });

  say("Opened #" + pr.number);
  return { url: pr.html_url, number: pr.number, branch, base };
}

export function pullRequestBody(fixes, scan) {
  const lines = [
    "Opened by Salus from the scan of `" + (scan?.target_url || "your app") + "`.",
    "",
    "Nothing here has been applied to your app. Read it, change what you disagree with, merge when you are happy.",
    "",
    "## What this changes",
    "",
  ];
  fixes.forEach((fix) => {
    lines.push("### " + fix.title);
    lines.push("");
    lines.push(fix.summary);
    lines.push("");
    fix.files.forEach((f) => lines.push("- `" + f.path + "` " + f.why));
    lines.push("");
    if (fix.manual && fix.manual.length) {
      lines.push("Before merging:");
      fix.manual.forEach((m) => lines.push("- " + m));
      lines.push("");
    }
  });
  const open = fixes.filter((f) => !f.closes);
  if (open.length) {
    lines.push("## These do not close on their own");
    lines.push("");
    open.forEach((f) => lines.push("- **" + f.title + "** needs the steps above finished by hand."));
    lines.push("");
  }
  return lines.join("\n");
}
