# Salus

A local developer tool for inspecting a running web app, reviewing passive security findings, and keeping reports with the observed evidence.

The local Node server runs without accounts, provider keys, or installed dependencies. It shares the pure detection engine with the separate Supabase prototype. Findings distinguish observations from checks that could not finish. Reports are evidence to investigate, not a certification that a target is secure.

## Run a local scan

Use Node.js 22.17 or newer:

```sh
npm start
```

Open <http://127.0.0.1:8787>. Start the development app you want to inspect, enter its address such as `http://127.0.0.1:3000`, choose checks, and confirm that you own or may test it. Salus saves the result under `.salus/reports/`. Reopen it from the saved reports list, even after restarting the server. Set the `PORT` environment variable to change Salus's port.

The scanner accepts only `localhost`, `127.0.0.1`, and `[::1]` targets. Scripts and redirects must stay on the selected origin. It sends unauthenticated GET requests, inspects the page and up to six linked scripts, caps response bodies at 2 MB, and limits each scan to 24 requests. It does not crawl additional pages, run JavaScript, inspect dynamically loaded modules, test credential validity, or call discovered third-party backends. Linked external resources, failed downloads, inline source maps, and resource limits produce incomplete coverage rather than a clean result.

Available checks are credential patterns, linked source maps, response headers, and framework or hosting fingerprints. Source maps distinguish filenames from included source text. Each selected check retains a `clean`, `found`, `partial`, or `blocked` record. Clean means no matching issue within the inspected scope. Report data stays local; the existing interface may load its fonts from public CDNs.

The report's explanations and suggested patches are deterministic drafts. Download and review patches before applying them. Local mode cannot publish pull requests. Public-host scanning, authentication tests, repository ingestion, automatic fixes, and multi-user hosting are outside this release.

## Static interface preview

Use Python to serve the repository. Copy `config.example.js` to `config.js` first; the placeholder values are enough for a preview.

```sh
python -m http.server 8080 --bind 127.0.0.1
```

Open <http://127.0.0.1:8080/app.html> or <http://127.0.0.1:8080/scanner.html>. A plain file server provides only the interface preview. Use `npm start` for local scanning and saved reports.

## Configure a hosted instance

The hosted Supabase prototype is separate from the supported local workflow and has not been deployment-verified in this pass. See [SETUP.md](SETUP.md). `config.js` is ignored by Git and holds its Supabase URL, browser publishable key, and OAuth settings. The local server supplies its own configuration and does not read these credentials. Never place a secret or service-role key in browser code.

A publishable key is intended for client use; access still depends on database grants, row-level policies, and the user's session. Review and verify those controls on the deployed project. A local source review cannot establish its live authorization state.

## Source map

| Path | Responsibility |
| --- | --- |
| `server.mjs`, `local/scan.mjs` | Local API, scan boundaries, coverage, and report persistence |
| `index.html`, `app.html`, `scanner.html`, `signin.html` | Landing, dashboard, scan, and login interfaces |
| `navigation.js` | Same-origin login return-path validation |
| `schema.sql` | Scan records and row-level policy definitions |
| `supabase/functions/scan/` | Scan orchestration and detection engine |
| `fixes.js`, `github.js` | Client-side patch and repository helpers |

The server engine implements the available Tier 1 checks. Higher tiers remain unavailable. Repository helpers and proposed patches still require review; they are not proof that a remediation is correct.

## Checks

Use Node.js 22.17 or newer:

```sh
npm test
```

The dependency-free tests run actual scans against local fixtures, verify persisted reports across server restarts, and exercise incomplete coverage, URL boundaries, access restrictions, classification, and redaction. They do not exercise a deployed Edge Function, live row-level policies, OAuth, or external scan targets.

## License

Original project source is available under the [MIT License](LICENSE). Third-party dependencies, model weights, fonts, documents, and datasets retain their own licenses. This license does not grant rights to third-party assets.
