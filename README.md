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

Available checks are credential patterns, linked source maps, response headers, and framework or hosting fingerprints. Source maps distinguish filenames from included source text. Each selected check retains a `clean`, `found`, `partial`, or `blocked` record. Clean means no matching issue within the inspected scope. Scanning stores reports locally; optional agent runs send selected source and redacted findings through your Codex account. The interface loads fonts from public CDNs.

The report explanations read from recorded evidence. Public-host scanning, authentication tests, whole-repository ingestion, automatic application of fixes, and multi-user hosting are outside this release.

## Draft a remediation with Codex

Install Codex CLI separately and run `codex login`. Git must be available on PATH. Salus reuses the installed CLI and its authentication; it does not require a separate API key. Account limits and provider terms still apply. If executable discovery fails, set `SALUS_CODEX_BIN` to the native Codex executable path before starting Salus.

Open the console, attach the source files relevant to a finding, and confirm each path relative to your project's root. Attach up to 20 text files totaling 256 KiB. Snapshots retain full source text and SHA-256 hashes under the ignored `.salus/reports/sources/` directory. Remove secrets and private data first; pattern checks cannot identify every credential.

Choose a finished scan, findings with evidence, and a snapshot. Explicitly consent to sharing them for model inference, then run the agent. Salus invokes Codex directly with user configuration and project instructions excluded, tools disabled, a read-only sandbox, and a structured-output schema. Runs have a three-minute process limit and bounded output. It records actual runtime events and exit status, with no simulated progress or canned fallback. Only attached paths can appear in a replacement draft.

Salus creates a patch from the returned replacements and runs `git apply --check` against a disposable copy of the attached source. This verifies applicability, not application behavior. Review the patch and manual steps, check it against your current files, and apply it yourself. Run your application's tests and restart its server, then scan again and compare the reports. Salus does not execute generated commands, modify your project, or publish pull requests.

Saved runs and patches live under `.salus/reports/runs/`. Interrupted runs reopen as failed. Stop Salus before deleting `.salus` to clear local reports, source snapshots, and run records.

## Static interface preview

Use Python to serve the repository. Copy `config.example.js` to `config.js` first; the placeholder values are enough for a preview.

```sh
python -m http.server 8080 --bind 127.0.0.1
```

Open <http://127.0.0.1:8080/> for the landing page. A plain file server provides only an interface preview. Use `npm start` for scanning, saved reports, and agents.

## Configure a hosted instance

The hosted Supabase prototype is separate from the supported local workflow and has not been deployment-verified in this pass. See [SETUP.md](SETUP.md). `config.js` is ignored by Git and holds its Supabase URL, browser publishable key, and OAuth settings. The local server supplies its own configuration and does not read these credentials. Never place a secret or service-role key in browser code.

A publishable key is intended for client use; access still depends on database grants, row-level policies, and the user's session. Review and verify those controls on the deployed project. A local source review cannot establish its live authorization state.

## Source map

| Path | Responsibility |
| --- | --- |
| `server.mjs`, `local/scan.mjs` | Local API, scan boundaries, coverage, and report persistence |
| `index.html`, `app.html`, `scanner.html`, `reports.html`, `docs.html` | Landing, agent console, scanner, report comparison, and guide |
| `product.js`, `product.css`, `auth.css` | Local interface behavior and shared styling |
| `local/agent.mjs` | Source snapshots, actual Codex execution, and validated draft patches |
| `navigation.js` | Same-origin login return-path validation |
| `schema.sql` | Scan records and row-level policy definitions |
| `supabase/functions/scan/` | Scan orchestration and detection engine |
| `signin.html`, `fixes.js`, `github.js` | Legacy hosted prototype files, unused by the local agent workflow |

The local server serves only its public page and asset allowlist. It binds to loopback, rejects foreign API origins and hosts, and prevents framing of its pages. It is a trusted single-user tool, not a security boundary between local users.

## Checks

Use Node.js 22.17 or newer:

```sh
npm test
```

The dependency-free tests run actual scans against local fixtures and cover persistence, incomplete coverage, URL boundaries, access restrictions, redaction, source validation, patch applicability, interrupted runs, and page assets. They do not invoke a live model or exercise deployed Edge Functions, row-level policies, OAuth, or external targets. Live agent behavior requires a separate configured-runtime check.

## License

Original project source is available under the [MIT License](LICENSE). Third-party dependencies, model weights, fonts, documents, and datasets retain their own licenses. This license does not grant rights to third-party assets.
