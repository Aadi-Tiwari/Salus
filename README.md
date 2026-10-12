# Salus

A web interface for collecting passive security findings, reviewing scan evidence, and preparing fixes.

Salus uses static HTML and JavaScript for the interface, Supabase for accounts and scan records, and an Edge Function for server-side checks. Findings distinguish a detected issue from a check that could not run. Results are evidence to investigate, not a certification that a target is secure.

## Local preview

Use Python to serve the repository. Copy `config.example.js` to `config.js` first; the placeholder values are enough for a preview.

```sh
python -m http.server 8080 --bind 127.0.0.1
```

Open <http://127.0.0.1:8080/app.html> or <http://127.0.0.1:8080/scanner.html>. Loopback hosts enter an explicit local preview. You can inspect the dashboard and configure scan inputs. Live scans, saved reports, and GitHub account access require the configured hosted service. Preview actions do not silently create scan records.

## Configure a hosted instance

See [SETUP.md](SETUP.md). `config.js` is ignored by Git and holds the Supabase URL, browser publishable key, and OAuth settings for your instance. Never place a Supabase secret or service-role key in browser code.

A publishable key is intended for client use; access still depends on database grants, row-level policies, and the user's session. Review and verify those controls on the deployed project. A local source review cannot establish its live authorization state.

## Source map

| Path | Responsibility |
| --- | --- |
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

The dependency-free tests cover safe return paths, secret classification, and redaction. They do not exercise a deployed Edge Function, live row-level policies, OAuth, or external scan targets. Use scans only on targets you own or are authorized to assess.
