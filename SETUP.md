# Wiring up the Salus backend

Salus is static HTML plus Supabase. There is no server of its own, so the scan
engine runs as a Supabase Edge Function. Two steps, both one-time.

## 1. Create the tables

Open the SQL editor for the project and run `schema.sql`:

    https://supabase.com/dashboard/project/zqqwxjgmnqwgxwciwknx/sql/new

It creates `scans`, `findings`, `finding_steps` and `finding_messages`, turns on
Row Level Security so every row is reachable only by the account that owns it,
and adds the three tables the scan page watches to the realtime publication.

The file is safe to run more than once. Policies are dropped before they are
recreated, and the publication changes swallow a duplicate.

Until this runs, `scanner.html` will say so in as many words rather than failing
with a generic save error. It detects PostgREST's `PGRST205`, which is the code
for a table the API cannot see.

## 2. Deploy the scan engine

Needs the Supabase CLI, signed in and linked to the project:

    supabase functions deploy scan

The function reads the caller's JWT and creates its Supabase client with that
token, so it can only ever touch the calling user's own rows. It needs no
service role key and none is stored anywhere in this repository.

Until it is deployed, a scan still records correctly and the report page says
the engine did not answer instead of showing an empty report that looks like a
clean bill of health.

## What the engine does and does not do

It runs the six Tier 1 checks server side, because a browser cannot read a
cross-origin response at all. For each check it writes the finding and its
steps before doing the work, so the report fills in as it goes.

Three rules it holds to:

- A check that ran and found nothing is deleted, not written. A finding on the
  report means something was actually found.
- A check that could not run is marked `blocked` with `evidence` left null and
  its severity demoted to `context`. It never writes a sentence describing work
  that did not happen.
- Credentials found in a bundle are redacted before storage. The first six and
  last four characters survive; the middle is masked.

Tier 2 and Tier 3 are not implemented. Their options stay locked in the page.

## Testing without a live project

`scanner.html` imports Supabase by full URL, so an import map can redirect that
one specifier at a local mock and exercise the real page against fixtures. That
is how the report views, the injection escaping, the failure states and the
responsive breakpoints were checked.
