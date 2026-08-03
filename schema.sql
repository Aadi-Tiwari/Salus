-- Salus database schema.
--
-- Run this once in the Supabase SQL editor:
--   supabase.com/dashboard/project/zqqwxjgmnqwgxwciwknx/sql/new
--
-- Every table is owner-scoped by Row Level Security. The publishable key that
-- ships in config.js can only ever reach rows whose user_id matches the signed
-- in account, so a leaked publishable key exposes nothing.

-- ---------------------------------------------------------------- scans ----
create table if not exists public.scans (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid not null default auth.uid() references auth.users(id) on delete cascade,
  target_url    text not null,
  target_host   text not null,
  repo          text,
  upload_name   text,
  checks        text[] not null,
  status        text   not null default 'queued'
                  check (status in ('queued','running','done','failed')),
  error         text,
  -- The ownership attestation. Recorded at insert because the modal that
  -- collects it is the same action that creates the row.
  authorized_at timestamptz not null default now(),
  started_at    timestamptz,
  finished_at   timestamptz,
  created_at    timestamptz not null default now()
);

-- ------------------------------------------------------------- findings ----
create table if not exists public.findings (
  id          uuid primary key default gen_random_uuid(),
  scan_id     uuid not null references public.scans(id) on delete cascade,
  user_id     uuid not null default auth.uid() references auth.users(id) on delete cascade,
  check_key   text not null,
  title       text not null,
  -- The endpoint, bundle path or header name the finding points at.
  locator     text not null default '',
  severity    text not null
                check (severity in ('breach','high','medium','context')),
  blast       text not null,
  -- Filled in once the check has actually proven the finding. Null means the
  -- work has not run yet, which is why the UI must not print it as evidence.
  evidence    text,
  generator   text,
  affected    integer,
  status      text not null default 'pending'
                check (status in ('pending','running','done','failed','blocked')),
  duration_ms integer,
  position    integer not null default 0,
  created_at  timestamptz not null default now()
);

create index if not exists findings_scan_idx on public.findings (scan_id, position);

-- -------------------------------------------------------- finding_steps ----
-- One row per line of the evidence trail. Held as rows rather than a jsonb
-- blob so the engine can flip a single step to done as it works, and the page
-- can stream that one change instead of re-reading the finding.
create table if not exists public.finding_steps (
  id         uuid primary key default gen_random_uuid(),
  finding_id uuid not null references public.findings(id) on delete cascade,
  user_id    uuid not null default auth.uid() references auth.users(id) on delete cascade,
  position   integer not null,
  label      text not null,
  state      text not null default 'pending'
               check (state in ('pending','active','done','blocked')),
  created_at timestamptz not null default now(),
  unique (finding_id, position)
);

create index if not exists finding_steps_finding_idx on public.finding_steps (finding_id, position);

-- ----------------------------------------------------- finding_messages ----
create table if not exists public.finding_messages (
  id          uuid primary key default gen_random_uuid(),
  scan_id     uuid not null references public.scans(id) on delete cascade,
  user_id     uuid not null default auth.uid() references auth.users(id) on delete cascade,
  role        text not null check (role in ('user','agent')),
  body        text not null,
  -- Which findings the question was asked about, so the thread can be replayed
  -- with the same context it was answered under.
  context_ids uuid[] not null default '{}',
  created_at  timestamptz not null default now()
);

create index if not exists finding_messages_scan_idx on public.finding_messages (scan_id, created_at);

-- ------------------------------------------------------------------ RLS ----
alter table public.scans            enable row level security;
alter table public.findings         enable row level security;
alter table public.finding_steps    enable row level security;
alter table public.finding_messages enable row level security;

-- Policies are dropped first so this file can be re-run after an edit.
drop policy if exists scans_owner            on public.scans;
drop policy if exists findings_owner         on public.findings;
drop policy if exists finding_steps_owner    on public.finding_steps;
drop policy if exists finding_messages_owner on public.finding_messages;

create policy scans_owner on public.scans
  for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

create policy findings_owner on public.findings
  for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

create policy finding_steps_owner on public.finding_steps
  for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

create policy finding_messages_owner on public.finding_messages
  for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

-- -------------------------------------------------------------- realtime ----
-- Lets the scan page watch findings appear instead of polling for them.
-- add table is not idempotent, so swallow the duplicate on a re-run.
do $$
begin
  alter publication supabase_realtime add table public.findings;
exception when duplicate_object then null;
end $$;

do $$
begin
  alter publication supabase_realtime add table public.finding_steps;
exception when duplicate_object then null;
end $$;

do $$
begin
  alter publication supabase_realtime add table public.scans;
exception when duplicate_object then null;
end $$;
