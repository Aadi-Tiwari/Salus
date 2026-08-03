// Salus front-end configuration.
//
// Both values here are safe to ship to a browser. The publishable key is
// designed for client use and is enforced by Row Level Security on the
// database side. The secret key (sb_secret_...) must NEVER appear in this
// file, in any file served to a browser, or in a commit. It belongs only on
// a server you control.
// After editing this file, hard-refresh (Ctrl+Shift+R). Browsers cache it, and
// a stale copy looks exactly like a config that did not take.
window.SALUS_CONFIG = {
  // Supabase -> Project Settings -> Data API -> Project URL.
  // The project ref is the same string in your dashboard address bar:
  // supabase.com/dashboard/project/<REF>
  SUPABASE_URL: "https://zqqwxjgmnqwgxwciwknx.supabase.co",

  SUPABASE_PUBLISHABLE_KEY: "sb_publishable_L0pNSGa2MLanz6smSfJAyQ_lEoEjbi8",

  // Where a signed-in user lands.
  AFTER_SIGNIN: "/app.html",

  // GitHub scopes. "repo" covers private repositories, which Salus needs to
  // open a pull request against them. Drop to "public_repo" if you only ever
  // touch public repos; it is a much easier permission for a founder to grant.
  GITHUB_SCOPES: "read:user user:email repo",
};
