export function safeReturnPath(value, origin) {
  if (typeof value !== "string" || !value.startsWith("/")) return "/app.html";
  try {
    const target = new URL(value, origin);
    if (target.origin !== origin || target.pathname.startsWith("//")) return "/app.html";
    return target.pathname + target.search + target.hash;
  } catch {
    return "/app.html";
  }
}
