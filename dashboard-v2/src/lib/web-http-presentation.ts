/** These are presentation hints from attacker-controlled HTTP fields, not verified browser identity. */
export function reportedClient(userAgent: string | null | undefined): string | null {
  if (!userAgent) return null;
  const patterns: Array<[RegExp, string]> = [
    [/Edg\/([\d.]+)/i, "Edge"],
    [/Firefox\/([\d.]+)/i, "Firefox"],
    [/(?:Chrome|Chromium)\/([\d.]+)/i, "Chrome/Chromium"],
    [/Version\/([\d.]+).*Safari/i, "Safari"],
    [/curl\/([\d.]+)/i, "curl"],
    [/Python-urllib\/([\d.]+)/i, "Python urllib"],
  ];
  for (const [pattern, name] of patterns) {
    const version = userAgent.match(pattern)?.[1];
    if (version) return `${name} ${version}`;
  }
  return "Other / unrecognized client";
}

/** Keep the exact captured query separate; this is only a human-readable interpretation. */
export function decodedQueryForDisplay(query: string | null | undefined): string | null {
  if (!query) return null;
  try {
    const decoded = decodeURIComponent(query.replace(/\+/g, " "));
    return decoded !== query ? decoded : null;
  } catch {
    return null;
  }
}
