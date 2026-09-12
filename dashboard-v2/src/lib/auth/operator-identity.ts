const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function normalizeEmail(value: string): string | null {
  const email = value.trim().toLowerCase();
  return EMAIL_PATTERN.test(email) ? email : null;
}

export function emailLookup(email: string): RegExp {
  return new RegExp(`^${escapeRegExp(email)}$`, "i");
}
