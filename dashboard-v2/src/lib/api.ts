export class DashboardApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "DashboardApiError";
    this.status = status;
  }
}

export async function fetchDashboardJson<T>(
  path: string,
  signal?: AbortSignal,
): Promise<T> {
  const response = await fetch(path, {
    method: "GET",
    headers: { Accept: "application/json" },
    cache: "no-store",
    signal,
  });

  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  if (!response.ok) {
    const message =
      body && typeof body === "object" && "error" in body
        ? String((body as { error?: unknown }).error || `HTTP ${response.status}`)
        : `HTTP ${response.status}`;
    throw new DashboardApiError(message, response.status);
  }
  return body as T;
}

export function apiQuery(path: string, values: Record<string, string | number | undefined>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== "") {
      params.set(key, String(value));
    }
  }
  const query = params.toString();
  return query ? `${path}?${query}` : path;
}

export function apiErrorMessage(error: unknown): string {
  if (error instanceof DashboardApiError) return error.message;
  if (error instanceof Error) return error.message;
  return "The dashboard backend did not return usable data.";
}
