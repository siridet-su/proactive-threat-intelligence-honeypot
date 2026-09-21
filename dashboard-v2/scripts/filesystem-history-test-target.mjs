import { URL } from "node:url";

export const FILESYSTEM_HISTORY_TEST_DATABASE_PREFIX = "pti_fa010_test_";
const RUN_ID_PATTERN = /^[a-z0-9]+$/;

function normalizedHostname(hostname) {
  return hostname.replace(/^\[|\]$/g, "").toLowerCase();
}

export function makeFilesystemHistoryTestDatabase(runId) {
  if (typeof runId !== "string" || !RUN_ID_PATTERN.test(runId)) {
    throw new Error("FA-010 run identifier must contain only lowercase letters and digits");
  }
  return `${FILESYSTEM_HISTORY_TEST_DATABASE_PREFIX}${runId}`;
}

export function validateFilesystemHistoryTestTarget({ uri, databaseName, runId }) {
  if (typeof uri !== "string" || !uri) throw new Error("FA-010 Mongo URI is required");
  if (typeof runId !== "string" || !RUN_ID_PATTERN.test(runId)) {
    throw new Error("FA-010 Mongo run identifier is missing or invalid");
  }
  if (databaseName === "honeypot_db" || !databaseName.startsWith(FILESYSTEM_HISTORY_TEST_DATABASE_PREFIX)) {
    throw new Error("FA-010 destructive target must use the test-only database prefix");
  }
  const expectedDatabaseName = makeFilesystemHistoryTestDatabase(runId);
  if (databaseName !== expectedDatabaseName) {
    throw new Error("FA-010 database name does not match the run identifier");
  }

  let parsed;
  try {
    parsed = new URL(uri);
  } catch {
    throw new Error("FA-010 Mongo URI is invalid");
  }
  if (parsed.protocol !== "mongodb:") {
    throw new Error("FA-010 Mongo URI must use mongodb:// with a loopback host");
  }
  const hostname = normalizedHostname(parsed.hostname);
  if (hostname !== "127.0.0.1" && hostname !== "localhost" && hostname !== "::1") {
    throw new Error("FA-010 Mongo URI hostname must be loopback");
  }
  const uriDatabaseName = decodeURIComponent(parsed.pathname.replace(/^\/+/, ""));
  if (uriDatabaseName !== databaseName) {
    throw new Error("FA-010 Mongo URI database does not match the validated test database");
  }
  return { uri, databaseName, runId };
}

export function runWithValidatedFilesystemHistoryTarget(config, connect) {
  const validated = validateFilesystemHistoryTestTarget(config);
  return connect(validated);
}
