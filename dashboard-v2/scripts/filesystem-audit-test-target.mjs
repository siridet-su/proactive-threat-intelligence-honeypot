import { URL } from "node:url";

export const FILESYSTEM_AUDIT_TEST_DATABASE_PREFIX = "pti_fa016_test_";
const RUN_ID_PATTERN = /^[a-z0-9]+$/;

export function makeFilesystemAuditTestDatabase(runId) {
  if (typeof runId !== "string" || !RUN_ID_PATTERN.test(runId)) {
    throw new Error("FA-016 run identifier must contain only lowercase letters and digits");
  }
  return `${FILESYSTEM_AUDIT_TEST_DATABASE_PREFIX}${runId}`;
}

export function validateFilesystemAuditTestTarget({ uri, databaseName, runId }) {
  if (typeof uri !== "string" || !uri) throw new Error("FA-016 Mongo URI is required");
  if (typeof runId !== "string" || !RUN_ID_PATTERN.test(runId)) throw new Error("FA-016 run identifier is missing or invalid");
  if (databaseName === "honeypot_db" || !databaseName.startsWith(FILESYSTEM_AUDIT_TEST_DATABASE_PREFIX)) {
    throw new Error("FA-016 destructive target must use the test-only database prefix");
  }
  if (databaseName !== makeFilesystemAuditTestDatabase(runId)) throw new Error("FA-016 database does not match run identifier");
  const parsed = new URL(uri);
  if (parsed.protocol !== "mongodb:") throw new Error("FA-016 URI must use mongodb://");
  const hostname = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!["127.0.0.1", "localhost", "::1"].includes(hostname)) throw new Error("FA-016 URI must use a loopback host");
  const uriDatabase = decodeURIComponent(parsed.pathname.replace(/^\/+/, ""));
  if (uriDatabase !== databaseName) throw new Error("FA-016 URI database does not match validated database");
  return { uri, databaseName, runId };
}
