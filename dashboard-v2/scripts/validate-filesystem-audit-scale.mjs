import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  makeFilesystemAuditTestDatabase,
  validateFilesystemAuditTestTarget,
} from "./filesystem-audit-test-target.mjs";

const runId = `${process.pid.toString(36)}${Date.now().toString(36)}${randomUUID().replaceAll("-", "")}`.toLowerCase();
const containerName = `pti-fa016-mongo-${process.pid}`;
const databaseName = makeFilesystemAuditTestDatabase(runId);
const dashboardPath = new URL("../", import.meta.url).pathname;
const processorPath = new URL("../../agents/processor-agent/", import.meta.url).pathname;

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", ...options });
  if (result.status !== 0) throw new Error(`${command} ${args.join(" ")} failed:\n${result.stderr || result.stdout || "unknown error"}`);
  return result.stdout.trim();
}

let containerStarted = false;
let cleanupComplete = false;
function cleanup() {
  if (!containerStarted || cleanupComplete) return;
  cleanupComplete = true;
  const result = spawnSync("docker", ["rm", "--force", containerName], { encoding: "utf8" });
  if (result.status !== 0 && process.exitCode === undefined) process.exitCode = result.status ?? 1;
}
process.once("SIGINT", () => { cleanup(); process.exit(130); });
process.once("SIGTERM", () => { cleanup(); process.exit(143); });

try {
  const placeholder = validateFilesystemAuditTestTarget({
    uri: `mongodb://127.0.0.1:27017/${databaseName}`,
    databaseName,
    runId,
  });
  run("docker", [
    "run", "--detach", "--rm", "--name", containerName,
    "-p", "127.0.0.1::27017", "mongo:8.0", "--bind_ip_all", "--setParameter", "ttlMonitorSleepSecs=1",
  ]);
  containerStarted = true;
  let ready = false;
  for (let attempt = 0; attempt < 45; attempt += 1) {
    const health = spawnSync("docker", ["exec", containerName, "mongosh", "--quiet", "--eval", "db.adminCommand({ ping: 1 }).ok"], { encoding: "utf8" });
    if (health.status === 0 && health.stdout.trim() === "1") { ready = true; break; }
    run("sleep", ["1"]);
  }
  if (!ready) throw new Error("FA-016 temporary MongoDB container did not become ready");
  const port = run("docker", ["port", containerName, "27017/tcp"]).match(/127\.0\.0\.1:(\d+)/)?.[1];
  if (!port) throw new Error("could not determine FA-016 temporary MongoDB port");
  const validated = validateFilesystemAuditTestTarget({
    ...placeholder,
    uri: `mongodb://127.0.0.1:${port}/${databaseName}`,
  });
  const env = {
    ...process.env,
    FA016_MONGO_URI: validated.uri,
    FA016_MONGO_DB: validated.databaseName,
    FA016_MONGO_RUN_ID: validated.runId,
    GOCACHE: process.env.FA016_GOCACHE || "/tmp/pti-fa016-gocache",
  };
  const npmCommand = process.env.npm_execpath || "npm";
  const dashboard = spawnSync(npmCommand, ["run", "test", "--", "tests/filesystem-audit-scale.integration.test.ts"], { cwd: dashboardPath, env, encoding: "utf8", stdio: "inherit" });
  if (dashboard.status !== 0) process.exitCode = dashboard.status ?? 1;
  const go = spawnSync("go", ["test", "-count=1", "-run", "TestFA016", "./..."], { cwd: processorPath, env, encoding: "utf8", stdio: "inherit" });
  if (go.status !== 0) process.exitCode = go.status ?? 1;
} finally {
  cleanup();
}
