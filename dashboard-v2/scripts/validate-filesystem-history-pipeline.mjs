import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";

import {
  makeFilesystemHistoryTestDatabase,
  validateFilesystemHistoryTestTarget,
} from "./filesystem-history-test-target.mjs";

const containerName = `pti-fa010-mongo-${process.pid}`;
const dashboardPath = new URL("../", import.meta.url).pathname;
const runId = `${process.pid.toString(36)}${Date.now().toString(36)}${randomUUID().replaceAll("-", "")}`.toLowerCase();
const databaseName = makeFilesystemHistoryTestDatabase(runId);

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", ...options });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed:\n${result.stderr || result.stdout || "unknown error"}`);
  }
  return result.stdout.trim();
}

let containerStarted = false;
let cleanupComplete = false;

function cleanupContainer() {
  if (!containerStarted || cleanupComplete) return;
  cleanupComplete = true;
  const cleanup = spawnSync("docker", ["rm", "--force", containerName], { encoding: "utf8" });
  if (cleanup.status !== 0 && process.exitCode === undefined) process.exitCode = cleanup.status ?? 1;
}

process.once("SIGINT", () => {
  cleanupContainer();
  process.exit(130);
});
process.once("SIGTERM", () => {
  cleanupContainer();
  process.exit(143);
});

try {
  const portPlaceholder = 27017;
  const preflightTarget = validateFilesystemHistoryTestTarget({
    uri: `mongodb://127.0.0.1:${portPlaceholder}/${databaseName}`,
    databaseName,
    runId,
  });
  run("docker", [
    "run",
    "--detach",
    "--rm",
    "--name",
    containerName,
    "-p",
    "127.0.0.1::27017",
    "mongo:8.0",
    "--bind_ip_all",
  ]);
  containerStarted = true;

  let ready = false;
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const health = spawnSync("docker", [
      "exec",
      containerName,
      "mongosh",
      "--quiet",
      "--eval",
      "db.adminCommand({ ping: 1 }).ok",
    ], { encoding: "utf8" });
    if (health.status === 0 && health.stdout.trim() === "1") {
      ready = true;
      break;
    }
    run("sleep", ["1"]);
  }
  if (!ready) throw new Error("temporary MongoDB container did not become ready");

  const portOutput = run("docker", ["port", containerName, "27017/tcp"]);
  const portMatch = portOutput.match(/127\.0\.0\.1:(\d+)/);
  if (!portMatch) throw new Error(`could not determine temporary MongoDB port from: ${portOutput}`);

  const npmCommand = process.env.npm_execpath || "npm";
  const testUri = `mongodb://127.0.0.1:${portMatch[1]}/${databaseName}`;
  const validatedTarget = validateFilesystemHistoryTestTarget({
    ...preflightTarget,
    uri: testUri,
  });
  const testResult = spawnSync(npmCommand, [
    "run",
    "test",
    "--",
    "tests/filesystem-history-pagination.test.ts",
  ], {
    cwd: dashboardPath,
    encoding: "utf8",
    env: {
      ...process.env,
      FA010_MONGO_URI: validatedTarget.uri,
      FA010_MONGO_TEST_DB: validatedTarget.databaseName,
      FA010_MONGO_RUN_ID: validatedTarget.runId,
    },
    stdio: "inherit",
  });
  if (testResult.status !== 0) process.exitCode = testResult.status ?? 1;
} finally {
  cleanupContainer();
}
