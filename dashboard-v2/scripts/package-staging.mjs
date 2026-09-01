#!/usr/bin/env node

import { createWriteStream } from "node:fs";
import { access, cp, mkdir, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { execFileSync, spawn } from "node:child_process";

const dashboardRoot = resolve(dirname(new URL(import.meta.url).pathname), "..");
const repositoryRoot = resolve(dashboardRoot, "..");
const outputRoot = resolve(
  process.env.STAGING_ARTIFACT_DIR || join(tmpdir(), "dashboard-v2-staging-artifacts"),
);
const standaloneRoot = join(dashboardRoot, ".next", "standalone");
const lockPath = join(dashboardRoot, "package-lock.json");

function fail(message) {
  console.error(`staging package failed: ${message}`);
  process.exitCode = 1;
  throw new Error(message);
}

function gitRevision(args) {
  return execFileSync("git", args, { cwd: repositoryRoot, encoding: "utf8" }).trim();
}

function sha256File(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function runArchive(packageRoot, archivePath, includePublic) {
  return new Promise((resolveArchive, rejectArchive) => {
    const tarArgs = [
      "--sort=name",
      "--mtime=@0",
      "--owner=0",
      "--group=0",
      "--numeric-owner",
      "-cf",
      "-",
      "-C",
      packageRoot,
      "server.js",
      ".next",
      "node_modules",
      "build-metadata.json",
      "package.json",
    ];
    if (includePublic) tarArgs.push("public");

    const tar = spawn("tar", tarArgs, { stdio: ["ignore", "pipe", "pipe"] });
    const gzip = spawn("gzip", ["-n", "-9"], { stdio: ["pipe", "pipe", "pipe"] });
    const output = createWriteStream(archivePath, { mode: 0o600 });
    let diagnostics = "";
    tar.stderr.on("data", (chunk) => { diagnostics += chunk.toString(); });
    gzip.stderr.on("data", (chunk) => { diagnostics += chunk.toString(); });
    tar.stdout.pipe(gzip.stdin);
    gzip.stdout.pipe(output);

    let tarCode;
    let gzipCode;
    let outputClosed = false;
    const finish = () => {
      if (!outputClosed || tarCode === undefined || gzipCode === undefined) return;
      if (tarCode !== 0 || gzipCode !== 0) {
        rejectArchive(new Error(diagnostics.trim() || "tar/gzip failed"));
      } else {
        resolveArchive();
      }
    };
    output.on("error", rejectArchive);
    tar.stdout.on("error", rejectArchive);
    gzip.stdin.on("error", rejectArchive);
    output.on("close", () => { outputClosed = true; finish(); });
    tar.on("error", rejectArchive);
    gzip.on("error", rejectArchive);
    tar.on("close", (code) => { tarCode = code; finish(); });
    gzip.on("close", (code) => { gzipCode = code; finish(); });
  });
}

const commit = process.env.GITHUB_SHA || gitRevision(["rev-parse", "HEAD"]);
if (!/^[0-9a-f]{40}$/i.test(commit)) fail("GITHUB_SHA must be a full commit SHA");
const tree = process.env.GITHUB_TREE_SHA || gitRevision(["rev-parse", `${commit}^{tree}`]);
if (!/^[0-9a-f]{40}$/i.test(tree)) fail("source tree must be a full tree SHA");
const runId = process.env.GITHUB_RUN_ID || "local";
if (!/^[A-Za-z0-9._-]{1,128}$/.test(runId)) fail("CI run ID contains unsafe characters");

const lockSha256 = sha256File(lockPath);
const buildId = process.env.NEXT_PUBLIC_DASHBOARD_BUILD_ID || commit;
const deploymentLabel = (process.env.NEXT_PUBLIC_DASHBOARD_DEPLOYMENT_LABEL || "STAGING").trim().toUpperCase();
if (deploymentLabel !== "STAGING") fail("staging packages must be built with the STAGING label");

await mkdir(outputRoot, { recursive: true, mode: 0o700 });
const packageRoot = await mkdtemp(join(tmpdir(), "dashboard-v2-staging-package-"));
try {
  const standaloneServer = join(standaloneRoot, "server.js");
  const standaloneNext = join(standaloneRoot, ".next");
  if (!(await exists(standaloneServer)) || !(await exists(standaloneNext))) {
    fail(".next/standalone is missing; run npm run build first");
  }

  await cp(standaloneRoot, packageRoot, { recursive: true, dereference: false });
  await cp(join(dashboardRoot, "package.json"), join(packageRoot, "package.json"), {
    force: true,
  });
  await cp(join(dashboardRoot, ".next", "static"), join(packageRoot, ".next", "static"), {
    recursive: true,
    dereference: false,
    force: true,
  });
  const publicRoot = join(dashboardRoot, "public");
  const includePublic = await exists(publicRoot);
  if (includePublic) {
    await cp(publicRoot, join(packageRoot, "public"), { recursive: true, dereference: false, force: true });
  }

  const metadata = {
    schema_version: "dashboard-v2-staging-artifact.v1",
    deployment_environment: "staging",
    deployment_label: deploymentLabel,
    build_id: buildId,
    git_commit_sha: commit,
    git_tree_sha: tree,
    package_lock_sha256: lockSha256,
    ci_run_id: runId,
    artifact_contents: ["server.js", ".next", "node_modules", "build-metadata.json", "package.json", ...(includePublic ? ["public"] : [])],
  };
  await writeFile(join(packageRoot, "build-metadata.json"), `${JSON.stringify(metadata, null, 2)}\n`, { mode: 0o644 });

  const archiveName = `dashboard-v2-staging-${commit}.tar.gz`;
  const archivePath = join(outputRoot, archiveName);
  await runArchive(packageRoot, archivePath, includePublic);
  const artifactSha256 = sha256File(archivePath);
  const artifactBytes = (await stat(archivePath)).size;
  const manifest = {
    schema_version: "dashboard-v2-staging-artifact-manifest.v1",
    ...metadata,
    artifact_file: archiveName,
    artifact_sha256: artifactSha256,
    artifact_bytes: await artifactBytes,
    package_root: relative(repositoryRoot, dashboardRoot),
  };
  const manifestPath = join(outputRoot, `${archiveName}.manifest.json`);
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
  console.log(JSON.stringify({ artifact: archivePath, manifest: manifestPath, artifact_sha256: artifactSha256, git_commit_sha: commit }));
} finally {
  await rm(packageRoot, { recursive: true, force: true });
}

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}
