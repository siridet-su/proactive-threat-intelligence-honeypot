#!/usr/bin/env node

import {
  access,
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readlink,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { execFileSync } from "node:child_process";
import { validateArchive } from "./staging-archive-policy.mjs";

const dashboardRoot = resolve(dirname(new URL(import.meta.url).pathname), "..");
const repositoryRoot = resolve(dashboardRoot, "..");
const outputRoot = resolve(
  process.env.STAGING_ARTIFACT_DIR || join(tmpdir(), "dashboard-v2-staging-artifacts"),
);
const standaloneRoot = join(dashboardRoot, ".next", "standalone");
const lockPath = join(dashboardRoot, "package-lock.json");

function fail(message) {
  console.error(`staging package failed: ${message}`);
  if (process.env.GITHUB_ACTIONS === "true") {
    console.log(`::error file=scripts/package-staging.mjs,line=1,title=staging packaging failed::${message}`);
  }
  process.exitCode = 1;
  throw new Error(message);
}

function gitRevision(args) {
  return execFileSync("git", args, { cwd: repositoryRoot, encoding: "utf8" }).trim();
}

function sha256File(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function isWithin(root, target) {
  const pathFromRoot = relative(root, target);
  return pathFromRoot === "" || (
    !pathFromRoot.startsWith(".." + sep) &&
    pathFromRoot !== ".." &&
    !isAbsolute(pathFromRoot)
  );
}

async function ensureDestinationDirectory(destinationPath) {
  try {
    const destinationStat = await lstat(destinationPath);
    if (destinationStat.isSymbolicLink() || !destinationStat.isDirectory()) {
      throw new Error("destination directory is not a regular directory");
    }
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    await mkdir(destinationPath, { recursive: true });
  }
}

async function materializeEntry(
  sourcePath,
  destinationPath,
  allowedRoot,
  origin,
  symlinkInventory,
  activeDirectories,
) {
  const sourceStat = await lstat(sourcePath);
  if (sourceStat.isSymbolicLink()) {
    const target = await readlink(sourcePath);
    const lexicalTarget = resolve(dirname(sourcePath), target);
    let resolvedTarget = lexicalTarget;
    let targetExists = true;
    try {
      resolvedTarget = await realpath(lexicalTarget);
    } catch {
      targetExists = false;
    }
    const insideAllowedRoot = targetExists && isWithin(allowedRoot, resolvedTarget);
    const classification = !targetExists
      ? "BROKEN_LINK"
      : isAbsolute(target)
        ? "UNEXPECTED"
        : insideAllowedRoot
          ? "INTERNAL_SAFE_DEPENDENCY_LINK"
          : "ESCAPES_PACKAGE_TREE";
    symlinkInventory.push({
      path: relative(repositoryRoot, sourcePath),
      target,
      resolved_absolute_target: resolvedTarget,
      target_exists: targetExists,
      inside_allowed_source_root: insideAllowedRoot,
      origin,
      classification,
    });
    if (!targetExists) throw new Error("broken symbolic link: " + relative(repositoryRoot, sourcePath));
    if (isAbsolute(target)) throw new Error("absolute symbolic link target: " + relative(repositoryRoot, sourcePath));
    if (!insideAllowedRoot) throw new Error("symbolic link escapes allowed source root: " + relative(repositoryRoot, sourcePath));
    if (activeDirectories.has(resolvedTarget)) {
      throw new Error("symbolic link cycle: " + relative(repositoryRoot, sourcePath));
    }
    return materializeEntry(
      resolvedTarget,
      destinationPath,
      allowedRoot,
      origin,
      symlinkInventory,
      activeDirectories,
    );
  }

  if (sourceStat.isDirectory()) {
    const sourceRealPath = await realpath(sourcePath);
    if (activeDirectories.has(sourceRealPath)) {
      throw new Error("directory cycle: " + relative(repositoryRoot, sourcePath));
    }
    const nextActiveDirectories = new Set(activeDirectories);
    nextActiveDirectories.add(sourceRealPath);
    await ensureDestinationDirectory(destinationPath);
    for (const child of await readdir(sourcePath)) {
      await materializeEntry(
        join(sourcePath, child),
        join(destinationPath, child),
        allowedRoot,
        origin,
        symlinkInventory,
        nextActiveDirectories,
      );
    }
    await chmod(destinationPath, sourceStat.mode & 0o7777);
    return;
  }

  if (!sourceStat.isFile()) {
    throw new Error("unsupported source member type: " + relative(repositoryRoot, sourcePath));
  }
  await mkdir(dirname(destinationPath), { recursive: true });
  try {
    const destinationStat = await lstat(destinationPath);
    if (destinationStat.isSymbolicLink() || !destinationStat.isFile()) {
      throw new Error("destination file is not a regular file");
    }
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  await copyFile(sourcePath, destinationPath);
  await chmod(destinationPath, sourceStat.mode & 0o7777);
}

async function materializeTree(sourceRoot, destinationRoot, allowedRoot, origin, symlinkInventory) {
  const allowedRealPath = await realpath(allowedRoot);
  const sourceStat = await lstat(sourceRoot);
  if (sourceStat.isSymbolicLink() || !sourceStat.isDirectory()) {
    throw new Error("source root is not a regular directory: " + relative(repositoryRoot, sourceRoot));
  }
  await materializeEntry(
    sourceRoot,
    destinationRoot,
    allowedRealPath,
    origin,
    symlinkInventory,
    new Set(),
  );
}

async function inspectPackageTree(packageRoot) {
  const symlinks = [];
  let regularFiles = 0;
  let directories = 0;
  async function visit(path) {
    const pathStat = await lstat(path);
    if (pathStat.isSymbolicLink()) {
      symlinks.push(relative(repositoryRoot, path));
      return;
    }
    if (pathStat.isDirectory()) {
      directories += 1;
      for (const child of await readdir(path)) await visit(join(path, child));
      return;
    }
    if (!pathStat.isFile()) {
      throw new Error("package contains unsupported member type: " + relative(repositoryRoot, path));
    }
    if (pathStat.nlink !== 1) {
      throw new Error("package contains a hard-linked file: " + relative(repositoryRoot, path));
    }
    regularFiles += 1;
  }
  await visit(packageRoot);
  return { symlinks, symlink_count: symlinks.length, regular_files: regularFiles, directories };
}
function runArchive(packageRoot, archivePath, includePublic) {
  const tarArgs = [
    "--sort=name",
    "--mtime=@0",
    "--owner=0",
    "--group=0",
    "--numeric-owner",
    "--hard-dereference",
    "--use-compress-program=gzip -n -9",
    "-cf",
    archivePath,
    "-C",
    packageRoot,
    "server.js",
    ".next",
    "node_modules",
    "build-metadata.json",
    "package.json",
  ];
  if (includePublic) tarArgs.push("public");

  try {
    execFileSync("tar", tarArgs, { stdio: ["ignore", "pipe", "pipe"] });
  } catch {
    fail("tar archive creation failed");
  }
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

try {
  await mkdir(outputRoot, { recursive: true, mode: 0o700 });
} catch {
  fail("artifact directory creation failed");
}
const packageRoot = await mkdtemp(join(tmpdir(), "dashboard-v2-staging-package-"));
try {
  const standaloneServer = join(standaloneRoot, "server.js");
  const standaloneNext = join(standaloneRoot, ".next");
  if (!(await exists(standaloneServer)) || !(await exists(standaloneNext))) {
    fail(".next/standalone is missing; run npm run build first");
  }

  const symlinkInventory = [];
  try {
    await materializeTree(
      standaloneRoot,
      packageRoot,
      standaloneRoot,
      "next_standalone",
      symlinkInventory,
    );
  } catch (error) {
    fail("standalone copy failed: " + error.message);
  }
  try {
    await materializeEntry(
      join(dashboardRoot, "package.json"),
      join(packageRoot, "package.json"),
      await realpath(dashboardRoot),
      "package_metadata",
      symlinkInventory,
      new Set(),
    );
  } catch (error) {
    fail("package metadata copy failed: " + error.message);
  }
  try {
    await materializeTree(
      join(dashboardRoot, ".next", "static"),
      join(packageRoot, ".next", "static"),
      join(dashboardRoot, ".next", "static"),
      "next_static",
      symlinkInventory,
    );
  } catch (error) {
    fail("static asset copy failed: " + error.message);
  }
  const publicRoot = join(dashboardRoot, "public");
  const includePublic = await exists(publicRoot);
  if (includePublic) {
    try {
      await materializeTree(
        publicRoot,
        join(packageRoot, "public"),
        publicRoot,
        "public_assets",
        symlinkInventory,
      );
    } catch (error) {
      fail("public asset copy failed: " + error.message);
    }
  }

  let packageTree;
  try {
    packageTree = await inspectPackageTree(packageRoot);
  } catch (error) {
    fail("package tree safety validation failed: " + error.message);
  }
  if (packageTree.symlink_count !== 0) {
    fail("package tree contains symbolic links after materialization");
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
    materialization: {
      archive_symlinks_allowed: false,
      pre_materialization_tree: {
        source_roots: [
          relative(repositoryRoot, standaloneRoot),
          relative(repositoryRoot, join(dashboardRoot, ".next", "static")),
          ...(includePublic ? [relative(repositoryRoot, publicRoot)] : []),
        ],
        symlink_count: symlinkInventory.length,
      },
      symlink_count_before: symlinkInventory.length,
      symlink_inventory: symlinkInventory,
      symlink_count_after: packageTree.symlink_count,
    },
  };
  try {
    await writeFile(join(packageRoot, "build-metadata.json"), `${JSON.stringify(metadata, null, 2)}\n`, { mode: 0o644 });
  } catch {
    fail("build metadata write failed");
  }

  const archiveName = `dashboard-v2-staging-${commit}.tar.gz`;
  const archivePath = join(outputRoot, archiveName);
  await runArchive(packageRoot, archivePath, includePublic);
  let archiveValidation;
  try {
    archiveValidation = validateArchive(archivePath);
  } catch (error) {
    await rm(archivePath, { force: true });
    fail("archive safety validation failed: " + error.message);
  }
  const artifactSha256 = sha256File(archivePath);
  const artifactBytes = (await stat(archivePath)).size;
  const manifest = {
    schema_version: "dashboard-v2-staging-artifact-manifest.v1",
    ...metadata,
    artifact_file: archiveName,
    artifact_sha256: artifactSha256,
    artifact_bytes: await artifactBytes,
    package_root: relative(repositoryRoot, dashboardRoot),
    symlink_count_before: symlinkInventory.length,
    symlink_inventory: symlinkInventory,
    symlink_count_after: packageTree.symlink_count,
    archive_validation: archiveValidation,
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
