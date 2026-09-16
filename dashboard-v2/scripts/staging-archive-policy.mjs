#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

export const ALLOWED_ARCHIVE_PATHS = Object.freeze([
  "server.js",
  "build-metadata.json",
  "package.json",
  ".next",
  ".next/",
  "node_modules",
  "node_modules/",
  "public",
  "public/",
]);

function normalizeEntry(rawEntry) {
  const entry = rawEntry.replace(/^\.\/+/, "").replace(/\/+$/, "");
  if (!entry || entry === ".") {
    throw new Error("archive contains an empty path");
  }
  if (entry.startsWith("/") || entry.includes("\0")) {
    throw new Error("archive contains an absolute or invalid path");
  }
  const parts = entry.split("/");
  if (parts.some((part) => part === ".." || part === "")) {
    throw new Error("archive contains a path traversal entry");
  }
  return entry;
}

function isAllowedEntry(entry) {
  return ALLOWED_ARCHIVE_PATHS.some((prefix) =>
    prefix.endsWith("/")
      ? entry === prefix.slice(0, -1) || entry.startsWith(prefix)
      : entry === prefix,
  );
}

export function validateArchive(archivePath) {
  const verbose = execFileSync(
    "tar",
    ["--list", "--verbose", "--file", archivePath],
    { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 },
  );
  const names = execFileSync("tar", ["--list", "--file", archivePath], {
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  const memberTypeCounts = {};
  const entries = [];

  for (const rawLine of verbose.split("\n")) {
    if (!rawLine) continue;
    const type = rawLine[0];
    memberTypeCounts[type] = (memberTypeCounts[type] || 0) + 1;
    if (type !== "-" && type !== "d") {
      throw new Error("archive contains unsupported member type: " + type);
    }
  }

  for (const rawEntry of names.split("\n")) {
    if (!rawEntry) continue;
    const entry = normalizeEntry(rawEntry);
    if (!isAllowedEntry(entry)) {
      throw new Error("archive contains an unexpected path: " + entry);
    }
    entries.push(entry);
  }

  return {
    archive_path_safety: "PASS",
    archive_symlink_count: memberTypeCounts.l || 0,
    archive_hardlink_count: memberTypeCounts.h || 0,
    member_type_counts: memberTypeCounts,
    entry_count: entries.length,
  };
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : "";
if (invokedPath === resolve(fileURLToPath(import.meta.url))) {
  const archivePath = process.argv[2];
  if (!archivePath) {
    console.error("usage: staging-archive-policy.mjs ARCHIVE");
    process.exitCode = 2;
  } else {
    try {
      console.log(JSON.stringify(validateArchive(archivePath)));
    } catch (error) {
      console.error("archive validation failed: " + error.message);
      process.exitCode = 1;
    }
  }
}
