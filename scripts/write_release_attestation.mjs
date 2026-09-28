#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash } from "node:crypto";
import { lstatSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const FULL_SHA_PATTERN = /^[0-9a-f]{40}$/u;
const POSITIVE_INTEGER_PATTERN = /^[1-9][0-9]*$/u;
const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const OUTPUT_DIRECTORY = "release-attestation";
const OUTPUT_PATH = `${OUTPUT_DIRECTORY}/crates-preflight.json`;
const PACKAGE_DIRECTORY = "target/package";
const MAX_ARCHIVE_BYTES = 20 * 1024 * 1024;
const PUBLIC_PACKAGES = Object.freeze([
  "reallyme-openid4vp-proto",
  "reallyme-openid4vp-dcql",
  "reallyme-openid4vp-types",
  "reallyme-openid4vp-dc-api",
  "reallyme-openid4vp-formats",
  "reallyme-openid4vp-wallet",
  "reallyme-openid4vp-profiles",
  "reallyme-openid4vp-verifier",
  "reallyme-openid4vp-http",
  "reallyme-openid4vp-proto-codec",
  "reallyme-openid4vp-runtime",
  "reallyme-openid4vp",
]);
const PREREQUISITE_RUNS = Object.freeze({
  ci: "CI_RUN_ID",
  fuzz: "FUZZ_RUN_ID",
  protobuf_ci: "PROTOBUF_CI_RUN_ID",
  secret_scan: "SECRET_SCAN_RUN_ID",
});

const fail = (code) => {
  console.error(`release attestation creation failed: ${code}`);
  process.exit(1);
};

const parsePositiveInteger = (value, code) => {
  if (typeof value !== "string" || !POSITIVE_INTEGER_PATTERN.test(value)) {
    fail(code);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    fail(code);
  }
  return parsed;
};

const repository = process.env.GITHUB_REPOSITORY;
const releaseSha = process.env.RELEASE_SHA;
const version = process.env.RELEASE_VERSION;
if (typeof repository !== "string" || !REPOSITORY_PATTERN.test(repository)) {
  fail("invalid-repository");
}
if (typeof releaseSha !== "string" || !FULL_SHA_PATTERN.test(releaseSha)) {
  fail("invalid-release-sha");
}
if (typeof version !== "string" || !VERSION_PATTERN.test(version)) {
  fail("invalid-release-version");
}
const runId = parsePositiveInteger(process.env.GITHUB_RUN_ID, "invalid-run-id");
const runAttempt = parsePositiveInteger(process.env.GITHUB_RUN_ATTEMPT, "invalid-run-attempt");
if (runAttempt !== 1) {
  fail("rerun-cannot-create-release-attestation");
}

const crates = PUBLIC_PACKAGES.map((name) => {
  const file = `${name}-${version}.crate`;
  const archivePath = path.join(PACKAGE_DIRECTORY, file);
  try {
    const status = lstatSync(archivePath);
    if (
      status.isSymbolicLink() ||
      !status.isFile() ||
      status.size < 1 ||
      status.size > MAX_ARCHIVE_BYTES
    ) {
      fail("invalid-crate-archive");
    }
    return {
      file,
      sha256: createHash("sha256").update(readFileSync(archivePath)).digest("hex"),
      size: status.size,
    };
  } catch (error) {
    if (error instanceof Error && error.message === "invalid-crate-archive") {
      throw error;
    }
    fail("missing-crate-archive");
  }
});

const attestation = {
  schema: "reallyme.openid4vp.crates_preflight.v4",
  crates,
  prerequisites: Object.fromEntries(
    Object.entries(PREREQUISITE_RUNS).map(([name, environmentName]) => [
      name,
      parsePositiveInteger(process.env[environmentName], `invalid-${name}-run-id`),
    ]),
  ),
  repository,
  workflow: "crates-package-preflight.yml",
  run_id: runId,
  run_attempt: runAttempt,
  release_sha: releaseSha,
  version,
};

try {
  mkdirSync(OUTPUT_DIRECTORY, { recursive: true });
  writeFileSync(OUTPUT_PATH, `${JSON.stringify(attestation, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
} catch {
  fail("attestation-write-failed");
}
console.log("reviewed crates package attestation written");
