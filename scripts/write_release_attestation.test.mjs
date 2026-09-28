#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const script = fileURLToPath(new URL("./write_release_attestation.mjs", import.meta.url));
const version = "0.1.0";
const packageNames = Object.freeze([
  "reallyme-openid4vp-proto",
  "reallyme-openid4vp-dcql",
  "reallyme-openid4vp-types",
  "reallyme-openid4vp-dc-api",
  "reallyme-openid4vp-formats",
  "reallyme-openid4vp-wallet",
]);

const runFixture = ({ missingPackage, runAttempt = "1", symlinkPackage } = {}) => {
  const directory = mkdtempSync(join(tmpdir(), "openid4vp-write-attestation-test-"));
  try {
    const packageDirectory = join(directory, "target", "package");
    mkdirSync(packageDirectory, { recursive: true });
    for (const name of packageNames) {
      if (name === missingPackage || name === symlinkPackage) {
        continue;
      }
      writeFileSync(join(packageDirectory, `${name}-${version}.crate`), `archive-${name}`);
    }
    if (symlinkPackage !== undefined) {
      symlinkSync(
        join(packageDirectory, `${packageNames[0]}-${version}.crate`),
        join(packageDirectory, `${symlinkPackage}-${version}.crate`),
      );
    }
    const result = spawnSync(process.execPath, [script], {
      cwd: directory,
      encoding: "utf8",
      env: {
        ...process.env,
        CI_RUN_ID: "1001",
        FUZZ_RUN_ID: "1002",
        GITHUB_REPOSITORY: "reallyme/openid4vp",
        GITHUB_RUN_ATTEMPT: runAttempt,
        GITHUB_RUN_ID: "2001",
        PROTOBUF_CI_RUN_ID: "1003",
        RELEASE_SHA: "a".repeat(40),
        RELEASE_VERSION: version,
        SECRET_SCAN_RUN_ID: "1004",
      },
    });
    const outputPath = join(directory, "release-attestation", "crates-preflight.json");
    const document = result.status === 0 ? JSON.parse(readFileSync(outputPath, "utf8")) : null;
    return { document, result };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
};

test("writes exact v3 evidence for the fixed public crate set and prerequisite runs", () => {
  const { document, result } = runFixture();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(document.schema, "reallyme.openid4vp.crates_preflight.v3");
  assert.deepEqual(document.prerequisites, {
    ci: 1001,
    fuzz: 1002,
    protobuf_ci: 1003,
    secret_scan: 1004,
  });
  assert.deepEqual(
    document.crates.map((crate) => crate.file),
    packageNames.map((name) => `${name}-${version}.crate`),
  );
  for (const [index, crate] of document.crates.entries()) {
    const contents = `archive-${packageNames[index]}`;
    assert.equal(crate.size, Buffer.byteLength(contents));
    assert.equal(crate.sha256, createHash("sha256").update(contents).digest("hex"));
  }
});

test("fails closed for reruns, missing archives, and symbolic-link archives", () => {
  for (const fixture of [
    { runAttempt: "2" },
    { missingPackage: packageNames[1] },
    { symlinkPackage: packageNames[1] },
  ]) {
    const { result } = runFixture(fixture);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /release attestation creation failed/u);
  }
});
