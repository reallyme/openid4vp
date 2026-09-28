// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

const script = fileURLToPath(new URL("./publish-crates-in-order.mjs", import.meta.url));

function runFixture({
  corruptChecksum = false,
  extraPublishable = false,
  mode = "publish",
  registryToken = "test-placeholder",
  reorderIndependent = false,
  rustVersion = "1.96",
  scenario = "success",
  requirement = "^0.1.0",
  version = "0.1.0",
} = {}) {
  const directory = mkdtempSync(join(tmpdir(), "openid4vp-publish-test-"));
  try {
    const packageNames = [
      "reallyme-openid4vp-proto",
      "reallyme-openid4vp-dcql",
      "reallyme-openid4vp-types",
    ];
    const metadataPackages = [
      {
        name: "reallyme-openid4vp-proto",
        version,
        rust_version: rustVersion,
        publish: null,
        dependencies: [],
      },
      {
        name: "reallyme-openid4vp-types",
        version,
        rust_version: rustVersion,
        publish: null,
        dependencies: [{
          name: "reallyme-openid4vp-dcql",
          source: null,
          path: "crates/dcql",
          kind: null,
          req: requirement,
        }],
      },
      {
        name: "reallyme-openid4vp-dcql",
        version,
        rust_version: rustVersion,
        publish: null,
        dependencies: [],
      },
    ];
    if (reorderIndependent) {
      metadataPackages.push(metadataPackages.shift());
    }
    if (extraPublishable) {
      metadataPackages.push({
        name: "reallyme-openid4vp-runtime",
        version,
        rust_version: rustVersion,
        publish: null,
        dependencies: [],
      });
    }
    const callsPath = join(directory, "calls.json");
    const attestationPath = join(directory, "attestation.json");
    const ledgerPath = join(directory, "publication-ledger.json");
    const reviewedDirectory = join(directory, "reviewed-crates");
    const preload = join(directory, "mock.mjs");
    writeFileSync(callsPath, "[]");
    mkdirSync(reviewedDirectory);
    for (const name of packageNames) {
      writeFileSync(join(reviewedDirectory, `${name}-${version}.crate`), `archive-${name}`);
    }
    writeFileSync(attestationPath, JSON.stringify({
      schema: "reallyme.openid4vp.crates_preflight.v3",
      crates: packageNames.map((name) => ({
        file: `${name}-${version}.crate`,
        sha256: corruptChecksum
          ? "f".repeat(64)
          : createHash("sha256").update(`archive-${name}`).digest("hex"),
        size: Buffer.byteLength(`archive-${name}`),
      })),
      prerequisites: {
        ci: 1001,
        fuzz: 1002,
        protobuf_ci: 1003,
        secret_scan: 1004,
      },
      repository: "reallyme/openid4vp",
      workflow: "crates-package-preflight.yml",
      run_id: 123,
      run_attempt: 1,
      release_sha: "a".repeat(40),
      version,
    }));
    // Intercept every child process: these tests must never invoke Cargo,
    // access a registry, publish a crate, or perform real retry waits.
    writeFileSync(preload, `
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const calls = [];
const scenario = ${JSON.stringify(scenario)};
let attempts = 0;
let delayedIndexChecks = scenario === "index-lag" ? 1 : 0;
let delayedPublishIndexChecks = scenario === "publish-index-lag" ? 1 : 0;
const registry = new Set(
  scenario === "partial"
    ? ["reallyme-openid4vp-proto", "reallyme-openid4vp-dcql"]
    : [],
);
Atomics.wait = (_array, _index, _value, delay) => {
  calls.push(["wait", delay]);
  writeFileSync(${JSON.stringify(callsPath)}, JSON.stringify(calls));
  return "timed-out";
};
childProcess.spawnSync = (command, args) => {
  calls.push([command, ...args]);
  writeFileSync(${JSON.stringify(callsPath)}, JSON.stringify(calls));
  const ok = { status: 0, stdout: "", stderr: "" };
  if (command === "curl") {
    const outputPath = args[args.indexOf("--output") + 1];
    const archiveName = outputPath.slice(outputPath.lastIndexOf("/") + 1);
    const packageName = archiveName.slice(0, -("-${version}.crate".length));
    if (!registry.has(packageName)) return { ...ok, status: 22, stderr: "not visible" };
    writeFileSync(outputPath, "archive-" + packageName);
    return ok;
  }
  if (command !== "cargo") return { ...ok, status: 99 };
  if (args[0] === "metadata") return { ...ok, stdout: JSON.stringify({
    target_directory: ${JSON.stringify(directory)},
    packages: ${JSON.stringify(metadataPackages)},
  }) };
  if (args[0] === "package") {
    const packageName = args[args.indexOf("-p") + 1];
    if (
      packageName === "reallyme-openid4vp-types" &&
      (!registry.has("reallyme-openid4vp-dcql") || delayedIndexChecks > 0)
    ) {
      if (delayedIndexChecks > 0) delayedIndexChecks -= 1;
      return {
        ...ok,
        status: 101,
        stderr:
          "no matching package named " +
          String.fromCharCode(96) +
          "reallyme-openid4vp-dcql" +
          String.fromCharCode(96) +
          " found",
      };
    }
    mkdirSync(join(${JSON.stringify(directory)}, "package"), { recursive: true });
    writeFileSync(
      join(${JSON.stringify(directory)}, "package", packageName + "-${version}.crate"),
      "archive-" + packageName,
    );
    return ok;
  }
  if (args[0] !== "publish") return { ...ok, status: 99 };
  const packageName = args[args.indexOf("-p") + 1];
  if (registry.has(packageName)) {
    return { ...ok, status: 101, stderr: "crate version already exists" };
  }
  if (
    scenario === "publish-index-lag" &&
    packageName === "reallyme-openid4vp-types" &&
    delayedPublishIndexChecks > 0
  ) {
    delayedPublishIndexChecks -= 1;
    return {
      ...ok,
      status: 101,
      stderr: "failed to select a version for the requirement " +
        String.fromCharCode(96) + "reallyme-openid4vp-dcql = ^0.1.0" +
        String.fromCharCode(96),
    };
  }
  attempts += 1;
  if (scenario === "exhausted" || (scenario === "retry" && attempts === 1)) {
    if (scenario === "retry") {
      // The archive is unchanged for an ordinary retry.
    }
    return { ...ok, status: 101, stderr: "too many requests" };
  }
  if (scenario === "tamper-retry" && attempts === 1) {
    writeFileSync(
      join(${JSON.stringify(directory)}, "package", packageName + "-${version}.crate"),
      "tampered-archive",
    );
    return { ...ok, status: 101, stderr: "too many requests" };
  }
  if (scenario === "failure") return { ...ok, status: 101, stderr: "package verification failed" };
  registry.add(packageName);
  return ok;
};
syncBuiltinESMExports();
`);
    const result = spawnSync(process.execPath, ["--import", pathToFileURL(preload).href, script, mode], {
      cwd: directory,
      encoding: "utf8",
      timeout: 30_000,
      env: {
        ...process.env,
        GITHUB_REPOSITORY: "reallyme/openid4vp",
        PREFLIGHT_RUN_ID: "123",
        PUBLICATION_LEDGER_PATH: ledgerPath,
        RELEASE_ATTESTATION_PATH: attestationPath,
        RELEASE_SHA: "a".repeat(40),
        RELEASE_VERSION: version,
        REVIEWED_CRATE_DIRECTORY: reviewedDirectory,
        CARGO_REGISTRY_TOKEN: registryToken,
      },
    });
    assert.equal(result.error, undefined);
    const ledger = existsSync(ledgerPath)
      ? JSON.parse(readFileSync(ledgerPath, "utf8"))
      : null;
    return { ...result, calls: JSON.parse(readFileSync(callsPath, "utf8")), ledger };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("successful publication respects dependency order", () => {
  const result = runFixture();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.calls.filter((call) => call[1] === "publish").map((call) => call[3]),
    [
      "reallyme-openid4vp-proto",
      "reallyme-openid4vp-dcql",
      "reallyme-openid4vp-types",
    ]);
  assert.ok(
    result.calls
      .filter((call) => call[1] === "publish")
      .every((call) => call.includes("--no-verify")),
  );
  assert.equal(result.calls.filter((call) => call[0] === "curl").length, 3);
  assert.deepEqual(
    result.calls
      .filter((call) => call[0] === "cargo" && ["package", "publish"].includes(call[1]))
      .map((call) => [call[1], call[3]]),
    [
      ["package", "reallyme-openid4vp-proto"],
      ["publish", "reallyme-openid4vp-proto"],
      ["package", "reallyme-openid4vp-dcql"],
      ["publish", "reallyme-openid4vp-dcql"],
      ["package", "reallyme-openid4vp-types"],
      ["publish", "reallyme-openid4vp-types"],
    ],
  );
  assert.equal(result.ledger.schema, "reallyme.openid4vp.crates-publication-ledger.v1");
  assert.equal(result.ledger.state, "completed");
  assert.deepEqual(
    result.ledger.crates.map((entry) => entry.state),
    ["published", "published", "published"],
  );
  assert.ok(result.ledger.crates.every((entry) => /^[0-9a-f]{64}$/u.test(entry.archive_sha256)));
});

test("rate-limit exhaustion fails without publishing dependent crates", () => {
  const result = runFixture({ scenario: "exhausted" });
  assert.equal(result.status, 101);
  const publishes = result.calls.filter((call) => call[1] === "publish");
  assert.equal(publishes.length, 12);
  assert.ok(publishes.every((call) => call[3] === "reallyme-openid4vp-proto"));
  assert.equal(result.calls.filter((call) => call[0] === "wait").length, 11);
  assert.equal(result.ledger.state, "in_progress");
  assert.equal(result.ledger.crates[0].state, "attempting");
});

test("transient rate limits retry before publishing dependent crates", () => {
  const result = runFixture({ scenario: "retry" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.calls.filter((call) => call[0] === "wait"), [["wait", 60000]]);
});

test("index visibility advances only after the dependency publication step", () => {
  const result = runFixture({ scenario: "index-lag" });
  assert.equal(result.status, 0, result.stderr);
  const typePackages = result.calls.filter(
    (call) => call[1] === "package" && call[3] === "reallyme-openid4vp-types",
  );
  assert.equal(typePackages.length, 2);
  assert.ok(
    result.calls.findIndex(
      (call) => call[1] === "publish" && call[3] === "reallyme-openid4vp-dcql",
    ) < result.calls.indexOf(typePackages[0]),
  );
  assert.deepEqual(result.calls.filter((call) => call[0] === "wait"), [["wait", 15000]]);
});

test("publication retries when crates.io dependency resolution is briefly stale", () => {
  const result = runFixture({ scenario: "publish-index-lag" });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(
    result.calls.filter(
      (call) => call[1] === "publish" && call[3] === "reallyme-openid4vp-types",
    ).length,
    2,
  );
  assert.deepEqual(result.calls.filter((call) => call[0] === "wait"), [["wait", 15000]]);
});

test("partial publication recovery verifies existing bytes before continuing", () => {
  const result = runFixture({ scenario: "partial" });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.calls.filter((call) => call[0] === "curl").length, 3);
  assert.deepEqual(
    result.calls.filter((call) => call[1] === "publish").map((call) => call[3]),
    [
      "reallyme-openid4vp-proto",
      "reallyme-openid4vp-dcql",
      "reallyme-openid4vp-types",
    ],
  );
  assert.deepEqual(
    result.ledger.crates.map((entry) => entry.state),
    ["verified_existing", "verified_existing", "published"],
  );
});

test("archive drift between retries fails before a second upload", () => {
  const result = runFixture({ scenario: "tamper-retry" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /does not match the reviewed package archive/u);
  assert.equal(result.calls.filter((call) => call[1] === "publish").length, 1);
});

test("non-retryable publication errors fail immediately", () => {
  const result = runFixture({ scenario: "failure" });
  assert.equal(result.status, 101);
  assert.equal(result.calls.filter((call) => call[1] === "publish").length, 1);
  assert.equal(result.calls.filter((call) => call[0] === "wait").length, 0);
});

test("archive hash mismatch fails before the first upload", () => {
  const result = runFixture({ corruptChecksum: true });
  assert.equal(result.status, 1);
  assert.equal(result.calls.filter((call) => call[1] === "publish").length, 0);
});

test("publication fails before packaging when the registry credential is absent", () => {
  const result = runFixture({ registryToken: "" });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /registry credential/u);
  assert.ok(result.calls.every((call) => call[1] === "metadata"));
});

test("unapproved publishable crates fail before publication", () => {
  const result = runFixture({ extraPublishable: true });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /not in the approved publish set/u);
  assert.equal(result.calls.filter((call) => call[1] === "publish").length, 0);
});

test("approved crate versions and MSRV fail closed", () => {
  for (const fixture of [
    { version: "0.1.1" },
    { rustVersion: "1.97" },
  ]) {
    const result = runFixture({ mode: "order", ...fixture });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /approved crates\.io publish set validation failed/u);
  }
});

test("metadata enumeration cannot change the approved publish sequence", () => {
  const result = runFixture({ reorderIndependent: true });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.calls.filter((call) => call[1] === "publish").map((call) => call[3]),
    [
      "reallyme-openid4vp-proto",
      "reallyme-openid4vp-dcql",
      "reallyme-openid4vp-types",
    ]);
});

test("zero-major caret requirements match Cargo compatibility boundaries", () => {
  for (const [requirement, accepted] of [
    ["^0.1.0", true],
    ["=0.1.0", true],
    ["0.1.0", true],
    ["^0.0.1", false],
    ["^0.1.1", false],
    ["^0.2.0", false],
    ["^0.1.0junk", false],
  ]) {
    const result = runFixture({ mode: "order", requirement });
    assert.equal(result.status === 0, accepted, requirement);
    assert.ok(result.calls.every((call) => call[1] === "metadata"));
  }
});
