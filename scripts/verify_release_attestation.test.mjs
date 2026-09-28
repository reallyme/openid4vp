#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  ReleaseAttestationError,
  selectLatestPreflightRun,
  verifyAttestedCrateArchives,
  verifyAttestationDocument,
  verifyWorkflowRun,
  verifyReleaseAttestation,
} from "./verify_release_attestation.mjs";

const releaseSha = "a".repeat(40);
const expected = Object.freeze({
  repository: "reallyme/openid4vp",
  runId: 123,
  releaseSha,
  releaseVersion: "0.2.1",
});
const attestation = (overrides = {}) => ({
  schema: "reallyme.openid4vp.crates_preflight.v4",
  crates: [
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
  ].map((name, index) => ({
    file: `${name}-${expected.releaseVersion}.crate`,
    sha256: "bcdef0123456"[index].repeat(64),
    size: index + 1,
  })),
  prerequisites: {
    ci: 1001,
    fuzz: 1002,
    protobuf_ci: 1003,
    secret_scan: 1004,
  },
  repository: expected.repository,
  workflow: "crates-package-preflight.yml",
  run_id: expected.runId,
  run_attempt: 1,
  release_sha: releaseSha,
  version: expected.releaseVersion,
  ...overrides,
});
const workflowRun = (overrides = {}) => ({
  workflow_id: 456,
  id: expected.runId,
  event: "workflow_dispatch",
  head_branch: "main",
  head_sha: releaseSha,
  status: "completed",
  conclusion: "success",
  run_attempt: 1,
  path: ".github/workflows/crates-package-preflight.yml",
  ...overrides,
});
const listedWorkflowRun = (overrides = {}) => ({
  workflow_id: 456,
  id: expected.runId,
  event: "workflow_dispatch",
  head_branch: "main",
  head_sha: releaseSha,
  status: "completed",
  conclusion: "success",
  run_attempt: 1,
  path: ".github/workflows/crates-package-preflight.yml",
  display_title: `Crates package preflight ${expected.releaseVersion} @ ${releaseSha}`,
  ...overrides,
});

test("reviewed attestation accepts the exact run, SHA, and version", () => {
  assert.doesNotThrow(() => verifyAttestationDocument(attestation(), expected));
  assert.doesNotThrow(() =>
    verifyWorkflowRun(workflowRun(), {
      workflowId: 456,
      runId: expected.runId,
      releaseSha,
    }),
  );
});

test("attestation rejects mismatched inputs and unreviewed fields", () => {
  for (const candidate of [
    attestation({ version: "0.1.0" }),
    attestation({ release_sha: "b".repeat(40) }),
    attestation({ run_id: 124 }),
    attestation({ extra: true }),
  ]) {
    assert.throws(
      () => verifyAttestationDocument(candidate, expected),
      ReleaseAttestationError,
    );
  }
});

test("attestation rejects malformed, reordered, and mismatched crate evidence", () => {
  const validCrates = attestation().crates;
  for (const crates of [
    [],
    validCrates.slice(0, validCrates.length - 1),
    [{ ...validCrates[0], sha256: "bad" }, ...validCrates.slice(1)],
    [validCrates[1], validCrates[0], ...validCrates.slice(2)],
    [{ ...validCrates[0], file: "other.crate" }, ...validCrates.slice(1)],
    [{ ...validCrates[0], size: 0 }, ...validCrates.slice(1)],
  ]) {
    assert.throws(
      () => verifyAttestationDocument(attestation({ crates }), expected),
      ReleaseAttestationError,
    );
  }
});

test("attestation rejects missing, extra, and invalid prerequisite CI run IDs", () => {
  for (const prerequisites of [
    { ci: 1, fuzz: 2, protobuf_ci: 3 },
    { ci: 1, fuzz: 2, protobuf_ci: 3, secret_scan: 4, extra: 5 },
    { ci: 0, fuzz: 2, protobuf_ci: 3, secret_scan: 4 },
    { ci: 1, fuzz: "2", protobuf_ci: 3, secret_scan: 4 },
  ]) {
    assert.throws(
      () => verifyAttestationDocument(attestation({ prerequisites }), expected),
      ReleaseAttestationError,
    );
  }
});

test("reviewed crate archives must match the attested bytes, sizes, and file type", () => {
  const directory = mkdtempSync(join(tmpdir(), "openid4vp-attestation-test-"));
  try {
    const crates = attestation().crates.map((crate, index) => {
      const contents = Buffer.alloc(index + 1, index + 1);
      writeFileSync(join(directory, crate.file), contents);
      return {
        ...crate,
        sha256: createHash("sha256").update(contents).digest("hex"),
        size: contents.length,
      };
    });
    const document = attestation({ crates });
    assert.doesNotThrow(() => verifyAttestedCrateArchives(document, directory));

    writeFileSync(join(directory, crates[1].file), "tampered");
    assert.throws(
      () => verifyAttestedCrateArchives(document, directory),
      (error) =>
        error instanceof ReleaseAttestationError && error.code === "crate-archive-mismatch",
    );

    rmSync(join(directory, crates[1].file));
    symlinkSync(join(directory, crates[0].file), join(directory, crates[1].file));
    assert.throws(
      () => verifyAttestedCrateArchives(document, directory),
      ReleaseAttestationError,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("failed, rerun, wrong-branch, and wrong-workflow runs fail closed", () => {
  for (const candidate of [
    workflowRun({ conclusion: "failure" }),
    workflowRun({ run_attempt: 2 }),
    workflowRun({ head_branch: "feature" }),
    workflowRun({ workflow_id: 457 }),
    workflowRun({ path: ".github/workflows/other.yml@refs/heads/main" }),
  ]) {
    assert.throws(
      () =>
        verifyWorkflowRun(candidate, {
          workflowId: 456,
          runId: expected.runId,
          releaseSha,
        }),
      ReleaseAttestationError,
    );
  }
});

test("automatic resolution selects the latest exact successful preflight", () => {
  const latest = selectLatestPreflightRun(
    {
      workflow_runs: [
        listedWorkflowRun({ id: 121 }),
        listedWorkflowRun({ id: 123 }),
        listedWorkflowRun({ id: 124, head_sha: "b".repeat(40) }),
      ],
    },
    {
      workflowId: 456,
      releaseSha,
      releaseVersion: expected.releaseVersion,
    },
  );
  assert.equal(latest.id, 123);
});

test("newer failed, running, wrong-version, and rerun preflights fail closed", () => {
  const rejectedLatestRuns = [
    listedWorkflowRun({ id: 124, conclusion: "failure" }),
    listedWorkflowRun({ id: 124, conclusion: null, status: "in_progress" }),
    listedWorkflowRun({
      id: 124,
      display_title: `Crates package preflight 0.1.0 @ ${releaseSha}`,
    }),
    listedWorkflowRun({ id: 124, run_attempt: 2 }),
  ];
  for (const rejected of rejectedLatestRuns) {
    assert.throws(
      () =>
        selectLatestPreflightRun(
          { workflow_runs: [listedWorkflowRun({ id: 123 }), rejected] },
          {
            workflowId: 456,
            releaseSha,
            releaseVersion: expected.releaseVersion,
          },
        ),
      ReleaseAttestationError,
    );
  }
});

test("automatic resolution rejects missing and malformed workflow results", () => {
  for (const candidate of [{}, { workflow_runs: [] }, { workflow_runs: [null] }]) {
    assert.throws(
      () =>
        selectLatestPreflightRun(candidate, {
          workflowId: 456,
          releaseSha,
          releaseVersion: expected.releaseVersion,
        }),
      ReleaseAttestationError,
    );
  }
});

test("waiting rejects zero polling intervals before querying GitHub", () => {
  assert.throws(() => verifyReleaseAttestation({ env: {
    GITHUB_REPOSITORY: expected.repository,
    RELEASE_SHA: releaseSha,
    RELEASE_VERSION: expected.releaseVersion,
    GITHUB_SHA: releaseSha,
    GH_TOKEN: "test-placeholder",
    RELEASE_ATTESTATION_WAIT_SECONDS: "60",
    RELEASE_ATTESTATION_POLL_SECONDS: "0",
  } }), { name: "ReleaseAttestationError", code: "invalid-release-attestation-poll-seconds" });
});
