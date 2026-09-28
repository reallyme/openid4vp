#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  formatRequiredCiOutputs,
  RequiredCiError,
  resolveRequiredCiWithWait,
  selectRequiredCiRun,
} from "./verify_required_ci.mjs";

const RELEASE_SHA = "0123456789abcdef0123456789abcdef01234567";
const WORKFLOW_ID = 41;
const WORKFLOW_FILE = "ci.yml";
const expected = {
  releaseSha: RELEASE_SHA,
  workflowFile: WORKFLOW_FILE,
  workflowId: WORKFLOW_ID,
};

const workflowRun = (overrides = {}) => ({
  conclusion: "success",
  event: "push",
  head_branch: "main",
  head_sha: RELEASE_SHA,
  id: 100,
  path: ".github/workflows/ci.yml",
  run_attempt: 1,
  status: "completed",
  workflow_id: WORKFLOW_ID,
  ...overrides,
});

test("accepts exact successful first-attempt push evidence", () => {
  const selected = selectRequiredCiRun(
    { workflow_runs: [workflowRun()] },
    expected,
  );
  assert.equal(selected.event, "push");
});

test("distinguishes failed, cancelled, pending, and rerun evidence", () => {
  for (const [latest, code] of [
    [workflowRun({ conclusion: "failure", id: 101 }), "required-ci-run-failed"],
    [workflowRun({ conclusion: "cancelled", id: 101 }), "required-ci-run-cancelled"],
    [workflowRun({ conclusion: null, id: 101, status: "in_progress" }), "required-ci-run-pending"],
    [workflowRun({ id: 101, run_attempt: 2 }), "required-ci-rerun-not-accepted"],
  ]) {
    assert.throws(
      () => selectRequiredCiRun({ workflow_runs: [workflowRun(), latest] }, expected),
      (error) => error instanceof RequiredCiError && error.code === `${code}:${WORKFLOW_FILE}`,
    );
  }
});

test("distinguishes missing exact-SHA evidence", () => {
  assert.throws(
    () => selectRequiredCiRun({ workflow_runs: [] }, expected),
    (error) =>
      error instanceof RequiredCiError &&
      error.code === `missing-required-ci-run:${WORKFLOW_FILE}`,
  );
});

test("rejects evidence from another workflow, branch, commit, or event", () => {
  const mismatches = [
    { workflow_id: WORKFLOW_ID + 1 },
    { path: ".github/workflows/fuzz.yml" },
    { head_branch: "release" },
    { head_sha: "fedcba9876543210fedcba9876543210fedcba98" },
    { event: "pull_request" },
  ];
  for (const mismatch of mismatches) {
    assert.throws(
      () =>
        selectRequiredCiRun(
          { workflow_runs: [workflowRun(mismatch)] },
          expected,
        ),
      RequiredCiError,
    );
  }
});

test("rejects malformed GitHub workflow responses", () => {
  for (const malformed of [
    null,
    {},
    { workflow_runs: "not-an-array" },
    { workflow_runs: [null] },
    { workflow_runs: [workflowRun({ id: "100" })] },
  ]) {
    assert.throws(
      () =>
        selectRequiredCiRun(malformed, {
          releaseSha: RELEASE_SHA,
          workflowFile: WORKFLOW_FILE,
          workflowId: WORKFLOW_ID,
        }),
      RequiredCiError,
    );
  }
});

test("serializes prerequisite workflow run IDs in the fixed attestation mapping", () => {
  assert.equal(
    formatRequiredCiOutputs([{ id: 11 }, { id: 12 }, { id: 13 }, { id: 14 }]),
    [
      "ci_run_id=11",
      "protobuf_ci_run_id=12",
      "fuzz_run_id=13",
      "secret_scan_run_id=14",
    ].join("\n"),
  );
  assert.throws(
    () => formatRequiredCiOutputs([{ id: 11 }]),
    (error) =>
      error instanceof RequiredCiError && error.code === "invalid-required-ci-output-set",
  );
});

test("bounded polling waits for pending exact-SHA workflow evidence", () => {
  let currentTime = 1_000;
  let attempts = 0;
  const sleeps = [];
  const expectedRuns = [{ id: 11 }, { id: 12 }, { id: 13 }, { id: 14 }];
  const resolved = resolveRequiredCiWithWait({
    pollSeconds: 20,
    releaseSha: RELEASE_SHA,
    repository: "reallyme/openid4vp",
    waitSeconds: 60,
    now: () => currentTime,
    resolve: () => {
      attempts += 1;
      if (attempts === 1) {
        throw new RequiredCiError("required-ci-run-pending:ci.yml");
      }
      if (attempts === 2) {
        throw new RequiredCiError("missing-required-ci-run:fuzz.yml");
      }
      return expectedRuns;
    },
    sleep: (seconds) => {
      sleeps.push(seconds);
      currentTime += seconds * 1_000;
    },
  });

  assert.equal(attempts, 3);
  assert.deepEqual(sleeps, [20, 20]);
  assert.equal(resolved, expectedRuns);
});

test("bounded polling fails immediately for terminal CI outcomes", () => {
  let sleeps = 0;
  assert.throws(
    () =>
      resolveRequiredCiWithWait({
        pollSeconds: 20,
        releaseSha: RELEASE_SHA,
        repository: "reallyme/openid4vp",
        waitSeconds: 60,
        resolve: () => {
          throw new RequiredCiError("required-ci-run-failed:ci.yml");
        },
        sleep: () => {
          sleeps += 1;
        },
      }),
    (error) =>
      error instanceof RequiredCiError && error.code === "required-ci-run-failed:ci.yml",
  );
  assert.equal(sleeps, 0);
});

test("bounded polling reports pending evidence when its deadline expires", () => {
  let currentTime = 1_000;
  const sleeps = [];
  assert.throws(
    () =>
      resolveRequiredCiWithWait({
        pollSeconds: 20,
        releaseSha: RELEASE_SHA,
        repository: "reallyme/openid4vp",
        waitSeconds: 30,
        now: () => currentTime,
        resolve: () => {
          throw new RequiredCiError("required-ci-run-pending:fuzz.yml");
        },
        sleep: (seconds) => {
          sleeps.push(seconds);
          currentTime += seconds * 1_000;
        },
      }),
    (error) =>
      error instanceof RequiredCiError && error.code === "required-ci-run-pending:fuzz.yml",
  );
  assert.deepEqual(sleeps, [20, 10]);
});
