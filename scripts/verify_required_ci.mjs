#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const FULL_SHA_PATTERN = /^[0-9a-f]{40}$/u;
const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const MAX_COMMAND_OUTPUT_BYTES = 1_048_576;
const REQUIRED_WORKFLOWS = Object.freeze([
  "ci.yml",
  "protobuf-ci.yml",
  "fuzz.yml",
  "secret-scan.yml",
]);
const REQUIRED_WORKFLOW_OUTPUTS = Object.freeze([
  "ci_run_id",
  "protobuf_ci_run_id",
  "fuzz_run_id",
  "secret_scan_run_id",
]);
const REQUIRED_EVENT = "push";

export class RequiredCiError extends Error {
  constructor(code) {
    super(code);
    this.name = "RequiredCiError";
    this.code = code;
  }
}

const fail = (code, workflowFile) => {
  throw new RequiredCiError(
    workflowFile === undefined ? code : `${code}:${workflowFile}`,
  );
};

const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

const runJson = (arguments_, code) => {
  const result = spawnSync("gh", arguments_, {
    encoding: "utf8",
    maxBuffer: MAX_COMMAND_OUTPUT_BYTES,
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (result.error !== undefined || result.status !== 0 || typeof result.stdout !== "string") {
    fail(code);
  }
  try {
    return JSON.parse(result.stdout);
  } catch {
    fail(code);
  }
};

const validateRun = (value) => {
  if (!isRecord(value)) {
    fail("invalid-required-ci-run-list");
  }
  const {
    conclusion,
    event,
    head_branch: headBranch,
    head_sha: headSha,
    id,
    path,
    run_attempt: runAttempt,
    status,
    workflow_id: workflowId,
  } = value;
  if (
    !Number.isSafeInteger(id) ||
    id < 1 ||
    !Number.isSafeInteger(workflowId) ||
    workflowId < 1 ||
    !Number.isSafeInteger(runAttempt) ||
    runAttempt < 1 ||
    typeof event !== "string" ||
    typeof headBranch !== "string" ||
    typeof headSha !== "string" ||
    typeof path !== "string" ||
    typeof status !== "string" ||
    (conclusion !== null && typeof conclusion !== "string")
  ) {
    fail("invalid-required-ci-run-list");
  }
  return {
    conclusion,
    event,
    headBranch,
    headSha,
    id,
    path,
    runAttempt,
    status,
    workflowId,
  };
};

export const selectRequiredCiRun = (value, expected) => {
  if (!isRecord(value) || !Array.isArray(value.workflow_runs)) {
    fail("invalid-required-ci-run-list");
  }
  const candidates = value.workflow_runs
    .map((run) => validateRun(run))
    .filter(
      (run) =>
        run.workflowId === expected.workflowId &&
        run.event === REQUIRED_EVENT &&
        run.headBranch === "main" &&
        run.headSha === expected.releaseSha &&
        run.path === `.github/workflows/${expected.workflowFile}`,
    )
    .sort((left, right) =>
      left.id === right.id ? right.runAttempt - left.runAttempt : right.id - left.id,
    );
  const latest = candidates[0];
  if (latest === undefined) {
    fail("missing-required-ci-run", expected.workflowFile);
  }
  if (latest.runAttempt !== 1) {
    fail("required-ci-rerun-not-accepted", expected.workflowFile);
  }
  if (latest.status !== "completed") {
    fail("required-ci-run-pending", expected.workflowFile);
  }
  if (latest.conclusion === "failure") {
    fail("required-ci-run-failed", expected.workflowFile);
  }
  if (latest.conclusion === "cancelled") {
    fail("required-ci-run-cancelled", expected.workflowFile);
  }
  if (latest.conclusion !== "success") {
    fail("required-ci-run-not-successful", expected.workflowFile);
  }
  return latest;
};

export const verifyRequiredCi = ({ env = process.env } = {}) => {
  const repository = env.GITHUB_REPOSITORY;
  const releaseSha = env.RELEASE_SHA;
  if (typeof repository !== "string" || !REPOSITORY_PATTERN.test(repository)) {
    fail("invalid-repository");
  }
  if (typeof releaseSha !== "string" || !FULL_SHA_PATTERN.test(releaseSha)) {
    fail("invalid-release-sha");
  }
  if (env.GITHUB_SHA !== releaseSha) {
    fail("workflow-head-mismatch");
  }
  if (typeof env.GH_TOKEN !== "string" || env.GH_TOKEN.length === 0) {
    fail("missing-github-token");
  }

  return REQUIRED_WORKFLOWS.map((workflowFile) => {
    const workflow = runJson(
      ["api", `repos/${repository}/actions/workflows/${workflowFile}`],
      `required-ci-workflow-query-failed:${workflowFile}`,
    );
    if (!isRecord(workflow) || !Number.isSafeInteger(workflow.id) || workflow.id < 1) {
      fail("invalid-required-ci-workflow-response", workflowFile);
    }
    const runs = runJson(
      [
        "api",
        `repos/${repository}/actions/workflows/${workflow.id}/runs?branch=main&head_sha=${releaseSha}&per_page=100`,
      ],
      `required-ci-run-list-query-failed:${workflowFile}`,
    );
    return selectRequiredCiRun(runs, {
      releaseSha,
      workflowFile,
      workflowId: workflow.id,
    });
  });
};

export const formatRequiredCiOutputs = (runs) => {
  if (!Array.isArray(runs) || runs.length !== REQUIRED_WORKFLOW_OUTPUTS.length) {
    fail("invalid-required-ci-output-set");
  }
  return runs
    .map((run, index) => {
      if (!isRecord(run) || !Number.isSafeInteger(run.id) || run.id < 1) {
        fail("invalid-required-ci-output-set");
      }
      return `${REQUIRED_WORKFLOW_OUTPUTS[index]}=${run.id}`;
    })
    .join("\n");
};

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  try {
    const runs = verifyRequiredCi();
    if (process.env.REQUIRED_CI_WRITE_GITHUB_OUTPUT === "1") {
      const outputPath = process.env.GITHUB_OUTPUT;
      if (typeof outputPath !== "string" || outputPath.length === 0) {
        fail("missing-github-output");
      }
      appendFileSync(outputPath, `${formatRequiredCiOutputs(runs)}\n`, {
        encoding: "utf8",
      });
    }
    console.log("exact release commit has successful required workflow evidence");
  } catch (error) {
    const code = error instanceof RequiredCiError ? error.code : "unexpected-failure";
    console.error(`required CI verification failed: ${code}`);
    process.exit(1);
  }
}
