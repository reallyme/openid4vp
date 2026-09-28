#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ENVIRONMENT_NAME = "crates-io";
const MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024;
const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;

export class ReleaseEnvironmentError extends Error {
  constructor(code) {
    super(code);
    this.name = "ReleaseEnvironmentError";
    this.code = code;
  }
}

const fail = (code) => {
  throw new ReleaseEnvironmentError(code);
};

const isRecord = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);

export const verifyEnvironmentDocument = (value) => {
  if (
    !isRecord(value) ||
    value.name !== ENVIRONMENT_NAME ||
    !Array.isArray(value.protection_rules) ||
    !isRecord(value.deployment_branch_policy) ||
    value.deployment_branch_policy.protected_branches !== true ||
    value.deployment_branch_policy.custom_branch_policies !== false
  ) {
    fail("release-environment-is-not-protected");
  }
  const reviewerRule = value.protection_rules.find(
    (rule) => isRecord(rule) && rule.type === "required_reviewers",
  );
  if (
    !isRecord(reviewerRule) ||
    reviewerRule.prevent_self_review !== true ||
    !Array.isArray(reviewerRule.reviewers) ||
    reviewerRule.reviewers.length === 0 ||
    reviewerRule.reviewers.some(
      (entry) =>
        !isRecord(entry) ||
        (entry.type !== "User" && entry.type !== "Team") ||
        !isRecord(entry.reviewer) ||
        !Number.isSafeInteger(entry.reviewer.id) ||
        entry.reviewer.id < 1,
    )
  ) {
    fail("release-environment-review-is-not-protected");
  }
};

export const verifyReleaseEnvironment = ({ env = process.env } = {}) => {
  const repository = env.GITHUB_REPOSITORY;
  if (typeof repository !== "string" || !REPOSITORY_PATTERN.test(repository)) {
    fail("invalid-repository");
  }
  if (typeof env.GH_TOKEN !== "string" || env.GH_TOKEN.length === 0) {
    fail("missing-github-token");
  }
  const result = spawnSync(
    "gh",
    ["api", `repos/${repository}/environments/${ENVIRONMENT_NAME}`],
    {
      encoding: "utf8",
      maxBuffer: MAX_COMMAND_OUTPUT_BYTES,
      stdio: ["ignore", "pipe", "ignore"],
    },
  );
  if (result.error !== undefined || result.status !== 0 || typeof result.stdout !== "string") {
    fail("release-environment-query-failed");
  }
  let document;
  try {
    document = JSON.parse(result.stdout);
  } catch {
    fail("invalid-release-environment-response");
  }
  verifyEnvironmentDocument(document);
};

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  try {
    verifyReleaseEnvironment();
    console.log("protected release environment verified");
  } catch (error) {
    const code = error instanceof ReleaseEnvironmentError ? error.code : "unexpected-failure";
    console.error(`release environment verification failed: ${code}`);
    process.exit(1);
  }
}
