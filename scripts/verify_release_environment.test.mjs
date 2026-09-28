#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  ReleaseEnvironmentError,
  verifyEnvironmentDocument,
} from "./verify_release_environment.mjs";

const protectedEnvironment = (overrides = {}) => ({
  name: "crates-io",
  protection_rules: [
    {
      type: "required_reviewers",
      prevent_self_review: true,
      reviewers: [{ type: "Team", reviewer: { id: 7 } }],
    },
  ],
  deployment_branch_policy: {
    protected_branches: true,
    custom_branch_policies: false,
  },
  ...overrides,
});

test("protected release environment accepts reviewers and protected branches", () => {
  assert.doesNotThrow(() => verifyEnvironmentDocument(protectedEnvironment()));
});

test("release environment fails closed without each required protection", () => {
  const rejected = [
    null,
    protectedEnvironment({ name: "production" }),
    protectedEnvironment({ protection_rules: [] }),
    protectedEnvironment({
      protection_rules: [
        { type: "required_reviewers", prevent_self_review: false, reviewers: [{}] },
      ],
    }),
    protectedEnvironment({
      protection_rules: [
        { type: "required_reviewers", prevent_self_review: true, reviewers: [] },
      ],
    }),
    protectedEnvironment({
      protection_rules: [
        { type: "required_reviewers", prevent_self_review: true, reviewers: [null] },
      ],
    }),
    protectedEnvironment({
      deployment_branch_policy: { protected_branches: false, custom_branch_policies: true },
    }),
  ];
  for (const candidate of rejected) {
    assert.throws(
      () => verifyEnvironmentDocument(candidate),
      ReleaseEnvironmentError,
    );
  }
});
