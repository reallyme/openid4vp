// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

const missingCommand = "openid4vp-deliberately-missing-ripgrep";

for (const script of [
  "scripts/check-rust-source-policy.sh",
  "scripts/check-zk-boundary-policy.sh",
  "scripts/check-formal-models.sh",
]) {
  test(`${script} fails closed without ripgrep`, () => {
    const result = spawnSync("/bin/bash", [script], {
      cwd: process.cwd(),
      encoding: "utf8",
      env: {
        ...process.env,
        OPENID4VP_RG_BIN: missingCommand,
      },
    });

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /ripgrep/i);
  });
}
