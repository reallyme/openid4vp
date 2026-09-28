#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  ReleaseSourceError,
  resolveReleaseVersion,
} from "./verify_release_source.mjs";

const publishableManifestCount = 12;
const manifestVersions = (version) => Array(publishableManifestCount).fill(version);

test("release version is derived only when every publishable crate agrees", () => {
  assert.equal(
    resolveReleaseVersion({
      derivesVersion: true,
      manifestVersions: manifestVersions("0.1.0"),
      requestedVersion: undefined,
    }),
    "0.1.0",
  );
  assert.throws(
    () =>
      resolveReleaseVersion({
        derivesVersion: true,
        manifestVersions: [...manifestVersions("0.1.0").slice(0, -1), "0.1.1"],
        requestedVersion: undefined,
      }),
    ReleaseSourceError,
  );
});

test("explicit preflight version remains bound to every crate manifest", () => {
  assert.equal(
    resolveReleaseVersion({
      derivesVersion: false,
      manifestVersions: manifestVersions("0.1.0"),
      requestedVersion: "0.1.0",
    }),
    "0.1.0",
  );
  for (const requestedVersion of [undefined, "v0.1.0", "0.1.1"]) {
    assert.throws(
      () =>
        resolveReleaseVersion({
          derivesVersion: false,
          manifestVersions: manifestVersions("0.1.0"),
          requestedVersion,
        }),
      ReleaseSourceError,
    );
  }
});
