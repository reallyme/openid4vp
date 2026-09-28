#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  CHECK_IDEMPOTENT_ARGUMENT,
  hardenGeneratedProto,
} from "./proto-hardening/core.mjs";
import { OPENID4VP_SCALAR_FIELD_CLASSIFICATIONS } from "./proto-hardening/openid4vp-scalar-policy.mjs";

const supportedArguments = new Set([CHECK_IDEMPOTENT_ARGUMENT]);
const suppliedArguments = new Set();

function fail(message) {
  console.error(`generated OpenID4VP proto hardening failed: ${message}`);
  process.exit(1);
}

for (const argument of process.argv.slice(2)) {
  if (!supportedArguments.has(argument)) {
    fail(`unsupported argument ${argument}`);
  }
  if (suppliedArguments.has(argument)) {
    fail(`argument ${argument} was specified more than once`);
  }
  suppliedArguments.add(argument);
}

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const generatedRoot = resolve(
  root,
  "crates/proto/src/generated/buffa",
);
const generatedStem = "reallyme.openid4vp.v1.openid4vp";

hardenGeneratedProto({
  checkIdempotent: suppliedArguments.has(CHECK_IDEMPOTENT_ARGUMENT),
  failurePrefix: "generated OpenID4VP proto hardening failed",
  protoPath: resolve(
    root,
    "crates/proto/proto/reallyme/openid4vp/v1/openid4vp.proto",
  ),
  generatedPath: resolve(generatedRoot, `${generatedStem}.rs`),
  oneofPath: resolve(generatedRoot, `${generatedStem}.__oneof.rs`),
  viewPath: resolve(generatedRoot, `${generatedStem}.__view.rs`),
  viewOneofPath: resolve(generatedRoot, `${generatedStem}.__view_oneof.rs`),
  scalarFieldClassifications: OPENID4VP_SCALAR_FIELD_CLASSIFICATIONS,
  // The envelope contains sensitive nested messages even though its only
  // scalar field is a public format marker. Redact the complete borrowed view
  // so generated Debug output cannot expose proof-bundle structure.
  additionalSensitiveMessages: ["ZkPresentation"],
});
