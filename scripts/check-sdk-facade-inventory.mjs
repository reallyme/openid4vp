#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const facade = readFileSync(resolve(root, "crates/openid4vp/src/lib.rs"), "utf8");
const sdk = readFileSync(resolve(root, "crates/openid4vp/src/sdk.rs"), "utf8");
const manifest = readFileSync(resolve(root, "crates/openid4vp/Cargo.toml"), "utf8");
const failures = [];

const aliases = [
  ...facade.matchAll(/pub use reallyme_openid4vp_[a-z_]+ as ([a-z_]+);/gu),
].map((match) => match[1]);
if (facade.includes("pub mod policy;")) {
  aliases.push("policy");
}
if (facade.includes("pub mod sdk;")) {
  aliases.push("sdk");
}

const expected = [
  "dc_api",
  "dcql",
  "formats",
  "http",
  "policy",
  "profiles",
  "runtime",
  "sdk",
  "types",
  "verifier",
  "wallet",
];
const observed = [...new Set(aliases)].sort();
if (JSON.stringify(observed) !== JSON.stringify(expected)) {
  failures.push(
    `root facade changed; expected ${expected.join(", ")}, observed ${observed.join(", ")}`,
  );
}

if (!facade.includes("#[cfg(feature = \"codec\")]\npub mod sdk;")) {
  failures.push("canonical sdk module must remain gated by the codec feature");
}

for (const removed of [
  "pub use reallyme_openid4vp_proto as proto;",
  "pub use reallyme_openid4vp_proto_codec as proto_codec;",
]) {
  if (facade.includes(removed)) {
    failures.push(`deprecated root facade alias returned: ${removed}`);
  }
}
if (/^proto\s*=\s*\[/mu.test(manifest)) {
  failures.push("deprecated root proto feature returned; generated contracts belong under sdk");
}

for (const required of [
  "pub use reallyme_openid4vp_proto::generated as protobuf;",
  "execute_operation_v1",
  "execute_operation_json_v1",
  "openid4vp_proto_from_json",
  "openid4vp_proto_to_json",
  "OpenId4VpErrorReason",
  "IdentityStackError",
]) {
  if (!sdk.includes(required)) {
    failures.push(`crates/openid4vp/src/sdk.rs is missing canonical boundary ${required}`);
  }
}

for (const forbidden of [
  "reallyme_openid4vp_dc_api",
  "reallyme_openid4vp_dcql",
  "reallyme_openid4vp_formats",
  "reallyme_openid4vp_http",
  "reallyme_openid4vp_profiles",
  "reallyme_openid4vp_runtime",
  "reallyme_openid4vp_types",
  "reallyme_openid4vp_verifier",
  "reallyme_openid4vp_wallet",
  "serde_json::Value",
]) {
  if (sdk.includes(forbidden)) {
    failures.push(`crates/openid4vp/src/sdk.rs exposes non-generated DTO boundary ${forbidden}`);
  }
}

if (failures.length !== 0) {
  console.error("SDK facade inventory checks failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log(`SDK facade inventory checks passed for ${expected.length} root surfaces`);
