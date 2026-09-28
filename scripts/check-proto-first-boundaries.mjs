#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const failures = [];

function read(path) {
  return readFileSync(resolve(repoRoot, path), "utf8");
}

function requireText(path, needle) {
  if (!read(path).includes(needle)) {
    failures.push(`${path}: missing required proto-first marker ${JSON.stringify(needle)}`);
  }
}

function rejectText(path, needle) {
  if (read(path).includes(needle)) {
    failures.push(`${path}: forbidden proto-first boundary text ${JSON.stringify(needle)}`);
  }
}

function rustFiles(directory) {
  const absolute = resolve(repoRoot, directory);
  const files = [];
  for (const entry of readdirSync(absolute)) {
    const path = resolve(absolute, entry);
    const stat = statSync(path);
    if (stat.isDirectory()) {
      files.push(...rustFiles(`${directory}/${entry}`));
    } else if (entry.endsWith(".rs")) {
      files.push(`${directory}/${entry}`);
    }
  }
  return files;
}

function productionRustSource(path) {
  const source = read(path);
  const testModule = source.indexOf("#[cfg(test)]");
  return testModule === -1 ? source : source.slice(0, testModule);
}

function isSeparateRustTest(path) {
  const fileName = path.slice(path.lastIndexOf("/") + 1);
  return (
    path.includes("/tests/") ||
    fileName === "test.rs" ||
    fileName === "tests.rs" ||
    fileName.endsWith("_test.rs") ||
    fileName.endsWith("_tests.rs")
  );
}

function rejectDirectJsonCalls(paths, allowlist) {
  const forbidden = [
    "serde_json::from_",
    "serde_json::to_",
    "serde_json::json!",
  ];
  for (const path of paths) {
    if (allowlist.has(path) || isSeparateRustTest(path)) {
      continue;
    }
    const source = productionRustSource(path);
    for (const needle of forbidden) {
      if (source.includes(needle)) {
        failures.push(`${path}: direct JSON boundary call ${JSON.stringify(needle)}`);
      }
    }
  }
}

rejectText("Cargo.toml", "connectrpc");
rejectText("Cargo.toml", "\n[package]\n");
requireText("Cargo.toml", '"crates/openid4vp"');
requireText("crates/openid4vp/Cargo.toml", 'name = "reallyme-openid4vp"');
requireText("crates/openid4vp/Cargo.toml", "publish = true");
rejectText("crates/proto/Cargo.toml", "connectrpc");
rejectText("crates/runtime/Cargo.toml", "connectrpc");
rejectText("crates/runtime/src/report_runtime_error.rs", "ConnectServer");
rejectText("crates/runtime/src/map_runtime_error_reason.rs", "ConnectServer");
rejectText("buf.gen.yaml", "protoc-gen-connect");
requireText(
  "scripts/harden-generated-openid4vp-proto.mjs",
  'from "./proto-hardening/core.mjs"',
);
requireText("scripts/proto-hardening/core.mjs", "export function hardenGeneratedProto");
requireText("scripts/proto-hardening/core.mjs", "parseProtoContracts");
requireText("scripts/proto-hardening/README.md", "Sibling repositories");
rejectText(
  "crates/proto/proto/reallyme/openid4vp/v1/openid4vp.proto",
  "service OpenId4Vp",
);
requireText(
  "crates/proto/proto/reallyme/openid4vp/v1/openid4vp_service.proto",
  "service OpenId4VpVerifierService",
);

if (existsSync(resolve(repoRoot, "protos/reallyme/openid4vp/v1/openid4vp.proto"))) {
  failures.push("legacy protos/reallyme/openid4vp/v1/openid4vp.proto must not return");
}
if (existsSync(resolve(repoRoot, "crates/proto/openid4vp"))) {
  failures.push("legacy nested crates/proto/openid4vp directory must not return");
}
if (existsSync(resolve(repoRoot, "crates/proto/codec"))) {
  failures.push("legacy nested crates/proto/codec directory must not return");
}
if (existsSync(resolve(repoRoot, "crates/proto/src/generated/connect"))) {
  failures.push("message-only proto crate must not contain generated Connect Rust");
}
if (existsSync(resolve(repoRoot, "crates/proto-codec/tests/fixtures"))) {
  failures.push("shared contract fixtures must remain in the root vectors directory");
}
if (existsSync(resolve(repoRoot, "conformance/vectors"))) {
  failures.push("reusable protocol vectors must remain in the root vectors directory");
}
if (existsSync(resolve(repoRoot, "LICENSE"))) {
  failures.push("single-license root LICENSE file must not return");
}
if (existsSync(resolve(repoRoot, "NOTICE"))) {
  failures.push("repository NOTICE file must not return");
}
for (const crateDirectory of [
  "crates/openid4vp",
  "crates/proto",
  "crates/proto-codec",
  "crates/types",
  "crates/dcql",
  "crates/verifier",
  "crates/wallet",
  "crates/dc-api",
  "crates/formats",
  "crates/profiles",
  "crates/runtime",
  "crates/http",
]) {
  if (existsSync(resolve(repoRoot, crateDirectory, "LICENSE"))) {
    failures.push(`${crateDirectory}/LICENSE: per-crate license copy must not return`);
  }
  if (existsSync(resolve(repoRoot, crateDirectory, "NOTICE"))) {
    failures.push(`${crateDirectory}/NOTICE: per-crate NOTICE file must not return`);
  }
}

for (const vectorPath of [
  "vectors/openid4vp-malicious-json.json",
  "vectors/dc-api/openid4vp-browser-request.json",
  "vectors/mdoc/annex-b-handover.json",
]) {
  if (!existsSync(resolve(repoRoot, vectorPath))) {
    failures.push(`${vectorPath}: required reusable protocol vector is missing`);
  }
}

rejectDirectJsonCalls(
  rustFiles("crates/runtime/src"),
  new Set(),
);
rejectDirectJsonCalls(
  rustFiles("crates/proto-codec/src"),
  new Set([
    "crates/proto-codec/src/encode_message.rs",
    "crates/proto-codec/src/sensitive_json.rs",
  ]),
);
rejectDirectJsonCalls(
  rustFiles("crates/types/src"),
  new Set(["crates/types/src/transaction_data.rs"]),
);
rejectDirectJsonCalls(
  rustFiles("crates/dcql/src"),
  new Set(["crates/dcql/src/model.rs"]),
);
rejectDirectJsonCalls(
  rustFiles("crates/formats/src"),
  new Set(["crates/formats/src/zk_presentation.rs"]),
);
for (const directory of [
  "crates/dc-api/src",
  "crates/http/src",
  "crates/profiles/src",
  "crates/verifier/src",
  "crates/wallet/src",
]) {
  rejectDirectJsonCalls(rustFiles(directory), new Set());
}

requireText("crates/dcql/src/model.rs", "canonicalize_json_text");
requireText("crates/dcql/src/model.rs", "MAX_DCQL_JSON_BYTES");
requireText("crates/dcql/src/model.rs", "DuplicateJsonKey");
requireText("crates/dcql/src/model.rs", "impl ZeroizeOnDrop for DcqlQuery");
requireText("crates/types/src/transaction_data.rs", "canonicalize_json_text");
requireText("crates/types/src/transaction_data.rs", "canonicalize_trusted_json_value");
requireText("crates/types/src/transaction_data.rs", "MAX_TRANSACTION_DATA_JSON_BYTES");
requireText("crates/types/src/transaction_data.rs", "Zeroizing<Vec<u8>>");
rejectText("crates/types/src/transaction_data.rs", "fn canonicalize_json_with_depth");
rejectText("crates/types/src/transaction_data.rs", "serde_json::from_slice");
requireText(
  "crates/types/src/define_metadata.rs",
  "impl ZeroizeOnDrop for ClientMetadata",
);
requireText(
  "crates/types/src/request.rs",
  "impl ZeroizeOnDrop for AuthorizationRequestObject",
);
requireText("crates/formats/src/zk_presentation.rs", "validate_zk_presentation_shape");
requireText(
  "crates/proto/proto/reallyme/openid4vp/v1/openid4vp.proto",
  "ZkPresentation zk = 3;",
);
requireText("crates/formats/src/zk_presentation_types.rs", "impl ZeroizeOnDrop for ZkPresentation");
requireText(
  "crates/verifier/src/binding.rs",
  "impl ZeroizeOnDrop for RequestBinding",
);
requireText(
  "crates/verifier/src/holder_binding.rs",
  "impl ZeroizeOnDrop for HolderBindingClaims",
);
requireText(
  "crates/verifier/src/jar.rs",
  "impl ZeroizeOnDrop for CompactJwt",
);
requireText(
  "crates/verifier/src/session.rs",
  "impl ZeroizeOnDrop for SessionRecord",
);
requireText(
  "crates/wallet/src/transport.rs",
  "impl ZeroizeOnDrop for AuthorizationRequestTransport",
);
requireText(
  "crates/wallet/src/verify_nested_request_object_with_jose.rs",
  "Result<Zeroizing<Vec<u8>>, WalletError>",
);
requireText(
  "crates/http/src/build_request_uri_http_request.rs",
  "impl ZeroizeOnDrop for RequestUriHttpRequest",
);
requireText(
  "crates/http/src/resolve_request_uri.rs",
  "impl ZeroizeOnDrop for RequestObjectHttpResponse",
);
requireText(
  "crates/http/src/resolve_request_uri.rs",
  "impl ZeroizeOnDrop for RequestUriResolutionPolicy",
);
requireText(
  "crates/runtime/src/load_request_object.rs",
  "impl ZeroizeOnDrop for HostedRequestObject",
);
requireText(
  "crates/runtime/src/handle_authorization_request_launch.rs",
  "impl ZeroizeOnDrop for AuthorizationRequestLaunchHttpRequest",
);
requireText(
  "crates/runtime/src/prepare_authorization_request_launch.rs",
  "impl ZeroizeOnDrop for AuthorizationRequestLaunchRequest",
);
requireText(
  "crates/runtime/src/prepare_authorization_request_launch.rs",
  "impl ZeroizeOnDrop for AuthorizationRequestLaunch",
);
rejectText(
  "crates/runtime/src/route_verifier_http.rs",
  "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub enum VerifierHttpEndpoint",
);
for (const fixture of [
  "authorization-request.json",
  "authorization-response.json",
  "problem-details.json",
  "dc-api-request-options.json",
  "build-authorization-request.json",
  "validate-authorization-response.json",
  "malicious-duplicate-field.json",
  "malicious-unknown-enum.json",
]) {
  const path = `vectors/protojson/${fixture}`;
  if (!existsSync(resolve(repoRoot, path))) {
    failures.push(`${path}: required generated ProtoJSON fixture is missing`);
  }
}

for (const fixture of [
  "authorization-request.pb.hex",
  "authorization-response.pb.hex",
  "problem-details.pb.hex",
  "build-authorization-request.pb.hex",
]) {
  const path = `vectors/protobuf/${fixture}`;
  if (!existsSync(resolve(repoRoot, path))) {
    failures.push(`${path}: required protobuf wire fixture is missing`);
  }
}
requireText(
  "crates/proto-codec/tests/protojson_fixtures.rs",
  "protobuf_wire_fixtures_match_protojson_contracts",
);

for (const fuzzArtifact of [
  "fuzz/fuzz_targets/problem_details_proto_json.rs",
  "fuzz/fuzz_targets/service_envelope_proto_json.rs",
  "fuzz/corpus/problem_details_proto_json/problem-details.json",
  "fuzz/corpus/service_envelope_proto_json/build-authorization-request.json",
  "fuzz/corpus/service_envelope_proto_json/validate-authorization-response.json",
]) {
  if (!existsSync(resolve(repoRoot, fuzzArtifact))) {
    failures.push(`${fuzzArtifact}: required generated ProtoJSON fuzz artifact is missing`);
  }
}
requireText(
  "fuzz/fuzz_targets/problem_details_proto_json.rs",
  "pb::ProblemDetails",
);
requireText(
  "fuzz/fuzz_targets/service_envelope_proto_json.rs",
  "pb::BuildAuthorizationRequestRequest",
);
requireText("scripts/run-fuzz-smoke.sh", '"problem_details_proto_json"');
requireText("scripts/run-fuzz-smoke.sh", '"service_envelope_proto_json"');

for (const domainCrate of [
  "crates/types/src/lib.rs",
  "crates/dcql/src/lib.rs",
  "crates/dc-api/src/lib.rs",
  "crates/formats/src/lib.rs",
]) {
  requireText(domainCrate, "Serde implementations in this crate");
  requireText(domainCrate, "SDK DTO contracts");
}
requireText("README.md", "Generated protobuf messages and generated ProtoJSON");
requireText("README.md", "[MIT License](LICENSE-MIT)");
requireText("README.md", "[Apache License, Version 2.0](LICENSE-APACHE)");
requireText("Cargo.toml", 'license = "MIT OR Apache-2.0"');
requireText("LICENSE-MIT", "MIT License");
requireText("LICENSE-APACHE", "Apache License");
requireText("README.md", "docs/rust-publishing.md");
requireText("README.md", "ReallyMe Identity");
rejectText("README.md", "https://github.com/reallyme/identity");
rejectText("README.md", "https://github.com/reallyme/wallet");
rejectText("README.md", "identity-sdk");
requireText("conformance/README.md", "downstream `identity-conformance` orchestration");
rejectText("conformance/README.md", "reallyme/openid-conformance");
requireText(
  ".github/workflows/ci.yml",
  "node scripts/publish-crates-in-order.mjs inspect",
);
requireText(
  ".github/workflows/crates-package-preflight.yml",
  "node scripts/publish-crates-in-order.mjs inspect",
);
requireText(
  ".github/workflows/ci.yml",
  "scripts/check-openid4vp-format.sh",
);
requireText("scripts/check-openid4vp-format.sh", "reallyme-openid4vp-conformance");
requireText(
  "docs/rust-publishing.md",
  "node scripts/publish-crates-in-order.mjs inspect --allow-dirty",
);
requireText("scripts/publish-crates-in-order.mjs", '"--locked"');
requireText("docs/rust-publishing.md", "reallyme-openid4vp-proto");
requireText("docs/rust-publishing.md", "reallyme/identity");
requireText("docs/rust-publishing.md", "@reallyme/identity");
rejectText("docs/rust-publishing.md", "identity-sdk");
requireText("docs/rust-publishing.md", "The approved release set is");
requireText("docs/platform-binding-contract.md", "vectors/protobuf");
for (const publishableCrate of [
  "crates/dcql/Cargo.toml",
  "crates/types/Cargo.toml",
  "crates/proto/Cargo.toml",
  "crates/dc-api/Cargo.toml",
  "crates/formats/Cargo.toml",
  "crates/wallet/Cargo.toml",
  "crates/profiles/Cargo.toml",
  "crates/verifier/Cargo.toml",
  "crates/http/Cargo.toml",
  "crates/proto-codec/Cargo.toml",
  "crates/runtime/Cargo.toml",
  "crates/openid4vp/Cargo.toml",
]) {
  requireText(publishableCrate, "publish = true");
}
requireText("conformance/Cargo.toml", "publish = false");
requireText("fuzz/Cargo.toml", "publish = false");

if (failures.length !== 0) {
  console.error("proto-first boundary checks failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("proto-first boundary checks passed");
