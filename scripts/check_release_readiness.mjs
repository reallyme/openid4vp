#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { OPENID4VP_SCALAR_FIELD_CLASSIFICATIONS } from "./proto-hardening/openid4vp-scalar-policy.mjs";

const coreUrl = process.env.RELEASE_READINESS_CORE_URL;
if (typeof coreUrl !== "string" || coreUrl.length === 0) {
  console.error("release readiness check failed: pinned core URL is unavailable");
  process.exit(1);
}
const { createReleaseReadinessContext } = await import(coreUrl);

const supportedArguments = new Set(["--generated-freshness", "--policy-only"]);
const suppliedArguments = process.argv.slice(2);
for (const argument of suppliedArguments) {
  if (!supportedArguments.has(argument)) {
    console.error(`release readiness check failed: unsupported argument ${argument}`);
    process.exit(2);
  }
}
if (new Set(suppliedArguments).size !== suppliedArguments.length) {
  console.error("release readiness check failed: duplicate arguments are not allowed");
  process.exit(2);
}
const generatedFreshnessMode = suppliedArguments.includes(
  "--generated-freshness",
);
if (generatedFreshnessMode && suppliedArguments.includes("--policy-only")) {
  console.error(
    "release readiness check failed: generated freshness and policy-only modes are mutually exclusive",
  );
  process.exit(2);
}
const generatedBuffaFiles = [
  "crates/proto/src/generated/buffa/mod.rs",
  "crates/proto/src/generated/buffa/reallyme.openid4vp.v1.mod.rs",
  "crates/proto/src/generated/buffa/reallyme.openid4vp.v1.openid4vp.rs",
  "crates/proto/src/generated/buffa/reallyme.openid4vp.v1.openid4vp.__oneof.rs",
  "crates/proto/src/generated/buffa/reallyme.openid4vp.v1.openid4vp.__view.rs",
  "crates/proto/src/generated/buffa/reallyme.openid4vp.v1.openid4vp.__view_oneof.rs",
];

const shared = createReleaseReadinessContext({
  scriptUrl: import.meta.url,
  requireTrackedFiles: true,
});

shared.assertReallyMeReleasePackagePolicy({
  scriptPath: "scripts/check_release_readiness.mjs",
  version: "0.6.6",
});
shared.assertWorkflowActionsPinned();
shared.assertNodeWorkflowJobsPinNode({ nodeVersion: "24" });
shared.assertCargoFuzzWorkflowPolicy({
  workflow: ".github/workflows/fuzz.yml",
  version: "0.13.2",
  minimumInstallations: 2,
  requiredInstallSteps: [
    { job: "build", name: "Install cargo-fuzz" },
    { job: "scheduled", name: "Install cargo-fuzz" },
  ],
});
shared.assertCargoWorkspacePolicy();
shared.assertRepositoryShapePolicy({
  archetype: "protocol-engine",
  requiredLanes: [
    "crates",
    "contracts",
    "conformance",
    "docs",
    "scripts",
    ".github",
  ],
  optionalLanes: ["vectors", "fuzz"],
  exceptions: [{ path: "formal", reason: "organization-specific" }],
  crates: [
    { path: "crates/openid4vp", role: "facade" },
    { path: "crates/proto", role: "proto" },
    { path: "crates/proto-codec", role: "proto-codec" },
    { path: "crates/types", role: "domain" },
    { path: "crates/dcql", role: "domain" },
    { path: "crates/verifier", role: "domain" },
    { path: "crates/wallet", role: "domain" },
    { path: "crates/dc-api", role: "adapter" },
    { path: "crates/formats", role: "adapter" },
    { path: "crates/profiles", role: "domain" },
    { path: "crates/runtime", role: "runtime" },
    { path: "crates/http", role: "transport" },
  ],
  subLanes: {},
  forbiddenPaths: [
    "COMPLIANCE_MAP.md",
    "CONTRACT.md",
    "PACKAGING.md",
    "PROTO_FIRST_REFACTOR_PLAN.md",
    "SPEC_MAP.md",
    "THREAT_MODEL.md",
    "crates/proto/openid4vp",
    "crates/proto/codec",
    "conformance/vectors",
  ],
  requireReleaseReadiness: true,
});
shared.assertRustSourcePolicy({
  roots: ["."],
  generatedPrefixes: ["crates/proto/src/generated"],
  baselinePath: null,
  productionTargetLines: 500,
  productionHardLines: 500,
  testTargetLines: 800,
  testHardLines: 800,
  moduleHardLines: 100,
  forbidWildcardImports: true,
  forbidInlineTests: true,
  forbidSubstantiveFacades: true,
  forbidPanickingProductionCode: true,
  forbidDynamicErrorSurfaces: true,
});
// This repository currently owns no TypeScript, Swift, or Kotlin source lanes.
// Add the corresponding source policy when one of those lanes is introduced.
shared.assertSpdxHeaders({
  exclusions: [{ path: "crates/proto/src/generated/buffa", reason: "generated" }],
  requireExclusionsMatched: true,
  requireExclusionReasons: true,
  license: "SPDX-License-Identifier: MIT OR Apache-2.0",
});
const generatedHardeningPolicy = {
  hardeningScript: "scripts/proto-hardening/core.mjs",
  protoSchema:
    "crates/proto/proto/reallyme/openid4vp/v1/openid4vp.proto",
  generatedRust:
    "crates/proto/src/generated/buffa/reallyme.openid4vp.v1.openid4vp.rs",
  generatedView:
    "crates/proto/src/generated/buffa/reallyme.openid4vp.v1.openid4vp.__view.rs",
  protoCargo: "crates/proto/Cargo.toml",
  requiredScriptNeedles: [
    "parseProtoContracts",
    "deserialize_zeroizing_bytes",
    "deserialize_zeroizing_string",
    "hardenOneofDeserializers",
    "hardenOneofs",
    "hardenViewOneofs",
    "scalarFieldClassifications",
  ],
  requiredCargoNeedles: ['"dep:zeroize"'],
  scalarFieldClassifications: OPENID4VP_SCALAR_FIELD_CLASSIFICATIONS,
  requiredGeneratedNeedles: [
    "deserialize_zeroizing_bytes",
    "deserialize_zeroizing_string",
    "impl ::core::ops::Drop for ZkPresentation",
    "__reallyme_zeroize_unknown_fields(&mut self.__buffa_unknown_fields);",
  ],
  forbiddenGeneratedNeedles: [
    '.field("proof", &self.proof)',
    '.field("public_inputs", &self.public_inputs)',
    "::buffa::alloc::format!(",
  ],
  requiredViewNeedles: [
    'formatter.write_str("ZkPresentationView(<redacted>)")',
    'formatter.write_str("ZkPresentationOwnedView(<redacted>)")',
  ],
  additionalGeneratedPolicies: [
    {
      path:
        "crates/proto/src/generated/buffa/reallyme.openid4vp.v1.openid4vp.__oneof.rs",
      required: [
        'formatter.write_str("Kind::Json(<redacted>)")',
        "impl ::core::ops::Drop for Kind",
        "Self::Json(value) => ::zeroize::Zeroize::zeroize(value)",
      ],
    },
    {
      path:
        "crates/proto/src/generated/buffa/reallyme.openid4vp.v1.openid4vp.__view_oneof.rs",
      required: ['formatter.write_str("KindView::Json(<redacted>)")'],
    },
    {
      path: "crates/proto/tests/generated_security_tests.rs",
      required: [
        "generated_zk_presentation_debug_output_is_redacted",
        "generated_oneof_json_debug_output_is_redacted",
        "generated_clear_removes_sensitive_byte_fields",
      ],
    },
  ],
};
shared.assertReallyMeProtobufReleasePolicy({
  buffaVersion: "0.9.2",
  generatedFreshnessMode,
  workflowMode: "delegated",
  generatedFreshnessStepRun:
    "node .release-readiness/scripts/run-consumer-check.mjs --generated-freshness",
  installBufUses:
    "bufbuild/buf-setup-action@a47c93e0b1648d5651a065437926377d060baa99",
  hardeningPolicy: generatedHardeningPolicy,
  generatedFreshness: {
    generatedPaths: ["crates/proto/src/generated/buffa"],
    commands: [
      ["buf", ["lint"]],
      ["buf", ["generate"]],
      ["node", ["scripts/harden-generated-openid4vp-proto.mjs"]],
      ["rustfmt", ["--edition", "2021", ...generatedBuffaFiles]],
      ["node", ["scripts/harden-generated-openid4vp-proto.mjs", "--check-idempotent"]],
    ],
  },
});
shared.assertContains(
  "scripts/harden-generated-openid4vp-proto.mjs",
  "hardenGeneratedProto({",
);
shared.assertContains(
  "scripts/harden-generated-openid4vp-proto.mjs",
  "OPENID4VP_SCALAR_FIELD_CLASSIFICATIONS",
);
shared.assertContains(
  "crates/proto-codec/src/encode_message.rs",
  ".with_unknown_field_limit(OPENID4VP_PROTO_UNKNOWN_FIELD_LIMIT)",
);
shared.assertContains(
  "crates/proto-codec/src/encode_message.rs",
  ".try_encode_bounded(max_bytes, &mut *bytes)",
);
shared.assertContains(
  "crates/proto-codec/src/encode_message.rs",
  "if !generated_proto_fits_message_budget(&message)",
);
shared.assertContains(
  "crates/proto-codec/src/encode_message.rs",
  "message.compute_size(&mut cache) <= max_bytes",
);
shared.assertContains(
  "crates/proto-codec/src/encode_message.rs",
  "let mut json_bytes = Zeroizing::new(Vec::new())",
);
shared.assertContains(
  "crates/proto-codec/src/encode_message.rs",
  "if !generated_proto_fits_message_budget(message)",
);
shared.assertContains(
  "crates/proto-codec/src/sensitive_json.rs",
  "let mut encoded = Zeroizing::new(Vec::new())",
);
shared.assertContains(
  "crates/proto-codec/tests/verify_codec.rs",
  "generated_proto_decode_rejects_unknown_fields",
);
shared.assertContains(
  ".gitleaksignore",
  "dacf7fbb55e538a2b06edb8a965e0fa2c2b1dc6f:conformance/oidf/configs/vp-wallet-test-config-dcql-sdjwt-haip.json:jwt:41",
);
const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const failures = [];

function readRepoFile(path) {
  return readFileSync(resolve(repoRoot, path), "utf8");
}

function recordFailure(message) {
  failures.push(message);
}

function requireText(path, requiredText, reason) {
  const text = readRepoFile(path);
  if (!text.includes(requiredText)) {
    recordFailure(`${path}: missing ${reason}`);
  }
}

function rejectText(path, rejectedText, reason) {
  const text = readRepoFile(path);
  if (text.includes(rejectedText)) {
    recordFailure(path + ": contains stale " + reason);
  }
}

function rejectExistingPath(path, reason) {
  if (existsSync(resolve(repoRoot, path))) {
    recordFailure(path + ": stale " + reason + " must not be checked in");
  }
}

function cargoMetadata() {
  const result = spawnSync("cargo", ["metadata", "--format-version", "1", "--no-deps"], {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    process.stderr.write(result.stderr);
    process.exit(result.status ?? 1);
  }
  return JSON.parse(result.stdout);
}

function isPublishablePackage(pkg) {
  return !(Array.isArray(pkg.publish) && pkg.publish.length === 0);
}

function parseVersion(version) {
  const parts = version.split(".");
  if (parts.length !== 3) {
    return null;
  }

  const parsed = parts.map((part) => Number.parseInt(part, 10));
  if (parsed.some((part) => !Number.isSafeInteger(part) || part < 0)) {
    return null;
  }

  return {
    major: parsed[0],
    minor: parsed[1],
    patch: parsed[2],
  };
}

function isCaretReqSatisfied(req, version) {
  if (!req.startsWith("^")) {
    return req === `=${version}` || req === version;
  }

  const minimum = parseVersion(req.slice(1));
  const actual = parseVersion(version);
  if (minimum === null || actual === null) {
    return false;
  }

  if (actual.major !== minimum.major) {
    return false;
  }

  if (minimum.major === 0 && actual.minor !== minimum.minor) {
    return false;
  }

  if (actual.minor < minimum.minor) {
    return false;
  }

  return actual.minor !== minimum.minor || actual.patch >= minimum.patch;
}

function checkWorkspacePackagePolicy(metadata) {
  const workspacePackageIds = new Set(metadata.workspace_members);
  const workspacePackages = metadata.packages.filter((pkg) => workspacePackageIds.has(pkg.id));
  const publishable = new Map();
  const approvedExternalPathDependencies = new Map();

  for (const pkg of workspacePackages) {
    const manifestPath = relative(repoRoot, pkg.manifest_path);
    const manifest = readFileSync(pkg.manifest_path, "utf8");

    if (!manifest.includes("[lints]\nworkspace = true")) {
      recordFailure(`${manifestPath}: member crate must inherit workspace lints`);
    }

    if (isPublishablePackage(pkg)) {
      publishable.set(pkg.name, pkg);
      if (!manifest.includes("include = [")) {
        recordFailure(`${manifestPath}: publishable crate must use an include allowlist`);
      }
    }
  }

  for (const pkg of publishable.values()) {
    for (const dep of pkg.dependencies) {
      if (dep.source !== null || typeof dep.path !== "string") {
        continue;
      }

      const depName = dep.package ?? dep.name;
      const target = publishable.get(depName);
      if (target === undefined) {
        const approvedPathSuffix = approvedExternalPathDependencies.get(depName);
        const normalizedPath = dep.path.replaceAll("\\", "/");
        if (
          approvedPathSuffix === undefined
          || !normalizedPath.endsWith(approvedPathSuffix)
          || !isCaretReqSatisfied(dep.req, "0.1.0")
        ) {
          recordFailure(`${pkg.name}: unapproved external path dependency ${depName}`);
        }
        continue;
      }

      if (!isCaretReqSatisfied(dep.req, target.version)) {
        recordFailure(
          `${pkg.name}: stale publishable path dependency ${depName} ${dep.req}; local version is ${target.version}`,
        );
      }
    }
  }
}

function checkRepositoryPolicy() {
  const workflowDirectory = ".github/workflows";
  for (const workflowName of readdirSync(resolve(repoRoot, workflowDirectory))) {
    if (!workflowName.endsWith(".yml") && !workflowName.endsWith(".yaml")) {
      continue;
    }

    const workflowPath = `${workflowDirectory}/${workflowName}`;
    rejectText(
      workflowPath,
      "reallyme/identity-taxonomy",
      "private identity-taxonomy CI dependency",
    );
    rejectText(
      workflowPath,
      "reallyme/identity-conformance",
      "private identity-conformance CI dependency",
    );
    rejectText(
      workflowPath,
      "REALLYME_CI_TOKEN",
      "private repository access credential",
    );
    rejectText(
      workflowPath,
      "repository: reallyme/ssi",
      "redundant SSI source checkout",
    );
  }

  for (const evidenceWorkflow of [
    ".github/workflows/ci.yml",
    ".github/workflows/fuzz.yml",
    ".github/workflows/protobuf-ci.yml",
    ".github/workflows/secret-scan.yml",
  ]) {
    rejectText(
      evidenceWorkflow,
      "paths:",
      "path-filtered exact-SHA release evidence workflow",
    );
    rejectText(
      evidenceWorkflow,
      "paths-ignore:",
      "path-filtered exact-SHA release evidence workflow",
    );
  }

  requireText(
    "rust-toolchain.toml",
    'channel = "1.98.1"',
    "pinned maintainer Rust toolchain",
  );
  requireText("Cargo.toml", 'rust-version = "1.96"', "public crate MSRV");
  for (const workflowPath of [
    ".github/workflows/conformance.yml",
    ".github/workflows/crates-package-preflight.yml",
    ".github/workflows/crates-release.yml",
    ".github/workflows/protobuf-ci.yml",
  ]) {
    requireText(workflowPath, "toolchain: 1.98.1", "pinned Rust 1.98.1 toolchain");
    rejectText(workflowPath, "toolchain: 1.96.0", "maintenance toolchain pinned to the MSRV");
  }
  requireText(
    ".github/workflows/ci.yml",
    "name: Public crates MSRV 1.96",
    "narrow public-crate MSRV job",
  );
  requireText(
    ".github/workflows/ci.yml",
    "toolchain: 1.98.1",
    "primary Rust 1.98.1 toolchain",
  );
  requireText(
    ".github/workflows/ci.yml",
    "toolchain: 1.96.0",
    "Rust 1.96 MSRV toolchain",
  );
  requireText(
    ".github/workflows/ci.yml",
    "cargo check --locked --all-features",
    "locked public-crate MSRV check",
  );
  for (const packageName of [
    "reallyme-openid4vp-proto",
    "reallyme-openid4vp-dcql",
    "reallyme-openid4vp-types",
  ]) {
    requireText(
      ".github/workflows/ci.yml",
      `-p ${packageName}`,
      `${packageName} MSRV coverage`,
    );
  }
  requireText(
    ".github/workflows/ci.yml",
    "targets: wasm32-unknown-unknown",
    "composed-Wasm compilation target",
  );
  requireText(
    ".github/workflows/ci.yml",
    "--no-default-features --features wasm",
    "feature-scoped composed-Wasm check",
  );
  rejectText(
    "conformance/Cargo.toml",
    "wasm =",
    "conformance-only Wasm feature",
  );
  requireText(
    "scripts/check-rust-packaging.sh",
    "ReallyMe Identity owns the combined Wasm module",
    "combined-Wasm ownership enforcement",
  );
  requireText(
    "scripts/check-rust-packaging.sh",
    'git ls-files -- \'*.wasm\' \'package.json\' \'*/package.json\'',
    "standalone Wasm and npm artifact rejection",
  );

  rejectExistingPath(
    "scripts/release-readiness",
    "vendored release-readiness core",
  );
  requireText(
    ".github/workflows/ci.yml",
    "bdedc88f3f25fcc14242730d4dec6ce6a0c75531",
    "release-readiness v0.6.6 commit pin",
  );
  requireText(
    ".github/workflows/protobuf-ci.yml",
    "bdedc88f3f25fcc14242730d4dec6ce6a0c75531",
    "protobuf release-readiness v0.6.6 commit pin",
  );
  requireText(
    "formal/README.md",
    "openid4vp_session_binding.spthy",
    "formal model inventory",
  );
  requireText(
    "formal/tamarin/openid4vp_session_binding.spthy",
    "lemma verifier_session_accepts_at_most_once",
    "verifier replay-resistance lemma",
  );
  requireText(
    "scripts/check-formal-models.sh",
    "openid4vp_session_binding.spthy",
    "formal model verification entry point",
  );
  requireText(
    ".github/workflows/ci.yml",
    "scripts/check-formal-models.sh",
    "formal model CI gate",
  );
  requireText(
    ".github/workflows/ci.yml",
    "tool: ripgrep@15.2.0",
    "pinned ripgrep version",
  );
  rejectText("Cargo.toml", "\n[package]\n", "non-virtual root package declaration");
  requireText("Cargo.toml", '"crates/openid4vp"', "facade workspace member");
  requireText(
    "crates/openid4vp/Cargo.toml",
    "publish = false",
    "facade publish=false",
  );
  requireText(
    "crates/openid4vp/Cargo.toml",
    'include = ["/src/**/*.rs", "/Cargo.toml", "/README.md"]',
    "facade package include allowlist",
  );
  requireText(
    "crates/openid4vp/Cargo.toml",
    "codec = [",
    "canonical generated SDK feature",
  );
  rejectText(
    "crates/openid4vp/Cargo.toml",
    "\nproto = [",
    "retired facade proto feature",
  );
  requireText("Cargo.toml", 'unsafe_code = "deny"', "unsafe_code deny lint");
  requireText(
    "Cargo.toml",
    'license = "MIT OR Apache-2.0"',
    "dual-license workspace metadata",
  );
  requireText("LICENSE-MIT", "MIT License", "root MIT license text");
  requireText("LICENSE-APACHE", "Apache License", "root Apache license text");
  requireText("README.md", "[MIT License](LICENSE-MIT)", "MIT license link");
  requireText(
    "README.md",
    "[Apache License, Version 2.0](LICENSE-APACHE)",
    "Apache license link",
  );
  requireText(
    "README.md",
    "crates.io version `0.3.3`",
    "current exact SSI dependency version",
  );
  rejectText(
    "README.md",
    "crates.io version `0.1.0`",
    "obsolete SSI dependency version",
  );
  requireText("Cargo.toml", 'unwrap_used = "deny"', "unwrap_used deny lint");
  requireText("Cargo.toml", 'expect_used = "deny"', "expect_used deny lint");
  requireText("Cargo.toml", 'panic = "deny"', "panic deny lint");
  requireText("Cargo.toml", 'wildcard_imports = "deny"', "wildcard_imports deny lint");
  requireText("Cargo.toml", 'buffa = { version = "0.9.2"', "Buffa dependency");
  rejectText("Cargo.toml", "connectrpc", "Connect dependency in the message workspace");
  rejectText(
    "crates/runtime/src/report_runtime_error.rs",
    "ConnectServer",
    "Connect-owned runtime error",
  );
  requireText("Cargo.toml", 'reallyme-jose = { version = "=0.4.0", default-features = false }', "registry ReallyMe jose dependency");
  requireText("Cargo.toml", 'reallyme-codec = { version = "=0.2.3", default-features = false }', "registry ReallyMe codec dependency");
  requireText("Cargo.toml", 'reallyme-crypto = { version = "=0.3.9", default-features = false }', "registry ReallyMe crypto dependency");
  requireText(
    "Cargo.toml",
    'reallyme-ssi-proto = { version = "=0.3.3", default-features = false }',
    "registry SSI canonical proto dependency",
  );
  rejectText(
    "Cargo.toml",
    "reallyme-credential =",
    "unused direct SSI credential dependency",
  );
  rejectText(
    "Cargo.toml",
    'reallyme-identity-common-proto',
    "retired SSI common proto package name",
  );
  requireText(
    "Cargo.toml",
    'reallyme-openid4vc-profiles = { version = "=0.3.3", default-features = false }',
    "registry shared OpenID4VC profiles dependency",
  );
  rejectText("Cargo.toml", 'path = "../ssi/', "SSI sibling dependency path");
  rejectText("Cargo.toml", 'path = "../identity/', "old identity sibling dependency path");
  requireText(
    "crates/dc-api/Cargo.toml",
    'reallyme-mdoc = { version = "=0.3.3", default-features = false }',
    "registry SSI mdoc dependency",
  );
  rejectText(
    "crates/dc-api/Cargo.toml",
    'path = "../../../ssi/',
    "SSI sibling dependency path",
  );
  rejectText(
    "crates/dc-api/Cargo.toml",
    'path = "../../../identity/',
    "old identity mdoc sibling dependency path",
  );
  requireText(
    "crates/formats/Cargo.toml",
    'reallyme-mdoc = { version = "=0.3.3", default-features = false }',
    "formats registry SSI mdoc dependency",
  );
  requireText(
    "crates/formats/Cargo.toml",
    'reallyme-sd-jwt = { version = "=0.3.3", default-features = false }',
    "formats registry SSI SD-JWT dependency",
  );
  rejectText(
    "crates/formats/Cargo.toml",
    'path = "../../../ssi/',
    "SSI sibling dependency path",
  );
  rejectText(
    "crates/formats/Cargo.toml",
    'path = "../../../identity/',
    "old formats identity mdoc sibling dependency path",
  );
  rejectText(
    ".github/workflows/ci.yml",
    "repository: reallyme/ssi",
    "redundant SSI source checkout",
  );
  if (existsSync(resolve(repoRoot, ".github/dependency-pins.json"))) {
    recordFailure("obsolete source dependency pins file must not return");
  }
  for (const workflow of [
    ".github/workflows/ci.yml",
    ".github/workflows/conformance.yml",
    ".github/workflows/fuzz.yml",
    ".github/workflows/crates-package-preflight.yml",
    ".github/workflows/crates-release.yml",
  ]) {
    rejectText(workflow, "repository: reallyme/zk", "ZK sibling checkout");
    rejectText(workflow, "source-pins", "obsolete source dependency pin step");
  }
  for (const manifest of [
    "Cargo.toml",
    "crates/formats/Cargo.toml",
    "crates/verifier/Cargo.toml",
    "crates/wallet/Cargo.toml",
    "crates/runtime/Cargo.toml",
  ]) {
    rejectText(manifest, "reallyme-zk", "ZK crate dependency");
  }
  rejectText(
    ".github/workflows/ci.yml",
    "REALLYME_CI_TOKEN",
    "private dependency access token",
  );
  rejectText(
    ".github/workflows/ci.yml",
    "gh repo clone reallyme/identity ../identity",
    "old identity sibling checkout",
  );
  rejectText(
    ".github/workflows/conformance.yml",
    "repository: reallyme/ssi",
    "redundant conformance SSI source checkout",
  );
  rejectText(
    ".github/workflows/conformance.yml",
    "REALLYME_CI_TOKEN",
    "private conformance dependency access token",
  );
  rejectText(
    ".github/workflows/conformance.yml",
    "gh repo clone reallyme/identity ../identity",
    "old conformance identity sibling checkout",
  );
  for (const dispatchEndpoint of [
    "inputs.verifier_launch_endpoint",
    "inputs.verifier_evidence_endpoint",
    "inputs.wallet_harness_endpoint",
  ]) {
    rejectText(
      ".github/workflows/conformance.yml",
      dispatchEndpoint,
      "dispatch-controlled credential-bearing conformance endpoint",
    );
  }
  rejectText("Cargo.toml", "[patch.crates-io]", "local crates.io patch bridge");
  rejectText("Cargo.toml", 'path = "../crypto"', "local ReallyMe crypto path dependency");
  rejectText("Cargo.toml", 'path = "../jose"', "local ReallyMe jose path dependency");
  rejectText("fuzz/Cargo.toml", "[patch.crates-io]", "fuzz local crates.io patch bridge");
  requireText("deny.toml", 'wildcards = "deny"', "cargo-deny wildcard dependency policy");
  requireText("deny.toml", 'unknown-registry = "deny"', "cargo-deny registry policy");
  requireText("deny.toml", 'unknown-git = "deny"', "cargo-deny git policy");
  requireText(
    "deny.toml",
    "allow-git = []",
    "Git dependency prohibition",
  );
  requireText("README.md", "OpenID4VP 1.0 final", "final-spec positioning");
  requireText("README.md", "conformance/README.md", "conformance runbook link");
  requireText(
    "conformance/README.md",
    "downstream `identity-conformance` orchestration",
    "downstream composed-conformance ownership",
  );
  rejectText(
    "conformance/README.md",
    "reallyme/openid-conformance",
    "old conformance repository name",
  );
  requireText(
    "README.md",
    "reallyme/release-readiness#bdedc88f3f25fcc14242730d4dec6ce6a0c75531",
    "pinned release-readiness validation command",
  );
  requireText("README.md", "docs/rust-publishing.md", "Rust publishing ownership documentation");
  requireText(
    "README.md",
    "ReallyMe Identity",
    "ReallyMe Identity composition boundary",
  );
  rejectText(
    "README.md",
    "https://github.com/reallyme/identity",
    "unpublished ReallyMe Identity repository link",
  );
  rejectText(
    "README.md",
    "https://github.com/reallyme/wallet",
    "unpublished ReallyMe Wallet repository link",
  );
  rejectText("README.md", "identity-sdk", "old Identity repository name");
  requireText("docs/rust-publishing.md", "reallyme-openid4vp-proto", "proto package ownership");
  requireText("docs/rust-publishing.md", "reallyme/identity", "platform package ownership");
  requireText(
    "docs/rust-publishing.md",
    "@reallyme/identity",
    "TypeScript package ownership",
  );
  rejectText(
    "docs/rust-publishing.md",
    "identity-sdk",
    "old Identity repository or package name",
  );
  requireText(
    "crates/proto/Cargo.toml",
    '"/tests/**/*"',
    "packaged generated security tests",
  );
  requireText(
    "vectors/README.md",
    "vectors/protojson",
    "root protocol-vector ownership",
  );
  requireText(
    "crates/proto-codec/tests/protojson_fixtures.rs",
    "protobuf_wire_fixtures_match_protojson_contracts",
    "protobuf and ProtoJSON golden parity test",
  );
  requireText(
    ".github/workflows/ci.yml",
    "node scripts/publish-crates-in-order.mjs inspect",
    "Rust package inspection CI gate",
  );
  for (const policyCommand of [
    "scripts/check-rust-source-policy.sh",
    "node scripts/check-ssi-remote-resolution.mjs",
    "node scripts/check-sdk-facade-inventory.mjs",
    "scripts/check-zk-boundary-policy.sh",
  ]) {
    requireText(
      ".github/workflows/ci.yml",
      policyCommand,
      `CI policy gate ${policyCommand}`,
    );
  }
  requireText(
    ".github/workflows/ci.yml",
    "cargo doc --locked --workspace --no-deps --all-features",
    "all-feature documentation gate",
  );
  requireText(
    ".github/workflows/ci.yml",
    "scripts/check-openid4vp-format.sh",
    "repository-scoped formatting CI gate",
  );
  requireText(
    ".github/workflows/ci.yml",
    "node --test scripts/*.test.mjs",
    "repository policy script test gate",
  );
  requireText(
    ".github/workflows/ci.yml",
    "group: ci-${{ github.ref }}",
    "superseded CI run cancellation",
  );
  rejectText(
    ".github/workflows/ci.yml",
    "scripts/run-fuzz-smoke.sh",
    "fuzz work duplicated outside the dedicated fuzz workflow",
  );
  rejectText(
    ".github/workflows/ci.yml",
    "cargo check --locked --workspace --all-features",
    "workspace check duplicated by all-targets Clippy",
  );
  requireText(
    ".github/workflows/ci.yml",
    "cargo deny --locked --manifest-path fuzz/Cargo.toml --config fuzz/deny.toml check",
    "fuzz-specific dependency-policy configuration",
  );
  requireText(
    ".github/workflows/ci.yml",
    "cargo deny --locked check",
    "locked dependency-policy resolution",
  );
  requireText(
    ".github/workflows/secret-scan.yml",
    "scripts/run-gitleaks.sh",
    "complete-history secret scan",
  );
  requireText(
    ".github/renovate.json",
    '"minimumReleaseAge": "7 days"',
    "dependency update stabilization window",
  );
  requireText(
    ".github/workflows/ci.yml",
    "scripts/audit_committed_lockfiles.sh",
    "committed lockfile advisory audit",
  );
  requireText(
    ".github/workflows/crates-package-preflight.yml",
    "name: Crates Package Preflight",
    "COSE-compatible package preflight button",
  );
  requireText(
    ".github/workflows/crates-package-preflight.yml",
    "run-name: Crates package preflight ${{ inputs.version }} @ ${{ github.sha }}",
    "commit-bound package preflight run name",
  );
  requireText(
    ".github/workflows/crates-package-preflight.yml",
    "default: 0.1.0",
    "package preflight version default",
  );
  requireText(
    ".github/workflows/crates-package-preflight.yml",
    "node scripts/verify_release_source.mjs",
    "release source verification",
  );
  requireText(
    ".github/workflows/crates-package-preflight.yml",
    "node scripts/verify_required_ci.mjs",
    "exact-commit required CI evidence",
  );
  requireText(
    ".github/workflows/ci.yml",
    "CARGO_SEMVER_CHECKS_VERSION: 0.50.0",
    "pinned public API compatibility tool",
  );
  requireText(
    ".github/workflows/ci.yml",
    "node scripts/check-published-semver.mjs",
    "registry-index-backed public API baseline resolution",
  );
  requireText(
    ".github/workflows/ci.yml",
    "cargo-semver-checks@${{ env.CARGO_SEMVER_CHECKS_VERSION }}",
    "pinned public API compatibility tool installation",
  );
  rejectText(
    ".github/workflows/crates-package-preflight.yml",
    "https://crates.io/api/v1/crates/",
    "unauthenticated crates.io HTTP metadata probe",
  );
  rejectText(
    ".github/workflows/crates-package-preflight.yml",
    "cargo-semver-checks",
    "public API review duplicated after exact-commit CI",
  );
  rejectText(
    ".github/workflows/crates-package-preflight.yml",
    "semver-checks",
    "public API review duplicated after exact-commit CI",
  );
  for (const duplicateGate of [
    "cargo clippy --locked --workspace",
    "cargo test --locked --workspace",
    "scripts/run-fuzz-smoke.sh",
    "--generated-freshness",
    "scripts/check-formal-models.sh",
    "cargo deny check",
  ]) {
    rejectText(
      ".github/workflows/crates-package-preflight.yml",
      duplicateGate,
      "release preflight duplicate of commit-bound CI",
    );
  }
  requireText(
    ".github/workflows/crates-package-preflight.yml",
    "node scripts/write_release_attestation.mjs",
    "reviewed package attestation",
  );
  requireText(
    ".github/workflows/crates-package-preflight.yml",
    "reallyme-openid4vp-crates-preflight-${{ inputs.version }}-${{ github.sha }}",
    "commit- and version-bound preflight artifact",
  );
  requireText(
    ".github/workflows/crates-package-preflight.yml",
    "reallyme-openid4vp-crate-archives-${{ inputs.version }}-${{ github.sha }}",
    "commit- and version-bound reviewed crate archives",
  );
  requireText(
    ".github/workflows/crates-package-preflight.yml",
    "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8",
    "reviewed release evidence provenance",
  );
  requireText(
    ".github/workflows/crates-release.yml",
    "name: Crates.io Release",
    "COSE-compatible crates.io release button",
  );
  requireText(
    ".github/workflows/crates-release.yml",
    "run-name: Crates.io release @ ${{ github.sha }}",
    "commit-bound crates.io release run name",
  );
  rejectText(
    ".github/workflows/crates-release.yml",
    "inputs.version",
    "release workflow version input",
  );
  requireText(
    ".github/workflows/crates-release.yml",
    "environment: crates-io",
    "protected crates.io release environment",
  );
  requireText(
    ".github/workflows/crates-release.yml",
    "publish:\n    name: Publish ReallyMe OpenID4VP crates\n    needs: [verify-preflight, prepare-source-release]",
    "publish job identity",
  );
  requireText(
    ".github/workflows/crates-release.yml",
    "    permissions:\n      actions: read\n      contents: read",
    "publish job cross-run artifact permission",
  );
  rejectText(
    ".github/workflows/crates-release.yml",
    "id-token: write",
    "crates.io trusted-publishing OIDC permission",
  );
  rejectText(
    ".github/workflows/crates-release.yml",
    "rust-lang/crates-io-auth-action",
    "crates.io trusted-publishing action",
  );
  rejectText(
    ".github/workflows/crates-release.yml",
    "bootstrap_first_publish",
    "bootstrap publishing mode",
  );
  rejectText(
    ".github/workflows/crates-release.yml",
    "CRATES_IO_BOOTSTRAP_TOKEN",
    "bootstrap crates.io credential",
  );
  requireText(
    ".github/workflows/crates-release.yml",
    "secrets.CARGO_REGISTRY_TOKEN",
    "protected crates.io environment secret",
  );
  requireText(
    ".github/workflows/crates-release.yml",
    "node scripts/verify_release_attestation.mjs",
    "reviewed preflight verification",
  );
  requireText(
    ".github/workflows/crates-release.yml",
    "node scripts/verify_release_environment.mjs",
    "protected release environment verification",
  );
  requireText(
    ".github/workflows/crates-release.yml",
    "node scripts/publish-crates-in-order.mjs publish",
    "dependency-ordered crates.io publication",
  );
  requireText(
    ".github/workflows/crates-release.yml",
    "gh attestation verify",
    "reviewed evidence provenance verification",
  );
  requireText(
    ".github/workflows/crates-release.yml",
    "REVIEWED_CRATE_DIRECTORY: reviewed-crates",
    "publication from reviewed archive bytes",
  );
  requireText(
    ".github/workflows/crates-release.yml",
    "PUBLICATION_LEDGER_PATH: ${{ runner.temp }}/crates-publication-ledger.json",
    "machine-readable partial publication ledger",
  );
  requireText(
    ".github/workflows/crates-release.yml",
    "prepare-source-release:",
    "immutable source identity before registry publication",
  );
  requireText(
    ".github/workflows/crates-release.yml",
    'tag="reallyme-openid4vp-v${RELEASE_VERSION}"',
    "immutable release tag",
  );
  rejectText(
    ".github/workflows/crates-release.yml",
    "git push",
    "credential-bearing Git push finalization",
  );
  requireText(
    "scripts/publish-crates-in-order.mjs",
    'const MODE_ORDER = "order";',
    "release order inspection mode",
  );
  requireText(
    "scripts/publish-crates-in-order.mjs",
    "const APPROVED_PUBLISH_SEQUENCE = [",
    "explicit crates.io publish set",
  );
  requireText(
    "scripts/publish-crates-in-order.mjs",
    'const APPROVED_MSRV = "1.96";',
    "public crate MSRV enforcement",
  );
  requireText(
    "scripts/publish-crates-in-order.mjs",
    "checkApprovedPublishSequence();",
    "exact crates.io publication order enforcement",
  );
  requireText(
    "scripts/publish-crates-in-order.mjs",
    '"--offline",\n    "--no-run"',
    "normalized package test compilation",
  );
  requireText(
    "scripts/publish-crates-in-order.mjs",
    "verifyPublishedPackageMatches(pkg, reviewed)",
    "idempotent archive verification",
  );
  requireText(
    "scripts/publish-crates-in-order.mjs",
    "reallyme.openid4vp.crates-publication-ledger.v1",
    "crates.io publication ledger schema",
  );
  requireText(
    "scripts/publish-crates-in-order.mjs",
    '"--locked", "--no-verify"',
    "credential-safe publication without build-script verification",
  );
  requireText(
    "scripts/verify_release_source.mjs",
    "main:refs/remotes/origin/main",
    "current-main release source binding",
  );
  requireText(
    "scripts/verify_required_ci.mjs",
    'const REQUIRED_WORKFLOWS = Object.freeze([',
    "required workflow evidence set",
  );
  requireText(
    "scripts/verify_required_ci.mjs",
    'run.path === `.github/workflows/${expected.workflowFile}`',
    "required CI workflow path binding",
  );
  requireText(
    "scripts/verify_required_ci.mjs",
    'run.headSha === expected.releaseSha',
    "required CI commit binding",
  );
  requireText(
    "scripts/verify_release_attestation.mjs",
    "value.run_attempt !== 1",
    "preflight rerun rejection",
  );
  requireText(
    "scripts/write_release_attestation.mjs",
    "reallyme.openid4vp.crates_preflight.v3",
    "OpenID4VP release attestation schema",
  );
  requireText(
    "scripts/write_release_attestation.mjs",
    'createHash("sha256")',
    "reviewed package archive hashes",
  );
  requireText(
    "docs/rust-publishing.md",
    "does not request an OIDC token and does not use crates.io Trusted Publishing",
    "token-based crates.io publishing documentation",
  );
  rejectExistingPath(
    ".github/workflows/release-preflight.yml",
    "legacy unbound release preflight",
  );
}

function checkDeletedDocumentationIsNotReferenced() {
  const publicFiles = [
    "README.md",
    "contracts/repository-contract.md",
    "contracts/compliance-map.md",
    "contracts/spec-map.md",
    "docs/threat-model.md",
    "docs/packaging.md",
    "conformance/README.md",
    "conformance/requirements/eudi-presentation.json",
  ];
  const deletedDocs = [
    "AGENTS.md",
    "IDENTITY_SDK_INTEGRATION.md",
    "JWE_DEPENDENCIES.md",
    "MEPROTO_PORT_AUDIT.md",
    "OPENID4VP_COMPLIANCE_CHECKLIST.md",
    "REFACTOR-BRIEF.md",
    "SDK_INTEGRATION.md",
    "SPEC_MAP.md",
    "TODO.md",
    "llms.txt",
    "openid4vp-considerations.md",
  ];

  rejectExistingPath("src", "root package source directory");
  rejectExistingPath("tests", "root package test directory");
  rejectExistingPath(
    "conformance/reports",
    "retained conformance evidence owned by identity-conformance",
  );
  rejectExistingPath("LICENSE", "single-license root file");
  rejectExistingPath("NOTICE", "repository NOTICE file");

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
    rejectExistingPath(`${crateDirectory}/LICENSE`, "per-crate license copy");
    rejectExistingPath(`${crateDirectory}/NOTICE`, "per-crate NOTICE file");
  }

  for (const publicCrateDirectory of [
    "crates/proto",
    "crates/dcql",
    "crates/types",
  ]) {
    requireText(
      `${publicCrateDirectory}/LICENSE-MIT`,
      "MIT License",
      "packaged MIT license text",
    );
    requireText(
      `${publicCrateDirectory}/LICENSE-APACHE`,
      "Apache License",
      "packaged Apache license text",
    );
    requireText(
      `${publicCrateDirectory}/Cargo.toml`,
      '"/LICENSE-MIT"',
      "MIT license package allowlist entry",
    );
    requireText(
      `${publicCrateDirectory}/Cargo.toml`,
      '"/LICENSE-APACHE"',
      "Apache license package allowlist entry",
    );
    if (
      readRepoFile(`${publicCrateDirectory}/LICENSE-MIT`)
      !== readRepoFile("LICENSE-MIT")
    ) {
      recordFailure(
        `${publicCrateDirectory}/LICENSE-MIT: must match the canonical root license`,
      );
    }
    if (
      readRepoFile(`${publicCrateDirectory}/LICENSE-APACHE`)
      !== readRepoFile("LICENSE-APACHE")
    ) {
      recordFailure(
        `${publicCrateDirectory}/LICENSE-APACHE: must match the canonical root license`,
      );
    }
  }

  for (const deletedDoc of deletedDocs) {
    rejectExistingPath(deletedDoc, "retired public documentation");
  }

  for (const path of publicFiles) {
    for (const deletedDoc of deletedDocs) {
      rejectText(path, deletedDoc, `deleted documentation reference ${deletedDoc}`);
    }
  }
}

const headerCheckedExtensions = new Set([
  ".mjs",
  ".proto",
  ".py",
  ".rs",
  ".sh",
  ".toml",
  ".yaml",
  ".yml",
]);

const headerCheckedNames = new Set([".gitignore"]);
const skippedDirectories = new Set([
  ".git",
  ".idea",
  ".vscode",
  "target",
  "node_modules",
  "corpus",
  "artifacts",
  "generated",
]);

function extensionOf(path) {
  const lastSlash = path.lastIndexOf("/");
  const fileName = lastSlash === -1 ? path : path.slice(lastSlash + 1);
  const lastDot = fileName.lastIndexOf(".");
  if (lastDot <= 0) {
    return "";
  }

  return fileName.slice(lastDot);
}

function shouldCheckHeader(relativePath) {
  const fileName = relativePath.slice(relativePath.lastIndexOf("/") + 1);
  return headerCheckedNames.has(fileName) || headerCheckedExtensions.has(extensionOf(relativePath));
}

function walkFiles(relativeDir) {
  const absoluteDir = resolve(repoRoot, relativeDir);
  const files = [];
  for (const entry of readdirSync(absoluteDir)) {
    if (skippedDirectories.has(entry)) {
      continue;
    }

    const relativePath = relativeDir === "" ? entry : `${relativeDir}/${entry}`;
    const absolutePath = resolve(repoRoot, relativePath);
    const stat = statSync(absolutePath);
    if (stat.isDirectory()) {
      files.push(...walkFiles(relativePath));
      continue;
    }

    if (stat.isFile()) {
      files.push(relativePath);
    }
  }

  return files;
}

function checkSpdxHeaders() {
  for (const path of walkFiles("")) {
    if ([".md", ".txt"].includes(extensionOf(path))) {
      const text = readRepoFile(path);
      if (
        text.includes("SPDX-FileCopyrightText:") ||
        text.includes("SPDX-License-Identifier:")
      ) {
        recordFailure(`${path}: documentation must not carry an SPDX header`);
      }
      continue;
    }
    if (!shouldCheckHeader(path)) {
      continue;
    }

    const text = readRepoFile(path);
    if (!text.includes("SPDX-FileCopyrightText: 2026 ReallyMe LLC")) {
      recordFailure(`${path}: missing ReallyMe SPDX copyright header`);
    }
    if (!text.includes("SPDX-License-Identifier: MIT OR Apache-2.0")) {
      recordFailure(`${path}: missing MIT OR Apache-2.0 SPDX license header`);
    }
  }
}

function checkFuzzTargetCoverage() {
  const fuzzCargo = readRepoFile("fuzz/Cargo.toml");
  const fuzzSmoke = readRepoFile("scripts/run-fuzz-smoke.sh");
  const fuzzWorkflow = readRepoFile(".github/workflows/fuzz.yml");
  const fuzzTargets = [...fuzzCargo.matchAll(/^name = "([^"]+)"$/gmu)]
    .map((match) => match[1])
    .filter((name) => name !== "openid4vp-fuzz")
    .sort();

  if (fuzzTargets.length === 0) {
    recordFailure("fuzz/Cargo.toml declares no fuzz targets");
    return;
  }

  for (const target of fuzzTargets) {
    if (!fuzzSmoke.includes(`"${target}"`)) {
      recordFailure(`scripts/run-fuzz-smoke.sh does not run fuzz target ${target}`);
    }
  }
  if (!fuzzWorkflow.includes("scripts/run-fuzz-smoke.sh")) {
    recordFailure(".github/workflows/fuzz.yml does not use the canonical fuzz target runner");
  }
  if (!fuzzWorkflow.includes('OPENID4VP_FUZZ_MAX_TOTAL_TIME: "300"')) {
    recordFailure(".github/workflows/fuzz.yml does not time-box scheduled fuzz targets");
  }
  if (fuzzWorkflow.includes("matrix.target")) {
    recordFailure(".github/workflows/fuzz.yml rebuilds the workspace once per fuzz target");
  }
  if (!fuzzSmoke.includes('fuzz build')) {
    recordFailure("scripts/run-fuzz-smoke.sh does not build the fuzz target set once");
  }
  if (fuzzSmoke.includes('fuzz run')) {
    recordFailure("scripts/run-fuzz-smoke.sh invokes Cargo once per fuzz target");
  }
}

const metadata = cargoMetadata();
checkRepositoryPolicy();
checkWorkspacePackagePolicy(metadata);
checkDeletedDocumentationIsNotReferenced();
checkSpdxHeaders();
checkFuzzTargetCoverage();

if (failures.length !== 0) {
  console.error("release readiness checks failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("release readiness checks passed");
