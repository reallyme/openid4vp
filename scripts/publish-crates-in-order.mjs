// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  readAttestation,
  verifyAttestedCrateArchives,
  verifyAttestationDocument,
} from "./verify_release_attestation.mjs";

const MODE_INSPECT = "inspect";
const MODE_ORDER = "order";
const MODE_PUBLISH = "publish";
const MAX_PUBLISH_ATTEMPTS = 12;
const CRATES_IO_DEFAULT_RATE_LIMIT_RETRY_MS = 60000;
const CRATES_IO_INDEX_RETRY_BASE_MS = 15000;
const CRATES_IO_ARCHIVE_VERIFY_RETRIES = "12";
const CRATES_IO_ARCHIVE_VERIFY_RETRY_DELAY_SECONDS = "10";
const CRATES_IO_ARCHIVE_VERIFY_MAX_SECONDS = "180";
const APPROVED_PUBLISH_SEQUENCE = [
  { name: "reallyme-openid4vp-proto", version: "0.1.1" },
  { name: "reallyme-openid4vp-dcql", version: "0.1.1" },
  { name: "reallyme-openid4vp-types", version: "0.1.1" },
  { name: "reallyme-openid4vp-dc-api", version: "0.1.1" },
  { name: "reallyme-openid4vp-formats", version: "0.1.1" },
  { name: "reallyme-openid4vp-wallet", version: "0.1.1" },
];
const APPROVED_MSRV = "1.96";
const REQUIRED_PUBLISH_ORDER_EDGES = [
  ["reallyme-openid4vp-dcql", "reallyme-openid4vp-types"],
  ["reallyme-openid4vp-types", "reallyme-openid4vp-dc-api"],
  ["reallyme-openid4vp-types", "reallyme-openid4vp-formats"],
  ["reallyme-openid4vp-dc-api", "reallyme-openid4vp-wallet"],
  ["reallyme-openid4vp-formats", "reallyme-openid4vp-wallet"],
];
const args = process.argv.slice(2);
const mode = args[0] ?? MODE_INSPECT;
const allowDirty = args.includes("--allow-dirty");
const unknownArgs = args.slice(1).filter((arg) => arg !== "--allow-dirty");
const releaseVersion = process.env.RELEASE_VERSION ?? "";
const releaseSha = process.env.RELEASE_SHA ?? "";
const publicationLedgerPath = process.env.PUBLICATION_LEDGER_PATH ?? "";
const reviewedCrateDirectory = process.env.REVIEWED_CRATE_DIRECTORY ?? "";
const releaseAttestationPath =
  process.env.RELEASE_ATTESTATION_PATH ?? "release-attestation/crates-preflight.json";

if (
  (mode !== MODE_INSPECT && mode !== MODE_ORDER && mode !== MODE_PUBLISH) ||
  unknownArgs.length !== 0
) {
  console.error(
    `usage: node scripts/publish_crates_in_order.mjs ${MODE_INSPECT}|${MODE_ORDER}|${MODE_PUBLISH} [--allow-dirty]`,
  );
  process.exit(2);
}

if (allowDirty && mode !== MODE_INSPECT && mode !== MODE_ORDER) {
  console.error("--allow-dirty is only supported for local package inspection and order checks");
  process.exit(2);
}

if (mode === MODE_PUBLISH && releaseVersion.length === 0) {
  console.error("RELEASE_VERSION must be set when publishing crates.");
  process.exit(2);
}

if (
  mode === MODE_PUBLISH &&
  (!/^[0-9a-f]{40}$/u.test(releaseSha) ||
    publicationLedgerPath.length === 0 ||
    reviewedCrateDirectory.length === 0 ||
    typeof process.env.CARGO_REGISTRY_TOKEN !== "string" ||
    process.env.CARGO_REGISTRY_TOKEN.length === 0)
) {
  console.error(
    "Release identity, reviewed archives, publication ledger, and registry credential are required.",
  );
  process.exit(2);
}

if (releaseVersion.length !== 0 && !/^[0-9]+[.][0-9]+[.][0-9]+$/u.test(releaseVersion)) {
  console.error("RELEASE_VERSION must be an exact semver release such as 0.1.0.");
  process.exit(2);
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    stdio: options.capture ? "pipe" : "inherit",
  });
  if (result.error) {
    throw result.error;
  }
  return result;
}

function sleepMs(delayMs) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, delayMs);
}

function retryAfterMs(output) {
  const match = /try again after ([^\n.]+ GMT)/i.exec(output);
  if (!match) {
    return null;
  }

  const retryAt = Date.parse(match[1]);
  if (!Number.isFinite(retryAt)) {
    return null;
  }

  const delayMs = retryAt - Date.now() + 10000;
  return Math.max(delayMs, 10000);
}

const metadataResult = run(
  "cargo",
  ["metadata", "--locked", "--format-version", "1", "--no-deps"],
  {
    capture: true,
  },
);

if (metadataResult.status !== 0) {
  process.stderr.write(metadataResult.stderr);
  process.exit(metadataResult.status ?? 1);
}

const metadata = JSON.parse(metadataResult.stdout);
const packageDirectory = path.join(metadata.target_directory, "package");

function parsePositiveInteger(value) {
  if (typeof value !== "string" || !/^[1-9][0-9]*$/u.test(value)) {
    return null;
  }
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

function isPublishablePackage(pkg) {
  return !(Array.isArray(pkg.publish) && pkg.publish.length === 0);
}

const publishable = new Map();
for (const pkg of metadata.packages) {
  if (isPublishablePackage(pkg)) {
    publishable.set(pkg.name, pkg);
  }
}

function checkApprovedPublishSet() {
  const approvedByName = new Map(
    APPROVED_PUBLISH_SEQUENCE.map((approved) => [approved.name, approved]),
  );
  const failures = [];

  for (const pkg of publishable.values()) {
    if (!approvedByName.has(pkg.name)) {
      failures.push(`${pkg.name} is publishable but is not in the approved publish set`);
    }
  }

  for (const approved of APPROVED_PUBLISH_SEQUENCE) {
    const pkg = publishable.get(approved.name);
    if (pkg === undefined) {
      failures.push(`${approved.name} must be publishable`);
      continue;
    }
    if (pkg.version !== approved.version) {
      failures.push(`${pkg.name} is ${pkg.version}; approved version is ${approved.version}`);
    }
    if (pkg.rust_version !== APPROVED_MSRV) {
      failures.push(`${pkg.name} rust-version is ${pkg.rust_version ?? "unset"}; expected ${APPROVED_MSRV}`);
    }
  }

  if (failures.length !== 0) {
    console.error("approved crates.io publish set validation failed:");
    for (const failure of failures) {
      console.error(`- ${failure}`);
    }
    process.exit(1);
  }
}

function dependencyPackageName(dep) {
  return dep.package ?? dep.name;
}

function isWorkspacePathDependency(dep) {
  return (
    dep.source === null &&
    typeof dep.path === "string" &&
    publishable.has(dependencyPackageName(dep))
  );
}

function isPublishOrderingDependency(dep) {
  // crates.io resolves normalized dev-dependencies while validating an upload,
  // so public path-based test dependencies must be available first as well.
  return isWorkspacePathDependency(dep);
}

function parseVersion(version) {
  const parts = version.split(".");
  if (!/^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u.test(version)) {
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

  // Cargo keeps ^0.0.x within that exact patch release.
  if (minimum.major === 0 && minimum.minor === 0 && actual.patch !== minimum.patch) {
    return false;
  }

  if (actual.minor < minimum.minor) {
    return false;
  }

  if (actual.minor === minimum.minor && actual.patch < minimum.patch) {
    return false;
  }

  return true;
}

function checkPathDependencyVersions() {
  const failures = [];
  for (const pkg of publishable.values()) {
    for (const dep of pkg.dependencies) {
      if (!isPublishOrderingDependency(dep)) {
        continue;
      }

      const target = publishable.get(dependencyPackageName(dep));
      if (!isCaretReqSatisfied(dep.req, target.version)) {
        failures.push(
          `${pkg.name} depends on ${dep.name} with ${dep.req}; local version is ${target.version}`,
        );
      }
    }
  }

  if (failures.length !== 0) {
    console.error("publishable workspace path dependency versions are stale:");
    for (const failure of failures) {
      console.error(`- ${failure}`);
    }
    process.exit(1);
  }
}

function checkReleaseVersion() {
  if (releaseVersion.length === 0) {
    return;
  }

  const failures = [];
  for (const pkg of publishable.values()) {
    if (pkg.version !== releaseVersion) {
      failures.push(`${pkg.name} is ${pkg.version}; expected ${releaseVersion}`);
    }
  }
  if (failures.length !== 0) {
    console.error("publishable crate versions do not match RELEASE_VERSION:");
    for (const failure of failures) {
      console.error(`- ${failure}`);
    }
    process.exit(1);
  }
}

const visiting = new Set();
const visited = new Set();
const ordered = [];

checkApprovedPublishSet();

function visit(pkg) {
  if (visited.has(pkg.name)) {
    return;
  }
  if (visiting.has(pkg.name)) {
    console.error(`workspace publish dependency cycle at ${pkg.name}`);
    process.exit(1);
  }

  visiting.add(pkg.name);
  for (const dep of pkg.dependencies) {
    const depName = dependencyPackageName(dep);
    if (isPublishOrderingDependency(dep) && publishable.has(depName)) {
      visit(publishable.get(depName));
    }
  }
  visiting.delete(pkg.name);
  visited.add(pkg.name);
  ordered.push(pkg);
}

for (const pkg of publishable.values()) {
  visit(pkg);
}

const approvedOrderIndex = new Map(
  APPROVED_PUBLISH_SEQUENCE.map((pkg, index) => [pkg.name, index]),
);
ordered.sort(
  (left, right) => approvedOrderIndex.get(left.name) - approvedOrderIndex.get(right.name),
);

console.log(`Publish order (${ordered.length} crates):`);
for (const pkg of ordered) {
  console.log(`- ${pkg.name} ${pkg.version}`);
}

function checkRequiredPublishOrderEdges() {
  const failures = [];
  const orderedPackageNames = new Set(orderedIndexByName.keys());

  for (const pkg of ordered) {
    const packageIndex = orderedIndexByName.get(pkg.name);
    for (const dep of pkg.dependencies) {
      const dependencyName = dependencyPackageName(dep);
      if (!isPublishOrderingDependency(dep)) {
        continue;
      }
      const dependencyIndex = orderedIndexByName.get(dependencyName);
      if (
        dependencyIndex === undefined ||
        packageIndex === undefined ||
        dependencyIndex >= packageIndex
      ) {
        failures.push(`${dependencyName} must publish before ${pkg.name}`);
      }
    }
  }

  for (const [dependencyName, packageName] of REQUIRED_PUBLISH_ORDER_EDGES) {
    const dependencyIndex = orderedIndexByName.get(dependencyName);
    const packageIndex = orderedIndexByName.get(packageName);
    if (dependencyIndex === undefined || packageIndex === undefined) {
      failures.push(`${dependencyName} before ${packageName} cannot be checked; package is missing`);
      continue;
    }

    if (dependencyIndex >= packageIndex) {
      failures.push(`${dependencyName} must publish before ${packageName}`);
    }
  }

  if (failures.length !== 0) {
    console.error(
      `publishable packages discovered: ${[...orderedPackageNames].sort().join(", ")}`,
    );
    console.error("required publish dependency order is not satisfied:");
    for (const failure of failures) {
      console.error(`- ${failure}`);
    }
    process.exit(1);
  }
}

function checkApprovedPublishSequence() {
  const actual = ordered.map((pkg) => pkg.name);
  const expected = APPROVED_PUBLISH_SEQUENCE.map((pkg) => pkg.name);
  if (
    actual.length !== expected.length ||
    actual.some((name, index) => name !== expected[index])
  ) {
    console.error(`approved publish order is ${expected.join(", ")}`);
    console.error(`discovered publish order is ${actual.join(", ")}`);
    process.exit(1);
  }
}

const orderedIndexByName = new Map();
ordered.forEach((pkg, index) => {
  orderedIndexByName.set(pkg.name, index);
});

checkPathDependencyVersions();
checkRequiredPublishOrderEdges();
checkApprovedPublishSequence();
checkReleaseVersion();

if (mode === MODE_ORDER) {
  process.exit(0);
}

const unpackDirectory = path.join(packageDirectory, "release-preflight");

if (mode === MODE_INSPECT) {
  // Package the reviewed release set as one workspace operation so Cargo can
  // normalize dependencies whose earlier versions are not in the registry yet.
  const packageArgs = ["package", "--workspace", "--no-verify", "--locked"];
  for (const pkg of metadata.packages) {
    if (!publishable.has(pkg.name)) {
      packageArgs.push("--exclude", pkg.name);
    }
  }
  if (allowDirty) {
    packageArgs.push("--allow-dirty");
  }
  const packageResult = run("cargo", packageArgs);
  if (packageResult.status !== 0) {
    process.exit(packageResult.status ?? 1);
  }

  fs.rmSync(unpackDirectory, { force: true, recursive: true });
  fs.mkdirSync(unpackDirectory, { recursive: true });
  for (const pkg of ordered) {
    const archive = path.join(packageDirectory, `${pkg.name}-${pkg.version}.crate`);
    const extractResult = run("tar", ["-xzf", archive, "-C", unpackDirectory]);
    if (extractResult.status !== 0) {
      process.exit(extractResult.status ?? 1);
    }
  }
}

function unresolvedRegistryPackages(output) {
  const missing = [];
  const noMatchPattern = /no matching package named `([^`]+)` found/g;
  for (let match = noMatchPattern.exec(output); match !== null; match = noMatchPattern.exec(output)) {
    missing.push(match[1]);
  }

  const versionSelectPattern = /failed to select a version for the requirement `([^`\s]+) =/g;
  for (
    let match = versionSelectPattern.exec(output);
    match !== null;
    match = versionSelectPattern.exec(output)
  ) {
    missing.push(match[1]);
  }

  return [...new Set(missing)];
}

function isEarlierWorkspaceDependency(pkg, depName) {
  const pkgIndex = orderedIndexByName.get(pkg.name);
  const depIndex = orderedIndexByName.get(depName);
  return depIndex !== undefined && pkgIndex !== undefined && depIndex < pkgIndex;
}

function inspectPackage(pkg) {
  const listArgs = ["package", "-p", pkg.name, "--list", "--locked"];
  if (allowDirty) {
    listArgs.push("--allow-dirty");
  }
  const listResult = run("cargo", listArgs);
  if (listResult.status !== 0) {
    process.exit(listResult.status ?? 1);
  }

  const manifestPath = path.join(unpackDirectory, `${pkg.name}-${pkg.version}`, "Cargo.toml");
  const patchArgs = [];
  for (const dependency of ordered) {
    if (!isEarlierWorkspaceDependency(pkg, dependency.name)) {
      continue;
    }
    const dependencyPath = path.join(unpackDirectory, `${dependency.name}-${dependency.version}`);
    patchArgs.push(
      "--config",
      `patch.crates-io.'${dependency.name}'.path=${JSON.stringify(dependencyPath)}`,
    );
  }

  // Fetch the normalized archive's locked dependency graph explicitly before
  // enforcing an offline build. This proves each packaged crate builds from
  // its published shape, not only from the workspace path dependency graph.
  const fetchArgs = ["fetch", "--manifest-path", manifestPath, ...patchArgs];
  if (patchArgs.length === 0) {
    fetchArgs.push("--locked");
  }
  const fetchResult = run("cargo", fetchArgs);
  if (fetchResult.status !== 0) {
    process.exit(fetchResult.status ?? 1);
  }

  const checkArgs = [
    "check",
    "--manifest-path",
    manifestPath,
    "--all-features",
    "--locked",
    "--offline",
    ...patchArgs,
  ];
  const checkResult = run("cargo", checkArgs);
  if (checkResult.status !== 0) {
    process.exit(checkResult.status ?? 1);
  }

  // Compile the tests from the normalized archive as well. Workspace tests
  // cannot detect a package include list that omitted a test-only module,
  // fixture, or generated security assertion.
  const testArgs = [
    "test",
    "--manifest-path",
    manifestPath,
    "--all-features",
    "--locked",
    "--offline",
    "--no-run",
    ...patchArgs,
  ];
  const testResult = run("cargo", testArgs);
  if (testResult.status !== 0) {
    process.exit(testResult.status ?? 1);
  }

  const dryRunArgs = ["publish", "-p", pkg.name, "--dry-run", "--locked"];
  if (allowDirty) {
    dryRunArgs.push("--allow-dirty");
  }
  const dryRunResult = run("cargo", dryRunArgs, { capture: true });
  process.stdout.write(dryRunResult.stdout);
  process.stderr.write(dryRunResult.stderr);
  if (dryRunResult.status === 0) {
    return;
  }

  const combined = `${dryRunResult.stdout}\n${dryRunResult.stderr}`;
  const missing = unresolvedRegistryPackages(combined);
  if (
    missing.length !== 0 &&
    missing.every((depName) => isEarlierWorkspaceDependency(pkg, depName))
  ) {
    console.log(
      `${pkg.name} dry-run reached unpublished ordered workspace dependencies: ${missing.join(", ")}`,
    );
    return;
  }

  process.exit(dryRunResult.status ?? 1);
}

function localArchiveMetadata(pkg) {
  const archive = path.join(packageDirectory, `${pkg.name}-${pkg.version}.crate`);
  if (!fs.existsSync(archive)) {
    console.error(`${pkg.name} ${pkg.version} package archive is missing`);
    process.exit(1);
  }
  const status = fs.lstatSync(archive);
  if (status.isSymbolicLink() || !status.isFile() || status.size < 1) {
    console.error(`${pkg.name} ${pkg.version} package archive is invalid`);
    process.exit(1);
  }
  return {
    sha256: createHash("sha256").update(fs.readFileSync(archive)).digest("hex"),
    size: status.size,
  };
}

function assertReviewedArchive(pkg, reviewed) {
  const local = localArchiveMetadata(pkg);
  const reviewedPath = path.resolve(reviewedCrateDirectory, reviewed.file);
  let reviewedStatus;
  try {
    reviewedStatus = fs.lstatSync(reviewedPath);
  } catch {
    console.error(`${pkg.name} ${pkg.version} reviewed package archive is missing`);
    process.exit(1);
  }
  if (
    reviewedStatus.isSymbolicLink() ||
    !reviewedStatus.isFile() ||
    reviewedStatus.size !== reviewed.size
  ) {
    console.error(`${pkg.name} ${pkg.version} reviewed package archive is invalid`);
    process.exit(1);
  }
  const reviewedChecksum = createHash("sha256")
    .update(fs.readFileSync(reviewedPath))
    .digest("hex");
  if (
    local.sha256 !== reviewed.sha256 ||
    local.size !== reviewed.size ||
    reviewedChecksum !== reviewed.sha256
  ) {
    console.error(`${pkg.name} ${pkg.version} does not match the reviewed package archive`);
    process.exit(1);
  }
}

function packageReviewedCrate(pkg, reviewed) {
  const args = ["package", "-p", pkg.name, "--no-verify", "--locked"];
  for (let attempt = 1; attempt <= MAX_PUBLISH_ATTEMPTS; attempt += 1) {
    const result = run("cargo", args, { capture: true });
    process.stdout.write(result.stdout);
    process.stderr.write(result.stderr);
    if (result.status === 0) {
      assertReviewedArchive(pkg, reviewed);
      return;
    }

    const combined = `${result.stdout}\n${result.stderr}`;
    const missing = unresolvedRegistryPackages(combined);
    const waitingForEarlierDependency =
      missing.length !== 0 &&
      missing.every((dependencyName) => isEarlierWorkspaceDependency(pkg, dependencyName));
    if (!waitingForEarlierDependency || attempt === MAX_PUBLISH_ATTEMPTS) {
      process.exit(result.status ?? 1);
    }

    const delayMs = attempt * CRATES_IO_INDEX_RETRY_BASE_MS;
    console.log(
      `crates.io index has not exposed ${missing.join(", ")} for packaging; retrying ${pkg.name} in ${delayMs / 1000}s...`,
    );
    sleepMs(delayMs);
  }
}

function publishPackage(pkg, reviewed) {
  // Package verification and attested archive comparison have already run
  // before this function. Avoid executing dependency build scripts while a
  // registry credential is present in the environment.
  const args = ["publish", "-p", pkg.name, "--locked", "--no-verify"];

  for (let attempt = 1; attempt <= MAX_PUBLISH_ATTEMPTS; attempt += 1) {
    // Cargo reconstructs the upload from the workspace on every invocation.
    // Rechecking the reviewed archive before each retry prevents local drift
    // from turning a transient registry retry into publication of new bytes.
    assertReviewedArchive(pkg, reviewed);
    const result = run("cargo", args, { capture: true });
    process.stdout.write(result.stdout);
    process.stderr.write(result.stderr);

    if (result.status === 0) {
      assertReviewedArchive(pkg, reviewed);
      verifyPublishedPackageMatches(pkg, reviewed);
      return "published";
    }

    const combined = `${result.stdout}\n${result.stderr}`;
    if (combined.includes("already uploaded") || combined.includes("already exists")) {
      assertReviewedArchive(pkg, reviewed);
      verifyPublishedPackageMatches(pkg, reviewed);
      console.log(`${pkg.name} ${pkg.version} is already published; continuing.`);
      return "verified_existing";
    }

    const lowerCombined = combined.toLowerCase();
    const rateLimitDelayMs = retryAfterMs(combined);
    if (
      lowerCombined.includes("too many requests") ||
      lowerCombined.includes("rate-limited") ||
      lowerCombined.includes("rate limited") ||
      lowerCombined.includes("rate limit") ||
      /\b429\b/u.test(lowerCombined)
    ) {
      // Exhaustion must fail the release before attempting dependent crates.
      if (attempt === MAX_PUBLISH_ATTEMPTS) {
        console.error(`publication retry limit reached for ${pkg.name}`);
        process.exit(result.status ?? 1);
      }
      const delayMs = rateLimitDelayMs ?? CRATES_IO_DEFAULT_RATE_LIMIT_RETRY_MS;
      console.log(
        `crates.io rate-limited new crate uploads; retrying ${pkg.name} in ${Math.ceil(delayMs / 1000)}s...`,
      );
      sleepMs(delayMs);
      continue;
    }

    const registryIndexIsStale =
      combined.includes("no matching package named") ||
      combined.includes("failed to select a version for the requirement");
    if (!registryIndexIsStale || attempt === MAX_PUBLISH_ATTEMPTS) {
      process.exit(result.status ?? 1);
    }

    const delayMs = attempt * CRATES_IO_INDEX_RETRY_BASE_MS;
    console.log(
      `crates.io index has not observed a freshly published dependency yet; retrying ${pkg.name} in ${delayMs / 1000}s...`,
    );
    sleepMs(delayMs);
  }
}

function loadReviewedCrates() {
  const runId = parsePositiveInteger(process.env.PREFLIGHT_RUN_ID);
  const repository = process.env.GITHUB_REPOSITORY;
  const releaseSha = process.env.RELEASE_SHA;
  if (
    runId === null ||
    typeof repository !== "string" ||
    typeof releaseSha !== "string"
  ) {
    console.error("reviewed package attestation identity is missing");
    process.exit(1);
  }

  let attestation;
  try {
    attestation = verifyAttestationDocument(readAttestation(releaseAttestationPath), {
      repository,
      runId,
      releaseSha,
      releaseVersion,
    });
    verifyAttestedCrateArchives(attestation, reviewedCrateDirectory);
  } catch {
    console.error("reviewed package attestation is invalid");
    process.exit(1);
  }
  const reviewedCrates = new Map(
    attestation.crates.map((crate, index) => [APPROVED_PUBLISH_SEQUENCE[index].name, crate]),
  );
  if (
    reviewedCrates.size !== ordered.length ||
    ordered.some((pkg) => !reviewedCrates.has(pkg.name))
  ) {
    console.error("reviewed package set does not match the current publish set");
    process.exit(1);
  }

  return reviewedCrates;
}

function verifyPublishedPackageMatches(pkg, reviewed) {
  const localArchive = path.join(packageDirectory, `${pkg.name}-${pkg.version}.crate`);
  if (!fs.existsSync(localArchive)) {
    console.error(`${pkg.name} ${pkg.version} local package archive is missing`);
    process.exit(1);
  }

  const comparisonDirectory = fs.mkdtempSync(path.join(packageDirectory, "published-"));
  const publishedArchive = path.join(comparisonDirectory, `${pkg.name}-${pkg.version}.crate`);
  const packageName = encodeURIComponent(pkg.name);
  const packageVersion = encodeURIComponent(pkg.version);
  const downloadUrl =
    `https://static.crates.io/crates/${packageName}/${packageName}-${packageVersion}.crate`;

  try {
    const downloadResult = run(
      "curl",
      [
        "--fail-with-body",
        "--location",
        "--proto",
        "=https",
        "--tlsv1.2",
        "--retry",
        CRATES_IO_ARCHIVE_VERIFY_RETRIES,
        "--retry-delay",
        CRATES_IO_ARCHIVE_VERIFY_RETRY_DELAY_SECONDS,
        "--retry-max-time",
        CRATES_IO_ARCHIVE_VERIFY_MAX_SECONDS,
        "--retry-all-errors",
        "--output",
        publishedArchive,
        downloadUrl,
      ],
      { capture: true },
    );
    if (downloadResult.status !== 0) {
      process.stdout.write(downloadResult.stdout);
      process.stderr.write(downloadResult.stderr);
      process.exit(downloadResult.status ?? 1);
    }

    const local = localArchiveMetadata(pkg);
    if (local.sha256 !== reviewed.sha256 || local.size !== reviewed.size) {
      console.error(`${pkg.name} ${pkg.version} local archive changed during publication`);
      process.exit(1);
    }
    const publishedChecksum = createHash("sha256")
      .update(fs.readFileSync(publishedArchive))
      .digest("hex");
    if (local.sha256 !== publishedChecksum) {
      console.error(
        `${pkg.name} ${pkg.version} is already published from different source bytes`,
      );
      process.exit(1);
    }
  } finally {
    fs.rmSync(comparisonDirectory, { force: true, recursive: true });
  }
}

const publicationLedger = {
  schema: "reallyme.openid4vp.crates-publication-ledger.v1",
  repository: "reallyme/openid4vp",
  source_commit: releaseSha,
  release_version: releaseVersion,
  state: "not_started",
  crates: ordered.map((pkg, publishOrder) => ({
    name: pkg.name,
    version: pkg.version,
    publish_order: publishOrder,
    state: "pending",
    archive_sha256: null,
  })),
};

function writePublicationLedger() {
  if (mode !== MODE_PUBLISH) {
    return;
  }
  fs.mkdirSync(path.dirname(publicationLedgerPath), { recursive: true });
  const temporaryPath = `${publicationLedgerPath}.tmp`;
  fs.writeFileSync(temporaryPath, `${JSON.stringify(publicationLedger, null, 2)}\n`, {
    mode: 0o600,
  });
  fs.renameSync(temporaryPath, publicationLedgerPath);
}

const reviewedCrates = mode === MODE_PUBLISH ? loadReviewedCrates() : null;

if (mode === MODE_PUBLISH) {
  publicationLedger.state = "in_progress";
  writePublicationLedger();
}

for (const pkg of ordered) {
  if (mode === MODE_INSPECT) {
    inspectPackage(pkg);
    continue;
  }

  const reviewed = reviewedCrates?.get(pkg.name);
  if (reviewed === undefined) {
    console.error(`${pkg.name} ${pkg.version} reviewed archive evidence is missing`);
    process.exit(1);
  }
  const ledgerEntry = publicationLedger.crates.find((entry) => entry.name === pkg.name);
  if (ledgerEntry !== undefined) {
    ledgerEntry.state = "attempting";
    writePublicationLedger();
  }
  // Registry visibility advances only after the exact reviewed archive for
  // the prior crate has been uploaded and downloaded back byte-for-byte.
  packageReviewedCrate(pkg, reviewed);
  const publishState = publishPackage(pkg, reviewed);
  if (ledgerEntry !== undefined) {
    ledgerEntry.state = publishState;
    ledgerEntry.archive_sha256 = localArchiveMetadata(pkg).sha256;
    writePublicationLedger();
  }
}

if (mode === MODE_PUBLISH) {
  publicationLedger.state = "completed";
  writePublicationLedger();
}
