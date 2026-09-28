#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const manifest = readFileSync(resolve(root, "Cargo.toml"), "utf8");
const cratesIoSource = "registry+https://github.com/rust-lang/crates.io-index";
const directDependencies = [
  { name: "reallyme-jose", version: "0.4.0" },
  { name: "reallyme-openid4vc-profiles", version: "0.3.3" },
  { name: "reallyme-ssi-proto", version: "0.3.3" },
];
const rootLockedDependencies = [
  ...directDependencies,
  { name: "reallyme-mdoc", version: "0.3.3" },
  { name: "reallyme-sd-jwt", version: "0.3.3" },
];
const fuzzLockedDependencies = rootLockedDependencies.filter(
  ({ name }) => name !== "reallyme-openid4vc-profiles",
);

function fail(message) {
  console.error(`SSI remote resolution check failed: ${message}`);
  process.exit(1);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

for (const { name, version } of directDependencies) {
  const dependencyPattern = new RegExp(
    `^${escapeRegExp(name)}\\s*=\\s*\\{([^}]+)\\}$`,
    "gmu",
  );
  const matches = [...manifest.matchAll(dependencyPattern)];
  if (matches.length !== 1 || matches[0][1] === undefined) {
    fail(`Cargo.toml must declare ${name} exactly once`);
  }

  const declaration = matches[0][1];
  const exactVersion = new RegExp(
    `version\\s*=\\s*"=${escapeRegExp(version)}"`,
    "u",
  );
  if (!exactVersion.test(declaration)) {
    fail(`${name} must use exact version =${version}`);
  }
  if (/\b(?:git|path)\s*=/u.test(declaration)) {
    fail(`${name} must resolve from crates.io`);
  }
}

function readLockedPackages(lockfile) {
  return readFileSync(resolve(root, lockfile), "utf8")
    .split("[[package]]")
    .slice(1)
    .map((block) => ({
      name: block.match(/^name = "([^"]+)"$/mu)?.[1],
      version: block.match(/^version = "([^"]+)"$/mu)?.[1],
      source: block.match(/^source = "([^"]+)"$/mu)?.[1],
      checksum: block.match(/^checksum = "([0-9a-f]{64})"$/mu)?.[1],
    }));
}

function validateLockedPackage(lockfile, packages, expected) {
  const matches = packages.filter(({ name }) => name === expected.name);
  if (matches.length !== 1) {
    fail(`${lockfile} must contain exactly one ${expected.name} package`);
  }

  const [cargoPackage] = matches;
  if (
    cargoPackage.version !== expected.version ||
    cargoPackage.source !== cratesIoSource
  ) {
    fail(
      `${lockfile} must resolve ${expected.name} ${expected.version} from crates.io`,
    );
  }
  if (cargoPackage.checksum === undefined) {
    fail(`${lockfile} must lock the crates.io checksum for ${expected.name}`);
  }
}

const rootPackages = readLockedPackages("Cargo.lock");
for (const expected of rootLockedDependencies) {
  validateLockedPackage("Cargo.lock", rootPackages, expected);
}

const fuzzPackages = readLockedPackages("fuzz/Cargo.lock");
for (const expected of fuzzLockedDependencies) {
  validateLockedPackage("fuzz/Cargo.lock", fuzzPackages, expected);
}

console.log(
  `SSI remote resolution check passed for ${rootLockedDependencies.length} locked crates`,
);
