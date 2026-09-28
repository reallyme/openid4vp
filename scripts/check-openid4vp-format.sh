#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

# Enumerate this repository's workspace packages explicitly. `cargo fmt --all`
# can traverse local path dependencies in sibling ReallyMe worktrees, which
# makes this repository's formatting gate depend on unrelated pending edits.
packages=(
  reallyme-openid4vp
  reallyme-openid4vp-proto
  reallyme-openid4vp-proto-codec
  reallyme-openid4vp-types
  reallyme-openid4vp-dcql
  reallyme-openid4vp-verifier
  reallyme-openid4vp-wallet
  reallyme-openid4vp-dc-api
  reallyme-openid4vp-formats
  reallyme-openid4vp-profiles
  reallyme-openid4vp-runtime
  reallyme-openid4vp-http
  reallyme-openid4vp-conformance
)

for package in "${packages[@]}"; do
  cargo fmt --package "${package}" --check
done
