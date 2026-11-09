#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

readonly rg_bin="${OPENID4VP_RG_BIN:-rg}"
if ! command -v "${rg_bin}" >/dev/null 2>&1; then
  printf '%s\n' "error: ZK boundary policy requires ripgrep" >&2
  exit 1
fi

status=0

manifest_matches="$({
  find . \
    -name Cargo.toml \
    -not -path './target/*' \
    -not -path './fuzz/target/*' \
    -not -path './.git/*' \
    -print0 \
    | xargs -0 "${rg_bin}" -n 'reallyme-zk-[A-Za-z0-9_-]+|backend-bb|barretenberg|bb-prover|bb_prover' \
    | "${rg_bin}" -v 'reallyme-zk-api'
} || true)"
if [ -n "${manifest_matches}" ]; then
  printf '%s\n' "error: OpenID4VP may depend only on the backend-neutral ZK API crate" >&2
  printf '%s\n' "${manifest_matches}" >&2
  status=1
fi

source_matches="$({
  "${rg_bin}" -n 'reallyme_zk_[A-Za-z0-9_]+|backend_bb|BbProver|BbVerifier' \
    crates conformance \
    --glob '!crates/proto/src/generated/**' \
    | "${rg_bin}" -v 'reallyme_zk_api'
} || true)"
if [ -n "${source_matches}" ]; then
  printf '%s\n' "error: OpenID4VP source must stay on the backend-neutral ZK API" >&2
  printf '%s\n' "${source_matches}" >&2
  status=1
fi

# The protobuf transport retains its established ZkPrepared* schema names, but
# handwritten Rust must use the canonical persona-credential-evidence API so a
# deprecated compatibility alias cannot silently return at the ZK boundary.
deprecated_rust_api_matches="$({
  "${rg_bin}" -n '\b(Verified)?ZkPrepared[A-Za-z0-9_]*' crates conformance fuzz/fuzz_targets \
    --glob '!crates/proto/src/generated/**' \
    | "${rg_bin}" -v 'pb::presentation_value::Kind::ZkPreparedPersona|`ZkPreparedVerifierRequestV1`'
} || true)"
if [ -n "${deprecated_rust_api_matches}" ]; then
  printf '%s\n' "error: handwritten Rust must use canonical ZkPersonaCredentialEvidence names" >&2
  printf '%s\n' "${deprecated_rust_api_matches}" >&2
  status=1
fi

checkout_matches="$({
  "${rg_bin}" -n 'repository: reallyme/zk|read-ci-dependency-pins|source-pins' .github/workflows
} || true)"
if [ -n "${checkout_matches}" ]; then
  printf '%s\n' "error: workflows must not fetch a ZK sibling repository" >&2
  printf '%s\n' "${checkout_matches}" >&2
  status=1
fi

if ! "${rg_bin}" -q 'ZkPresentation zk = 3;' \
  crates/proto/proto/reallyme/openid4vp/v1/openid4vp.proto; then
  printf '%s\n' "error: typed protobuf ZK presentation envelope is missing" >&2
  status=1
fi

if ! "${rg_bin}" -q 'pub trait HolderBindingVerifier' \
  crates/verifier/src/holder_binding_context.rs; then
  printf '%s\n' "error: composed format-verification port is missing" >&2
  status=1
fi

if ! "${rg_bin}" -q 'pub struct ZkHolderBindingVerifier' \
  crates/verifier/src/zk_holder_binding.rs; then
  printf '%s\n' "error: backend-neutral ZK holder-binding adapter is missing" >&2
  status=1
fi

exit "${status}"
