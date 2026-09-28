#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

readonly rg_bin="${OPENID4VP_RG_BIN:-rg}"
if ! command -v "${rg_bin}" >/dev/null 2>&1; then
  echo "formal model check failed: ripgrep is not installed" >&2
  exit 1
fi

readonly required_tamarin_version="1.12.0"
readonly model="formal/tamarin/openid4vp_session_binding.spthy"
readonly prover="${TAMARIN_PROVER_BIN:-tamarin-prover}"

if ! command -v "${prover}" >/dev/null 2>&1; then
  echo "formal model check failed: tamarin-prover is not installed" >&2
  exit 1
fi

prover_version="$("${prover}" --version 2>&1)"
if ! "${rg_bin}" -q "tamarin-prover ${required_tamarin_version}" <<<"${prover_version}"; then
  echo "formal model check failed: expected tamarin-prover ${required_tamarin_version}" >&2
  exit 1
fi

formal_output="$(mktemp)"
trap 'rm -f "${formal_output}"' EXIT

"${prover}" --prove --quit-on-warning "${model}" >"${formal_output}"

lemmas=(
  sanity_acceptance_exists
  sanity_request_object_refetch_exists
  accepted_presentation_has_exact_session_binding
  verifier_session_accepts_at_most_once
  accepted_presentation_follows_session_start
)

for lemma in "${lemmas[@]}"; do
  if ! "${rg_bin}" -q "^  ${lemma} .*: verified" "${formal_output}"; then
    echo "formal model check failed: ${lemma} was not verified" >&2
    exit 1
  fi
done

if "${rg_bin}" -q 'falsified|analysis incomplete|wellformedness check failed' "${formal_output}"; then
  echo "formal model check failed: prover reported an incomplete or invalid result" >&2
  exit 1
fi

echo "formal model checks passed (${#lemmas[@]} lemmas, Tamarin ${required_tamarin_version})"
