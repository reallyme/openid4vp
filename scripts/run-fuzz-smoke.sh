#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

readonly FUZZ_RUNS="${OPENID4VP_FUZZ_RUNS:-16}"
readonly FUZZ_MAX_LEN="${OPENID4VP_FUZZ_MAX_LEN:-4096}"
readonly FUZZ_MAX_TOTAL_TIME="${OPENID4VP_FUZZ_MAX_TOTAL_TIME:-}"
readonly FUZZ_RSS_LIMIT_MB="${OPENID4VP_FUZZ_RSS_LIMIT_MB:-4096}"
readonly FUZZ_TOOLCHAIN="${OPENID4VP_FUZZ_TOOLCHAIN:-nightly-2026-09-15}"

readonly -a FUZZ_TARGETS=(
  "dcql_json"
  "authorization_request_transport"
  "request_object_jwt"
  "client_identifier"
  "authorization_response_json"
  "authorization_response_proto"
  "authorization_request_proto"
  "problem_details_proto_json"
  "service_envelope_proto_json"
  "transaction_data_json"
  "dc_api_response_json"
  "dcql_evaluation"
  "direct_post_form"
  "direct_post_jwt_form"
  "dc_api_request_json"
  "verifier_attestation_parameters"
  "sd_jwt_presentation"
  "mdoc_presentation"
  "zk_presentation_value"
  "operation_contract"
  "session_record_proto"
  "hosted_request_object_proto"
)

require_positive_integer() {
  local name="$1"
  local value="$2"

  case "$value" in
    "" | *[!0-9]*)
      printf '%s must be a positive integer\n' "$name" >&2
      exit 2
      ;;
  esac

  if [ "$value" -eq 0 ]; then
    printf '%s must be greater than zero\n' "$name" >&2
    exit 2
  fi
}

require_positive_integer "OPENID4VP_FUZZ_MAX_LEN" "$FUZZ_MAX_LEN"
if [ -n "$FUZZ_MAX_TOTAL_TIME" ]; then
  require_positive_integer "OPENID4VP_FUZZ_MAX_TOTAL_TIME" "$FUZZ_MAX_TOTAL_TIME"
  require_positive_integer "OPENID4VP_FUZZ_RSS_LIMIT_MB" "$FUZZ_RSS_LIMIT_MB"
else
  require_positive_integer "OPENID4VP_FUZZ_RUNS" "$FUZZ_RUNS"
fi

case "$FUZZ_TOOLCHAIN" in
  "" | *[!A-Za-z0-9._-]*)
    printf 'OPENID4VP_FUZZ_TOOLCHAIN must be a rustup toolchain name\n' >&2
    exit 2
    ;;
esac

# cargo-fuzz does not expose Cargo's --locked flag. Validate the dedicated
# fuzz workspace lockfile first so dependency drift fails before any target is
# built or executed.
cargo "+${FUZZ_TOOLCHAIN}" metadata \
  --locked \
  --manifest-path fuzz/Cargo.toml \
  --format-version 1 \
  >/dev/null

# Build and link the complete target set once. A per-target Cargo invocation
# repeats graph checks and can relink targets between runs.
cargo "+${FUZZ_TOOLCHAIN}" fuzz build

host_target="$(rustc "+${FUZZ_TOOLCHAIN}" -vV | sed -n 's/^host: //p')"
if [ -z "${host_target}" ]; then
  printf 'unable to determine the pinned nightly host target\n' >&2
  exit 1
fi
readonly fuzz_binary_directory="fuzz/target/${host_target}/release"

for target in "${FUZZ_TARGETS[@]}"; do
  artifact_directory="fuzz/artifacts/${target}"
  corpus_directory="fuzz/corpus/${target}"
  mkdir -p "${artifact_directory}" "${corpus_directory}"
  if [ -n "$FUZZ_MAX_TOTAL_TIME" ]; then
    fuzz_args=(
      "${corpus_directory}"
      "-max_total_time=${FUZZ_MAX_TOTAL_TIME}"
      "-rss_limit_mb=${FUZZ_RSS_LIMIT_MB}"
      "-max_len=${FUZZ_MAX_LEN}"
      "-artifact_prefix=${artifact_directory}/"
    )
  else
    fuzz_args=(
      "${corpus_directory}"
      "-runs=${FUZZ_RUNS}"
      "-max_len=${FUZZ_MAX_LEN}"
      "-artifact_prefix=${artifact_directory}/"
    )
  fi
  printf 'Running fuzz smoke target: %s\n' "$target"
  "${fuzz_binary_directory}/${target}" "${fuzz_args[@]}"
done
