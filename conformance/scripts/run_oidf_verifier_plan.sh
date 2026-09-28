#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

suite_dir="${CONFORMANCE_SUITE_DIR:-}"
base_url="${EXAMPLE_VERIFIER_BASE_URL:-}"
runner_mode="${OIDF_RUNNER_MODE:-pending}"
flow_driver_mode="${OIDF_VERIFIER_FLOW_DRIVER_MODE:-pending}"
results_dir="${CONFORMANCE_RESULTS_DIR:-target/conformance-results}"
matrix="${OIDF_PROFILE_MATRIX:-conformance/oidf/profile-matrix.json}"
matrix_overlay="${OIDF_MATRIX_OVERLAY:-}"
result_assertion="${OIDF_RESULT_ASSERTION:-conformance/scripts/assert_oidf_results.sh}"
target_verifier="${OIDF_TARGET_VERIFIER:-conformance/scripts/verify_oidf_certification_target.py}"
matrix_reader="${OIDF_MATRIX_READER:-conformance/scripts/read_oidf_certification_matrix.py}"
runtime_config_preparer="${OIDF_RUNTIME_CONFIG_PREPARER:-conformance/scripts/prepare_oidf_runtime_config.py}"
endpoint_validator="${OIDF_ENDPOINT_VALIDATOR:-conformance/scripts/validate_oidf_runtime_endpoints.py}"
export_root="${OIDF_EXPORT_DIR:-${results_dir}/oidf-verifier-export}"
python_bin="${PYTHON:-python3}"
flow_driver="${OIDF_VERIFIER_FLOW_DRIVER:-conformance/scripts/drive_oidf_verifier_flow.py}"
evidence_collector="${OIDF_VERIFIER_EVIDENCE_COLLECTOR:-conformance/scripts/collect_oidf_verifier_evidence.py}"
verifier_health_endpoint="${OIDF_VERIFIER_HEALTH_ENDPOINT:-}"
verifier_evidence_endpoint="${OIDF_VERIFIER_EVIDENCE_ENDPOINT:-}"
verifier_launch_token="${OIDF_VERIFIER_LAUNCH_TOKEN:-}"
verifier_evidence_token="${OIDF_VERIFIER_EVIDENCE_TOKEN:-}"
oidf_alias="${OIDF_VERIFIER_ALIAS:-}"
flow_driver_pid=""
runtime_config_dir=""
active_profile_id="verifier-harness"
active_plan_id="oid4vp-1final-verifier-haip-test-plan"
selected_profile_id="${OIDF_PROFILE_ID:-}"
target_overlay_args=()
reader_overlay_args=()
assert_overlay_args=()
alias_args=()
endpoint_validator_args=()
runtime_endpoints=()

cleanup_flow_driver() {
  if [[ -n "${flow_driver_pid}" ]]; then
    kill "${flow_driver_pid}" 2>/dev/null || true
    wait "${flow_driver_pid}" 2>/dev/null || true
  fi
  if [[ -n "${runtime_config_dir}" && -d "${runtime_config_dir}" ]]; then
    rm -rf -- "${runtime_config_dir}"
  fi
}

trap cleanup_flow_driver EXIT

write_result() {
  local profile_id="$1"
  local plan_id="$2"
  local status="$3"
  local reason="$4"
  local module_count="${5:-}"
  local result_file="${results_dir}/${profile_id}.json"
  mkdir -p "${results_dir}"
  if [[ -n "${module_count}" ]]; then
    printf '{"plan_id":"%s","profile_id":"%s","status":"%s","reason":"%s","triggered_modules":%s}\n' \
      "${plan_id}" "${profile_id}" "${status}" "${reason}" "${module_count}" > "${result_file}"
  else
    printf '{"plan_id":"%s","profile_id":"%s","status":"%s","reason":"%s"}\n' \
      "${plan_id}" "${profile_id}" "${status}" "${reason}" > "${result_file}"
  fi
}

fail_with_result() {
  local reason="$1"
  write_result "${active_profile_id}" "${active_plan_id}" "failed" "${reason}"
  echo "${reason}" >&2
  exit 2
}

derive_health_endpoint() {
  local endpoint="$1"
  case "${endpoint}" in
    */oidf/launch)
      printf '%s/healthz\n' "${endpoint%/oidf/launch}"
      ;;
    *)
      printf '\n'
      ;;
  esac
}

require_composed_verifier_host() {
  local endpoint="$1"
  if [[ -z "${endpoint}" ]]; then
    fail_with_result "missing_verifier_health_endpoint"
  fi
  if ! command -v curl >/dev/null 2>&1; then
    fail_with_result "missing_curl"
  fi
  if ! command -v jq >/dev/null 2>&1; then
    fail_with_result "missing_jq"
  fi
  if ! curl --fail --silent --show-error --max-time 10 "${endpoint}" \
    | jq -e '.composed_flow_driver_enabled == true' >/dev/null; then
    fail_with_result "verifier_host_missing_composed_flow_driver"
  fi
}

require_flow_driver_coverage() {
  local expected="$1"
  local result_file="$2"
  local profile_id="$3"
  if [[ ! -f "${result_file}" ]]; then
    fail_with_result "oidf_verifier_flow_driver_evidence_missing"
  fi
  if ! jq -e --argjson expected "${expected}" --arg profile_id "${profile_id}" \
    '.status == "passed" and .triggered_modules == $expected
      and .profile_id == $profile_id
      and (.plan_instance_id | type == "string" and length > 0)' \
    "${result_file}" >/dev/null; then
    fail_with_result "oidf_verifier_flow_driver_coverage_mismatch"
  fi
}

for required_command in git "${python_bin}"; do
  if ! command -v "${required_command}" >/dev/null 2>&1; then
    fail_with_result "missing_required_command"
  fi
done

if [[ -z "${suite_dir}" || ! -d "${suite_dir}" ]]; then
  fail_with_result "missing_conformance_suite"
fi
if [[ -z "${base_url}" ]]; then
  fail_with_result "missing_example_verifier_base_url"
fi
if [[ ! -f "${matrix}" ]]; then
  fail_with_result "missing_profile_matrix"
fi
if [[ -z "${selected_profile_id}" ]]; then
  fail_with_result "missing_oidf_profile_id"
fi
if [[ -n "${matrix_overlay}" ]]; then
  if [[ ! -f "${matrix_overlay}" ]]; then
    fail_with_result "missing_certification_matrix_overlay"
  fi
  target_overlay_args=(--overlay "${matrix_overlay}")
  reader_overlay_args=(--overlay "${matrix_overlay}")
  assert_overlay_args=(--overlay "${matrix_overlay}")
fi
if [[ ! -f "${target_verifier}" ]]; then
  fail_with_result "missing_certification_target_verifier"
fi
if [[ ! -f "${matrix_reader}" ]]; then
  fail_with_result "missing_certification_matrix_reader"
fi
if [[ ! -f "${endpoint_validator}" ]]; then
  fail_with_result "missing_oidf_endpoint_validator"
fi
if ! "${python_bin}" "${target_verifier}" "${suite_dir}" "${matrix}" "${target_overlay_args[@]}"; then
  fail_with_result "certification_target_verification_failed"
fi

expected_commit="$("${python_bin}" "${matrix_reader}" commit "${matrix}" "${reader_overlay_args[@]}")" \
  || fail_with_result "invalid_certification_matrix"
configured_commit="${OIDF_SUITE_COMMIT:-${expected_commit}}"
if [[ "${configured_commit}" != "${expected_commit}" ]]; then
  fail_with_result "configured_suite_commit_mismatch"
fi
actual_commit="$(git -C "${suite_dir}" rev-parse HEAD 2>/dev/null || true)"
if [[ "${actual_commit}" != "${expected_commit}" ]]; then
  fail_with_result "conformance_suite_commit_mismatch"
fi

case "${CONFORMANCE_DEV_MODE:-false}" in
  1 | true | TRUE | yes | YES)
    development_mode="true"
    ;;
  0 | false | FALSE | no | NO | "")
    development_mode="false"
    ;;
  *)
    fail_with_result "invalid_conformance_dev_mode"
    ;;
esac
case "${CONFORMANCE_VERIFY_SSL:-true}" in
  1 | true | TRUE | yes | YES)
    verify_ssl="true"
    ;;
  0 | false | FALSE | no | NO)
    verify_ssl="false"
    ;;
  *)
    fail_with_result "invalid_conformance_verify_ssl"
    ;;
esac

runner="${suite_dir}/scripts/run-test-plan.py"
config_file="${OIDF_CONFIG_FILE:-${suite_dir}/scripts/test-configs-rp-against-op/vp-verifier-test-config.json}"

echo "OIDF suite: ${suite_dir}"
echo "OIDF suite commit: ${expected_commit}"
echo "Certification matrix: ${matrix}"
if [[ -n "${matrix_overlay}" ]]; then
  echo "Certification matrix overlay: ${matrix_overlay}"
fi
echo "Verifier endpoint: configured"

if [[ "${runner_mode}" != "execute" && "${runner_mode}" != "pending" ]]; then
  fail_with_result "invalid_oidf_runner_mode"
fi

if [[ "${runner_mode}" == "pending" ]]; then
  processed_profiles=0
  while IFS=$'\t' read -r profile_id plan_id _expression module_count; do
    processed_profiles=$((processed_profiles + 1))
    write_result "${profile_id}" "${plan_id}" "pending_runner" \
      "oidf_suite_runner_not_yet_enabled" "${module_count}"
  done < <("${python_bin}" "${matrix_reader}" profiles "${matrix}" --role verifier \
    --profile "${selected_profile_id}" "${reader_overlay_args[@]}")
  if [[ "${processed_profiles}" -eq 0 ]]; then
    fail_with_result "certification_profiles_missing"
  fi
  echo "Harness ready: enable execute mode only when the suite server and verifier host are reachable."
  exit 0
fi

if [[ -z "${CONFORMANCE_SERVER:-}" ]]; then
  fail_with_result "missing_conformance_server"
fi
if [[ -z "${CONFORMANCE_SERVER_MTLS:-}" ]]; then
  fail_with_result "missing_conformance_server_mtls"
fi
if [[ "${development_mode}" == "false" && -z "${CONFORMANCE_TOKEN:-}" ]]; then
  fail_with_result "missing_conformance_token"
fi
if [[ "${development_mode}" == "false" && -z "${CONFORMANCE_API_TOKEN:-}" ]]; then
  fail_with_result "missing_conformance_api_token"
fi
if [[ "${development_mode}" == "false" && "${verify_ssl}" != "true" ]]; then
  fail_with_result "insecure_conformance_tls"
fi
if [[ "${development_mode}" == "true" ]]; then
  endpoint_validator_args=(--allow-http)
fi
for endpoint in \
  "${CONFORMANCE_SERVER}" \
  "${CONFORMANCE_SERVER_MTLS}" \
  "${base_url}" \
  "${OIDF_VERIFIER_LAUNCH_ENDPOINT:-}" \
  "${verifier_evidence_endpoint}" \
  "${verifier_health_endpoint}"; do
  if [[ -n "${endpoint}" ]]; then
    runtime_endpoints+=("${endpoint}")
  fi
done
if ! "${python_bin}" "${endpoint_validator}" \
  "${endpoint_validator_args[@]}" "${runtime_endpoints[@]}"; then
  fail_with_result "invalid_oidf_runtime_endpoint"
fi
if [[ ! -f "${runner}" ]]; then
  fail_with_result "missing_oidf_runner"
fi
if [[ ! -f "${config_file}" ]]; then
  fail_with_result "missing_oidf_config"
fi
if [[ ! -f "${runtime_config_preparer}" ]]; then
  fail_with_result "missing_oidf_runtime_config_preparer"
fi
if [[ ! -f "${evidence_collector}" ]]; then
  fail_with_result "missing_oidf_verifier_evidence_collector"
fi
if [[ -z "${verifier_evidence_endpoint}" ]]; then
  fail_with_result "missing_oidf_verifier_evidence_endpoint"
fi
if [[ -z "${verifier_launch_token}" ]]; then
  fail_with_result "missing_oidf_verifier_launch_token"
fi
if [[ -z "${verifier_evidence_token}" ]]; then
  fail_with_result "missing_oidf_verifier_evidence_token"
fi
if [[ ! -x "${result_assertion}" ]]; then
  fail_with_result "missing_oidf_result_assertion"
fi

if [[ -n "${oidf_alias}" ]]; then
  alias_args=(--alias "${oidf_alias}")
fi
runtime_config_dir="$(mktemp -d "${TMPDIR:-/tmp}/reallyme-oidf-vp-verifier.XXXXXX")" \
  || fail_with_result "oidf_runtime_config_directory_failed"
chmod 700 "${runtime_config_dir}" \
  || fail_with_result "oidf_runtime_config_directory_failed"
runtime_config="${runtime_config_dir}/verifier.json"
oidf_alias="$("${python_bin}" "${runtime_config_preparer}" \
  "${config_file}" "${runtime_config}" \
  --alias-prefix "reallyme-vp-wallet" "${alias_args[@]}")" \
  || fail_with_result "oidf_runtime_config_preparation_failed"
config_file="${runtime_config}"

if [[ "${flow_driver_mode}" == "execute" ]]; then
  if [[ ! -f "${flow_driver}" ]]; then
    fail_with_result "missing_oidf_flow_driver"
  fi
  preflight_result="${results_dir}/oidf-verifier-flow-driver-preflight.json"
  if [[ -e "${preflight_result}" ]]; then
    fail_with_result "oidf_flow_driver_preflight_result_already_exists"
  fi
  if ! OIDF_PLAN_ID="${active_plan_id}" OIDF_ALIAS="${oidf_alias}" \
    OIDF_PROFILE_ID="verifier-preflight" \
    OIDF_FLOW_DRIVER_RESULT_FILE="${preflight_result}" \
    "${python_bin}" "${flow_driver}" --dry-run; then
    fail_with_result "oidf_flow_driver_configuration_failed"
  fi
  if [[ -z "${verifier_health_endpoint}" ]]; then
    verifier_health_endpoint="$(derive_health_endpoint "${OIDF_VERIFIER_LAUNCH_ENDPOINT:-}")"
  fi
  require_composed_verifier_host "${verifier_health_endpoint}"
elif [[ "${flow_driver_mode}" == "pending" ]]; then
  fail_with_result "oidf_verifier_flow_driver_disabled"
else
  fail_with_result "invalid_oidf_flow_driver_mode"
fi

mkdir -p "${export_root}"
processed_profiles=0
while IFS=$'\t' read -r profile_id plan_id expression module_count; do
  processed_profiles=$((processed_profiles + 1))
  active_profile_id="${profile_id}"
  active_plan_id="${plan_id}"
  profile_export_dir="${export_root}/${profile_id}"
  profile_flow_driver_result="${results_dir}/oidf-verifier-flow-drivers/${profile_id}.json"
  if [[ -e "${profile_export_dir}" ]]; then
    fail_with_result "oidf_profile_export_already_exists"
  fi
  if [[ -e "${profile_flow_driver_result}" ]]; then
    fail_with_result "oidf_flow_driver_result_already_exists"
  fi
  mkdir -p "${profile_export_dir}"
  mkdir -p "$(dirname -- "${profile_flow_driver_result}")"
  echo "Running certification profile: ${profile_id}"
  profile_started_after="$("${python_bin}" -c 'import time; print(time.time())')" \
    || fail_with_result "oidf_profile_start_time_failed"
  OIDF_PLAN_ID="${plan_id}" \
  OIDF_ALIAS="${oidf_alias}" \
  OIDF_PROFILE_ID="${profile_id}" \
  OIDF_EXPECTED_MODULE_COUNT="${module_count}" \
  OIDF_FLOW_DRIVER_RESULT_FILE="${profile_flow_driver_result}" \
  "${python_bin}" "${flow_driver}" &
  flow_driver_pid="$!"
  echo "OIDF verifier flow driver started for ${profile_id}"
  if ! "${python_bin}" "${runner}" --export-dir "${profile_export_dir}" \
    "${expression}" "${config_file}"; then
    fail_with_result "oidf_suite_runner_failed"
  fi
  if ! wait "${flow_driver_pid}"; then
    flow_driver_pid=""
    fail_with_result "oidf_verifier_flow_driver_exited"
  fi
  flow_driver_pid=""
  require_flow_driver_coverage \
    "${module_count}" "${profile_flow_driver_result}" "${profile_id}"
  implementation_evidence_dir="${results_dir}/implementation-evidence/${profile_id}"
  if ! "${python_bin}" "${evidence_collector}" \
    --matrix "${matrix}" \
    --profile "${profile_id}" \
    --plan "${plan_id}" \
    --alias "${oidf_alias}" \
    --started-after "${profile_started_after}" \
    --output-dir "${implementation_evidence_dir}"; then
    fail_with_result "oidf_verifier_implementation_evidence_incomplete"
  fi
  plan_instance_id="$(jq -er '.plan_instance_id' "${implementation_evidence_dir}/index.json")" \
    || fail_with_result "oidf_verifier_plan_binding_missing"
  flow_driver_plan_instance_id="$(jq -er '.plan_instance_id' "${profile_flow_driver_result}")" \
    || fail_with_result "oidf_verifier_flow_driver_plan_binding_missing"
  if [[ "${flow_driver_plan_instance_id}" != "${plan_instance_id}" ]]; then
    fail_with_result "oidf_verifier_flow_driver_plan_binding_mismatch"
  fi
  if ! "${result_assertion}" "${profile_export_dir}" --matrix "${matrix}" \
    "${assert_overlay_args[@]}" --profile "${profile_id}" \
    --expected-plan-instance-id "${plan_instance_id}"; then
    fail_with_result "oidf_suite_export_incomplete"
  fi
  write_result "${profile_id}" "${plan_id}" "validated" \
    "oidf_suite_runner_completed" "${module_count}"
done < <("${python_bin}" "${matrix_reader}" profiles "${matrix}" --role verifier \
  --profile "${selected_profile_id}" "${reader_overlay_args[@]}")
if [[ "${processed_profiles}" -eq 0 ]]; then
  fail_with_result "certification_profiles_missing"
fi
