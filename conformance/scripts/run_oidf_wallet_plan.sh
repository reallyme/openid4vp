#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

suite_dir="${CONFORMANCE_SUITE_DIR:-}"
runner_mode="${OIDF_WALLET_RUNNER_MODE:-${OIDF_RUNNER_MODE:-pending}}"
flow_driver_mode="${OIDF_WALLET_FLOW_DRIVER_MODE:-pending}"
results_dir="${CONFORMANCE_RESULTS_DIR:-target/conformance-results}"
matrix="${OIDF_PROFILE_MATRIX:-conformance/oidf/profile-matrix.json}"
result_assertion="${OIDF_RESULT_ASSERTION:-conformance/scripts/assert_oidf_results.sh}"
target_verifier="${OIDF_TARGET_VERIFIER:-conformance/scripts/verify_oidf_certification_target.py}"
matrix_reader="${OIDF_MATRIX_READER:-conformance/scripts/read_oidf_certification_matrix.py}"
config_verifier="${OIDF_WALLET_CONFIG_VERIFIER:-conformance/scripts/verify_oidf_wallet_config.py}"
sd_jwt_config_file="${OIDF_WALLET_SD_JWT_CONFIG_FILE:-conformance/oidf/configs/vp-wallet-test-config-dcql-sdjwt-haip.json}"
mdoc_config_file="${OIDF_WALLET_MDOC_CONFIG_FILE:-conformance/oidf/configs/vp-wallet-test-config-dcql-mdoc-haip.json}"
runtime_config_preparer="${OIDF_RUNTIME_CONFIG_PREPARER:-conformance/scripts/prepare_oidf_runtime_config.py}"
endpoint_validator="${OIDF_ENDPOINT_VALIDATOR:-conformance/scripts/validate_oidf_runtime_endpoints.py}"
wallet_harness_endpoint="${OIDF_WALLET_HARNESS_ENDPOINT:-}"
wallet_harness_health_endpoint="${OIDF_WALLET_HARNESS_HEALTH_ENDPOINT:-}"
wallet_error_screen_endpoint="${OIDF_WALLET_ERROR_SCREEN_ENDPOINT:-}"
wallet_harness_token="${OIDF_WALLET_HARNESS_TOKEN:-}"
wallet_screenshot_browser="${OIDF_WALLET_SCREENSHOT_BROWSER:-}"
oidf_alias="${OIDF_WALLET_ALIAS:-}"
export_root="${OIDF_WALLET_EXPORT_DIR:-${results_dir}/oidf-wallet-export}"
python_bin="${PYTHON:-python3}"
flow_driver="${OIDF_WALLET_FLOW_DRIVER:-conformance/scripts/drive_oidf_wallet_flow.py}"
flow_driver_pid=""
runtime_config_dir=""
active_profile_id="wallet-harness"
active_plan_id="oid4vp-1final-wallet-haip-test-plan"
selected_profile_id="${OIDF_PROFILE_ID:-}"
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
    */oidf/wallet/authorize)
      printf '%s/healthz\n' "${endpoint%/oidf/wallet/authorize}"
      ;;
    *)
      printf '\n'
      ;;
  esac
}

derive_error_screen_endpoint() {
  local endpoint="$1"
  case "${endpoint}" in
    */oidf/wallet/authorize)
      printf '%s/oidf/wallet/error\n' "${endpoint%/oidf/wallet/authorize}"
      ;;
    *)
      printf '\n'
      ;;
  esac
}

require_composed_wallet_harness() {
  local endpoint="$1"
  if [[ -z "${endpoint}" ]]; then
    fail_with_result "missing_wallet_harness_health_endpoint"
  fi
  if ! command -v curl >/dev/null 2>&1; then
    fail_with_result "missing_curl"
  fi
  if ! command -v jq >/dev/null 2>&1; then
    fail_with_result "missing_jq"
  fi
  if ! curl --fail --silent --show-error --max-time 10 "${endpoint}" \
    | jq -e '.composed_flow_driver_enabled == true' >/dev/null; then
    fail_with_result "wallet_harness_missing_composed_flow_driver"
  fi
}

require_flow_driver_coverage() {
  local expected="$1"
  local result_file="$2"
  local profile_id="$3"
  if [[ ! -f "${result_file}" ]]; then
    fail_with_result "oidf_wallet_flow_driver_evidence_missing"
  fi
  if ! jq -e --argjson expected "${expected}" --arg profile_id "${profile_id}" \
    '.status == "passed" and .triggered_modules == $expected
      and .profile_id == $profile_id
      and (.plan_instance_id | type == "string" and length > 0)' \
    "${result_file}" >/dev/null; then
    fail_with_result "oidf_wallet_flow_driver_coverage_mismatch"
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
if [[ ! -f "${matrix}" ]]; then
  fail_with_result "missing_profile_matrix"
fi
if [[ -z "${selected_profile_id}" ]]; then
  fail_with_result "missing_oidf_profile_id"
fi
if [[ ! -f "${target_verifier}" ]]; then
  fail_with_result "missing_certification_target_verifier"
fi
if [[ ! -f "${matrix_reader}" ]]; then
  fail_with_result "missing_certification_matrix_reader"
fi
if [[ ! -f "${config_verifier}" ]]; then
  fail_with_result "missing_oidf_wallet_config_verifier"
fi
for config_file in "${sd_jwt_config_file}" "${mdoc_config_file}"; do
  if [[ ! -f "${config_file}" ]]; then
    fail_with_result "missing_oidf_wallet_config"
  fi
done
if [[ ! -f "${runtime_config_preparer}" ]]; then
  fail_with_result "missing_oidf_runtime_config_preparer"
fi
if [[ ! -f "${endpoint_validator}" ]]; then
  fail_with_result "missing_oidf_endpoint_validator"
fi
if ! "${python_bin}" "${target_verifier}" "${suite_dir}" "${matrix}"; then
  fail_with_result "certification_target_verification_failed"
fi
if ! "${python_bin}" "${config_verifier}" "${suite_dir}" "${sd_jwt_config_file}" \
  --credential-format sd_jwt_vc; then
  fail_with_result "oidf_wallet_config_verification_failed"
fi
if ! "${python_bin}" "${config_verifier}" "${suite_dir}" "${mdoc_config_file}" \
  --credential-format iso_mdl; then
  fail_with_result "oidf_wallet_config_verification_failed"
fi

expected_commit="$("${python_bin}" "${matrix_reader}" commit "${matrix}")" \
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

echo "OIDF suite: ${suite_dir}"
echo "OIDF suite commit: ${expected_commit}"
echo "Certification matrix: ${matrix}"
if [[ -n "${wallet_harness_endpoint}" ]]; then
  echo "Wallet harness endpoint: configured"
else
  echo "Wallet harness endpoint: pending"
fi

if [[ "${runner_mode}" != "execute" && "${runner_mode}" != "pending" ]]; then
  fail_with_result "invalid_oidf_wallet_runner_mode"
fi

if [[ "${runner_mode}" == "pending" ]]; then
  processed_profiles=0
  while IFS=$'\t' read -r profile_id plan_id _expression module_count \
    _credential_format _response_mode; do
    processed_profiles=$((processed_profiles + 1))
    write_result "${profile_id}" "${plan_id}" "pending_runner" \
      "oidf_wallet_runner_not_yet_enabled" "${module_count}"
  done < <("${python_bin}" "${matrix_reader}" profiles "${matrix}" --role wallet \
    --profile "${selected_profile_id}" --include-credential-format \
    --include-response-mode)
  if [[ "${processed_profiles}" -eq 0 ]]; then
    fail_with_result "certification_profiles_missing"
  fi
  echo "Harness ready: enable execute mode only when the suite server and wallet host are reachable."
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
if [[ -z "${wallet_error_screen_endpoint}" ]]; then
  wallet_error_screen_endpoint="$(derive_error_screen_endpoint "${wallet_harness_endpoint}")"
fi
for endpoint in \
  "${CONFORMANCE_SERVER}" \
  "${CONFORMANCE_SERVER_MTLS}" \
  "${wallet_harness_endpoint}" \
  "${wallet_harness_health_endpoint}" \
  "${wallet_error_screen_endpoint}"; do
  if [[ -n "${endpoint}" ]]; then
    runtime_endpoints+=("${endpoint}")
  fi
done
if ! "${python_bin}" "${endpoint_validator}" \
  "${endpoint_validator_args[@]}" "${runtime_endpoints[@]}"; then
  fail_with_result "invalid_oidf_runtime_endpoint"
fi
if [[ -z "${wallet_harness_endpoint}" ]]; then
  fail_with_result "missing_wallet_harness_endpoint"
fi
if [[ -z "${wallet_harness_token}" ]]; then
  fail_with_result "missing_wallet_harness_token"
fi
if [[ -z "${wallet_error_screen_endpoint}" ]]; then
  fail_with_result "missing_wallet_error_screen_endpoint"
fi
if [[ -z "${wallet_screenshot_browser}" ]]; then
  fail_with_result "missing_wallet_screenshot_browser"
fi
if [[ ! -f "${runner}" ]]; then
  fail_with_result "missing_oidf_runner"
fi
if [[ ! -x "${result_assertion}" ]]; then
  fail_with_result "missing_oidf_result_assertion"
fi

if [[ "${flow_driver_mode}" == "execute" ]]; then
  if [[ ! -f "${flow_driver}" ]]; then
    fail_with_result "missing_oidf_wallet_flow_driver"
  fi
  if ! OIDF_PLAN_ID="${active_plan_id}" OIDF_ALIAS="wallet-preflight" \
    OIDF_PROFILE_ID="wallet-preflight" \
    OIDF_PROFILE_CREDENTIAL_FORMAT="sd_jwt_vc" \
    OIDF_PROFILE_RESPONSE_MODE="direct_post.jwt" \
    OIDF_EXPECTED_MODULE_COUNT=1 \
    OIDF_WALLET_ERROR_SCREEN_ENDPOINT="${wallet_error_screen_endpoint}" \
    OIDF_WALLET_SCREENSHOT_BROWSER="${wallet_screenshot_browser}" \
    "${python_bin}" "${flow_driver}" --dry-run; then
    fail_with_result "oidf_wallet_flow_driver_configuration_failed"
  fi
  if [[ -z "${wallet_harness_health_endpoint}" ]]; then
    wallet_harness_health_endpoint="$(derive_health_endpoint "${wallet_harness_endpoint}")"
  fi
  require_composed_wallet_harness "${wallet_harness_health_endpoint}"
elif [[ "${flow_driver_mode}" == "pending" ]]; then
  fail_with_result "oidf_wallet_flow_driver_disabled"
else
  fail_with_result "invalid_oidf_wallet_flow_driver_mode"
fi

mkdir -p "${export_root}"
runtime_config_dir="$(mktemp -d "${TMPDIR:-/tmp}/reallyme-oidf-vp-wallet.XXXXXX")" \
  || fail_with_result "oidf_runtime_config_directory_failed"
chmod 700 "${runtime_config_dir}" \
  || fail_with_result "oidf_runtime_config_directory_failed"
processed_profiles=0
while IFS=$'\t' read -r profile_id plan_id expression module_count credential_format \
  response_mode; do
  processed_profiles=$((processed_profiles + 1))
  active_profile_id="${profile_id}"
  active_plan_id="${plan_id}"
  profile_export_dir="${export_root}/${profile_id}"
  if [[ -e "${profile_export_dir}" ]]; then
    fail_with_result "oidf_profile_export_already_exists"
  fi
  mkdir -p "${profile_export_dir}"
  echo "Running certification profile: ${profile_id}"
  case "${credential_format}" in
    sd_jwt_vc)
      profile_config_template="${sd_jwt_config_file}"
      ;;
    iso_mdl)
      profile_config_template="${mdoc_config_file}"
      ;;
    *)
      fail_with_result "oidf_wallet_profile_credential_format_invalid"
      ;;
  esac
  if [[ -n "${oidf_alias}" ]]; then
    alias_args=(--alias "${oidf_alias}")
  else
    alias_args=()
  fi
  profile_config_file="${runtime_config_dir}/${profile_id}.json"
  profile_alias="$("${python_bin}" "${runtime_config_preparer}" \
    "${profile_config_template}" "${profile_config_file}" \
    --alias-prefix "reallyme-vp-verifier" "${alias_args[@]}")" \
    || fail_with_result "oidf_runtime_config_preparation_failed"
  flow_driver_result="${results_dir}/oidf-wallet-flow-driver-${profile_id}.json"
  OIDF_PLAN_ID="${plan_id}" \
  OIDF_ALIAS="${profile_alias}" \
  OIDF_PROFILE_ID="${profile_id}" \
  OIDF_PROFILE_CREDENTIAL_FORMAT="${credential_format}" \
  OIDF_PROFILE_RESPONSE_MODE="${response_mode}" \
  OIDF_EXPECTED_MODULE_COUNT="${module_count}" \
  OIDF_WALLET_FLOW_DRIVER_RESULT_FILE="${flow_driver_result}" \
  OIDF_WALLET_ERROR_SCREEN_ENDPOINT="${wallet_error_screen_endpoint}" \
  OIDF_WALLET_SCREENSHOT_BROWSER="${wallet_screenshot_browser}" \
  "${python_bin}" "${flow_driver}" &
  flow_driver_pid="$!"
  echo "OIDF wallet flow driver started for profile: ${profile_id}"
  if ! OIDF_WALLET_HARNESS_ENDPOINT="${wallet_harness_endpoint}" \
    "${python_bin}" "${runner}" --export-dir "${profile_export_dir}" \
    "${expression}" "${profile_config_file}"; then
    fail_with_result "oidf_suite_runner_failed"
  fi
  if ! wait "${flow_driver_pid}"; then
    flow_driver_pid=""
    fail_with_result "oidf_wallet_flow_driver_exited"
  fi
  flow_driver_pid=""
  require_flow_driver_coverage "${module_count}" "${flow_driver_result}" "${profile_id}"
  plan_instance_id="$(jq -er '.plan_instance_id' "${flow_driver_result}")" \
    || fail_with_result "oidf_wallet_flow_driver_plan_binding_missing"
  if ! "${result_assertion}" "${profile_export_dir}" --matrix "${matrix}" \
    --profile "${profile_id}" \
    --expected-plan-instance-id "${plan_instance_id}"; then
    fail_with_result "oidf_suite_export_incomplete"
  fi
  write_result "${profile_id}" "${plan_id}" "validated" \
    "oidf_wallet_suite_runner_completed" "${module_count}"
done < <("${python_bin}" "${matrix_reader}" profiles "${matrix}" --role wallet \
  --profile "${selected_profile_id}" --include-credential-format \
  --include-response-mode)
if [[ "${processed_profiles}" -eq 0 ]]; then
  fail_with_result "certification_profiles_missing"
fi
