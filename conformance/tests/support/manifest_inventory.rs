// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde_json::Value;

use super::RequirementManifest;

pub(super) fn requirements(manifest: &RequirementManifest) -> Vec<Value> {
    manifest
        .body
        .get("requirements")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

pub(super) fn has_non_empty_string_array(item: &Value, key: &str) -> bool {
    item.get(key)
        .and_then(Value::as_array)
        .is_some_and(|values| {
            !values.is_empty()
                && values
                    .iter()
                    .all(|value| value.as_str().is_some_and(|entry| !entry.trim().is_empty()))
        })
}

pub(super) fn string_array_values<'a>(item: &'a Value, key: &str) -> Vec<&'a str> {
    item.get(key)
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

pub(super) fn test_anchor_exists(test_name: &str) -> bool {
    executable_test_exists(test_name)
}

pub(super) fn executable_test_exists(identity: &str) -> bool {
    let Some((module, function_name)) = identity.rsplit_once("::") else {
        return false;
    };
    if function_name.is_empty()
        || !function_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return false;
    }
    let Some(source) = test_source_for_module(module) else {
        return false;
    };
    let declaration = ["fn ", function_name, "("].concat();
    let lines: Vec<&str> = source.lines().collect();
    lines.iter().enumerate().any(|(index, line)| {
        if !line.trim_start().starts_with(&declaration) {
            return false;
        }
        let start = index.saturating_sub(4);
        lines[start..index]
            .iter()
            .any(|candidate| candidate.trim() == "#[test]")
    })
}

pub(super) fn test_source_for_module(module: &str) -> Option<&'static str> {
    match module {
        "reallyme_openid4vp_conformance::vectors_tests" => {
            Some(include_str!("../vectors_tests.rs"))
        }
        "reallyme_openid4vp_dc_api::request::tests" => {
            Some(include_str!("../../../crates/dc-api/src/request_tests.rs"))
        }
        "reallyme_openid4vp_dcql::evaluate::tests" => {
            Some(include_str!("../../../crates/dcql/src/evaluate_tests.rs"))
        }
        "reallyme_openid4vp_formats::mdoc::tests" => {
            Some(include_str!("../../../crates/formats/src/mdoc_tests.rs"))
        }
        "reallyme_openid4vp_formats::parse_transaction_data_binding::tests" => Some(include_str!(
            "../../../crates/formats/src/parse_transaction_data_binding_tests.rs"
        )),
        "reallyme_openid4vp_formats::sd_jwt::tests" => {
            Some(include_str!("../../../crates/formats/src/sd_jwt_tests.rs"))
        }
        "reallyme_openid4vp_http::build_request_uri_http_request::tests" => Some(include_str!(
            "../../../crates/http/src/build_request_uri_http_request_tests.rs"
        )),
        "reallyme_openid4vp_http::resolve_request_uri::tests" => Some(include_str!(
            "../../../crates/http/src/resolve_request_uri_tests.rs"
        )),
        "reallyme_openid4vp_profiles::describe_haip::tests" => Some(include_str!(
            "../../../crates/profiles/src/describe_haip_tests.rs"
        )),
        "reallyme_openid4vp_proto_codec::verify_codec" => Some(include_str!(
            "../../../crates/proto-codec/tests/verify_codec.rs"
        )),
        "reallyme_openid4vp_runtime::build_direct_post_success_response::tests" => Some(
            include_str!("../../../crates/runtime/src/build_direct_post_success_response_tests.rs"),
        ),
        "reallyme_openid4vp_runtime::verify_runtime" => Some(concat!(
            include_str!("../../../crates/runtime/src/verify_runtime_tests.rs"),
            include_str!("../../../crates/runtime/src/verify_runtime_request_tests.rs"),
            include_str!("../../../crates/runtime/src/verify_runtime_jwt_tests.rs"),
            include_str!("../../../crates/runtime/src/verify_runtime_follow_back_tests.rs"),
            include_str!("../../../crates/runtime/src/verify_runtime_response_mode_tests.rs")
        )),
        "reallyme_openid4vp_types::client_id::tests" => {
            Some(include_str!("../../../crates/types/src/client_id_tests.rs"))
        }
        "reallyme_openid4vp_types::define_metadata::tests" => Some(include_str!(
            "../../../crates/types/src/define_metadata_tests.rs"
        )),
        "reallyme_openid4vp_types::response::tests" => {
            Some(include_str!("../../../crates/types/src/response_tests.rs"))
        }
        "reallyme_openid4vp_verifier::binding::tests" => Some(include_str!(
            "../../../crates/verifier/src/binding_tests.rs"
        )),
        "reallyme_openid4vp_verifier::mdoc_holder_binding::tests" => Some(include_str!(
            "../../../crates/verifier/src/mdoc_holder_binding_tests.rs"
        )),
        "reallyme_openid4vp_verifier::response::tests" => Some(include_str!(
            "../../../crates/verifier/src/response_tests.rs"
        )),
        "reallyme_openid4vp_wallet::build_authorization_response::tests" => Some(include_str!(
            "../../../crates/wallet/src/build_authorization_response_tests.rs"
        )),
        "reallyme_openid4vp_wallet::encrypt_authorization_response_with_jose::tests" => {
            Some(include_str!(
                "../../../crates/wallet/src/encrypt_authorization_response_with_jose_tests.rs"
            ))
        }
        "reallyme_openid4vp_wallet::jar::tests" => {
            Some(include_str!("../../../crates/wallet/src/jar_tests.rs"))
        }
        "reallyme_openid4vp_wallet::metadata_reference::tests" => Some(include_str!(
            "../../../crates/wallet/src/metadata_reference_tests.rs"
        )),
        "reallyme_openid4vp_wallet::multisigned_request_object::tests" => Some(include_str!(
            "../../../crates/wallet/src/multisigned_request_object_tests.rs"
        )),
        "reallyme_openid4vp_wallet::transport::tests" => Some(include_str!(
            "../../../crates/wallet/src/transport_tests.rs"
        )),
        "reallyme_openid4vp_wallet::unsigned_dc_api_request::tests" => Some(include_str!(
            "../../../crates/wallet/src/unsigned_dc_api_request_tests.rs"
        )),
        "reallyme_openid4vp_wallet::validate_endpoint_binding::tests" => Some(include_str!(
            "../../../crates/wallet/src/validate_endpoint_binding_tests.rs"
        )),
        "reallyme_openid4vp_wallet::verifier_attestation::tests" => Some(include_str!(
            "../../../crates/wallet/src/verifier_attestation_tests.rs"
        )),
        "reallyme_openid4vp_wallet::verify_nested_request_object_with_jose::tests" => {
            Some(include_str!(
                "../../../crates/wallet/src/verify_nested_request_object_with_jose_tests.rs"
            ))
        }
        "reallyme_openid4vp_wallet::verify_signed_request_object_with_jose::tests" => {
            Some(include_str!(
                "../../../crates/wallet/src/verify_signed_request_object_with_jose_tests.rs"
            ))
        }
        _ => None,
    }
}

pub(super) fn manifests() -> [(&'static str, &'static str); 21] {
    [
        (
            "specifications.lock",
            include_str!("../../specifications.lock"),
        ),
        (
            "requirements/openid4vp.json",
            include_str!("../../requirements/openid4vp.json"),
        ),
        (
            "requirements/haip-presentation.json",
            include_str!("../../requirements/haip-presentation.json"),
        ),
        (
            "requirements/eudi-presentation.json",
            include_str!("../../requirements/eudi-presentation.json"),
        ),
        (
            "oidf/exclusions.json",
            include_str!("../../oidf/exclusions.json"),
        ),
        (
            "oidf/profile-matrix.json",
            include_str!("../../oidf/profile-matrix.json"),
        ),
        (
            "oidf/demo-rehearsal-overlay.json",
            include_str!("../../oidf/demo-rehearsal-overlay.json"),
        ),
        ("eudi/sources.lock", include_str!("../../eudi/sources.lock")),
        (
            "eudi/test-cases.json",
            include_str!("../../eudi/test-cases.json"),
        ),
        (
            "eudi/upstream-tests.json",
            include_str!("../../eudi/upstream-tests.json"),
        ),
        (
            "eudi/exclusions.json",
            include_str!("../../eudi/exclusions.json"),
        ),
        (
            "eudi/fixture-inventory.json",
            include_str!("../../eudi/fixture-inventory.json"),
        ),
        (
            "vectors/openid4vp-malicious-json.json",
            include_str!("../../../vectors/openid4vp-malicious-json.json"),
        ),
        (
            "fixtures/eudi/reference-verifier-wallet.json",
            include_str!("../../fixtures/eudi/reference-verifier-wallet.json"),
        ),
        (
            "fixtures/eudi/same-device-presentation.json",
            include_str!("../../fixtures/eudi/same-device-presentation.json"),
        ),
        (
            "fixtures/eudi/cross-device-presentation.json",
            include_str!("../../fixtures/eudi/cross-device-presentation.json"),
        ),
        (
            "fixtures/eudi/negative-nonce-mismatch.json",
            include_str!("../../fixtures/eudi/negative-nonce-mismatch.json"),
        ),
        (
            "fixtures/ewc/eudi-wallet-rfcs-presentation.json",
            include_str!("../../fixtures/ewc/eudi-wallet-rfcs-presentation.json"),
        ),
        (
            "fixtures/ewc/dc-api-wallet-flow.json",
            include_str!("../../fixtures/ewc/dc-api-wallet-flow.json"),
        ),
        (
            "vectors/dc-api/openid4vp-browser-request.json",
            include_str!("../../../vectors/dc-api/openid4vp-browser-request.json"),
        ),
        (
            "vectors/mdoc/annex-b-handover.json",
            include_str!("../../../vectors/mdoc/annex-b-handover.json"),
        ),
    ]
}

pub(super) fn fixture_path_exists(path: &str) -> bool {
    matches!(
        path,
        "conformance/fixtures/eudi/reference-verifier-wallet.json"
            | "conformance/fixtures/eudi/same-device-presentation.json"
            | "conformance/fixtures/eudi/cross-device-presentation.json"
            | "conformance/fixtures/eudi/negative-nonce-mismatch.json"
            | "conformance/fixtures/ewc/eudi-wallet-rfcs-presentation.json"
            | "conformance/fixtures/ewc/dc-api-wallet-flow.json"
            | "vectors/dc-api/openid4vp-browser-request.json"
            | "vectors/mdoc/annex-b-handover.json"
    )
}
