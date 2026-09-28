// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

//! Checks that conformance control-plane manifests remain machine-readable.

use std::collections::BTreeMap;

use serde_json::Value;

#[path = "support/manifest_inventory.rs"]
mod manifest_inventory;
use manifest_inventory::{
    executable_test_exists, fixture_path_exists, has_non_empty_string_array, manifests,
    requirements, string_array_values, test_anchor_exists,
};

fn specification_lock_is_valid(lock: &Value) -> bool {
    let expected = BTreeMap::from([
        (
            "haip-1.0-final",
            "3996e0479d06b72d6d68668b8ae3cd39fddfc29ae9220c0c3fead7dc060ec4fb",
        ),
        (
            "openid4vp-1.0-final",
            "08e635ea3563b192309c627382c281c81de176e94cdb5ffb11b13ac624f7e12e",
        ),
        (
            "openid4vci-1.0-final",
            "f123c3178cacd27688b15b762098a045e9eb35eccfe2f5f18a357c3815e06ba7",
        ),
        (
            "w3c-digital-credentials-2025-12-08",
            "bd0e2b26a5480cbd1ddc5683c44df97e1c0aa2b7d7e0a303a39a0b05d3a39607",
        ),
        (
            "sd-jwt-vc-draft-13",
            "c1cb38fde3c41f32a7915bebbff2c76b121da9712a07ecb2a25a9802e428b38d",
        ),
        (
            "oauth-status-list-draft-14",
            "7f47502ad2f076879a06880a4e1f864991ae1bfc21f86f6ffa1d73cd4a930352",
        ),
        (
            "fapi-security-profile-2.0-final",
            "26a49ad19b1f2b19ecc1cd9b825b4d5012f5e03a5dc8cb0dbd26462d39da465c",
        ),
        (
            "rfc9101",
            "14a98eb7f65063f0eaa37b0d48ed0e956cb5fd8e38e799a28a119c56554ccb94",
        ),
        (
            "rfc9901",
            "cabbdc4048c1d6dd06ebb2a64e287b55d252c5c2e1b1b9fe680441df7a35eafd",
        ),
        (
            "rfc9457",
            "f705945670a08239544e8ce53ba8a8c41d4b67ccfcd1a36c0eb4ee851a35bbab",
        ),
    ]);
    let Some(specifications) = lock.get("specifications").and_then(Value::as_array) else {
        return false;
    };
    if lock.get("schema_version").and_then(Value::as_u64) != Some(2)
        || lock
            .get("profile_dependencies_complete")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return false;
    }
    let mut actual = BTreeMap::new();
    let mut iso_revision_found = false;
    for specification in specifications {
        let Some(id) = specification.get("id").and_then(Value::as_str) else {
            return false;
        };
        let Some(url) = specification.get("url").and_then(Value::as_str) else {
            return false;
        };
        if url.contains("github.io") || url == "https://www.w3.org/TR/digital-credentials/" {
            return false;
        }
        if id == "iso-iec-18013-5-2021" {
            iso_revision_found = specification.get("revision").and_then(Value::as_str)
                == Some("ISO/IEC 18013-5:2021")
                && specification.get("content_access").and_then(Value::as_str)
                    == Some("licensed_standard");
            continue;
        }
        let Some(digest) = specification.get("sha256").and_then(Value::as_str) else {
            return false;
        };
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return false;
        }
        actual.insert(id, digest);
    }
    iso_revision_found && actual == expected
}

#[test]
fn specification_lock_pins_complete_haip_dependencies() {
    let lock: Value = serde_json::from_str(include_str!("../specifications.lock"))
        .expect("specification lock is valid JSON");
    assert!(specification_lock_is_valid(&lock));

    let mut changed_digest = lock.clone();
    changed_digest["specifications"][0]["sha256"] = Value::String("0".repeat(64));
    assert!(!specification_lock_is_valid(&changed_digest));

    let mut missing_dependency = lock.clone();
    if let Some(specifications) = missing_dependency["specifications"].as_array_mut() {
        specifications.retain(|entry| entry["id"] != "sd-jwt-vc-draft-13");
    }
    assert!(!specification_lock_is_valid(&missing_dependency));

    let mut editor_url = lock;
    editor_url["specifications"][3]["url"] =
        Value::String("https://w3c-fedid.github.io/digital-credentials/".to_owned());
    assert!(!specification_lock_is_valid(&editor_url));
}

#[test]
fn conformance_manifests_are_valid_json() {
    for (name, body) in manifests() {
        let parsed = serde_json::from_str::<Value>(body);
        assert!(parsed.is_ok(), "manifest {name} must parse as JSON");
    }
}

#[test]
fn oidf_runner_requires_exported_result_artifacts() {
    let workflow = include_str!("../../.github/workflows/conformance.yml");
    let runner = include_str!("../scripts/run_oidf_verifier_plan.sh");
    let wallet_runner = include_str!("../scripts/run_oidf_wallet_plan.sh");
    let wallet_driver = include_str!("../scripts/drive_oidf_wallet_flow.py");
    let evidence_collector = include_str!("../scripts/collect_oidf_verifier_evidence.py");
    let verifier = include_str!("../scripts/assert_oidf_results.sh");
    let strict_verifier = include_str!("../scripts/assert_oidf_results.py");
    let target_verifier = include_str!("../scripts/verify_oidf_certification_target.py");
    let wallet_config_verifier = include_str!("../scripts/verify_oidf_wallet_config.py");
    let matrix_reader = include_str!("../scripts/read_oidf_certification_matrix.py");
    let endpoint_validator = include_str!("../scripts/validate_oidf_runtime_endpoints.py");
    let discovery = include_str!("../scripts/discover_oidf_openid4vp.py");
    let preflight = include_str!("../scripts/preflight_oidf_verifier.sh");
    let verifier_plan = include_str!("../oidf-verifier-plan.toml");
    let wallet_plan = include_str!("../oidf-wallet-plan.toml");
    let wallet_config = include_str!("../oidf/configs/vp-wallet-test-config-dcql-sdjwt-haip.json");
    let wallet_mdoc_config =
        include_str!("../oidf/configs/vp-wallet-test-config-dcql-mdoc-haip.json");
    assert!(
        runner.contains("results_dir=\"${CONFORMANCE_RESULTS_DIR:-target/conformance-results}\"")
    );
    assert!(runner.contains("conformance/scripts/assert_oidf_results.sh"));
    assert!(runner.contains("profile-matrix.json"));
    assert!(runner.contains("missing_oidf_profile_id"));
    assert!(runner.contains("--profile \"${selected_profile_id}\""));
    assert!(!runner.contains("OIDF_MATRIX_OVERLAY"));
    assert!(runner.contains("oidf_suite_export_incomplete"));
    assert!(runner.contains("missing_conformance_token"));
    assert!(runner.contains("OIDF_VERIFIER_HEALTH_ENDPOINT"));
    assert!(runner.contains("verifier_host_missing_composed_flow_driver"));
    assert!(runner.contains("oidf_verifier_flow_driver_exited"));
    assert!(runner.contains("oidf_verifier_flow_driver_disabled"));
    assert!(runner.contains("OIDF_VERIFIER_ALIAS"));
    assert!(runner.contains("oidf_verifier_flow_driver_coverage_mismatch"));
    assert!(runner.contains("OIDF_PROFILE_ID"));
    assert!(runner.contains("OIDF_EXPECTED_MODULE_COUNT"));
    assert!(runner.contains("OIDF_VERIFIER_EVIDENCE_ENDPOINT"));
    assert!(runner.contains("validate_oidf_runtime_endpoints.py"));
    assert!(runner.contains("invalid_oidf_runtime_endpoint"));
    assert!(runner.contains("oidf_verifier_implementation_evidence_incomplete"));
    assert!(runner.contains("mktemp -d"));
    assert!(!runner.contains("${results_dir}/oidf-runtime-configs"));
    assert!(runner.contains("--expected-plan-instance-id"));
    assert!(runner.contains("oidf_verifier_plan_binding_missing"));
    assert!(evidence_collector.contains("plan_instance_id"));
    assert!(evidence_collector.contains("evidence_module_result_invalid"));
    assert!(evidence_collector.contains("evidence_record_binding_mismatch"));
    assert!(evidence_collector.contains("evidence_required_observation_missing"));
    assert!(wallet_runner.contains("OIDF_WALLET_HARNESS_ENDPOINT"));
    assert!(wallet_runner
        .contains("results_dir=\"${CONFORMANCE_RESULTS_DIR:-target/conformance-results}\""));
    assert!(wallet_runner.contains("missing_oidf_profile_id"));
    assert!(wallet_runner.contains("--profile \"${selected_profile_id}\""));
    assert!(wallet_runner.contains("OIDF_WALLET_HARNESS_HEALTH_ENDPOINT"));
    assert!(wallet_runner.contains("missing_wallet_harness_token"));
    assert!(!wallet_runner.contains("OIDF_MATRIX_OVERLAY"));
    assert!(wallet_runner.contains("OIDF_WALLET_FLOW_DRIVER_MODE"));
    assert!(wallet_runner.contains("conformance/scripts/drive_oidf_wallet_flow.py"));
    assert!(wallet_runner.contains("oidf_wallet_suite_runner_completed"));
    assert!(wallet_runner.contains("missing_conformance_token"));
    assert!(wallet_runner.contains("verify_oidf_wallet_config.py"));
    assert!(wallet_runner.contains("oidf_wallet_config_verification_failed"));
    assert!(wallet_runner.contains("wallet_harness_missing_composed_flow_driver"));
    assert!(wallet_runner.contains("oidf_wallet_flow_driver_exited"));
    assert!(wallet_runner.contains("oidf_wallet_flow_driver_disabled"));
    assert!(wallet_runner.contains("OIDF_WALLET_ALIAS"));
    assert!(wallet_runner.contains("validate_oidf_runtime_endpoints.py"));
    assert!(wallet_runner.contains("invalid_oidf_runtime_endpoint"));
    assert!(wallet_runner.contains("oidf_wallet_flow_driver_coverage_mismatch"));
    assert!(wallet_runner.contains("mktemp -d"));
    assert!(!wallet_runner.contains("${results_dir}/oidf-runtime-configs"));
    assert!(wallet_runner.contains("--expected-plan-instance-id"));
    assert!(wallet_runner.contains("oidf-wallet-flow-driver-${profile_id}.json"));
    assert!(wallet_runner
        .contains("conformance/oidf/configs/vp-wallet-test-config-dcql-sdjwt-haip.json"));
    assert!(wallet_runner
        .contains("conformance/oidf/configs/vp-wallet-test-config-dcql-mdoc-haip.json"));
    assert!(wallet_runner.contains("--include-credential-format"));
    assert!(wallet_runner.contains("--credential-format sd_jwt_vc"));
    assert!(wallet_runner.contains("--credential-format iso_mdl"));
    assert!(wallet_config.contains("\"dcql\""));
    assert!(!wallet_config.contains("presentation_definition"));
    assert!(wallet_config.contains("\"trust_anchor_pem\""));
    assert!(wallet_config.contains("\"status_list_trust_anchor_pem\""));
    assert!(wallet_config.contains("\"client2\""));
    assert!(wallet_config.contains("vp-signing-jwk-2.json"));
    assert!(wallet_mdoc_config.contains("\"format\": \"mso_mdoc\""));
    assert!(wallet_mdoc_config.contains("org.iso.18013.5.1.mDL"));
    assert!(wallet_mdoc_config.contains("\"trust_anchor_pem\""));
    assert!(!wallet_mdoc_config.contains("dc+sd-jwt"));
    assert!(!workflow.contains("conformance/scripts/run_oidf_wallet_plan.sh"));
    assert!(!workflow.contains("conformance/scripts/run_oidf_verifier_plan.sh"));
    assert!(workflow.contains("read_oidf_certification_matrix.py"));
    assert!(workflow.contains("commit conformance/oidf/profile-matrix.json"));
    assert!(!workflow.contains("profile_id:"));
    assert!(!workflow.contains("inputs."));
    assert!(workflow.contains("fetch --depth 1 origin \"${oidf_suite_commit}\""));
    assert!(!workflow.contains("oidf_demo_commit"));
    assert!(!workflow.contains("secrets."));
    assert!(!workflow.contains("OIDF_WALLET_HARNESS_ENDPOINT"));
    assert!(!workflow.contains("OIDF_CONFORMANCE_TOKEN"));
    assert!(wallet_driver.contains("browser"));
    assert!(wallet_driver.contains("visited"));
    assert!(wallet_driver.contains("OIDF_WALLET_HARNESS_ENDPOINT"));
    assert!(wallet_driver.contains("OIDF_WALLET_HARNESS_TOKEN"));
    assert!(verifier_plan.contains("oid4vp-1final-verifier-haip-test-plan"));
    assert!(wallet_plan.contains("oid4vp-1final-wallet-haip-test-plan"));
    assert!(wallet_plan.contains("reallyme/wallet"));
    assert!(verifier.contains("assert_oidf_results.py"));
    assert!(strict_verifier.contains("result_module_coverage_mismatch"));
    assert!(strict_verifier.contains("result_module_unexpected_result"));
    assert!(strict_verifier.contains("PASSED"));
    assert!(strict_verifier.contains("REVIEW"));
    assert!(strict_verifier.contains("result_module_not_finished"));
    assert!(strict_verifier.contains("result_suite_version_mismatch"));
    assert!(strict_verifier.contains("variant_keys"));
    assert!(strict_verifier.contains("MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES"));
    assert!(target_verifier.contains("matrix_module_coverage_drift"));
    assert!(target_verifier.contains("suite_commit_mismatch"));
    assert!(target_verifier.contains("suite_worktree_dirty"));
    assert!(!target_verifier.contains("--overlay"));
    assert!(wallet_config_verifier.contains("wallet_config_signers_not_distinct"));
    assert!(wallet_config_verifier.contains("wallet_config_duplicate_json_key"));
    assert!(wallet_config_verifier.contains("wallet_config_trust_anchor_material_mismatch"));
    assert!(wallet_config_verifier.contains("wallet_config_profile_format_mismatch"));
    assert!(matrix_reader.contains("matrix_credential_format_ambiguous"));
    assert!(matrix_reader.contains("matrix_role_profiles_missing"));
    assert!(workflow.contains("conformance/scripts/discover_oidf_openid4vp.py"));
    assert!(workflow.contains("conformance/scripts/verify_oidf_certification_target.py"));
    assert!(workflow.contains("conformance/scripts/test_assert_oidf_results.py"));
    assert!(workflow.contains("conformance/scripts/test_drive_oidf_verifier_flow.py"));
    assert!(workflow.contains("conformance/scripts/test_collect_oidf_verifier_evidence.py"));
    assert!(workflow.contains("conformance/scripts/test_drive_oidf_wallet_flow.py"));
    assert!(workflow.contains("conformance/scripts/test_read_oidf_certification_matrix.py"));
    assert!(!workflow.contains("conformance/scripts/seal_oidf_evidence.py"));
    assert!(!workflow.contains("OIDF_DEPLOYMENT_NAME"));
    assert!(!workflow.contains("OIDF_DEPLOYMENT_VERSION"));
    assert!(!workflow.contains("schedule:"));
    assert!(workflow.contains("conformance/scripts/test_validate_oidf_runtime_endpoints.py"));
    assert!(workflow.contains("conformance/scripts/test_verify_oidf_certification_target.py"));
    assert!(workflow.contains("conformance/scripts/test_verify_oidf_wallet_config.py"));
    assert!(!workflow.contains("workflow_call:"));
    assert!(workflow
        .contains("maven@sha256:c2a2c58516d160f43b50f12baa427ca86989e0bc942609e04aff61da5d9a7d74"));
    assert!(workflow.contains("-e HOME=/maven-home"));
    assert!(workflow.contains("-e MAVEN_CONFIG=/maven-home"));
    assert!(workflow.contains("-Dmaven.repo.local=/maven-home/repository"));
    assert!(workflow.contains("-Dmaven.test.skip -Dpmd.skip clean package"));
    assert!(workflow.contains("VariantCondition_UnitTest,LoadBuiltInDcqlQuery_UnitTest,*VP1Final*"));
    assert!(workflow.contains("cargo test --locked -p reallyme-openid4vp-conformance"));
    assert!(workflow.contains("python3 -m venv \"${runner_venv}\""));
    assert!(workflow.contains("\"${runner_venv}/bin/python\" -m pip install"));
    assert!(workflow.contains("--only-binary=:all:"));
    assert!(workflow.contains("--require-hashes"));
    assert!(workflow.contains("conformance/scripts/oidf-runner-requirements.lock"));
    assert!(workflow.contains("rev-parse HEAD)\" = \"${oidf_suite_commit}"));
    assert!(workflow.contains("oidf_plan_execution: false"));
    assert!(workflow.contains("certification_evidence: false"));
    assert!(workflow.contains("path: openid4vp/target/oidf-protocol-compatibility"));
    assert!(workflow.contains("if-no-files-found: error"));
    assert!(preflight.contains("require_command docker"));
    assert!(preflight.contains("docker daemon is not reachable"));
    assert!(!preflight.contains("require_command java"));
    assert!(!preflight.contains("require_command mvn"));
    assert!(preflight.contains("missing required command"));
    assert!(discovery.contains("Discover OpenID4VP"));
    assert!(endpoint_validator.contains("oidf_runtime_endpoint_invalid"));
    assert!(endpoint_validator.contains("parsed.username is not None"));
    let conformance_readme = include_str!("../README.md");
    assert!(conformance_readme.contains("downstream `identity-conformance` orchestration"));
    assert!(conformance_readme.contains("Publish for certification"));
    assert!(conformance_readme.contains("Declaration of Conformance"));
    assert!(!conformance_readme.contains("reallyme/openid-conformance"));
    assert!(!include_str!("../README.md").contains("reports/oidf-manifest.json"));
}

#[test]
fn oidf_profile_matrix_covers_all_supported_haip_profiles() {
    let matrix = parse_json_or_null(include_str!("../oidf/profile-matrix.json"));
    let profiles = matrix
        .get("profiles")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        profiles.len(),
        6,
        "public matrix must contain all six supported HAIP profiles"
    );

    let verifier_profiles = profiles
        .iter()
        .filter(|profile| profile.get("role").and_then(Value::as_str) == Some("verifier"))
        .count();
    let wallet_profiles = profiles
        .iter()
        .filter(|profile| profile.get("role").and_then(Value::as_str) == Some("wallet"))
        .count();
    assert_eq!(verifier_profiles, 2);
    assert_eq!(wallet_profiles, 4);

    let mut total_expected_module_executions = 0usize;
    for profile in profiles {
        assert!(
            profile
                .get("plan_id")
                .and_then(Value::as_str)
                .is_some_and(|plan_id| plan_id.ends_with("-haip-test-plan")),
            "every certification profile must use a HAIP plan"
        );
        let expected_module_count = profile
            .get("expected_groups")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|group| group.get("modules").and_then(Value::as_array))
            .map(Vec::len)
            .sum::<usize>();
        assert!(
            expected_module_count > 0,
            "every certification profile must enumerate expected modules"
        );
        let expected_modules = profile
            .get("expected_groups")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|group| group.get("modules").and_then(Value::as_array))
            .flatten()
            .filter_map(Value::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        let review_required = profile
            .get("review_required_modules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let review_allowed = profile
            .get("review_allowed_modules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert!(
            profile.get("review_required_modules").is_some()
                && profile.get("review_allowed_modules").is_some(),
            "every profile must declare its exact suite review policy"
        );
        let review_required = review_required
            .iter()
            .filter_map(Value::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        let review_allowed = review_allowed
            .iter()
            .filter_map(Value::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert!(review_required.is_subset(&expected_modules));
        assert!(review_allowed.is_subset(&expected_modules));
        assert!(review_required.is_disjoint(&review_allowed));
        total_expected_module_executions += expected_module_count;
        if profile.get("role").and_then(Value::as_str) == Some("verifier") {
            let expectations = profile
                .get("evidence_expectations")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            assert_eq!(
                expectations.len(),
                expected_module_count,
                "every verifier module needs an evidence expectation"
            );
        }
    }
    assert_eq!(
        total_expected_module_executions, 119,
        "the reviewed suite revision has exactly 119 HAIP module executions"
    );
}

#[test]
fn implemented_requirements_are_mapped_to_tests() {
    assert_implemented_requirements_are_mapped(RequirementManifest {
        name: "requirements/openid4vp.json",
        body: parse_json_or_null(include_str!("../requirements/openid4vp.json")),
    });
    assert_implemented_requirements_are_mapped(RequirementManifest {
        name: "requirements/haip-presentation.json",
        body: parse_json_or_null(include_str!("../requirements/haip-presentation.json")),
    });
    assert_implemented_requirements_are_mapped(RequirementManifest {
        name: "requirements/eudi-presentation.json",
        body: parse_json_or_null(include_str!("../requirements/eudi-presentation.json")),
    });
}

#[test]
fn requirement_test_anchors_exist_in_repo() {
    assert_requirement_test_anchors_exist(RequirementManifest {
        name: "requirements/openid4vp.json",
        body: parse_json_or_null(include_str!("../requirements/openid4vp.json")),
    });
    assert_requirement_test_anchors_exist(RequirementManifest {
        name: "requirements/haip-presentation.json",
        body: parse_json_or_null(include_str!("../requirements/haip-presentation.json")),
    });
    assert_requirement_test_anchors_exist(RequirementManifest {
        name: "requirements/eudi-presentation.json",
        body: parse_json_or_null(include_str!("../requirements/eudi-presentation.json")),
    });
}

#[test]
fn requirement_manifests_bind_atomic_claims_to_executable_evidence() {
    let openid4vp = parse_json_or_null(include_str!("../requirements/openid4vp.json"));
    assert!(requirement_manifest_is_semantic(
        &openid4vp,
        "openid4vp-1.0-final",
        "08e635ea3563b192309c627382c281c81de176e94cdb5ffb11b13ac624f7e12e",
    ));

    let haip = parse_json_or_null(include_str!("../requirements/haip-presentation.json"));
    assert!(requirement_manifest_is_semantic(
        &haip,
        "haip-1.0-final",
        "3996e0479d06b72d6d68668b8ae3cd39fddfc29ae9220c0c3fead7dc060ec4fb",
    ));

    let mut helper_as_evidence = openid4vp.clone();
    helper_as_evidence["requirements"][0]["positive_tests"][0] = Value::String(
        "reallyme_openid4vp_conformance::manifest_tests::test_anchor_exists".to_owned(),
    );
    assert!(!requirement_manifest_is_semantic(
        &helper_as_evidence,
        "openid4vp-1.0-final",
        "08e635ea3563b192309c627382c281c81de176e94cdb5ffb11b13ac624f7e12e",
    ));

    let mut wrong_module = openid4vp.clone();
    wrong_module["requirements"][0]["positive_tests"][0] = Value::String(
        "reallyme_openid4vp_types::response::tests::evaluates_required_query_with_selected_claims"
            .to_owned(),
    );
    assert!(!requirement_manifest_is_semantic(
        &wrong_module,
        "openid4vp-1.0-final",
        "08e635ea3563b192309c627382c281c81de176e94cdb5ffb11b13ac624f7e12e",
    ));

    let mut inverse_evidence = openid4vp.clone();
    inverse_evidence["requirements"][0]["positive_tests"][0] = Value::String(
        "reallyme_openid4vp_dcql::evaluate::tests::rejects_duplicate_query_ids".to_owned(),
    );
    assert!(!requirement_manifest_is_semantic(
        &inverse_evidence,
        "openid4vp-1.0-final",
        "08e635ea3563b192309c627382c281c81de176e94cdb5ffb11b13ac624f7e12e",
    ));

    let mut changed_digest = openid4vp;
    changed_digest["requirements"][0]["normative_reference"]["sha256"] =
        Value::String("0".repeat(64));
    assert!(!requirement_manifest_is_semantic(
        &changed_digest,
        "openid4vp-1.0-final",
        "08e635ea3563b192309c627382c281c81de176e94cdb5ffb11b13ac624f7e12e",
    ));
}

#[test]
fn eudi_open_items_have_accountable_next_actions() {
    assert_open_items_have_next_actions(
        parse_json_or_null(include_str!("../eudi/test-cases.json"))
            .get("test_cases")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    );
    assert_open_items_have_next_actions(
        parse_json_or_null(include_str!("../eudi/upstream-tests.json"))
            .get("tests")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    );
}

#[test]
fn eudi_fixture_inventory_has_owned_or_delegated_evidence() {
    let inventory = parse_json_or_null(include_str!("../eudi/fixture-inventory.json"));
    let fixtures = inventory
        .get("fixtures")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(
        !fixtures.is_empty(),
        "EUDI fixture inventory must contain fixture records"
    );

    for fixture in fixtures {
        let fixture_id = fixture
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("unknown-fixture");
        let status = fixture.get("status").and_then(Value::as_str).unwrap_or("");
        match status {
            "covered-locally" => {
                let path = fixture
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                assert!(
                    fixture_path_exists(path),
                    "local fixture inventory path must exist: {fixture_id} {path}"
                );
                assert!(
                    has_non_empty_string_array(&fixture, "local_evidence"),
                    "local fixture must map evidence: {fixture_id}"
                );
            }
            "delegated" => {
                assert!(
                    fixture
                        .get("owner")
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.trim().is_empty()),
                    "delegated fixture must name owner: {fixture_id}"
                );
                assert!(
                    has_non_empty_string_array(&fixture, "delegated_evidence"),
                    "delegated fixture must map evidence: {fixture_id}"
                );
            }
            _ => {
                assert!(
                    fixture
                        .get("next_action")
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.trim().is_empty()),
                    "open fixture must have next_action: {fixture_id}"
                );
            }
        }
    }
}

struct RequirementManifest {
    name: &'static str,
    body: Value,
}

fn parse_json_or_null(body: &str) -> Value {
    match serde_json::from_str(body) {
        Ok(value) => value,
        Err(_) => Value::Null,
    }
}

fn assert_implemented_requirements_are_mapped(manifest: RequirementManifest) {
    let entries = requirements(&manifest);
    assert!(
        !entries.is_empty(),
        "requirement manifest must contain records: {}",
        manifest.name
    );

    for item in entries {
        let status = item.get("status").and_then(Value::as_str).unwrap_or("");
        if !status.starts_with("implemented") {
            continue;
        }

        let requirement_id = item
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("unknown-requirement");
        assert!(
            has_non_empty_string_array(&item, "implementation_paths"),
            "implemented requirement must map implementation anchors: {} {}",
            manifest.name,
            requirement_id
        );
        assert!(
            has_non_empty_string_array(&item, "positive_tests")
                || has_non_empty_string_array(&item, "negative_tests"),
            "implemented requirement must map tests: {} {}",
            manifest.name,
            requirement_id
        );
    }
}

fn assert_requirement_test_anchors_exist(manifest: RequirementManifest) {
    for item in requirements(&manifest) {
        let requirement_id = item
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("unknown-requirement");
        for test_name in string_array_values(&item, "positive_tests") {
            assert!(
                test_anchor_exists(test_name),
                "requirement maps an unknown positive test anchor: {} {} {}",
                manifest.name,
                requirement_id,
                test_name
            );
        }
        for test_name in string_array_values(&item, "negative_tests") {
            assert!(
                test_anchor_exists(test_name),
                "requirement maps an unknown negative test anchor: {} {} {}",
                manifest.name,
                requirement_id,
                test_name
            );
        }
    }
}

fn requirement_manifest_is_semantic(
    manifest: &Value,
    expected_specification: &str,
    expected_digest: &str,
) -> bool {
    if manifest.get("schema_version").and_then(Value::as_u64) != Some(2)
        || manifest.get("specification").and_then(Value::as_str) != Some(expected_specification)
        || manifest.get("specification_sha256").and_then(Value::as_str) != Some(expected_digest)
    {
        return false;
    }

    let Some(requirements) = manifest.get("requirements").and_then(Value::as_array) else {
        return false;
    };
    if requirements.is_empty() {
        return false;
    }

    requirements.iter().all(|requirement| {
        let status = requirement
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !status.starts_with("implemented") {
            return true;
        }
        let nonempty = |key: &str| {
            requirement
                .get(key)
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty())
        };
        let Some(reference) = requirement.get("normative_reference") else {
            return false;
        };
        if !nonempty("normative_statement")
            || reference.get("specification_id").and_then(Value::as_str)
                != Some(expected_specification)
            || reference.get("sha256").and_then(Value::as_str) != Some(expected_digest)
            || !reference
                .get("section")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty())
            || !has_non_empty_string_array(requirement, "implementation_paths")
            || !has_non_empty_string_array(requirement, "positive_tests")
            || !has_non_empty_string_array(requirement, "negative_tests")
        {
            return false;
        }

        let positive = string_array_values(requirement, "positive_tests");
        let negative = string_array_values(requirement, "negative_tests");
        positive.iter().all(|identity| {
            executable_test_exists(identity)
                && evidence_polarity(identity) == EvidencePolarity::Positive
        }) && negative.iter().all(|identity| {
            executable_test_exists(identity)
                && evidence_polarity(identity) == EvidencePolarity::Negative
        }) && positive.iter().all(|identity| !negative.contains(identity))
    })
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum EvidencePolarity {
    Positive,
    Negative,
}

fn evidence_polarity(identity: &str) -> EvidencePolarity {
    let name = identity.rsplit("::").next().unwrap_or_default();
    if name.starts_with("rejects_")
        || name == "haip_profile_rejects_plaintext_response_modes"
        || name.starts_with("preserves_rejected_")
        || name.starts_with("verifier_http_runtime_maps_missing_")
        || matches!(
            name,
            "enforces_required_credential_sets"
                | "enforces_x5c_count_and_certificate_size_bounds"
                | "requires_every_query_when_no_credential_sets_are_present"
                | "verifier_http_runtime_rejects_wrong_browser_and_replayed_follow_back"
                | "verifier_http_runtime_keeps_timed_out_follow_back_result_unreleased"
                | "authorization_error_does_not_create_a_follow_back_result"
        )
    {
        EvidencePolarity::Negative
    } else {
        EvidencePolarity::Positive
    }
}

fn assert_open_items_have_next_actions(entries: Vec<Value>) {
    for item in entries {
        let status = item.get("status").and_then(Value::as_str).unwrap_or("");
        let has_local_test = item
            .get("local_test")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty());
        let has_exclusion = item
            .get("exclusion_reason")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty());
        if status.starts_with("implemented")
            || status.starts_with("covered-locally")
            || status == "pinned-release"
            || has_local_test
            || has_exclusion
        {
            continue;
        }
        assert!(
            item.get("next_action")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "open EUDI item must have next_action: {item:?}"
        );
    }
}
