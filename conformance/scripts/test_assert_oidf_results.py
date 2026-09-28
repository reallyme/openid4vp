#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import assert_oidf_results


PLAN_ID = "oid4vp-1final-verifier-haip-test-plan"
PROFILE_ID = "verifier-test-profile"
MODULE_ID = "oid4vp-1final-verifier-happy-flow"
MODULE_VARIANTS = {
    "vp_profile": "haip",
    "credential_format": "sd_jwt_vc",
    "response_mode": "direct_post.jwt",
    "client_id_prefix": "x509_hash",
    "request_method": "request_uri_signed",
}
MODULE_VARIANT_KEYS = tuple(sorted(MODULE_VARIANTS))


def bind_result_policy(
    matrix: dict[str, object], module_id: str, mode: str
) -> None:
    sources = matrix["result_policy_sources"]
    if not isinstance(sources, dict):
        raise AssertionError("fixture result policy source map is invalid")
    sources[module_id] = {
        "mode": mode,
        "module_source": "src/main/java/example/Module.java",
        "review_source": "src/main/java/example/Module.java",
    }


class AssertOidfResultsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.matrix = self.root / "matrix.json"
        self.results = self.root / "results"
        self.results.mkdir()
        self.matrix.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "suite": {
                        "repository": "https://gitlab.com/openid/conformance-suite",
                        "commit": "0" * 40,
                        "describe": "production",
                        "version": "5.3.1",
                    },
                    "result_policy_sources": {},
                    "profiles": [
                        {
                            "id": PROFILE_ID,
                            "plan_id": PLAN_ID,
                            "review_required_modules": [],
                            "review_allowed_modules": [],
                            "expected_groups": [
                                {
                                    "variants": MODULE_VARIANTS,
                                    "modules": [MODULE_ID],
                                }
                            ],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

    def test_overlay_adds_rehearsal_module_to_expected_export(self) -> None:
        overlay = self.root / "overlay.json"
        overlay.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "purpose": "oidf-demo-pre-submission",
                    "suite": {
                        "repository": "https://gitlab.com/openid/conformance-suite",
                        "commit": "1" * 40,
                        "describe": "demo",
                        "version": "5.2.4",
                    },
                    "profile_additions": [
                        {
                            "profile_id": PROFILE_ID,
                            "group_variants": MODULE_VARIANTS,
                            "modules": ["rehearsal-module"],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        expected = assert_oidf_results.load_expected_profile(
            self.matrix, PROFILE_ID, overlay
        )

        self.assertEqual(sum(expected.cases.values()), 2)

    def test_accepts_complete_passing_export(self) -> None:
        self.write_result("PASSED")

        expected = assert_oidf_results.load_expected_profile(self.matrix, PROFILE_ID)
        observed = assert_oidf_results.collect_results(
            self.results, expected.variant_keys
        )

        self.assertIsNone(
            assert_oidf_results.assert_complete_results(expected, observed)
        )

    def test_rejects_skipped_applicable_module(self) -> None:
        self.write_result("SKIPPED")

        self.assert_failure("result_module_unexpected_result")

    def test_rejects_failed_module(self) -> None:
        self.write_result("FAILED")

        self.assert_failure("result_module_unexpected_result")

    def test_accepts_review_only_for_explicitly_review_required_module(self) -> None:
        matrix = json.loads(self.matrix.read_text(encoding="utf-8"))
        matrix["profiles"][0]["review_required_modules"] = [MODULE_ID]
        bind_result_policy(matrix, MODULE_ID, "review_required")
        self.matrix.write_text(json.dumps(matrix), encoding="utf-8")
        self.write_result("REVIEW")

        expected = assert_oidf_results.load_expected_profile(self.matrix, PROFILE_ID)
        observed = assert_oidf_results.collect_results(
            self.results, expected.variant_keys
        )

        self.assertIsNone(
            assert_oidf_results.assert_complete_results(expected, observed)
        )

    def test_rejects_passed_for_review_required_module(self) -> None:
        matrix = json.loads(self.matrix.read_text(encoding="utf-8"))
        matrix["profiles"][0]["review_required_modules"] = [MODULE_ID]
        bind_result_policy(matrix, MODULE_ID, "review_required")
        self.matrix.write_text(json.dumps(matrix), encoding="utf-8")
        self.write_result("PASSED")

        self.assert_failure("result_module_unexpected_result")

    def test_review_allowed_module_accepts_passed_or_review(self) -> None:
        matrix = json.loads(self.matrix.read_text(encoding="utf-8"))
        matrix["profiles"][0]["review_allowed_modules"] = [MODULE_ID]
        bind_result_policy(matrix, MODULE_ID, "review_allowed")
        self.matrix.write_text(json.dumps(matrix), encoding="utf-8")

        for result_value in ("PASSED", "REVIEW"):
            self.write_result(result_value)
            expected = assert_oidf_results.load_expected_profile(
                self.matrix, PROFILE_ID
            )
            observed = assert_oidf_results.collect_results(
                self.results, expected.variant_keys
            )
            self.assertIsNone(
                assert_oidf_results.assert_complete_results(expected, observed)
            )

    def test_rejects_unclassified_review_result(self) -> None:
        self.write_result("REVIEW")

        self.assert_failure("result_module_unexpected_result")

    def test_rejects_overlapping_or_unknown_review_policy(self) -> None:
        base_matrix = self.matrix.read_text(encoding="utf-8")
        for required, allowed, reason in (
            (
                [MODULE_ID],
                [MODULE_ID],
                "matrix_result_policy_sources_invalid",
            ),
            (["unknown-module"], [], "matrix_result_expectations_invalid"),
        ):
            matrix = json.loads(base_matrix)
            matrix["profiles"][0]["review_required_modules"] = required
            matrix["profiles"][0]["review_allowed_modules"] = allowed
            for module_id in set(required + allowed):
                mode = (
                    "review_required"
                    if module_id in required
                    else "review_allowed"
                )
                bind_result_policy(matrix, module_id, mode)
            self.matrix.write_text(json.dumps(matrix), encoding="utf-8")

            with self.assertRaises(assert_oidf_results.ResultFailure) as caught:
                assert_oidf_results.load_expected_profile(self.matrix, PROFILE_ID)
            self.assertEqual(caught.exception.reason, reason)

    def test_rejects_missing_expected_module(self) -> None:
        (self.results / "metadata.json").write_text("{}", encoding="utf-8")

        with self.assertRaises(assert_oidf_results.ResultFailure) as caught:
            assert_oidf_results.collect_results(self.results, MODULE_VARIANT_KEYS)
        self.assertEqual(caught.exception.reason, "result_test_logs_missing")

    def test_rejects_unexpected_module(self) -> None:
        self.write_result("PASSED", module_id="unexpected-module")

        self.assert_failure("result_module_coverage_mismatch")

    def test_rejects_unexpected_module_variant(self) -> None:
        result = json.loads(self.result_json("PASSED"))
        result["testInfo"]["variant"]["variant"]["request_method"] = "url_query"
        (self.results / "result.json").write_text(
            json.dumps(result), encoding="utf-8"
        )

        self.assert_failure("result_module_coverage_mismatch")

    def test_rejects_wrong_credential_format_even_when_modules_match(self) -> None:
        result = json.loads(self.result_json("PASSED"))
        result["testInfo"]["variant"]["variant"]["credential_format"] = "iso_mdl"
        (self.results / "result.json").write_text(
            json.dumps(result), encoding="utf-8"
        )

        self.assert_failure("result_module_coverage_mismatch")

    def test_rejects_wrong_response_mode_even_when_modules_match(self) -> None:
        result = json.loads(self.result_json("PASSED"))
        result["testInfo"]["variant"]["variant"]["response_mode"] = "dc_api.jwt"
        (self.results / "result.json").write_text(
            json.dumps(result), encoding="utf-8"
        )

        self.assert_failure("result_module_coverage_mismatch")

    def test_rejects_unfinished_module(self) -> None:
        result = json.loads(self.result_json("PASSED"))
        result["testInfo"]["status"] = "RUNNING"
        (self.results / "result.json").write_text(
            json.dumps(result), encoding="utf-8"
        )

        self.assert_failure("result_module_not_finished")

    def test_rejects_wrong_suite_version(self) -> None:
        result = json.loads(self.result_json("PASSED"))
        result["exportedVersion"] = "5.2.4"
        (self.results / "result.json").write_text(
            json.dumps(result), encoding="utf-8"
        )

        self.assert_failure("result_suite_version_mismatch")

    def test_rejects_wrong_test_version(self) -> None:
        result = json.loads(self.result_json("PASSED"))
        result["testInfo"]["version"] = "5.2.4"
        (self.results / "result.json").write_text(
            json.dumps(result), encoding="utf-8"
        )

        self.assert_failure("result_suite_version_mismatch")

    def test_rejects_results_from_multiple_plan_instances(self) -> None:
        profile = json.loads(self.matrix.read_text(encoding="utf-8"))
        profile["profiles"][0]["expected_groups"][0]["modules"].append(MODULE_ID)
        self.matrix.write_text(json.dumps(profile), encoding="utf-8")
        (self.results / "first.json").write_text(
            self.result_json("PASSED", plan_instance_id="plan-instance-one"),
            encoding="utf-8",
        )
        (self.results / "second.json").write_text(
            self.result_json("PASSED", plan_instance_id="plan-instance-two"),
            encoding="utf-8",
        )

        self.assert_failure("result_plan_instance_mismatch")

    def test_rejects_export_from_a_different_plan_instance(self) -> None:
        self.write_result("PASSED", plan_instance_id="observed-plan-instance")
        expected = assert_oidf_results.load_expected_profile(self.matrix, PROFILE_ID)
        observed = assert_oidf_results.collect_results(
            self.results, expected.variant_keys
        )

        with self.assertRaises(assert_oidf_results.ResultFailure) as caught:
            assert_oidf_results.assert_complete_results(
                expected, observed, "expected-plan-instance"
            )
        self.assertEqual(
            caught.exception.reason, "result_plan_instance_binding_mismatch"
        )

    def test_rejects_duplicate_json_members(self) -> None:
        (self.results / "result.json").write_text(
            '{"testInfo":{"testName":"one","testName":"two","result":"PASSED"}}',
            encoding="utf-8",
        )

        with self.assertRaises(assert_oidf_results.ResultFailure) as caught:
            assert_oidf_results.collect_results(self.results, MODULE_VARIANT_KEYS)
        self.assertEqual(caught.exception.reason, "result_json_invalid")

    def test_rejects_non_standard_non_finite_json_number(self) -> None:
        (self.results / "result.json").write_text(
            '{"testInfo":NaN}', encoding="utf-8"
        )

        with self.assertRaises(assert_oidf_results.ResultFailure) as caught:
            assert_oidf_results.collect_results(self.results, MODULE_VARIANT_KEYS)
        self.assertEqual(caught.exception.reason, "result_json_invalid")

    def test_rejects_oversized_json_before_parsing(self) -> None:
        (self.results / "result.json").write_bytes(b"{" + (b" " * 32))

        with mock.patch.object(assert_oidf_results, "MAX_JSON_BYTES", 8):
            with self.assertRaises(assert_oidf_results.ResultFailure) as caught:
                assert_oidf_results.collect_results(
                    self.results, MODULE_VARIANT_KEYS
                )
        self.assertEqual(caught.exception.reason, "result_json_too_large")

    def test_rejects_excessively_nested_json_with_stable_error(self) -> None:
        (self.results / "result.json").write_text(
            ("[" * 200) + ("]" * 200), encoding="utf-8"
        )

        with self.assertRaises(assert_oidf_results.ResultFailure) as caught:
            assert_oidf_results.collect_results(self.results, MODULE_VARIANT_KEYS)
        self.assertEqual(caught.exception.reason, "result_json_nesting_exceeded")

    def test_rejects_zip_member_path_traversal(self) -> None:
        with zipfile.ZipFile(self.results / "results.zip", "w") as archive:
            archive.writestr("../result.json", self.result_json("PASSED"))

        with self.assertRaises(assert_oidf_results.ResultFailure) as caught:
            assert_oidf_results.collect_results(self.results, MODULE_VARIANT_KEYS)
        self.assertEqual(caught.exception.reason, "result_zip_member_path_invalid")

    def test_reads_bounded_zip_export(self) -> None:
        with zipfile.ZipFile(self.results / "results.zip", "w") as archive:
            archive.writestr("result.json", self.result_json("PASSED"))

        expected = assert_oidf_results.load_expected_profile(self.matrix, PROFILE_ID)
        observed = assert_oidf_results.collect_results(
            self.results, expected.variant_keys
        )

        self.assertIsNone(
            assert_oidf_results.assert_complete_results(expected, observed)
        )

    def test_accepts_all_exact_profiles_from_reviewed_matrix(self) -> None:
        reviewed_matrix = (
            Path(__file__).resolve().parent.parent
            / "oidf"
            / "profile-matrix.json"
        )
        matrix_value = json.loads(reviewed_matrix.read_text(encoding="utf-8"))
        profiles = matrix_value["profiles"]
        module_execution_count = 0

        for profile in profiles:
            profile_results = self.root / profile["id"]
            profile_results.mkdir()
            result_index = 0
            review_required = set(profile["review_required_modules"])
            for group in profile["expected_groups"]:
                for module_id in group["modules"]:
                    module_execution_count += 1
                    result_index += 1
                    result = {
                        "exportedVersion": matrix_value["suite"]["version"],
                        "testInfo": {
                            "planId": f"instance-{profile['id']}",
                            "testName": module_id,
                            "status": "FINISHED",
                            "result": (
                                "REVIEW" if module_id in review_required else "PASSED"
                            ),
                            "version": matrix_value["suite"]["version"],
                            "variant": {"variant": group["variants"]},
                        }
                    }
                    (profile_results / f"result-{result_index}.json").write_text(
                        json.dumps(result), encoding="utf-8"
                    )

            expected = assert_oidf_results.load_expected_profile(
                reviewed_matrix, profile["id"]
            )
            observed = assert_oidf_results.collect_results(
                profile_results, expected.variant_keys
            )
            self.assertIsNone(
                assert_oidf_results.assert_complete_results(expected, observed)
            )

        self.assertEqual(len(profiles), 6)
        self.assertEqual(module_execution_count, 119)

    def assert_failure(self, reason: str) -> None:
        expected = assert_oidf_results.load_expected_profile(self.matrix, PROFILE_ID)
        observed = assert_oidf_results.collect_results(
            self.results, expected.variant_keys
        )
        with self.assertRaises(assert_oidf_results.ResultFailure) as caught:
            assert_oidf_results.assert_complete_results(expected, observed)
        self.assertEqual(caught.exception.reason, reason)

    def write_result(
        self,
        result: str,
        module_id: str = MODULE_ID,
        plan_instance_id: str = PLAN_ID,
    ) -> None:
        (self.results / "result.json").write_text(
            self.result_json(result, module_id, plan_instance_id), encoding="utf-8"
        )

    @staticmethod
    def result_json(
        result: str,
        module_id: str = MODULE_ID,
        plan_instance_id: str = PLAN_ID,
    ) -> str:
        return json.dumps(
            {
                "exportedVersion": "5.3.1",
                "testInfo": {
                    "planId": plan_instance_id,
                    "testName": module_id,
                    "status": "FINISHED",
                    "result": result,
                    "version": "5.3.1",
                    "variant": {"variant": MODULE_VARIANTS},
                }
            }
        )


if __name__ == "__main__":
    unittest.main()
