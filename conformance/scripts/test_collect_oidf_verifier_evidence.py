#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import collect_oidf_verifier_evidence as collector


PROFILE_ID = "verifier-sd-jwt-vc-direct-post-jwt"
PLAN_ID = "oid4vp-1final-verifier-haip-test-plan"
PLAN_INSTANCE_ID = "plan-instance-1"
MODULE_NAME = "oid4vp-1final-verifier-happy-flow"
MODULE_ID = "module-instance-1"
CONTROL_TOKEN = "e" * collector.MIN_CONTROL_TOKEN_BYTES


def matrix() -> dict[str, object]:
    return {
        "schema_version": 1,
        "profiles": [
            {
                "id": PROFILE_ID,
                "role": "verifier",
                "plan_id": PLAN_ID,
                "review_required_modules": [],
                "review_allowed_modules": [],
                "evidence_expectations": {
                    MODULE_NAME: {
                        "decision": "accepted",
                        "observation_kind": "authorization_response_validation",
                        "minimum_observations": 1,
                    }
                },
                "expected_groups": [{"modules": [MODULE_NAME]}],
            }
        ],
    }


def evidence() -> dict[str, object]:
    return {
        "schema_version": 1,
        "plan_id": PLAN_ID,
        "profile_id": PROFILE_ID,
        "module_id": MODULE_ID,
        "module_name": MODULE_NAME,
        "decision": "accepted",
        "reason_code": "authorization_response_accepted",
        "observations": [
            {
                "kind": "authorization_response_validation",
                "outcome": "accepted",
                "reason_code": "credential_proofs_valid",
            }
        ],
    }


def config(root: Path, matrix_path: Path) -> collector.CollectorConfig:
    return collector.CollectorConfig(
        conformance_server="https://www.certification.openid.net/",
        conformance_api_token="secret",
        verify_ssl=True,
        evidence_endpoint="https://verifier.example.test/oidf/evidence",
        evidence_token=CONTROL_TOKEN,
        plan_id=PLAN_ID,
        alias="oidf-vp-test-wallet",
        started_after=1.0,
        profile_id=PROFILE_ID,
        output_directory=root / "evidence",
        matrix_path=matrix_path,
    )


class CollectOidfVerifierEvidenceTests(unittest.TestCase):
    def test_secret_bearing_config_disables_generated_repr(self) -> None:
        configured = config(Path("."), Path("matrix.json"))

        self.assertNotIn(CONTROL_TOKEN, repr(configured))
        self.assertNotIn("secret", repr(configured))

    def test_dev_mode_omits_suite_api_authorization(self) -> None:
        args = argparse.Namespace(
            matrix="matrix.json",
            profile=PROFILE_ID,
            plan=PLAN_ID,
            alias="unique-alias",
            started_after=1.0,
            output_dir="evidence",
        )
        environment = {
            "CONFORMANCE_DEV_MODE": "true",
            "CONFORMANCE_SERVER": "https://suite.example.test/",
            "OIDF_VERIFIER_EVIDENCE_ENDPOINT": "https://verifier.example.test/evidence",
            "OIDF_VERIFIER_EVIDENCE_TOKEN": CONTROL_TOKEN,
        }
        with mock.patch.dict(collector.os.environ, environment, clear=True):
            configured = collector.read_config(args)
        self.assertIsNone(configured.conformance_api_token)

        without_token = replace(
            config(Path("."), Path("matrix.json")),
            conformance_api_token=None,
        )
        with mock.patch.object(
            collector,
            "read_json_response",
            return_value={"status": "ok"},
        ) as read_json_response:
            collector.api_get_json(without_token, "api/runner")
        request = read_json_response.call_args_list[0].args[0]
        self.assertNotIn("Authorization", request.headers)

    def test_dev_mode_allows_only_loopback_http_evidence_endpoint(self) -> None:
        args = argparse.Namespace(
            matrix="matrix.json",
            profile=PROFILE_ID,
            plan=PLAN_ID,
            alias="unique-alias",
            started_after=1.0,
            output_dir="evidence",
        )
        base_environment = {
            "CONFORMANCE_DEV_MODE": "true",
            "CONFORMANCE_SERVER": "https://suite.example.test/",
            "OIDF_VERIFIER_EVIDENCE_TOKEN": CONTROL_TOKEN,
        }
        for endpoint in (
            "http://127.0.0.1:8791/evidence",
            "http://[::1]:8791/evidence",
            "http://localhost:8791/evidence",
        ):
            with self.subTest(endpoint=endpoint), mock.patch.dict(
                collector.os.environ,
                {**base_environment, "OIDF_VERIFIER_EVIDENCE_ENDPOINT": endpoint},
                clear=True,
            ):
                collector.read_config(args)

        with mock.patch.dict(
            collector.os.environ,
            {
                **base_environment,
                "OIDF_VERIFIER_EVIDENCE_ENDPOINT": "http://verifier.example.test/evidence",
            },
            clear=True,
        ):
            with self.assertRaises(collector.EvidenceFailure) as caught:
                collector.read_config(args)
        self.assertEqual(caught.exception.reason, "evidence_endpoint_invalid")

    def test_production_mode_requires_suite_api_token(self) -> None:
        args = argparse.Namespace(
            matrix="matrix.json",
            profile=PROFILE_ID,
            plan=PLAN_ID,
            alias="unique-alias",
            started_after=1.0,
            output_dir="evidence",
        )
        environment = {
            "CONFORMANCE_SERVER": "https://suite.example.test/",
            "OIDF_VERIFIER_EVIDENCE_ENDPOINT": "https://verifier.example.test/evidence",
            "OIDF_VERIFIER_EVIDENCE_TOKEN": CONTROL_TOKEN,
        }
        with mock.patch.dict(collector.os.environ, environment, clear=True):
            with self.assertRaises(collector.EvidenceFailure) as caught:
                collector.read_config(args)
        self.assertEqual(caught.exception.reason, "evidence_environment_missing")

    def test_evidence_request_always_uses_dedicated_bearer_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scoped = config(root, root / "matrix.json")
            with mock.patch.object(
                collector,
                "read_json_response",
                return_value=evidence(),
            ) as read_json_response:
                returned = collector.fetch_host_evidence(
                    scoped,
                    collector.ModuleInstance(MODULE_ID, MODULE_NAME),
                )

        request = read_json_response.call_args_list[0].args[0]
        self.assertEqual(returned, evidence())
        self.assertEqual(
            request.headers["Authorization"],
            f"Bearer {CONTROL_TOKEN}",
        )

    def test_collects_bound_passed_module_with_private_atomic_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            matrix_path = root / "matrix.json"
            matrix_path.write_text(json.dumps(matrix()), encoding="utf-8")
            responses = [
                {
                    "data": [
                        {
                            "_id": PLAN_INSTANCE_ID,
                            "planName": PLAN_ID,
                            "started": "2026-09-19T12:00:00Z",
                            "config": {"alias": "oidf-vp-test-wallet"},
                            "modules": [
                                {
                                    "testModule": MODULE_NAME,
                                    "instances": [MODULE_ID],
                                }
                            ],
                        }
                    ]
                },
                {
                    "testName": MODULE_NAME,
                    "status": "FINISHED",
                    "result": "PASSED",
                },
            ]
            with mock.patch.object(
                collector, "api_get_json", side_effect=responses
            ), mock.patch.object(
                collector, "fetch_host_evidence", return_value=evidence()
            ):
                collector.collect(config(root, matrix_path))

            record_path = root / "evidence" / f"{MODULE_NAME}--{MODULE_ID}.json"
            index_path = root / "evidence" / "index.json"
            self.assertEqual(json.loads(record_path.read_text()), evidence())
            self.assertEqual(record_path.stat().st_mode & 0o777, 0o600)
            index = json.loads(index_path.read_text())
            self.assertEqual(index["module_count"], 1)
            self.assertEqual(index["plan_instance_id"], PLAN_INSTANCE_ID)
            self.assertEqual(index["records"][0]["suite_result"], "PASSED")
            self.assertEqual(len(index["records"][0]["sha256"]), 64)

    def test_accepts_review_only_when_the_matrix_requires_review(self) -> None:
        instance = collector.ModuleInstance(MODULE_ID, MODULE_NAME)
        review_expectation = collector.EvidenceExpectation(
            "accepted",
            "authorization_response_validation",
            1,
            frozenset(("REVIEW",)),
        )

        result = collector.validate_finished_module(
            {
                "testName": MODULE_NAME,
                "status": "FINISHED",
                "result": "REVIEW",
            },
            instance,
            review_expectation,
        )

        self.assertEqual(result, "REVIEW")
        with self.assertRaises(collector.EvidenceFailure) as caught:
            collector.validate_finished_module(
                {
                    "testName": MODULE_NAME,
                    "status": "FINISHED",
                    "result": "PASSED",
                },
                instance,
                review_expectation,
            )
        self.assertEqual(caught.exception.reason, "evidence_module_result_invalid")

    def test_rejects_plan_without_safe_instance_identifier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            matrix_path = root / "matrix.json"
            matrix_path.write_text(json.dumps(matrix()), encoding="utf-8")
            response = {
                "data": [
                    {
                        "_id": "unsafe/plan",
                        "planName": PLAN_ID,
                        "started": "2026-09-19T12:00:00Z",
                        "config": {"alias": "oidf-vp-test-wallet"},
                        "modules": [],
                    }
                ]
            }
            with mock.patch.object(collector, "api_get_json", return_value=response):
                with self.assertRaises(collector.EvidenceFailure) as caught:
                    collector.fetch_module_instances(
                        config(root, matrix_path), {MODULE_NAME}
                    )
            self.assertEqual(
                caught.exception.reason, "evidence_plan_instance_id_invalid"
            )

    def test_rejects_stale_or_foreign_module_binding(self) -> None:
        changed = evidence()
        changed["module_id"] = "foreign-module"
        with self.assertRaises(collector.EvidenceFailure) as caught:
            collector.validate_evidence(
                changed,
                config(Path("."), Path("matrix.json")),
                collector.ModuleInstance(MODULE_ID, MODULE_NAME),
                collector.EvidenceExpectation(
                    "accepted",
                    "authorization_response_validation",
                    1,
                    frozenset(("PASSED",)),
                ),
            )
        self.assertEqual(caught.exception.reason, "evidence_record_binding_mismatch")

    def test_rejects_wrong_decision_for_negative_test(self) -> None:
        with self.assertRaises(collector.EvidenceFailure) as caught:
            collector.validate_evidence(
                evidence(),
                config(Path("."), Path("matrix.json")),
                collector.ModuleInstance(MODULE_ID, MODULE_NAME),
                collector.EvidenceExpectation(
                    "rejected",
                    "authorization_response_validation",
                    1,
                    frozenset(("PASSED",)),
                ),
            )
        self.assertEqual(caught.exception.reason, "evidence_record_decision_mismatch")

    def test_rejects_missing_fetch_twice_observation(self) -> None:
        with self.assertRaises(collector.EvidenceFailure) as caught:
            collector.validate_evidence(
                evidence(),
                config(Path("."), Path("matrix.json")),
                collector.ModuleInstance(MODULE_ID, MODULE_NAME),
                collector.EvidenceExpectation(
                    "accepted",
                    "request_object_retrieval",
                    2,
                    frozenset(("PASSED",)),
                ),
            )
        self.assertEqual(caught.exception.reason, "evidence_required_observation_missing")

    def test_rejects_unbounded_or_unstructured_reason(self) -> None:
        changed = evidence()
        changed["reason_code"] = "Rejected credential belonging to Alice"
        with self.assertRaises(collector.EvidenceFailure) as caught:
            collector.validate_evidence(
                changed,
                config(Path("."), Path("matrix.json")),
                collector.ModuleInstance(MODULE_ID, MODULE_NAME),
                collector.EvidenceExpectation(
                    "accepted",
                    "authorization_response_validation",
                    1,
                    frozenset(("PASSED",)),
                ),
            )
        self.assertEqual(caught.exception.reason, "evidence_reason_invalid")

    def test_rejects_duplicate_json_members_and_deep_nesting(self) -> None:
        with self.assertRaises(collector.EvidenceFailure):
            collector.decode_json(b'{"schema_version":1,"schema_version":1}', "bad")
        deeply_nested = (("[" * 40) + "0" + ("]" * 40)).encode("utf-8")
        with self.assertRaises(collector.EvidenceFailure):
            collector.decode_json(deeply_nested, "bad")

    def test_rejects_non_standard_non_finite_json_number(self) -> None:
        with self.assertRaises(collector.EvidenceFailure) as caught:
            collector.decode_json(b'{"observation":-Infinity}', "bad")
        self.assertEqual(caught.exception.reason, "bad")

    def test_rejects_non_finite_evidence_start_time(self) -> None:
        args = argparse.Namespace(
            matrix="matrix.json",
            profile=PROFILE_ID,
            plan=PLAN_ID,
            alias="unique-alias",
            started_after=float("nan"),
            output_dir="evidence",
        )
        environment = {
            "CONFORMANCE_SERVER": "https://suite.example.test/",
            "CONFORMANCE_API_TOKEN": "opaque-token",
            "OIDF_VERIFIER_EVIDENCE_ENDPOINT": "https://verifier.example.test/evidence",
            "OIDF_VERIFIER_EVIDENCE_TOKEN": CONTROL_TOKEN,
        }
        with mock.patch.dict(collector.os.environ, environment, clear=True):
            with self.assertRaises(collector.EvidenceFailure) as caught:
                collector.read_config(args)
        self.assertEqual(caught.exception.reason, "evidence_started_after_invalid")

    def test_rejects_credentialed_suite_endpoint_before_sending_api_token(self) -> None:
        args = argparse.Namespace(
            matrix="matrix.json",
            profile=PROFILE_ID,
            plan=PLAN_ID,
            alias="unique-alias",
            started_after=1.0,
            output_dir="evidence",
        )
        environment = {
            "CONFORMANCE_SERVER": "https://user:secret@suite.example.test/",
            "CONFORMANCE_API_TOKEN": "opaque-token",
            "OIDF_VERIFIER_EVIDENCE_ENDPOINT": "https://verifier.example.test/evidence",
            "OIDF_VERIFIER_EVIDENCE_TOKEN": CONTROL_TOKEN,
        }
        with mock.patch.dict(collector.os.environ, environment, clear=True):
            with self.assertRaises(collector.EvidenceFailure) as caught:
                collector.read_config(args)
        self.assertEqual(caught.exception.reason, "evidence_endpoint_invalid")

    def test_requires_bounded_ascii_graphic_evidence_token(self) -> None:
        args = argparse.Namespace(
            matrix="matrix.json",
            profile=PROFILE_ID,
            plan=PLAN_ID,
            alias="unique-alias",
            started_after=1.0,
            output_dir="evidence",
        )
        invalid_tokens = (
            None,
            "e" * (collector.MIN_CONTROL_TOKEN_BYTES - 1),
            "e" * (collector.MAX_CONTROL_TOKEN_BYTES + 1),
            ("e" * collector.MIN_CONTROL_TOKEN_BYTES) + " ",
            ("e" * collector.MIN_CONTROL_TOKEN_BYTES) + "\n",
            ("e" * collector.MIN_CONTROL_TOKEN_BYTES) + "\N{LOCK}",
        )
        for token in invalid_tokens:
            environment = {
                "CONFORMANCE_SERVER": "https://suite.example.test/",
                "CONFORMANCE_API_TOKEN": "opaque-token",
                "OIDF_VERIFIER_EVIDENCE_ENDPOINT": "https://verifier.example.test/evidence",
            }
            if token is not None:
                environment["OIDF_VERIFIER_EVIDENCE_TOKEN"] = token
            with self.subTest(token=repr(token)), mock.patch.dict(
                collector.os.environ, environment, clear=True
            ):
                with self.assertRaises(collector.EvidenceFailure) as caught:
                    collector.read_config(args)
                expected = (
                    "evidence_environment_missing"
                    if token is None
                    else "evidence_control_token_invalid"
                )
                self.assertEqual(caught.exception.reason, expected)

    def test_expectations_must_cover_exact_module_inventory(self) -> None:
        changed = matrix()
        profile = changed["profiles"][0]
        profile["evidence_expectations"] = {}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "matrix.json"
            path.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaises(collector.EvidenceFailure) as caught:
                collector.read_expectations(path, PROFILE_ID)
        self.assertEqual(caught.exception.reason, "evidence_expectations_invalid")


if __name__ == "__main__":
    unittest.main()
