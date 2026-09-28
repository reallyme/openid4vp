#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import verify_oidf_certification_target


class VerifyOidfCertificationTargetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)

    def test_rejects_untracked_suite_source(self) -> None:
        subprocess.run(
            ("git", "init", "--quiet"),
            cwd=self.root,
            check=True,
            capture_output=True,
        )
        self.assertTrue(
            verify_oidf_certification_target.git_worktree_is_clean(self.root)
        )

        (self.root / "unexpected.java").write_text("class Unexpected {}\n", encoding="utf-8")

        self.assertFalse(
            verify_oidf_certification_target.git_worktree_is_clean(self.root)
        )

    def test_rejects_symlinked_source_file(self) -> None:
        source = self.root / "source.java"
        source.write_text("class Source {}\n", encoding="utf-8")
        link = self.root / "link.java"
        link.symlink_to(source)

        with self.assertRaises(
            verify_oidf_certification_target.TargetFailure
        ) as caught:
            verify_oidf_certification_target.read_bounded_text(link)
        self.assertEqual(caught.exception.reason, "input_file_symlink_rejected")

    def test_rejects_excessively_nested_matrix_before_copy(self) -> None:
        value: object = None
        for _ in range(verify_oidf_certification_target.MAX_JSON_DEPTH + 1):
            value = [value]

        with self.assertRaises(
            verify_oidf_certification_target.TargetFailure
        ) as caught:
            verify_oidf_certification_target.ensure_bounded_json(value)
        self.assertEqual(caught.exception.reason, "matrix_json_nesting_exceeded")

    def test_rejects_non_standard_non_finite_matrix_number(self) -> None:
        matrix = self.root / "matrix.json"
        matrix.write_text('{"schema_version":Infinity}', encoding="utf-8")

        with self.assertRaises(
            verify_oidf_certification_target.TargetFailure
        ) as caught:
            verify_oidf_certification_target.read_json_object(matrix)
        self.assertEqual(caught.exception.reason, "matrix_json_invalid")

    def test_binds_matrix_version_to_suite_build_version(self) -> None:
        properties = self.root / "src" / "main" / "resources"
        properties.mkdir(parents=True)
        (properties / "application.properties").write_text(
            "fintechlabs.version=5.3.1\n", encoding="utf-8"
        )

        verify_oidf_certification_target.verify_suite_version(
            self.root.resolve(), "5.3.1"
        )

        with self.assertRaises(
            verify_oidf_certification_target.TargetFailure
        ) as caught:
            verify_oidf_certification_target.verify_suite_version(
                self.root.resolve(), "5.2.4"
            )
        self.assertEqual(caught.exception.reason, "suite_version_mismatch")

    def test_rejects_non_semantic_matrix_suite_version(self) -> None:
        with self.assertRaises(
            verify_oidf_certification_target.TargetFailure
        ) as caught:
            verify_oidf_certification_target.verify_suite_version(
                self.root.resolve(), "release-latest"
            )
        self.assertEqual(caught.exception.reason, "matrix_suite_version_invalid")

    def test_rejects_incomplete_verifier_evidence_expectations(self) -> None:
        profile = {
            "expected_groups": [
                {
                    "modules": ["module-one", "module-two"],
                }
            ],
            "evidence_expectations": {
                "module-one": {
                    "decision": "accepted",
                    "observation_kind": "authorization_response_validation",
                    "minimum_observations": 1,
                }
            },
        }

        with self.assertRaises(
            verify_oidf_certification_target.TargetFailure
        ) as caught:
            verify_oidf_certification_target.verify_evidence_expectations(profile)
        self.assertEqual(caught.exception.reason, "matrix_evidence_coverage_mismatch")

    def test_applies_rehearsal_modules_to_exact_variant_group(self) -> None:
        matrix = {
            "schema_version": 1,
            "suite": {
                "repository": "https://gitlab.com/openid/conformance-suite",
                "commit": "0" * 40,
                "describe": "production",
                "version": "5.3.1",
            },
            "profiles": [
                {
                    "id": "verifier-profile",
                    "expected_groups": [
                        {
                            "variants": {
                                "credential_format": "sd_jwt_vc",
                                "response_mode": "direct_post.jwt",
                            },
                            "modules": ["base-module"],
                        }
                    ],
                }
            ],
        }
        overlay = {
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
                    "profile_id": "verifier-profile",
                    "group_variants": {
                        "credential_format": "sd_jwt_vc",
                        "response_mode": "direct_post.jwt",
                    },
                    "modules": ["rehearsal-module"],
                }
            ],
        }

        result = verify_oidf_certification_target.apply_rehearsal_overlay(
            matrix, overlay
        )

        self.assertEqual(result["suite"]["commit"], "1" * 40)
        self.assertEqual(result["suite"]["version"], "5.2.4")
        self.assertEqual(
            result["profiles"][0]["expected_groups"][0]["modules"],
            ["base-module", "rehearsal-module"],
        )
        self.assertEqual(
            matrix["profiles"][0]["expected_groups"][0]["modules"],
            ["base-module"],
        )

    def test_rejects_overlay_module_already_in_base_matrix(self) -> None:
        matrix = {
            "suite": {
                "repository": "https://gitlab.com/openid/conformance-suite",
                "commit": "0" * 40,
                "describe": "production",
                "version": "5.3.1",
            },
            "profiles": [
                {
                    "id": "verifier-profile",
                    "expected_groups": [
                        {
                            "variants": {"credential_format": "sd_jwt_vc"},
                            "modules": ["base-module"],
                        }
                    ],
                }
            ],
        }
        overlay = {
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
                    "profile_id": "verifier-profile",
                    "group_variants": {"credential_format": "sd_jwt_vc"},
                    "modules": ["base-module"],
                }
            ],
        }

        with self.assertRaises(
            verify_oidf_certification_target.TargetFailure
        ) as caught:
            verify_oidf_certification_target.apply_rehearsal_overlay(matrix, overlay)
        self.assertEqual(caught.exception.reason, "overlay_module_already_present")


if __name__ == "__main__":
    unittest.main()
