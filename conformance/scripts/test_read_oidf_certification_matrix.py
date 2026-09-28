#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import read_oidf_certification_matrix


class ReadOidfCertificationMatrixTests(unittest.TestCase):
    def test_selects_exactly_one_requested_profile(self) -> None:
        matrix = {
            "profiles": [
                {
                    "id": "verifier-one",
                    "role": "verifier",
                    "plan_id": "plan-one",
                    "expression": "plan-one[format=one]",
                    "expected_groups": [
                        {"variants": {"format": "one"}, "modules": ["module-one"]}
                    ],
                },
                {
                    "id": "verifier-two",
                    "role": "verifier",
                    "plan_id": "plan-one",
                    "expression": "plan-one[format=two]",
                    "expected_groups": [
                        {"variants": {"format": "two"}, "modules": ["module-two"]}
                    ],
                },
            ]
        }
        output = StringIO()
        with redirect_stdout(output):
            read_oidf_certification_matrix.write_profiles(
                matrix, "verifier", "verifier-two"
            )
        self.assertEqual(
            output.getvalue(),
            "verifier-two\tplan-one\tplan-one[format=two]\t1\n",
        )

    def test_accepts_reviewed_identifier_shape(self) -> None:
        self.assertEqual(
            read_oidf_certification_matrix.safe_identifier(
                "wallet-sd-jwt-vc-dc-api-jwt"
            ),
            "wallet-sd-jwt-vc-dc-api-jwt",
        )

    def test_rejects_parent_directory_identifier(self) -> None:
        with self.assertRaises(
            read_oidf_certification_matrix.MatrixFailure
        ) as caught:
            read_oidf_certification_matrix.safe_identifier("..")
        self.assertEqual(caught.exception.reason, "matrix_identifier_invalid")

    def test_rejects_leading_dot_identifier(self) -> None:
        with self.assertRaises(
            read_oidf_certification_matrix.MatrixFailure
        ) as caught:
            read_oidf_certification_matrix.safe_identifier(".profile")
        self.assertEqual(caught.exception.reason, "matrix_identifier_invalid")

    def test_rejects_non_standard_non_finite_json_number(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            matrix = Path(directory) / "matrix.json"
            matrix.write_text(
                '{"schema_version":1,"suite":NaN}', encoding="utf-8"
            )
            with self.assertRaises(
                read_oidf_certification_matrix.MatrixFailure
            ) as caught:
                read_oidf_certification_matrix.read_matrix(matrix)
        self.assertEqual(caught.exception.reason, "matrix_file_invalid")

    def test_reads_one_uniform_wallet_credential_format(self) -> None:
        profile = {
            "expected_groups": [
                {"variants": {"credential_format": "iso_mdl"}, "modules": ["one"]},
                {"variants": {"credential_format": "iso_mdl"}, "modules": ["two"]},
            ]
        }
        self.assertEqual(
            read_oidf_certification_matrix.profile_credential_format(profile),
            "iso_mdl",
        )

    def test_rejects_ambiguous_wallet_credential_formats(self) -> None:
        profile = {
            "expected_groups": [
                {"variants": {"credential_format": "iso_mdl"}},
                {"variants": {"credential_format": "sd_jwt_vc"}},
            ]
        }
        with self.assertRaises(
            read_oidf_certification_matrix.MatrixFailure
        ) as caught:
            read_oidf_certification_matrix.profile_credential_format(profile)
        self.assertEqual(
            caught.exception.reason, "matrix_credential_format_ambiguous"
        )

    def test_reads_one_uniform_wallet_response_mode(self) -> None:
        profile = {
            "expected_groups": [
                {"variants": {"response_mode": "dc_api.jwt"}},
                {"variants": {"response_mode": "dc_api.jwt"}},
            ]
        }
        self.assertEqual(
            read_oidf_certification_matrix.profile_response_mode(profile),
            "dc_api.jwt",
        )


if __name__ == "__main__":
    unittest.main()
