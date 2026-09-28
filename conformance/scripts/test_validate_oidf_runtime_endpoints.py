#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import validate_oidf_runtime_endpoints


class ValidateOidfRuntimeEndpointsTests(unittest.TestCase):
    def test_accepts_canonical_https_endpoint(self) -> None:
        validate_oidf_runtime_endpoints.validate_endpoint(
            "https://suite.example.test:8443/oidf/launch", False
        )

    def test_http_requires_explicit_development_mode(self) -> None:
        with self.assertRaises(validate_oidf_runtime_endpoints.EndpointFailure):
            validate_oidf_runtime_endpoints.validate_endpoint(
                "http://127.0.0.1:8787/oidf/launch", False
            )
        validate_oidf_runtime_endpoints.validate_endpoint(
            "http://127.0.0.1:8787/oidf/launch", True
        )

    def test_rejects_ambiguous_or_credentialed_endpoints(self) -> None:
        invalid = (
            "https://user:secret@suite.example.test/",
            "https://suite.example.test/path?token=secret",
            "https://suite.example.test/path#fragment",
            "https://suite.example.test\\@attacker.example/",
            "https://%73uite.example.test/",
            "HTTPS://suite.example.test/",
            "https://suite.example.test:0/",
            "https://suite.example.test:99999/",
            "https://suite.example.test/\n",
            "https://[invalid/",
        )
        for endpoint in invalid:
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(
                    validate_oidf_runtime_endpoints.EndpointFailure
                ):
                    validate_oidf_runtime_endpoints.validate_endpoint(endpoint, False)

    def test_rejects_oversized_endpoint(self) -> None:
        with self.assertRaises(validate_oidf_runtime_endpoints.EndpointFailure):
            validate_oidf_runtime_endpoints.validate_endpoint(
                "https://suite.example.test/"
                + ("a" * validate_oidf_runtime_endpoints.MAX_ENDPOINT_BYTES),
                False,
            )


if __name__ == "__main__":
    unittest.main()
