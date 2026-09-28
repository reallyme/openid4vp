#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import base64
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("verify_oidf_wallet_config.py")
SPEC = importlib.util.spec_from_file_location("verify_oidf_wallet_config", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("wallet config verifier module is unavailable")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def encoded_octet(value: int) -> str:
    return base64.urlsafe_b64encode(bytes([value]) * 32).decode("ascii").rstrip("=")


def signing_jwk(value: int) -> dict[str, object]:
    certificate = base64.b64encode(b"\x30\x03\x02\x01\x01").decode("ascii")
    return {
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "use": "sig",
        "x": encoded_octet(value),
        "y": encoded_octet(value + 1),
        "d": encoded_octet(value + 2),
        "x5c": [certificate],
    }


class WalletConfigVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.suite = self.root / "suite"
        self.material_root = self.suite / "scripts" / "certs-keys"
        self.material_root.mkdir(parents=True)
        self.primary = signing_jwk(1)
        self.secondary = signing_jwk(4)
        self.request_anchor = "-----BEGIN CERTIFICATE-----\nMAE=\n-----END CERTIFICATE-----\n"
        self.sd_jwt_anchor = "-----BEGIN CERTIFICATE-----\nMAI=\n-----END CERTIFICATE-----\n"
        self.mdoc_anchor = "-----BEGIN CERTIFICATE-----\nMAM=\n-----END CERTIFICATE-----\n"
        self.write_materials()
        self.template = self.root / "wallet.json"
        self.write_template()

    def write_materials(self) -> None:
        (self.material_root / "vp-signing-jwk.json").write_text(
            json.dumps(self.primary), encoding="utf-8"
        )
        (self.material_root / "vp-signing-jwk-2.json").write_text(
            json.dumps(self.secondary), encoding="utf-8"
        )
        (self.material_root / "vp-signing-ca.crt").write_text(
            self.request_anchor, encoding="utf-8"
        )
        (self.material_root / "vci-test-root.crt").write_text(
            self.sd_jwt_anchor, encoding="utf-8"
        )
        (self.material_root / "mdoc-iaca-root.crt").write_text(
            self.mdoc_anchor, encoding="utf-8"
        )

    def write_template(self, extra: str = "") -> None:
        template = """{
          "server": {"authorization_endpoint": "{BASEURL}authorize"},
          "client": {
            "jwks": {"keys": [{vp-signing-jwk.json}]},
            "dcql": {"credentials": [{
              "id": "my_credential",
              "format": "dc+sd-jwt",
              "meta": {"vct_values": ["urn:eudi:pid:1"]}
            }]}
          },
          "client2": {"jwks": {"keys": [{vp-signing-jwk-2.json}]}},
          "credential": {
            "signing_jwk": {vp-signing-jwk.json},
            "trust_anchor_pem": "{vci-test-root.crt}",
            "status_list_trust_anchor_pem": "{vci-test-root.crt}"
          }
        }"""
        self.template.write_text(template + extra, encoding="utf-8")

    def assert_failure(self, reason: str) -> None:
        with self.assertRaises(MODULE.ConfigFailure) as context:
            MODULE.verify_wallet_config(self.suite, self.template, "sd_jwt_vc")
        self.assertEqual(context.exception.reason, reason)

    def test_valid_template_matches_suite_material(self) -> None:
        MODULE.verify_wallet_config(self.suite, self.template, "sd_jwt_vc")

    def test_rejects_profile_format_mismatch(self) -> None:
        with self.assertRaises(MODULE.ConfigFailure) as context:
            MODULE.verify_wallet_config(self.suite, self.template, "iso_mdl")
        self.assertEqual(
            context.exception.reason, "wallet_config_profile_format_mismatch"
        )

    def test_accepts_mdoc_profile_template(self) -> None:
        text = self.template.read_text(encoding="utf-8")
        text = text.replace('"format": "dc+sd-jwt"', '"format": "mso_mdoc"')
        text = text.replace(
            '"meta": {"vct_values": ["urn:eudi:pid:1"]}',
            '"meta": {"doctype_value": "org.iso.18013.5.1.mDL"}',
        )
        text = text.replace("{vci-test-root.crt}", "{mdoc-iaca-root.crt}")
        self.template.write_text(text, encoding="utf-8")
        MODULE.verify_wallet_config(self.suite, self.template, "iso_mdl")

    def test_rejects_request_object_root_as_credential_root(self) -> None:
        text = self.template.read_text(encoding="utf-8")
        text = text.replace("{vci-test-root.crt}", "{vp-signing-ca.crt}")
        self.template.write_text(text, encoding="utf-8")
        self.assert_failure("wallet_config_required_material_missing")

    def test_duplicate_json_key_is_rejected(self) -> None:
        text = self.template.read_text(encoding="utf-8")
        self.template.write_text(
            text.replace(
                '"dcql": {"credentials": [{',
                '"dcql": {}, "dcql": {"credentials": [{',
            ),
            encoding="utf-8",
        )
        self.assert_failure("wallet_config_duplicate_json_key")

    def test_non_standard_non_finite_json_number_is_rejected(self) -> None:
        with self.assertRaises(MODULE.ConfigFailure) as context:
            MODULE.parse_json_object('{"value":NaN}', "wallet_config_invalid")
        self.assertEqual(context.exception.reason, "wallet_config_non_finite_number")

    def test_identical_signers_are_rejected(self) -> None:
        self.secondary = self.primary
        self.write_materials()
        self.assert_failure("wallet_config_signers_not_distinct")

    def test_unknown_placeholder_is_rejected(self) -> None:
        text = self.template.read_text(encoding="utf-8")
        self.template.write_text(
            text.replace(
                '"meta": {"vct_values": ["urn:eudi:pid:1"]}',
                '"meta": {"vct_values": ["urn:eudi:pid:1"]}, "bad": "{../key}"',
            ),
            encoding="utf-8",
        )
        self.assert_failure("wallet_config_unknown_placeholder")

    def test_primary_material_mismatch_is_rejected(self) -> None:
        text = self.template.read_text(encoding="utf-8")
        inline_key = json.dumps(signing_jwk(7))
        self.template.write_text(
            text.replace(
                '"jwks": {"keys": [{vp-signing-jwk.json}]}',
                f'"jwks": {{"keys": [{inline_key}]}}',
                1,
            ),
            encoding="utf-8",
        )
        self.assert_failure("wallet_config_primary_signer_material_mismatch")

    def test_trust_anchor_substitution_is_rejected(self) -> None:
        text = self.template.read_text(encoding="utf-8")
        self.template.write_text(
            text.replace(
                '"trust_anchor_pem": "{vci-test-root.crt}"',
                '"trust_anchor_pem": "-----BEGIN CERTIFICATE----- substituted"',
            ),
            encoding="utf-8",
        )
        self.assert_failure("wallet_config_trust_anchor_material_mismatch")

    def test_oversized_template_is_rejected_before_parsing(self) -> None:
        self.template.write_bytes(b" " * (MODULE.MAX_TEMPLATE_BYTES + 1))
        self.assert_failure("wallet_config_template_unavailable")

    def test_excessive_json_depth_is_rejected(self) -> None:
        value: object = None
        for _index in range(MODULE.MAX_JSON_DEPTH + 1):
            value = [value]
        with self.assertRaises(MODULE.ConfigFailure) as context:
            MODULE.validate_json_complexity(value)
        self.assertEqual(context.exception.reason, "wallet_config_json_too_deep")

    def test_symlinked_material_is_rejected(self) -> None:
        source = self.material_root / "vp-signing-jwk-2.json"
        target = self.root / "secondary.json"
        source.replace(target)
        source.symlink_to(target)
        self.assert_failure("wallet_config_material_path_invalid")

    def test_symlinked_template_is_rejected(self) -> None:
        target = self.root / "target.json"
        self.template.replace(target)
        self.template.symlink_to(target)
        self.assert_failure("wallet_config_template_unavailable")


if __name__ == "__main__":
    unittest.main()
