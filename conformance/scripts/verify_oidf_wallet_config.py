#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate the wallet plan template against the pinned suite key material."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from pathlib import Path
from typing import NoReturn


MAX_TEMPLATE_BYTES = 1 * 1024 * 1024
MAX_MATERIAL_BYTES = 1 * 1024 * 1024
MAX_EXPANDED_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 50_000
MAX_PLACEHOLDERS = 32

PLACEHOLDER_PATTERN = re.compile(r"\{([A-Za-z0-9][A-Za-z0-9._-]{0,126}[A-Za-z0-9]|[A-Za-z0-9])\}")
RAW_PLACEHOLDER_PATTERN = re.compile(r"\{([^{}\s\"]+)\}")
RUNTIME_PLACEHOLDERS = frozenset(
    {"BASEURL", "BASEURLMTLS", "EXTERNALBASEURL", "HOSTNAME", "LOCALBASEURL"}
)
MATERIAL_NAMES = frozenset(
    {
        "mdoc-iaca-root.crt",
        "vci-test-root.crt",
        "vp-signing-jwk.json",
        "vp-signing-jwk-2.json",
        "vp-signing-ca.crt",
    }
)
REQUIRED_SIGNING_MATERIALS = frozenset(
    {"vp-signing-jwk.json", "vp-signing-jwk-2.json"}
)
CREDENTIAL_TRUST_MATERIALS = frozenset(
    {"mdoc-iaca-root.crt", "vci-test-root.crt"}
)
RUNTIME_VALUES = {
    "BASEURL": "https://conformance.invalid/",
    "BASEURLMTLS": "https://mtls.conformance.invalid/",
    "EXTERNALBASEURL": "https://external.conformance.invalid/",
    "HOSTNAME": "conformance.invalid",
    "LOCALBASEURL": "https://local.conformance.invalid/",
}
SUPPORTED_CREDENTIAL_FORMATS = frozenset({"sd_jwt_vc", "iso_mdl"})
CREDENTIAL_TRUST_ANCHOR_BY_FORMAT = {
    "sd_jwt_vc": "vci-test-root.crt",
    "iso_mdl": "mdoc-iaca-root.crt",
}


class ConfigFailure(Exception):
    """A stable, non-sensitive wallet configuration validation failure."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def fail(reason: str) -> NoReturn:
    raise ConfigFailure(reason)


def read_bounded_text(path: Path, limit: int, failure_reason: str) -> str:
    if path.is_symlink():
        fail(failure_reason)
    try:
        size = path.stat().st_size
    except OSError:
        fail(failure_reason)
    if size > limit:
        fail(failure_reason)
    try:
        data = path.read_bytes()
    except OSError:
        fail(failure_reason)
    if len(data) > limit:
        fail(failure_reason)
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        fail(failure_reason)


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail("wallet_config_duplicate_json_key")
        result[key] = value
    return result


def parse_json_object(text: str, failure_reason: str) -> dict[str, object]:
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_non_finite_number,
        )
    except ConfigFailure:
        raise
    except (json.JSONDecodeError, RecursionError):
        fail(failure_reason)
    if not isinstance(parsed, dict):
        fail(failure_reason)
    validate_json_complexity(parsed)
    return parsed


def reject_non_finite_number(_value: str) -> None:
    fail("wallet_config_non_finite_number")


def validate_json_complexity(root: object) -> None:
    nodes = 0
    pending: list[tuple[object, int]] = [(root, 1)]
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            fail("wallet_config_json_too_complex")
        if depth > MAX_JSON_DEPTH:
            fail("wallet_config_json_too_deep")
        if isinstance(value, dict):
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)


def material_path(material_root: Path, name: str) -> Path:
    candidate = material_root / name
    try:
        resolved_root = material_root.resolve(strict=True)
        resolved_candidate = candidate.resolve(strict=True)
    except OSError:
        fail("wallet_config_material_unavailable")
    if resolved_candidate.parent != resolved_root or candidate.is_symlink():
        fail("wallet_config_material_path_invalid")
    return candidate


def load_materials(suite_dir: Path) -> dict[str, str]:
    material_root = suite_dir / "scripts" / "certs-keys"
    if material_root.is_symlink() or not material_root.is_dir():
        fail("wallet_config_material_directory_invalid")
    materials: dict[str, str] = {}
    for name in sorted(MATERIAL_NAMES):
        path = material_path(material_root, name)
        materials[name] = read_bounded_text(
            path, MAX_MATERIAL_BYTES, "wallet_config_material_unavailable"
        ).replace("\n", " ")
    return materials


def expand_template(template: str, materials: dict[str, str]) -> str:
    raw_placeholders = RAW_PLACEHOLDER_PATTERN.findall(template)
    if any(PLACEHOLDER_PATTERN.fullmatch("{" + name + "}") is None for name in raw_placeholders):
        fail("wallet_config_unknown_placeholder")
    placeholders = PLACEHOLDER_PATTERN.findall(template)
    if len(placeholders) > MAX_PLACEHOLDERS:
        fail("wallet_config_too_many_placeholders")
    placeholder_names = frozenset(placeholders)
    unknown = placeholder_names - RUNTIME_PLACEHOLDERS - MATERIAL_NAMES
    if unknown:
        fail("wallet_config_unknown_placeholder")
    if not REQUIRED_SIGNING_MATERIALS.issubset(placeholder_names):
        fail("wallet_config_required_material_missing")
    if len(placeholder_names & CREDENTIAL_TRUST_MATERIALS) != 1:
        fail("wallet_config_required_material_missing")

    expanded = template
    for name, value in RUNTIME_VALUES.items():
        expanded = expanded.replace("{" + name + "}", value)
    for name, value in materials.items():
        expanded = expanded.replace("{" + name + "}", value)
        if len(expanded.encode("utf-8")) > MAX_EXPANDED_BYTES:
            fail("wallet_config_expanded_too_large")
    if PLACEHOLDER_PATTERN.search(expanded) is not None:
        fail("wallet_config_placeholder_unresolved")
    return expanded


def require_object(parent: dict[str, object], name: str) -> dict[str, object]:
    value = parent.get(name)
    if not isinstance(value, dict):
        fail("wallet_config_shape_invalid")
    return value


def require_non_empty_string(parent: dict[str, object], name: str) -> str:
    value = parent.get(name)
    if not isinstance(value, str) or not value.strip():
        fail("wallet_config_shape_invalid")
    return value


def decode_base64url_32(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 43:
        return False
    try:
        decoded = base64.urlsafe_b64decode(value + "=")
    except (ValueError, binascii.Error):
        return False
    return len(decoded) == 32


def validate_signing_jwk(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        fail("wallet_config_signing_jwk_invalid")
    expected_strings = {"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig"}
    if any(value.get(name) != expected for name, expected in expected_strings.items()):
        fail("wallet_config_signing_jwk_invalid")
    if not all(decode_base64url_32(value.get(name)) for name in ("x", "y", "d")):
        fail("wallet_config_signing_jwk_invalid")
    certificate_chain = value.get("x5c")
    if not isinstance(certificate_chain, list) or not certificate_chain:
        fail("wallet_config_signing_jwk_invalid")
    for certificate in certificate_chain:
        if not isinstance(certificate, str) or not certificate:
            fail("wallet_config_signing_jwk_invalid")
        try:
            decoded = base64.b64decode(certificate, validate=True)
        except (ValueError, binascii.Error):
            fail("wallet_config_signing_jwk_invalid")
        if not decoded or decoded[0] != 0x30:
            fail("wallet_config_signing_jwk_invalid")
    return value


def first_signing_key(client: dict[str, object]) -> dict[str, object]:
    jwks = require_object(client, "jwks")
    keys = jwks.get("keys")
    if not isinstance(keys, list) or len(keys) != 1:
        fail("wallet_config_signing_key_count_invalid")
    return validate_signing_jwk(keys[0])


def contains_key(root: object, forbidden_key: str) -> bool:
    pending = [root]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if forbidden_key in value:
                return True
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    return False


def validate_dcql_credential_format(
    client: dict[str, object], credential_format: str
) -> None:
    dcql = require_object(client, "dcql")
    credentials = dcql.get("credentials")
    if not isinstance(credentials, list) or len(credentials) != 1:
        fail("wallet_config_dcql_credentials_invalid")
    credential = credentials[0]
    if not isinstance(credential, dict):
        fail("wallet_config_dcql_credentials_invalid")
    meta = credential.get("meta")
    if not isinstance(meta, dict):
        fail("wallet_config_dcql_credentials_invalid")

    if credential_format == "sd_jwt_vc":
        if credential.get("format") != "dc+sd-jwt":
            fail("wallet_config_profile_format_mismatch")
        if meta.get("vct_values") != ["urn:eudi:pid:1"] or "doctype_value" in meta:
            fail("wallet_config_profile_type_mismatch")
    elif credential_format == "iso_mdl":
        if credential.get("format") != "mso_mdoc":
            fail("wallet_config_profile_format_mismatch")
        if (
            meta.get("doctype_value") != "org.iso.18013.5.1.mDL"
            or "vct_values" in meta
        ):
            fail("wallet_config_profile_type_mismatch")
    else:
        fail("wallet_config_credential_format_invalid")


def validate_config(
    config: dict[str, object], materials: dict[str, str], credential_format: str
) -> None:
    if contains_key(config, "presentation_definition"):
        fail("wallet_config_presentation_exchange_forbidden")

    server = require_object(config, "server")
    authorization_endpoint = require_non_empty_string(server, "authorization_endpoint")
    if not authorization_endpoint.startswith("https://"):
        fail("wallet_config_authorization_endpoint_invalid")

    client = require_object(config, "client")
    client2 = require_object(config, "client2")
    primary_key = first_signing_key(client)
    secondary_key = first_signing_key(client2)
    if primary_key == secondary_key:
        fail("wallet_config_signers_not_distinct")
    validate_dcql_credential_format(client, credential_format)

    credential = require_object(config, "credential")
    credential_key = validate_signing_jwk(credential.get("signing_jwk"))
    trust_anchor = require_non_empty_string(credential, "trust_anchor_pem")
    status_trust_anchor = require_non_empty_string(
        credential, "status_list_trust_anchor_pem"
    )
    if not trust_anchor.startswith("-----BEGIN CERTIFICATE-----"):
        fail("wallet_config_trust_anchor_invalid")

    expected_primary = parse_json_object(
        materials["vp-signing-jwk.json"], "wallet_config_material_json_invalid"
    )
    expected_secondary = parse_json_object(
        materials["vp-signing-jwk-2.json"], "wallet_config_material_json_invalid"
    )
    validate_signing_jwk(expected_primary)
    validate_signing_jwk(expected_secondary)
    if primary_key != expected_primary or credential_key != expected_primary:
        fail("wallet_config_primary_signer_material_mismatch")
    if secondary_key != expected_secondary:
        fail("wallet_config_secondary_signer_material_mismatch")
    if expected_primary == expected_secondary:
        fail("wallet_config_suite_signers_not_distinct")
    expected_anchor = materials[CREDENTIAL_TRUST_ANCHOR_BY_FORMAT[credential_format]]
    if trust_anchor != expected_anchor or status_trust_anchor != expected_anchor:
        fail("wallet_config_trust_anchor_material_mismatch")


def verify_wallet_config(
    suite_dir: Path, template_path: Path, credential_format: str
) -> None:
    if credential_format not in SUPPORTED_CREDENTIAL_FORMATS:
        fail("wallet_config_credential_format_invalid")
    if suite_dir.is_symlink() or not suite_dir.is_dir():
        fail("wallet_config_suite_directory_invalid")
    template = read_bounded_text(
        template_path, MAX_TEMPLATE_BYTES, "wallet_config_template_unavailable"
    )
    materials = load_materials(suite_dir)
    expanded = expand_template(template, materials)
    config = parse_json_object(expanded, "wallet_config_json_invalid")
    validate_config(config, materials, credential_format)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite_dir", type=Path)
    parser.add_argument("config_template", type=Path)
    parser.add_argument(
        "--credential-format",
        required=True,
        choices=sorted(SUPPORTED_CREDENTIAL_FORMATS),
    )
    arguments = parser.parse_args()
    try:
        verify_wallet_config(
            arguments.suite_dir,
            arguments.config_template,
            arguments.credential_format,
        )
    except ConfigFailure as error:
        print(error.reason, file=sys.stderr)
        return 2
    print("OIDF wallet configuration matches pinned suite material")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
