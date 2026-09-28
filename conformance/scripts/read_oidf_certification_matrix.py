#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Read validated scalar data from the public OIDF protocol-profile matrix."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import verify_oidf_certification_target


MAX_MATRIX_BYTES = 2_000_000
SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
SAFE_COMMIT = re.compile(r"[0-9a-f]{40}")


class MatrixFailure(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def main() -> int:
    parser = argparse.ArgumentParser(description="Read the OIDF protocol-profile matrix.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    commit_parser = subparsers.add_parser("commit")
    commit_parser.add_argument("matrix")
    commit_parser.add_argument("--overlay")
    profiles_parser = subparsers.add_parser("profiles")
    profiles_parser.add_argument("matrix")
    profiles_parser.add_argument("--role", required=True, choices=("verifier", "wallet"))
    profiles_parser.add_argument("--profile")
    profiles_parser.add_argument("--overlay")
    profiles_parser.add_argument("--include-credential-format", action="store_true")
    profiles_parser.add_argument("--include-response-mode", action="store_true")
    args = parser.parse_args()

    try:
        matrix = read_matrix(Path(args.matrix))
        if args.overlay is not None:
            matrix = apply_overlay(matrix, Path(args.overlay))
        if args.command == "commit":
            print(read_commit(matrix))
        elif args.command == "profiles":
            write_profiles(
                matrix,
                args.role,
                args.profile,
                args.include_credential_format,
                args.include_response_mode,
            )
        else:
            raise MatrixFailure("matrix_command_invalid")
        return 0
    except MatrixFailure as error:
        print(error.reason, file=sys.stderr)
        return 2


def apply_overlay(matrix: dict[str, Any], overlay_path: Path) -> dict[str, Any]:
    try:
        overlay = verify_oidf_certification_target.read_json_object(overlay_path)
        return verify_oidf_certification_target.apply_rehearsal_overlay(matrix, overlay)
    except verify_oidf_certification_target.TargetFailure as error:
        raise MatrixFailure("matrix_overlay_invalid") from error


def read_matrix(path: Path) -> dict[str, Any]:
    try:
        if path.is_symlink() or path.stat().st_size > MAX_MATRIX_BYTES:
            raise MatrixFailure("matrix_file_rejected")
        text = path.read_text(encoding="utf-8")
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicate_members,
            parse_constant=reject_non_finite_number,
        )
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        RecursionError,
        MatrixFailure,
    ) as error:
        raise MatrixFailure("matrix_file_invalid") from error
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise MatrixFailure("matrix_shape_invalid")
    return value


def read_commit(matrix: dict[str, Any]) -> str:
    suite = matrix.get("suite")
    if not isinstance(suite, dict):
        raise MatrixFailure("matrix_shape_invalid")
    commit = suite.get("commit")
    if not isinstance(commit, str) or SAFE_COMMIT.fullmatch(commit) is None:
        raise MatrixFailure("matrix_commit_invalid")
    return commit


def write_profiles(
    matrix: dict[str, Any],
    role: str,
    selected_profile_id: str | None = None,
    include_credential_format: bool = False,
    include_response_mode: bool = False,
) -> None:
    profiles = matrix.get("profiles")
    if not isinstance(profiles, list):
        raise MatrixFailure("matrix_shape_invalid")
    count = 0
    if selected_profile_id is not None:
        selected_profile_id = safe_identifier(selected_profile_id)
    for profile in profiles:
        if not isinstance(profile, dict) or profile.get("role") != role:
            continue
        profile_id = safe_identifier(profile.get("id"))
        if selected_profile_id is not None and profile_id != selected_profile_id:
            continue
        plan_id = safe_identifier(profile.get("plan_id"))
        expression = safe_expression(profile.get("expression"))
        module_count = expected_module_count(profile)
        fields: list[str | int] = [profile_id, plan_id, expression, module_count]
        if include_credential_format:
            if role != "wallet":
                raise MatrixFailure("matrix_credential_format_role_invalid")
            fields.append(profile_credential_format(profile))
        if include_response_mode:
            if role != "wallet":
                raise MatrixFailure("matrix_response_mode_role_invalid")
            fields.append(profile_response_mode(profile))
        print("\t".join(str(field) for field in fields))
        count += 1
    if count == 0:
        raise MatrixFailure("matrix_role_profiles_missing")


def profile_credential_format(profile: dict[str, Any]) -> str:
    return profile_variant_value(
        profile,
        "credential_format",
        {"sd_jwt_vc", "iso_mdl"},
        "matrix_credential_format_invalid",
        "matrix_credential_format_ambiguous",
    )


def profile_response_mode(profile: dict[str, Any]) -> str:
    return profile_variant_value(
        profile,
        "response_mode",
        {"direct_post.jwt", "dc_api.jwt"},
        "matrix_response_mode_invalid",
        "matrix_response_mode_ambiguous",
    )


def profile_variant_value(
    profile: dict[str, Any],
    key: str,
    supported: set[str],
    invalid_reason: str,
    ambiguous_reason: str,
) -> str:
    groups = profile.get("expected_groups")
    if not isinstance(groups, list) or not groups:
        raise MatrixFailure("matrix_shape_invalid")
    values: set[str] = set()
    for group in groups:
        if not isinstance(group, dict):
            raise MatrixFailure("matrix_shape_invalid")
        variants = group.get("variants")
        if not isinstance(variants, dict):
            raise MatrixFailure("matrix_shape_invalid")
        value = variants.get(key)
        if not isinstance(value, str) or value not in supported:
            raise MatrixFailure(invalid_reason)
        values.add(value)
    if len(values) != 1:
        raise MatrixFailure(ambiguous_reason)
    return values.pop()


def expected_module_count(profile: dict[str, Any]) -> int:
    groups = profile.get("expected_groups")
    if not isinstance(groups, list) or not groups:
        raise MatrixFailure("matrix_shape_invalid")
    count = 0
    for group in groups:
        if not isinstance(group, dict):
            raise MatrixFailure("matrix_shape_invalid")
        modules = group.get("modules")
        if not isinstance(modules, list) or not modules:
            raise MatrixFailure("matrix_shape_invalid")
        for module_id in modules:
            safe_identifier(module_id)
        count += len(modules)
    return count


def safe_identifier(value: Any) -> str:
    if not isinstance(value, str) or SAFE_IDENTIFIER.fullmatch(value) is None:
        raise MatrixFailure("matrix_identifier_invalid")
    return value


def safe_expression(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\t" in value
        or "\n" in value
        or "\r" in value
    ):
        raise MatrixFailure("matrix_expression_invalid")
    return value


def reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MatrixFailure("json_duplicate_member")
        result[key] = value
    return result


def reject_non_finite_number(_value: str) -> None:
    raise MatrixFailure("matrix_non_finite_number")


if __name__ == "__main__":
    sys.exit(main())
