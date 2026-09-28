#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Verify that the profile matrix exactly matches a checked-out OIDF suite.

This check intentionally reads suite source rather than trusting a previously
generated inventory. A suite update that adds, removes, or renames a module must
therefore update the reviewed matrix before conformance execution can proceed.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


MAX_INPUT_BYTES = 2_000_000
MAX_JSON_DEPTH = 128
MAX_JSON_NODES = 200_000
MODULE_NAME_PATTERN = re.compile(r'testName\s*=\s*"([^"]+)"')
CLASS_NAME_PATTERN = re.compile(r"\bpublic\s+class\s+([A-Za-z][A-Za-z0-9_]*)")
PLAN_MODULES_PATTERN = re.compile(
    r"testModules\s*=\s*List\.of\((.*?)\);", re.DOTALL
)
PLAN_CLASS_PATTERN = re.compile(r"\b([A-Za-z][A-Za-z0-9_]*)\.class\b")
EXPRESSION_VARIANT_PATTERN = re.compile(r"\[([^=\]]+)=([^\]]+)\]")
SUITE_VERSION_PATTERN = re.compile(
    r"^fintechlabs\.version=([^\s#]+)\s*$", re.MULTILINE
)
SEMVER_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


class TargetFailure(Exception):
    """Stable, non-sensitive certification-target validation failure."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify an OIDF suite checkout against the protocol-profile matrix."
    )
    parser.add_argument("suite_dir", help="Checked-out OIDF conformance-suite directory")
    parser.add_argument("matrix", help="Protocol-profile matrix JSON")
    parser.add_argument(
        "--overlay",
        help="Optional reviewed module overlay for a stricter rehearsal deployment",
    )
    args = parser.parse_args()

    try:
        suite_dir = Path(args.suite_dir).resolve()
        matrix_path = Path(args.matrix).resolve()
        matrix = read_json_object(matrix_path)
        if args.overlay is not None:
            matrix = apply_rehearsal_overlay(
                matrix, read_json_object(Path(args.overlay).resolve())
            )
        verify_matrix(suite_dir, matrix)
        print("OIDF protocol profiles match the reviewed suite contract")
        return 0
    except TargetFailure as error:
        print(error.reason, file=sys.stderr)
        return 2


def apply_rehearsal_overlay(
    matrix: dict[str, Any], overlay: dict[str, Any]
) -> dict[str, Any]:
    """Apply an explicit deployment overlay without weakening the base matrix.

    The OIDF demo deployment may intentionally carry tests ahead of the
    production certification deployment. Keeping those additions in a small,
    reviewed overlay makes that stricter rehearsal target visible while the
    formal production matrix remains an exact certification target.
    """

    if overlay.get("schema_version") != 1:
        raise TargetFailure("overlay_schema_version_unsupported")
    if required_string(overlay, "purpose") != "oidf-demo-pre-submission":
        raise TargetFailure("overlay_purpose_invalid")

    result = copy.deepcopy(matrix)
    base_suite = required_object(result, "suite")
    overlay_suite = required_object(overlay, "suite")
    if required_string(overlay_suite, "repository") != required_string(
        base_suite, "repository"
    ):
        raise TargetFailure("overlay_repository_mismatch")
    commit = required_string(overlay_suite, "commit")
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise TargetFailure("overlay_commit_invalid")
    base_suite["commit"] = commit
    base_suite["describe"] = required_string(overlay_suite, "describe")
    base_suite["version"] = required_string(overlay_suite, "version")

    profiles = {
        required_string(profile, "id"): profile
        for profile in required_object_array(result, "profiles")
    }
    seen_profiles: set[str] = set()
    additions = required_object_array(overlay, "profile_additions")
    for addition in additions:
        profile_id = required_string(addition, "profile_id")
        if profile_id in seen_profiles:
            raise TargetFailure("overlay_duplicate_profile")
        seen_profiles.add(profile_id)
        profile = profiles.get(profile_id)
        if profile is None:
            raise TargetFailure("overlay_profile_unknown")

        expected_variants = required_string_map(addition, "group_variants")
        matching_groups = [
            group
            for group in required_object_array(profile, "expected_groups")
            if required_string_map(group, "variants") == expected_variants
        ]
        if len(matching_groups) != 1:
            raise TargetFailure("overlay_group_not_unique")

        modules = required_string_array(addition, "modules")
        if len(modules) != len(set(modules)):
            raise TargetFailure("overlay_duplicate_module")
        target_modules = required_string_array(matching_groups[0], "modules")
        if set(modules).intersection(target_modules):
            raise TargetFailure("overlay_module_already_present")
        target_modules.extend(modules)
        profile_expectations = profile.get("evidence_expectations")
        if isinstance(profile_expectations, dict):
            addition_expectations = required_object(addition, "evidence_expectations")
            if set(addition_expectations) != set(modules):
                raise TargetFailure("overlay_evidence_coverage_mismatch")
            if set(addition_expectations).intersection(profile_expectations):
                raise TargetFailure("overlay_evidence_already_present")
            profile_expectations.update(copy.deepcopy(addition_expectations))

    return result


def verify_matrix(suite_dir: Path, matrix: dict[str, Any]) -> None:
    if not suite_dir.is_dir():
        raise TargetFailure("suite_directory_missing")
    if not git_worktree_is_clean(suite_dir):
        raise TargetFailure("suite_worktree_dirty")
    if matrix.get("schema_version") != 1:
        raise TargetFailure("matrix_schema_version_unsupported")

    suite = required_object(matrix, "suite")
    expected_commit = required_string(suite, "commit")
    actual_commit = git_head(suite_dir)
    if actual_commit != expected_commit:
        raise TargetFailure("suite_commit_mismatch")
    verify_suite_version(suite_dir, required_string(suite, "version"))

    plans = required_object_array(matrix, "plans")
    profiles = required_object_array(matrix, "profiles")
    if not plans or not profiles:
        raise TargetFailure("matrix_coverage_empty")

    profile_ids: set[str] = set()
    plans_by_role: dict[str, dict[str, Any]] = {}
    for plan in plans:
        role = required_role(plan)
        if role in plans_by_role:
            raise TargetFailure("matrix_duplicate_role_plan")
        plans_by_role[role] = plan
        verify_plan_sources(suite_dir, plan)

    profiles_by_role: dict[str, list[dict[str, Any]]] = {
        "verifier": [],
        "wallet": [],
    }
    for profile in profiles:
        profile_id = required_string(profile, "id")
        if profile_id in profile_ids:
            raise TargetFailure("matrix_duplicate_profile_id")
        profile_ids.add(profile_id)
        role = required_role(profile)
        plan = plans_by_role.get(role)
        if plan is None:
            raise TargetFailure("matrix_profile_without_plan")
        if required_string(profile, "plan_id") != required_string(plan, "plan_id"):
            raise TargetFailure("matrix_profile_plan_mismatch")
        verify_profile(profile)
        profiles_by_role[role].append(profile)

    verify_result_policy_sources(suite_dir, matrix, profiles)

    for role, plan in plans_by_role.items():
        role_profiles = profiles_by_role.get(role, [])
        if not role_profiles:
            raise TargetFailure("matrix_plan_without_profiles")
        verify_module_coverage(suite_dir, plan, role_profiles)


def verify_suite_version(suite_dir: Path, expected_version: str) -> None:
    """Bind retained exports to the version built by the pinned suite checkout."""

    if SEMVER_PATTERN.fullmatch(expected_version) is None:
        raise TargetFailure("matrix_suite_version_invalid")
    properties = safe_suite_path(
        suite_dir, "src/main/resources/application.properties"
    )
    matches = SUITE_VERSION_PATTERN.findall(read_bounded_text(properties))
    if len(matches) != 1:
        raise TargetFailure("suite_version_unavailable")
    if matches[0] != expected_version:
        raise TargetFailure("suite_version_mismatch")


def verify_plan_sources(suite_dir: Path, plan: dict[str, Any]) -> None:
    plan_id = required_string(plan, "plan_id")
    plan_source = safe_suite_path(suite_dir, required_string(plan, "plan_source"))
    base_source = safe_suite_path(suite_dir, required_string(plan, "base_plan_source"))
    module_dir = safe_suite_path(
        suite_dir, required_string(plan, "module_source_directory")
    )
    plan_text = read_bounded_text(plan_source)
    read_bounded_text(base_source)
    if not module_dir.is_dir():
        raise TargetFailure("suite_module_source_directory_missing")
    if plan_id not in plan_text:
        raise TargetFailure("suite_certification_plan_id_missing")


def verify_profile(profile: dict[str, Any]) -> None:
    plan_id = required_string(profile, "plan_id")
    expression = required_string(profile, "expression")
    if not expression.startswith(f"{plan_id}["):
        raise TargetFailure("matrix_expression_plan_mismatch")
    selected_variants = dict(EXPRESSION_VARIANT_PATTERN.findall(expression))
    required_selected = {"credential_format", "response_mode"}
    if required_role(profile) == "wallet":
        required_selected.add("credential_type")
    if not required_selected.issubset(selected_variants):
        raise TargetFailure("matrix_expression_missing_required_variant")

    groups = required_object_array(profile, "expected_groups")
    if not groups:
        raise TargetFailure("matrix_profile_has_no_expected_groups")
    common_variants: dict[str, str] | None = None
    for group in groups:
        variants = required_string_map(group, "variants")
        modules = required_string_array(group, "modules")
        if not variants or not modules:
            raise TargetFailure("matrix_expected_group_empty")
        if len(modules) != len(set(modules)):
            raise TargetFailure("matrix_expected_group_duplicate_module")
        if common_variants is None:
            common_variants = dict(variants)
        else:
            common_variants = {
                key: value
                for key, value in common_variants.items()
                if variants.get(key) == value
            }

    if common_variants is None:
        raise TargetFailure("matrix_profile_has_no_expected_groups")
    for key, value in selected_variants.items():
        if common_variants.get(key) != value:
            raise TargetFailure("matrix_expression_variant_mismatch")
    expected_modules = {
        module
        for group in groups
        for module in required_string_array(group, "modules")
    }
    review_required = set(
        required_string_array(profile, "review_required_modules", allow_empty=True)
    )
    review_allowed = set(
        required_string_array(profile, "review_allowed_modules", allow_empty=True)
    )
    if (
        not review_required.issubset(expected_modules)
        or not review_allowed.issubset(expected_modules)
        or review_required.intersection(review_allowed)
    ):
        raise TargetFailure("matrix_result_expectation_invalid")
    if required_role(profile) == "verifier":
        verify_evidence_expectations(profile)


def verify_result_policy_sources(
    suite_dir: Path, matrix: dict[str, Any], profiles: list[dict[str, Any]]
) -> None:
    expected_modes: dict[str, str] = {}
    for profile in profiles:
        for key, mode in (
            ("review_required_modules", "review_required"),
            ("review_allowed_modules", "review_allowed"),
        ):
            for module_id in required_string_array(profile, key, allow_empty=True):
                previous = expected_modes.get(module_id)
                if previous is not None and previous != mode:
                    raise TargetFailure("matrix_result_policy_source_invalid")
                expected_modes[module_id] = mode
    sources = required_object(matrix, "result_policy_sources")
    if set(sources) != set(expected_modes):
        raise TargetFailure("matrix_result_policy_source_invalid")
    for module_id, raw in sources.items():
        if not isinstance(raw, dict) or set(raw) != {
            "mode",
            "module_source",
            "review_source",
        }:
            raise TargetFailure("matrix_result_policy_source_invalid")
        if required_string(raw, "mode") != expected_modes[module_id]:
            raise TargetFailure("matrix_result_policy_source_invalid")
        module_source = safe_suite_path(
            suite_dir, required_string(raw, "module_source")
        )
        module_text = read_bounded_text(module_source)
        module_matches = MODULE_NAME_PATTERN.findall(module_text)
        if module_matches != [module_id]:
            raise TargetFailure("matrix_result_policy_module_binding_invalid")
        review_source = safe_suite_path(
            suite_dir, required_string(raw, "review_source")
        )
        review_text = read_bounded_text(review_source)
        if not any(
            marker in review_text
            for marker in ("createPlaceholder", "createScreenshotPlaceholder", "screenshot")
        ):
            raise TargetFailure("matrix_result_policy_review_binding_invalid")


def verify_evidence_expectations(profile: dict[str, Any]) -> None:
    expected_modules = {
        module
        for group in required_object_array(profile, "expected_groups")
        for module in required_string_array(group, "modules")
    }
    expectations = required_object(profile, "evidence_expectations")
    if set(expectations) != expected_modules:
        raise TargetFailure("matrix_evidence_coverage_mismatch")
    allowed_decisions = {"accepted", "rejected"}
    allowed_kinds = {
        "authorization_response_validation",
        "credential_proof_validation",
        "request_object_retrieval",
        "response_decryption",
        "session_consumption",
    }
    for raw in expectations.values():
        if not isinstance(raw, dict) or set(raw) != {
            "decision",
            "observation_kind",
            "minimum_observations",
        }:
            raise TargetFailure("matrix_evidence_expectation_invalid")
        if raw.get("decision") not in allowed_decisions:
            raise TargetFailure("matrix_evidence_expectation_invalid")
        if raw.get("observation_kind") not in allowed_kinds:
            raise TargetFailure("matrix_evidence_expectation_invalid")
        minimum = raw.get("minimum_observations")
        if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 1:
            raise TargetFailure("matrix_evidence_expectation_invalid")


def verify_module_coverage(
    suite_dir: Path,
    plan: dict[str, Any],
    profiles: list[dict[str, Any]],
) -> None:
    module_dir = safe_suite_path(
        suite_dir, required_string(plan, "module_source_directory")
    )
    class_to_module = load_module_names(module_dir)
    base_source = safe_suite_path(suite_dir, required_string(plan, "base_plan_source"))
    base_classes = parse_base_plan_classes(read_bounded_text(base_source))
    try:
        base_modules = {class_to_module[class_name] for class_name in base_classes}
    except KeyError as error:
        raise TargetFailure("suite_base_plan_module_annotation_missing") from error

    expected_modules: set[str] = set()
    for profile in profiles:
        for group in required_object_array(profile, "expected_groups"):
            expected_modules.update(required_string_array(group, "modules"))

    exclusions = required_object_array(plan, "excluded_modules", allow_empty=True)
    excluded_modules: set[str] = set()
    for exclusion in exclusions:
        module_id = required_string(exclusion, "module_id")
        required_string(exclusion, "reason")
        excluded_modules.add(module_id)

    if expected_modules.intersection(excluded_modules):
        raise TargetFailure("matrix_module_both_expected_and_excluded")
    if expected_modules.union(excluded_modules) != base_modules:
        raise TargetFailure("matrix_module_coverage_drift")


def load_module_names(module_dir: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for source in sorted(module_dir.glob("*.java")):
        text = read_bounded_text(source)
        module_match = MODULE_NAME_PATTERN.search(text)
        class_match = CLASS_NAME_PATTERN.search(text)
        if module_match is None or class_match is None:
            continue
        class_name = class_match.group(1)
        if class_name in result:
            raise TargetFailure("suite_duplicate_module_class")
        result[class_name] = module_match.group(1)
    return result


def parse_base_plan_classes(text: str) -> set[str]:
    match = PLAN_MODULES_PATTERN.search(text)
    if match is None:
        raise TargetFailure("suite_base_plan_module_list_missing")
    classes = set(PLAN_CLASS_PATTERN.findall(match.group(1)))
    if not classes:
        raise TargetFailure("suite_base_plan_module_list_empty")
    return classes


def safe_suite_path(suite_dir: Path, relative: str) -> Path:
    candidate = (suite_dir / relative).resolve()
    try:
        candidate.relative_to(suite_dir)
    except ValueError as error:
        raise TargetFailure("matrix_suite_path_escapes_checkout") from error
    if not candidate.exists():
        raise TargetFailure("matrix_suite_path_missing")
    return candidate


def read_bounded_text(path: Path) -> str:
    try:
        if path.is_symlink():
            raise TargetFailure("input_file_symlink_rejected")
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise TargetFailure("input_file_too_large")
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise TargetFailure("input_file_unreadable") from error


def read_json_object(path: Path) -> dict[str, Any]:
    text = read_bounded_text(path)
    try:
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicate_members,
            parse_constant=reject_non_finite_number,
        )
    except (json.JSONDecodeError, RecursionError, TargetFailure) as error:
        raise TargetFailure("matrix_json_invalid") from error
    if not isinstance(value, dict):
        raise TargetFailure("matrix_json_invalid_shape")
    ensure_bounded_json(value)
    return value


def ensure_bounded_json(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    visited = 0
    while stack:
        current, depth = stack.pop()
        visited += 1
        if visited > MAX_JSON_NODES:
            raise TargetFailure("matrix_json_node_limit_exceeded")
        if depth > MAX_JSON_DEPTH:
            raise TargetFailure("matrix_json_nesting_exceeded")
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)


def reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TargetFailure("json_duplicate_member")
        result[key] = value
    return result


def reject_non_finite_number(_value: str) -> None:
    raise TargetFailure("matrix_json_non_finite_number")


def required_object(value: dict[str, Any], key: str) -> dict[str, Any]:
    item = value.get(key)
    if not isinstance(item, dict):
        raise TargetFailure("matrix_json_invalid_shape")
    return item


def required_object_array(
    value: dict[str, Any], key: str, *, allow_empty: bool = False
) -> list[dict[str, Any]]:
    item = value.get(key)
    if not isinstance(item, list) or (not allow_empty and not item):
        raise TargetFailure("matrix_json_invalid_shape")
    if not all(isinstance(entry, dict) for entry in item):
        raise TargetFailure("matrix_json_invalid_shape")
    return item


def required_string(value: dict[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise TargetFailure("matrix_json_invalid_shape")
    return item


def required_string_array(
    value: dict[str, Any], key: str, *, allow_empty: bool = False
) -> list[str]:
    item = value.get(key)
    if not isinstance(item, list) or (not allow_empty and not item):
        raise TargetFailure("matrix_json_invalid_shape")
    if not all(isinstance(entry, str) and entry for entry in item):
        raise TargetFailure("matrix_json_invalid_shape")
    return item


def required_string_map(value: dict[str, Any], key: str) -> dict[str, str]:
    item = value.get(key)
    if not isinstance(item, dict) or not item:
        raise TargetFailure("matrix_json_invalid_shape")
    if not all(
        isinstance(map_key, str)
        and map_key
        and isinstance(map_value, str)
        and map_value
        for map_key, map_value in item.items()
    ):
        raise TargetFailure("matrix_json_invalid_shape")
    return item


def required_role(value: dict[str, Any]) -> str:
    role = required_string(value, "role")
    if role not in {"verifier", "wallet"}:
        raise TargetFailure("matrix_role_invalid")
    return role


def git_head(suite_dir: Path) -> str:
    try:
        completed = subprocess.run(
            ("git", "rev-parse", "HEAD"),
            cwd=suite_dir,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise TargetFailure("suite_git_head_unavailable") from error
    commit = completed.stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise TargetFailure("suite_git_head_invalid")
    return commit


def git_worktree_is_clean(suite_dir: Path) -> bool:
    try:
        completed = subprocess.run(
            (
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=normal",
            ),
            cwd=suite_dir,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise TargetFailure("suite_git_status_unavailable") from error
    return completed.stdout == ""


if __name__ == "__main__":
    sys.exit(main())
