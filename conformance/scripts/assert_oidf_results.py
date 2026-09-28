#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Fail closed unless an OIDF export covers one complete protocol profile."""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

import verify_oidf_certification_target


MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_ZIP_BYTES = 128 * 1024 * 1024
MAX_ZIP_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES = 128 * 1024 * 1024
MAX_ZIP_MEMBERS = 4096
MAX_JSON_DEPTH = 128
MAX_JSON_NODES = 200_000
REQUIRED_MODULE_STATUS = "FINISHED"
PASSED_MODULE_RESULT = "PASSED"
REVIEW_MODULE_RESULT = "REVIEW"


class ResultFailure(Exception):
    """Stable, non-sensitive result-validation failure."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ExpectedProfile:
    suite_version: str
    plan_id: str
    variant_keys: tuple[str, ...]
    cases: Counter[tuple[str, tuple[tuple[str, str], ...]]]
    allowed_results: dict[
        tuple[str, tuple[tuple[str, str], ...]], frozenset[str]
    ]


@dataclass(frozen=True)
class ObservedResult:
    exported_version: str
    test_version: str
    plan_instance_id: str
    module_id: str
    match_variants: tuple[tuple[str, str], ...]
    status: str
    result: str


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Assert complete OIDF results for one protocol profile."
    )
    parser.add_argument("results_dir", help="OIDF export directory")
    parser.add_argument("--matrix", required=True, help="Certification matrix JSON")
    parser.add_argument("--overlay", help="Optional reviewed rehearsal overlay JSON")
    parser.add_argument("--profile", required=True, help="Matrix profile id")
    parser.add_argument(
        "--expected-plan-instance-id",
        help="Exact OIDF plan instance selected by the profile-bound flow driver",
    )
    args = parser.parse_args()

    try:
        overlay_path = Path(args.overlay) if args.overlay is not None else None
        expected = load_expected_profile(Path(args.matrix), args.profile, overlay_path)
        observed = collect_results(Path(args.results_dir), expected.variant_keys)
        assert_complete_results(expected, observed, args.expected_plan_instance_id)
        result_counts = Counter(result.result for result in observed)
        print(
            "OIDF profile export is complete: "
            f"modules={len(observed)} "
            f"passed={result_counts[PASSED_MODULE_RESULT]} "
            f"review={result_counts[REVIEW_MODULE_RESULT]}"
        )
        return 0
    except ResultFailure as error:
        print(error.reason, file=sys.stderr)
        return 2


def load_expected_profile(
    matrix_path: Path, profile_id: str, overlay_path: Path | None = None
) -> ExpectedProfile:
    matrix = read_json_file(matrix_path, MAX_JSON_BYTES, "matrix")
    if not isinstance(matrix, dict) or matrix.get("schema_version") != 1:
        raise ResultFailure("matrix_invalid_shape")
    if overlay_path is not None:
        try:
            overlay = verify_oidf_certification_target.read_json_object(overlay_path)
            matrix = verify_oidf_certification_target.apply_rehearsal_overlay(
                matrix, overlay
            )
        except verify_oidf_certification_target.TargetFailure as error:
            raise ResultFailure("matrix_overlay_invalid") from error
    suite = matrix.get("suite")
    if not isinstance(suite, dict):
        raise ResultFailure("matrix_invalid_shape")
    suite_version = required_string(suite, "version", "matrix_invalid_shape")
    profiles = matrix.get("profiles")
    if not isinstance(profiles, list):
        raise ResultFailure("matrix_invalid_shape")
    validate_result_policy_bindings(matrix, profiles)
    matches = [
        profile
        for profile in profiles
        if isinstance(profile, dict) and profile.get("id") == profile_id
    ]
    if len(matches) != 1:
        raise ResultFailure("matrix_profile_not_unique")
    profile = matches[0]
    plan_id = required_string(profile, "plan_id", "matrix_invalid_shape")
    groups = profile.get("expected_groups")
    if not isinstance(groups, list) or not groups:
        raise ResultFailure("matrix_invalid_shape")
    cases: Counter[tuple[str, tuple[tuple[str, str], ...]]] = Counter()
    expected_module_ids: set[str] = set()
    for group in groups:
        if not isinstance(group, dict):
            raise ResultFailure("matrix_invalid_shape")
        group_modules = group.get("modules")
        if not isinstance(group_modules, list) or not group_modules:
            raise ResultFailure("matrix_invalid_shape")
        for module_id in group_modules:
            if not isinstance(module_id, str) or not module_id:
                raise ResultFailure("matrix_invalid_shape")
            expected_module_ids.add(module_id)
    review_required = read_module_set(
        profile, "review_required_modules", expected_module_ids
    )
    review_allowed = read_module_set(
        profile, "review_allowed_modules", expected_module_ids
    )
    if review_required & review_allowed:
        raise ResultFailure("matrix_result_expectations_invalid")
    allowed_results: dict[
        tuple[str, tuple[tuple[str, str], ...]], frozenset[str]
    ] = {}
    variant_keys: tuple[str, ...] | None = None
    for group in groups:
        if not isinstance(group, dict):
            raise ResultFailure("matrix_invalid_shape")
        group_modules = group.get("modules")
        if not isinstance(group_modules, list) or not group_modules:
            raise ResultFailure("matrix_invalid_shape")
        variants = group.get("variants")
        if not isinstance(variants, dict):
            raise ResultFailure("matrix_invalid_shape")
        group_variant_keys = tuple(sorted(variants))
        if not group_variant_keys:
            raise ResultFailure("matrix_invalid_shape")
        if variant_keys is None:
            variant_keys = group_variant_keys
        elif variant_keys != group_variant_keys:
            raise ResultFailure("matrix_variant_keys_inconsistent")
        match_variants = select_match_variants(
            variants, group_variant_keys, "matrix_invalid_shape"
        )
        for module_id in group_modules:
            if not isinstance(module_id, str) or not module_id:
                raise ResultFailure("matrix_invalid_shape")
            case = (module_id, match_variants)
            cases[case] += 1
            if module_id in review_required:
                allowed_results[case] = frozenset((REVIEW_MODULE_RESULT,))
            elif module_id in review_allowed:
                allowed_results[case] = frozenset(
                    (PASSED_MODULE_RESULT, REVIEW_MODULE_RESULT)
                )
            else:
                allowed_results[case] = frozenset((PASSED_MODULE_RESULT,))
    if variant_keys is None:
        raise ResultFailure("matrix_invalid_shape")
    return ExpectedProfile(
        suite_version=suite_version,
        plan_id=plan_id,
        variant_keys=variant_keys,
        cases=cases,
        allowed_results=allowed_results,
    )


def read_module_set(
    profile: dict[str, Any], key: str, expected_module_ids: set[str]
) -> set[str]:
    values = profile.get(key)
    if not isinstance(values, list):
        raise ResultFailure("matrix_result_expectations_invalid")
    modules: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not value or value in modules:
            raise ResultFailure("matrix_result_expectations_invalid")
        if value not in expected_module_ids:
            raise ResultFailure("matrix_result_expectations_invalid")
        modules.add(value)
    return modules


def validate_result_policy_bindings(
    matrix: dict[str, Any], profiles: list[Any]
) -> None:
    required_modes: dict[str, str] = {}
    for profile in profiles:
        if not isinstance(profile, dict):
            raise ResultFailure("matrix_result_policy_sources_invalid")
        for key, mode in (
            ("review_required_modules", "review_required"),
            ("review_allowed_modules", "review_allowed"),
        ):
            values = profile.get(key)
            if not isinstance(values, list):
                raise ResultFailure("matrix_result_policy_sources_invalid")
            for value in values:
                if not isinstance(value, str) or not value:
                    raise ResultFailure("matrix_result_policy_sources_invalid")
                previous = required_modes.get(value)
                if previous is not None and previous != mode:
                    raise ResultFailure("matrix_result_policy_sources_invalid")
                required_modes[value] = mode
    sources = matrix.get("result_policy_sources")
    if not isinstance(sources, dict) or set(sources) != set(required_modes):
        raise ResultFailure("matrix_result_policy_sources_invalid")
    for module_id, source in sources.items():
        if not isinstance(source, dict) or set(source) != {
            "mode",
            "module_source",
            "review_source",
        }:
            raise ResultFailure("matrix_result_policy_sources_invalid")
        if source.get("mode") != required_modes[module_id]:
            raise ResultFailure("matrix_result_policy_sources_invalid")
        for key in ("module_source", "review_source"):
            path = source.get(key)
            if (
                not isinstance(path, str)
                or not path.startswith("src/main/java/")
                or ".." in Path(path).parts
                or any(character in path for character in ("\t", "\r", "\n"))
            ):
                raise ResultFailure("matrix_result_policy_sources_invalid")


def collect_results(
    results_dir: Path, variant_keys: tuple[str, ...]
) -> list[ObservedResult]:
    if not results_dir.is_dir():
        raise ResultFailure("results_directory_missing")
    observed: list[ObservedResult] = []
    artifact_count = 0
    for path in sorted(results_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.is_symlink():
            raise ResultFailure("result_symlink_rejected")
        suffix = path.suffix.lower()
        if suffix == ".json":
            artifact_count += 1
            value = read_json_file(path, MAX_JSON_BYTES, "result")
            append_observed(value, observed, variant_keys)
        elif suffix == ".zip":
            artifact_count += 1
            observed.extend(read_zip_results(path, variant_keys))
    if artifact_count == 0:
        raise ResultFailure("result_artifacts_missing")
    if not observed:
        raise ResultFailure("result_test_logs_missing")
    return observed


def read_zip_results(
    path: Path, variant_keys: tuple[str, ...]
) -> list[ObservedResult]:
    try:
        if path.stat().st_size > MAX_ZIP_BYTES:
            raise ResultFailure("result_zip_too_large")
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as error:
        raise ResultFailure("result_zip_invalid") from error
    observed: list[ObservedResult] = []
    try:
        members = archive.infolist()
        if len(members) > MAX_ZIP_MEMBERS:
            raise ResultFailure("result_zip_too_many_members")
        total_uncompressed = 0
        for member in members:
            member_path = PurePosixPath(member.filename)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise ResultFailure("result_zip_member_path_invalid")
            if member.is_dir() or member_path.suffix.lower() != ".json":
                continue
            if member.file_size > MAX_ZIP_MEMBER_BYTES:
                raise ResultFailure("result_zip_member_too_large")
            total_uncompressed += member.file_size
            if total_uncompressed > MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES:
                raise ResultFailure("result_zip_uncompressed_size_exceeded")
            try:
                raw = archive.read(member)
            except (OSError, RuntimeError, zipfile.BadZipFile) as error:
                raise ResultFailure("result_zip_member_unreadable") from error
            value = decode_json(raw, "result")
            append_observed(value, observed, variant_keys)
    finally:
        archive.close()
    return observed


def append_observed(
    value: Any,
    observed: list[ObservedResult],
    variant_keys: tuple[str, ...],
) -> None:
    if not isinstance(value, dict):
        return
    test_info = value.get("testInfo")
    if not isinstance(test_info, dict):
        return
    exported_version = required_string(
        value, "exportedVersion", "result_test_info_invalid"
    )
    module_id = required_string(test_info, "testName", "result_test_info_invalid")
    status = required_string(test_info, "status", "result_test_info_invalid")
    result = required_string(test_info, "result", "result_test_info_invalid")
    test_version = required_string(
        test_info, "version", "result_test_info_invalid"
    )
    plan_instance_id = required_string(
        test_info, "planId", "result_test_info_invalid"
    )
    serialized_variants = test_info.get("variant")
    if not isinstance(serialized_variants, dict):
        raise ResultFailure("result_test_info_invalid")
    nested_variants = serialized_variants.get("variant")
    if isinstance(nested_variants, dict):
        serialized_variants = nested_variants
    match_variants = select_match_variants(
        serialized_variants, variant_keys, "result_test_info_invalid"
    )
    observed.append(
        ObservedResult(
            exported_version=exported_version,
            test_version=test_version,
            plan_instance_id=plan_instance_id,
            module_id=module_id,
            match_variants=match_variants,
            status=status,
            result=result,
        )
    )


def assert_complete_results(
    expected: ExpectedProfile,
    observed: Iterable[ObservedResult],
    expected_plan_instance_id: str | None = None,
) -> None:
    if expected_plan_instance_id is not None and not expected_plan_instance_id:
        raise ResultFailure("result_expected_plan_instance_invalid")
    actual_cases: Counter[tuple[str, tuple[tuple[str, str], ...]]] = Counter()
    observed_count = 0
    plan_instance_id: str | None = None
    for result in observed:
        observed_count += 1
        if (
            result.exported_version != expected.suite_version
            or result.test_version != expected.suite_version
        ):
            raise ResultFailure("result_suite_version_mismatch")
        if plan_instance_id is None:
            plan_instance_id = result.plan_instance_id
        elif result.plan_instance_id != plan_instance_id:
            raise ResultFailure("result_plan_instance_mismatch")
        if (
            expected_plan_instance_id is not None
            and result.plan_instance_id != expected_plan_instance_id
        ):
            raise ResultFailure("result_plan_instance_binding_mismatch")
        if result.status != REQUIRED_MODULE_STATUS:
            raise ResultFailure("result_module_not_finished")
        case = (result.module_id, result.match_variants)
        if case not in expected.cases:
            raise ResultFailure("result_module_coverage_mismatch")
        allowed_results = expected.allowed_results.get(case)
        if allowed_results is None or result.result not in allowed_results:
            raise ResultFailure("result_module_unexpected_result")
        actual_cases[case] += 1
    if observed_count == 0:
        raise ResultFailure("result_test_logs_missing")
    if actual_cases != expected.cases:
        raise ResultFailure("result_module_coverage_mismatch")


def read_json_file(path: Path, maximum_bytes: int, kind: str) -> Any:
    try:
        if path.is_symlink():
            raise ResultFailure(f"{kind}_symlink_rejected")
        size = path.stat().st_size
        if size > maximum_bytes:
            raise ResultFailure(f"{kind}_json_too_large")
        raw = path.read_bytes()
    except OSError as error:
        raise ResultFailure(f"{kind}_json_unreadable") from error
    return decode_json(raw, kind)


def decode_json(raw: bytes, kind: str) -> Any:
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicate_members,
            parse_constant=reject_non_finite_number,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, ResultFailure) as error:
        raise ResultFailure(f"{kind}_json_invalid") from error
    ensure_bounded_json(value, kind)
    return value


def reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ResultFailure("json_duplicate_member")
        result[key] = value
    return result


def reject_non_finite_number(_value: str) -> None:
    raise ResultFailure("json_non_finite_number")


def ensure_bounded_json(value: Any, kind: str) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    visited = 0
    while stack:
        current, depth = stack.pop()
        visited += 1
        if visited > MAX_JSON_NODES:
            raise ResultFailure(f"{kind}_json_node_limit_exceeded")
        if depth > MAX_JSON_DEPTH:
            raise ResultFailure(f"{kind}_json_nesting_exceeded")
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)


def required_string(value: dict[str, Any], key: str, reason: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise ResultFailure(reason)
    return item


def select_match_variants(
    variants: dict[str, Any], keys: tuple[str, ...], reason: str
) -> tuple[tuple[str, str], ...]:
    selected: list[tuple[str, str]] = []
    for key in keys:
        value = variants.get(key)
        if not isinstance(value, str) or not value:
            raise ResultFailure(reason)
        selected.append((key, value))
    return tuple(selected)


if __name__ == "__main__":
    sys.exit(main())
