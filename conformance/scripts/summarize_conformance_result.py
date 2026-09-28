#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Write a non-PII Markdown summary for conformance result JSON files."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from typing import Any


KNOWN_STATUSES = frozenset(
    {"validated", "passed", "failed", "pending_runner", "dry_run"}
)


@dataclass(frozen=True)
class ResultRecord:
    path: str
    status: str
    reason: str
    plan_id: str | None
    profile_id: str | None
    triggered_modules: int | None


class SummaryFailure(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Summarize OpenID4VP conformance JSON result files.",
    )
    parser.add_argument("paths", nargs="+", help="result JSON files")
    parser.add_argument(
        "--output",
        default=os.environ.get("GITHUB_STEP_SUMMARY"),
        help="Markdown output path; defaults to GITHUB_STEP_SUMMARY",
    )
    args = parser.parse_args()
    try:
        records = [read_result(path) for path in args.paths]
        summary = build_summary(records)
        if args.output:
            append_summary(args.output, summary)
        else:
            print(summary, end="")
        return 0
    except SummaryFailure as error:
        print(error.reason, file=sys.stderr)
        return 2


def read_result(path: str) -> ResultRecord:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as exc:
        raise SummaryFailure("result_file_unreadable") from exc
    except json.JSONDecodeError as exc:
        raise SummaryFailure("result_file_invalid_json") from exc
    if not isinstance(data, dict):
        raise SummaryFailure("result_file_invalid_shape")
    status = string_field(data, "status")
    if status not in KNOWN_STATUSES:
        raise SummaryFailure("result_file_unknown_status")
    reason = string_field(data, "reason")
    plan_id = optional_string_field(data, "plan_id")
    profile_id = optional_string_field(data, "profile_id")
    triggered_modules = optional_int_field(data, "triggered_modules")
    return ResultRecord(
        path=path,
        status=status,
        reason=reason,
        plan_id=plan_id,
        profile_id=profile_id,
        triggered_modules=triggered_modules,
    )


def string_field(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or value == "":
        raise SummaryFailure("result_file_invalid_shape")
    return value


def optional_string_field(data: dict[str, Any], key: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or value == "":
        raise SummaryFailure("result_file_invalid_shape")
    return value


def optional_int_field(data: dict[str, Any], key: str) -> int | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, int) or value < 0:
        raise SummaryFailure("result_file_invalid_shape")
    return value


def build_summary(records: list[ResultRecord]) -> str:
    if len(records) == 0:
        raise SummaryFailure("no_result_files")
    lines = [
        "## OpenID4VP Conformance",
        "",
        "| Result file | Plan | Profile | Status | Reason | Triggered modules |",
        "| --- | --- | --- | --- | --- | ---: |",
    ]
    for record in records:
        lines.append(
            "| {path} | {plan} | {profile} | {status} | {reason} | {triggered} |".format(
                path=markdown_escape(os.path.basename(record.path)),
                plan=markdown_escape(record.plan_id or "-"),
                profile=markdown_escape(record.profile_id or "-"),
                status=markdown_escape(record.status),
                reason=markdown_escape(record.reason),
                triggered="-" if record.triggered_modules is None else str(record.triggered_modules),
            )
        )
    lines.append("")
    return "\n".join(lines)


def markdown_escape(value: str) -> str:
    return value.replace("|", "\\|")


def append_summary(path: str, summary: str) -> None:
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(summary)
    except OSError as exc:
        raise SummaryFailure("summary_file_unwritable") from exc


if __name__ == "__main__":
    sys.exit(main())
