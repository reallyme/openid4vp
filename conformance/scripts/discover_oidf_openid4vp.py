#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Discover OpenID4VP-related OIDF conformance-suite plans and modules.

The OIDF conformance suite is external and changes independently of this
repository. This script inspects the exact checked-out suite tree used by CI and
writes machine-readable discovery artifacts so pinned manifests can be refreshed
from evidence instead of memory.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


MAX_FILE_BYTES = 1_000_000
TEXT_SUFFIXES = {
    ".adoc",
    ".conf",
    ".groovy",
    ".html",
    ".java",
    ".js",
    ".json",
    ".kt",
    ".md",
    ".properties",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
PLAN_MATCH_TOKENS = (
    "openid4vp",
    "oid4vp",
    "verifiable presentation",
    "verifiable presentations",
    "presentation verifier",
    "vp verifier",
    "vp wallet",
)
PLAN_PATTERN = re.compile(
    r"oid4vp[-_][A-Za-z0-9_.:\-\[\]=,]+test[-_]plan(?:\[[^\]\n\r]+])?",
    re.IGNORECASE,
)
CLASS_PATTERN = re.compile(r"\b(class|interface|enum)\s+([A-Za-z][A-Za-z0-9_]*)")


@dataclass(frozen=True)
class SourceMatch:
    """One suite source file relevant to OpenID4VP discovery."""

    path: str
    text: str


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Discover OpenID4VP OIDF conformance-suite artifacts."
    )
    parser.add_argument("suite_dir", help="Checked-out OIDF conformance-suite directory")
    parser.add_argument(
        "output_dir",
        help="Directory that receives suite.lock, plans.json, modules.json, and oidf-discovery.json",
    )
    args = parser.parse_args()

    suite_dir = Path(args.suite_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    if not suite_dir.is_dir():
        print("suite directory does not exist", file=sys.stderr)
        return 66

    output_dir.mkdir(parents=True, exist_ok=True)
    matches = list(discover_source_matches(suite_dir))
    suite_lock = build_suite_lock(suite_dir)
    plans = build_plans(matches)
    modules = build_modules(matches, plans)
    discovery = {
        "schema_version": 1,
        "suite": suite_lock,
        "plans": plans["plans"],
        "modules": modules["modules"],
    }

    write_json(output_dir / "suite.lock", suite_lock)
    write_json(output_dir / "plans.json", plans)
    write_json(output_dir / "modules.json", modules)
    write_json(output_dir / "oidf-discovery.json", discovery)
    return 0


def discover_source_matches(suite_dir: Path) -> Iterable[SourceMatch]:
    for path in sorted(suite_dir.rglob("*")):
        if not should_read(path):
            continue
        text = read_text(path)
        if text is None:
            continue
        relative = path.relative_to(suite_dir).as_posix()
        if is_relevant_source(relative, text):
            yield SourceMatch(path=relative, text=text)


def should_read(path: Path) -> bool:
    if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
        return False
    try:
        return path.stat().st_size <= MAX_FILE_BYTES
    except OSError:
        return False


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None
    except OSError:
        return None


def build_suite_lock(suite_dir: Path) -> dict[str, object]:
    return {
        "schema_version": 1,
        "repository": "https://gitlab.com/openid/conformance-suite",
        "commit": git_output(suite_dir, "rev-parse", "HEAD"),
        "describe": git_output(suite_dir, "describe", "--tags", "--always"),
        "discovery_status": "generated-from-checked-out-suite",
        "discovery_script": "conformance/scripts/discover_oidf_openid4vp.py",
    }


def build_plans(matches: list[SourceMatch]) -> dict[str, object]:
    discovered: dict[str, dict[str, object]] = {}
    for match in matches:
        for plan_id in sorted(set(PLAN_PATTERN.findall(match.text))):
            normalized = plan_id.lower()
            discovered[plan_id] = {
                "plan_id": plan_id,
                "role_under_test": infer_role(normalized),
                "profile": infer_profile(normalized),
                "flow": infer_flow(normalized),
                "source": match.path,
                "automated": True,
                "supported": True,
                "status": "discovered",
            }
    return {
        "schema_version": 1,
        "plans": sorted(discovered.values(), key=lambda item: str(item["plan_id"])),
    }


def build_modules(matches: list[SourceMatch], plans: dict[str, object]) -> dict[str, object]:
    plan_ids = [str(plan["plan_id"]) for plan in plans["plans"]]
    modules: list[dict[str, object]] = []
    for match in matches:
        if not is_vp_module_source(match.path):
            continue
        module_id = infer_module_id(match)
        if module_id is None:
            continue
        text = match.text.lower()
        modules.append(
            {
                "plan_id": matching_plan_id(match.text, plan_ids),
                "module_id": module_id,
                "role_under_test": infer_role(text),
                "flow": infer_flow(text),
                "profile": infer_profile(text),
                "topic": infer_topic(text),
                "specification": "openid4vp-1.0-final",
                "sections": [],
                "supported": True,
                "automated": True,
                "source": match.path,
                "exclusion_reason": None,
            }
        )
    modules.sort(key=lambda item: (str(item["module_id"]), str(item["source"])))
    return {"schema_version": 1, "modules": modules}


def is_relevant_source(relative_path: str, text: str) -> bool:
    relative_lowered = relative_path.lower()
    text_lowered = text.lower()
    if is_vp_module_source(relative_path):
        return True
    return any(
        token in text_lowered or token in relative_lowered for token in PLAN_MATCH_TOKENS
    )


def is_vp_module_source(relative_path: str) -> bool:
    lowered = relative_path.lower()
    return (
        "/vp" in lowered
        or "/oid4vp" in lowered
        or "/openid4vp" in lowered
        or "presentation" in lowered
    ) and (
        lowered.startswith("src/main/java/net/openid/conformance")
        or lowered.startswith("src/test/java/net/openid/conformance")
    )


def infer_module_id(match: SourceMatch) -> str | None:
    class_match = CLASS_PATTERN.search(match.text)
    if class_match is not None:
        return class_match.group(2)
    stem = Path(match.path).stem
    if stem:
        return stem
    return None


def matching_plan_id(text: str, plan_ids: list[str]) -> str | None:
    lowered = text.lower()
    for plan_id in plan_ids:
        if plan_id.lower() in lowered:
            return plan_id
    return None


def infer_role(text: str) -> str:
    if "wallet" in text or "holder" in text:
        return "wallet"
    if "verifier" in text or "relying party" in text or "rp" in text:
        return "verifier"
    return "unknown"


def infer_profile(text: str) -> str:
    if "haip" in text or "high assurance" in text:
        return "haip"
    return "base"


def infer_flow(text: str) -> str:
    if "dc_api" in text or "digital credential" in text:
        return "dc_api"
    if "direct_post.jwt" in text or "direct-post-jwt" in text:
        return "direct_post.jwt"
    if "direct_post" in text or "direct-post" in text:
        return "direct_post"
    return "unspecified"


def infer_topic(text: str) -> str:
    if "dcql" in text:
        return "dcql"
    if "metadata" in text:
        return "metadata"
    if "nonce" in text:
        return "nonce"
    if "attestation" in text:
        return "verifier_attestation"
    if "encryption" in text or "jwe" in text or "jwt" in text:
        return "encryption"
    if "mdoc" in text or "mdl" in text:
        return "mdoc"
    if "sd-jwt" in text or "sd_jwt" in text:
        return "sd_jwt_vc"
    if "request_uri" in text:
        return "request_uri"
    return "unspecified"


def git_output(workdir: Path, *args: str) -> str | None:
    try:
        completed = subprocess.run(
            ("git", *args),
            cwd=workdir,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    value = completed.stdout.strip()
    if value:
        return value
    return None


def write_json(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
