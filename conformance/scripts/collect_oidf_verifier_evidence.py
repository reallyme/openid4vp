#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Collect bounded, module-bound evidence from a deployed verifier host."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import ssl
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn

import validate_oidf_runtime_endpoints


MAX_JSON_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 10_000
MAX_OBSERVATIONS = 32
MIN_CONTROL_TOKEN_BYTES = 32
MAX_CONTROL_TOKEN_BYTES = 4096
HTTP_TIMEOUT_SECONDS = 20.0
PLAN_PAGE_SIZE = 200
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,191}$")
SAFE_REASON = re.compile(r"^[a-z][a-z0-9_]{0,95}$")
FINISHED_STATUS = "FINISHED"
PASSED_RESULT = "PASSED"
REVIEW_RESULT = "REVIEW"
DECISIONS = frozenset(("accepted", "rejected"))
OBSERVATION_KINDS = frozenset(
    (
        "authorization_response_validation",
        "credential_proof_validation",
        "request_object_retrieval",
        "response_decryption",
        "session_consumption",
    )
)


@dataclass(frozen=True)
class EvidenceExpectation:
    decision: str
    observation_kind: str
    minimum_observations: int
    allowed_results: frozenset[str]


@dataclass(frozen=True)
class ModuleInstance:
    module_id: str
    module_name: str


@dataclass(frozen=True)
class PlanEvidence:
    plan_instance_id: str
    module_instances: tuple[ModuleInstance, ...]


@dataclass(frozen=True, repr=False)
class CollectorConfig:
    conformance_server: str
    conformance_api_token: str | None
    verify_ssl: bool
    evidence_endpoint: str
    evidence_token: str
    plan_id: str
    alias: str
    started_after: float
    profile_id: str
    output_directory: Path
    matrix_path: Path


class EvidenceFailure(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirects so configured evidence origins cannot become SSRF pivots."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Collect per-module OIDF verifier implementation evidence."
    )
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--alias", required=True)
    parser.add_argument("--started-after", required=True, type=float)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    try:
        config = read_config(args)
        collect(config)
        return 0
    except EvidenceFailure as error:
        print(error.reason, file=sys.stderr)
        return 2


def read_config(args: argparse.Namespace) -> CollectorConfig:
    conformance_server = required_environment("CONFORMANCE_SERVER")
    development_mode = read_bool_environment("CONFORMANCE_DEV_MODE", False)
    conformance_api_token = optional_environment("CONFORMANCE_API_TOKEN")
    if not development_mode and conformance_api_token is None:
        raise EvidenceFailure("evidence_environment_missing")
    evidence_endpoint = required_environment("OIDF_VERIFIER_EVIDENCE_ENDPOINT")
    evidence_token = validate_control_token(
        required_environment("OIDF_VERIFIER_EVIDENCE_TOKEN")
    )
    validate_https_endpoint(conformance_server)
    validate_evidence_endpoint(evidence_endpoint, development_mode)
    if not math.isfinite(args.started_after) or args.started_after <= 0:
        raise EvidenceFailure("evidence_started_after_invalid")
    return CollectorConfig(
        conformance_server=conformance_server,
        conformance_api_token=conformance_api_token,
        verify_ssl=read_bool_environment("CONFORMANCE_VERIFY_SSL", True),
        evidence_endpoint=evidence_endpoint,
        evidence_token=evidence_token,
        plan_id=safe_identifier(args.plan, "evidence_plan_id_invalid"),
        alias=safe_identifier(args.alias, "evidence_alias_invalid"),
        started_after=args.started_after,
        profile_id=safe_identifier(args.profile, "evidence_profile_id_invalid"),
        output_directory=Path(args.output_dir),
        matrix_path=Path(args.matrix),
    )


def collect(config: CollectorConfig) -> None:
    expectations = read_expectations(config.matrix_path, config.profile_id)
    plan_evidence = fetch_module_instances(config, set(expectations))
    if config.output_directory.exists():
        raise EvidenceFailure("evidence_output_already_exists")
    try:
        config.output_directory.mkdir(parents=True, mode=0o700)
    except OSError as error:
        raise EvidenceFailure("evidence_output_create_failed") from error

    index_records: list[dict[str, object]] = []
    for instance in sorted(
        plan_evidence.module_instances, key=lambda value: value.module_name
    ):
        info = api_get_json(
            config,
            f"api/info/{urllib.parse.quote(instance.module_id, safe='')}",
        )
        suite_result = validate_finished_module(
            info, instance, expectations[instance.module_name]
        )
        evidence = fetch_host_evidence(config, instance)
        validate_evidence(evidence, config, instance, expectations[instance.module_name])
        filename = f"{instance.module_name}--{instance.module_id}.json"
        encoded = canonical_json(evidence)
        write_private_file(config.output_directory / filename, encoded)
        index_records.append(
            {
                "file": filename,
                "module_id": instance.module_id,
                "module_name": instance.module_name,
                "suite_result": suite_result,
                "sha256": hashlib.sha256(encoded).hexdigest(),
            }
        )
    index = {
        "schema_version": 1,
        "profile_id": config.profile_id,
        "plan_id": config.plan_id,
        "plan_instance_id": plan_evidence.plan_instance_id,
        "module_count": len(index_records),
        "records": index_records,
    }
    write_private_file(config.output_directory / "index.json", canonical_json(index))


def read_expectations(path: Path, profile_id: str) -> dict[str, EvidenceExpectation]:
    matrix = read_json_file(path, "evidence_matrix_invalid")
    profiles = matrix.get("profiles")
    if not isinstance(profiles, list):
        raise EvidenceFailure("evidence_matrix_invalid")
    matches = [
        profile
        for profile in profiles
        if isinstance(profile, dict) and profile.get("id") == profile_id
    ]
    if len(matches) != 1 or matches[0].get("role") != "verifier":
        raise EvidenceFailure("evidence_profile_invalid")
    profile = matches[0]
    module_names = expected_module_names(profile)
    raw_expectations = profile.get("evidence_expectations")
    if not isinstance(raw_expectations, dict) or set(raw_expectations) != module_names:
        raise EvidenceFailure("evidence_expectations_invalid")
    review_required = read_module_set(
        profile, "review_required_modules", module_names
    )
    review_allowed = read_module_set(profile, "review_allowed_modules", module_names)
    if review_required & review_allowed:
        raise EvidenceFailure("evidence_result_expectations_invalid")
    expectations: dict[str, EvidenceExpectation] = {}
    for module_name, raw in raw_expectations.items():
        safe_identifier(module_name, "evidence_module_name_invalid")
        if not isinstance(raw, dict) or set(raw) != {
            "decision",
            "observation_kind",
            "minimum_observations",
        }:
            raise EvidenceFailure("evidence_expectations_invalid")
        decision = raw.get("decision")
        kind = raw.get("observation_kind")
        minimum = raw.get("minimum_observations")
        if decision not in DECISIONS or kind not in OBSERVATION_KINDS:
            raise EvidenceFailure("evidence_expectations_invalid")
        if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 1:
            raise EvidenceFailure("evidence_expectations_invalid")
        if module_name in review_required:
            allowed_results = frozenset((REVIEW_RESULT,))
        elif module_name in review_allowed:
            allowed_results = frozenset((PASSED_RESULT, REVIEW_RESULT))
        else:
            allowed_results = frozenset((PASSED_RESULT,))
        expectations[module_name] = EvidenceExpectation(
            decision, kind, minimum, allowed_results
        )
    return expectations


def read_module_set(
    profile: dict[str, Any], key: str, expected_names: set[str]
) -> set[str]:
    values = profile.get(key)
    if not isinstance(values, list):
        raise EvidenceFailure("evidence_result_expectations_invalid")
    modules: set[str] = set()
    for value in values:
        name = safe_identifier(value, "evidence_module_name_invalid")
        if name in modules or name not in expected_names:
            raise EvidenceFailure("evidence_result_expectations_invalid")
        modules.add(name)
    return modules


def expected_module_names(profile: dict[str, Any]) -> set[str]:
    groups = profile.get("expected_groups")
    if not isinstance(groups, list) or not groups:
        raise EvidenceFailure("evidence_expectations_invalid")
    names: set[str] = set()
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("modules"), list):
            raise EvidenceFailure("evidence_expectations_invalid")
        for value in group["modules"]:
            name = safe_identifier(value, "evidence_module_name_invalid")
            if name in names:
                raise EvidenceFailure("evidence_expectations_invalid")
            names.add(name)
    return names


def fetch_module_instances(
    config: CollectorConfig, expected_names: set[str]
) -> PlanEvidence:
    query = urllib.parse.urlencode(
        {
            "start": 0,
            "length": PLAN_PAGE_SIZE,
            "plan": config.plan_id,
            "from": datetime.fromtimestamp(
                config.started_after, timezone.utc
            ).isoformat(),
        }
    )
    response = api_get_json(config, f"api/plan?{query}")
    if not isinstance(response, dict) or not isinstance(response.get("data"), list):
        raise EvidenceFailure("evidence_plan_response_invalid")
    plans = []
    for item in response["data"]:
        if not isinstance(item, dict) or item.get("planName") != config.plan_id:
            continue
        item_config = item.get("config")
        started = parse_oidf_time(item.get("started"))
        if (
            isinstance(item_config, dict)
            and item_config.get("alias") == config.alias
            and started is not None
            and started >= config.started_after
        ):
            plans.append(item)
    if len(plans) != 1:
        raise EvidenceFailure("evidence_plan_not_unique")
    plan_instance_id = safe_identifier(
        plans[0].get("_id"), "evidence_plan_instance_id_invalid"
    )
    modules = plans[0].get("modules")
    if not isinstance(modules, list):
        raise EvidenceFailure("evidence_plan_response_invalid")
    instances: list[ModuleInstance] = []
    observed_names: set[str] = set()
    for module in modules:
        if not isinstance(module, dict):
            raise EvidenceFailure("evidence_plan_response_invalid")
        name = safe_identifier(module.get("testModule"), "evidence_module_name_invalid")
        raw_instances = module.get("instances")
        if name not in expected_names or not isinstance(raw_instances, list):
            raise EvidenceFailure("evidence_module_inventory_mismatch")
        if len(raw_instances) != 1:
            raise EvidenceFailure("evidence_module_instance_count_invalid")
        module_id = safe_identifier(raw_instances[0], "evidence_module_id_invalid")
        instances.append(ModuleInstance(module_id, name))
        observed_names.add(name)
    if observed_names != expected_names or len(instances) != len(expected_names):
        raise EvidenceFailure("evidence_module_inventory_mismatch")
    return PlanEvidence(plan_instance_id, tuple(instances))


def validate_finished_module(
    value: object, instance: ModuleInstance, expectation: EvidenceExpectation
) -> str:
    if not isinstance(value, dict):
        raise EvidenceFailure("evidence_module_info_invalid")
    if value.get("testName") != instance.module_name:
        raise EvidenceFailure("evidence_module_binding_mismatch")
    result = value.get("result")
    if value.get("status") != FINISHED_STATUS:
        raise EvidenceFailure("evidence_module_not_finished")
    if not isinstance(result, str) or result not in expectation.allowed_results:
        raise EvidenceFailure("evidence_module_result_invalid")
    return result


def fetch_host_evidence(
    config: CollectorConfig, instance: ModuleInstance
) -> dict[str, Any]:
    payload = canonical_json(
        {
            "plan_id": config.plan_id,
            "profile_id": config.profile_id,
            "module_id": instance.module_id,
            "module_name": instance.module_name,
        }
    )
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {config.evidence_token}",
        "Content-Type": "application/json",
    }
    request = urllib.request.Request(
        config.evidence_endpoint,
        data=payload,
        headers=headers,
        method="POST",
    )
    return read_json_response(request, config.verify_ssl, "evidence_host_request_failed")


def validate_evidence(
    evidence: dict[str, Any],
    config: CollectorConfig,
    instance: ModuleInstance,
    expectation: EvidenceExpectation,
) -> None:
    if set(evidence) != {
        "schema_version",
        "plan_id",
        "profile_id",
        "module_id",
        "module_name",
        "decision",
        "reason_code",
        "observations",
    }:
        raise EvidenceFailure("evidence_record_shape_invalid")
    if (
        evidence.get("schema_version") != 1
        or evidence.get("plan_id") != config.plan_id
        or evidence.get("profile_id") != config.profile_id
        or evidence.get("module_id") != instance.module_id
        or evidence.get("module_name") != instance.module_name
    ):
        raise EvidenceFailure("evidence_record_binding_mismatch")
    if evidence.get("decision") != expectation.decision:
        raise EvidenceFailure("evidence_record_decision_mismatch")
    validate_reason(evidence.get("reason_code"))
    observations = evidence.get("observations")
    if (
        not isinstance(observations, list)
        or not observations
        or len(observations) > MAX_OBSERVATIONS
    ):
        raise EvidenceFailure("evidence_observations_invalid")
    matching = 0
    for observation in observations:
        if not isinstance(observation, dict) or set(observation) != {
            "kind",
            "outcome",
            "reason_code",
        }:
            raise EvidenceFailure("evidence_observations_invalid")
        kind = observation.get("kind")
        outcome = observation.get("outcome")
        if kind not in OBSERVATION_KINDS or outcome not in DECISIONS:
            raise EvidenceFailure("evidence_observations_invalid")
        validate_reason(observation.get("reason_code"))
        if kind == expectation.observation_kind and outcome == expectation.decision:
            matching += 1
    if matching < expectation.minimum_observations:
        raise EvidenceFailure("evidence_required_observation_missing")


def validate_reason(value: object) -> None:
    if not isinstance(value, str) or SAFE_REASON.fullmatch(value) is None:
        raise EvidenceFailure("evidence_reason_invalid")


def api_get_json(config: CollectorConfig, relative_path: str) -> dict[str, Any]:
    base = config.conformance_server
    if not base.endswith("/"):
        base = f"{base}/"
    request = urllib.request.Request(urllib.parse.urljoin(base, relative_path), method="GET")
    request.add_header("Accept", "application/json")
    if config.conformance_api_token is not None:
        request.add_header("Authorization", f"Bearer {config.conformance_api_token}")
    return read_json_response(request, config.verify_ssl, "evidence_oidf_api_failed")


def read_json_response(
    request: urllib.request.Request, verify_ssl: bool, reason: str
) -> dict[str, Any]:
    context = None if verify_ssl else ssl._create_unverified_context()
    opener = urllib.request.build_opener(
        NoRedirectHandler(), urllib.request.HTTPSHandler(context=context)
    )
    try:
        with opener.open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    declared = int(content_length)
                except ValueError as error:
                    raise EvidenceFailure("evidence_response_size_invalid") from error
                if declared < 0 or declared > MAX_JSON_BYTES:
                    raise EvidenceFailure("evidence_response_too_large")
            raw = response.read(MAX_JSON_BYTES + 1)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as error:
        raise EvidenceFailure(reason) from error
    if len(raw) > MAX_JSON_BYTES:
        raise EvidenceFailure("evidence_response_too_large")
    value = decode_json(raw, reason)
    if not isinstance(value, dict):
        raise EvidenceFailure(reason)
    return value


def read_json_file(path: Path, reason: str) -> dict[str, Any]:
    try:
        if path.is_symlink() or path.stat().st_size > MAX_JSON_BYTES:
            raise EvidenceFailure(reason)
        raw = path.read_bytes()
    except OSError as error:
        raise EvidenceFailure(reason) from error
    value = decode_json(raw, reason)
    if not isinstance(value, dict):
        raise EvidenceFailure(reason)
    return value


def decode_json(raw: bytes, reason: str) -> object:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_non_finite_number,
        )
        ensure_bounded_json(value)
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError, EvidenceFailure) as error:
        raise EvidenceFailure(reason) from error


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceFailure("evidence_json_duplicate_member")
        result[key] = value
    return result


def reject_non_finite_number(_value: str) -> None:
    raise EvidenceFailure("evidence_json_non_finite_number")


def ensure_bounded_json(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 1)]
    visited = 0
    while stack:
        current, depth = stack.pop()
        visited += 1
        if visited > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise EvidenceFailure("evidence_json_bounds_exceeded")
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def write_private_file(path: Path, contents: bytes) -> None:
    descriptor = -1
    temporary_path = ""
    try:
        descriptor, temporary_path = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(contents)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        temporary_path = ""
    except OSError as error:
        raise EvidenceFailure("evidence_write_failed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass


def required_environment(name: str) -> str:
    value = optional_environment(name)
    if value is None:
        raise EvidenceFailure("evidence_environment_missing")
    return value


def optional_environment(name: str) -> str | None:
    value = os.environ.get(name)
    return value if value else None


def validate_control_token(value: str) -> str:
    encoded = value.encode("utf-8")
    if (
        len(encoded) < MIN_CONTROL_TOKEN_BYTES
        or len(encoded) > MAX_CONTROL_TOKEN_BYTES
        or not value.isascii()
        or not all(
            character.isprintable() and not character.isspace()
            for character in value
        )
    ):
        raise EvidenceFailure("evidence_control_token_invalid")
    return value


def read_bool_environment(name: str, default: bool) -> bool:
    value = optional_environment(name)
    if value is None:
        return default
    if value.lower() in ("1", "true", "yes"):
        return True
    if value.lower() in ("0", "false", "no"):
        return False
    raise EvidenceFailure("evidence_boolean_environment_invalid")


def safe_identifier(value: object, reason: str) -> str:
    if not isinstance(value, str) or SAFE_IDENTIFIER.fullmatch(value) is None:
        raise EvidenceFailure(reason)
    return value


def parse_oidf_time(value: object) -> float | None:
    if not isinstance(value, str):
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    match = re.match(r"^(.*?\.)(\d+)([+-]\d\d:\d\d)?$", normalized)
    if match is not None and len(match.group(2)) > 6:
        normalized = f"{match.group(1)}{match.group(2)[:6]}{match.group(3) or ''}"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def validate_https_endpoint(value: str) -> None:
    try:
        validate_oidf_runtime_endpoints.validate_endpoint(value, False)
    except validate_oidf_runtime_endpoints.EndpointFailure as error:
        raise EvidenceFailure("evidence_endpoint_invalid") from error


def validate_evidence_endpoint(value: str, development_mode: bool) -> None:
    try:
        validate_oidf_runtime_endpoints.validate_endpoint(value, development_mode)
        parsed = urllib.parse.urlsplit(value)
    except (ValueError, validate_oidf_runtime_endpoints.EndpointFailure) as error:
        raise EvidenceFailure("evidence_endpoint_invalid") from error
    if parsed.scheme == "http" and parsed.hostname not in {
        "127.0.0.1",
        "::1",
        "localhost",
    }:
        raise EvidenceFailure("evidence_endpoint_invalid")


if __name__ == "__main__":
    sys.exit(main())
