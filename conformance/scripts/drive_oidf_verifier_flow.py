#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Drive OIDF OpenID4VP verifier modules from the suite mock wallet.

The OIDF verifier plan acts as a mock wallet. Once each module reaches
WAITING it exposes an authorization endpoint; a verifier under test must start
its normal presentation request flow against that endpoint. This script is the
small CI sidecar that discovers those endpoints and triggers the verifier host
without logging Request Objects, request URIs, bearer tokens, or wallet data.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import validate_oidf_runtime_endpoints


DEFAULT_TIMEOUT_SECONDS = 7200.0
DEFAULT_POLL_SECONDS = 1.0
# These sidecars run unattended beside the suite; hostile or mistaken
# environment values must not create a busy loop or an effectively endless run.
MIN_TIMEOUT_SECONDS = 1.0
MAX_TIMEOUT_SECONDS = 24.0 * 60.0 * 60.0
MIN_POLL_SECONDS = 0.1
MAX_POLL_SECONDS = 60.0
HTTP_TIMEOUT_SECONDS = 20.0
MAX_HTTP_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 50_000
MAX_LAUNCH_PARAMETERS = 64
MAX_LAUNCH_PARAMETER_BYTES = 64 * 1024
MAX_LAUNCH_PARAMETERS_TOTAL_BYTES = 128 * 1024
MAX_EXPECTED_MODULES = 256
MIN_CONTROL_TOKEN_BYTES = 32
MAX_CONTROL_TOKEN_BYTES = 4096
PLAN_PAGE_SIZE = 200
TEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
RESULT_FILENAME = "oidf-verifier-flow-driver.json"
STATUS_WAITING = "WAITING"


@dataclass(frozen=True, repr=False)
class DriverConfig:
    conformance_server: str | None
    conformance_api_token: str | None
    conformance_verify_ssl: bool
    module_id: str | None
    plan_id: str | None
    alias: str | None
    profile_id: str | None
    expected_module_count: int | None
    started_after_epoch_seconds: float
    authorization_endpoint: str | None
    verifier_launch_endpoint: str | None
    verifier_launch_token: str | None
    client_id: str | None
    request_uri: str | None
    request_object_jwt: str | None
    request_uri_method: str | None
    authorization_http_method: str
    timeout_seconds: float
    poll_seconds: float
    result_file: str


@dataclass(frozen=True)
class PlanScope:
    plan_instance_id: str
    module_ids: tuple[str, ...]


@dataclass(frozen=True)
class DriverOutcome:
    triggered_modules: int
    plan_instance_id: str | None


class DriverFailure(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Keep authenticated control-plane requests on their configured origin."""

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
        description="Trigger OIDF OpenID4VP verifier mock-wallet flows.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate configuration and write a result without network calls",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="trigger one discovered endpoint and exit instead of watching",
    )
    args = parser.parse_args()

    config: DriverConfig | None = None
    try:
        config = read_config()
        validate_config(config)
        if args.dry_run:
            write_result(config.result_file, "dry_run", "configuration_valid", 0)
            print("OIDF verifier flow driver dry run: configuration_valid")
            return 0
        outcome = run_driver(config, args.once)
        write_result(
            config.result_file,
            "passed",
            "flow_driver_completed",
            outcome.triggered_modules,
            config.profile_id,
            outcome.plan_instance_id,
        )
        print(
            "OIDF verifier flow driver completed: "
            f"triggered={outcome.triggered_modules}"
        )
        return 0
    except DriverFailure as error:
        result_file = config.result_file if config is not None else default_result_file()
        write_result(result_file, "failed", error.reason, 0)
        print(error.reason, file=sys.stderr)
        return 2


def default_result_file() -> str:
    results_dir = os.environ.get(
        "CONFORMANCE_RESULTS_DIR", "target/conformance-results"
    )
    return os.path.join(results_dir, RESULT_FILENAME)


def read_config() -> DriverConfig:
    result_file = os.environ.get(
        "OIDF_FLOW_DRIVER_RESULT_FILE",
        default_result_file(),
    )
    return DriverConfig(
        conformance_server=empty_to_none(os.environ.get("CONFORMANCE_SERVER")),
        conformance_api_token=empty_to_none(os.environ.get("CONFORMANCE_API_TOKEN")),
        conformance_verify_ssl=read_bool_env("CONFORMANCE_VERIFY_SSL", True),
        module_id=empty_to_none(os.environ.get("OIDF_MODULE_ID")),
        plan_id=empty_to_none(os.environ.get("OIDF_PLAN_ID")),
        alias=empty_to_none(os.environ.get("OIDF_ALIAS")),
        profile_id=empty_to_none(os.environ.get("OIDF_PROFILE_ID")),
        expected_module_count=read_optional_int_env("OIDF_EXPECTED_MODULE_COUNT"),
        started_after_epoch_seconds=time.time() - 5.0,
        authorization_endpoint=empty_to_none(os.environ.get("OIDF_AUTHORIZATION_ENDPOINT")),
        verifier_launch_endpoint=empty_to_none(os.environ.get("OIDF_VERIFIER_LAUNCH_ENDPOINT")),
        verifier_launch_token=empty_to_none(os.environ.get("OIDF_VERIFIER_LAUNCH_TOKEN")),
        client_id=empty_to_none(os.environ.get("OIDF_CLIENT_ID")),
        request_uri=empty_to_none(os.environ.get("OIDF_REQUEST_URI")),
        request_object_jwt=empty_to_none(os.environ.get("OIDF_REQUEST_OBJECT_JWT")),
        request_uri_method=empty_to_none(os.environ.get("OIDF_REQUEST_URI_METHOD")),
        authorization_http_method=os.environ.get("OIDF_AUTHORIZATION_HTTP_METHOD", "GET"),
        timeout_seconds=read_float_env(
            "OIDF_FLOW_DRIVER_TIMEOUT_SECONDS",
            DEFAULT_TIMEOUT_SECONDS,
            MIN_TIMEOUT_SECONDS,
            MAX_TIMEOUT_SECONDS,
        ),
        poll_seconds=read_float_env(
            "OIDF_FLOW_DRIVER_POLL_SECONDS",
            DEFAULT_POLL_SECONDS,
            MIN_POLL_SECONDS,
            MAX_POLL_SECONDS,
        ),
        result_file=result_file,
    )


def empty_to_none(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    return value


def read_bool_env(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    normalized = value.lower()
    if normalized in ("1", "true", "yes"):
        return True
    if normalized in ("0", "false", "no"):
        return False
    raise DriverFailure("invalid_boolean_environment")


def read_float_env(name: str, default: float, minimum: float, maximum: float) -> float:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    try:
        parsed = float(value)
    except ValueError as exc:
        raise DriverFailure("invalid_numeric_environment") from exc
    if not math.isfinite(parsed) or parsed < minimum or parsed > maximum:
        raise DriverFailure("invalid_numeric_environment")
    return parsed


def read_optional_int_env(name: str) -> int | None:
    value = empty_to_none(os.environ.get(name))
    if value is None:
        return None
    try:
        parsed = int(value)
    except ValueError as exc:
        raise DriverFailure("invalid_numeric_environment") from exc
    if parsed <= 0 or parsed > MAX_EXPECTED_MODULES:
        raise DriverFailure("invalid_numeric_environment")
    return parsed


def validate_config(config: DriverConfig) -> None:
    method = config.authorization_http_method.upper()
    if method not in ("GET", "POST"):
        raise DriverFailure("invalid_authorization_http_method")
    for identifier in (config.module_id, config.plan_id, config.alias):
        if identifier is not None and TEST_ID_PATTERN.fullmatch(identifier) is None:
            raise DriverFailure("invalid_oidf_plan_scope")
    if config.request_uri is not None and config.request_object_jwt is not None:
        raise DriverFailure("conflicting_request_material")
    for material in (
        config.client_id,
        config.request_uri,
        config.request_object_jwt,
        config.request_uri_method,
    ):
        if (
            material is not None
            and len(material.encode("utf-8")) > MAX_LAUNCH_PARAMETER_BYTES
        ):
            raise DriverFailure("request_material_too_large")
    if config.verifier_launch_endpoint is None:
        if config.request_uri is None and config.request_object_jwt is None:
            raise DriverFailure("missing_verifier_launch_or_request_material")
        if config.request_uri is not None and config.client_id is None:
            raise DriverFailure("missing_client_id_for_request_uri")
    elif config.profile_id is None or TEST_ID_PATTERN.fullmatch(config.profile_id) is None:
        raise DriverFailure("missing_or_invalid_profile_id")
    else:
        validate_control_token(
            config.verifier_launch_token,
            "missing_or_invalid_verifier_launch_token",
        )
    if config.authorization_endpoint is None and config.conformance_server is None:
        raise DriverFailure("missing_authorization_endpoint_or_conformance_server")
    if (
        config.authorization_endpoint is None
        and config.module_id is None
        and (config.plan_id is None or config.alias is None)
    ):
        raise DriverFailure("missing_oidf_plan_scope")
    if config.conformance_server is not None:
        validate_http_endpoint(config.conformance_server, "invalid_conformance_server")
    if config.verifier_launch_endpoint is not None:
        validate_http_endpoint(
            config.verifier_launch_endpoint, "invalid_verifier_launch_endpoint"
        )
    if config.authorization_endpoint is not None:
        validate_http_endpoint(
            config.authorization_endpoint, "invalid_authorization_endpoint"
        )


def validate_control_token(value: str | None, reason: str) -> str:
    if value is None:
        raise DriverFailure(reason)
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
        raise DriverFailure(reason)
    return value


def run_driver(config: DriverConfig, once: bool) -> DriverOutcome:
    if config.authorization_endpoint is not None:
        trigger_endpoint(config, "manual", None, config.authorization_endpoint)
        return DriverOutcome(1, None)

    deadline = time.monotonic() + config.timeout_seconds
    triggered_modules: set[str] = set()
    plan_instance_id: str | None = None
    while time.monotonic() < deadline:
        if config.module_id is not None:
            module_ids = (config.module_id,)
        else:
            scope = fetch_scoped_plan(config)
            if scope is None:
                time.sleep(config.poll_seconds)
                continue
            if plan_instance_id is None:
                plan_instance_id = scope.plan_instance_id
            elif plan_instance_id != scope.plan_instance_id:
                raise DriverFailure("oidf_plan_instance_changed")
            module_ids = scope.module_ids
        triggered_this_poll = trigger_waiting_modules(
            config, triggered_modules, module_ids
        )
        if triggered_this_poll > 0:
            write_result(
                config.result_file,
                "running",
                "flow_driver_active",
                len(triggered_modules),
                config.profile_id,
                plan_instance_id,
            )
        if once and triggered_this_poll > 0:
            return DriverOutcome(len(triggered_modules), plan_instance_id)
        if (
            config.expected_module_count is not None
            and len(triggered_modules) >= config.expected_module_count
        ):
            if len(triggered_modules) > config.expected_module_count:
                raise DriverFailure("triggered_module_count_exceeded")
            return DriverOutcome(len(triggered_modules), plan_instance_id)
        time.sleep(config.poll_seconds)
    if len(triggered_modules) == 0:
        raise DriverFailure("no_waiting_oidf_verifier_module")
    return DriverOutcome(len(triggered_modules), plan_instance_id)


def trigger_waiting_modules(
    config: DriverConfig,
    triggered_modules: set[str],
    scoped_module_ids: tuple[str, ...] | None = None,
) -> int:
    module_ids = (
        [config.module_id]
        if config.module_id is not None
        else list(scoped_module_ids or ())
    )
    triggered = 0
    for module_id in module_ids:
        if module_id in triggered_modules:
            continue
        info = fetch_module_info(config, module_id)
        if info.get("status") != STATUS_WAITING:
            continue
        runner_status = fetch_runner_status(config, module_id)
        endpoint = exposed_authorization_endpoint(runner_status)
        if endpoint is None:
            continue
        module_name = safe_test_identifier(
            info.get("testName"), "invalid_oidf_module_name"
        )
        trigger_endpoint(config, module_id, module_name, endpoint)
        triggered_modules.add(module_id)
        triggered += 1
    return triggered


def fetch_scoped_module_ids(config: DriverConfig) -> list[str]:
    scope = fetch_scoped_plan(config)
    return [] if scope is None else list(scope.module_ids)


def fetch_scoped_plan(config: DriverConfig) -> PlanScope | None:
    plan_id = require_value(config.plan_id, "missing_oidf_plan_scope")
    query = urllib.parse.urlencode(
        {
            "start": 0,
            "length": PLAN_PAGE_SIZE,
            "plan": plan_id,
            "from": datetime.fromtimestamp(
                config.started_after_epoch_seconds,
                timezone.utc,
            ).isoformat(),
        }
    )
    data = api_get_json(config, f"api/plan?{query}")
    if not isinstance(data, dict) or not isinstance(data.get("data"), list):
        raise DriverFailure("invalid_oidf_plan_response")
    plans = []
    for item in data["data"]:
        if not isinstance(item, dict) or item.get("planName") != config.plan_id:
            continue
        started = parse_oidf_time(item.get("started"))
        if started is None or started < config.started_after_epoch_seconds:
            continue
        item_config = item.get("config")
        if not isinstance(item_config, dict) or item_config.get("alias") != config.alias:
            continue
        plans.append(item)
    if not plans:
        return None
    if len(plans) != 1:
        raise DriverFailure("oidf_plan_not_unique")
    plan_instance_id = safe_test_identifier(
        plans[0].get("_id"), "invalid_oidf_plan_instance_id"
    )
    module_ids: list[str] = []
    modules = plans[0].get("modules")
    if not isinstance(modules, list):
        raise DriverFailure("invalid_oidf_plan_response")
    for module in modules:
        if not isinstance(module, dict) or not isinstance(module.get("instances"), list):
            continue
        for item in module["instances"]:
            if isinstance(item, str) and TEST_ID_PATTERN.fullmatch(item) is not None:
                module_ids.append(item)
    return PlanScope(plan_instance_id, tuple(module_ids))


def parse_oidf_time(value: Any) -> float | None:
    if not isinstance(value, str):
        return None
    normalized = normalize_iso8601_fraction(value)
    normalized = normalized[:-1] + "+00:00" if normalized.endswith("Z") else normalized
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def normalize_iso8601_fraction(value: str) -> str:
    match = re.match(r"^(.*?\.)(\d+)(Z|[+-]\d\d:\d\d)?$", value)
    if match is None or len(match.group(2)) <= 6:
        return value
    return f"{match.group(1)}{match.group(2)[:6]}{match.group(3) or ''}"


def fetch_module_info(config: DriverConfig, module_id: str) -> dict[str, Any]:
    data = api_get_json(config, f"api/info/{quote_path_segment(module_id)}")
    if not isinstance(data, dict):
        raise DriverFailure("invalid_oidf_info_response")
    return data


def fetch_runner_status(config: DriverConfig, module_id: str) -> dict[str, Any]:
    data = api_get_json(config, f"api/runner/{quote_path_segment(module_id)}")
    if not isinstance(data, dict):
        raise DriverFailure("invalid_oidf_runner_response")
    return data


def exposed_authorization_endpoint(status: dict[str, Any]) -> str | None:
    exposed = status.get("exposed")
    if not isinstance(exposed, dict):
        return None
    return string_value(exposed.get("authorization_endpoint"))


def trigger_endpoint(
    config: DriverConfig,
    module_id: str,
    module_name: str | None,
    authorization_endpoint: str,
) -> None:
    validate_http_endpoint(authorization_endpoint, "invalid_authorization_endpoint")
    if config.verifier_launch_endpoint is not None:
        launch_verifier_host(
            config,
            module_id,
            require_value(module_name, "missing_oidf_module_name"),
            authorization_endpoint,
        )
    else:
        call_authorization_endpoint(config, authorization_endpoint)


def launch_verifier_host(
    config: DriverConfig,
    module_id: str,
    module_name: str,
    authorization_endpoint: str,
) -> None:
    payload = {
        "authorization_endpoint": authorization_endpoint,
        "module_id": module_id,
        "module_name": module_name,
        "plan_id": require_value(config.plan_id, "missing_oidf_plan_scope"),
        "profile_id": require_value(config.profile_id, "missing_or_invalid_profile_id"),
    }
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    launch_token = validate_control_token(
        config.verifier_launch_token,
        "missing_or_invalid_verifier_launch_token",
    )
    headers = {
        "Authorization": f"Bearer {launch_token}",
        "Content-Type": "application/json",
    }
    request = urllib.request.Request(
        config.verifier_launch_endpoint,
        data=body,
        headers=headers,
        method="POST",
    )
    response_body = open_request(request, config.conformance_verify_ssl, "verifier_launch_failed")
    if len(response_body) == 0:
        return
    launch = parse_verifier_launch_response(response_body)
    if launch["authorization_endpoint"] != authorization_endpoint:
        raise DriverFailure("verifier_launch_authorization_endpoint_mismatch")
    method = launch.get("method") or config.authorization_http_method
    call_authorization_endpoint_with_params(
        config,
        launch["authorization_endpoint"],
        launch["parameters"],
        method,
    )


def call_authorization_endpoint(config: DriverConfig, authorization_endpoint: str) -> None:
    params = authorization_endpoint_params(config)
    call_authorization_endpoint_with_params(
        config,
        authorization_endpoint,
        params,
        config.authorization_http_method,
    )


def call_authorization_endpoint_with_params(
    config: DriverConfig,
    authorization_endpoint: str,
    params: dict[str, str],
    authorization_http_method: str,
) -> None:
    method = authorization_http_method.upper()
    if method not in ("GET", "POST"):
        raise DriverFailure("invalid_authorization_http_method")
    if method == "POST":
        body = urllib.parse.urlencode(params).encode("utf-8")
        request = urllib.request.Request(
            authorization_endpoint,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
    else:
        separator = "&" if "?" in authorization_endpoint else "?"
        target = f"{authorization_endpoint}{separator}{urllib.parse.urlencode(params)}"
        request = urllib.request.Request(target, method="GET")
    # This driver is a browser surrogate only until the suite has consumed the
    # authorization request.  A redirect after that point is the terminal
    # browser handoff (normally the verifier's post-response completion page),
    # not another control-plane request.  Refusing to follow it avoids turning
    # a suite-controlled Location header into an SSRF primitive.
    open_request(
        request,
        config.conformance_verify_ssl,
        "authorization_endpoint_call_failed",
        accept_redirect_response=True,
    )


def parse_verifier_launch_response(body: bytes) -> dict[str, Any]:
    parsed = decode_json(body, "verifier_launch_invalid_json")
    if not isinstance(parsed, dict):
        raise DriverFailure("verifier_launch_invalid_json")
    endpoint = string_value(parsed.get("authorization_endpoint"))
    if endpoint is None:
        raise DriverFailure("verifier_launch_missing_authorization_endpoint")
    parameters = parse_verifier_launch_parameters(parsed.get("parameters"))
    launch: dict[str, Any] = {
        "authorization_endpoint": endpoint,
        "parameters": parameters,
    }
    method = string_value(parsed.get("method"))
    if method is not None:
        launch["method"] = method
    return launch


def parse_verifier_launch_parameters(value: Any) -> dict[str, str]:
    if not isinstance(value, list):
        raise DriverFailure("verifier_launch_invalid_parameters")
    if len(value) > MAX_LAUNCH_PARAMETERS:
        raise DriverFailure("verifier_launch_invalid_parameters")
    parameters: dict[str, str] = {}
    total_bytes = 0
    for item in value:
        if not isinstance(item, dict):
            raise DriverFailure("verifier_launch_invalid_parameters")
        name = string_value(item.get("name"))
        parameter_value = string_value(item.get("value"))
        if name is None or parameter_value is None:
            raise DriverFailure("verifier_launch_invalid_parameters")
        name_bytes = len(name.encode("utf-8"))
        value_bytes = len(parameter_value.encode("utf-8"))
        if (
            name_bytes > MAX_LAUNCH_PARAMETER_BYTES
            or value_bytes > MAX_LAUNCH_PARAMETER_BYTES
        ):
            raise DriverFailure("verifier_launch_invalid_parameters")
        total_bytes += name_bytes + value_bytes
        if total_bytes > MAX_LAUNCH_PARAMETERS_TOTAL_BYTES:
            raise DriverFailure("verifier_launch_invalid_parameters")
        if name in parameters:
            raise DriverFailure("verifier_launch_duplicate_parameter")
        parameters[name] = parameter_value
    if "request" not in parameters and "request_uri" not in parameters:
        raise DriverFailure("verifier_launch_missing_request_material")
    return parameters


def authorization_endpoint_params(config: DriverConfig) -> dict[str, str]:
    if config.request_uri is not None:
        params = {
            "client_id": require_value(config.client_id, "missing_client_id_for_request_uri"),
            "request_uri": config.request_uri,
        }
        if config.request_uri_method is not None:
            params["request_uri_method"] = config.request_uri_method
        return params
    return {"request": require_value(config.request_object_jwt, "missing_request_object_jwt")}


def require_value(value: str | None, reason: str) -> str:
    if value is None:
        raise DriverFailure(reason)
    return value


def api_get_json(config: DriverConfig, relative_path: str) -> Any:
    server = require_value(config.conformance_server, "missing_conformance_server")
    base = server if server.endswith("/") else f"{server}/"
    request = urllib.request.Request(urllib.parse.urljoin(base, relative_path), method="GET")
    request.add_header("Accept", "application/json")
    if config.conformance_api_token is not None:
        request.add_header("Authorization", f"Bearer {config.conformance_api_token}")
    body = open_request(request, config.conformance_verify_ssl, "oidf_api_request_failed")
    return decode_json(body, "oidf_api_invalid_json")


def decode_json(raw: bytes, reason: str) -> Any:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate_members,
            parse_constant=reject_non_finite_number,
        )
        ensure_bounded_json(value)
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError, DriverFailure) as exc:
        raise DriverFailure(reason) from exc


def reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DriverFailure("json_duplicate_member")
        result[key] = value
    return result


def reject_non_finite_number(_value: str) -> None:
    raise DriverFailure("json_non_finite_number")


def ensure_bounded_json(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    visited = 0
    while stack:
        current, depth = stack.pop()
        visited += 1
        if visited > MAX_JSON_NODES:
            raise DriverFailure("json_node_limit_exceeded")
        if depth > MAX_JSON_DEPTH:
            raise DriverFailure("json_nesting_exceeded")
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)


def open_request(
    request: urllib.request.Request,
    verify_ssl: bool,
    reason: str,
    *,
    accept_redirect_response: bool = False,
) -> bytes:
    context = None if verify_ssl else ssl._create_unverified_context()
    opener = urllib.request.build_opener(
        NoRedirectHandler(), urllib.request.HTTPSHandler(context=context)
    )
    try:
        with opener.open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            status = response.getcode()
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    declared_length = int(content_length)
                except ValueError as exc:
                    raise DriverFailure("http_response_size_invalid") from exc
                if declared_length < 0 or declared_length > MAX_HTTP_RESPONSE_BYTES:
                    raise DriverFailure("http_response_too_large")
            body = response.read(MAX_HTTP_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        accepted_redirect = 300 <= exc.code < 400 and accept_redirect_response
        exc.close()
        if accepted_redirect:
            return b""
        raise DriverFailure(reason) from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise DriverFailure(reason) from exc
    if status < 200 or status >= 400:
        raise DriverFailure(reason)
    if len(body) > MAX_HTTP_RESPONSE_BYTES:
        raise DriverFailure("http_response_too_large")
    return body


def validate_http_endpoint(value: str, reason: str) -> None:
    allow_http = read_bool_env("CONFORMANCE_DEV_MODE", False)
    try:
        validate_oidf_runtime_endpoints.validate_endpoint(value, allow_http)
    except validate_oidf_runtime_endpoints.EndpointFailure as exc:
        raise DriverFailure(reason) from exc


def quote_path_segment(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def string_value(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    return None


def safe_test_identifier(value: Any, reason: str) -> str:
    parsed = string_value(value)
    if parsed is None or TEST_ID_PATTERN.fullmatch(parsed) is None:
        raise DriverFailure(reason)
    return parsed


def write_result(
    path: str,
    status: str,
    reason: str,
    triggered: int,
    profile_id: str | None = None,
    plan_instance_id: str | None = None,
) -> None:
    directory = os.path.dirname(path)
    if directory != "":
        os.makedirs(directory, exist_ok=True)
    result = {
        "status": status,
        "reason": reason,
        "triggered_modules": triggered,
    }
    if profile_id is not None:
        result["profile_id"] = profile_id
    if plan_instance_id is not None:
        result["plan_instance_id"] = plan_instance_id
    temporary_directory = directory if directory != "" else "."
    descriptor = -1
    temporary_path = ""
    try:
        descriptor, temporary_path = tempfile.mkstemp(
            dir=temporary_directory,
            prefix=".oidf-verifier-flow-driver.",
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            json.dump(result, handle, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        temporary_path = ""
    except OSError as exc:
        raise DriverFailure("result_write_failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path != "":
            try:
                os.unlink(temporary_path)
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
