#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Drive OIDF OpenID4VP wallet modules into the ReallyMe wallet harness.

The OIDF wallet plan acts as a verifier. Once a module reaches WAITING, the
suite publishes either an authorization request URL or a structured Digital
Credentials API request. This sidecar discovers that launch material and
forwards it to the injected wallet harness. The harness remains
responsible for parsing and recording the wallet launch; credential inventory,
consent, and presentation generation stay in reallyme/wallet.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import signal
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import oidf_wallet_error_evidence
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
MAX_BROWSER_API_REQUESTS = 16
MAX_JWS_SIGNATURES = 16
MAX_EXPECTED_MODULES = 512
MAX_BROWSER_HANDOFF_URI_BYTES = 8 * 1024
MAX_HARNESS_SESSION_ID = (1 << 64) - 1
# The OIDF verifier observes the callback asynchronously and allows 30 seconds.
# Keep the browser alive long enough for cold Chromium startup and local TLS
# negotiation while preserving headroom for the suite to record the callback.
HANDOFF_BROWSER_NAVIGATION_SECONDS = 20.0
HANDOFF_BROWSER_EXIT_SECONDS = 5.0
MIN_CONTROL_TOKEN_BYTES = 32
MAX_CONTROL_TOKEN_BYTES = 4096
PLAN_PAGE_SIZE = 200
TEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
RESULT_FILENAME = "oidf-wallet-flow-driver.json"
STATUS_WAITING = "WAITING"
SUPPORTED_BROWSER_PROTOCOLS = frozenset(
    {
        "openid4vp-v1-unsigned",
        "openid4vp-v1-signed",
        "openid4vp-v1-multisigned",
    }
)


@dataclass(frozen=True, repr=False)
class DriverConfig:
    conformance_server: str | None
    conformance_api_token: str | None
    conformance_verify_ssl: bool
    module_id: str | None
    plan_id: str | None
    alias: str | None
    profile_id: str | None
    credential_format: str | None
    response_mode: str | None
    expected_module_count: int | None
    started_after_epoch_seconds: float
    wallet_harness_endpoint: str | None
    wallet_error_screen_endpoint: str | None
    wallet_harness_token: str | None
    wallet_harness_method: str
    wallet_screenshot_browser: str | None
    timeout_seconds: float
    poll_seconds: float
    result_file: str


class WalletLaunchKind(Enum):
    AUTHORIZATION_REQUEST = "authorization_request"
    BROWSER_API = "browser_api"


@dataclass(frozen=True, repr=False)
class WalletLaunch:
    kind: WalletLaunchKind
    authorization_request: str | None = None
    browser_api_request: dict[str, Any] | None = None
    submit_url: str | None = None


@dataclass(frozen=True)
class PlanScope:
    plan_instance_id: str
    module_ids: tuple[str, ...]


@dataclass(frozen=True)
class DriverOutcome:
    triggered_modules: int
    plan_instance_id: str


class DriverFailure(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.triggered_modules = 0
        self.plan_instance_id: str | None = None

    def retain_progress(
        self,
        triggered_modules: int,
        plan_instance_id: str | None,
    ) -> None:
        """Attach only non-sensitive progress already proven by this run."""
        if triggered_modules > self.triggered_modules:
            self.triggered_modules = triggered_modules
        if self.plan_instance_id is None:
            self.plan_instance_id = plan_instance_id


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
        description="Trigger OIDF OpenID4VP wallet harness flows.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate configuration and write a result without network calls",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="trigger one discovered wallet launch and exit instead of watching",
    )
    args = parser.parse_args()

    config: DriverConfig | None = None
    try:
        config = read_config()
        validate_config(config)
        if args.dry_run:
            write_result(config.result_file, "dry_run", "configuration_valid", 0)
            print("OIDF wallet flow driver dry run: configuration_valid")
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
            "OIDF wallet flow driver completed: "
            f"triggered={outcome.triggered_modules}"
        )
        return 0
    except DriverFailure as error:
        result_file = config.result_file if config is not None else default_result_file()
        write_result(
            result_file,
            "failed",
            error.reason,
            error.triggered_modules,
            config.profile_id if config is not None else None,
            error.plan_instance_id,
        )
        print(error.reason, file=sys.stderr)
        return 2


def default_result_file() -> str:
    results_dir = os.environ.get(
        "CONFORMANCE_RESULTS_DIR", "target/conformance-results"
    )
    return os.path.join(results_dir, RESULT_FILENAME)


def read_config() -> DriverConfig:
    result_file = os.environ.get(
        "OIDF_WALLET_FLOW_DRIVER_RESULT_FILE",
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
        credential_format=empty_to_none(
            os.environ.get("OIDF_PROFILE_CREDENTIAL_FORMAT")
        ),
        response_mode=empty_to_none(os.environ.get("OIDF_PROFILE_RESPONSE_MODE")),
        expected_module_count=read_optional_int_env(
            "OIDF_EXPECTED_MODULE_COUNT", 1, MAX_EXPECTED_MODULES
        ),
        started_after_epoch_seconds=time.time() - 5.0,
        wallet_harness_endpoint=empty_to_none(os.environ.get("OIDF_WALLET_HARNESS_ENDPOINT")),
        wallet_error_screen_endpoint=empty_to_none(
            os.environ.get("OIDF_WALLET_ERROR_SCREEN_ENDPOINT")
        ),
        wallet_harness_token=empty_to_none(os.environ.get("OIDF_WALLET_HARNESS_TOKEN")),
        wallet_harness_method=os.environ.get("OIDF_WALLET_HARNESS_METHOD", "POST"),
        wallet_screenshot_browser=empty_to_none(
            os.environ.get("OIDF_WALLET_SCREENSHOT_BROWSER")
        ),
        timeout_seconds=read_float_env(
            "OIDF_WALLET_FLOW_DRIVER_TIMEOUT_SECONDS",
            DEFAULT_TIMEOUT_SECONDS,
            MIN_TIMEOUT_SECONDS,
            MAX_TIMEOUT_SECONDS,
        ),
        poll_seconds=read_float_env(
            "OIDF_WALLET_FLOW_DRIVER_POLL_SECONDS",
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


def read_optional_int_env(name: str, minimum: int, maximum: int) -> int | None:
    value = os.environ.get(name)
    if value is None or value == "":
        return None
    if not value.isascii() or not value.isdecimal():
        raise DriverFailure("invalid_integer_environment")
    parsed = int(value)
    if parsed < minimum or parsed > maximum:
        raise DriverFailure("invalid_integer_environment")
    return parsed


def validate_config(config: DriverConfig) -> None:
    if config.conformance_server is None:
        raise DriverFailure("missing_conformance_server")
    if config.wallet_harness_endpoint is None:
        raise DriverFailure("missing_wallet_harness_endpoint")
    if config.module_id is None and (config.plan_id is None or config.alias is None):
        raise DriverFailure("missing_oidf_plan_scope")
    for identifier in (config.module_id, config.plan_id, config.alias, config.profile_id):
        if identifier is not None and TEST_ID_PATTERN.fullmatch(identifier) is None:
            raise DriverFailure("invalid_oidf_plan_scope")
    if config.module_id is None:
        if (
            config.profile_id is None
            or config.credential_format not in {"sd_jwt_vc", "iso_mdl"}
            or config.response_mode not in {"direct_post.jwt", "dc_api.jwt"}
            or config.expected_module_count is None
        ):
            raise DriverFailure("missing_oidf_profile_scope")
    method = config.wallet_harness_method.upper()
    if method not in ("GET", "POST"):
        raise DriverFailure("invalid_wallet_harness_method")
    validate_http_endpoint(config.conformance_server, "invalid_conformance_server")
    validate_http_endpoint(
        config.wallet_harness_endpoint, "invalid_wallet_harness_endpoint"
    )
    if config.wallet_error_screen_endpoint is None:
        raise DriverFailure("missing_wallet_error_screen_endpoint")
    validate_http_endpoint(
        config.wallet_error_screen_endpoint, "invalid_wallet_error_screen_endpoint"
    )
    validate_control_token(config.wallet_harness_token)
    validate_screenshot_browser(config.wallet_screenshot_browser)


def validate_control_token(value: str | None) -> str:
    if value is None:
        raise DriverFailure("missing_or_invalid_wallet_harness_token")
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
        raise DriverFailure("missing_or_invalid_wallet_harness_token")
    return value


def validate_screenshot_browser(value: str | None) -> str:
    if value is None:
        raise DriverFailure("missing_or_invalid_wallet_screenshot_browser")
    try:
        oidf_wallet_error_evidence.validate_screenshot_browser(value)
    except oidf_wallet_error_evidence.EvidenceFailure as exc:
        raise DriverFailure(exc.reason) from exc
    return value


def run_driver(config: DriverConfig, once: bool) -> DriverOutcome:
    deadline = time.monotonic() + config.timeout_seconds
    triggered_modules: set[str] = set()
    plan_instance_id: str | None = None
    try:
        while time.monotonic() < deadline:
            scope = fetch_scoped_plan(config) if config.module_id is None else None
            if scope is not None:
                if plan_instance_id is None:
                    plan_instance_id = scope.plan_instance_id
                elif plan_instance_id != scope.plan_instance_id:
                    raise DriverFailure("oidf_plan_instance_changed")
            triggered_this_poll = trigger_waiting_modules(config, triggered_modules, scope)
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
                return DriverOutcome(
                    len(triggered_modules),
                    require_value(plan_instance_id, "oidf_plan_instance_missing"),
                )
            if (
                config.expected_module_count is not None
                and len(triggered_modules) == config.expected_module_count
            ):
                return DriverOutcome(
                    len(triggered_modules),
                    require_value(plan_instance_id, "oidf_plan_instance_missing"),
                )
            if (
                config.expected_module_count is not None
                and len(triggered_modules) > config.expected_module_count
            ):
                raise DriverFailure("oidf_wallet_module_count_exceeded")
            time.sleep(config.poll_seconds)
        if len(triggered_modules) == 0:
            raise DriverFailure("no_waiting_oidf_wallet_module")
        if config.expected_module_count is not None:
            raise DriverFailure("oidf_wallet_module_count_incomplete")
        return DriverOutcome(
            len(triggered_modules),
            require_value(plan_instance_id, "oidf_plan_instance_missing"),
        )
    except DriverFailure as error:
        error.retain_progress(len(triggered_modules), plan_instance_id)
        raise


def trigger_waiting_modules(
    config: DriverConfig,
    triggered_modules: set[str],
    scope: PlanScope | None = None,
) -> int:
    module_ids = (
        [config.module_id]
        if config.module_id is not None
        else list(scope.module_ids if scope is not None else ())
    )
    triggered = 0
    for module_id in module_ids:
        if module_id in triggered_modules:
            continue
        info = fetch_module_info(config, module_id)
        if info.get("status") != STATUS_WAITING:
            continue
        module_name = string_value(info.get("testName"))
        runner_status = fetch_runner_status(config, module_id)
        launch = wallet_launch(runner_status)
        if launch is None:
            continue
        call_wallet_harness(
            config,
            launch,
            module_id,
            is_expected_rejection_module(module_name),
        )
        triggered_modules.add(module_id)
        triggered += 1
    return triggered


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
        variant = plan_variants(item)
        if (
            variant.get("credential_format") != config.credential_format
            or variant.get("response_mode") != config.response_mode
        ):
            continue
        plans.append(item)
    if not plans:
        return None
    if len(plans) != 1:
        raise DriverFailure("oidf_plan_not_unique")
    plan_instance_id = string_value(plans[0].get("_id"))
    if plan_instance_id is None or TEST_ID_PATTERN.fullmatch(plan_instance_id) is None:
        raise DriverFailure("invalid_oidf_plan_response")
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


def plan_variants(item: dict[str, Any]) -> dict[str, Any]:
    variant = item.get("variant")
    if not isinstance(variant, dict):
        raise DriverFailure("invalid_oidf_plan_response")
    nested = variant.get("variant")
    if nested is not None:
        if set(variant) != {"variant"} or not isinstance(nested, dict):
            raise DriverFailure("invalid_oidf_plan_response")
        variant = nested
    return variant


def fetch_scoped_module_ids(config: DriverConfig) -> list[str]:
    scope = fetch_scoped_plan(config)
    return list(scope.module_ids) if scope is not None else []


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


def is_expected_rejection_module(module_name: str | None) -> bool:
    return module_name is not None and "-negative-test-" in module_name


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


def wallet_launch(status: dict[str, Any]) -> WalletLaunch | None:
    browser = status.get("browser")
    if not isinstance(browser, dict):
        return None
    browser_api_requests = browser.get("browserApiRequests")
    if browser_api_requests is not None:
        if not isinstance(browser_api_requests, list):
            raise DriverFailure("invalid_oidf_browser_api_request")
        for item in reversed(browser_api_requests):
            if not isinstance(item, dict):
                raise DriverFailure("invalid_oidf_browser_api_request")
            request = item.get("request")
            submit_url = string_value(item.get("submitUrl"))
            if not isinstance(request, dict) or submit_url is None:
                raise DriverFailure("invalid_oidf_browser_api_request")
            validate_browser_api_request(request)
            validate_http_endpoint(submit_url, "invalid_oidf_browser_api_submit_url")
            return WalletLaunch(
                kind=WalletLaunchKind.BROWSER_API,
                browser_api_request=request,
                submit_url=submit_url,
            )
    for key in ("visited", "urls"):
        value = last_string(browser.get(key))
        if value is not None:
            query = urllib.parse.urlsplit(value).query
            if query != "":
                return WalletLaunch(
                    kind=WalletLaunchKind.AUTHORIZATION_REQUEST,
                    authorization_request=query,
                )
    return None


def validate_browser_api_request(request: dict[str, Any]) -> None:
    digital = request.get("digital")
    if not isinstance(digital, dict):
        raise DriverFailure("invalid_oidf_browser_api_request")
    requests = digital.get("requests")
    if (
        not isinstance(requests, list)
        or not requests
        or len(requests) > MAX_BROWSER_API_REQUESTS
    ):
        raise DriverFailure("invalid_oidf_browser_api_request")
    for entry in requests:
        if not isinstance(entry, dict):
            raise DriverFailure("invalid_oidf_browser_api_request")
        protocol = string_value(entry.get("protocol"))
        data = entry.get("data")
        if protocol not in SUPPORTED_BROWSER_PROTOCOLS or not isinstance(data, dict):
            raise DriverFailure("invalid_oidf_browser_api_request")
        if protocol == "openid4vp-v1-signed":
            if string_value(data.get("request")) in (None, ""):
                raise DriverFailure("invalid_oidf_browser_api_request")
        elif protocol == "openid4vp-v1-multisigned":
            validate_general_jws(data.get("request"))


def validate_general_jws(value: Any) -> None:
    if not isinstance(value, dict):
        raise DriverFailure("invalid_oidf_browser_api_request")
    if string_value(value.get("payload")) in (None, ""):
        raise DriverFailure("invalid_oidf_browser_api_request")
    signatures = value.get("signatures")
    if (
        not isinstance(signatures, list)
        or not signatures
        or len(signatures) > MAX_JWS_SIGNATURES
    ):
        raise DriverFailure("invalid_oidf_browser_api_request")
    for signature in signatures:
        if not isinstance(signature, dict):
            raise DriverFailure("invalid_oidf_browser_api_request")
        if string_value(signature.get("protected")) in (None, ""):
            raise DriverFailure("invalid_oidf_browser_api_request")
        if string_value(signature.get("signature")) in (None, ""):
            raise DriverFailure("invalid_oidf_browser_api_request")


def validate_http_endpoint(value: str, reason: str) -> None:
    allow_http = read_bool_env("CONFORMANCE_DEV_MODE", False)
    try:
        validate_oidf_runtime_endpoints.validate_endpoint(value, allow_http)
    except validate_oidf_runtime_endpoints.EndpointFailure as exc:
        raise DriverFailure(reason) from exc


def last_string(value: Any) -> str | None:
    if not isinstance(value, list):
        return None
    for item in reversed(value):
        parsed = string_value(item)
        if parsed is not None and parsed != "":
            return parsed
    return None


def call_wallet_harness(
    config: DriverConfig,
    launch: WalletLaunch,
    module_id: str | None = None,
    expected_rejection: bool = False,
) -> None:
    endpoint = require_value(config.wallet_harness_endpoint, "missing_wallet_harness_endpoint")
    method = config.wallet_harness_method.upper()
    headers = wallet_harness_headers(config.wallet_harness_token)
    if launch.kind is WalletLaunchKind.BROWSER_API:
        if method != "POST":
            raise DriverFailure("browser_api_requires_post_harness")
        request_payload = launch.browser_api_request
        submit_url = launch.submit_url
        if request_payload is None or submit_url is None:
            raise DriverFailure("invalid_oidf_browser_api_request")
        body = json.dumps(
            {
                "browser_api_request": request_payload,
                "submit_url": submit_url,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        request = urllib.request.Request(
            endpoint,
            data=body,
            headers={**headers, "Content-Type": "application/json"},
            method="POST",
        )
        response = open_request(
            request,
            config.conformance_verify_ssl,
            "wallet_harness_call_failed",
            frozenset({400}) if expected_rejection else frozenset(),
        )
        complete_expected_rejection(config, launch, module_id, expected_rejection, response)
        return

    authorization_request = launch.authorization_request
    if authorization_request is None:
        raise DriverFailure("invalid_oidf_authorization_request")
    if method == "POST":
        body = json.dumps(
            {"authorization_request": authorization_request},
            separators=(",", ":"),
        ).encode("utf-8")
        request = urllib.request.Request(
            endpoint,
            data=body,
            headers={**headers, "Content-Type": "application/json"},
            method="POST",
        )
    else:
        separator = "&" if "?" in endpoint else "?"
        request = urllib.request.Request(
            f"{endpoint}{separator}{authorization_request}",
            headers=headers,
            method="GET",
        )
    response = open_request(
        request,
        config.conformance_verify_ssl,
        "wallet_harness_call_failed",
        frozenset({400}) if expected_rejection else frozenset(),
    )
    complete_expected_rejection(config, launch, module_id, expected_rejection, response)


def complete_expected_rejection(
    config: DriverConfig,
    launch: WalletLaunch,
    module_id: str | None,
    expected_rejection: bool,
    response: bytes | None,
) -> None:
    if not expected_rejection:
        if response is None:
            raise DriverFailure("wallet_harness_unexpected_rejection")
        redirect_uri = parse_wallet_harness_response(response, config)
        if redirect_uri is not None:
            open_browser_handoff(config, redirect_uri)
        return
    if response is not None:
        raise DriverFailure("wallet_harness_rejection_missing")
    test_id = require_value(module_id, "missing_oidf_module_scope")
    if launch.kind is WalletLaunchKind.BROWSER_API:
        submit_browser_api_rejection(config, launch)
    upload_error_screen(config, test_id)


def parse_wallet_harness_response(
    response: bytes,
    config: DriverConfig,
) -> str | None:
    payload = decode_json(response, "wallet_harness_invalid_response")
    if not isinstance(payload, dict) or set(payload) != {
        "session_id",
        "status",
        "transport",
        "flow",
    }:
        raise DriverFailure("wallet_harness_invalid_response")
    session_id = payload.get("session_id")
    if (
        not isinstance(session_id, int)
        or isinstance(session_id, bool)
        or session_id < 0
        or session_id > MAX_HARNESS_SESSION_ID
        or payload.get("status") != "completed"
        or not isinstance(payload.get("transport"), dict)
    ):
        raise DriverFailure("wallet_harness_invalid_response")
    flow = payload.get("flow")
    if not isinstance(flow, dict) or not set(flow).issubset({"status", "redirect_uri"}):
        raise DriverFailure("wallet_harness_invalid_response")
    flow_status = flow.get("status")
    if flow_status not in {"direct_post_jwt_submitted", "dc_api_jwt_submitted"}:
        raise DriverFailure("wallet_harness_invalid_response")
    redirect_uri = flow.get("redirect_uri")
    if redirect_uri is None:
        return None
    if flow_status != "direct_post_jwt_submitted" or not isinstance(redirect_uri, str):
        raise DriverFailure("wallet_harness_invalid_response")
    validate_browser_handoff_uri(redirect_uri, config)
    return redirect_uri


def validate_browser_handoff_uri(uri: str, config: DriverConfig) -> None:
    if uri == "" or len(uri.encode("utf-8")) > MAX_BROWSER_HANDOFF_URI_BYTES:
        raise DriverFailure("invalid_wallet_browser_handoff")
    try:
        parsed = urllib.parse.urlsplit(uri)
        conformance = urllib.parse.urlsplit(
            require_value(config.conformance_server, "missing_conformance_server")
        )
        port = parsed.port
        conformance_port = conformance.port
    except ValueError as exc:
        raise DriverFailure("invalid_wallet_browser_handoff") from exc
    if (
        parsed.scheme.lower() != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or conformance.hostname is None
    ):
        raise DriverFailure("invalid_wallet_browser_handoff")
    effective_port = 443 if port is None else port
    effective_conformance_port = 443 if conformance_port is None else conformance_port
    if (
        parsed.hostname.lower() != conformance.hostname.lower()
        or effective_port != effective_conformance_port
    ):
        raise DriverFailure("invalid_wallet_browser_handoff")


def open_browser_handoff(config: DriverConfig, redirect_uri: str) -> None:
    browser = validate_screenshot_browser(config.wallet_screenshot_browser)
    validate_browser_handoff_uri(redirect_uri, config)
    with tempfile.TemporaryDirectory(prefix="reallyme-wallet-handoff-") as directory:
        profile_path = os.path.join(directory, "browser-profile")
        arguments = [
            browser,
            "--headless=new",
            "--disable-background-networking",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            f"--user-data-dir={profile_path}",
            "--dump-dom",
        ]
        if not config.conformance_verify_ssl:
            # Local pre-submission suites use an ephemeral development CA. This
            # exception is never enabled for certification runs that verify TLS.
            arguments.append("--ignore-certificate-errors")
        arguments.append(redirect_uri)
        process: subprocess.Popen[bytes] | None = None
        try:
            process = subprocess.Popen(
                arguments,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            # Chromium's lifecycle is not a navigation receipt: some builds
            # exit with compositor/profile errors after the callback, while
            # others keep the renderer alive after issuing it. Give the real
            # browser a bounded navigation window, then clean up its isolated
            # process group. The OIDF module observes the callback itself and
            # remains the authoritative success check.
            try:
                process.wait(timeout=HANDOFF_BROWSER_NAVIGATION_SECONDS)
            except subprocess.TimeoutExpired:
                pass
        except OSError as exc:
            raise DriverFailure("wallet_browser_handoff_failed") from exc
        finally:
            stop_handoff_browser(process)


def stop_handoff_browser(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=HANDOFF_BROWSER_EXIT_SECONDS)
    except ProcessLookupError:
        return
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=HANDOFF_BROWSER_EXIT_SECONDS)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DriverFailure("wallet_browser_handoff_cleanup_failed") from exc
    except OSError as exc:
        raise DriverFailure("wallet_browser_handoff_cleanup_failed") from exc


def submit_browser_api_rejection(config: DriverConfig, launch: WalletLaunch) -> None:
    try:
        oidf_wallet_error_evidence.submit_browser_api_rejection(
            evidence_config(config),
            require_value(launch.submit_url, "invalid_oidf_browser_api_submit_url"),
            open_request,
        )
    except oidf_wallet_error_evidence.EvidenceFailure as exc:
        raise DriverFailure(exc.reason) from exc


def upload_error_screen(config: DriverConfig, module_id: str) -> None:
    try:
        oidf_wallet_error_evidence.upload_error_screen(
            evidence_config(config),
            module_id,
            oidf_wallet_error_evidence.EvidenceDependencies(
                open_request=open_request,
                api_get_json=lambda relative_path: api_get_json(config, relative_path),
                decode_json=decode_json,
            ),
        )
    except oidf_wallet_error_evidence.EvidenceFailure as exc:
        raise DriverFailure(exc.reason) from exc


def evidence_config(
    config: DriverConfig,
) -> oidf_wallet_error_evidence.EvidenceConfig:
    return oidf_wallet_error_evidence.EvidenceConfig(
        conformance_server=require_value(
            config.conformance_server,
            "missing_conformance_server",
        ),
        conformance_api_token=config.conformance_api_token,
        conformance_verify_ssl=config.conformance_verify_ssl,
        wallet_error_screen_endpoint=require_value(
            config.wallet_error_screen_endpoint,
            "missing_wallet_error_screen_endpoint",
        ),
        wallet_harness_token=validate_control_token(config.wallet_harness_token),
        wallet_screenshot_browser=validate_screenshot_browser(
            config.wallet_screenshot_browser
        ),
    )


def wallet_harness_headers(token: str | None) -> dict[str, str]:
    validated_token = validate_control_token(token)
    return {"Authorization": f"Bearer {validated_token}"}


def api_get_json(config: DriverConfig, relative_path: str) -> Any:
    server = require_value(config.conformance_server, "missing_conformance_server")
    base = server if server.endswith("/") else f"{server}/"
    request = urllib.request.Request(urllib.parse.urljoin(base, relative_path), method="GET")
    request.add_header("Accept", "application/json")
    if config.conformance_api_token is not None:
        request.add_header("Authorization", f"Bearer {config.conformance_api_token}")
    body = open_request(request, config.conformance_verify_ssl, "oidf_api_request_failed")
    if body is None:
        raise DriverFailure("oidf_api_request_failed")
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
    accepted_error_statuses: frozenset[int] = frozenset(),
) -> bytes | None:
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
        if exc.code in accepted_error_statuses:
            exc.close()
            return None
        raise DriverFailure(reason) from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise DriverFailure(reason) from exc
    if status < 200 or status >= 400:
        raise DriverFailure(reason)
    if len(body) > MAX_HTTP_RESPONSE_BYTES:
        raise DriverFailure("http_response_too_large")
    return body


def require_value(value: str | None, reason: str) -> str:
    if value is None:
        raise DriverFailure(reason)
    return value


def quote_path_segment(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def string_value(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    return None


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
            prefix=".oidf-wallet-flow-driver.",
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
