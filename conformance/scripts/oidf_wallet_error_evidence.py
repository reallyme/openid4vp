#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Capture OIDF evidence for a rejection produced by the wallet harness.

This module never decides whether an OpenID4VP request is valid. It receives a
rejection only after the canonical wallet flow returned HTTP 400, renders the
wallet-owned non-sensitive error view, and uploads that evidence to the exact
placeholder created by the conformance suite.
"""

from __future__ import annotations

import base64
import json
import os
import re
import signal
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


MAX_ERROR_SCREEN_BYTES = 32 * 1024
MAX_SCREENSHOT_BYTES = 500 * 1024
# The runner accepts evidence only after a complete PNG has been written. It
# does not rely on Chromium exiting: audited macOS builds can leave the parent
# process alive after the headless compositor has finished the capture.
SCREENSHOT_CAPTURE_TIMEOUT_SECONDS = 45.0
SCREENSHOT_PROCESS_EXIT_SECONDS = 5.0
SCREENSHOT_POLL_SECONDS = 0.1
PLACEHOLDER_WAIT_SECONDS = 60.0
TEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
EXPECTED_ERROR_TITLE = "<title>ReallyMe Wallet — Request not accepted</title>"


class EvidenceFailure(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class RequestOpener(Protocol):
    def __call__(
        self,
        request: urllib.request.Request,
        verify_ssl: bool,
        reason: str,
        accepted_error_statuses: frozenset[int] = frozenset(),
    ) -> bytes | None: ...


class ApiJsonGetter(Protocol):
    def __call__(self, relative_path: str) -> Any: ...


class JsonDecoder(Protocol):
    def __call__(self, raw: bytes, reason: str) -> Any: ...


@dataclass(frozen=True, repr=False)
class EvidenceConfig:
    conformance_server: str
    conformance_api_token: str | None
    conformance_verify_ssl: bool
    wallet_error_screen_endpoint: str
    wallet_harness_token: str
    wallet_screenshot_browser: str


@dataclass(frozen=True)
class EvidenceDependencies:
    open_request: RequestOpener
    api_get_json: ApiJsonGetter
    decode_json: JsonDecoder


def submit_browser_api_rejection(
    config: EvidenceConfig,
    submit_url: str,
    open_request: RequestOpener,
) -> None:
    if endpoint_origin(submit_url) != endpoint_origin(config.conformance_server):
        raise EvidenceFailure("invalid_oidf_browser_api_submit_origin")
    body = json.dumps(
        {
            "exception": {
                "name": "NotAllowedError",
                "message": "Wallet rejected the invalid presentation request",
            }
        },
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        submit_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    response = open_request(
        request,
        config.conformance_verify_ssl,
        "oidf_browser_api_rejection_submission_failed",
    )
    if response is None:
        raise EvidenceFailure("oidf_browser_api_rejection_submission_failed")


def upload_error_screen(
    config: EvidenceConfig,
    module_id: str,
    dependencies: EvidenceDependencies,
) -> None:
    html = fetch_wallet_error_screen(config, dependencies.open_request)
    screenshot = render_error_screen(config.wallet_screenshot_browser, html)
    placeholder = wait_for_image_placeholder(
        module_id,
        dependencies.api_get_json,
    )
    encoded = "data:image/png;base64," + base64.b64encode(screenshot).decode("ascii")
    base = (
        config.conformance_server
        if config.conformance_server.endswith("/")
        else f"{config.conformance_server}/"
    )
    relative = (
        f"api/log/{quote_path_segment(module_id)}/images/"
        f"{quote_path_segment(placeholder)}"
    )
    request = urllib.request.Request(
        urllib.parse.urljoin(base, relative),
        data=encoded.encode("ascii"),
        headers={"Content-Type": "text/plain"},
        method="POST",
    )
    if config.conformance_api_token is not None:
        request.add_header("Authorization", f"Bearer {config.conformance_api_token}")
    response = dependencies.open_request(
        request,
        config.conformance_verify_ssl,
        "oidf_error_screen_upload_failed",
    )
    if response is None:
        raise EvidenceFailure("oidf_error_screen_upload_failed")
    uploaded = dependencies.decode_json(response, "oidf_error_screen_upload_failed")
    if (
        not isinstance(uploaded, dict)
        or uploaded.get("testId") != module_id
        or uploaded.get("upload") is not None
        or uploaded.get("img") != encoded
    ):
        raise EvidenceFailure("oidf_error_screen_upload_failed")


def fetch_wallet_error_screen(
    config: EvidenceConfig,
    open_request: RequestOpener,
) -> bytes:
    request = urllib.request.Request(
        config.wallet_error_screen_endpoint,
        headers={
            "Authorization": f"Bearer {config.wallet_harness_token}",
            "Accept": "text/html",
        },
        method="GET",
    )
    body = open_request(
        request,
        config.conformance_verify_ssl,
        "wallet_error_screen_fetch_failed",
    )
    if body is None or len(body) == 0 or len(body) > MAX_ERROR_SCREEN_BYTES:
        raise EvidenceFailure("wallet_error_screen_invalid")
    try:
        text = body.decode("utf-8")
    except UnicodeError as exc:
        raise EvidenceFailure("wallet_error_screen_invalid") from exc
    if EXPECTED_ERROR_TITLE not in text or "Content-Security-Policy" not in text:
        raise EvidenceFailure("wallet_error_screen_invalid")
    return body


def render_error_screen(browser: str, html: bytes) -> bytes:
    validate_screenshot_browser(browser)
    with tempfile.TemporaryDirectory(prefix="reallyme-wallet-error-") as directory:
        html_path = os.path.join(directory, "error.html")
        screenshot_path = os.path.join(directory, "error.png")
        profile_path = os.path.join(directory, "browser-profile")
        with open(html_path, "xb") as output:
            output.write(html)
        os.chmod(html_path, 0o600)
        process: subprocess.Popen[bytes] | None = None
        try:
            process = subprocess.Popen(
                [
                    browser,
                    "--headless=new",
                    "--disable-background-networking",
                    "--disable-gpu",
                    "--hide-scrollbars",
                    "--no-first-run",
                    "--window-size=1280,720",
                    f"--user-data-dir={profile_path}",
                    f"--screenshot={screenshot_path}",
                    Path(html_path).as_uri(),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            screenshot = wait_for_complete_screenshot(process, screenshot_path)
        except OSError as exc:
            raise EvidenceFailure("wallet_error_screen_render_failed") from exc
        finally:
            stop_browser_process(process)
    return screenshot


def wait_for_complete_screenshot(
    process: subprocess.Popen[bytes],
    screenshot_path: str,
) -> bytes:
    deadline = time.monotonic() + SCREENSHOT_CAPTURE_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        screenshot = read_bounded_file(screenshot_path)
        if screenshot is not None and is_complete_png(screenshot):
            return screenshot
        if process.poll() is not None:
            break
        time.sleep(SCREENSHOT_POLL_SECONDS)
    raise EvidenceFailure("wallet_error_screen_render_failed")


def read_bounded_file(path: str) -> bytes | None:
    try:
        with open(path, "rb") as source:
            content = source.read(MAX_SCREENSHOT_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise EvidenceFailure("wallet_error_screen_render_failed") from exc
    if len(content) > MAX_SCREENSHOT_BYTES:
        raise EvidenceFailure("wallet_error_screen_render_failed")
    return content


def is_complete_png(content: bytes) -> bool:
    if not content.startswith(b"\x89PNG\r\n\x1a\n"):
        return False
    offset = 8
    while offset < len(content):
        if len(content) - offset < 12:
            return False
        chunk_length = int.from_bytes(content[offset : offset + 4], "big")
        chunk_end = offset + 12 + chunk_length
        if chunk_end > len(content):
            return False
        chunk_type = content[offset + 4 : offset + 8]
        chunk_data_end = offset + 8 + chunk_length
        expected_crc = int.from_bytes(content[chunk_data_end : chunk_end], "big")
        actual_crc = zlib.crc32(content[offset + 4 : chunk_data_end])
        if actual_crc != expected_crc:
            return False
        if chunk_type == b"IEND":
            return chunk_length == 0 and chunk_end == len(content)
        offset = chunk_end
    return False


def stop_browser_process(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        # Do not signal by a stale PID after Chromium has reaped itself. A PID
        # can be reused before cleanup runs, and the replacement process must
        # never become part of evidence-capture teardown.
        return
    signal_process_group(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=SCREENSHOT_PROCESS_EXIT_SECONDS)
    except subprocess.TimeoutExpired:
        signal_process_group(process.pid, signal.SIGKILL)
        try:
            process.wait(timeout=SCREENSHOT_PROCESS_EXIT_SECONDS)
        except subprocess.TimeoutExpired as exc:
            raise EvidenceFailure("wallet_error_screen_process_cleanup_failed") from exc


def signal_process_group(process_group_id: int, requested_signal: signal.Signals) -> None:
    try:
        os.killpg(process_group_id, requested_signal)
    except ProcessLookupError:
        # Chrome may have already reaped its helper processes after the PNG was
        # completed. A missing dedicated process group is the desired state.
        return
    except OSError as exc:
        raise EvidenceFailure("wallet_error_screen_process_cleanup_failed") from exc


def wait_for_image_placeholder(
    module_id: str,
    api_get_json: ApiJsonGetter,
) -> str:
    deadline = time.monotonic() + PLACEHOLDER_WAIT_SECONDS
    while time.monotonic() < deadline:
        log = api_get_json(f"api/log/{quote_path_segment(module_id)}")
        if not isinstance(log, list):
            raise EvidenceFailure("oidf_error_screen_placeholder_invalid")
        placeholders = [
            item.get("upload")
            for item in log
            if isinstance(item, dict)
            and isinstance(item.get("upload"), str)
            and TEST_ID_PATTERN.fullmatch(item["upload"]) is not None
        ]
        if len(placeholders) == 1:
            return placeholders[0]
        if len(placeholders) > 1:
            raise EvidenceFailure("oidf_error_screen_placeholder_invalid")
        time.sleep(0.2)
    raise EvidenceFailure("oidf_error_screen_placeholder_missing")


def endpoint_origin(value: str) -> tuple[str, str, int]:
    parsed = urllib.parse.urlsplit(value)
    hostname = parsed.hostname
    if hostname is None:
        raise EvidenceFailure("invalid_http_endpoint_origin")
    try:
        port = parsed.port
    except ValueError as exc:
        raise EvidenceFailure("invalid_http_endpoint_origin") from exc
    if port is None:
        port = 443 if parsed.scheme.lower() == "https" else 80
    return (parsed.scheme.lower(), hostname.lower(), port)


def validate_screenshot_browser(value: str) -> None:
    if not os.path.isabs(value) or not os.path.isfile(value) or not os.access(value, os.X_OK):
        raise EvidenceFailure("missing_or_invalid_wallet_screenshot_browser")


def quote_path_segment(value: str) -> str:
    return urllib.parse.quote(value, safe="")
