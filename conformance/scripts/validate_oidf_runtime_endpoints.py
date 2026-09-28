#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate certification runtime endpoints without exposing their values."""

from __future__ import annotations

import argparse
import sys
import urllib.parse
from typing import NoReturn


MAX_ENDPOINT_BYTES = 4096


class EndpointFailure(Exception):
    """Stable, non-sensitive runtime endpoint validation failure."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def fail(reason: str) -> NoReturn:
    raise EndpointFailure(reason)


def validate_endpoint(value: str, allow_http: bool) -> None:
    """Accept only canonical, uncredentialed HTTP(S) endpoint URLs.

    Certification endpoints are configuration boundaries that may receive
    bearer tokens or protocol payloads. Canonical ASCII URLs avoid parser
    disagreement, while rejecting userinfo and fragments prevents credentials
    or requests from being redirected to an operator-misread authority.
    """

    if (
        not value
        or not value.isascii()
        or value != value.strip()
        or any(character.isspace() for character in value)
        or "\\" in value
        or len(value.encode("ascii")) > MAX_ENDPOINT_BYTES
    ):
        fail("oidf_runtime_endpoint_invalid")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise EndpointFailure("oidf_runtime_endpoint_invalid") from error
    allowed_schemes = ("http", "https") if allow_http else ("https",)
    if (
        parsed.scheme not in allowed_schemes
        or not value.startswith(f"{parsed.scheme}://")
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
        or "%" in parsed.netloc
        or parsed.query != ""
        or parsed.fragment != ""
        or port == 0
    ):
        fail("oidf_runtime_endpoint_invalid")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allow-http",
        action="store_true",
        help="allow HTTP only for an explicitly selected local development run",
    )
    parser.add_argument("endpoints", nargs="+")
    args = parser.parse_args()
    try:
        for endpoint in args.endpoints:
            validate_endpoint(endpoint, args.allow_http)
    except EndpointFailure as error:
        print(error.reason, file=sys.stderr)
        return 2
    print("OIDF runtime endpoints valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
