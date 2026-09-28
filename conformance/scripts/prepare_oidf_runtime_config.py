#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Create a private OIDF runner config with a collision-resistant alias."""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
import tempfile
from pathlib import Path


MAX_CONFIG_BYTES = 2 * 1024 * 1024
ALIAS_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$")
ALIAS_MEMBER_PATTERN = re.compile(
    r'(?m)^(?P<indent>\s*)"alias"(?P<separator>\s*:\s*)"(?P<value>[^"\\]*)"'
)
KNOWN_SHARED_ALIASES = frozenset(("oidf-vp-test-wallet", "oidf-vp-test-verifier"))


class ConfigFailure(Exception):
    """Stable, non-sensitive runtime-configuration failure."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render an OIDF config with a unique top-level alias."
    )
    parser.add_argument("template")
    parser.add_argument("output")
    parser.add_argument("--alias")
    parser.add_argument("--alias-prefix", required=True)
    args = parser.parse_args()
    try:
        alias = validated_alias(args.alias, args.alias_prefix)
        render_config(Path(args.template), Path(args.output), alias)
        print(alias)
        return 0
    except ConfigFailure as error:
        print(error.reason, file=sys.stderr)
        return 2


def validated_alias(configured: str | None, prefix: str) -> str:
    if configured is None or configured == "":
        if ALIAS_PATTERN.fullmatch(prefix) is None:
            raise ConfigFailure("runtime_config_alias_prefix_invalid")
        configured = f"{prefix}-{secrets.token_hex(12)}"
    if (
        ALIAS_PATTERN.fullmatch(configured) is None
        or configured in KNOWN_SHARED_ALIASES
    ):
        raise ConfigFailure("runtime_config_alias_invalid")
    return configured


def render_config(template: Path, output: Path, alias: str) -> None:
    if output.exists() or output.is_symlink():
        raise ConfigFailure("runtime_config_output_already_exists")
    try:
        if template.is_symlink() or template.stat().st_size > MAX_CONFIG_BYTES:
            raise ConfigFailure("runtime_config_template_invalid")
        source = template.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ConfigFailure("runtime_config_template_invalid") from error
    matches = list(ALIAS_MEMBER_PATTERN.finditer(source))
    if len(matches) != 1:
        raise ConfigFailure("runtime_config_alias_member_invalid")
    match = matches[0]
    encoded_alias = json.dumps(alias, ensure_ascii=True)
    rendered = (
        source[: match.start()]
        + f'{match.group("indent")}"alias"{match.group("separator")}{encoded_alias}'
        + source[match.end() :]
    )
    write_private_file(output, rendered.encode("utf-8"))


def write_private_file(path: Path, contents: bytes) -> None:
    descriptor = -1
    temporary_path = ""
    try:
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        descriptor, temporary_path = tempfile.mkstemp(
            dir=path.parent, prefix=f".{path.name}."
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(contents)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        temporary_path = ""
    except OSError as error:
        raise ConfigFailure("runtime_config_write_failed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
