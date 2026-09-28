#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import prepare_oidf_runtime_config


class PrepareOidfRuntimeConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.template = self.root / "template.json"
        self.output = self.root / "private" / "runtime.json"
        self.template.write_text(
            '{\n  "alias": "shared-example",\n  "key": {key.json}\n}\n',
            encoding="utf-8",
        )

    def test_renders_only_top_level_alias_and_uses_private_permissions(self) -> None:
        alias = "reallyme-vp-wallet-0123456789abcdef"

        prepare_oidf_runtime_config.render_config(self.template, self.output, alias)

        contents = self.output.read_text(encoding="utf-8")
        self.assertIn(f'"alias": "{alias}"', contents)
        self.assertIn('"key": {key.json}', contents)
        mode = stat.S_IMODE(self.output.stat().st_mode)
        self.assertEqual(mode, 0o600)

    def test_generates_collision_resistant_alias(self) -> None:
        first = prepare_oidf_runtime_config.validated_alias(None, "reallyme-vp-wallet")
        second = prepare_oidf_runtime_config.validated_alias(None, "reallyme-vp-wallet")

        self.assertRegex(first, prepare_oidf_runtime_config.ALIAS_PATTERN)
        self.assertNotEqual(first, second)

    def test_rejects_known_shared_example_alias(self) -> None:
        with self.assertRaises(prepare_oidf_runtime_config.ConfigFailure) as caught:
            prepare_oidf_runtime_config.validated_alias(
                "oidf-vp-test-wallet", "reallyme-vp-wallet"
            )
        self.assertEqual(caught.exception.reason, "runtime_config_alias_invalid")

    def test_rejects_alias_character_not_accepted_by_oidf(self) -> None:
        with self.assertRaises(prepare_oidf_runtime_config.ConfigFailure) as caught:
            prepare_oidf_runtime_config.validated_alias(
                "reallyme.wallet.unique", "reallyme-vp-wallet"
            )
        self.assertEqual(caught.exception.reason, "runtime_config_alias_invalid")

    def test_rejects_duplicate_alias_members(self) -> None:
        self.template.write_text(
            '{\n"alias":"first",\n"alias":"second"\n}', encoding="utf-8"
        )

        with self.assertRaises(prepare_oidf_runtime_config.ConfigFailure) as caught:
            prepare_oidf_runtime_config.render_config(
                self.template, self.output, "reallyme-vp-wallet-0123456789abcdef"
            )
        self.assertEqual(caught.exception.reason, "runtime_config_alias_member_invalid")

    def test_refuses_to_overwrite_previous_runtime_config(self) -> None:
        self.output.parent.mkdir()
        self.output.write_text("retained evidence", encoding="utf-8")

        with self.assertRaises(prepare_oidf_runtime_config.ConfigFailure) as caught:
            prepare_oidf_runtime_config.render_config(
                self.template, self.output, "reallyme-vp-wallet-0123456789abcdef"
            )
        self.assertEqual(caught.exception.reason, "runtime_config_output_already_exists")


if __name__ == "__main__":
    unittest.main()
