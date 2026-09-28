#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import base64
import json
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import oidf_wallet_error_evidence


VALID_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwC"
    "AAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


def config() -> oidf_wallet_error_evidence.EvidenceConfig:
    return oidf_wallet_error_evidence.EvidenceConfig(
        conformance_server="https://suite.example.test",
        conformance_api_token=None,
        conformance_verify_ssl=True,
        wallet_error_screen_endpoint="https://wallet.example.test/error",
        wallet_harness_token="w" * 32,
        wallet_screenshot_browser=sys.executable,
    )


class OidfWalletErrorEvidenceTests(unittest.TestCase):
    def test_secret_bearing_config_disables_generated_repr(self) -> None:
        configured = config()

        self.assertNotIn("w" * 32, repr(configured))

    def test_complete_png_requires_valid_chunks_and_terminal_iend(self) -> None:
        self.assertTrue(oidf_wallet_error_evidence.is_complete_png(VALID_PNG))
        self.assertFalse(
            oidf_wallet_error_evidence.is_complete_png(VALID_PNG[:-1])
        )
        tampered = bytearray(VALID_PNG)
        tampered[20] ^= 1
        self.assertFalse(
            oidf_wallet_error_evidence.is_complete_png(bytes(tampered))
        )

    def test_bounded_file_reader_rejects_oversized_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            screenshot = Path(directory) / "oversized.png"
            screenshot.write_bytes(
                b"x" * (oidf_wallet_error_evidence.MAX_SCREENSHOT_BYTES + 1)
            )

            with self.assertRaises(
                oidf_wallet_error_evidence.EvidenceFailure
            ) as caught:
                oidf_wallet_error_evidence.read_bounded_file(str(screenshot))

        self.assertEqual(caught.exception.reason, "wallet_error_screen_render_failed")

    def test_render_returns_complete_png_and_always_cleans_process_group(self) -> None:
        process = mock.Mock()
        process.pid = 123

        with mock.patch.object(
            oidf_wallet_error_evidence.subprocess,
            "Popen",
            return_value=process,
        ), mock.patch.object(
            oidf_wallet_error_evidence,
            "wait_for_complete_screenshot",
            return_value=VALID_PNG,
        ), mock.patch.object(
            oidf_wallet_error_evidence,
            "stop_browser_process",
        ) as stop_browser_process:
            rendered = oidf_wallet_error_evidence.render_error_screen(
                sys.executable,
                b"<html></html>",
            )

        self.assertEqual(rendered, VALID_PNG)
        stop_browser_process.assert_called_once_with(process)

    def test_render_timeout_still_cleans_process_group(self) -> None:
        process = mock.Mock()
        process.pid = 123

        with mock.patch.object(
            oidf_wallet_error_evidence.subprocess,
            "Popen",
            return_value=process,
        ), mock.patch.object(
            oidf_wallet_error_evidence,
            "wait_for_complete_screenshot",
            side_effect=oidf_wallet_error_evidence.EvidenceFailure(
                "wallet_error_screen_render_failed"
            ),
        ), mock.patch.object(
            oidf_wallet_error_evidence,
            "stop_browser_process",
        ) as stop_browser_process, self.assertRaises(
            oidf_wallet_error_evidence.EvidenceFailure
        ):
            oidf_wallet_error_evidence.render_error_screen(
                sys.executable,
                b"<html></html>",
            )

        stop_browser_process.assert_called_once_with(process)

    def test_process_group_is_killed_and_reaped_after_graceful_timeout(self) -> None:
        process = mock.Mock()
        process.pid = 123
        process.poll.return_value = None
        process.wait.side_effect = [
            subprocess.TimeoutExpired(cmd="chrome", timeout=5.0),
            0,
        ]

        with mock.patch.object(
            oidf_wallet_error_evidence,
            "signal_process_group",
        ) as signal_process_group:
            oidf_wallet_error_evidence.stop_browser_process(process)

        self.assertEqual(
            signal_process_group.call_args_list,
            [mock.call(123, signal.SIGTERM), mock.call(123, signal.SIGKILL)],
        )

    def test_already_exited_browser_is_not_signaled(self) -> None:
        process = mock.Mock()
        process.poll.return_value = 0

        with mock.patch.object(
            oidf_wallet_error_evidence,
            "signal_process_group",
        ) as signal_process_group:
            oidf_wallet_error_evidence.stop_browser_process(process)

        signal_process_group.assert_not_called()
        process.wait.assert_not_called()

    def test_browser_api_rejection_stays_on_the_conformance_origin(self) -> None:
        with self.assertRaises(
            oidf_wallet_error_evidence.EvidenceFailure
        ) as caught:
            oidf_wallet_error_evidence.submit_browser_api_rejection(
                config(),
                "https://attacker.example.test/browser_api/submit",
                mock.Mock(),
            )

        self.assertEqual(
            caught.exception.reason,
            "invalid_oidf_browser_api_submit_origin",
        )

    def test_browser_api_rejection_submits_a_bounded_generic_exception(self) -> None:
        open_request = mock.Mock(return_value=b"")

        oidf_wallet_error_evidence.submit_browser_api_rejection(
            config(),
            "https://suite.example.test/browser_api/submit",
            open_request,
        )

        request = open_request.call_args.args[0]
        self.assertEqual(
            json.loads(request.data.decode("utf-8")),
            {
                "exception": {
                    "name": "NotAllowedError",
                    "message": "Wallet rejected the invalid presentation request",
                }
            },
        )

    def test_error_screen_upload_requires_the_filled_placeholder(self) -> None:
        screenshot = b"\x89PNG\r\n\x1a\nopaque"
        expected_image = "data:image/png;base64," + base64.b64encode(
            screenshot
        ).decode("ascii")
        open_request = mock.Mock(
            return_value=json.dumps(
                {
                    "testId": "module-one",
                    "img": expected_image,
                }
            ).encode("utf-8")
        )
        dependencies = oidf_wallet_error_evidence.EvidenceDependencies(
            open_request=open_request,
            api_get_json=mock.Mock(return_value=[]),
            decode_json=lambda raw, _reason: json.loads(raw.decode("utf-8")),
        )

        with mock.patch.object(
            oidf_wallet_error_evidence,
            "fetch_wallet_error_screen",
            return_value=b"<html></html>",
        ), mock.patch.object(
            oidf_wallet_error_evidence,
            "render_error_screen",
            return_value=screenshot,
        ), mock.patch.object(
            oidf_wallet_error_evidence,
            "wait_for_image_placeholder",
            return_value="placeholder-one",
        ):
            oidf_wallet_error_evidence.upload_error_screen(
                config(),
                "module-one",
                dependencies,
            )

    def test_error_screen_upload_rejects_an_unfilled_placeholder(self) -> None:
        screenshot = b"\x89PNG\r\n\x1a\nopaque"
        response = json.dumps(
            {
                "testId": "module-one",
                "upload": "placeholder-one",
            }
        ).encode("utf-8")
        dependencies = oidf_wallet_error_evidence.EvidenceDependencies(
            open_request=mock.Mock(return_value=response),
            api_get_json=mock.Mock(return_value=[]),
            decode_json=lambda raw, _reason: json.loads(raw.decode("utf-8")),
        )

        with mock.patch.object(
            oidf_wallet_error_evidence,
            "fetch_wallet_error_screen",
            return_value=b"<html></html>",
        ), mock.patch.object(
            oidf_wallet_error_evidence,
            "render_error_screen",
            return_value=screenshot,
        ), mock.patch.object(
            oidf_wallet_error_evidence,
            "wait_for_image_placeholder",
            return_value="placeholder-one",
        ), self.assertRaises(
            oidf_wallet_error_evidence.EvidenceFailure
        ) as caught:
            oidf_wallet_error_evidence.upload_error_screen(
                config(),
                "module-one",
                dependencies,
            )

        self.assertEqual(caught.exception.reason, "oidf_error_screen_upload_failed")

    def test_error_screen_fetch_requires_the_product_error_view(self) -> None:
        open_request = mock.Mock(
            return_value=b"<html><title>foreign</title></html>"
        )

        with self.assertRaises(
            oidf_wallet_error_evidence.EvidenceFailure
        ) as caught:
            oidf_wallet_error_evidence.fetch_wallet_error_screen(
                config(),
                open_request,
            )

        self.assertEqual(caught.exception.reason, "wallet_error_screen_invalid")


if __name__ == "__main__":
    unittest.main()
