#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import drive_oidf_wallet_flow


CONTROL_TOKEN = "w" * drive_oidf_wallet_flow.MIN_CONTROL_TOKEN_BYTES


def harness_response(
    flow_status: str = "dc_api_jwt_submitted",
    redirect_uri: str | None = None,
) -> bytes:
    flow = {"status": flow_status}
    if redirect_uri is not None:
        flow["redirect_uri"] = redirect_uri
    return json.dumps(
        {
            "session_id": 7,
            "status": "completed",
            "transport": {"kind": "browser_api", "request_count": 1},
            "flow": flow,
        },
        separators=(",", ":"),
    ).encode("utf-8")


def config(method: str = "POST") -> drive_oidf_wallet_flow.DriverConfig:
    return drive_oidf_wallet_flow.DriverConfig(
        conformance_server="https://suite.example.test",
        conformance_api_token=None,
        conformance_verify_ssl=True,
        module_id=None,
        plan_id="oid4vp-1final-wallet-haip-test-plan",
        alias="oidf-vp-test-verifier",
        profile_id="wallet-sd-jwt-vc-direct-post-jwt",
        credential_format="sd_jwt_vc",
        response_mode="direct_post.jwt",
        expected_module_count=15,
        started_after_epoch_seconds=0.0,
        wallet_harness_endpoint="https://wallet.example.test/launch",
        wallet_error_screen_endpoint="https://wallet.example.test/error",
        wallet_harness_token=CONTROL_TOKEN,
        wallet_harness_method=method,
        wallet_screenshot_browser=sys.executable,
        timeout_seconds=10.0,
        poll_seconds=1.0,
        result_file="result.json",
    )


class DriveOidfWalletFlowTests(unittest.TestCase):
    def test_secret_bearing_values_disable_generated_repr(self) -> None:
        configured = config()
        launch = drive_oidf_wallet_flow.WalletLaunch(
            drive_oidf_wallet_flow.WalletLaunchKind.AUTHORIZATION_REQUEST,
            authorization_request="request=secret-request-object",
        )

        self.assertNotIn(CONTROL_TOKEN, repr(configured))
        self.assertNotIn("secret-request-object", repr(launch))

    def test_result_write_is_complete_and_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result_path = Path(directory) / "driver.json"

            drive_oidf_wallet_flow.write_result(
                str(result_path), "running", "flow_driver_active", 7
            )

            self.assertEqual(
                json.loads(result_path.read_text(encoding="utf-8")),
                {
                    "status": "running",
                    "reason": "flow_driver_active",
                    "triggered_modules": 7,
                },
            )
            self.assertEqual(result_path.stat().st_mode & 0o777, 0o600)

    def test_extracts_authorization_request_query(self) -> None:
        launch = drive_oidf_wallet_flow.wallet_launch(
            {
                "browser": {
                    "visited": [
                        "https://wallet.example.test/authorize?client_id=client&request_uri=https%3A%2F%2Fsuite.example.test%2Frequest"
                    ]
                }
            }
        )

        self.assertIsNotNone(launch)
        if launch is None:
            self.fail("authorization request launch is required")
        self.assertEqual(
            launch.kind,
            drive_oidf_wallet_flow.WalletLaunchKind.AUTHORIZATION_REQUEST,
        )
        self.assertIn("request_uri=", launch.authorization_request or "")

    def test_extracts_structured_browser_api_request(self) -> None:
        request_payload = {
            "digital": {
                "requests": [
                    {
                        "protocol": "openid4vp-v1-multisigned",
                        "data": {
                            "request": {
                                "payload": "payload",
                                "signatures": [
                                    {"protected": "header", "signature": "signature"}
                                ],
                            }
                        },
                    }
                ]
            }
        }
        launch = drive_oidf_wallet_flow.wallet_launch(
            {
                "browser": {
                    "browserApiRequests": [
                        {
                            "request": request_payload,
                            "submitUrl": "https://suite.example.test/browser_api/submit",
                        }
                    ],
                    "urls": ["https://wallet.example.test/incorrect?request=old"],
                }
            }
        )

        self.assertIsNotNone(launch)
        if launch is None:
            self.fail("browser API launch is required")
        self.assertEqual(
            launch.kind, drive_oidf_wallet_flow.WalletLaunchKind.BROWSER_API
        )
        self.assertEqual(launch.browser_api_request, request_payload)
        self.assertEqual(
            launch.submit_url,
            "https://suite.example.test/browser_api/submit",
        )

    def test_forwards_browser_api_request_and_submit_url_as_json(self) -> None:
        launch = drive_oidf_wallet_flow.WalletLaunch(
            kind=drive_oidf_wallet_flow.WalletLaunchKind.BROWSER_API,
            browser_api_request={
                "digital": {
                    "requests": [
                        {
                            "protocol": "openid4vp-v1-unsigned",
                            "data": {"nonce": "opaque"},
                        }
                    ]
                }
            },
            submit_url="https://suite.example.test/browser_api/submit",
        )

        with mock.patch.object(
            drive_oidf_wallet_flow,
            "open_request",
            return_value=harness_response(),
        ) as open_request:
            drive_oidf_wallet_flow.call_wallet_harness(config(), launch)

        request = open_request.call_args.args[0]
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.get_header("Content-type"), "application/json")
        self.assertEqual(
            request.get_header("Authorization"), f"Bearer {CONTROL_TOKEN}"
        )
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(
            body["browser_api_request"]["digital"]["requests"][0]["protocol"],
            "openid4vp-v1-unsigned",
        )
        self.assertEqual(
            body["submit_url"], "https://suite.example.test/browser_api/submit"
        )

    def test_opens_valid_direct_post_handoff_in_an_isolated_browser(self) -> None:
        redirect_uri = "https://suite.example.test/callback#one-time-secret"
        process = mock.Mock()
        process.wait.return_value = 0
        process.poll.return_value = 0
        process.pid = 1234

        with mock.patch.object(
            drive_oidf_wallet_flow.subprocess, "Popen", return_value=process
        ) as popen:
            drive_oidf_wallet_flow.open_browser_handoff(config(), redirect_uri)

        arguments = popen.call_args.args[0]
        self.assertEqual(arguments[-1], redirect_uri)
        self.assertIn("--dump-dom", arguments)
        self.assertTrue(
            any(value.startswith("--user-data-dir=") for value in arguments)
        )
        self.assertNotIn("--ignore-certificate-errors", arguments)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])

    def test_harness_direct_post_response_triggers_the_front_channel(self) -> None:
        launch = drive_oidf_wallet_flow.WalletLaunch(
            kind=drive_oidf_wallet_flow.WalletLaunchKind.AUTHORIZATION_REQUEST,
            authorization_request="request=opaque",
        )
        redirect_uri = "https://suite.example.test/callback#one-time-secret"

        with mock.patch.object(
            drive_oidf_wallet_flow,
            "open_request",
            return_value=harness_response("direct_post_jwt_submitted", redirect_uri),
        ), mock.patch.object(
            drive_oidf_wallet_flow, "open_browser_handoff"
        ) as open_browser_handoff:
            drive_oidf_wallet_flow.call_wallet_harness(config(), launch)

        open_browser_handoff.assert_called_once_with(config(), redirect_uri)

    def test_local_browser_handoff_can_use_the_explicit_dev_tls_policy(self) -> None:
        local = config()
        local = drive_oidf_wallet_flow.DriverConfig(
            **{**local.__dict__, "conformance_verify_ssl": False}
        )
        process = mock.Mock()
        process.wait.return_value = 0
        process.poll.return_value = 0
        process.pid = 1234

        with mock.patch.object(
            drive_oidf_wallet_flow.subprocess, "Popen", return_value=process
        ) as popen:
            drive_oidf_wallet_flow.open_browser_handoff(
                local,
                "https://suite.example.test/callback#secret",
            )

        self.assertIn("--ignore-certificate-errors", popen.call_args.args[0])

    def test_browser_exit_status_does_not_override_the_suite_callback_result(self) -> None:
        process = mock.Mock()
        process.wait.return_value = 21
        process.poll.return_value = 21
        process.pid = 1234

        with mock.patch.object(
            drive_oidf_wallet_flow.subprocess, "Popen", return_value=process
        ):
            drive_oidf_wallet_flow.open_browser_handoff(
                config(),
                "https://suite.example.test/callback#secret",
            )

    def test_rejects_malformed_or_cross_origin_browser_handoffs(self) -> None:
        for redirect_uri in [
            "http://suite.example.test/callback",
            "https://user@suite.example.test/callback",
            "https://attacker.example.test/callback",
            "relative/callback",
        ]:
            with self.subTest(redirect_uri=redirect_uri):
                with self.assertRaises(drive_oidf_wallet_flow.DriverFailure) as caught:
                    drive_oidf_wallet_flow.parse_wallet_harness_response(
                        harness_response("direct_post_jwt_submitted", redirect_uri),
                        config(),
                    )
                self.assertEqual(
                    caught.exception.reason,
                    "invalid_wallet_browser_handoff",
                )

    def test_rejects_unknown_duplicate_and_mismatched_harness_response(self) -> None:
        malformed = [
            b'{"session_id":1,"status":"completed","transport":{},"flow":{"status":"direct_post_jwt_submitted"},"unknown":true}',
            b'{"session_id":1,"session_id":2,"status":"completed","transport":{},"flow":{"status":"direct_post_jwt_submitted"}}',
            harness_response("dc_api_jwt_submitted", "https://suite.example.test/callback"),
        ]
        for response in malformed:
            with self.subTest(response=response):
                with self.assertRaises(drive_oidf_wallet_flow.DriverFailure) as caught:
                    drive_oidf_wallet_flow.parse_wallet_harness_response(response, config())
                self.assertEqual(
                    caught.exception.reason,
                    "wallet_harness_invalid_response",
                )

    def test_live_browser_is_stopped_after_the_bounded_navigation_window(self) -> None:
        process = mock.Mock()
        process.wait.side_effect = [
            subprocess.TimeoutExpired(
                cmd="browser",
                timeout=drive_oidf_wallet_flow.HANDOFF_BROWSER_NAVIGATION_SECONDS,
            ),
            0,
        ]
        process.poll.return_value = None
        process.pid = 1234

        with mock.patch.object(
            drive_oidf_wallet_flow.subprocess, "Popen", return_value=process
        ), mock.patch.object(drive_oidf_wallet_flow.os, "killpg") as killpg:
            drive_oidf_wallet_flow.open_browser_handoff(
                config(),
                "https://suite.example.test/callback#secret",
            )

        killpg.assert_called_once_with(1234, drive_oidf_wallet_flow.signal.SIGTERM)

    def test_rejects_browser_api_forwarding_over_get(self) -> None:
        launch = drive_oidf_wallet_flow.WalletLaunch(
            kind=drive_oidf_wallet_flow.WalletLaunchKind.BROWSER_API,
            browser_api_request={"digital": {"requests": []}},
            submit_url="https://suite.example.test/browser_api/submit",
        )

        with self.assertRaises(drive_oidf_wallet_flow.DriverFailure) as caught:
            drive_oidf_wallet_flow.call_wallet_harness(config("GET"), launch)
        self.assertEqual(caught.exception.reason, "browser_api_requires_post_harness")

    def test_negative_module_allows_only_bad_request_rejection(self) -> None:
        launch = drive_oidf_wallet_flow.WalletLaunch(
            kind=drive_oidf_wallet_flow.WalletLaunchKind.AUTHORIZATION_REQUEST,
            authorization_request="request=opaque",
        )

        with mock.patch.object(
            drive_oidf_wallet_flow, "open_request", return_value=None
        ) as open_request, mock.patch.object(
            drive_oidf_wallet_flow, "upload_error_screen"
        ) as upload_error_screen:
            drive_oidf_wallet_flow.call_wallet_harness(
                config(), launch, "module-one", True
            )

        self.assertEqual(open_request.call_args.args[3], frozenset({400}))
        upload_error_screen.assert_called_once_with(config(), "module-one")

    def test_negative_module_rejects_a_successful_harness_response(self) -> None:
        launch = drive_oidf_wallet_flow.WalletLaunch(
            kind=drive_oidf_wallet_flow.WalletLaunchKind.AUTHORIZATION_REQUEST,
            authorization_request="request=opaque",
        )

        with mock.patch.object(
            drive_oidf_wallet_flow, "open_request", return_value=b"accepted"
        ) as open_request:
            with self.assertRaises(drive_oidf_wallet_flow.DriverFailure) as caught:
                drive_oidf_wallet_flow.call_wallet_harness(
                    config(), launch, "module-one", True
                )

        self.assertEqual(open_request.call_args.args[3], frozenset({400}))
        self.assertEqual(caught.exception.reason, "wallet_harness_rejection_missing")

    def test_browser_api_rejection_is_reported_before_error_evidence_upload(
        self,
    ) -> None:
        launch = drive_oidf_wallet_flow.WalletLaunch(
            kind=drive_oidf_wallet_flow.WalletLaunchKind.BROWSER_API,
            browser_api_request={
                "digital": {
                    "requests": [
                        {
                            "protocol": "openid4vp-v1-signed",
                            "data": {"request": "e30.e30.c2ln"},
                        }
                    ]
                }
            },
            submit_url="https://suite.example.test/browser_api/submit",
        )

        with mock.patch.object(
            drive_oidf_wallet_flow,
            "open_request",
            side_effect=[None, b""],
        ) as open_request, mock.patch.object(
            drive_oidf_wallet_flow, "upload_error_screen"
        ) as upload_error_screen:
            drive_oidf_wallet_flow.call_wallet_harness(
                config(), launch, "module-one", True
            )

        submission = open_request.call_args_list[1].args[0]
        self.assertEqual(
            submission.full_url,
            "https://suite.example.test/browser_api/submit",
        )
        self.assertEqual(
            json.loads(submission.data.decode("utf-8"))["exception"]["name"],
            "NotAllowedError",
        )
        upload_error_screen.assert_called_once_with(config(), "module-one")

    def test_browser_api_rejection_stays_on_the_conformance_origin(self) -> None:
        launch = drive_oidf_wallet_flow.WalletLaunch(
            kind=drive_oidf_wallet_flow.WalletLaunchKind.BROWSER_API,
            browser_api_request={"digital": {"requests": []}},
            submit_url="https://attacker.example.test/browser_api/submit",
        )

        with self.assertRaises(drive_oidf_wallet_flow.DriverFailure) as caught:
            drive_oidf_wallet_flow.submit_browser_api_rejection(config(), launch)

        self.assertEqual(
            caught.exception.reason,
            "invalid_oidf_browser_api_submit_origin",
        )

    def test_rejects_malformed_browser_api_status(self) -> None:
        with self.assertRaises(drive_oidf_wallet_flow.DriverFailure) as caught:
            drive_oidf_wallet_flow.wallet_launch(
                {"browser": {"browserApiRequests": [{"request": []}]}}
            )
        self.assertEqual(caught.exception.reason, "invalid_oidf_browser_api_request")

    def test_rejects_unknown_browser_api_protocol(self) -> None:
        with self.assertRaises(drive_oidf_wallet_flow.DriverFailure) as caught:
            drive_oidf_wallet_flow.validate_browser_api_request(
                {
                    "digital": {
                        "requests": [
                            {"protocol": "unknown", "data": {"request": "value"}}
                        ]
                    }
                }
            )
        self.assertEqual(caught.exception.reason, "invalid_oidf_browser_api_request")

    def test_rejects_multisigned_request_without_signatures(self) -> None:
        with self.assertRaises(drive_oidf_wallet_flow.DriverFailure) as caught:
            drive_oidf_wallet_flow.validate_browser_api_request(
                {
                    "digital": {
                        "requests": [
                            {
                                "protocol": "openid4vp-v1-multisigned",
                                "data": {
                                    "request": {"payload": "payload", "signatures": []}
                                },
                            }
                        ]
                    }
                }
            )
        self.assertEqual(caught.exception.reason, "invalid_oidf_browser_api_request")

    def test_scopes_plan_modules_by_name_alias_and_start_time(self) -> None:
        payload = {
            "data": [
                {
                    "_id": "other-plan-instance",
                    "planName": "other-plan",
                    "variant": {
                        "credential_format": "sd_jwt_vc",
                        "response_mode": "direct_post.jwt",
                    },
                    "started": "2026-09-19T10:00:00Z",
                    "config": {"alias": "oidf-vp-test-verifier"},
                    "modules": [{"instances": ["other-module"]}],
                },
                {
                    "_id": "wallet-plan-instance",
                    "planName": "oid4vp-1final-wallet-haip-test-plan",
                    "variant": {
                        "credential_format": "sd_jwt_vc",
                        "response_mode": "direct_post.jwt",
                    },
                    "started": "2026-09-19T10:00:01Z",
                    "config": {"alias": "oidf-vp-test-verifier"},
                    "modules": [{"instances": ["wallet-module-1", "../unsafe"]}],
                },
            ]
        }
        scoped = config()
        scoped = drive_oidf_wallet_flow.DriverConfig(
            **{
                **scoped.__dict__,
                "started_after_epoch_seconds": 1_700_000_000.0,
            }
        )
        with mock.patch.object(
            drive_oidf_wallet_flow, "api_get_json", return_value=payload
        ) as api_get_json:
            module_ids = drive_oidf_wallet_flow.fetch_scoped_module_ids(scoped)

        self.assertEqual(module_ids, ["wallet-module-1"])
        query = api_get_json.call_args.args[1]
        self.assertIn("plan=oid4vp-1final-wallet-haip-test-plan", query)
        self.assertIn("from=", query)

    def test_driver_completes_only_at_exact_expected_module_count(self) -> None:
        scoped = drive_oidf_wallet_flow.DriverConfig(
            **{**config().__dict__, "expected_module_count": 2, "poll_seconds": 0.1}
        )
        plan = drive_oidf_wallet_flow.PlanScope(
            "wallet-plan-instance", ("module-one", "module-two")
        )
        with mock.patch.object(
            drive_oidf_wallet_flow, "fetch_scoped_plan", return_value=plan
        ), mock.patch.object(
            drive_oidf_wallet_flow,
            "trigger_waiting_modules",
            side_effect=lambda _config, triggered, _scope: (
                triggered.update({"module-one", "module-two"}) or 2
            ),
        ), mock.patch.object(
            drive_oidf_wallet_flow, "write_result"
        ):
            outcome = drive_oidf_wallet_flow.run_driver(scoped, once=False)

        self.assertEqual(outcome.triggered_modules, 2)
        self.assertEqual(outcome.plan_instance_id, "wallet-plan-instance")

    def test_driver_failure_retains_completed_module_progress(self) -> None:
        scoped = drive_oidf_wallet_flow.DriverConfig(
            **{**config().__dict__, "expected_module_count": 2, "poll_seconds": 0.1}
        )
        plan = drive_oidf_wallet_flow.PlanScope(
            "wallet-plan-instance", ("module-one", "module-two")
        )

        def trigger_once_then_fail(
            _config: drive_oidf_wallet_flow.DriverConfig,
            triggered: set[str],
            _scope: drive_oidf_wallet_flow.PlanScope | None,
        ) -> int:
            if not triggered:
                triggered.add("module-one")
                return 1
            raise drive_oidf_wallet_flow.DriverFailure("wallet_harness_call_failed")

        with mock.patch.object(
            drive_oidf_wallet_flow, "fetch_scoped_plan", return_value=plan
        ), mock.patch.object(
            drive_oidf_wallet_flow,
            "trigger_waiting_modules",
            side_effect=trigger_once_then_fail,
        ), mock.patch.object(
            drive_oidf_wallet_flow, "write_result"
        ), mock.patch.object(
            drive_oidf_wallet_flow.time, "sleep"
        ), self.assertRaises(
            drive_oidf_wallet_flow.DriverFailure
        ) as caught:
            drive_oidf_wallet_flow.run_driver(scoped, once=False)

        self.assertEqual(caught.exception.triggered_modules, 1)
        self.assertEqual(caught.exception.plan_instance_id, "wallet-plan-instance")

    def test_rejects_ambiguous_matching_plan_instances(self) -> None:
        item = {
            "_id": "wallet-plan-instance",
            "planName": "oid4vp-1final-wallet-haip-test-plan",
            "variant": {
                "credential_format": "sd_jwt_vc",
                "response_mode": "direct_post.jwt",
            },
            "started": "2026-09-19T10:00:01Z",
            "config": {"alias": "oidf-vp-test-verifier"},
            "modules": [],
        }
        with mock.patch.object(
            drive_oidf_wallet_flow,
            "api_get_json",
            return_value={"data": [item, {**item, "_id": "second-instance"}]},
        ), self.assertRaises(drive_oidf_wallet_flow.DriverFailure) as caught:
            drive_oidf_wallet_flow.fetch_scoped_plan(config())
        self.assertEqual(caught.exception.reason, "oidf_plan_not_unique")

    def test_accepts_nested_suite_plan_variant_shape(self) -> None:
        item = {
            "variant": {
                "variant": {
                    "credential_format": "iso_mdl",
                    "response_mode": "dc_api.jwt",
                }
            }
        }
        self.assertEqual(
            drive_oidf_wallet_flow.plan_variants(item),
            {
                "credential_format": "iso_mdl",
                "response_mode": "dc_api.jwt",
            },
        )

    def test_rejects_ambiguous_direct_and_nested_plan_variants(self) -> None:
        item = {
            "variant": {
                "credential_format": "sd_jwt_vc",
                "variant": {
                    "credential_format": "iso_mdl",
                    "response_mode": "dc_api.jwt",
                },
            }
        }
        with self.assertRaises(drive_oidf_wallet_flow.DriverFailure) as caught:
            drive_oidf_wallet_flow.plan_variants(item)
        self.assertEqual(caught.exception.reason, "invalid_oidf_plan_response")

    def test_parses_suite_timestamp_with_nanosecond_precision(self) -> None:
        parsed = drive_oidf_wallet_flow.parse_oidf_time(
            "2026-09-19T10:00:01.123456789Z"
        )

        self.assertIsNotNone(parsed)

    def test_only_negative_test_modules_allow_protocol_rejection(self) -> None:
        self.assertTrue(
            drive_oidf_wallet_flow.is_expected_rejection_module(
                "oid4vp-1final-wallet-negative-test-missing-nonce"
            )
        )
        self.assertFalse(
            drive_oidf_wallet_flow.is_expected_rejection_module(
                "oid4vp-1final-wallet-multisigned-one-invalid-signature"
            )
        )

    def test_rejects_duplicate_json_members_from_suite_api(self) -> None:
        with self.assertRaises(drive_oidf_wallet_flow.DriverFailure) as caught:
            drive_oidf_wallet_flow.decode_json(
                b'{"browser":{},"browser":{}}', "oidf_api_invalid_json"
            )
        self.assertEqual(caught.exception.reason, "oidf_api_invalid_json")

    def test_rejects_non_standard_non_finite_json_number(self) -> None:
        with self.assertRaises(drive_oidf_wallet_flow.DriverFailure) as caught:
            drive_oidf_wallet_flow.decode_json(
                b'{"started":Infinity}', "oidf_api_invalid_json"
            )
        self.assertEqual(caught.exception.reason, "oidf_api_invalid_json")

    def test_rejects_non_finite_numeric_environment(self) -> None:
        for value in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(value=value), mock.patch.dict(
                drive_oidf_wallet_flow.os.environ,
                {"OIDF_WALLET_FLOW_DRIVER_POLL_SECONDS": value},
                clear=True,
            ):
                with self.assertRaises(drive_oidf_wallet_flow.DriverFailure) as caught:
                    drive_oidf_wallet_flow.read_float_env(
                        "OIDF_WALLET_FLOW_DRIVER_POLL_SECONDS", 1.0, 0.1, 60.0
                    )
                self.assertEqual(caught.exception.reason, "invalid_numeric_environment")

    def test_rejects_out_of_range_numeric_environment(self) -> None:
        for value in ("0.01", "60.01"):
            with self.subTest(value=value), mock.patch.dict(
                drive_oidf_wallet_flow.os.environ,
                {"OIDF_WALLET_FLOW_DRIVER_POLL_SECONDS": value},
                clear=True,
            ):
                with self.assertRaises(drive_oidf_wallet_flow.DriverFailure) as caught:
                    drive_oidf_wallet_flow.read_float_env(
                        "OIDF_WALLET_FLOW_DRIVER_POLL_SECONDS", 1.0, 0.1, 60.0
                    )
                self.assertEqual(caught.exception.reason, "invalid_numeric_environment")

    def test_rejects_credentialed_wallet_harness_endpoint(self) -> None:
        unsafe = drive_oidf_wallet_flow.DriverConfig(
            **{
                **config().__dict__,
                "wallet_harness_endpoint": "https://user:pass@wallet.example/launch",
            }
        )

        with self.assertRaises(drive_oidf_wallet_flow.DriverFailure) as caught:
            drive_oidf_wallet_flow.validate_config(unsafe)
        self.assertEqual(caught.exception.reason, "invalid_wallet_harness_endpoint")

    def test_requires_bounded_ascii_graphic_wallet_harness_token(self) -> None:
        invalid_tokens = (
            None,
            "w" * (drive_oidf_wallet_flow.MIN_CONTROL_TOKEN_BYTES - 1),
            "w" * (drive_oidf_wallet_flow.MAX_CONTROL_TOKEN_BYTES + 1),
            ("w" * drive_oidf_wallet_flow.MIN_CONTROL_TOKEN_BYTES) + " ",
            ("w" * drive_oidf_wallet_flow.MIN_CONTROL_TOKEN_BYTES) + "\n",
            ("w" * drive_oidf_wallet_flow.MIN_CONTROL_TOKEN_BYTES) + "\N{LOCK}",
        )
        for token in invalid_tokens:
            with self.subTest(token=repr(token)):
                invalid = drive_oidf_wallet_flow.DriverConfig(
                    **{**config().__dict__, "wallet_harness_token": token}
                )
                with self.assertRaises(
                    drive_oidf_wallet_flow.DriverFailure
                ) as caught:
                    drive_oidf_wallet_flow.validate_config(invalid)
                self.assertEqual(
                    caught.exception.reason,
                    "missing_or_invalid_wallet_harness_token",
                )

    def test_rejects_unsafe_plan_scope(self) -> None:
        unsafe = drive_oidf_wallet_flow.DriverConfig(
            **{**config().__dict__, "alias": "unsafe/alias"}
        )
        with self.assertRaises(drive_oidf_wallet_flow.DriverFailure) as caught:
            drive_oidf_wallet_flow.validate_config(unsafe)
        self.assertEqual(caught.exception.reason, "invalid_oidf_plan_scope")

    def test_http_control_plane_requires_explicit_development_mode(self) -> None:
        with mock.patch.dict(drive_oidf_wallet_flow.os.environ, {}, clear=True):
            with self.assertRaises(drive_oidf_wallet_flow.DriverFailure):
                drive_oidf_wallet_flow.validate_http_endpoint(
                    "http://127.0.0.1:8787/submit",
                    "invalid_oidf_browser_api_submit_url",
                )
        with mock.patch.dict(
            drive_oidf_wallet_flow.os.environ,
            {"CONFORMANCE_DEV_MODE": "true"},
            clear=True,
        ):
            drive_oidf_wallet_flow.validate_http_endpoint(
                "http://127.0.0.1:8787/submit",
                "invalid_oidf_browser_api_submit_url",
            )

    def test_redirect_handler_refuses_redirects(self) -> None:
        handler = drive_oidf_wallet_flow.NoRedirectHandler()

        redirected = handler.redirect_request(
            mock.Mock(), mock.Mock(), 307, "Redirect", mock.Mock(), "https://other.example/"
        )

        self.assertIsNone(redirected)

    def test_rejects_excessively_nested_suite_api_json(self) -> None:
        raw = (("[" * 100) + ("0") + ("]" * 100)).encode("utf-8")
        with self.assertRaises(drive_oidf_wallet_flow.DriverFailure) as caught:
            drive_oidf_wallet_flow.decode_json(raw, "oidf_api_invalid_json")
        self.assertEqual(caught.exception.reason, "oidf_api_invalid_json")


if __name__ == "__main__":
    unittest.main()
