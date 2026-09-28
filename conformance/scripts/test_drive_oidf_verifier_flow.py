#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import drive_oidf_verifier_flow


CONTROL_TOKEN = "v" * drive_oidf_verifier_flow.MIN_CONTROL_TOKEN_BYTES


def config() -> drive_oidf_verifier_flow.DriverConfig:
    return drive_oidf_verifier_flow.DriverConfig(
        conformance_server="https://suite.example.test",
        conformance_api_token=None,
        conformance_verify_ssl=True,
        module_id=None,
        plan_id="oid4vp-1final-verifier-haip-test-plan",
        alias="oidf-vp-test-wallet",
        profile_id="verifier-sd-jwt-vc-direct-post-jwt",
        expected_module_count=11,
        started_after_epoch_seconds=0.0,
        authorization_endpoint=None,
        verifier_launch_endpoint="https://verifier.example.test/oidf/launch",
        verifier_launch_token=CONTROL_TOKEN,
        client_id=None,
        request_uri=None,
        request_object_jwt=None,
        request_uri_method=None,
        authorization_http_method="GET",
        timeout_seconds=10.0,
        poll_seconds=1.0,
        result_file="result.json",
    )


class DriveOidfVerifierFlowTests(unittest.TestCase):
    def test_secret_bearing_config_disables_generated_repr(self) -> None:
        configured = config()

        self.assertNotIn(CONTROL_TOKEN, repr(configured))

    def test_result_write_is_complete_and_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result_path = Path(directory) / "driver.json"

            drive_oidf_verifier_flow.write_result(
                str(result_path), "running", "flow_driver_active", 3
            )

            self.assertEqual(
                json.loads(result_path.read_text(encoding="utf-8")),
                {
                    "status": "running",
                    "reason": "flow_driver_active",
                    "triggered_modules": 3,
                },
            )
            self.assertEqual(result_path.stat().st_mode & 0o777, 0o600)

    def test_parses_typed_launch_response(self) -> None:
        launch = drive_oidf_verifier_flow.parse_verifier_launch_response(
            json.dumps(
                {
                    "authorization_endpoint": "https://suite.example.test/authorize",
                    "method": "POST",
                    "parameters": [
                        {"name": "client_id", "value": "x509_hash:client"},
                        {
                            "name": "request_uri",
                            "value": "https://verifier.example.test/request",
                        },
                    ],
                }
            ).encode("utf-8")
        )

        self.assertEqual(launch["method"], "POST")
        self.assertEqual(
            launch["parameters"]["request_uri"],
            "https://verifier.example.test/request",
        )

    def test_launch_payload_binds_profile_to_module(self) -> None:
        scoped = config()
        response = json.dumps(
            {
                "authorization_endpoint": "https://suite.example.test/authorize",
                "parameters": [{"name": "request", "value": "signed.request.jwt"}],
            }
        ).encode("utf-8")
        with mock.patch.object(
            drive_oidf_verifier_flow, "open_request", return_value=response
        ) as open_request:
            drive_oidf_verifier_flow.launch_verifier_host(
                scoped,
                "module-instance-1",
                "oid4vp-1final-verifier-happy-flow",
                "https://suite.example.test/authorize",
            )

        sent = json.loads(open_request.call_args_list[0].args[0].data.decode("utf-8"))
        self.assertEqual(sent["plan_id"], scoped.plan_id)
        self.assertEqual(sent["profile_id"], scoped.profile_id)
        self.assertEqual(sent["module_id"], "module-instance-1")
        self.assertEqual(
            open_request.call_args_list[0].args[0].headers["Authorization"],
            f"Bearer {CONTROL_TOKEN}",
        )

    def test_composed_launch_requires_bounded_ascii_graphic_token(self) -> None:
        invalid_tokens = (
            None,
            "v" * (drive_oidf_verifier_flow.MIN_CONTROL_TOKEN_BYTES - 1),
            "v" * (drive_oidf_verifier_flow.MAX_CONTROL_TOKEN_BYTES + 1),
            ("v" * drive_oidf_verifier_flow.MIN_CONTROL_TOKEN_BYTES) + " ",
            ("v" * drive_oidf_verifier_flow.MIN_CONTROL_TOKEN_BYTES) + "\n",
            ("v" * drive_oidf_verifier_flow.MIN_CONTROL_TOKEN_BYTES) + "\N{LOCK}",
        )
        for token in invalid_tokens:
            with self.subTest(token=repr(token)):
                invalid = drive_oidf_verifier_flow.DriverConfig(
                    **{**config().__dict__, "verifier_launch_token": token}
                )
                with self.assertRaises(
                    drive_oidf_verifier_flow.DriverFailure
                ) as caught:
                    drive_oidf_verifier_flow.validate_config(invalid)
                self.assertEqual(
                    caught.exception.reason,
                    "missing_or_invalid_verifier_launch_token",
                )

    def test_direct_smoke_mode_does_not_require_control_token(self) -> None:
        direct = drive_oidf_verifier_flow.DriverConfig(
            **{
                **config().__dict__,
                "verifier_launch_endpoint": None,
                "verifier_launch_token": None,
                "client_id": "x509_hash:client",
                "request_uri": "https://verifier.example.test/request/one",
            }
        )

        drive_oidf_verifier_flow.validate_config(direct)

    def test_rejects_launch_response_that_changes_suite_endpoint(self) -> None:
        response = json.dumps(
            {
                "authorization_endpoint": "https://attacker.example/authorize",
                "parameters": [{"name": "request", "value": "signed.request.jwt"}],
            }
        ).encode("utf-8")
        with mock.patch.object(
            drive_oidf_verifier_flow, "open_request", return_value=response
        ):
            with self.assertRaises(drive_oidf_verifier_flow.DriverFailure) as caught:
                drive_oidf_verifier_flow.launch_verifier_host(
                    config(),
                    "module-instance-1",
                    "oid4vp-1final-verifier-happy-flow",
                    "https://suite.example.test/authorize",
                )
        self.assertEqual(
            caught.exception.reason,
            "verifier_launch_authorization_endpoint_mismatch",
        )

    def test_requires_profile_for_composed_launch(self) -> None:
        scoped = config()
        without_profile = drive_oidf_verifier_flow.DriverConfig(
            **{**scoped.__dict__, "profile_id": None}
        )

        with self.assertRaises(drive_oidf_verifier_flow.DriverFailure) as caught:
            drive_oidf_verifier_flow.validate_config(without_profile)
        self.assertEqual(caught.exception.reason, "missing_or_invalid_profile_id")

    def test_rejects_unsafe_plan_scope_and_oversized_direct_material(self) -> None:
        unsafe_scope = drive_oidf_verifier_flow.DriverConfig(
            **{**config().__dict__, "alias": "unsafe/alias"}
        )
        with self.assertRaises(drive_oidf_verifier_flow.DriverFailure) as caught:
            drive_oidf_verifier_flow.validate_config(unsafe_scope)
        self.assertEqual(caught.exception.reason, "invalid_oidf_plan_scope")

        oversized = drive_oidf_verifier_flow.DriverConfig(
            **{
                **config().__dict__,
                "verifier_launch_endpoint": None,
                "client_id": "client",
                "request_uri": "r"
                * (drive_oidf_verifier_flow.MAX_LAUNCH_PARAMETER_BYTES + 1),
            }
        )
        with self.assertRaises(drive_oidf_verifier_flow.DriverFailure) as caught:
            drive_oidf_verifier_flow.validate_config(oversized)
        self.assertEqual(caught.exception.reason, "request_material_too_large")

    def test_rejects_missing_or_unsafe_suite_module_name(self) -> None:
        for value in (None, "unsafe/module", "m" * 129):
            with self.subTest(value=value):
                with self.assertRaises(
                    drive_oidf_verifier_flow.DriverFailure
                ) as caught:
                    drive_oidf_verifier_flow.safe_test_identifier(
                        value, "invalid_oidf_module_name"
                    )
                self.assertEqual(caught.exception.reason, "invalid_oidf_module_name")

    def test_expected_module_count_is_bounded(self) -> None:
        with mock.patch.dict(
            drive_oidf_verifier_flow.os.environ,
            {"OIDF_EXPECTED_MODULE_COUNT": str(drive_oidf_verifier_flow.MAX_EXPECTED_MODULES + 1)},
            clear=True,
        ):
            with self.assertRaises(drive_oidf_verifier_flow.DriverFailure) as caught:
                drive_oidf_verifier_flow.read_optional_int_env(
                    "OIDF_EXPECTED_MODULE_COUNT"
                )
        self.assertEqual(caught.exception.reason, "invalid_numeric_environment")

    def test_rejects_non_finite_numeric_environment(self) -> None:
        for value in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(value=value), mock.patch.dict(
                drive_oidf_verifier_flow.os.environ,
                {"OIDF_FLOW_DRIVER_TIMEOUT_SECONDS": value},
                clear=True,
            ):
                with self.assertRaises(
                    drive_oidf_verifier_flow.DriverFailure
                ) as caught:
                    drive_oidf_verifier_flow.read_float_env(
                        "OIDF_FLOW_DRIVER_TIMEOUT_SECONDS", 10.0, 1.0, 60.0
                    )
                self.assertEqual(caught.exception.reason, "invalid_numeric_environment")

    def test_rejects_out_of_range_numeric_environment(self) -> None:
        for value in ("0.999", "60.001"):
            with self.subTest(value=value), mock.patch.dict(
                drive_oidf_verifier_flow.os.environ,
                {"OIDF_FLOW_DRIVER_TIMEOUT_SECONDS": value},
                clear=True,
            ):
                with self.assertRaises(
                    drive_oidf_verifier_flow.DriverFailure
                ) as caught:
                    drive_oidf_verifier_flow.read_float_env(
                        "OIDF_FLOW_DRIVER_TIMEOUT_SECONDS", 10.0, 1.0, 60.0
                    )
                self.assertEqual(caught.exception.reason, "invalid_numeric_environment")

    def test_profile_driver_exits_only_at_exact_module_count(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scoped = drive_oidf_verifier_flow.DriverConfig(
                **{**config().__dict__, "result_file": str(Path(directory) / "result.json")}
            )

            def trigger_modules(
                _config: drive_oidf_verifier_flow.DriverConfig,
                triggered: set[str],
                _module_ids: tuple[str, ...],
            ) -> int:
                for index in range(11):
                    triggered.add(f"module-{index}")
                return 11

            with mock.patch.object(
                drive_oidf_verifier_flow,
                "trigger_waiting_modules",
                side_effect=trigger_modules,
            ), mock.patch.object(
                drive_oidf_verifier_flow,
                "fetch_scoped_plan",
                return_value=drive_oidf_verifier_flow.PlanScope(
                    "plan-instance-1", tuple(f"module-{index}" for index in range(11))
                ),
            ), mock.patch.object(drive_oidf_verifier_flow.time, "sleep") as sleep:
                outcome = drive_oidf_verifier_flow.run_driver(scoped, once=False)

        self.assertEqual(outcome.triggered_modules, 11)
        self.assertEqual(outcome.plan_instance_id, "plan-instance-1")
        sleep.assert_not_called()

    def test_profile_driver_rejects_trigger_count_above_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scoped = drive_oidf_verifier_flow.DriverConfig(
                **{**config().__dict__, "result_file": str(Path(directory) / "result.json")}
            )

            def trigger_modules(
                _config: drive_oidf_verifier_flow.DriverConfig,
                triggered: set[str],
                _module_ids: tuple[str, ...],
            ) -> int:
                for index in range(12):
                    triggered.add(f"module-{index}")
                return 12

            with mock.patch.object(
                drive_oidf_verifier_flow,
                "trigger_waiting_modules",
                side_effect=trigger_modules,
            ), mock.patch.object(
                drive_oidf_verifier_flow,
                "fetch_scoped_plan",
                return_value=drive_oidf_verifier_flow.PlanScope(
                    "plan-instance-1", tuple(f"module-{index}" for index in range(12))
                ),
            ):
                with self.assertRaises(drive_oidf_verifier_flow.DriverFailure) as caught:
                    drive_oidf_verifier_flow.run_driver(scoped, once=False)
        self.assertEqual(caught.exception.reason, "triggered_module_count_exceeded")

    def test_rejects_duplicate_launch_parameter(self) -> None:
        body = json.dumps(
            {
                "authorization_endpoint": "https://suite.example.test/authorize",
                "parameters": [
                    {"name": "request", "value": "first"},
                    {"name": "request", "value": "second"},
                ],
            }
        ).encode("utf-8")

        with self.assertRaises(drive_oidf_verifier_flow.DriverFailure) as caught:
            drive_oidf_verifier_flow.parse_verifier_launch_response(body)
        self.assertEqual(caught.exception.reason, "verifier_launch_duplicate_parameter")

    def test_rejects_duplicate_json_members(self) -> None:
        with self.assertRaises(drive_oidf_verifier_flow.DriverFailure) as caught:
            drive_oidf_verifier_flow.decode_json(
                b'{"status":"WAITING","status":"FINISHED"}',
                "oidf_api_invalid_json",
            )
        self.assertEqual(caught.exception.reason, "oidf_api_invalid_json")

    def test_rejects_non_standard_non_finite_json_number(self) -> None:
        with self.assertRaises(drive_oidf_verifier_flow.DriverFailure) as caught:
            drive_oidf_verifier_flow.decode_json(
                b'{"started":NaN}', "oidf_api_invalid_json"
            )
        self.assertEqual(caught.exception.reason, "oidf_api_invalid_json")

    def test_rejects_credentialed_control_plane_endpoint(self) -> None:
        unsafe = drive_oidf_verifier_flow.DriverConfig(
            **{
                **config().__dict__,
                "verifier_launch_endpoint": "https://user:pass@verifier.example/launch",
            }
        )

        with self.assertRaises(drive_oidf_verifier_flow.DriverFailure) as caught:
            drive_oidf_verifier_flow.validate_config(unsafe)
        self.assertEqual(caught.exception.reason, "invalid_verifier_launch_endpoint")

    def test_http_control_plane_requires_explicit_development_mode(self) -> None:
        with mock.patch.dict(drive_oidf_verifier_flow.os.environ, {}, clear=True):
            with self.assertRaises(drive_oidf_verifier_flow.DriverFailure):
                drive_oidf_verifier_flow.validate_http_endpoint(
                    "http://127.0.0.1:8787/authorize",
                    "invalid_authorization_endpoint",
                )
        with mock.patch.dict(
            drive_oidf_verifier_flow.os.environ,
            {"CONFORMANCE_DEV_MODE": "true"},
            clear=True,
        ):
            drive_oidf_verifier_flow.validate_http_endpoint(
                "http://127.0.0.1:8787/authorize",
                "invalid_authorization_endpoint",
            )

    def test_redirect_handler_refuses_redirects(self) -> None:
        handler = drive_oidf_verifier_flow.NoRedirectHandler()

        redirected = handler.redirect_request(
            mock.Mock(), mock.Mock(), 302, "Found", mock.Mock(), "https://other.example/"
        )

        self.assertIsNone(redirected)

    def test_authorization_call_accepts_terminal_redirect_without_following(self) -> None:
        redirect = drive_oidf_verifier_flow.urllib.error.HTTPError(
            "https://suite.example.test/authorize",
            303,
            "See Other",
            {"Location": "https://verifier.example.test/completed"},
            io.BytesIO(b""),
        )
        opener = mock.Mock()
        opener.open.side_effect = redirect
        with mock.patch.object(
            drive_oidf_verifier_flow.urllib.request,
            "build_opener",
            return_value=opener,
        ):
            drive_oidf_verifier_flow.call_authorization_endpoint_with_params(
                config(),
                "https://suite.example.test/authorize",
                {"request": "signed.request.jwt"},
                "GET",
            )

        opener.open.assert_called_once()

    def test_control_request_rejects_redirect_response(self) -> None:
        redirect = drive_oidf_verifier_flow.urllib.error.HTTPError(
            "https://suite.example.test/api/info/module",
            302,
            "Found",
            {"Location": "https://attacker.example/"},
            io.BytesIO(b""),
        )
        opener = mock.Mock()
        opener.open.side_effect = redirect
        with mock.patch.object(
            drive_oidf_verifier_flow.urllib.request,
            "build_opener",
            return_value=opener,
        ):
            with self.assertRaises(drive_oidf_verifier_flow.DriverFailure) as caught:
                drive_oidf_verifier_flow.open_request(
                    mock.Mock(), True, "oidf_api_request_failed"
                )

        self.assertEqual(caught.exception.reason, "oidf_api_request_failed")

    def test_rejects_excessively_nested_json(self) -> None:
        raw = (("[" * 100) + "0" + ("]" * 100)).encode("utf-8")
        with self.assertRaises(drive_oidf_verifier_flow.DriverFailure) as caught:
            drive_oidf_verifier_flow.decode_json(raw, "oidf_api_invalid_json")
        self.assertEqual(caught.exception.reason, "oidf_api_invalid_json")

    def test_rejects_excessive_launch_parameter_count(self) -> None:
        parameters = [
            {"name": f"parameter-{index}", "value": "value"}
            for index in range(drive_oidf_verifier_flow.MAX_LAUNCH_PARAMETERS + 1)
        ]
        with self.assertRaises(drive_oidf_verifier_flow.DriverFailure) as caught:
            drive_oidf_verifier_flow.parse_verifier_launch_parameters(parameters)
        self.assertEqual(caught.exception.reason, "verifier_launch_invalid_parameters")

    def test_rejects_excessive_aggregate_launch_parameter_size(self) -> None:
        value = "v" * drive_oidf_verifier_flow.MAX_LAUNCH_PARAMETER_BYTES
        parameters = [
            {"name": "request", "value": value},
            {"name": "request_uri", "value": value},
            {"name": "client_id", "value": "overflow"},
        ]
        with self.assertRaises(drive_oidf_verifier_flow.DriverFailure) as caught:
            drive_oidf_verifier_flow.parse_verifier_launch_parameters(parameters)
        self.assertEqual(caught.exception.reason, "verifier_launch_invalid_parameters")

    def test_scopes_plan_modules_by_name_alias_and_start_time(self) -> None:
        payload = {
            "data": [
                {
                    "_id": "plan-instance-1",
                    "planName": "oid4vp-1final-verifier-haip-test-plan",
                    "started": "2026-09-19T10:00:01Z",
                    "config": {"alias": "wrong-alias"},
                    "modules": [{"instances": ["wrong-module"]}],
                },
                {
                    "_id": "plan-instance-2",
                    "planName": "oid4vp-1final-verifier-haip-test-plan",
                    "started": "2026-09-19T10:00:02Z",
                    "config": {"alias": "oidf-vp-test-wallet"},
                    "modules": [{"instances": ["verifier-module-1", "unsafe/id"]}],
                },
            ]
        }
        scoped = config()
        scoped = drive_oidf_verifier_flow.DriverConfig(
            **{
                **scoped.__dict__,
                "started_after_epoch_seconds": 1_700_000_000.0,
            }
        )
        with mock.patch.object(
            drive_oidf_verifier_flow, "api_get_json", return_value=payload
        ) as api_get_json:
            module_ids = drive_oidf_verifier_flow.fetch_scoped_module_ids(scoped)

        self.assertEqual(module_ids, ["verifier-module-1"])
        query = api_get_json.call_args.args[1]
        self.assertIn("plan=oid4vp-1final-verifier-haip-test-plan", query)
        self.assertIn("from=", query)

    def test_rejects_ambiguous_plan_scope(self) -> None:
        plan = {
            "_id": "plan-instance-1",
            "planName": "oid4vp-1final-verifier-haip-test-plan",
            "started": "2026-09-19T10:00:02Z",
            "config": {"alias": "oidf-vp-test-wallet"},
            "modules": [],
        }
        scoped = drive_oidf_verifier_flow.DriverConfig(
            **{**config().__dict__, "started_after_epoch_seconds": 1_700_000_000.0}
        )
        with mock.patch.object(
            drive_oidf_verifier_flow,
            "api_get_json",
            return_value={"data": [plan, {**plan, "_id": "plan-instance-2"}]},
        ):
            with self.assertRaises(drive_oidf_verifier_flow.DriverFailure) as caught:
                drive_oidf_verifier_flow.fetch_scoped_plan(scoped)
        self.assertEqual(caught.exception.reason, "oidf_plan_not_unique")

    def test_rejects_plan_instance_change_while_driving(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scoped = drive_oidf_verifier_flow.DriverConfig(
                **{
                    **config().__dict__,
                    "expected_module_count": 2,
                    "result_file": str(Path(directory) / "result.json"),
                }
            )

            def trigger_one(
                _config: drive_oidf_verifier_flow.DriverConfig,
                triggered: set[str],
                module_ids: tuple[str, ...],
            ) -> int:
                triggered.add(module_ids[0])
                return 1

            scopes = [
                drive_oidf_verifier_flow.PlanScope(
                    "plan-instance-1", ("module-1",)
                ),
                drive_oidf_verifier_flow.PlanScope(
                    "plan-instance-2", ("module-2",)
                ),
            ]
            with mock.patch.object(
                drive_oidf_verifier_flow, "fetch_scoped_plan", side_effect=scopes
            ), mock.patch.object(
                drive_oidf_verifier_flow,
                "trigger_waiting_modules",
                side_effect=trigger_one,
            ), mock.patch.object(drive_oidf_verifier_flow.time, "sleep"):
                with self.assertRaises(
                    drive_oidf_verifier_flow.DriverFailure
                ) as caught:
                    drive_oidf_verifier_flow.run_driver(scoped, once=False)
        self.assertEqual(caught.exception.reason, "oidf_plan_instance_changed")

    def test_parses_suite_timestamp_with_nanosecond_precision(self) -> None:
        parsed = drive_oidf_verifier_flow.parse_oidf_time(
            "2026-09-19T10:00:01.123456789Z"
        )

        self.assertIsNotNone(parsed)


if __name__ == "__main__":
    unittest.main()
