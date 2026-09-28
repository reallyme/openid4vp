#!/usr/bin/env sh
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

exec python3 "${script_dir}/assert_oidf_results.py" "$@"
