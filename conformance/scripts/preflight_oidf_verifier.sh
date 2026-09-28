#!/usr/bin/env sh
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -eu

require_command() {
  command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "missing required command: $command_name" >&2
    exit 69
  fi
}

require_command curl
require_command git
require_command java
require_command mvn
require_command openssl
require_command python3

java_version="$(java -version 2>&1)" || {
  echo "unable to determine java version" >&2
  exit 69
}
case "${java_version}" in
  *'version "21"'* | *'version "21.'*) ;;
  *)
    echo "java 21 is required" >&2
    exit 69
    ;;
esac

maven_version="$(mvn -version 2>&1)" || {
  echo "unable to determine maven java version" >&2
  exit 69
}
case "${maven_version}" in
  *'Java version: 21'*) ;;
  *)
    echo "maven must run with java 21" >&2
    exit 69
    ;;
esac
