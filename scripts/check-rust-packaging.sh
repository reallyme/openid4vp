#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

check_crate_types() {
  local manifest="$1"
  local crate_types="$2"

  if [[ "$crate_types" == *"cdylib"* ]]; then
    printf '%s\n' "error: $manifest declares a cdylib; ReallyMe Identity owns the combined Wasm module"
    return 1
  fi
  if [[ "$crate_types" == *"staticlib"* || "$crate_types" == *"dylib"* ]]; then
    if [[ "$crate_types" != *"rlib"* ]]; then
      printf '%s\n' "error: $manifest declares an FFI crate-type without rlib"
      return 1
    fi
  fi
  return 0
}

failures=0

if command -v cargo >/dev/null 2>&1 && command -v jq >/dev/null 2>&1 && jq --version >/dev/null 2>&1; then
  if ! cargo_metadata="$(cargo metadata --format-version=1 --no-deps)"; then
    printf '%s\n' "Rust binary packaging policy failed: cargo metadata was unavailable."
    exit 1
  fi
  if ! package_targets="$(
    printf '%s' "${cargo_metadata}" |
      jq -r '.packages[] | .manifest_path as $manifest | .targets[] | [$manifest, (.crate_types | join(","))] | @tsv'
  )"; then
    printf '%s\n' "Rust binary packaging policy failed: cargo metadata could not be parsed."
    exit 1
  fi
  if [[ -z "${package_targets}" ]]; then
    printf '%s\n' "Rust binary packaging policy failed: cargo metadata contained no package targets."
    exit 1
  fi

  if ! forbidden_dependencies="$(
    printf '%s' "${cargo_metadata}" |
      jq -r '.packages[] | select(any(.dependencies[]; .name == "wasm-bindgen" or .package == "wasm-bindgen")) | .manifest_path'
  )"; then
    printf '%s\n' "Rust binary packaging policy failed: workspace dependencies could not be inspected."
    exit 1
  fi
  if [[ -n "${forbidden_dependencies}" ]]; then
    while IFS= read -r manifest; do
      printf '%s\n' "error: $manifest depends on wasm-bindgen; bindings belong to ReallyMe Identity"
    done <<< "${forbidden_dependencies}"
    failures=1
  fi

  if ! wasm_binary_targets="$(
    printf '%s' "${cargo_metadata}" |
      jq -r '.packages[] | select((.features | has("wasm")) and any(.targets[]; any(.kind[]; . == "bin"))) | .manifest_path'
  )"; then
    printf '%s\n' "Rust binary packaging policy failed: Wasm targets could not be inspected."
    exit 1
  fi
  if [[ -n "${wasm_binary_targets}" ]]; then
    while IFS= read -r manifest; do
      printf '%s\n' "error: $manifest combines a wasm feature with a standalone binary target"
    done <<< "${wasm_binary_targets}"
    failures=1
  fi

  while IFS= read -r tracked_artifact; do
    if [[ -n "${tracked_artifact}" ]]; then
      printf '%s\n' "error: $tracked_artifact is a standalone Wasm or npm artifact owned by ReallyMe Identity"
      failures=1
    fi
  done < <(git ls-files -- '*.wasm' 'package.json' '*/package.json')

  while IFS= read -r target; do
    manifest=${target%%	*}
    crate_types=${target#*	}
    if ! check_crate_types "$manifest" "$crate_types"; then
      failures=1
    fi
  done <<< "${package_targets}"

  if [[ "$failures" -ne 0 ]]; then
    printf '%s\n' "Rust binary packaging policy failed. See docs/packaging.md."
    exit 1
  fi

  printf '%s\n' "Rust binary packaging policy passed."
  exit 0
fi

# The fallback reads each manifest and writes diagnostics only to stdout;
# ShellCheck cannot infer that the helper never writes back to its argument.
# shellcheck disable=SC2094
while IFS= read -r manifest; do
  in_lib=0
  crate_type=""

  while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in
      "[lib]"*)
        in_lib=1
        crate_type=""
        ;;
      "["*)
        if [[ "$in_lib" -eq 1 ]]; then
          if ! check_crate_types "$manifest" "$crate_type"; then
            failures=1
          fi
        fi
        in_lib=0
        crate_type=""
        ;;
      *"crate-type"*)
        if [[ "$in_lib" -eq 1 ]]; then
          crate_type="$line"
        fi
        ;;
      *)
        if [[ "$in_lib" -eq 1 && -n "$crate_type" ]]; then
          crate_type="$crate_type $line"
        fi
        ;;
    esac
  done < "$manifest"

  if [[ "$in_lib" -eq 1 ]]; then
    if ! check_crate_types "$manifest" "$crate_type"; then
      failures=1
    fi
  fi
done < <(find . -path './target' -prune -o -name Cargo.toml -print | sort)

if [[ "$failures" -ne 0 ]]; then
  printf '%s\n' "Rust binary packaging policy failed. See docs/packaging.md."
  exit 1
fi

printf '%s\n' "Rust binary packaging policy passed."
