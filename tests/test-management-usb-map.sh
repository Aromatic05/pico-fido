#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${TMPDIR:-/tmp}/pico-fido-management-usb-map-$$"
trap 'rm -f "$out"' EXIT

cc -std=c11 -Wall -Wextra -Werror \
    -I"$root/src/fido" -I"$root/pico-keys-sdk/src/fs" \
    "$root/tests/management_usb_map_test.c" -o "$out"
"$out"
echo 'management capability -> USB interface map: PASS'
