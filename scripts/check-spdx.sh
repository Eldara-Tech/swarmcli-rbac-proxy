#!/usr/bin/env sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright © 2026 Eldara Tech
set -eu

fail=0

check_file () {
  f="$1"
  if ! head -n 20 "$f" | grep -q "SPDX-License-Identifier: AGPL-3.0-only"; then
    echo "Missing SPDX header: $f"
    fail=1
  fi
}

find . -type f \( -name '*.go' -o -name '*.sh' \) \
  -not -path './vendor/*' \
  -not -path './.git/*' \
  | while read -r f; do
      check_file "$f"
    done

exit "$fail"
