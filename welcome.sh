#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright © 2026 Eldara Tech
# shellcheck shell=sh
# Display welcome banner once per shell session.
if [ -z "$_WELCOME_SHOWN" ]; then
  _WELCOME_SHOWN=1
  export _WELCOME_SHOWN
  cat <<'BANNER'

   ______       ________   ____  ____  ___   ______   ____
  / ___/ |     / / ____/  / __ \/ __ )/   | / ____/  / __ \_________  _  ____  __
  \__ \| | /| / / /      / /_/ / __  / /| |/ /      / /_/ / ___/ __ \| |/_/ / / /
 ___/ /| |/ |/ / /___   / _, _/ /_/ / ___ / /___   / ____/ /  / /_/ />  </ /_/ /
/____/ |__/|__/\____/  /_/ |_/_____/_/  |_\____/  /_/   /_/   \____/_/|_|\__, /
                                                                        /____/

  Report issues : https://github.com/Eldara-Tech/swarmcli-rbac-proxy/issues
  License       : AGPL-3.0-only
  CLI help      : swcproxy --help

BANNER
fi
