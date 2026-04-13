#!/bin/sh
# shellcheck shell=sh
# Display welcome banner once per shell session.
if [ -z "$_WELCOME_SHOWN" ]; then
  _WELCOME_SHOWN=1
  export _WELCOME_SHOWN
  cat <<'BANNER'

  SwarmCLI RBAC Proxy

  Report issues : https://github.com/Eldara-Tech/swarmcli-rbac-proxy/issues
  License       : See repository for details
  CLI help      : swcproxy --help

BANNER
fi
