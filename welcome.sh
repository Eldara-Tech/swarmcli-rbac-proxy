# shellcheck shell=sh
# Display welcome banner once per shell session.
[ -n "$_WELCOME_SHOWN" ] && return 0
_WELCOME_SHOWN=1
export _WELCOME_SHOWN
cat <<'BANNER'

  SwarmCLI RBAC Proxy

  Report issues : https://github.com/Eldara-Tech/swarmcli-rbac-proxy/issues
  License       : See LICENSE file for details
  CLI help      : swcproxy --help

BANNER
