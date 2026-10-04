#!/bin/sh
# stunnel does not expand environment variables: substitute the two
# non-secret values a template names, then run stunnel in the foreground.
set -eu
conf="${1:?usage: tunnel-entrypoint CONFIG}"
if [ -n "${BAO_UPSTREAM:-}" ]; then
  : "${BAO_SERVER_NAME:?set BAO_SERVER_NAME with BAO_UPSTREAM}"
  sed -e "s|@BAO_UPSTREAM@|$BAO_UPSTREAM|" -e "s|@BAO_SERVER_NAME@|$BAO_SERVER_NAME|" "$conf" > /tmp/stunnel.conf
  conf=/tmp/stunnel.conf
fi
exec stunnel "$conf"
