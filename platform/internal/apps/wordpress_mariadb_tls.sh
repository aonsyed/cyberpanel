#!/bin/sh
# WP-CLI's import option filter drops MariaDB's peer-verification flag.
# Keep defaults disabled and enforce verification at the actual client entry.
if [ "$1" = "--no-defaults" ]; then shift; fi
exec /usr/bin/mariadb --no-defaults --ssl=1 --ssl-verify-server-cert=1 "$@"
