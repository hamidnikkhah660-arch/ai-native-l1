#!/bin/sh
set -eu
umask 077
mkdir -p /data
chown qfp6:qfp6 /data
exec setpriv --reuid=10001 --regid=10001 --clear-groups python3 /app/entrypoint.py
