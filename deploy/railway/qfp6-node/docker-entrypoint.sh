#!/bin/sh
set -eu
umask 077
mkdir -p /data
chown qfp6:qfp6 /data
exec gosu qfp6 python3 /app/entrypoint.py
