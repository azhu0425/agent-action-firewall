#!/usr/bin/env sh
# Thin wrapper: scripts/verify.py is the single source of truth.
exec python "$(dirname "$0")/verify.py" "$@"
