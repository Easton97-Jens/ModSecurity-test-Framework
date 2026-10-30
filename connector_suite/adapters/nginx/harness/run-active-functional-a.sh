#!/bin/sh
# Exactly two inventoried host cases: Phase-4 callback enabled and disabled.
set -eu
SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
NGINX_FUNCTIONAL_SCOPE=selected-phase4
export NGINX_FUNCTIONAL_SCOPE
exec /usr/bin/python3 -I "$SCRIPT_DIR/run_github_hosted_functional_a.py"
