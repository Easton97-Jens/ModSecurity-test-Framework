#!/bin/sh
# Build the canonical approved SDK; never execute Framework smoke programs.
set -eu

: "${RUNNER_TEMP:?RUNNER_TEMP must identify the external runner work directory}"
VERIFIED_RUN_ROOT="$RUNNER_TEMP/framework-sonar-sdk"
export VERIFIED_RUN_ROOT
SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/../../lib/path-bootstrap.sh"
REPO_ROOT=$FRAMEWORK_ROOT
export REPO_ROOT
. "$CI_ROOT/lib/common.sh"

# The existing provisioner verifies origin, exact commit and submodule identities.
ci_provision_approved_modsecurity_v3_checkout "$MODSECURITY_V3_SOURCE_DIR"
MAKEFLAGS="-j$(getconf _NPROCESSORS_ONLN)"
export MAKEFLAGS
sh "$CI_ROOT/provisioning/build-v3-under-src.sh"
