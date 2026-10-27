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

# Provisioning intentionally refuses to create an absent storage parent.
# Establish both parents privately through the same physical-path admission.
assert_safe_runtime_path "$VERIFIED_RUN_ROOT" "Sonar SDK run root"
assert_safe_runtime_path "$SOURCE_ROOT" "Sonar SDK source parent"
ci_modsecurity_v3_require_fresh_destination "$VERIFIED_RUN_ROOT"
ci_modsecurity_v3_create_private_fresh_root "$VERIFIED_RUN_ROOT"
ci_modsecurity_v3_require_fresh_destination "$SOURCE_ROOT"
ci_modsecurity_v3_create_private_fresh_root "$SOURCE_ROOT"

# The existing provisioner verifies origin, exact commit and submodule identities.
ci_provision_approved_modsecurity_v3_checkout "$MODSECURITY_V3_SOURCE_DIR"
MAKEFLAGS="-j$(getconf _NPROCESSORS_ONLN)"
export MAKEFLAGS
sh "$CI_ROOT/provisioning/build-v3-under-src.sh"
