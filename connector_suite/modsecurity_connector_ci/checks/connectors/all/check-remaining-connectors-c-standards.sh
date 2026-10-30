#!/bin/sh
# Resolve test infrastructure only from the explicitly selected Framework.
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
: "${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}"
: "${CONNECTOR_REVISION:?CONNECTOR_REVISION is required explicitly}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$TEST_ROOT/ci/lib/path-bootstrap.sh"
set -eu

cc="${CC:-cc}"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$CONNECTOR_ROOT
cd "$repo_root"

command -v "$cc" >/dev/null 2>&1 || {
  echo "BLOCKED: remaining_connectors_c_standards missing C compiler: $cc"
  exit 77
}

explicit_profile=0
if [ -n "${CONNECTOR_C_STD_PROFILE:-}" ]; then
  profiles="$CONNECTOR_C_STD_PROFILE"
  explicit_profile=1
else
  profiles="c17 c23 c2y"
fi

base_files="common/src/config.c common/src/generic_mapper.c common/src/request_helpers.c common/src/response_helpers.c common/src/request_mapper_contract.c common/src/response_mapper_contract.c common/src/headers.c common/src/block_statuses.c common/src/http_status.c common/src/resource_limits.c common/src/error.c"
headers="connectors/envoy/src/envoy_modsecurity_mapper.h connectors/traefik/src/traefik_modsecurity_mapper.h connectors/lighttpd/src/lighttpd_modsecurity_mapper.h"
files="$base_files"
# These standalone test sources were previously included by the product src globs.
test_files="$TEST_ROOT/connector_suite/adapters/envoy/src/envoy_ext_authz_response_companion_test.c $TEST_ROOT/connector_suite/adapters/traefik/src/traefik_forwardauth_response_companion_test.c"
add_existing_sources() {
  for pattern in "$@"; do
    for file in $pattern; do
      if [ -f "$file" ]; then
        files="$files ${file#./}"
      fi
    done
  done
}
add_existing_sources \
  connectors/envoy/metadata.c connectors/traefik/metadata.c connectors/lighttpd/metadata.c \
  connectors/envoy/src/*.c connectors/traefik/src/*.c connectors/lighttpd/src/*.c \
  connectors/envoy/build/*.c connectors/traefik/build/*.c connectors/lighttpd/build/*.c

for f in $files $headers; do
  [ -f "$repo_root/$f" ] || { echo "BLOCKED: remaining_connectors_c_standards missing headers/source: $f"; exit 77; }
done

for f in $test_files; do
  [ -f "$f" ] || { echo "BLOCKED: remaining_connectors_c_standards missing test source: $f"; exit 77; }
done

detect_std() {
  profile=$1
  case "$profile" in
    c17)
      std=c17
      ;;
    c23)
      if "$cc" -std=c23 -E -x c /dev/null >/dev/null 2>&1; then
        std=c23
      elif "$cc" -std=c2x -E -x c /dev/null >/dev/null 2>&1; then
        std=c2x
      else
        echo "BLOCKED: remaining_connectors_c_standards compiler lacks c23/c2x"
        return 77
      fi
      ;;
    c2y|future-c)
      if "$cc" -std=c2y -E -x c /dev/null >/dev/null 2>&1; then
        std=c2y
      elif "$cc" -std=gnu2y -E -x c /dev/null >/dev/null 2>&1; then
        std=gnu2y
      else
        echo "BLOCKED: remaining_connectors_c_standards compiler lacks c2y/gnu2y"
        return 77
      fi
      ;;
    *)
      echo "ERROR: unknown remaining connector C standard profile: $profile" >&2
      return 2
      ;;
  esac
  return 0
}

run_profile() {
  profile=$1
  std=""
  detect_std "$profile" || return "$?"
  : "${RUNNER_TEMP:?RUNNER_TEMP must select an existing external output parent}"
  tmp=$(mktemp -d "$RUNNER_TEMP/remaining-connectors-standards-$profile.XXXXXX")
  compile_one() {
    src=$1
    obj=$2
    extra_include=""
    case "$src" in
      */connectors/envoy/*) extra_include="-I$repo_root/connectors/envoy" ;;
      */connectors/traefik/*) extra_include="-I$repo_root/connectors/traefik" ;;
      */connectors/lighttpd/*) extra_include="-I$repo_root/connectors/lighttpd" ;;
      *) extra_include="" ;;
    esac
    set +e
    "$cc" -std="$std" -Wall -Wextra -Werror -I"$repo_root/common/include" -I"$repo_root" $extra_include -I"$repo_root/connectors/envoy" -I"$repo_root/connectors/traefik" -I"$repo_root/connectors/lighttpd" -I"$repo_root/connectors/envoy/src" -I"$repo_root/connectors/traefik/src" -I"$repo_root/connectors/lighttpd/src" -c "$src" -o "$obj" >"$obj.out" 2>"$obj.err"
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
      return 0
    fi
    cat "$obj.err" >&2
    echo "FAIL: remaining connectors C standard check failed ($profile): $src" >&2
    return "$rc"
  }
  for f in $files; do
    compile_one "$repo_root/$f" "$tmp/$(echo "$f" | tr '/.' '__').o" || { rc=$?; rm -rf "$tmp"; return "$rc"; }
  done
  for f in $test_files; do
    compile_one "$f" "$tmp/$(basename "$f").o" || { rc=$?; rm -rf "$tmp"; return "$rc"; }
  done
  for header in $headers; do
    smoke="$tmp/$(basename "$header").smoke.c"
    obj="$tmp/$(basename "$header").smoke.o"
    cat > "$smoke" <<EOF
#include "$repo_root/$header"
int main(void) { return 0; }
EOF
    compile_one "$smoke" "$obj" || { rc=$?; rm -rf "$tmp"; return "$rc"; }
  done
  rm -rf "$tmp"
  echo "PASS: remaining connectors C standard check ($profile)"
  return 0
}

overall_rc=0
for profile in $profiles; do
  set +e
  run_profile "$profile"
  rc=$?
  set -e
  if [ "$rc" -eq 77 ]; then
    echo "SKIPPED/BLOCKED: remaining connectors C standard profile $profile"
    if [ "$explicit_profile" -eq 1 ]; then
      exit 77
    fi
    continue
  fi
  if [ "$rc" -ne 0 ]; then
    overall_rc=$rc
  fi
done
exit "$overall_rc"
