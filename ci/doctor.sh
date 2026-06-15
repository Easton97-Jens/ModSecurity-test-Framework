#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)}"
CONNECTOR_ROOT="${CONNECTOR_ROOT:-$(pwd)}"
REPO_ROOT="$CONNECTOR_ROOT"
. "$SCRIPT_DIR/common.sh"

PYTHON_BIN="${PYTHON_BIN:-$(ci_python)}"
status=0
DOCTOR_MODE="${DOCTOR_MODE:-full}"

say() { ci_info "doctor $*"; }
blocked() { ci_blocked "$*"; status=77; }
warn() { ci_warn "$*"; }
section() {
  section_title=$1
  echo ""
  echo "$section_title:"
}
check_cmd() {
  cmd_name=$1
  if command -v "$cmd_name" >/dev/null 2>&1; then
    say "toolchain: $cmd_name ok"
  else
    blocked "toolchain missing: $cmd_name"
  fi
}

show_component() {
  label=$1
  value=$2
  if [ -n "$value" ]; then
    say "runtime: $label -> $value"
  else
    say "runtime: $label -> not found"
  fi
}

section "SOURCE-BUILD READINESS"
say "python interpreter: $PYTHON_BIN"
"$PYTHON_BIN" --version || blocked "python executable failed: $PYTHON_BIN"
if [ -x "$CONNECTOR_ROOT/.venv/bin/python" ]; then say "venv: detected $CONNECTOR_ROOT/.venv/bin/python"; else blocked "venv missing (.venv/bin/python); run make setup-dev"; fi
if ! "$PYTHON_BIN" "$FRAMEWORK_ROOT/ci/check-python-deps.py"; then blocked "missing Python dependencies for selected interpreter"; fi

for tool in git make gcc autoconf automake libtool pkg-config; do check_cmd "$tool"; done
if command -v clang >/dev/null 2>&1; then say "toolchain: clang ok (optional)"; else say "toolchain: clang missing (optional)"; fi

say "build root: $BUILD_ROOT"
mkdir -p "$BUILD_ROOT" || blocked "cannot create BUILD_ROOT: $BUILD_ROOT"
say "source root: $SOURCE_ROOT"

if detected=$(BUILD_ROOT="$BUILD_ROOT" MODSECURITY_V3_SOURCE_DIR="${MODSECURITY_V3_SOURCE_DIR:-}" FRAMEWORK_ROOT="$FRAMEWORK_ROOT" CONNECTOR_ROOT="$CONNECTOR_ROOT" sh "$FRAMEWORK_ROOT/ci/find-modsecurity-v3.sh"); then
  say "detected MODSECURITY_V3_SOURCE_DIR=$detected"
else
  if [ "$DOCTOR_MODE" = "quick" ]; then
    warn "missing ModSecurity_V3 source tree (quick mode)"
  else
    blocked "missing ModSecurity_V3 source tree"
  fi
  echo "Suggested fixes:"
  echo "- export MODSECURITY_V3_SOURCE_DIR=/path/to/ModSecurity_V3"
  echo "- OR run: make fetch-deps"
fi

if command -v git >/dev/null 2>&1; then
  if ! ci_require_https_github_repo_url "$MODSECURITY_V3_GIT_URL" MODSECURITY_V3_GIT_URL; then
    blocked "MODSECURITY_V3_GIT_URL does not satisfy HTTPS GitHub URL policy"
  fi
  if git ls-remote --heads "$MODSECURITY_V3_GIT_URL" >/dev/null 2>&1; then
    say "github reachability: ok"
  else
    blocked "github unreachable for ModSecurity fetch"
  fi
fi

if [ -d "$SOURCE_ROOT/ModSecurity_V3" ]; then
  say "sources: BUILD_ROOT-aligned ModSecurity_V3 present"
else
  if [ "$DOCTOR_MODE" = "quick" ]; then
    warn "sources missing under BUILD_ROOT (quick mode): $SOURCE_ROOT/ModSecurity_V3"
  else
    blocked "sources missing under BUILD_ROOT: $SOURCE_ROOT/ModSecurity_V3"
  fi
fi

section "OPTIONAL INSTALLED READINESS"
say "installed components are diagnostic only; source-build smokes do not require them"

APXS_BIN="${APXS_BIN:-$(ci_find_bin_multi $CI_APXS_BIN_CANDIDATES 2>/dev/null || true)}"
APACHE_BIN="${APACHE_BIN:-${APACHECTL_BIN:-$(ci_find_bin_multi $CI_APACHE_BIN_CANDIDATES 2>/dev/null || true)}}"
if [ -z "$APACHECTL_BIN" ] && [ -n "$APACHE_BIN" ]; then
  case "$(basename "$APACHE_BIN")" in
    apachectl) APACHECTL_BIN=$APACHE_BIN ;;
    *) ;;
  esac
fi
if [ -z "$APACHE_BIN" ] && [ -n "$APXS_BIN" ]; then
  APACHE_BIN=$(ci_resolve_apache_from_apxs "$APXS_BIN" 2>/dev/null || true)
fi
NGINX_BIN="${NGINX_BIN:-$(ci_find_bin_multi $CI_NGINX_BIN_CANDIDATES 2>/dev/null || true)}"

show_component apache_bin "$APACHE_BIN"
show_component apachectl_bin "$APACHECTL_BIN"
show_component apxs_bin "$APXS_BIN"
show_component nginx_bin "$NGINX_BIN"

if [ -z "$MODSECURITY_PKG_CONFIG" ] && command -v pkg-config >/dev/null 2>&1; then
  for pkg in modsecurity libmodsecurity; do
    if pkg-config --exists "$pkg"; then
      MODSECURITY_PKG_CONFIG=$pkg
      break
    fi
  done
fi

if [ -z "$MODSECURITY_LIB_DIR" ]; then
  for libdir in $CI_INSTALLED_LIB_SEARCH_DIRS; do
    if [ -f "$libdir/libmodsecurity.so" ] || [ -f "$libdir/libmodsecurity.so.3" ]; then
      MODSECURITY_LIB_DIR=$libdir
      break
    fi
  done
fi

if [ -z "$MODSECURITY_INCLUDE_DIR" ]; then
  for incdir in $CI_INSTALLED_INCLUDE_SEARCH_DIRS; do
    if [ -f "$incdir/modsecurity/modsecurity.h" ]; then
      MODSECURITY_INCLUDE_DIR=$incdir
      break
    fi
  done
fi

if [ -n "$MODSECURITY_PKG_CONFIG" ]; then
  say "runtime: modsecurity pkg-config -> $MODSECURITY_PKG_CONFIG"
else
  say "runtime: modsecurity pkg-config -> not found"
fi
show_component modsecurity_lib_dir "$MODSECURITY_LIB_DIR"
show_component modsecurity_include_dir "$MODSECURITY_INCLUDE_DIR"

apache_ready=BLOCKED
nginx_ready=BLOCKED
full_ready=BLOCKED
[ -n "$APACHE_BIN" ] && [ -n "$APXS_BIN" ] && apache_ready=READY
[ -n "$NGINX_BIN" ] && nginx_ready=READY
if [ "$apache_ready" = "READY" ] && [ "$nginx_ready" = "READY" ]; then
  full_ready=READY
elif [ "$apache_ready" = "READY" ] || [ "$nginx_ready" = "READY" ]; then
  full_ready=PARTIAL
fi
if [ -z "$MODSECURITY_PKG_CONFIG" ] && { [ -z "$MODSECURITY_LIB_DIR" ] || [ -z "$MODSECURITY_INCLUDE_DIR" ]; }; then
  apache_ready=BLOCKED
  nginx_ready=BLOCKED
  full_ready=BLOCKED
fi

echo "INSTALLED COMPONENTS:"
if [ -n "$APACHE_BIN" ]; then echo "  Apache runtime: FOUND ($APACHE_BIN)"; else echo "  Apache runtime: NOT FOUND"; fi
if [ -n "$APXS_BIN" ]; then echo "  APXS (Apache dev): FOUND ($APXS_BIN)"; else echo "  APXS (Apache dev): NOT FOUND"; fi
if [ -n "$NGINX_BIN" ]; then echo "  NGINX: FOUND ($NGINX_BIN)"; else echo "  NGINX: NOT FOUND"; fi
if [ -n "$MODSECURITY_PKG_CONFIG" ]; then
  echo "  libmodsecurity: FOUND (pkg-config:$MODSECURITY_PKG_CONFIG)"
elif [ -n "$MODSECURITY_LIB_DIR" ] && [ -n "$MODSECURITY_INCLUDE_DIR" ]; then
  echo "  libmodsecurity: FOUND (lib:$MODSECURITY_LIB_DIR include:$MODSECURITY_INCLUDE_DIR)"
else
  echo "  libmodsecurity: NOT FOUND"
fi
if [ -z "$APACHE_BIN" ] && [ -n "$APXS_BIN" ]; then
  echo "  note: apache2-dev appears installed without a detected Apache runtime binary"
fi
if [ -z "$APACHE_BIN" ] && [ -n "$APXS_BIN" ]; then
  echo "  hint: Debian/Ubuntu runtime package: apt-get install apache2 or apache2-bin"
fi

echo "SMOKE-INSTALLED READINESS:"
echo "  Apache installed smoke: $apache_ready"
echo "  NGINX installed smoke: $nginx_ready"
echo "  Full installed smoke: $full_ready"

if [ "$status" -eq 0 ]; then
  say "source-build diagnostics complete; run make smoke-all locally for authoritative runtime evidence"
else
  if [ "$DOCTOR_MODE" = "quick" ]; then
    echo "doctor: quick mode completed with source-build warnings"
  else
    echo "doctor: source-build readiness BLOCKED"
  fi
fi

exit "$status"
