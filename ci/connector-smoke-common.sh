#!/bin/sh

CONNECTOR_SMOKE_SCRIPT_DIR="${CONNECTOR_SMOKE_SCRIPT_DIR:-$(CDPATH= cd "$(dirname "$0")" && pwd)}"
FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-$(CDPATH= cd "$CONNECTOR_SMOKE_SCRIPT_DIR/.." && pwd)}"

if [ -n "${CONNECTOR_ROOT:-}" ]; then
    CONNECTOR_ROOT=$(CDPATH= cd "$CONNECTOR_ROOT" && pwd)
elif [ -d "$FRAMEWORK_ROOT/../../connectors" ]; then
    CONNECTOR_ROOT=$(CDPATH= cd "$FRAMEWORK_ROOT/../.." && pwd)
else
    CONNECTOR_ROOT=$(pwd)
fi

. "$CONNECTOR_SMOKE_SCRIPT_DIR/common.sh"

RESULTS_DIR="${RESULTS_DIR:-$BUILD_ROOT/results}"
PYTHON_BIN="${PYTHON:-$(ci_python)}"

connector_smoke_require_src_path() {
    path=$1
    label=$2
    assert_safe_runtime_path "$path" "$label" || exit 77
}

connector_smoke_require_runtime_path() {
    path=$1
    label=$2
    assert_safe_runtime_path "$path" "$label" || exit 77
}

connector_smoke_require_build_path() {
    path=$1
    label=$2
    assert_safe_runtime_path "$path" "$label" || exit 77
    case "$path" in
        "$BUILD_ROOT"|"$BUILD_ROOT"/*) return 0 ;;
        *) echo "BLOCKED: $label must be under BUILD_ROOT: $path" >&2; exit 77 ;;
    esac
}

connector_smoke_require_results_path() {
    path=$1
    label=$2
    assert_safe_runtime_path "$path" "$label" || exit 77
    case "$path" in
        "$BUILD_ROOT"|"$BUILD_ROOT"/*) return 0 ;;
        *) echo "BLOCKED: $label must be under BUILD_ROOT: $path" >&2; exit 77 ;;
    esac
}

connector_smoke_require_log_path() {
    path=$1
    label=$2
    assert_safe_runtime_path "$path" "$label" || exit 77
    case "$path" in
        "$BUILD_ROOT"|"$BUILD_ROOT"/*) return 0 ;;
        *) echo "BLOCKED: $label must be under BUILD_ROOT: $path" >&2; exit 77 ;;
    esac
}

connector_smoke_validate_roots() {
    connector_smoke_require_src_path "$SOURCE_ROOT" SOURCE_ROOT
    connector_smoke_require_runtime_path "$BUILD_ROOT" BUILD_ROOT
    connector_smoke_require_runtime_path "$TMP_ROOT" TMP_ROOT
    connector_smoke_require_runtime_path "$RESULTS_DIR" RESULTS_DIR
    connector_smoke_require_runtime_path "$LOG_ROOT" LOG_ROOT
    [ -d "$CONNECTOR_ROOT/connectors" ] || {
        echo "BLOCKED: CONNECTOR_ROOT does not contain connectors/: $CONNECTOR_ROOT" >&2
        exit 77
    }
    command -v "$PYTHON_BIN" >/dev/null 2>&1 || {
        echo "BLOCKED: missing Python interpreter: $PYTHON_BIN" >&2
        exit 77
    }
    mkdir -p "$RESULTS_DIR" "$TMP_ROOT" "$LOG_ROOT"
}

connector_smoke_is_global_runtime_path() {
    path=$1
    case "$path" in
        /usr|/usr/*|/usr/local|/usr/local/*|/opt|/opt/*|/bin|/bin/*|/sbin|/sbin/*)
            return 0
            ;;
        *) return 1 ;;
    esac
}

connector_smoke_local_binary_path_ok() {
    path=$1
    case "$path" in
        /*) ;;
        *) return 1 ;;
    esac
    connector_smoke_is_global_runtime_path "$path" && return 1
    [ -f "$path" ] || return 1
    [ -x "$path" ] || return 1
    return 0
}

connector_smoke_require_local_binary_path() {
    path=$1
    label=${2:-runtime binary}
    case "$path" in
        /*) ;;
        *)
            echo "BLOCKED: $label must be an explicit absolute local path, not a PATH lookup: $path" >&2
            return 77
            ;;
    esac
    if connector_smoke_is_global_runtime_path "$path"; then
        echo "BLOCKED: $label must not point at a global system path: $path" >&2
        return 77
    fi
    if [ ! -f "$path" ] || [ ! -x "$path" ]; then
        echo "BLOCKED: $label is not executable: $path" >&2
        return 77
    fi
    return 0
}

connector_smoke_runtime_env_was_set() {
    env_var=$1
    flag_var="${env_var}_WAS_SET"
    flag_value=$(eval "printf '%s' \"\${$flag_var:-}\"")
    [ "$flag_value" = "1" ]
}

connector_smoke_connector_name_for_env_var() {
    case "$1" in
        ENVOY_BIN) printf '%s\n' envoy ;;
        TRAEFIK_BIN) printf '%s\n' traefik ;;
        LIGHTTPD_BIN) printf '%s\n' lighttpd ;;
        *) printf '%s\n' "" ;;
    esac
}

connector_smoke_connector_lookup_roots() {
    case "$1" in
        envoy)
            printf '%s\n' \
                "${ENVOY_COMPONENT_ROOT:-}" \
                "${ENVOY_RUNTIME_ROOT:-}" \
                "${ENVOY_CONFIG_ROOT:-}" \
                "${ENVOY_RESULT_ROOT:-}"
            ;;
        traefik)
            printf '%s\n' \
                "${TRAEFIK_COMPONENT_ROOT:-}" \
                "${TRAEFIK_RUNTIME_ROOT:-}" \
                "${TRAEFIK_CONFIG_ROOT:-}" \
                "${TRAEFIK_RESULT_ROOT:-}"
            ;;
        lighttpd)
            printf '%s\n' \
                "${LIGHTTPD_COMPONENT_ROOT:-}" \
                "${LIGHTTPD_RUNTIME_ROOT:-}" \
                "${LIGHTTPD_CONFIG_ROOT:-}" \
                "${LIGHTTPD_RESULT_ROOT:-}"
            ;;
    esac
}

connector_smoke_default_verified_roots() {
    seen_default_roots=
    for base in \
        "${RUNNER_TEMP:-}" \
        "${TMPDIR:-}" \
        /tmp \
        /var/tmp
    do
        [ -n "$base" ] || continue
        for root in \
            "$base/ModSecurity-conector-verified" \
            "$base/ModSecurity-conector-verified/component-cache" \
            "$base/ModSecurity-conector-verified/build" \
            "$base/ModSecurity-conector-verified/src"
        do
            case "
$seen_default_roots
" in
                *"
$root
"*) continue ;;
            esac
            seen_default_roots="${seen_default_roots}
$root"
            printf '%s\n' "$root"
        done
    done
}

find_runtime_binary_in_root() {
    root=$1
    binary_name=$2
    [ -n "$root" ] || return 1
    [ -d "$root" ] || return 1
    case "$root" in
        /usr|/usr/*|/usr/local|/usr/local/*|/opt|/opt/*|/bin|/bin/*|/sbin|/sbin/*)
            return 1
            ;;
    esac
    for candidate in \
        "$root/$binary_name" \
        "$root/bin/$binary_name" \
        "$root/sbin/$binary_name" \
        "$root/runtime/$binary_name" \
        "$root/runtime/bin/$binary_name" \
        "$root/$binary_name/bin/$binary_name" \
        "$root/$binary_name/sbin/$binary_name"
    do
        if [ -f "$candidate" ] && [ -x "$candidate" ] && ! connector_smoke_is_global_runtime_path "$candidate"; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    find "$root" -maxdepth 6 -type f -name "$binary_name" -perm /111 2>/dev/null | while IFS= read -r candidate; do
        if ! connector_smoke_is_global_runtime_path "$candidate"; then
            printf '%s\n' "$candidate"
            break
        fi
    done | sed -n '1p'
}

find_runtime_binary() {
    env_var=$1
    binary_name=$2
    env_value=$(eval "printf '%s' \"\${$env_var:-}\"")
    connector=$(connector_smoke_connector_name_for_env_var "$env_var")
    if [ -n "$env_value" ]; then
        if connector_smoke_runtime_env_was_set "$env_var"; then
            connector_smoke_require_local_binary_path "$env_value" "$env_var" || return 1
            printf '%s\n' "$env_value"
            return 0
        fi
        if connector_smoke_local_binary_path_ok "$env_value"; then
            printf '%s\n' "$env_value"
            return 0
        fi
    fi

    for root in \
        $(connector_smoke_connector_lookup_roots "$connector") \
        "${CONNECTOR_COMPONENT_CACHE:-}" \
        "${VERIFIED_COMPONENT_CACHE:-}" \
        "${VERIFIED_BUILD_ROOT:-}" \
        "${BUILD_ROOT:-}" \
        "${VERIFIED_RUN_ROOT:-}" \
        "${SOURCE_ROOT:-}" \
        $(connector_smoke_default_verified_roots)
    do
        found=$(find_runtime_binary_in_root "$root" "$binary_name" || true)
        if [ -n "$found" ]; then
            printf '%s\n' "$found"
            return 0
        fi
    done
    return 1
}

require_local_binary() {
    env_var=$1
    binary_name=$2
    find_runtime_binary "$env_var" "$binary_name"
}

connector_smoke_runtime_lookup_roots_args() {
    connector=${1:-}
    seen_roots=
    for root in \
        $(connector_smoke_connector_lookup_roots "$connector") \
        "${CONNECTOR_COMPONENT_CACHE:-}" \
        "${VERIFIED_COMPONENT_CACHE:-}" \
        "${VERIFIED_BUILD_ROOT:-}" \
        "${BUILD_ROOT:-}" \
        "${VERIFIED_RUN_ROOT:-}" \
        "${SOURCE_ROOT:-}" \
        $(connector_smoke_default_verified_roots)
    do
        [ -n "$root" ] || continue
        case "
$seen_roots
" in
            *"
$root
"*) continue ;;
        esac
        seen_roots="${seen_roots}
$root"
        printf '%s\n' "--runtime-lookup-root"
        printf '%s\n' "$root"
    done
}

connector_smoke_decision_backend_value() {
    connector=${1:-}
    connector_backend=
    case "$connector" in
        envoy) connector_backend="${ENVOY_DECISION_BACKEND:-}" ;;
        traefik) connector_backend="${TRAEFIK_DECISION_BACKEND:-}" ;;
        lighttpd) connector_backend="${LIGHTTPD_DECISION_BACKEND:-}" ;;
    esac
    if [ -n "$connector_backend" ]; then
        printf '%s\n' "$connector_backend"
        return 0
    fi
    printf '%s\n' "${DECISION_BACKEND:-simple}"
}

connector_smoke_normalize_decision_backend() {
    backend=${1:-simple}
    case "$backend" in
        ""|simple|decision-service|local-decision-service)
            printf '%s\n' simple
            ;;
        libmodsecurity)
            printf '%s\n' libmodsecurity
            ;;
        *)
            return 1
            ;;
    esac
}

connector_smoke_modsecurity_rule_file() {
    case "${MODSECURITY_RULESET:-targeted}:${MODSECURITY_SMOKE_CASE:-targeted}" in
        targeted:request_body)
            printf '%s\n' "${MODSECURITY_REQUEST_BODY_SMOKE_RULE_FILE:-$CONNECTOR_ROOT/common/rules/modsecurity_request_body_smoke.conf}"
            ;;
        *)
            printf '%s\n' "${MODSECURITY_TARGETED_SMOKE_RULE_FILE:-$CONNECTOR_ROOT/common/rules/modsecurity_targeted_smoke.conf}"
            ;;
    esac
}

connector_smoke_modsecurity_rule_id() {
    case "${MODSECURITY_RULESET:-targeted}:${MODSECURITY_SMOKE_CASE:-targeted}" in
        crs:*) printf '%s\n' "" ;;
        targeted:request_body) printf '%s\n' "1000002" ;;
        *) printf '%s\n' "1000001" ;;
    esac
}

connector_smoke_modsecurity_missing() {
    CONNECTOR_SMOKE_MODSECURITY_MISSING_REASON=$1
    CONNECTOR_SMOKE_MODSECURITY_MISSING_DEPENDENCY=${2:-libmodsecurity}
    export CONNECTOR_SMOKE_MODSECURITY_MISSING_REASON CONNECTOR_SMOKE_MODSECURITY_MISSING_DEPENDENCY
    return 1
}

connector_smoke_resolve_modsecurity_backend() {
    rule_file=${1:-${MODSECURITY_TARGETED_SMOKE_RULE_FILE:-}}
    [ -n "$rule_file" ] || connector_smoke_modsecurity_missing \
        "modsecurity targeted smoke rule file is not configured" \
        "modsecurity targeted smoke rule"

    export CONNECTOR_COMPONENT_CACHE VERIFIED_COMPONENT_CACHE VERIFIED_BUILD_ROOT
    export BUILD_ROOT VERIFIED_RUN_ROOT TMP_ROOT LOG_ROOT SOURCE_ROOT
    export MODSECURITY_SOURCE_DIR MODSECURITY_V3_SOURCE_DIR MODSECURITY_V3_ROOT
    export MODSECURITY_INCLUDE_DIR MODSECURITY_LIB_DIR MODSECURITY_LIB_FILE
    export MODSECURITY_PKG_CONFIG_PATH MODSECURITY_PREFIX MODSECURITY_MANIFEST

    if ! resolved=$("$PYTHON_BIN" - "$rule_file" <<'PY' 2>&1
import json
import os
import sys
from pathlib import Path

rule_file = Path(sys.argv[1])
if not rule_file.is_file():
    raise SystemExit(f"modsecurity targeted smoke rule file missing: {rule_file}")

system_roots = (
    "/usr",
    "/usr/local",
    "/opt",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
)


def env_path(name: str) -> Path | None:
    value = os.environ.get(name, "")
    return Path(value) if value else None


def under(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def is_system_path(path: Path) -> bool:
    text = str(path)
    return any(text == root or text.startswith(f"{root}/") for root in system_roots)


allowed_roots: list[Path] = []


def add_unique_path(target: list[Path], path: Path | None) -> None:
    if path is None or not path.is_absolute():
        return
    text = str(path)
    if text not in {str(existing) for existing in target}:
        target.append(path)


for name in (
    "CONNECTOR_COMPONENT_CACHE",
    "VERIFIED_COMPONENT_CACHE",
    "VERIFIED_BUILD_ROOT",
    "BUILD_ROOT",
    "VERIFIED_RUN_ROOT",
    "TMP_ROOT",
    "LOG_ROOT",
    "SOURCE_ROOT",
    "MODSECURITY_SOURCE_DIR",
    "MODSECURITY_V3_SOURCE_DIR",
    "MODSECURITY_V3_ROOT",
    "XDG_CACHE_HOME",
):
    value = os.environ.get(name, "")
    if value:
        add_unique_path(allowed_roots, Path(value))
for literal in ("/tmp", "/var/tmp"):
    add_unique_path(allowed_roots, Path(literal))
for base_text in (
    os.environ.get("RUNNER_TEMP", ""),
    os.environ.get("TMPDIR", ""),
    "/tmp",
    "/var/tmp",
):
    if not base_text:
        continue
    verified_root = Path(base_text) / "ModSecurity-conector-verified"
    add_unique_path(allowed_roots, verified_root)
    add_unique_path(allowed_roots, verified_root / "component-cache")


def is_allowed_local(path: Path) -> bool:
    if not path.is_absolute() or is_system_path(path):
        return False
    return any(under(path, root) for root in allowed_roots)


def reject_if_not_local(path: Path, label: str) -> None:
    if not is_allowed_local(path):
        raise SystemExit(f"{label} must be a local common.sh-managed path, not a system/PATH fallback: {path}")


def find_lib(lib_dir: Path) -> Path | None:
    for name in ("libmodsecurity.so", "libmodsecurity.so.3"):
        candidate = lib_dir / name
        if candidate.exists():
            return candidate
    for candidate in sorted(lib_dir.glob("libmodsecurity.so*")):
        if candidate.exists():
            return candidate
    return None


def candidate_ok(data: dict[str, str]) -> bool:
    include_dir = Path(data.get("include_dir", ""))
    lib_dir = Path(data.get("lib_dir", ""))
    lib_file = Path(data.get("lib_file", "")) if data.get("lib_file") else find_lib(lib_dir)
    if not include_dir or not lib_dir or not lib_file:
        return False
    for path, label in (
        (include_dir, "MODSECURITY_INCLUDE_DIR"),
        (lib_dir, "MODSECURITY_LIB_DIR"),
        (lib_file, "MODSECURITY_LIB_FILE"),
    ):
        reject_if_not_local(path, label)
    required_headers = (
        include_dir / "modsecurity/modsecurity.h",
        include_dir / "modsecurity/rules_set.h",
        include_dir / "modsecurity/transaction.h",
    )
    return all(path.is_file() for path in required_headers) and lib_file.exists()


def emit(data: dict[str, str]) -> None:
    include_dir = Path(data["include_dir"])
    lib_dir = Path(data["lib_dir"])
    lib_file = Path(data.get("lib_file", "")) if data.get("lib_file") else find_lib(lib_dir)
    pkg_config_path = Path(data.get("pkg_config_path", "")) if data.get("pkg_config_path") else None
    prefix = data.get("prefix", "")
    manifest = data.get("manifest", "")
    if pkg_config_path and pkg_config_path.exists():
        reject_if_not_local(pkg_config_path, "MODSECURITY_PKG_CONFIG_PATH")
    else:
        pkg_config_path = None
    print(f"MODSECURITY_INCLUDE_DIR={include_dir}")
    print(f"MODSECURITY_LIB_DIR={lib_dir}")
    print(f"MODSECURITY_LIB_FILE={lib_file}")
    print(f"MODSECURITY_PKG_CONFIG_PATH={pkg_config_path or ''}")
    print(f"MODSECURITY_PREFIX={prefix}")
    print(f"MODSECURITY_MANIFEST={manifest}")


env_include = env_path("MODSECURITY_INCLUDE_DIR")
env_lib_dir = env_path("MODSECURITY_LIB_DIR")
env_lib_file = env_path("MODSECURITY_LIB_FILE")
if env_include or env_lib_dir or env_lib_file:
    if not env_include:
        raise SystemExit("MODSECURITY_INCLUDE_DIR is required when overriding local libmodsecurity paths")
    if not env_lib_dir and not env_lib_file:
        raise SystemExit("MODSECURITY_LIB_DIR or MODSECURITY_LIB_FILE is required when overriding local libmodsecurity paths")
    if env_lib_file and not env_lib_dir:
        env_lib_dir = env_lib_file.parent
    data = {
        "include_dir": str(env_include),
        "lib_dir": str(env_lib_dir),
        "lib_file": str(env_lib_file or ""),
        "pkg_config_path": os.environ.get("MODSECURITY_PKG_CONFIG_PATH", ""),
        "prefix": os.environ.get("MODSECURITY_PREFIX", ""),
        "manifest": os.environ.get("MODSECURITY_MANIFEST", ""),
    }
    if not candidate_ok(data):
        raise SystemExit("local libmodsecurity override is incomplete: headers and library are required")
    emit(data)
    raise SystemExit(0)

candidates: list[dict[str, str]] = []
seen_manifests: set[Path] = set()


def add_manifest_candidate(manifest: Path) -> None:
    if manifest in seen_manifests:
        return
    seen_manifests.add(manifest)
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except Exception:
        return
    data["manifest"] = str(manifest)
    candidates.append(data)


def add_prefix_candidate(prefix: Path) -> None:
    candidates.append({
        "include_dir": str(prefix / "include"),
        "lib_dir": str(prefix / "lib"),
        "lib_file": str(prefix / "lib/libmodsecurity.so"),
        "pkg_config_path": str(prefix / "lib/pkgconfig"),
        "prefix": str(prefix),
        "manifest": "",
    })


search_roots: list[Path] = []
for name in (
    "CONNECTOR_COMPONENT_CACHE",
    "VERIFIED_COMPONENT_CACHE",
    "VERIFIED_BUILD_ROOT",
    "BUILD_ROOT",
    "VERIFIED_RUN_ROOT",
    "TMP_ROOT",
    "LOG_ROOT",
    "SOURCE_ROOT",
):
    value = os.environ.get(name, "")
    if value:
        add_unique_path(search_roots, Path(value))
for base_text in (
    os.environ.get("RUNNER_TEMP", ""),
    os.environ.get("TMPDIR", ""),
    "/tmp",
    "/var/tmp",
):
    if not base_text:
        continue
    verified_root = Path(base_text) / "ModSecurity-conector-verified"
    add_unique_path(search_roots, verified_root)
    add_unique_path(search_roots, verified_root / "component-cache")

cache_roots: list[Path] = []
for root in search_roots:
    add_unique_path(cache_roots, root)
    add_unique_path(cache_roots, root / "component-cache")
    if root.name in {"build", "logs", "tmp", "src", "sources"}:
        add_unique_path(cache_roots, root.parent / "component-cache")
    if root.name == "component-cache":
        add_unique_path(cache_roots, root)

for cache in cache_roots:
    for manifest in sorted((cache / "builds/modsecurity").glob("*/manifest.json"), key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True):
        if manifest in seen_manifests:
            continue
        add_manifest_candidate(manifest)
    for prefix in sorted((cache / "prefix/modsecurity").glob("*"), key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True):
        add_prefix_candidate(prefix)

for candidate in candidates:
    try:
        ok = candidate_ok(candidate)
    except SystemExit:
        continue
    if ok:
        emit(candidate)
        raise SystemExit(0)

raise SystemExit("local libmodsecurity headers/library not available in common.sh-managed component caches")
PY
    ); then
        connector_smoke_modsecurity_missing "$resolved" "libmodsecurity"
        return 1
    fi

    MODSECURITY_INCLUDE_DIR=$(printf '%s\n' "$resolved" | sed -n 's/^MODSECURITY_INCLUDE_DIR=//p')
    MODSECURITY_LIB_DIR=$(printf '%s\n' "$resolved" | sed -n 's/^MODSECURITY_LIB_DIR=//p')
    MODSECURITY_LIB_FILE=$(printf '%s\n' "$resolved" | sed -n 's/^MODSECURITY_LIB_FILE=//p')
    MODSECURITY_PKG_CONFIG_PATH=$(printf '%s\n' "$resolved" | sed -n 's/^MODSECURITY_PKG_CONFIG_PATH=//p')
    MODSECURITY_PREFIX=$(printf '%s\n' "$resolved" | sed -n 's/^MODSECURITY_PREFIX=//p')
    MODSECURITY_MANIFEST=$(printf '%s\n' "$resolved" | sed -n 's/^MODSECURITY_MANIFEST=//p')
    MODSECURITY_TARGETED_SMOKE_RULE_FILE=$rule_file
    export MODSECURITY_INCLUDE_DIR MODSECURITY_LIB_DIR MODSECURITY_LIB_FILE
    export MODSECURITY_PKG_CONFIG_PATH MODSECURITY_PREFIX MODSECURITY_MANIFEST
    export MODSECURITY_TARGETED_SMOKE_RULE_FILE
    return 0
}

resolve_evidence_root() {
    connector=$1
    connector_result_root=
    if [ -n "${EVIDENCE_ROOT:-}" ]; then
        printf '%s\n' "$EVIDENCE_ROOT"
        return 0
    fi
    case "$connector" in
        envoy) connector_result_root=${ENVOY_RESULT_ROOT:-} ;;
        traefik) connector_result_root=${TRAEFIK_RESULT_ROOT:-} ;;
        lighttpd) connector_result_root=${LIGHTTPD_RESULT_ROOT:-} ;;
    esac
    if [ -n "$connector_result_root" ]; then
        printf '%s\n' "$connector_result_root"
        return 0
    fi
    if [ -n "${VERIFIED_RUN_ROOT:-}" ]; then
        printf '%s/%s-smoke\n' "$VERIFIED_RUN_ROOT" "$connector"
        return 0
    fi
    printf '%s/results/%s-smoke\n' "$BUILD_ROOT" "$connector"
}

resolve_log_root() {
    connector=$1
    evidence_root=$2
    connector_log_root=
    if [ -n "${LOG_DIR:-}" ]; then
        printf '%s\n' "$LOG_DIR"
        return 0
    fi
    case "$connector" in
        envoy) connector_log_root=${ENVOY_LOG_ROOT:-} ;;
        traefik) connector_log_root=${TRAEFIK_LOG_ROOT:-} ;;
        lighttpd) connector_log_root=${LIGHTTPD_LOG_ROOT:-} ;;
    esac
    if [ -n "$connector_log_root" ]; then
        printf '%s\n' "$connector_log_root"
        return 0
    fi
    printf '%s/logs\n' "$evidence_root"
}

ensure_runtime_dirs() {
    evidence_root=${1:-}
    connector_smoke_validate_roots
    if [ -n "$evidence_root" ]; then
        connector_smoke_require_runtime_path "$evidence_root" EVIDENCE_ROOT
        mkdir -p "$evidence_root"
    fi
}

write_blocked_result() {
    connector=$1
    integration_mode=$2
    skipped_reason=$3
    missing_dependency=$4
    architecture_decision=${5:-}
    resolved_runtime_binary=${6:-}
    runtime_binary_env_var=${7:-}
    runtime_binary_name=${8:-}
    decision_backend=$(connector_smoke_decision_backend_value "$connector")
    if decision_backend=$(connector_smoke_normalize_decision_backend "$decision_backend" 2>/dev/null); then
        :
    else
        decision_backend=${DECISION_BACKEND:-simple}
    fi
    modsecurity_rule_file=$(connector_smoke_modsecurity_rule_file)
    evidence_root=$(resolve_evidence_root "$connector")
    log_dir=$(resolve_log_root "$connector" "$evidence_root")
    decision_log_path=
    if [ "$decision_backend" = "libmodsecurity" ]; then
        decision_log_path="$log_dir/modsecurity-decision.log"
        if [ "${MODSECURITY_RULESET:-targeted}" = "crs" ]; then
            decision_log_path="$log_dir/crs-decision.log"
        elif [ "${MODSECURITY_SMOKE_CASE:-targeted}" = "request_body" ]; then
            decision_log_path="$log_dir/request-body-decision.log"
        fi
    fi
    writer="$CONNECTOR_ROOT/common/scripts/write_smoke_result.py"
    starter_available=false
    if connector_smoke_starter_available "$connector"; then
        starter_available=true
    fi

    ensure_runtime_dirs "$evidence_root"
    connector_smoke_require_runtime_path "$log_dir" LOG_DIR
    mkdir -p "$log_dir"
    [ -f "$writer" ] || {
        echo "BLOCKED: common smoke result writer missing: $writer" >&2
        exit 77
    }
    lookup_args=$(connector_smoke_runtime_lookup_roots_args "$connector")

    # shellcheck disable=SC2086
    "$PYTHON_BIN" "$writer" \
        --connector "$connector" \
        --integration-mode "$integration_mode" \
        --status BLOCKED \
        --exit-code 77 \
        --runtime-verified false \
        --response-body-verified false \
        --allowed-request-status not-run \
        --blocked-request-status not-run \
        --evidence-root "$evidence_root" \
        --results-dir "$RESULTS_DIR" \
        --connector-root "$CONNECTOR_ROOT" \
        --source-root "$SOURCE_ROOT" \
        --build-root "$BUILD_ROOT" \
        --tmp-root "$TMP_ROOT" \
        --log-root "$LOG_ROOT" \
        --log-dir "$log_dir" \
        --harness-path "${HARNESS_PATH:-}" \
        --skipped-reason "$skipped_reason" \
        --resolved-runtime-binary "$resolved_runtime_binary" \
        --runtime-binary-env-var "$runtime_binary_env_var" \
        --runtime-binary-name "$runtime_binary_name" \
        --starter-checks-available "$starter_available" \
        --missing-dependency "$missing_dependency" \
        --decision-backend "$decision_backend" \
        --modsecurity-ruleset "${MODSECURITY_RULESET:-targeted}" \
        --modsecurity-smoke-case "${MODSECURITY_SMOKE_CASE:-targeted}" \
        --crs-smoke-case "${CRS_SMOKE_CASE:-minimal}" \
        --modsecurity-backend-verified false \
        --modsecurity-rule-file "$modsecurity_rule_file" \
        --modsecurity-rule-id "$(connector_smoke_modsecurity_rule_id)" \
        --modsecurity-rule-loaded false \
        --request-body-smoke-verified false \
        --request-body-access-enabled false \
        --request-body-rule-file "$([ "${MODSECURITY_SMOKE_CASE:-targeted}" = "request_body" ] && printf '%s' "$modsecurity_rule_file" || printf '')" \
        --request-body-rule-id "$([ "${MODSECURITY_SMOKE_CASE:-targeted}" = "request_body" ] && printf '1000002' || printf '')" \
        --request-body-rule-loaded false \
        --request-method "$([ "${MODSECURITY_SMOKE_CASE:-targeted}" = "request_body" ] && printf 'POST' || printf '')" \
        --blocked-body-marker "$([ "${MODSECURITY_SMOKE_CASE:-targeted}" = "request_body" ] && printf 'modsec-request-body-block' || printf '')" \
        --intervention-status not-run \
        --decision-log-path "$decision_log_path" \
        --architecture-decision "$architecture_decision" \
        --crs-repo-url "${CRS_REPO_URL:-}" \
        --crs-git-ref "${CRS_GIT_REF:-}" \
        --crs-source-dir "${CRS_SOURCE_DIR:-}" \
        --crs-runtime-dir "${CRS_RUNTIME_DIR:-}" \
        --crs-version "" \
        --crs-minimal-smoke-verified false \
        --crs-secondary-smoke-verified false \
        $lookup_args
}

connector_skip_missing_dependency() {
    connector=$1
    integration_mode=$2
    skipped_reason=$3
    missing_dependency=$4
    architecture_decision=${5:-}
    resolved_runtime_binary=${6:-}
    runtime_binary_env_var=${7:-}
    runtime_binary_name=${8:-}
    write_blocked_result "$connector" "$integration_mode" "$skipped_reason" "$missing_dependency" "$architecture_decision" "$resolved_runtime_binary" "$runtime_binary_env_var" "$runtime_binary_name"
    echo "$connector runtime smoke: BLOCKED - $skipped_reason"
    echo "Runtime not verified"
    echo "Evidence root: $(resolve_evidence_root "$connector")"
    exit 77
}

connector_smoke_starter_available() {
    connector=$1
    if [ -f "$CONNECTOR_ROOT/connectors/$connector/Makefile" ]; then
        return 0
    fi
    if [ -d "$CONNECTOR_ROOT/connectors/$connector/build" ]; then
        return 0
    fi
    return 1
}

connector_smoke_write_evidence() {
    connector=$1
    status=$2
    exit_code=$3
    runtime_status=$4
    reason=$5
    harness_path=$6
    results_jsonl="$RESULTS_DIR/$connector-results.jsonl"
    summary_json="$RESULTS_DIR/$connector-summary.json"
    summary_text="$RESULTS_DIR/$connector-summary.txt"
    starter_available=false
    if connector_smoke_starter_available "$connector"; then
        starter_available=true
    fi
    "$PYTHON_BIN" - "$results_jsonl" "$summary_json" "$summary_text" \
        "$connector" "$status" "$exit_code" "$runtime_status" "$reason" \
        "$harness_path" "$starter_available" "$CONNECTOR_ROOT" "$SOURCE_ROOT" \
        "$BUILD_ROOT" "$RESULTS_DIR" "$TMP_ROOT" "$LOG_ROOT" <<'PY'
import json
import sys
from datetime import datetime, timezone

(
    results_jsonl,
    summary_json,
    summary_text,
    connector,
    status,
    exit_code_text,
    runtime_status,
    reason,
    harness_path,
    starter_available_text,
    connector_root,
    source_root,
    build_root,
    results_dir,
    tmp_root,
    log_root,
) = sys.argv[1:]

exit_code = int(exit_code_text)
starter_available = starter_available_text == "true"
now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
note = "Build/self-test starter evidence is available via make connector-starter-checks but is not runtime smoke evidence."
record = {
    "connector": connector,
    "test_type": "runtime-smoke",
    "status": status,
    "exit_code": exit_code,
    "runtime_verified": False,
    "runtime_status": runtime_status,
    "response_body_verified": False,
    "reason": reason,
    "starter_checks_available": starter_available,
    "installs_global_artifacts": False,
    "harness_path": harness_path,
    "generated_at": now,
    "note": note,
}
counts = {"PASS": 0, "FAIL": 0, "BLOCKED": 0, "NOT_RUN": 0}
counts[status] = counts.get(status, 0) + 1
summary = {
    "connector": connector,
    "generated_at": now,
    "connector_root": connector_root,
    "source_root": source_root,
    "build_root": build_root,
    "results_dir": results_dir,
    "tmp_root": tmp_root,
    "log_root": log_root,
    "status": status,
    "counts": counts,
    "runtime_verified": False,
    "runtime_status": runtime_status,
    "response_body_verified": False,
    "reason": reason,
    "starter_checks_available": starter_available,
    "installs_global_artifacts": False,
    "harness_path": harness_path,
    "note": note,
    "results": [record],
}
with open(results_jsonl, "w", encoding="utf-8") as handle:
    handle.write(json.dumps(record, sort_keys=True))
    handle.write("\n")
with open(summary_json, "w", encoding="utf-8") as handle:
    json.dump(summary, handle, indent=2, sort_keys=True)
    handle.write("\n")
with open(summary_text, "w", encoding="utf-8") as handle:
    handle.write(f"{status} {connector}-runtime-smoke {reason}\n")
    handle.write("Runtime not verified\n")
    handle.write(f"{note}\n")
PY
}

connector_smoke_run() {
    connector=$1
    harness_script=$2
    connector_smoke_validate_roots
    connector_dir="$CONNECTOR_ROOT/connectors/$connector"
    [ -d "$connector_dir" ] || {
        connector_smoke_write_evidence "$connector" BLOCKED 77 blocked "connector directory missing" "$harness_script"
        exit 77
    }
    if [ ! -x "$harness_script" ]; then
        connector_smoke_write_evidence "$connector" BLOCKED 77 blocked "runtime harness not implemented" "$harness_script"
        echo "$connector runtime smoke: BLOCKED - runtime harness not implemented"
        echo "Runtime not verified"
        exit 77
    fi
    set +e
    (
        cd "$CONNECTOR_ROOT"
        SOURCE_ROOT="$SOURCE_ROOT" BUILD_ROOT="$BUILD_ROOT" RESULTS_DIR="$RESULTS_DIR" TMP_ROOT="$TMP_ROOT" LOG_ROOT="$LOG_ROOT" CONNECTOR_ROOT="$CONNECTOR_ROOT" FRAMEWORK_ROOT="$FRAMEWORK_ROOT" sh "$harness_script"
    )
    rc=$?
    set -e
    results_jsonl="$RESULTS_DIR/$connector-results.jsonl"
    if [ "$rc" -eq 0 ] && [ "${RUN_ONE_CASE:-0}" = "1" ]; then
        case_result_path="${LOG_DIR:-$LOG_ROOT/$connector-runtime}/result.json"
        if [ -s "$case_result_path" ]; then
            exit 0
        fi
    fi
    if [ "$rc" -eq 0 ] && [ ! -s "$results_jsonl" ]; then
        connector_smoke_write_evidence "$connector" BLOCKED 77 blocked "runtime harness produced no case evidence" "$harness_script"
        echo "$connector runtime smoke: BLOCKED - runtime harness produced no case evidence"
        echo "Runtime not verified"
        exit 77
    fi
    exit "$rc"
}
