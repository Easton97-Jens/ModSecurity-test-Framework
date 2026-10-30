#!/usr/bin/env python3
"""Verify config, request-free start and request runtime stages remain distinct."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import re
import sys


ROOT = connector_root()
MAKEFILE = (source_path('Makefile', root=ROOT)).read_text(encoding="utf-8")
errors: list[str] = []

for connector in ("envoy", "traefik", "lighttpd"):
    for prefix in ("check", "start-smoke", "runtime-smoke"):
        target = f"{prefix}-{connector}" if prefix != "check" else f"check-{connector}-config"
        if re.search(rf"^{re.escape(target)}\s*:", MAKEFILE, flags=re.MULTILINE) is None:
            errors.append(f"root Makefile missing {target}")

start_scripts = {
    "envoy": source_path('connectors/envoy/harness/start_envoy_connector.sh', root=ROOT),
    "traefik": source_path('connectors/traefik/scripts/start-smoke.sh', root=ROOT),
    "lighttpd": source_path('connectors/lighttpd/harness/start_lighttpd_smoke.sh', root=ROOT),
}
for connector, path in start_scripts.items():
    if not path.is_file():
        errors.append(f"{connector}: start-smoke script missing")
        continue
    content = path.read_text(encoding="utf-8", errors="replace")
    for request_token in ("curl ", "urllib.request", "X-Modsec-Smoke", "/blocked"):
        if request_token in content:
            errors.append(f"{connector}: request-free start smoke contains {request_token!r}")
    if not any(token in content for token in ("kill -0", "process.poll")):
        errors.append(f"{connector}: start smoke does not check process liveness")
    if not any(token in content for token in ("wait ", ".wait(")):
        errors.append(f"{connector}: start smoke does not wait for clean shutdown")


def check_traefik_start_contract(content: str) -> list[str]:
    range_name = "TRAEFIK_DIAGNOSTIC_SED_RANGE"
    range_program = "1,160" + "p"
    range_declaration = f"{range_name}='{range_program}'"
    sed_print = "sed -n "
    range_use = f'{sed_print}"${range_name}"'
    legacy_range_use = f"{sed_print}'{range_program}'"
    trap_registration = "trap cleanup EXIT HUP INT TERM"
    output_root_mutation = 'rm -rf "$START_ROOT"'
    stderr_names = ("CONFIG_STDERR", "SERVICE_STDERR", "TRAEFIK_STDERR")
    config_stderr, service_stderr, traefik_stderr = (f"${name}" for name in stderr_names)
    observer_build_stderr = "$START_ROOT/response-observer-build.log"
    expected_operands = (
        observer_build_stderr,
        config_stderr,
        service_stderr,
        traefik_stderr,
        traefik_stderr,
    )
    actual_operands = tuple(
        re.findall(
            rf'^[ \t]*{re.escape(range_use)} "([^"]+)" >&2[ \t]*$',
            content,
            flags=re.MULTILINE,
        )
    )
    config_stdout = config_stderr.replace("STDERR", "STDOUT")
    service_pid_ref, traefik_pid_ref = (f"${name}" for name in ("service_pid", "traefik_pid"))
    rc_reference = "$rc"
    rc_capture = "rc=$?"
    exit_with_rc = f'exit "{rc_reference}"'
    diagnostic_template = f'{range_use} "{{stderr}}" >&2'
    cleanup_template = "\n".join(
        (
            '    if [ -n "{pid}" ] && kill -0 "{pid}" 2>/dev/null; then',
            '        kill "{pid}" 2>/dev/null || true',
            '        wait "{pid}" 2>/dev/null || true',
            "    fi",
        )
    )
    liveness_template = "\n".join(
        (
            '    if ! kill -0 "{pid}" 2>/dev/null; then',
            '        wait "{pid}" || rc=$?',
            "        rc=${{rc:-1}}",
            '        echo "{message} (rc=$rc)" >&2',
            f"        {diagnostic_template}",
            '        exit "$rc"',
            "    fi",
        )
    )
    template_rewrite = "\n".join(
        (
            "sed \\",
            '    -e "s|__AUTH_ADDRESS__|$SERVICE_LISTEN|g" \\',
            '    -e "s|__UPSTREAM_ADDRESS__|$UPSTREAM_ADDRESS|g" \\',
            '    -e "s|__COMPANION_SOCKET__|$COMPANION_SOCKET|g" \\',
            '    "$TRAEFIK_TEMPLATE" > "$TRAEFIK_CONFIG"',
        )
    )
    cleanup_block = "\n".join(
        (
            "cleanup() {",
            cleanup_template.format(pid=traefik_pid_ref),
            cleanup_template.format(pid=service_pid_ref),
            '    rm -f "$SERVICE_PID_FILE" "$TRAEFIK_PID_FILE"',
            "}",
        )
    )
    config_block = "\n".join(
        (
            f') >"{config_stdout}" 2>"{config_stderr}" || {{',
            f"    {rc_capture}",
            '    echo "FAIL: Traefik connector config check failed (rc=$rc)" >&2',
            f"    {diagnostic_template.format(stderr=config_stderr)}",
            f"    {exit_with_rc}",
            "}",
        )
    )
    controls = (
        (len(re.findall(rf"^{re.escape(range_declaration)}$", content, flags=re.MULTILINE)) == 1,
         "traefik: diagnostic sed range must have one fixed declaration"),
        (re.search(rf"^[ \t]*export[ \t]+{re.escape(range_name)}(?:[ \t=]|$)", content, flags=re.MULTILINE) is None,
         "traefik: diagnostic sed range must not be exported"),
        (content.count(range_name) == 6,
         "traefik: diagnostic sed range must only occur in its declaration and five direct uses"),
        (legacy_range_use not in content,
         "traefik: legacy direct diagnostic sed range remains"),
        (content.count(sed_print) == len(expected_operands),
         "traefik: must retain exactly five diagnostic sed calls"),
        (actual_operands == expected_operands,
         "traefik: diagnostic sed calls must retain their exact stderr operands"),
        (all(content.find(marker) >= 0 for marker in (trap_registration, output_root_mutation, range_use)) and
         content.find(trap_registration) < content.find(range_declaration) < content.find(output_root_mutation) < content.find(range_use),
         "traefik: diagnostic sed range must be declared after cleanup registration before use"),
    )
    required_controls = (
        "set -eu",
        'case "$START_ROOT" in',
        'if [ -L "$START_ROOT" ]; then',
        'require_executable "$CONNECTOR_BIN" "Traefik forwardAuth connector"',
        'require_executable "$TRAEFIK_BIN" "Traefik"',
        'require_loopback_address "$SERVICE_LISTEN" "TRAEFIK_CONNECTOR_LISTEN"',
        'require_loopback_address "$TRAEFIK_LISTEN" "TRAEFIK_START_LISTEN"',
        'require_loopback_address "$UPSTREAM_ADDRESS" "TRAEFIK_START_UPSTREAM"',
        'if [ ! -f "$CONFIG_PATH" ]; then',
        'if [ ! -f "$TRAEFIK_TEMPLATE" ]; then',
        'case "$COMPANION_SOCKET" in',
        '"$START_ROOT"/*) ;;',
        'mkdir -p "$COMPANION_DIR"',
        'chmod 700 "$START_ROOT" "$COMPANION_DIR"',
        template_rewrite,
        cleanup_block,
        config_block,
        liveness_template.format(
            pid=service_pid_ref,
            message="FAIL: Traefik forwardAuth service exited during start smoke",
            stderr=service_stderr,
        ),
        liveness_template.format(
            pid=traefik_pid_ref,
            message="FAIL: Traefik exited during start smoke",
            stderr=traefik_stderr,
        ),
        "\n".join(
            (
                f'if [ -s "{traefik_stderr}" ]; then',
                '    echo "FAIL: Traefik reported a configuration/start error" >&2',
                f"    {diagnostic_template.format(stderr=traefik_stderr)}",
                "    exit 1",
                "fi",
            )
        ),
    )
    return [message for passed, message in controls if not passed] + [
        f"traefik: missing required start control {control!r}"
        for control in required_controls
        if control not in content
    ]


traefik_path = start_scripts["traefik"]
if traefik_path.is_file():
    errors.extend(check_traefik_start_contract(traefik_path.read_text(encoding="utf-8", errors="replace")))

if "start-smoke-remaining-connectors" not in MAKEFILE:
    errors.append("aggregate start smoke target missing")
if "runtime-smoke-remaining-connectors" not in MAKEFILE:
    errors.append("aggregate runtime smoke target missing")

if errors:
    print("\n".join(errors), file=sys.stderr)
    raise SystemExit(1)
print("remaining connectors start wiring: ok")
