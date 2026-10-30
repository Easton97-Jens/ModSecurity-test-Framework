#!/usr/bin/env python3
"""Check that each remaining connector has a live host-to-Common path."""
from modsecurity_test_framework.connector_context import connector_root, source_path

import sys


ROOT = connector_root()


def text(path: str) -> str:
    target = source_path(path, root=ROOT)
    return target.read_text(encoding="utf-8", errors="replace") if target.is_file() else ""


checks = {
    "envoy": {
        "connectors/envoy/src/envoy_ext_authz_service_main.c": (
            "msconnector_http_authorization_service_main",
            "envoy_modsecurity_map_request",
            "ext_authz",
        ),
        "connectors/envoy/harness/run_envoy_connector_runtime.sh": (
            "ENVOY_BIN",
            "X-Modsec-Smoke",
            "blocked_status",
            "EVENT_LOG_PATH",
        ),
    },
    "traefik": {
        "connectors/traefik/src/traefik_forwardauth_service_main.c": (
            "msconnector_http_authorization_service_main",
            "traefik_modsecurity_map_request",
            "forwardAuth",
        ),
        "connectors/traefik/scripts/runtime-smoke.sh": (
            "runtime_smoke.py",
        ),
        "connectors/traefik/scripts/runtime_smoke.py": (
            "TRAEFIK_BIN",
            "X-Modsec-Smoke",
            "blocked",
            "events.jsonl",
        ),
    },
    "lighttpd": {
        "connectors/lighttpd/module/mod_msconnector.c": (
            "mod_msconnector_plugin_init",
            "config_plugin_values_init",
            "lighttpd_modsecurity_map_request",
            "msconnector_runtime_transaction_begin",
            "http_status_set_err",
            "handle_request_reset",
        ),
        "connectors/lighttpd/harness/runtime_lighttpd_smoke.sh": (
            "LIGHTTPD_BIN",
            "mod_msconnector",
            "X-Modsec-Smoke",
            "403",
        ),
    },
}

errors: list[str] = []
for connector, files in checks.items():
    for relative, tokens in files.items():
        content = text(relative)
        if not content:
            errors.append(f"{connector}: host integration file missing: {relative}")
            continue
        for token in tokens:
            if token not in content:
                errors.append(f"{connector}: {relative} missing live-path token {token}")

runtime = text("common/runtime/msconnector_runtime.c")
service = text("common/runtime/http_authorization_service.c")
for token in (
    "msconnector_runtime_transaction_begin",
    "msconnector_runtime_transaction_process_response",
    "msconnector_runtime_transaction_finish",
    "msconnector_rule_loader_load_config",
    "msconnector_event_write_jsonl_line",
):
    if token not in runtime:
        errors.append(f"shared host runtime missing {token}")
if "profile->map_request" not in service:
    errors.append("authorization host service does not invoke connector request mapper")
if "msconnector_runtime_transaction_begin" not in service:
    errors.append("authorization host service does not enter Common transaction lifecycle")

if errors:
    print("\n".join(errors), file=sys.stderr)
    raise SystemExit(1)
print("remaining connectors host integration: ok")
