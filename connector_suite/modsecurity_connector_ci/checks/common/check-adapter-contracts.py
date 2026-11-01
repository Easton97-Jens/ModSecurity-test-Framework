#!/usr/bin/env python3
"""Check global common adapter contracts for new connectors."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
from pathlib import Path
import sys

ROOT = connector_root()
HEADERS = [
    "adapter.h", "adapter_contract.h", "adapter_metadata.h", "config.h",
    "directive_spec.h", "directive_adapter.h", "request.h",
    "request_mapper_contract.h", "response.h", "response_mapper_contract.h",
    "generic_mapper.h",
    "decision.h", "event.h", "event_jsonl.h", "capabilities.h",
    "body_policy.h", "resource_limits.h", "dos_guard.h", "flow_guard.h",
    "integrity_event.h", "crs.h",
]
SOURCES = [
    "adapter.c", "adapter_contract.c", "adapter_metadata.c", "config.c",
    "directive_spec.c", "directive_adapter.c", "body_policy.c",
    "resource_limits.c", "dos_guard.c", "flow_guard.c", "integrity_event.c",
    "request_mapper_contract.c", "response_mapper_contract.c",
    "generic_mapper.c", "crs.c",
    "decision.c", "event.c", "event_jsonl.c", "capabilities.c",
]
SERVER_TOKENS = ["ngx_", "httpd", "apr_", "haproxy", "envoy", "lighttpd", "traefik"]
SERVER_INCLUDE_TOKENS = (
    "nginx",
    "ngx_",
    "httpd",
    "http_config",
    "apr_",
    "haproxy",
    "envoy",
    "lighttpd",
    "traefik",
)


def extract_include_target(line: str) -> str:
    stripped = line.strip()
    if not stripped.startswith("#"):
        return ""

    rest = stripped[1:].lstrip()
    if not rest.startswith("include"):
        return ""

    rest = rest[len("include"):].lstrip()
    if not rest:
        return ""

    opener = rest[0]
    if opener == "<":
        closer = ">"
    elif opener == '"':
        closer = '"'
    else:
        return ""

    end = rest.find(closer, 1)
    if end == -1:
        return ""

    return rest[1:end]


def contains_server_include(text: str) -> str:
    for line in text.splitlines():
        target = extract_include_target(line).lower()
        if target and any(token in target for token in SERVER_INCLUDE_TOKENS):
            return target
    return ""


ok = True
for name in HEADERS:
    path = source_path('common/include/msconnector', root=ROOT) / name
    if not path.exists():
        print(f"missing common header: {path.relative_to(ROOT)}")
        ok = False
for name in SOURCES:
    path = source_path('common/src', root=ROOT) / name
    if not path.exists():
        print(f"missing common source: {path.relative_to(ROOT)}")
        ok = False

adapter_h = (source_path('common/include/msconnector/adapter.h', root=ROOT)).read_text() if (source_path('common/include/msconnector/adapter.h', root=ROOT)).exists() else ""
for token in ("metadata", "init", "process", "finish"):
    if token not in adapter_h:
        print(f"adapter.h missing callback-like token: {token}")
        ok = False
metadata_h = (source_path('common/include/msconnector/adapter_metadata.h', root=ROOT)).read_text() if (source_path('common/include/msconnector/adapter_metadata.h', root=ROOT)).exists() else ""
for token in ("connector_name", "server_family", "source_kind", "build_status", "runtime_status", "verification_status"):
    if token not in metadata_h:
        print(f"adapter_metadata.h missing field: {token}")
        ok = False

for rel in ("common/include/msconnector/request_mapper_contract.h", "common/include/msconnector/response_mapper_contract.h", "common/src/request_mapper_contract.c", "common/src/response_mapper_contract.c"):
    path = ROOT / rel
    if path.exists():
        text = path.read_text().lower()
        for token in SERVER_TOKENS:
            if token in text:
                print(f"server token in mapper contract: {rel}: {token}")
                ok = False

common_contract_files = (
    list((source_path('common/include/msconnector', root=ROOT)).glob("*.h"))
    + list((source_path('common/src', root=ROOT)).glob("*.c"))
    + list((source_path('common/runtime', root=ROOT)).glob("*.h"))
    + list((source_path('common/runtime', root=ROOT)).glob("*.c"))
)
for path in common_contract_files:
    text = path.read_text(errors="ignore")
    target = contains_server_include(text)
    if target:
        print(f"server-specific include in common: {path.relative_to(ROOT)}: {target}")
        ok = False

print("adapter-contracts: common contracts present; runtime remains host-neutral")
if not ok:
    sys.exit(1)
