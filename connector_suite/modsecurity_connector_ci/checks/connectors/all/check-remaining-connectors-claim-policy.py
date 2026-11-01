#!/usr/bin/env python3
"""Keep remaining-connector claims aligned with executable evidence paths."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import re
import sys


ROOT = connector_root()
CONNECTORS = ("envoy", "traefik", "lighttpd")
READINESS_REPORT_EN = "reports/current/readiness.md"
REPORTS = (
    READINESS_REPORT_EN,
    "reports/current/readiness.de.md",
)
STATUS_DOCUMENTS = {
    "envoy": "connectors/envoy/TODO.md",
    "traefik": "connectors/traefik/TODO.md",
    "lighttpd": "connectors/lighttpd/TODO.md",
}
ALLOWED_METADATA_STATUSES = (
    "compile_verified",
    "link_verified",
    "config_load_verified",
    "start_smoke_verified",
    "minimal_runtime_smoke",
    "partial_runtime_path",
    "requires_runtime_evidence",
    "connector-gap",
    "not_verified",
)
POSITIVE_FORBIDDEN = (
    r"production[-_ ]ready\s*[:=]\s*(?:true|yes|verified)",
    r"security[-_ ]verified\s*[:=]\s*(?:true|yes)",
    r"crs[-_ ]verified\s*[:=]\s*(?:true|yes)",
    r"full[-_ ]matrix[-_ ]verified\s*[:=]\s*(?:true|yes)",
    r"response[-_ ]body[-_ ]verified\s*[:=]\s*(?:true|yes)",
    r"all[-_ ]connectors[-_ ]verified\s*[:=]\s*(?:true|yes)",
)

errors: list[str] = []
for relative in REPORTS:
    path = ROOT / relative
    if not path.is_file():
        errors.append(f"readiness report missing: {relative}")
        continue
    content = path.read_text(encoding="utf-8", errors="replace")
    if "PASS" not in content or "NOT EXECUTED" not in content:
        errors.append(f"readiness report does not distinguish selected core from extended scope: {relative}")
    for pattern in POSITIVE_FORBIDDEN:
        if re.search(pattern, content, flags=re.IGNORECASE):
            errors.append(f"forbidden positive claim in {relative}: {pattern}")
    if "Claims deliberately not made" not in content and "Bewusst nicht erhobene Claims" not in content:
        errors.append(f"claim-boundary section missing: {relative}")

runtime_paths = {
    "envoy": source_path('connectors/envoy/harness/run_envoy_connector_runtime.sh', root=ROOT),
    "traefik": source_path('connectors/traefik/scripts/runtime-smoke.sh', root=ROOT),
    "lighttpd": source_path('connectors/lighttpd/harness/runtime_lighttpd_smoke.sh', root=ROOT),
}
readiness_en_path = ROOT / READINESS_REPORT_EN
readiness_en = readiness_en_path.read_text(encoding="utf-8", errors="replace") if readiness_en_path.is_file() else ""
for connector in CONNECTORS:
    metadata_path = source_path('connectors', root=ROOT) / connector / "metadata.c"
    metadata = metadata_path.read_text(encoding="utf-8", errors="replace")
    metadata_statuses = {status for status in ALLOWED_METADATA_STATUSES if f'"{status}"' in metadata}
    if not metadata_statuses:
        errors.append(f"{connector}: metadata has no allowed status")
    status_document_path = ROOT / STATUS_DOCUMENTS[connector]
    if not status_document_path.is_file():
        errors.append(f"{connector}: current status document missing: {STATUS_DOCUMENTS[connector]}")
    else:
        status_document = status_document_path.read_text(encoding="utf-8", errors="replace")
        undocumented = sorted(status for status in metadata_statuses if status not in status_document)
        if undocumented:
            errors.append(f"{connector}: status document does not match metadata {undocumented}")
    if "minimal_runtime_smoke" in metadata and not runtime_paths[connector].is_file():
        errors.append(f"{connector}: runtime status promoted without executable evidence producer")
    if not re.search(rf"\|\s*{re.escape(connector)}\s*\|", readiness_en, re.IGNORECASE):
        errors.append(f"reports/current/readiness.md: missing current status row for {connector}")

if errors:
    print("\n".join(errors), file=sys.stderr)
    raise SystemExit(1)
print("remaining connectors claim policy: ok")
