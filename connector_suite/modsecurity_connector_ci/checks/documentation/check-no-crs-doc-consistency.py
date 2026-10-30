#!/usr/bin/env python3
"""Check canonical No-CRS metadata, TODOs, and consolidated readiness reports."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import re
from pathlib import Path


ROOT = connector_root()
CONNECTORS = ("apache", "nginx", "haproxy", "envoy", "traefik", "lighttpd")
READINESS_REPORTS = (
    ("reports/current/readiness.md", "**Language:**"),
    ("reports/current/readiness.de.md", "**Sprache:**"),
)
CORE_COMPLETION_REPORTS = (
    ("reports/current/core-completion.md", "**Language:**"),
    ("reports/current/core-completion.de.md", "**Sprache:**"),
)
CAPABILITY_CATALOG_JSON = "reports/testing/generated/canonical/connector-capabilities.generated.json"
CAPABILITY_CATALOG_MARKDOWN = "reports/testing/generated/canonical/connector-capabilities.generated.md"
CORE_CAPABILITIES = ("phase1", "phase2", "phase3", "phase4", "event_jsonl")
NOT_EXECUTED_STATUS = "NOT EXECUTED"
REPORT_STATUSES = {
    "PASS",
    "FAIL",
    "BLOCKED",
    "UNSUPPORTED",
    "NOT IMPLEMENTED",
    NOT_EXECUTED_STATUS,
    "IMPLEMENTED, NOT ASSERTED",
}


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def read(path: Path, errors: list[str]) -> str:
    if not path.is_file():
        fail(errors, f"missing required document: {path.relative_to(ROOT)}")
        return ""
    return path.read_text(encoding="utf-8")


def table_statuses(text: str) -> list[str]:
    statuses: list[str] = []
    for line in text.splitlines():
        if not line.startswith("|") or "---" in line:
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        statuses.extend(cell for cell in cells if cell in REPORT_STATUSES or cell.isupper())
    return statuses


def display_name(connector: str) -> str:
    return {
        "apache": "Apache",
        "nginx": "NGINX",
        "haproxy": "HAProxy",
        "envoy": "Envoy",
        "traefik": "Traefik",
    }.get(connector, connector)


def connector_section(text: str, connector: str) -> str:
    heading = re.escape(display_name(connector))
    match = re.search(rf"^### {heading}\s*$([\s\S]*?)(?=^### |\Z)", text, flags=re.MULTILINE)
    return match.group(1) if match else ""


def capability_manifests(errors: list[str]) -> dict[str, dict[str, object]]:
    manifests: dict[str, dict[str, object]] = {}
    for connector in CONNECTORS:
        path = ROOT / f"connectors/{connector}/capabilities.json"
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            fail(errors, f"invalid capability manifest {path.relative_to(ROOT)}: {exc}")
            continue
        if not isinstance(value.get("capabilities"), dict):
            fail(errors, f"{path.relative_to(ROOT)}: capabilities must be an object")
        manifests[connector] = value

        todo = read(ROOT / f"connectors/{connector}/TODO.md", errors)
        for required in (
            "capabilities.json",
            NOT_EXECUTED_STATUS,
            f"no-crs-baseline-{connector}",
            f"evidence-check-{connector}",
        ):
            if required not in todo:
                fail(errors, f"connectors/{connector}/TODO.md: missing canonical marker {required!r}")
    return manifests


def readiness_documents(errors: list[str]) -> dict[str, str]:
    readiness: dict[str, str] = {}
    for relative, switch in READINESS_REPORTS:
        text = read(ROOT / relative, errors)
        readiness[relative] = text
        if switch not in text:
            fail(errors, f"{relative}: missing bilingual language switch")
        if not any(status in table_statuses(text) for status in REPORT_STATUSES):
            fail(errors, f"{relative}: readiness table contains no canonical status cells")
        if "Claims deliberately not made" not in text and "Bewusst nicht erhobene Claims" not in text:
            fail(errors, f"{relative}: claim-boundary section missing")
    return readiness


def core_completion_documents(errors: list[str]) -> tuple[dict[str, str], str]:
    core_completion: dict[str, str] = {}
    core_run_ids: set[str] = set()
    for relative, switch in CORE_COMPLETION_REPORTS:
        text = read(ROOT / relative, errors)
        core_completion[relative] = text
        if switch not in text:
            fail(errors, f"{relative}: missing bilingual language switch")
        run_match = re.search(r"(?:Shared run ID|Gemeinsame Run-ID):\s*`([^`]+)`", text)
        if not run_match:
            fail(errors, f"{relative}: missing shared canonical run identifier")
        else:
            core_run_ids.add(run_match.group(1))
        if "full-lifecycle-all-connectors" not in text or not re.search(r"exit\s+`0`", text, flags=re.IGNORECASE):
            fail(errors, f"{relative}: PASS core table lacks aggregate exit-zero boundary")
        if "make check-six-connector-core-completion" not in text:
            fail(errors, f"{relative}: missing core checker boundary")

    if len(core_run_ids) != 1:
        fail(errors, f"core completion language pair has inconsistent run identifiers: {sorted(core_run_ids)}")
    return core_completion, next(iter(core_run_ids), "")


def check_readiness_core_binding(errors: list[str], readiness: dict[str, str], core_run_id: str) -> None:
    for relative, text in readiness.items():
        if core_run_id and core_run_id not in text:
            fail(errors, f"{relative}: readiness is not bound to core run {core_run_id}")



def check_connector_rows(errors: list[str], readiness: dict[str, str], core_completion: dict[str, str]) -> None:
    english = readiness.get("reports/current/readiness.md", "")
    core_english = core_completion.get("reports/current/core-completion.md", "")
    for connector in CONNECTORS:
        display = display_name(connector)
        if not re.search(rf"\|\s*{re.escape(display)}\s*\|", english, re.IGNORECASE):
            fail(errors, f"reports/current/readiness.md: readiness table is missing {connector}")
        if not re.search(
            rf"^\|\s*{re.escape(display)}\s*\|(?:\s*PASS\s*\|){{8}}",
            core_english,
            flags=re.IGNORECASE | re.MULTILINE,
        ):
            fail(errors, f"reports/current/core-completion.md: compact core row for {connector} is not eight PASS results")
        readiness_row = re.search(rf"^\|\s*{re.escape(display)}\s*\|.*$", english, flags=re.IGNORECASE | re.MULTILINE)
        if not readiness_row or "PASS" not in readiness_row.group(0) or NOT_EXECUTED_STATUS not in readiness_row.group(0):
            fail(errors, f"reports/current/readiness.md: {connector} must keep selected core PASS separate from extended {NOT_EXECUTED_STATUS}")


def check_connector_boundaries(errors: list[str]) -> None:
    envoy_todo = read(source_path('connectors/envoy/TODO.md', root=ROOT), errors)
    if "Status: targeted `minimal_runtime_smoke`" not in envoy_todo:
        fail(errors, "Envoy TODO must identify the existing targeted minimal runtime path")
    traefik_todo = read(source_path('connectors/traefik/TODO.md', root=ROOT), errors)
    for marker in ("forwardBody", "request_body_mode=none", "unsupported_by_host_model"):
        if marker not in traefik_todo:
            fail(errors, f"Traefik TODO is missing architecture boundary marker {marker}")
    lighttpd_todo = read(source_path('connectors/lighttpd/TODO.md', root=ROOT), errors)
    if "`implemented_not_asserted`, not verified" not in lighttpd_todo:
        fail(errors, "lighttpd TODO must keep Phase 3 implemented but unverified")

    overview_en = read(source_path('docs/README.md', root=ROOT), errors)
    overview_de = read(source_path('docs/README.de.md', root=ROOT), errors)
    for marker in ("Envoy", "Traefik", "lighttpd", "minimal_runtime_smoke", "capabilities.json"):
        if marker not in overview_en or marker not in overview_de:
            fail(errors, f"repository overview pair is missing {marker!r}")


def capability_aggregate(errors: list[str]) -> dict[str, object] | None:
    aggregate_path = ROOT / CAPABILITY_CATALOG_JSON
    try:
        return json.loads(aggregate_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(errors, f"invalid generated capability aggregate: {exc}")
        return None


def check_runtime_promotion(errors: list[str], aggregate: dict[str, object]) -> None:
    runtime_promotion = aggregate.get("runtime_promotion")
    if not isinstance(runtime_promotion, bool):
        fail(errors, "generated capability aggregate runtime_promotion must be Boolean")
    if runtime_promotion is not True:
        if runtime_promotion is not False:
            fail(errors, "generated capability aggregate has an invalid runtime_promotion value")
        return
    runtime_evidence = aggregate.get("runtime_evidence")
    if not isinstance(runtime_evidence, dict):
        fail(errors, "runtime-promoted capability aggregate is missing runtime_evidence")
        return
    if not isinstance(runtime_evidence.get("run_id"), str) or not runtime_evidence["run_id"]:
        fail(errors, "runtime-promoted capability aggregate is missing its run_id")
    if runtime_evidence.get("evidence_stage") != "no_crs_baseline":
        fail(errors, "runtime-promoted capability aggregate must use no_crs_baseline evidence")
    evidence_connectors = runtime_evidence.get("connectors")
    if not isinstance(evidence_connectors, dict) or set(evidence_connectors) != set(CONNECTORS):
        fail(errors, "runtime-promoted capability aggregate lacks one or more connector results")


def catalog_capability_errors(
    connector: str,
    manifest_capabilities: dict[str, object],
    generated_capabilities: dict[str, object],
    section: str,
) -> list[str]:
    errors: list[str] = []
    for capability in CORE_CAPABILITIES:
        entry = manifest_capabilities.get(capability)
        expected = entry.get("state") if isinstance(entry, dict) else None
        observed_entry = generated_capabilities.get(capability)
        observed = observed_entry.get("state") if isinstance(observed_entry, dict) else None
        if not isinstance(expected, str) or not expected:
            errors.append(f"connectors/{connector}/capabilities.json: missing {capability} state")
            continue
        if observed != expected:
            errors.append(f"{connector}: generated capability catalog disagrees on {capability}: {observed!r} != {expected!r}")
        row_pattern = rf"\|\s*`{re.escape(capability)}`\s*\|\s*`{re.escape(expected)}`\s*\|"
        if not re.search(row_pattern, section):
            errors.append(f"{CAPABILITY_CATALOG_MARKDOWN}: {connector} detail row disagrees with {capability}={expected}")
    return errors


def catalog_connector_errors(
    connector: str,
    manifest: dict[str, object],
    generated_connectors: dict[str, object],
    catalog_markdown: str,
) -> list[str]:
    manifest_capabilities = manifest.get("capabilities")
    generated = generated_connectors.get(connector)
    generated_capabilities = generated.get("capabilities") if isinstance(generated, dict) else None
    if not isinstance(manifest_capabilities, dict) or not isinstance(generated_capabilities, dict):
        return [f"{connector}: capability manifest/catalog mapping is invalid"]
    section = connector_section(catalog_markdown, connector)
    if not section:
        return [f"{CAPABILITY_CATALOG_MARKDOWN}: missing {connector} detail section"]
    return catalog_capability_errors(connector, manifest_capabilities, generated_capabilities, section)


def check_capability_catalog(errors: list[str], manifests: dict[str, dict[str, object]], aggregate: dict[str, object]) -> None:
    generated_connectors = aggregate.get("connectors")
    if not isinstance(generated_connectors, dict) or set(generated_connectors) != set(CONNECTORS):
        fail(errors, "generated capability aggregate does not contain exactly six connectors")
        return
    catalog_markdown = read(ROOT / CAPABILITY_CATALOG_MARKDOWN, errors)
    for connector, manifest in manifests.items():
        errors.extend(catalog_connector_errors(connector, manifest, generated_connectors, catalog_markdown))


def main() -> int:
    errors: list[str] = []
    manifests = capability_manifests(errors)
    readiness = readiness_documents(errors)
    core_completion, core_run_id = core_completion_documents(errors)
    check_readiness_core_binding(errors, readiness, core_run_id)
    check_connector_rows(errors, readiness, core_completion)
    check_connector_boundaries(errors)
    aggregate = capability_aggregate(errors)
    if aggregate is not None:
        check_runtime_promotion(errors, aggregate)
        check_capability_catalog(errors, manifests, aggregate)

    if errors:
        for error in errors:
            print(f"no-crs-doc-consistency: FAIL: {error}")
        return 1
    print("no-crs-doc-consistency: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
