#!/usr/bin/env python3
"""Create a payload-free reconstruction of a canonical lifecycle run's roots.

This intentionally reads only manifests, filesystem metadata, and known runner
defaults.  It never copies process environments, raw logs, request bodies, or
response bodies into the committed audit reports.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any



from modsecurity_connector_ci.lib.generated_report_utils import portable_path_reference
from modsecurity_connector_ci.lib.report_path_safety import add_safe_roots, safe_existing_file, safe_path, write_text_file


CONNECTORS = ("apache", "nginx", "haproxy", "envoy", "traefik", "lighttpd")


def absolute(value: str | Path) -> Path:
    return Path(value).expanduser().resolve(strict=False)


def sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_metadata(path: Path) -> dict[str, Any]:
    if not path.exists() and not path.is_symlink():
        return {
            "binary_exists": False,
            "binary_executable": False,
            "binary_owner": None,
            "binary_sha256": None,
            "binary_kind": "missing",
        }
    details = path.lstat()
    try:
        owner = pwd.getpwuid(details.st_uid).pw_name
    except KeyError:
        owner = str(details.st_uid)
    if stat.S_ISLNK(details.st_mode):
        kind = "symlink"
    elif stat.S_ISREG(details.st_mode):
        kind = "file"
    elif stat.S_ISDIR(details.st_mode):
        kind = "directory"
    else:
        kind = "other"
    return {
        "binary_exists": True,
        "binary_executable": bool(details.st_mode & 0o111) and stat.S_ISREG(details.st_mode),
        "binary_owner": f"{owner}:{details.st_gid}",
        "binary_sha256": sha256(path) if stat.S_ISREG(details.st_mode) else None,
        "binary_kind": kind,
    }


def read_object(path: Path) -> dict[str, Any]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def configured_paths(args: argparse.Namespace) -> tuple[Path | None, Path, Path, Path]:
    """Confine CLI-provided evidence paths to the caller's workspace."""

    workspace_root = Path.cwd().resolve(strict=False)
    add_safe_roots(workspace_root)
    input_json = safe_existing_file(args.input_json) if args.input_json else None
    output_paths = tuple(
        safe_path(path, must_exist=False)
        for path in (args.output_json, args.output_md, args.output_md_de)
    )
    if any(path is None for path in output_paths):
        raise SystemExit("output paths must remain inside the current workspace")
    return input_json, output_paths[0], output_paths[1], output_paths[2]


def newest(paths: list[Path]) -> Path | None:
    regular = [path for path in paths if path.is_file()]
    if not regular:
        return None
    return max(regular, key=lambda path: path.stat().st_mtime)


def selected_binary(connector: str, cache_root: Path, build_root: Path, manifest: dict[str, Any]) -> tuple[Path, str]:
    """Return the runner's expected binary and the evidence source used."""
    host_version = str(manifest.get("host_version", ""))
    # Apache and Envoy inventory records include the selected binary before the
    # version text.  Prefer it over a broad cache glob.
    if host_version.startswith("/"):
        candidate = Path(host_version.split("  version:", 1)[0].split(": error", 1)[0])
        if candidate.is_file():
            return candidate, "historical manifest host_version path"

    patterns: dict[str, tuple[str, ...]] = {
        "apache": ("builds/connectors/apache/*/httpd/bin/httpd",),
        "nginx": ("builds/connectors/nginx/*/nginx/sbin/nginx",),
        "haproxy": ("builds/connectors/haproxy/*/haproxy-runtime/haproxy/sbin/haproxy",),
        "envoy": ("envoy/bin/envoy",),
        "traefik": (),
        "lighttpd": ("lighttpd/bin/lighttpd",),
    }
    if connector == "traefik":
        return build_root / "traefik-connector/traefik-forwardauth", "runtime_smoke.py default TRAEFIK_CONNECTOR_BIN"
    candidates: list[Path] = []
    for pattern in patterns[connector]:
        candidates.extend(cache_root.glob(pattern))
    candidate = newest(candidates)
    if candidate is not None:
        return candidate, "historical cache artifact selected by connector host convention"
    # This remains an explicit expected path even if a previous cache was
    # absent; it is more useful than omitting the field from the audit.
    return cache_root / "missing" / connector, "no historical binary candidate was found"


def build_record(
    connector: str,
    *,
    run_id: str,
    verified_run_root: Path,
    build_root: Path,
    evidence_root: Path,
    component_cache_root: Path,
) -> dict[str, Any]:
    evidence_run = evidence_root / connector / run_id
    raw_run = build_root / "canonical-raw/no_crs_baseline" / connector / run_id
    manifest = read_object(evidence_run / "manifest.json")
    expected_binary, binary_source = selected_binary(connector, component_cache_root, build_root, manifest)
    metadata = file_metadata(expected_binary)
    apache_named_root = "full-lifecycle-apache-first-byte" in str(verified_run_root)
    foreign_root = apache_named_root and connector != "apache"
    sources = {
        "VERIFIED_RUN_ROOT": {
            "value": str(verified_run_root),
            "source": "caller environment of the historical canonical aggregate invocation",
        },
        "BUILD_ROOT": {
            "value": str(build_root),
            "source": "Makefile: VERIFIED_BUILD_ROOT defaults to VERIFIED_RUN_ROOT/build and ci/runtime/lifecycle/run-full-lifecycle-all-connectors.sh forwards it unchanged",
        },
        "EVIDENCE_ROOT": {
            "value": str(evidence_root),
            "source": "ci/runtime/lifecycle/run-full-lifecycle-all-connectors.sh defaults it from BUILD_ROOT/no-crs-evidence",
        },
        "NO_CRS_RAW_ROOT": {
            "value": str(build_root / "canonical-raw/no_crs_baseline"),
            "source": "ci/runtime/lifecycle/run-no-crs-baseline.sh default derived from BUILD_ROOT",
        },
        "CONNECTOR_COMPONENT_CACHE": {
            "value": str(component_cache_root),
            "source": "Makefile/ci/provisioning/cache/with-runtime-components.sh default derived from VERIFIED_RUN_ROOT/component-cache",
        },
        "TRAEFIK_CONNECTOR_BIN": {
            "value": str(build_root / "traefik-connector/traefik-forwardauth"),
            "source": "connectors/traefik/scripts/runtime_smoke.py inferred default; no explicit persisted assignment was recorded",
        },
    }
    record: dict[str, Any] = {
        "target": f"full-lifecycle-{connector}",
        "connector": connector,
        "run_id": run_id,
        "evidence_root": str(evidence_run),
        "run_root": str(raw_run),
        "build_root": str(build_root),
        "cache_root": str(component_cache_root),
        "component_cache_root": str(component_cache_root),
        "expected_binary": str(expected_binary),
        "resolved_binary": str(expected_binary) if metadata["binary_exists"] else None,
        "expected_binary_source": binary_source,
        "foreign_connector_root_detected": foreign_root,
        "source_of_each_environment_value": sources,
    }
    record.update(metadata)
    return record


def markdown(payload: dict[str, Any], language: str) -> str:
    german = language == "de"
    title = "Full-Lifecycle Runtime-Root-Audit" if not german else "Full-Lifecycle-Runtime-Root-Audit"
    intro = (
        "This report reconstructs paths and binary metadata only; it contains no raw environment values or payloads."
        if not german
        else "Dieser Bericht rekonstruiert nur Pfade und Binärmetadaten; er enthält keine rohen Umgebungswerte oder Payloads."
    )
    language_switch = (
        "**Language:** English | [Deutsch](full-lifecycle-runtime-root-audit.de.md)"
        if not german
        else "**Sprache:** [English](full-lifecycle-runtime-root-audit.md) | Deutsch"
    )
    labels = (
        {
            "run_id": "Run ID",
            "generated": "Generated",
            "target": "Target",
            "evidence": "Evidence root",
            "raw_run": "Raw run root",
            "build": "Build root",
            "cache": "Component cache root",
            "expected": "Expected binary",
            "resolved": "Resolved binary",
            "exists": "Exists/executable",
            "owner": "Owner/SHA-256",
            "foreign": "Foreign connector root detected",
            "environment": "Environment derivation",
            "findings": "Findings",
            "missing": "missing",
        }
        if not german
        else {
            "run_id": "Lauf-ID",
            "generated": "Erstellt",
            "target": "Ziel",
            "evidence": "Evidence-Root",
            "raw_run": "Raw-Run-Root",
            "build": "Build-Root",
            "cache": "Komponenten-Cache-Root",
            "expected": "Erwartete Binärdatei",
            "resolved": "Aufgelöste Binärdatei",
            "exists": "Existiert/ausführbar",
            "owner": "Eigentümer/SHA-256",
            "foreign": "Fremder Connector-Root erkannt",
            "environment": "Herleitung der Umgebung",
            "findings": "Erkenntnisse",
            "missing": "fehlend",
        }
    )
    german_environment_sources = {
        "VERIFIED_RUN_ROOT": "Aufruferumgebung der historischen kanonischen Aggregate-Ausführung.",
        "BUILD_ROOT": "Makefile: VERIFIED_BUILD_ROOT defaultet auf VERIFIED_RUN_ROOT/build; ci/runtime/lifecycle/run-full-lifecycle-all-connectors.sh leitet den Wert unverändert weiter.",
        "EVIDENCE_ROOT": "ci/runtime/lifecycle/run-full-lifecycle-all-connectors.sh leitete den historischen Default aus BUILD_ROOT/no-crs-evidence ab.",
        "NO_CRS_RAW_ROOT": "Historisches ci/runtime/lifecycle/run-no-crs-baseline.sh leitete den Default aus BUILD_ROOT ab.",
        "CONNECTOR_COMPONENT_CACHE": "Historisches Makefile/ci/provisioning/cache/with-runtime-components.sh leitete den Cache aus VERIFIED_RUN_ROOT/component-cache ab.",
        "TRAEFIK_CONNECTOR_BIN": "Von connectors/traefik/scripts/runtime_smoke.py abgeleiteter historischer Default; keine explizite persistierte Zuweisung wurde gefunden.",
    }
    german_findings = {
        "The historical aggregate forwarded one VERIFIED_RUN_ROOT to every connector; only raw evidence subdirectories were connector-qualified.": "Das historische Aggregate reichte einen VERIFIED_RUN_ROOT an alle Connectoren weiter; nur Raw-Evidence-Unterverzeichnisse waren connector-spezifisch.",
        "ci/runtime/lifecycle/run-no-crs-baseline.sh historically read runtime-env.sh and manifest.json from VERIFIED_RUN_ROOT/component-cache instead of CONNECTOR_COMPONENT_CACHE.": "Historisch las ci/runtime/lifecycle/run-no-crs-baseline.sh runtime-env.sh und manifest.json aus VERIFIED_RUN_ROOT/component-cache statt aus CONNECTOR_COMPONENT_CACHE.",
        "The Traefik full-lifecycle target dispatched runtime-smoke without a forwardAuth build prerequisite, so the inferred binary path was missing rather than non-executable.": "Das historische Traefik-Full-Lifecycle-Ziel startete runtime-smoke ohne forwardAuth-Build-Voraussetzung; der abgeleitete Binärpfad fehlte daher, statt nicht ausführbar zu sein.",
        "The historical Make wrapper translated a child Exit 77 into a Make failure status, losing the original BLOCKED classification at the stage boundary.": "Der historische Make-Wrapper übersetzte einen Child-Exit 77 in einen Make-Fehlerstatus und verlor damit die ursprüngliche BLOCKED-Klassifikation an der Stage-Grenze.",
    }
    lines = [
        f"# {title}",
        "",
        language_switch,
        "",
        intro,
        "",
        f"- {labels['run_id']}: `{payload['run_id']}`",
        f"- {labels['generated']}: `{payload['generated_at']}`",
        "",
    ]
    for record in payload["targets"]:
        lines.extend(
            [
                f"## {record['connector']}",
                "",
                f"- {labels['target']}: `{record['target']}`",
                f"- {labels['evidence']}: `{portable_path_reference(record['evidence_root'])}`",
                f"- {labels['raw_run']}: `{portable_path_reference(record['run_root'])}`",
                f"- {labels['build']}: `{portable_path_reference(record['build_root'])}`",
                f"- {labels['cache']}: `{portable_path_reference(record['component_cache_root'])}`",
                f"- {labels['expected']}: `{portable_path_reference(record['expected_binary'])}`",
                f"- {labels['resolved']}: `{portable_path_reference(record['resolved_binary']) if record['resolved_binary'] else labels['missing']}`",
                f"- {labels['exists']}: `{record['binary_exists']}` / `{record['binary_executable']}`",
                f"- {labels['owner']}: `{record['binary_owner'] or '-'} / {record['binary_sha256'] or '-'}`",
                f"- {labels['foreign']}: `{record['foreign_connector_root_detected']}`",
                "",
            ]
        )
    lines.extend([f"## {labels['environment']}", ""])
    for name, detail in payload["targets"][0]["source_of_each_environment_value"].items():
        source = german_environment_sources.get(name, detail["source"]) if german else detail["source"]
        lines.append(f"- `{name}`: {source}")
    lines.extend(["", f"## {labels['findings']}", ""])
    for finding in payload.get("findings", []):
        lines.append(f"- {german_findings.get(finding, finding) if german else finding}")
    lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verified-run-root", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--input-json", type=Path, help="Re-render retained Markdown from a prior JSON payload.")
    parser.add_argument("--output-json", required=True, type=Path)
    parser.add_argument("--output-md", required=True, type=Path)
    parser.add_argument("--output-md-de", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_json, output_json, output_md, output_md_de = configured_paths(args)
    if input_json:
        payload = read_object(input_json)
        if not payload or not isinstance(payload.get("targets"), list):
            raise SystemExit(f"invalid historical audit payload: {input_json}")
    else:
        if args.verified_run_root is None or not args.run_id:
            raise SystemExit("--verified-run-root and --run-id are required unless --input-json is supplied")
        verified_run_root = absolute(args.verified_run_root)
        build_root = verified_run_root / "build"
        evidence_root = absolute(args.evidence_root or build_root / "no-crs-evidence")
        cache_root = verified_run_root / "component-cache"
        payload = {
            "schema_version": 1,
            "kind": "full_lifecycle_runtime_root_audit",
            "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "run_id": args.run_id,
            "verified_run_root": str(verified_run_root),
            "findings": [
                "The historical aggregate forwarded one VERIFIED_RUN_ROOT to every connector; only raw evidence subdirectories were connector-qualified.",
                "ci/runtime/lifecycle/run-no-crs-baseline.sh historically read runtime-env.sh and manifest.json from VERIFIED_RUN_ROOT/component-cache instead of CONNECTOR_COMPONENT_CACHE.",
                "The Traefik full-lifecycle target dispatched runtime-smoke without a forwardAuth build prerequisite, so the inferred binary path was missing rather than non-executable.",
                "The historical Make wrapper translated a child Exit 77 into a Make failure status, losing the original BLOCKED classification at the stage boundary.",
            ],
            "targets": [
                build_record(
                    connector,
                    run_id=args.run_id,
                    verified_run_root=verified_run_root,
                    build_root=build_root,
                    evidence_root=evidence_root,
                    component_cache_root=cache_root,
                )
                for connector in CONNECTORS
            ],
        }
    write_text_file(output_json, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    write_text_file(output_md, markdown(payload, "en"))
    write_text_file(output_md_de, markdown(payload, "de"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
