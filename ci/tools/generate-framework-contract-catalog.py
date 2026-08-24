#!/usr/bin/env python3
"""Generate the package-safe, payload-free Framework contract catalog.

This is a maintenance tool, not a public consumer API.  It reads only the
checked-in Framework catalog and YAML case roots, emits a deterministic JSON
resource, and deliberately omits request/response bodies, headers values,
rules, logs, and absolute paths.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping
import json
import os
from pathlib import Path
import re
import secrets
import sys
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = ROOT / "tests/cases/no-crs-baseline/catalog.json"
CASE_ROOT = ROOT / "tests/cases"
DEFAULT_OUTPUT = ROOT / "modsecurity_test_framework/data/framework-contract-catalog.json"
SCHEMA_VERSION = 1
IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9_.:/-]{0,127}$")
MAX_CASES = 512
REQUIRED_CAPABILITY_LABEL = "required capability"


class GenerationError(ValueError):
    """Raised when checked-in sources cannot form one unambiguous catalog."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GenerationError("duplicate JSON key in source catalog")
        result[key] = value
    return result


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GenerationError("unable to read source catalog") from exc


def _identifier(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not IDENTIFIER_RE.fullmatch(value)
        or ".." in value
        or "//" in value
    ):
        raise GenerationError(f"invalid {label}")
    return value


def _string_list(value: Any, label: str, limit: int = 64) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > limit:
        raise GenerationError(f"invalid {label}")
    result = [_identifier(item, label) for item in value]
    if len(set(result)) != len(result):
        raise GenerationError(f"duplicate {label}")
    return result


def _optional_status(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 100 <= value <= 599:
        raise GenerationError("invalid declared HTTP status")
    return value


def _catalog_http_status(value: Any) -> int | None:
    """Return only a declared HTTP status, never a process exit status.

    The legacy No-CRS catalog reuses ``expected_status`` for a few configuration
    and lifecycle process outcomes (0/1).  Those values are intentionally not
    converted into HTTP statuses in the public typed contract.
    """

    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 599:
        raise GenerationError("invalid declared status value")
    return value if value >= 100 else None


def _optional_rule_id(value: Any) -> int | None:
    if value is None:
        return None
    if value == "none":
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 9_999_999:
        raise GenerationError("invalid declared rule id")
    return value


def _action(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    label = value.lower()
    if "redirect" in label:
        return "redirect"
    if "log_only" in label:
        return "log_only"
    if "abort" in label or "drop" in label or "reset" in label:
        return "abort_connection"
    if "deny" in label or "block" in label:
        return "deny"
    if "allow" in label or label == "pass":
        return "pass"
    return None


def _transport(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    label = value.lower()
    if "stream_reset" in label or "rst_stream" in label or "stream_cancel" in label:
        return "stream_reset"
    if "abort" in label or "disconnect" in label or "close" in label:
        return "connection_aborted"
    if "http3" in label or label.startswith("h3_"):
        return "http3"
    if "http2" in label or label.startswith("h2_"):
        return "http2"
    if "keepalive" in label or "keep_alive" in label:
        return "keep_alive"
    if "first_byte" in label:
        return "first_byte_before_response_end"
    if "buffer" in label:
        return "no_full_response_buffering"
    return None


def _compound(conditions: list[dict[str, Any]]) -> dict[str, Any]:
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for condition in conditions:
        encoded = json.dumps(condition, sort_keys=True, separators=(",", ":"))
        if encoded not in seen:
            seen.add(encoded)
            unique.append(condition)
    if not unique:
        raise GenerationError("missing declared expectation")
    if len(unique) == 1:
        return unique[0]
    return {"kind": "compound", "conditions": unique}


def _catalog_intervention(action: str, status: int | None, rule_id: int | None) -> dict[str, Any]:
    condition: dict[str, Any] = {"kind": "intervention", "action": action}
    if status is not None:
        condition["http_status"] = status
    if rule_id is not None:
        condition["rule_ids"] = [rule_id]
    return condition


def _catalog_action(action: str, rule_id: int | None) -> dict[str, Any]:
    condition: dict[str, Any] = {"kind": "action", "action": action}
    if rule_id is not None:
        condition["rule_ids"] = [rule_id]
    return condition


def _catalog_result_conditions(
    result: str, case: Mapping[str, Any], action: str | None, status: int | None, rule_id: int | None
) -> list[dict[str, Any]]:
    if status is not None:
        if action is not None and action != "pass":
            return [_catalog_intervention(action, status, rule_id)]
        return [{"kind": "http_status", "http_status": status}]
    if action is not None and action != "pass":
        return [_catalog_action(action, rule_id)]
    return _catalog_fallback_conditions(result, case)


def _catalog_fallback_conditions(result: str, case: Mapping[str, Any]) -> list[dict[str, Any]]:
    if result == "clean_shutdown":
        return [{
            "kind": "lifecycle",
            "predicates": {"request_completed": True, "cleanup_balanced": True},
        }]
    transport = _transport(result)
    if transport is not None:
        return [{"kind": "transport", "state": transport}]
    if "cleanup" in result:
        return [{"kind": "cleanup", "state": "balanced"}]
    if "body" not in result:
        return [{"kind": "event", "event_type": result}]
    capabilities = _string_list(case.get("required_capabilities"), REQUIRED_CAPABILITY_LABEL)
    if any(name.startswith("request_body") for name in capabilities):
        return [{"kind": "request_body", "state": "observed"}]
    if any(name.startswith("response_body") for name in capabilities):
        return [{"kind": "response_body", "state": "observed"}]
    return [{"kind": "event", "event_type": result}]


def _catalog_expectation(case: Mapping[str, Any]) -> dict[str, Any]:
    result = _identifier(case.get("expected_result"), "expected result")
    status = _catalog_http_status(case.get("expected_status"))
    rule_id = _optional_rule_id(case.get("expected_rule_id"))
    fields = _string_list(case.get("expected_event_fields"), "event field")
    action = _action(result)
    conditions = _catalog_result_conditions(result, case, action, status, rule_id)
    if "cleanup" in result and not any(item["kind"] == "cleanup" for item in conditions):
        conditions.append({"kind": "cleanup", "state": "balanced"})
    if rule_id is not None and not any(item["kind"] in {"intervention", "action"} for item in conditions):
        conditions.append({"kind": "rule_match", "rule_ids": [rule_id]})
    if fields:
        conditions.append({"kind": "event", "fields": fields})
    return _compound(conditions)


def _yaml_primary_conditions(
    raw_expectation: Mapping[str, Any], status: int | None, action: str | None, rule_id: int | None
) -> list[dict[str, Any]]:
    if action is not None:
        condition: dict[str, Any] = {"kind": "intervention", "action": action}
        if status is not None:
            condition["http_status"] = status
        if rule_id is not None:
            condition["rule_ids"] = [rule_id]
        return [condition]
    if status is not None:
        return [{"kind": "http_status", "http_status": status}]
    return []


def _yaml_transport_condition(raw_expectation: Mapping[str, Any]) -> dict[str, Any] | None:
    declared_transport = raw_expectation.get("transport")
    if not isinstance(declared_transport, str) or declared_transport == "http_status":
        return None
    transport = _transport(declared_transport)
    if transport is None:
        raise GenerationError("unknown declared transport expectation")
    return {"kind": "transport", "state": transport}


def _yaml_event_fields(raw_expectation: Mapping[str, Any]) -> list[str]:
    return [
        field
        for field, source_key in (("audit_log", "audit_log"), ("phase4_log", "phase4_log"))
        if raw_expectation.get(source_key) is not None
    ]


def _yaml_expectation(document: Mapping[str, Any]) -> dict[str, Any]:
    raw_expectation = document.get("expect")
    if not isinstance(raw_expectation, Mapping):
        raise GenerationError("case has no expectation mapping")
    status = _optional_status(raw_expectation.get("status"))
    action = _action(raw_expectation.get("intervention"))
    rule_id = _optional_rule_id(raw_expectation.get("rule_id"))
    conditions = _yaml_primary_conditions(raw_expectation, status, action, rule_id)
    transport = _yaml_transport_condition(raw_expectation)
    if transport is not None:
        conditions.append(transport)
    if raw_expectation.get("response_contains") is not None:
        conditions.append({"kind": "response_body", "state": "matched"})
    event_fields = _yaml_event_fields(raw_expectation)
    if event_fields:
        conditions.append({"kind": "event", "fields": event_fields})
    outcome = raw_expectation.get("outcome")
    if outcome is not None:
        conditions.append({"kind": "event", "event_type": _identifier(outcome, "outcome")})
    if rule_id is not None and not any(item["kind"] == "intervention" for item in conditions):
        conditions.append({"kind": "rule_match", "rule_ids": [rule_id]})
    if not conditions and document.get("expected_result") is not None:
        conditions.append({"kind": "event", "event_type": _identifier(document["expected_result"], "expected result")})
    return _compound(conditions)


def _catalog_record(case: Mapping[str, Any]) -> dict[str, Any]:
    case_id = _identifier(case.get("case_id"), "case id")
    title = case.get("title")
    if not isinstance(title, str) or not title or len(title) > 256:
        raise GenerationError("invalid catalog title")
    phase = case.get("phase")
    if isinstance(phase, bool) or not isinstance(phase, int) or not 0 <= phase <= 9:
        raise GenerationError("invalid catalog phase")
    group = _identifier(case.get("group"), "catalog group")
    required_capabilities = _string_list(
        case.get("required_capabilities"), REQUIRED_CAPABILITY_LABEL
    )
    return {
        "framework_test_id": f"no-crs-baseline:{case_id}",
        "display_name": title,
        "scenario_category": group,
        "phase": phase,
        "area": "no-crs-baseline",
        "profile": "no-crs-baseline",
        "required_capabilities": required_capabilities,
        "expectation": _catalog_expectation(case),
        "applicability": {
            "portable": None,
            "requires_crs": False,
            "connector": None,
            "declared_status": None,
        },
        "catalogs": ["no-crs-baseline"],
        "sources": [{"kind": "no_crs_catalog", "path": "tests/cases/no-crs-baseline/catalog.json"}],
    }


def _yaml_capabilities(document: Mapping[str, Any]) -> list[str]:
    explicit = document.get("required_capabilities")
    if explicit is not None:
        return _string_list(explicit, REQUIRED_CAPABILITY_LABEL)
    capabilities = document.get("capabilities")
    if not isinstance(capabilities, Mapping):
        return []
    result = [_identifier(name, "capability") for name, value in capabilities.items() if value is True]
    if len(result) > 64:
        raise GenerationError("too many capabilities")
    return sorted(result)


def _yaml_case_metadata(
    document: Mapping[str, Any], name: str
) -> tuple[str, str | None, int | None, str | None, str, str | None]:
    title = document.get("title")
    display_name = title if isinstance(title, str) and title else name
    if not isinstance(display_name, str) or len(display_name) > 256:
        raise GenerationError("invalid case title")
    category = document.get("category")
    if category is not None:
        category = _identifier(category, "case category")
    phase = document.get("phase")
    if phase is not None and (isinstance(phase, bool) or not isinstance(phase, int) or not 0 <= phase <= 9):
        raise GenerationError("invalid case phase")
    metadata = document.get("metadata")
    area = metadata.get("area") if isinstance(metadata, Mapping) else None
    if area is not None:
        area = _identifier(area, "case area")
    profile = "no-crs-baseline" if document.get("no_crs_baseline") is True else "default"
    profile_data = document.get("with_crs_no_mrts")
    if isinstance(profile_data, Mapping):
        profile = _identifier(profile_data.get("profile"), "profile")
    declared_status = document.get("status")
    if declared_status is not None:
        declared_status = _identifier(declared_status, "declared case status")
    return display_name, category, phase, area, profile, declared_status


def _yaml_applicability(document: Mapping[str, Any], connector: str | None, declared_status: str | None) -> dict[str, Any]:
    requires_crs = document.get("requires_crs")
    if requires_crs is not None and not isinstance(requires_crs, bool):
        raise GenerationError("invalid requires_crs")
    portable = document.get("portable")
    if portable is not None and not isinstance(portable, bool):
        raise GenerationError("invalid portable")
    return {
        "portable": portable,
        "requires_crs": requires_crs,
        "connector": connector,
        "declared_status": declared_status,
    }


def _yaml_record(document: Mapping[str, Any], relative_path: str, catalog_ids: set[str]) -> tuple[str, dict[str, Any], bool]:
    name = _identifier(document.get("name"), "case name")
    connector = document.get("connector")
    if connector is not None:
        connector = _identifier(connector, "connector")
    no_crs = document.get("no_crs_baseline") is True
    merge_with_catalog = no_crs and connector is None and name in catalog_ids
    if merge_with_catalog:
        return f"no-crs-baseline:{name}", {}, True
    case_id = "yaml:" + relative_path.removesuffix(".yaml").replace("/", ":")
    _identifier(case_id, "framework test id")
    display_name, category, phase, area, profile, declared_status = _yaml_case_metadata(document, name)
    return case_id, {
        "framework_test_id": case_id,
        "display_name": display_name,
        "scenario_category": category,
        "phase": phase,
        "area": area,
        "profile": profile,
        "required_capabilities": _yaml_capabilities(document),
        "expectation": _yaml_expectation(document),
        "applicability": _yaml_applicability(document, connector, declared_status),
        "catalogs": ["framework-yaml"],
        "sources": [{"kind": "yaml_case", "path": relative_path}],
    }, False


def _profile_source(document: Mapping[str, Any]) -> Mapping[str, Any]:
    profile_data = document.get("with_crs_no_mrts")
    if not isinstance(profile_data, Mapping):
        raise GenerationError("missing CRS profile")
    return profile_data


def _profile_expectation(profile_data: Mapping[str, Any]) -> tuple[int, str, int]:
    canonical_block = profile_data.get("canonical_block")
    if not isinstance(canonical_block, Mapping):
        raise GenerationError("missing canonical CRS block")
    status = _optional_status(canonical_block.get("expected_status"))
    action = _action(canonical_block.get("expected_intervention"))
    rule_id = _optional_rule_id(canonical_block.get("expected_rule_id"))
    if status is None or action is None or rule_id is None:
        raise GenerationError("invalid canonical CRS block")
    return status, action, rule_id


def _profile_provenance(profile_data: Mapping[str, Any], rule_id: int) -> dict[str, Any]:
    provenance = profile_data.get("provenance")
    if not isinstance(provenance, Mapping):
        raise GenerationError("missing CRS provenance")
    commit = provenance.get("commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise GenerationError("invalid CRS provenance commit")
    return {
        "release_tag": _identifier(provenance.get("release_tag"), "release tag"),
        "commit": commit,
        "expected_rule_id": rule_id,
    }


def _profile(document: Mapping[str, Any]) -> dict[str, Any]:
    profile_data = _profile_source(document)
    profile_name = _identifier(profile_data.get("profile"), "profile")
    connectors = _string_list(profile_data.get("connectors"), "profile connector", limit=16)
    status, action, rule_id = _profile_expectation(profile_data)
    return {
        "profile": profile_name,
        "fixture_id": _identifier(document.get("fixture_id"), "fixture id"),
        "connectors": sorted(connectors),
        "required_capabilities": _yaml_capabilities(document),
        "expectation": {
            "kind": "intervention",
            "http_status": status,
            "action": action,
            "rule_ids": [rule_id],
        },
        "provenance": _profile_provenance(profile_data, rule_id),
    }


def _catalog_source_records() -> tuple[dict[str, dict[str, Any]], set[str]]:
    catalog = _read_json(CATALOG_PATH)
    if not isinstance(catalog, Mapping) or catalog.get("schema_version") != 1:
        raise GenerationError("unsupported source catalog schema")
    raw_cases = catalog.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases or len(raw_cases) > MAX_CASES:
        raise GenerationError("invalid source catalog cases")
    records: dict[str, dict[str, Any]] = {}
    catalog_ids: set[str] = set()
    for raw_case in raw_cases:
        if not isinstance(raw_case, Mapping):
            raise GenerationError("invalid source catalog case")
        record = _catalog_record(raw_case)
        record_id = record["framework_test_id"]
        if record_id in records:
            raise GenerationError("duplicate source catalog test id")
        records[record_id] = record
        catalog_ids.add(_identifier(raw_case.get("case_id"), "case id"))
    return records, catalog_ids


def _read_yaml_case(path: Path) -> tuple[str, Mapping[str, Any]]:
    if path.is_symlink():
        raise GenerationError("symlinked YAML source is not allowed")
    relative_path = path.relative_to(ROOT).as_posix()
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise GenerationError("unable to read YAML source case") from exc
    if not isinstance(document, Mapping):
        raise GenerationError("invalid YAML source case")
    return relative_path, document


def _merge_yaml_record(
    records: dict[str, dict[str, Any]],
    record_id: str,
    record: dict[str, Any],
    merge_with_catalog: bool,
    relative_path: str,
) -> None:
    if merge_with_catalog:
        existing = records.get(record_id)
        if existing is None:
            raise GenerationError("unknown catalog merge target")
        existing["catalogs"].append("framework-yaml")
        existing["sources"].append({"kind": "yaml_case", "path": relative_path})
        return
    if record_id in records:
        raise GenerationError("duplicate or conflicting framework test id")
    records[record_id] = record


def _yaml_source_records(
    records: dict[str, dict[str, Any]], catalog_ids: set[str]
) -> dict[str, Any]:
    yaml_paths = sorted(CASE_ROOT.rglob("*.yaml"))
    if not yaml_paths or len(yaml_paths) > MAX_CASES:
        raise GenerationError("invalid YAML source case count")
    profile: dict[str, Any] | None = None
    for path in yaml_paths:
        relative_path, document = _read_yaml_case(path)
        record_id, record, merge_with_catalog = _yaml_record(document, relative_path, catalog_ids)
        _merge_yaml_record(records, record_id, record, merge_with_catalog, relative_path)
        if document.get("with_crs_no_mrts") is not None:
            if profile is not None:
                raise GenerationError("duplicate CRS profile")
            profile = _profile(document)
    if profile is None:
        raise GenerationError("missing CRS profile source")
    return profile


def build_catalog() -> dict[str, Any]:
    records, catalog_ids = _catalog_source_records()
    profile = _yaml_source_records(records, catalog_ids)
    tests = [records[record_id] for record_id in sorted(records)]
    return {
        "schema_version": SCHEMA_VERSION,
        "source_commit": "unavailable",
        "profiles": {profile["profile"]: profile},
        "tests": tests,
    }


def _serialized_catalog() -> str:
    return json.dumps(build_catalog(), indent=2, sort_keys=True) + "\n"


def _output_relative_path(output: Path) -> Path:
    """Return one lexical, Framework-contained output path.

    The maintenance generator is allowed to update only its checked-in JSON
    resource.  Resolve neither caller-selected paths nor symlinks here: the
    no-follow descriptor walk below owns that check without a check/use race.
    """

    try:
        relative = output.relative_to(ROOT)
    except ValueError as exc:
        raise GenerationError("output must remain within the Framework root") from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise GenerationError("output must remain within the Framework root")
    return relative


def _open_output_parent(relative_output: Path) -> tuple[int, str]:
    """Open the output parent below the physical Framework root, no-follow."""

    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not no_follow or not directory:
        raise GenerationError("platform cannot safely write contract catalog")
    descriptor: int | None = None
    try:
        descriptor = os.open(ROOT, os.O_RDONLY | directory | no_follow)
        for component in relative_output.parts[:-1]:
            try:
                next_descriptor = os.open(
                    component,
                    os.O_RDONLY | directory | no_follow,
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                os.mkdir(component, mode=0o755, dir_fd=descriptor)
                next_descriptor = os.open(
                    component,
                    os.O_RDONLY | directory | no_follow,
                    dir_fd=descriptor,
                )
            os.close(descriptor)
            descriptor = next_descriptor
        leaf = relative_output.parts[-1]
        return descriptor, leaf
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise GenerationError("unable to safely open contract catalog output") from exc


def _write_output(output: Path, serialized: str) -> None:
    """Atomically replace a regular output below a no-follow directory walk."""

    relative_output = _output_relative_path(output)
    parent_descriptor, leaf = _open_output_parent(relative_output)
    temporary_name = f".framework-contract-catalog-{secrets.token_hex(16)}.tmp"
    file_descriptor: int | None = None
    published = False
    try:
        file_descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_descriptor,
        )
        with os.fdopen(file_descriptor, "wb", closefd=True) as handle:
            file_descriptor = None
            handle.write(serialized.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(
            temporary_name,
            leaf,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        published = True
    except OSError as exc:
        raise GenerationError("unable to safely write contract catalog") from exc
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        if not published:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            except OSError:
                pass
        os.close(parent_descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    output = args.output
    if not output.is_absolute():
        output = ROOT / output
    try:
        _output_relative_path(output)
    except GenerationError as exc:
        print(exc, file=sys.stderr)
        return 2
    try:
        serialized = _serialized_catalog()
    except GenerationError as exc:
        print(f"contract catalog generation failed: {exc}", file=sys.stderr)
        return 2
    if args.check:
        try:
            current = output.read_text(encoding="utf-8")
        except OSError:
            current = ""
        if current != serialized:
            print("framework contract catalog is stale", file=sys.stderr)
            return 1
        return 0
    try:
        _write_output(output, serialized)
    except GenerationError as exc:
        print(f"contract catalog generation failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
