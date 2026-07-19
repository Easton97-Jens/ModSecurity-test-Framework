#!/usr/bin/env python3
"""Import generated MRTS go-ftw tests as framework-compatible YAML cases."""

from __future__ import annotations

import argparse
import base64
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import parse_qsl, quote, urlencode

INCOMPLETE_REASON = "MRTS classification incomplete"
ROOT_COLLECTIONS = [
    "ARGS",
    "ARGS_NAMES",
    "REQUEST_HEADERS",
    "REQUEST_HEADERS_NAMES",
    "REQUEST_COOKIES",
    "REQUEST_COOKIES_NAMES",
    "REQUEST_URI",
    "REQUEST_BODY",
    "FILES",
    "FILES_NAMES",
    "XML",
    "RESPONSE_HEADERS",
    "RESPONSE_BODY",
    "AUDIT_LOG",
]
PHASE_RE = re.compile(r"phase:(\d)")
RULE_ID_RE = re.compile(r"\bid:(\d+)\b")
STATUS_RE = re.compile(r"\bstatus:(\d{3})\b")
DISRUPTIVE_RE = re.compile(r"\b(?:deny|block|drop|redirect)\b")
TRANS_RE = re.compile(r"\bt:[^,\"]+")
RULE_START_RE = re.compile(r"^\s*(?:SecRule|SecAction)\b")
SCALAR_TRUE = {"true", "yes", "on"}
SCALAR_FALSE = {"false", "no", "off"}
DEFAULT_CLASSIFICATIONS_FILE = Path("tests/mrts/classifications.yaml")
YAML_FILE_GLOB = "*.yaml"
ROOT_OVERLAY_KEYS = {"version", "cases"}
CASE_OVERLAY_KEYS = {
    "classification",
    "classification_reason",
    "connector_observations",
    "report_labels",
    "non_promotion",
    "traceability",
}
CONNECTOR_OVERLAY_KEYS = {
    "classification",
    "classification_reason",
    "evidence_label",
    "report_labels",
    "non_promotion",
    "traceability",
}
NON_PROMOTION_KEYS = {"reason", "markers"}
TRACEABILITY_KEYS = {"definition", "generated_ftw", "rule_id", "runtime_snapshot", "notes", "source"}
CONNECTOR_KEYS = {"apache", "nginx", "haproxy"}
FORBIDDEN_OVERLAY_KEYS = {
    "body",
    "data",
    "expect",
    "expected",
    "expected_status",
    "ftw",
    "generated_rule",
    "headers",
    "http_status",
    "intervention",
    "method",
    "path",
    "phase",
    "request",
    "rule",
    "rules",
    "status",
    "uri",
    "variables",
}


def absolute_path_without_traversal(value: Path | str, label: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(f"{label} must be an absolute path without traversal: {value}")
    return candidate


def nearest_existing_directory(path: Path) -> Path:
    current = path
    while not current.exists() and current != current.parent:
        current = current.parent
    return current


def has_symlink_component(path: Path) -> bool:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if current.is_symlink():
            return True
        if not current.exists():
            return False
    return False


def private_runtime_root(value: Path | str, label: str) -> Path:
    candidate = absolute_path_without_traversal(value, label)
    if has_symlink_component(candidate):
        raise ValueError(f"{label} must not contain a symlink component: {candidate}")
    existing = nearest_existing_directory(candidate)
    mode = os.lstat(existing).st_mode
    if not stat.S_ISDIR(mode):
        raise ValueError(f"{label} must have an existing directory parent: {candidate}")
    if stat.S_IMODE(mode) & stat.S_IWOTH:
        raise ValueError(f"{label} must not use a publicly writable directory: {existing}")
    return candidate.resolve(strict=False)


def safe_corpus_component(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value):
        raise ValueError(f"MRTS corpus must be a single safe path component: {value}")
    return value


def configured_mrts_build_root(
    build_root_value: str,
    mrts_build_root_value: str,
) -> Path | None:
    if mrts_build_root_value:
        return private_runtime_root(mrts_build_root_value, "MRTS build root")
    if build_root_value:
        return private_runtime_root(build_root_value, "build root") / "mrts"
    verified_run_root = os.environ.get("VERIFIED_RUN_ROOT")
    if verified_run_root:
        return private_runtime_root(verified_run_root, "verified run root") / "build" / "mrts"
    return None


def parse_scalar(value: str) -> Any:
    value = value.strip()
    if not value:
        return ""
    lowered = value.lower()
    if lowered in SCALAR_TRUE:
        return True
    if lowered in SCALAR_FALSE:
        return False
    if lowered in {"null", "none", "~"}:
        return None
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    if value.startswith("[") and value.endswith("]"):
        body = value[1:-1].strip()
        if not body:
            return []
        return [parse_scalar(item.strip()) for item in body.split(",")]
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    return value


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def dedent_block(lines: Iterable[str]) -> str:
    collected = list(lines)
    indents = [indent_of(line) for line in collected if line.strip()]
    if not indents:
        return ""
    margin = min(indents)
    return "\n".join(line[margin:] for line in collected).rstrip() + "\n"


class MinimalYamlParser:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.lines = [
            line
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() not in {"---", "..."}
        ]

    def next_significant(self, index: int) -> str | None:
        while index < len(self.lines):
            line = self.lines[index]
            if line.strip() and not line.lstrip().startswith("#"):
                return line
            index += 1
        return None

    def parse_node(self, index: int, indent: int) -> tuple[Any, int]:
        candidate = self.next_significant(index)
        if candidate is not None and candidate.strip().startswith("- "):
            candidate_indent = indent_of(candidate)
            if candidate_indent <= indent or candidate_indent == indent + 2:
                return self.parse_sequence(index, candidate_indent)
        return self.parse_mapping(index, indent)

    def parse_sequence(self, index: int, indent: int) -> tuple[list[Any], int]:
        parsed: list[Any] = []
        while index < len(self.lines):
            line = self.lines[index]
            if not line.strip() or line.lstrip().startswith("#"):
                index += 1
                continue
            if indent_of(line) < indent or not line.strip().startswith("- "):
                break
            if indent_of(line) > indent:
                raise ValueError(f"unexpected sequence indentation in {self.path}: {line}")
            value, index = self.parse_sequence_item(index, indent)
            parsed.append(value)
        return parsed, index

    def parse_sequence_item(self, index: int, indent: int) -> tuple[Any, int]:
        line = self.lines[index]
        raw_value = line.strip()[2:].strip()
        index += 1
        if not raw_value:
            return self.parse_node(index, indent + 2)
        if ":" not in raw_value or raw_value.startswith(("'", '"')):
            return parse_scalar(raw_value), index
        key, value = raw_value.split(":", 1)
        value, index = self.collect_quoted_scalar(value.strip(), index, indent)
        item: dict[str, Any] = {key.strip(): parse_scalar(value.strip())}
        candidate = self.next_significant(index)
        if candidate is not None and indent_of(candidate) == indent + 2:
            nested, index = self.parse_mapping(index, indent + 2)
            item.update(nested)
        return item, index

    def parse_mapping(self, index: int, indent: int) -> tuple[dict[str, Any], int]:
        parsed: dict[str, Any] = {}
        while index < len(self.lines):
            line = self.lines[index]
            if not line.strip() or line.lstrip().startswith("#"):
                index += 1
                continue
            current_indent = indent_of(line)
            if current_indent < indent:
                break
            if current_indent > indent:
                raise ValueError(f"unexpected mapping indentation in {self.path}: {line}")
            stripped = line.strip()
            if ":" not in stripped:
                raise ValueError(f"expected YAML mapping in {self.path}: {line}")
            key, raw_value = stripped.split(":", 1)
            key = key.strip()
            raw_value = raw_value.strip()
            index += 1
            if raw_value in {"|", ">"}:
                parsed[key], index = self.parse_block(index, current_indent)
            elif raw_value:
                raw_value, index = self.collect_quoted_scalar(raw_value, index, current_indent)
                parsed[key] = parse_scalar(raw_value)
            else:
                nested, index = self.parse_node(index, current_indent + 2)
                parsed[key] = nested
        return parsed, index

    def collect_quoted_scalar(self, raw_value: str, index: int, parent_indent: int) -> tuple[str, int]:
        if not raw_value or raw_value[0] not in {"'", '"'}:
            return raw_value, index
        quote = raw_value[0]
        if len(raw_value) > 1 and raw_value.endswith(quote):
            return raw_value, index
        parts = [raw_value]
        while index < len(self.lines):
            line = self.lines[index]
            if line.strip() and indent_of(line) <= parent_indent:
                break
            parts.append(line.strip())
            index += 1
            if parts[-1].endswith(quote):
                break
        return " ".join(parts), index

    def parse_block(self, index: int, parent_indent: int) -> tuple[str, int]:
        block_lines: list[str] = []
        while index < len(self.lines):
            line = self.lines[index]
            if line.strip() and indent_of(line) <= parent_indent:
                break
            block_lines.append(line)
            index += 1
        return dedent_block(block_lines), index

    def parse(self) -> dict[str, Any]:
        parsed, _ = self.parse_mapping(0, 0)
        return parsed


def load_yaml(path: Path) -> dict[str, Any]:
    parsed = MinimalYamlParser(path).parse()
    if not isinstance(parsed, dict):
        raise ValueError(f"YAML root must be a mapping: {path}")
    return parsed


def overlay_key(value: object) -> str:
    return str(value).strip().lower().replace("-", "_")


def validate_allowed_keys(mapping: Mapping[str, Any], allowed: set[str], context: str) -> None:
    unknown = sorted(str(key) for key in mapping if overlay_key(key) not in allowed)
    if unknown:
        raise ValueError(f"{context} contains unsupported key(s): {', '.join(unknown)}")


def validate_no_forbidden_overlay_keys(value: Any, context: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = overlay_key(key)
            if normalized in FORBIDDEN_OVERLAY_KEYS:
                raise ValueError(f"{context} may not set semantic key {key!r}")
            validate_no_forbidden_overlay_keys(item, f"{context}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            validate_no_forbidden_overlay_keys(item, f"{context}[{index}]")


def validate_string_list(value: Any, context: str) -> None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{context} must be a list of strings")


def validate_optional_string(value: Any, context: str) -> None:
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{context} must be a string")


def validate_non_promotion(value: Any, context: str) -> None:
    if not isinstance(value, Mapping):
        raise ValueError(f"{context} must be a mapping")
    validate_allowed_keys(value, NON_PROMOTION_KEYS, context)
    validate_optional_string(value.get("reason"), f"{context}.reason")
    if "markers" in value:
        validate_string_list(value["markers"], f"{context}.markers")


def validate_traceability(value: Any, context: str) -> None:
    if not isinstance(value, Mapping):
        raise ValueError(f"{context} must be a mapping")
    validate_allowed_keys(value, TRACEABILITY_KEYS, context)
    for key, item in value.items():
        if not isinstance(item, (str, int, bool)):
            raise ValueError(f"{context}.{key} must be a scalar")


def validate_connector_observations(value: Any, context: str) -> None:
    if not isinstance(value, Mapping):
        raise ValueError(f"{context} must be a mapping")
    validate_allowed_keys(value, CONNECTOR_KEYS, context)
    for connector, item in value.items():
        item_context = f"{context}.{connector}"
        if not isinstance(item, Mapping):
            raise ValueError(f"{item_context} must be a mapping")
        validate_allowed_keys(item, CONNECTOR_OVERLAY_KEYS, item_context)
        validate_optional_string(item.get("classification"), f"{item_context}.classification")
        validate_optional_string(item.get("classification_reason"), f"{item_context}.classification_reason")
        validate_optional_string(item.get("evidence_label"), f"{item_context}.evidence_label")
        if "report_labels" in item:
            validate_string_list(item["report_labels"], f"{item_context}.report_labels")
        if "non_promotion" in item:
            validate_non_promotion(item["non_promotion"], f"{item_context}.non_promotion")
        if "traceability" in item:
            validate_traceability(item["traceability"], f"{item_context}.traceability")


def validate_case_overlay(case_key: str, value: Any) -> Mapping[str, Any]:
    context = f"classification overlay cases.{case_key}"
    if not isinstance(value, Mapping):
        raise ValueError(f"{context} must be a mapping")
    validate_no_forbidden_overlay_keys(value, context)
    validate_allowed_keys(value, CASE_OVERLAY_KEYS, context)
    validate_optional_string(value.get("classification"), f"{context}.classification")
    validate_optional_string(value.get("classification_reason"), f"{context}.classification_reason")
    if "report_labels" in value:
        validate_string_list(value["report_labels"], f"{context}.report_labels")
    if "connector_observations" in value:
        validate_connector_observations(value["connector_observations"], f"{context}.connector_observations")
    if "non_promotion" in value:
        validate_non_promotion(value["non_promotion"], f"{context}.non_promotion")
    if "traceability" in value:
        validate_traceability(value["traceability"], f"{context}.traceability")
    return value


def load_classification_overlays(path: Path) -> dict[str, Mapping[str, Any]]:
    if not path.exists():
        return {}
    data = load_yaml(path)
    validate_no_forbidden_overlay_keys(data, "classification overlay")
    validate_allowed_keys(data, ROOT_OVERLAY_KEYS, "classification overlay")
    cases = data.get("cases", {})
    if not isinstance(cases, Mapping):
        raise ValueError("classification overlay cases must be a mapping")
    overlays: dict[str, Mapping[str, Any]] = {}
    for key, value in cases.items():
        case_key = str(key)
        overlays[case_key] = validate_case_overlay(case_key, value)
    return overlays


def yaml_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if value is None:
        return "null"
    text = str(value)
    if text == "" or text.lower() in {"true", "false", "null"} or re.search(r"[:#\n\[\]{}]", text) or text.strip() != text:
        return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return text


def render_yaml_mapping_item(key: Any, item: Any, indent: int) -> list[str]:
    prefix = " " * indent
    if isinstance(item, str) and "\n" in item:
        block_lines = [
            f"{prefix}  {line}" if line else prefix
            for line in item.rstrip("\n").split("\n")
        ]
        return [f"{prefix}{key}: |", *block_lines]
    if isinstance(item, (Mapping, list)):
        return [f"{prefix}{key}:", *render_yaml(item, indent + 2)]
    return [f"{prefix}{key}: {yaml_scalar(item)}"]


def render_yaml_mapping(value: Mapping[str, Any], indent: int) -> list[str]:
    lines: list[str] = []
    for key, item in value.items():
        lines.extend(render_yaml_mapping_item(key, item, indent))
    return lines


def render_yaml_list_item(item: Any, indent: int) -> list[str]:
    prefix = " " * indent
    if isinstance(item, Mapping):
        rendered = render_yaml(item, indent + 2)
        if rendered:
            return [f"{prefix}- {rendered[0].lstrip()}", *rendered[1:]]
        return [f"{prefix}- {{}}"]
    if isinstance(item, list):
        return [f"{prefix}-", *render_yaml(item, indent + 2)]
    return [f"{prefix}- {yaml_scalar(item)}"]


def render_yaml_list(value: list[Any], indent: int) -> list[str]:
    lines: list[str] = []
    for item in value:
        lines.extend(render_yaml_list_item(item, indent))
    return lines


def render_yaml(value: Any, indent: int = 0) -> list[str]:
    if isinstance(value, Mapping):
        return render_yaml_mapping(value, indent)
    if isinstance(value, list):
        return render_yaml_list(value, indent)
    return [f"{' ' * indent}{yaml_scalar(value)}"]


def write_case(path: Path, case: Mapping[str, Any]) -> None:
    path.write_text("\n".join(render_yaml(case)) + "\n", encoding="utf-8")


def slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "_", value.lower()).strip("_")
    return slug or "case"


def stable_case_name(seed: str, used: dict[str, int]) -> str:
    base = f"mrts_{slugify(seed)}"
    count = used.get(base, 0) + 1
    used[base] = count
    return base if count == 1 else f"{base}_{count}"


def rule_blocks(text: str) -> Iterable[str]:
    current: list[str] = []
    for line in text.splitlines():
        if RULE_START_RE.match(line) and current:
            yield "\n".join(current) + "\n"
            current = []
        if line.strip() or current:
            current.append(line)
    if current:
        yield "\n".join(current) + "\n"


def relative_path(path: Path | None, root: Path) -> str:
    if path is None:
        return ""
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def read_rule_files(rule_dir: Path) -> tuple[dict[str, tuple[str, Path]], dict[str, tuple[str, Path]]]:
    by_id: dict[str, tuple[str, Path]] = {}
    by_base: dict[str, tuple[str, Path]] = {}
    for path in sorted(rule_dir.glob("*.conf")):
        text = path.read_text(encoding="utf-8")
        by_base[path.stem] = (text, path)
        for block in rule_blocks(text):
            for rule_id in RULE_ID_RE.findall(block):
                by_id[rule_id] = (block, path)
    return by_id, by_base


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def test_rule_ids(test: Mapping[str, Any]) -> list[str]:
    ids: list[str] = []
    ruleid = test.get("ruleid")
    if ruleid not in (None, ""):
        ids.append(str(ruleid))
    for stage in as_list(test.get("stages")):
        if not isinstance(stage, Mapping):
            continue
        output = stage.get("output")
        if not isinstance(output, Mapping):
            continue
        log = output.get("log")
        if isinstance(log, Mapping):
            ids.extend(str(item) for item in as_list(log.get("expect_ids")) if item not in (None, ""))
            ids.extend(str(item) for item in as_list(log.get("no_expect_ids")) if item not in (None, ""))
    return sorted(set(ids))


def matching_rule(
    test: Mapping[str, Any],
    source_path: Path,
    by_id: Mapping[str, tuple[str, Path]],
    by_base: Mapping[str, tuple[str, Path]],
) -> tuple[str, Path | None]:
    rule_ids = test_rule_ids(test)
    for rule_id in rule_ids:
        if rule_id in by_id:
            return by_id[rule_id]
    if rule_ids:
        return "", None
    source_base = source_path.stem
    if "_" in source_base:
        source_base = source_base.split("_", 1)[1]
    for base, item in by_base.items():
        if base == source_base or base in source_path.stem or source_base in base:
            return item
    return "", None


def yaml_files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(directory.glob(YAML_FILE_GLOB))


def definition_aliases(path: Path) -> list[str]:
    aliases = [path.name, path.stem]
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return aliases
    for line in lines:
        if line.startswith(("testfile:", "rulefile:")):
            _, value = line.split(":", 1)
            token = value.strip().strip("'\"")
            if token:
                aliases.extend([token, Path(token).stem])
    return aliases


def add_definition_aliases(index: dict[str, Path], path: Path) -> None:
    for alias in definition_aliases(path):
        index[alias] = path


def source_definition_index(definition_dirs: Iterable[Path]) -> dict[str, Path]:
    index: dict[str, Path] = {}
    for definition_dir in definition_dirs:
        for path in yaml_files(definition_dir):
            add_definition_aliases(index, path)
    return index


def source_definition_for(ftw_file: Path, rule_file: Path | None, index: Mapping[str, Path]) -> Path | None:
    candidates = [ftw_file.name, ftw_file.stem]
    if "_" in ftw_file.stem:
        candidates.append(ftw_file.stem.split("_", 1)[1])
    if rule_file is not None:
        candidates.extend([rule_file.name, rule_file.stem])
    for candidate in candidates:
        if candidate in index:
            return index[candidate]
    return None


def upstream_reference_for(path: Path, upstream_dir: Path | None) -> Path | None:
    if upstream_dir is None or not upstream_dir.is_dir():
        return None
    direct = upstream_dir / path.name
    if direct.exists():
        return direct
    matches = sorted(upstream_dir.glob(path.name))
    return matches[0] if matches else None


def detect_phase(rule_text: str) -> int | str:
    phases = sorted({int(item) for item in PHASE_RE.findall(rule_text)})
    return phases[0] if len(phases) == 1 else "unknown"


def detect_variables(rule_text: str) -> list[str]:
    return [collection for collection in ROOT_COLLECTIONS if re.search(rf"\b{re.escape(collection)}\b", rule_text)]


def detect_topic(rule_text: str, variables: list[str]) -> str:
    if "@detectXSS" in rule_text:
        return "XSS-like compatibility probes"
    if "@detectSQLi" in rule_text:
        return "SQLi-like compatibility probes"
    if "FILES" in variables or "FILES_NAMES" in variables:
        return "Multipart / FILES"
    if "XML" in variables:
        return "XML"
    if "RESPONSE_HEADERS" in variables:
        return "Response header probes"
    if "RESPONSE_BODY" in variables:
        return "Response body experimental probes"
    if "AUDIT_LOG" in variables:
        return "Audit-log probes"
    if "REQUEST_BODY" in variables and re.search(r"JSON|application/json", rule_text, re.I):
        return "JSON"
    transformations = [
        item.split(":", 1)[1].strip().lower()
        for item in TRANS_RE.findall(rule_text)
    ]
    if any(item and item != "none" for item in transformations):
        return "Transformations"
    if re.search(r"@(rx|streq|contains|beginsWith|endsWith|eq|gt|lt|pm)\b", rule_text):
        return "Operators"
    return "MRTS generated / unclassified"


def detect_connector_scope(rule_text: str) -> list[str]:
    lowered = rule_text.lower()
    if "apache" in lowered and "nginx" not in lowered:
        return ["apache"]
    if "nginx" in lowered and "apache" not in lowered:
        return ["nginx"]
    return ["common"]


def capability_flags(phase: int | str, variables: list[str], topic: str) -> dict[str, bool]:
    capabilities: dict[str, bool] = {"intervention": True}
    if isinstance(phase, int) and 1 <= phase <= 4:
        capabilities[f"phase{phase}"] = True
    mapping = {
        "ARGS": "query_args",
        "ARGS_NAMES": "args_names",
        "REQUEST_HEADERS": "request_headers",
        "REQUEST_HEADERS_NAMES": "request_headers",
        "REQUEST_COOKIES": "request_cookies",
        "REQUEST_COOKIES_NAMES": "request_cookies",
        "REQUEST_URI": "request_uri",
        "REQUEST_BODY": "request_body",
        "FILES": "files",
        "FILES_NAMES": "files",
        "XML": "xml",
        "RESPONSE_HEADERS": "response_headers",
        "RESPONSE_BODY": "response_body",
        "AUDIT_LOG": "audit_log",
    }
    for variable in variables:
        capability = mapping.get(variable)
        if capability:
            capabilities[capability] = True
    if topic == "Transformations":
        capabilities["transformations"] = True
    if topic == "Operators":
        capabilities["operators"] = True
    return dict(sorted(capabilities.items()))


def first_stage(test: Mapping[str, Any]) -> Mapping[str, Any]:
    stages = as_list(test.get("stages"))
    if stages and isinstance(stages[0], Mapping):
        return stages[0]
    return {}


def normalize_header_map(headers: Any) -> dict[str, str]:
    if isinstance(headers, Mapping):
        return {
            str(key): str(value)
            for key, value in headers.items()
            if str(key).lower() not in {"host", "user-agent", "accept"}
        }
    if isinstance(headers, list):
        normalized: dict[str, str] = {}
        for item in headers:
            if isinstance(item, Mapping) and item.get("name") not in (None, ""):
                name = str(item["name"])
                if name.lower() not in {"host", "user-agent", "accept"}:
                    normalized[name] = str(item.get("value", ""))
        return normalized
    return {}


def empty_request() -> dict[str, Any]:
    return {"method": "GET", "path": "/"}


def decode_encoded_request(raw: str) -> str | None:
    try:
        return base64.b64decode(raw, validate=True).decode("utf-8", "replace")
    except Exception:
        return None


def split_http_message(decoded: str) -> tuple[str, str]:
    head, separator, body = decoded.partition("\r\n\r\n")
    if not separator:
        head, _, body = decoded.partition("\n\n")
    return head, body


def encoded_request_start(head: str) -> tuple[str, str, list[str]] | None:
    lines = head.replace("\r\n", "\n").split("\n")
    if not lines:
        return None
    parts = lines[0].split()
    if len(parts) < 2:
        return None
    method = parts[0].upper()
    path = parts[1]
    if method not in {"GET", "POST"} or not path.startswith("/"):
        return None
    return method, path, lines[1:]


def encoded_request_headers(lines: Iterable[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        if name.strip().lower() not in {"host", "user-agent", "accept", "content-length"}:
            headers[name.strip()] = value.strip()
    return headers


def multipart_boundary(headers: Mapping[str, str]) -> str | None:
    content_type = next(
        (value for key, value in headers.items() if key.lower() == "content-type"),
        "",
    )
    if not content_type.lower().startswith("multipart/form-data") or "boundary=" not in content_type:
        return None
    return content_type.split("boundary=", 1)[1].split(";", 1)[0].strip().strip('"')


def multipart_part_headers(part_head: str) -> tuple[str, str]:
    disposition = ""
    content_type = ""
    for part_line in part_head.replace("\r\n", "\n").split("\n"):
        if ":" not in part_line:
            continue
        key, value = part_line.split(":", 1)
        if key.strip().lower() == "content-disposition":
            disposition = value.strip()
        elif key.strip().lower() == "content-type":
            content_type = value.strip()
    return disposition, content_type


def multipart_part(raw_part: str) -> dict[str, Any] | None:
    raw_part = raw_part.strip("\r\n")
    if not raw_part or raw_part == "--":
        return None
    raw_part = raw_part.removesuffix("--").strip("\r\n")
    part_head, _, part_body = raw_part.partition("\r\n\r\n")
    if not part_head:
        part_head, _, part_body = raw_part.partition("\n\n")
    disposition, content_type = multipart_part_headers(part_head)
    name_match = re.search(r'\bname="([^"]+)"', disposition)
    if not name_match:
        return None
    part: dict[str, Any] = {
        "name": name_match.group(1),
        "body": part_body.rstrip("\r\n"),
    }
    filename_match = re.search(r'\bfilename="([^"]*)"', disposition)
    if filename_match:
        part["filename"] = filename_match.group(1)
    if content_type:
        part["content_type"] = content_type
    return part


def multipart_parts(body: str, boundary: str) -> list[dict[str, Any]]:
    parts: list[dict[str, Any]] = []
    for raw_part in body.split(f"--{boundary}"):
        parsed = multipart_part(raw_part)
        if parsed is not None:
            parts.append(parsed)
    return parts


def attach_body_and_headers(
    request: dict[str, Any],
    body: str,
    headers: Mapping[str, str],
) -> None:
    if body:
        request["body"] = body
    if headers:
        request["headers"] = dict(sorted(headers.items()))


def request_from_encoded(raw: str) -> tuple[dict[str, Any], bool]:
    decoded = decode_encoded_request(raw)
    if decoded is None:
        return empty_request(), False
    head, body = split_http_message(decoded)
    start = encoded_request_start(head)
    if start is None:
        return empty_request(), False
    method, path, header_lines = start
    headers = encoded_request_headers(header_lines)
    request: dict[str, Any] = {"method": method, "path": path}
    boundary = multipart_boundary(headers)
    if boundary is not None:
        parts = multipart_parts(body, boundary)
        if boundary and parts:
            request["multipart"] = {"boundary": boundary, "parts": parts}
            return request, True
        return request, False
    attach_body_and_headers(request, body, headers)
    return request, True


def query_path_from_form_body(path: str, body: str) -> str:
    pairs = parse_qsl(body, keep_blank_values=True)
    if not pairs:
        return path
    separator = "&" if "?" in path else "?"
    return f"{path}{separator}{urlencode(pairs, quote_via=quote)}"


def add_stage_data(
    request: dict[str, Any],
    method: str,
    uri: str,
    input_data: Mapping[str, Any],
) -> None:
    data_value = input_data.get("data")
    if data_value in (None, ""):
        return
    data = str(data_value)
    if method == "GET":
        request["path"] = query_path_from_form_body(uri, data)
        return
    request["body"] = data
    request.setdefault("headers", {}).setdefault(
        "Content-Type", "application/x-www-form-urlencoded",
    )


def request_from_mapping_input(input_data: Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
    method = str(input_data.get("method") or "GET").upper()
    uri = str(input_data.get("uri") or "/")
    if method not in {"GET", "POST"} or not uri.startswith("/"):
        return empty_request(), False
    request: dict[str, Any] = {"method": method, "path": uri}
    kept_headers = normalize_header_map(input_data.get("headers"))
    if kept_headers:
        request["headers"] = dict(sorted(kept_headers.items()))
    add_stage_data(request, method, uri, input_data)
    return request, True


def request_from_stage(stage: Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
    input_data = stage.get("input")
    if not isinstance(input_data, Mapping):
        return empty_request(), False
    if "encoded_request" in input_data:
        return request_from_encoded(str(input_data.get("encoded_request") or ""))
    return request_from_mapping_input(input_data)


def output_log(stage: Mapping[str, Any]) -> Mapping[str, Any]:
    output = stage.get("output")
    if not isinstance(output, Mapping):
        return {}
    log = output.get("log")
    return log if isinstance(log, Mapping) else {}


def expectation_from_rule(stage: Mapping[str, Any], rule_text: str) -> tuple[dict[str, Any], bool]:
    output = stage.get("output")
    if isinstance(output, Mapping) and isinstance(output.get("status"), int):
        status = int(output["status"])
        return {"status": status, "intervention": "deny" if status >= 400 else "pass"}, True
    log = output_log(stage)
    if log.get("no_expect_ids") not in (None, [], ""):
        return {"status": 200, "intervention": "pass"}, True
    if log.get("expect_ids") not in (None, [], ""):
        match = STATUS_RE.search(rule_text)
        if match and DISRUPTIVE_RE.search(rule_text):
            return {"status": int(match.group(1)), "intervention": "deny"}, True
    return {"status": 200, "intervention": "pass"}, False


def case_seed(source_path: Path, test: Mapping[str, Any]) -> str:
    for key in ("test_title", "desc", "ruleid", "test_id"):
        value = test.get(key)
        if value not in (None, ""):
            return f"{source_path.stem}_{value}"
    return source_path.stem


def matching_overlay(
    name: str,
    source_path: Path,
    test: Mapping[str, Any],
    overlays: Mapping[str, Mapping[str, Any]],
) -> Mapping[str, Any]:
    rule_id = str(test.get("ruleid") or "").strip()
    candidates = [name, source_path.stem, str(source_path)]
    if rule_id:
        candidates.extend([rule_id, f"rule:{rule_id}"])
    for candidate in candidates:
        if candidate in overlays:
            return overlays[candidate]
    return {}


def apply_classification_overlay(case: dict[str, Any], overlay: Mapping[str, Any]) -> None:
    if not overlay:
        return
    metadata = case.setdefault("metadata", {})
    for key in [
        "classification",
        "classification_reason",
        "connector_observations",
        "report_labels",
        "non_promotion",
        "traceability",
    ]:
        if key in overlay:
            metadata[key] = overlay[key]


def resolved_case_status(active: bool, case_status: str) -> str:
    if case_status != "computed":
        return case_status
    return "active" if active else "pending"


def case_limitations(active: bool, status: str, pending_reason: str) -> list[str]:
    limitations = [
        "Generated from MRTS go-ftw output.",
        "MRTS evidence is optional and variant-specific.",
    ]
    if not active:
        limitations.append(INCOMPLETE_REASON)
    if status == "pending" and pending_reason and pending_reason not in limitations:
        limitations.append(pending_reason)
    return limitations


def case_metadata(
    framework_root: Path,
    mrts_corpus: str,
    source_definition: Path | None,
    upstream_file: Path | None,
    generated_ftw_file: Path,
    rule_path: Path | None,
    phase: int | str,
    topic: str,
    variables: list[str],
    connector_scope: list[str],
    status: str,
) -> dict[str, Any]:
    return {
        "source": "mrts",
        "generated": True,
        "mrts_corpus": mrts_corpus,
        "source_definition": relative_path(source_definition, framework_root),
        "upstream_file": relative_path(upstream_file, framework_root),
        "generated_ftw_file": relative_path(generated_ftw_file, framework_root),
        "generated_rule_file": relative_path(rule_path, framework_root),
        "phase": phase,
        "topic": topic,
        "variables": variables,
        "connector_scope": connector_scope,
        "status": status,
        "runtime_verified": False,
    }


def initialized_case(
    name: str,
    source_path: Path,
    connector_scope: list[str],
    status: str,
    limitations: list[str],
    metadata: dict[str, Any],
    capabilities: dict[str, bool],
    request: dict[str, Any],
    expect: dict[str, Any],
) -> dict[str, Any]:
    return {
        "name": name,
        "origin": [
            {
                "repo": "owasp-modsecurity/MRTS",
                "path": str(source_path),
                "reason": "Generated MRTS go-ftw test imported into framework YAML schema.",
            }
        ],
        "category": "mrts",
        "portable": connector_scope == ["common"],
        "status": status,
        "known_limitations": limitations,
        "metadata": metadata,
        "capabilities": capabilities,
        "rules": "SecRuleEngine On\n",
        "request": request,
        "expect": expect,
    }


def apply_case_reasons(
    case: dict[str, Any],
    active: bool,
    status: str,
    pending_reason: str,
) -> None:
    if not active:
        case["reason"] = INCOMPLETE_REASON
        case["metadata"]["reason"] = INCOMPLETE_REASON
    if status == "pending" and pending_reason:
        case["reason"] = pending_reason
        case["metadata"]["reason"] = pending_reason


def apply_case_connector_scope(case: dict[str, Any], connector_scope: list[str]) -> None:
    if connector_scope != ["common"]:
        case["connector"] = connector_scope[0]


def apply_case_rule_id(case: dict[str, Any], rule_id: Any) -> None:
    if rule_id in (None, ""):
        return
    normalized = int(rule_id) if str(rule_id).isdigit() else str(rule_id)
    case["expect"]["rule_id"] = normalized
    case["metadata"]["mrts_rule_id"] = normalized


def build_case(
    source_path: Path,
    test: Mapping[str, Any],
    rule_text: str,
    rule_path: Path | None,
    used_names: dict[str, int],
    overlays: Mapping[str, Mapping[str, Any]],
    *,
    framework_root: Path,
    mrts_corpus: str,
    source_definition: Path | None,
    upstream_file: Path | None,
    generated_ftw_file: Path,
    case_status: str,
    pending_reason: str,
) -> dict[str, Any]:
    stage = first_stage(test)
    request, request_reliable = request_from_stage(stage)
    expect, expect_reliable = expectation_from_rule(stage, rule_text)
    phase = detect_phase(rule_text)
    variables = detect_variables(rule_text)
    topic = detect_topic(rule_text, variables)
    connector_scope = detect_connector_scope(rule_text)
    supported_phase = isinstance(phase, int) and 1 <= phase <= 4
    classification_reliable = bool(rule_text and supported_phase and variables)
    active = request_reliable and expect_reliable and classification_reliable
    status = resolved_case_status(active, case_status)
    name = stable_case_name(case_seed(source_path, test), used_names)
    metadata = case_metadata(
        framework_root, mrts_corpus, source_definition, upstream_file,
        generated_ftw_file, rule_path, phase, topic, variables, connector_scope, status,
    )
    case = initialized_case(
        name, source_path, connector_scope, status,
        case_limitations(active, status, pending_reason), metadata,
        capability_flags(phase, variables, topic), request, expect,
    )
    apply_case_reasons(case, active, status, pending_reason)
    apply_case_connector_scope(case, connector_scope)
    apply_case_rule_id(case, test.get("ruleid"))
    apply_classification_overlay(case, matching_overlay(name, source_path, test, overlays))
    return case


def iter_ftw_tests(path: Path) -> Iterable[Mapping[str, Any]]:
    data = load_yaml(path)
    tests = data.get("tests")
    if isinstance(tests, list):
        for item in tests:
            if isinstance(item, Mapping):
                yield item
    else:
        yield {"test_title": path.stem, "stages": []}


def import_cases(
    framework_root: Path,
    ftw_dir: Path,
    rules_dir: Path,
    output_dir: Path,
    classifications_file: Path,
    *,
    mrts_corpus: str,
    source_definition_dirs: list[Path],
    upstream_ftw_dir: Path | None,
    case_status: str,
    pending_reason: str,
) -> int:
    output_dir = private_runtime_root(output_dir, "output directory")
    runner_dir = framework_root / "tests" / "runners"
    if str(runner_dir) not in sys.path:
        sys.path.insert(0, str(runner_dir))
    from runner_core import load_case

    by_id, by_base = read_rule_files(rules_dir)
    overlays = load_classification_overlays(classifications_file)
    definition_index = source_definition_index(source_definition_dirs)
    output_dir.mkdir(parents=True, exist_ok=True)
    for old in yaml_files(output_dir):
        old.unlink()

    used_names: dict[str, int] = {}
    count = 0
    for ftw_file in yaml_files(ftw_dir):
        for test in iter_ftw_tests(ftw_file):
            try:
                source_path = ftw_file.relative_to(framework_root)
            except ValueError:
                source_path = ftw_file
            rule_text, rule_path = matching_rule(test, ftw_file, by_id, by_base)
            source_definition = source_definition_for(ftw_file, rule_path, definition_index)
            upstream_file = upstream_reference_for(ftw_file, upstream_ftw_dir)
            case = build_case(
                source_path,
                test,
                rule_text,
                rule_path,
                used_names,
                overlays,
                framework_root=framework_root,
                mrts_corpus=mrts_corpus,
                source_definition=source_definition,
                upstream_file=upstream_file,
                generated_ftw_file=ftw_file,
                case_status=case_status,
                pending_reason=pending_reason,
            )
            output_path = output_dir / f"{case['name']}.yaml"
            write_case(output_path, case)
            load_case(output_path)
            count += 1
    print(f"Imported MRTS framework cases: {count}")
    print(f"Corpus: {mrts_corpus}")
    print(f"Output: {output_dir}")
    return 0


def required_mrts_build_root(args: argparse.Namespace) -> Path:
    root = configured_mrts_build_root(args.build_root, args.mrts_build_root)
    if root is None:
        raise ValueError(
            "MRTS build root is required when an input or output directory is omitted; "
            "pass --mrts-build-root, --build-root, or set VERIFIED_RUN_ROOT"
        )
    return root


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--framework-root", default=str(Path.cwd()))
    parser.add_argument("--mrts-ftw-dir")
    parser.add_argument("--mrts-rules-dir")
    parser.add_argument("--output-dir")
    parser.add_argument("--classifications-file")
    parser.add_argument("--mrts-corpus", default="upstream-config-tests")
    parser.add_argument("--build-root", default=os.environ.get("BUILD_ROOT", ""))
    parser.add_argument("--mrts-build-root", default=os.environ.get("MRTS_BUILD_ROOT", ""))
    parser.add_argument("--source-definition-dir", action="append", default=[])
    parser.add_argument("--upstream-ftw-dir")
    parser.add_argument("--case-status", choices=["computed", "pending", "active"], default="computed")
    parser.add_argument("--pending-reason", default="")
    args = parser.parse_args()

    framework_root = Path(args.framework_root).resolve()
    needs_mrts_build_root = not all(
        (args.mrts_ftw_dir, args.mrts_rules_dir, args.output_dir)
    )
    mrts_build_root = required_mrts_build_root(args) if needs_mrts_build_root else None
    mrts_corpus = (
        safe_corpus_component(args.mrts_corpus)
        if mrts_build_root is not None
        else args.mrts_corpus
    )
    ftw_dir = (
        Path(args.mrts_ftw_dir).resolve()
        if args.mrts_ftw_dir
        else mrts_build_root / mrts_corpus / "ftw"
    )
    rules_dir = (
        Path(args.mrts_rules_dir).resolve()
        if args.mrts_rules_dir
        else mrts_build_root / mrts_corpus / "rules"
    )
    output_dir = (
        Path(args.output_dir)
        if args.output_dir
        else mrts_build_root / mrts_corpus / "framework-cases"
    )
    classifications_file = (
        Path(args.classifications_file).resolve()
        if args.classifications_file
        else framework_root / DEFAULT_CLASSIFICATIONS_FILE
    )
    source_definition_dirs = [
        Path(item).resolve()
        for item in (args.source_definition_dir or [])
    ]
    upstream_ftw_dir = Path(args.upstream_ftw_dir).resolve() if args.upstream_ftw_dir else None
    return import_cases(
        framework_root,
        ftw_dir,
        rules_dir,
        output_dir,
        classifications_file,
        mrts_corpus=mrts_corpus,
        source_definition_dirs=source_definition_dirs,
        upstream_ftw_dir=upstream_ftw_dir,
        case_status=args.case_status,
        pending_reason=args.pending_reason,
    )


if __name__ == "__main__":
    raise SystemExit(main())
