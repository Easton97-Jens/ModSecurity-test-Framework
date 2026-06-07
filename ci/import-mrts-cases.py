#!/usr/bin/env python3
"""Import generated MRTS go-ftw tests as framework-compatible YAML cases."""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

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
SCALAR_TRUE = {"true", "yes", "on"}
SCALAR_FALSE = {"false", "no", "off"}


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
                parsed[key] = parse_scalar(raw_value)
            else:
                nested, index = self.parse_node(index, current_indent + 2)
                parsed[key] = nested
        return parsed, index

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


def render_yaml(value: Any, indent: int = 0) -> list[str]:
    prefix = " " * indent
    if isinstance(value, Mapping):
        lines: list[str] = []
        for key, item in value.items():
            if isinstance(item, str) and "\n" in item:
                lines.append(f"{prefix}{key}: |")
                lines.extend(f"{prefix}  {line}" if line else f"{prefix}" for line in item.rstrip("\n").split("\n"))
            elif isinstance(item, (Mapping, list)):
                lines.append(f"{prefix}{key}:")
                lines.extend(render_yaml(item, indent + 2))
            else:
                lines.append(f"{prefix}{key}: {yaml_scalar(item)}")
        return lines
    if isinstance(value, list):
        lines = []
        for item in value:
            if isinstance(item, Mapping):
                rendered = render_yaml(item, indent + 2)
                if rendered:
                    lines.append(f"{prefix}- {rendered[0].lstrip()}")
                    lines.extend(rendered[1:])
                else:
                    lines.append(f"{prefix}- {{}}")
            elif isinstance(item, list):
                lines.append(f"{prefix}-")
                lines.extend(render_yaml(item, indent + 2))
            else:
                lines.append(f"{prefix}- {yaml_scalar(item)}")
        return lines
    return [f"{prefix}{yaml_scalar(value)}"]


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


def read_rule_files(rule_dir: Path) -> tuple[dict[str, str], dict[str, str]]:
    by_id: dict[str, str] = {}
    by_base: dict[str, str] = {}
    for path in sorted(rule_dir.glob("*.conf")):
        text = path.read_text(encoding="utf-8")
        by_base[path.stem] = text
        for rule_id in RULE_ID_RE.findall(text):
            by_id[rule_id] = text
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


def matching_rule_text(test: Mapping[str, Any], source_path: Path, by_id: Mapping[str, str], by_base: Mapping[str, str]) -> str:
    for rule_id in test_rule_ids(test):
        if rule_id in by_id:
            return by_id[rule_id]
    source_base = source_path.stem
    if "_" in source_base:
        source_base = source_base.split("_", 1)[1]
    for base, text in by_base.items():
        if base == source_base or base in source_path.stem or source_base in base:
            return text
    return ""


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
    if TRANS_RE.search(rule_text):
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
    if isinstance(phase, int):
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


def request_from_stage(stage: Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
    input_data = stage.get("input")
    if not isinstance(input_data, Mapping):
        return {"method": "GET", "path": "/"}, False
    method = str(input_data.get("method") or "GET").upper()
    uri = str(input_data.get("uri") or "/")
    if method not in {"GET", "POST"} or not uri.startswith("/"):
        return {"method": "GET", "path": "/"}, False
    request: dict[str, Any] = {"method": method, "path": uri}
    headers = input_data.get("headers")
    if isinstance(headers, Mapping):
        kept_headers = {
            str(key): str(value)
            for key, value in headers.items()
            if str(key).lower() not in {"host", "user-agent", "accept"}
        }
        if kept_headers:
            request["headers"] = dict(sorted(kept_headers.items()))
    if "data" in input_data and input_data.get("data") not in (None, ""):
        request["body"] = str(input_data.get("data"))
        if "headers" not in request:
            request["headers"] = {}
        request["headers"].setdefault("Content-Type", "application/x-www-form-urlencoded")
    if "encoded_request" in input_data:
        return request, False
    return request, True


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


def build_case(source_path: Path, test: Mapping[str, Any], rule_text: str, used_names: dict[str, int]) -> dict[str, Any]:
    stage = first_stage(test)
    request, request_reliable = request_from_stage(stage)
    expect, expect_reliable = expectation_from_rule(stage, rule_text)
    phase = detect_phase(rule_text)
    variables = detect_variables(rule_text)
    topic = detect_topic(rule_text, variables)
    connector_scope = detect_connector_scope(rule_text)
    classification_reliable = bool(rule_text and isinstance(phase, int) and variables)
    active = request_reliable and expect_reliable and classification_reliable
    name = stable_case_name(case_seed(source_path, test), used_names)
    limitations = [
        "Generated from MRTS go-ftw output.",
        "MRTS evidence is optional and variant-specific.",
    ]
    if not active:
        limitations.append(INCOMPLETE_REASON)
    case: dict[str, Any] = {
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
        "status": "active" if active else "pending",
        "known_limitations": limitations,
        "metadata": {
            "source": "mrts",
            "generated": True,
            "phase": phase,
            "topic": topic,
            "variables": variables,
            "connector_scope": connector_scope,
            "status": "active" if active else "pending",
        },
        "capabilities": capability_flags(phase, variables, topic),
        "rules": "SecRuleEngine On\n",
        "request": request,
        "expect": expect,
    }
    if not active:
        case["reason"] = INCOMPLETE_REASON
        case["metadata"]["reason"] = INCOMPLETE_REASON
    if connector_scope != ["common"]:
        case["connector"] = connector_scope[0]
    rule_id = test.get("ruleid")
    if rule_id not in (None, ""):
        case["expect"]["rule_id"] = int(rule_id) if str(rule_id).isdigit() else str(rule_id)
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


def import_cases(framework_root: Path, ftw_dir: Path, rules_dir: Path, output_dir: Path) -> int:
    by_id, by_base = read_rule_files(rules_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    for old in output_dir.glob("*.yaml"):
        old.unlink()

    used_names: dict[str, int] = {}
    count = 0
    for ftw_file in sorted(ftw_dir.glob("*.yaml")):
        for test in iter_ftw_tests(ftw_file):
            rule_text = matching_rule_text(test, ftw_file, by_id, by_base)
            try:
                source_path = ftw_file.relative_to(framework_root)
            except ValueError:
                source_path = ftw_file
            case = build_case(source_path, test, rule_text, used_names)
            write_case(output_dir / f"{case['name']}.yaml", case)
            count += 1
    print(f"Imported MRTS framework cases: {count}")
    print(f"Output: {output_dir}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--framework-root", default=str(Path.cwd()))
    parser.add_argument("--mrts-ftw-dir")
    parser.add_argument("--mrts-rules-dir")
    parser.add_argument("--output-dir")
    args = parser.parse_args()

    framework_root = Path(args.framework_root).resolve()
    ftw_dir = Path(args.mrts_ftw_dir).resolve() if args.mrts_ftw_dir else framework_root / "tests/mrts/generated/ftw"
    rules_dir = Path(args.mrts_rules_dir).resolve() if args.mrts_rules_dir else framework_root / "tests/mrts/generated/rules"
    output_dir = Path(args.output_dir).resolve() if args.output_dir else framework_root / "tests/mrts/generated/framework-cases"
    return import_cases(framework_root, ftw_dir, rules_dir, output_dir)


if __name__ == "__main__":
    raise SystemExit(main())
