"""Minimal shared runner core for connector tests."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shlex
import time
from typing import Any, Iterable, Mapping

from adapter_interface import ConnectorAdapter
from case_roots import case_dirs, infer_runner_scope, path_is_in_extra_root
from msconnector_models import intervention_from_expect, operation_status

DEFAULT_RESPONSE_BODY = "TEST-OK-IF-YOU-SEE-THIS\n"
READY_BODY = "ready\n"

CAPABILITY_ALIASES = {
    "api_smoke": "api-smoke",
    "audit_log": "audit-log",
    "body_processor": "body-processors",
    "body_processors": "body-processors",
    "form_urlencoded": "form-urlencoded",
    "pass_through": "pass-through",
    "query_args": "query-args",
    "args_names": "args-names",
    "audit_log_absent": "audit-log-absent",
    "request_body": "request-body",
    "request_cookies": "request-cookies",
    "request_headers": "request-headers",
    "request_uri": "request-uri",
    "response_body": "response-body",
    "response_filters": "response-filters",
    "response_headers": "response-headers",
    "rule_parser": "rule-parser",
    "transaction_lifecycle": "transaction-lifecycle",
    "tx": "tx-collection",
}

KNOWN_CAPABILITIES = {
    "actions",
    "api-smoke",
    "args-names",
    "audit-log",
    "audit-log-absent",
    "body-processors",
    "collections",
    "engine-core",
    "files",
    "form-urlencoded",
    "intervention",
    "json",
    "logging",
    "multipart",
    "operators",
    "pass-through",
    "phase1",
    "phase2",
    "phase3",
    "phase4",
    "query-args",
    "request-cookies",
    "redirect",
    "request-body",
    "request-headers",
    "request-uri",
    "response-body",
    "response-filters",
    "response-headers",
    "rule-parser",
    "transaction-lifecycle",
    "transformations",
    "tx-collection",
    "xml",
}

CASE_STATUSES = {
    "active",
    "blocked",
    "connector-gap",
    "connector-specific",
    "experimental",
    "fail",
    "future",
    "fully-imported-common",
    "imported",
    "mapped",
    "mapped-only",
    "minimal",
    "pass",
    "pending",
    "runtime-difference",
    "skipped",
    "todo",
}

RESULT_STATUSES = {"pass", "fail", "blocked", "not_executable", "skipped"}
CONNECTORS = {"apache", "envoy", "haproxy", "lighttpd", "nginx", "traefik", "common"}
INTERVENTIONS = {"deny", "pass", "none", "redirect", "block"}
REQUEST_METHODS = {"GET", "POST"}
TRANSPORT_RESULTS = {"http_status", "connection_aborted", "aborted"}


@dataclass
class RunnerResult:
    response: Any
    artifacts: Mapping[str, Any]
    passed: bool
    errors: list[str]


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if not value:
        return ""
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in {"null", "none"}:
        return None
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    if value.isdigit():
        return int(value)
    return value


def _dedent_block(lines: Iterable[str]) -> str:
    collected = list(lines)
    indents = [
        len(line) - len(line.lstrip(" "))
        for line in collected
        if line.strip()
    ]
    if not indents:
        return ""
    margin = min(indents)
    return "\n".join(line[margin:] for line in collected).rstrip() + "\n"


def _load_yaml_with_pyyaml(path: Path) -> Mapping[str, Any] | None:
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError:
        return None
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, Mapping):
        raise ValueError(f"case file must contain a mapping: {path}")
    return loaded


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


_BLOCK_SCALAR_RE = re.compile(r"^[|>](?:[+-]|\d+)?(?:[+-]|\d+)?$")


class MinimalYamlParser:
    """Parse the documented minimal case schema without external dependencies."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.lines = path.read_text(encoding="utf-8").splitlines()

    def next_significant(self, index: int) -> str | None:
        while index < len(self.lines):
            candidate = self.lines[index]
            if candidate.strip() and not candidate.lstrip().startswith("#"):
                return candidate
            index += 1
        return None

    def parse_node(self, index: int, indent: int) -> tuple[Any, int]:
        candidate = self.next_significant(index)
        if candidate is not None and _indent_of(candidate) == indent and candidate.strip().startswith("- "):
            return self.parse_sequence(index, indent)
        return self.parse_mapping(index, indent)

    def parse_sequence(self, index: int, indent: int) -> tuple[list[Any], int]:
        parsed: list[Any] = []
        while index < len(self.lines):
            if not self.lines[index].strip() or self.lines[index].lstrip().startswith("#"):
                index += 1
                continue
            item = self._sequence_item(index, indent)
            if item is None:
                break
            value, index = item
            parsed.append(value)
        return parsed, index

    def _sequence_item(self, index: int, indent: int) -> tuple[Any, int] | None:
        line = self.lines[index]
        if _indent_of(line) < indent or not line.strip().startswith("- "):
            return None
        if _indent_of(line) > indent:
            raise ValueError(f"unexpected indentation in {self.path}: {line}")
        raw_value = line.strip()[2:].strip()
        index += 1
        if not raw_value:
            return self.parse_node(index, indent + 2)
        if ":" not in raw_value or raw_value.startswith(("'", '"')):
            return _parse_scalar(raw_value), index
        key, value = raw_value.split(":", 1)
        item: dict[str, Any] = {key.strip(): _parse_scalar(value.strip())}
        candidate = self.next_significant(index)
        if candidate is not None and _indent_of(candidate) == indent + 2:
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
            current_indent = _indent_of(line)
            if current_indent < indent:
                break
            if current_indent > indent:
                raise ValueError(f"unexpected indentation in {self.path}: {line}")
            stripped = line.strip()
            if ":" not in stripped:
                raise ValueError(f"expected key/value line in {self.path}: {line}")
            key, raw_value = stripped.split(":", 1)
            key = key.strip()
            raw_value = raw_value.strip()
            index += 1
            if _BLOCK_SCALAR_RE.fullmatch(raw_value):
                parsed[key], index = self.parse_block(index, current_indent)
                continue
            if raw_value:
                parsed[key] = _parse_scalar(raw_value)
                continue
            nested, index = self.parse_node(index, current_indent + 2)
            parsed[key] = nested
        return parsed, index

    def parse_block(self, index: int, parent_indent: int) -> tuple[str, int]:
        block_lines: list[str] = []
        while index < len(self.lines):
            line = self.lines[index]
            if line.strip() and _indent_of(line) <= parent_indent:
                break
            block_lines.append(line)
            index += 1
        return _dedent_block(block_lines), index

    def parse(self) -> Mapping[str, Any]:
        case, final_index = self.parse_mapping(0, 0)
        self._check_trailing(final_index)
        return case

    def _check_trailing(self, index: int) -> None:
        while index < len(self.lines):
            trailing = self.lines[index]
            if trailing.strip() and not trailing.lstrip().startswith("#"):
                raise ValueError(f"unexpected trailing content in {self.path}: {trailing}")
            index += 1


def _load_minimal_yaml(path: Path) -> Mapping[str, Any]:
    case = MinimalYamlParser(path).parse()
    return case


def load_case(path: str | Path) -> Mapping[str, Any]:
    case_path = Path(path)
    loaded = _load_yaml_with_pyyaml(case_path)
    case = dict(loaded if loaded is not None else _load_minimal_yaml(case_path))
    validate_case(case, case_path)
    return case


def validate_case(case: Mapping[str, Any], path: Path | None = None) -> None:
    where = f" in {path}" if path is not None else ""
    _validate_case_metadata(case, where)
    _validate_request(case, where)
    _validate_response(case, where)
    _validate_nginx(case, where)
    _validate_expect(case, where)


def _validate_case_metadata(case: Mapping[str, Any], where: str) -> None:
    if not str(case.get("name", "")).strip():
        raise ValueError(f"case requires name{where}")
    if not str(case.get("rules", "")).strip():
        raise ValueError(f"case requires rules{where}")
    _validate_capabilities(case, where)
    _validate_origin(case, where)
    _validate_known_limitations(case, where)
    portable = case.get("portable")
    if portable is not None and not isinstance(portable, bool):
        raise ValueError(f"case portable must be a boolean{where}")
    requires_crs = case.get("requires_crs")
    if requires_crs is not None and not isinstance(requires_crs, bool):
        raise ValueError(f"case requires_crs must be a boolean{where}")
    connector = case.get("connector")
    if connector is not None and str(connector) not in CONNECTORS:
        raise ValueError(f"case connector is unsupported{where}")
    status = case.get("status")
    if status is not None and str(status) not in CASE_STATUSES:
        raise ValueError(f"case status is unsupported{where}")


def _validate_capabilities(case: Mapping[str, Any], where: str) -> None:
    capabilities = case.get("capabilities", {})
    if capabilities is not None and not isinstance(capabilities, (Mapping, list)):
        raise ValueError(f"case capabilities must be a mapping or list{where}")
    if isinstance(capabilities, list) and not all(isinstance(item, str) for item in capabilities):
        raise ValueError(f"case capabilities list must contain strings{where}")
    unknown_capabilities = [
        capability
        for capability in _capability_names(case)
        if capability not in KNOWN_CAPABILITIES
    ]
    if unknown_capabilities:
        joined = ", ".join(sorted(unknown_capabilities))
        raise ValueError(f"case capabilities contain unsupported values: {joined}{where}")


def _validate_origin(case: Mapping[str, Any], where: str) -> None:
    origin = case.get("origin")
    if origin is None:
        return
    if not isinstance(origin, list) or not all(isinstance(item, Mapping) for item in origin):
        raise ValueError(f"case origin must be a list of mappings{where}")
    for item in origin:
        missing = [key for key in ("repo", "path", "reason") if not str(item.get(key, "")).strip()]
        if missing:
            raise ValueError(f"case origin entries require {missing[0]}{where}")


def _validate_known_limitations(case: Mapping[str, Any], where: str) -> None:
    known_limitations = case.get("known_limitations")
    if known_limitations is not None and not isinstance(known_limitations, (str, list)):
        raise ValueError(f"case known_limitations must be a string or list{where}")
    if isinstance(known_limitations, list) and not all(isinstance(item, str) for item in known_limitations):
        raise ValueError(f"case known_limitations list must contain strings{where}")


def _validate_request(case: Mapping[str, Any], where: str) -> None:
    request = case.get("request")
    if not isinstance(request, Mapping):
        raise ValueError(f"case requires request mapping{where}")
    if not str(request.get("method", "")).strip():
        raise ValueError(f"case requires request.method{where}")
    if str(request.get("method", "")).upper() not in REQUEST_METHODS:
        raise ValueError(f"case supports only GET or POST request.method{where}")
    if not str(request.get("path", "")).strip():
        raise ValueError(f"case requires request.path{where}")
    headers = request.get("headers", {})
    if headers is not None and not isinstance(headers, Mapping):
        raise ValueError(f"case request.headers must be a mapping{where}")
    header_map = headers if isinstance(headers, Mapping) else {}
    has_body = "body" in request and request.get("body") is not None
    has_multipart = "multipart" in request and request.get("multipart") is not None
    if has_body and has_multipart:
        raise ValueError(f"case request.body and request.multipart are mutually exclusive{where}")
    if has_multipart:
        _validate_multipart_request(request, header_map, where)


def _validate_multipart_request(request: Mapping[str, Any], headers: Mapping[str, Any], where: str) -> None:
    multipart = request.get("multipart")
    if not isinstance(multipart, Mapping):
        raise ValueError(f"case request.multipart must be a mapping{where}")
    if str(request.get("method", "")).upper() != "POST":
        raise ValueError(f"case request.multipart requires POST{where}")
    if not str(multipart.get("boundary") or "").strip():
        raise ValueError(f"case request.multipart requires boundary{where}")
    parts = multipart.get("parts")
    if not isinstance(parts, list) or not parts:
        raise ValueError(f"case request.multipart.parts must be a non-empty list{where}")
    for part in parts:
        if not isinstance(part, Mapping):
            raise ValueError(f"case multipart parts must be mappings{where}")
        if not str(part.get("name", "")).strip():
            raise ValueError(f"case multipart parts require name{where}")
    if any(str(name).lower() == "content-type" for name in headers):
        raise ValueError(f"case request.headers must not set Content-Type with request.multipart{where}")


def _validate_response(case: Mapping[str, Any], where: str) -> None:
    response = case.get("response")
    if response is None:
        return
    if not isinstance(response, Mapping):
        raise ValueError(f"case response must be a mapping{where}")
    if "body" in response and response.get("body") is not None and not isinstance(response.get("body"), str):
        raise ValueError(f"case response.body must be a string{where}")


def _validate_nginx(case: Mapping[str, Any], where: str) -> None:
    nginx = case.get("nginx")
    if nginx is None:
        return
    if not isinstance(nginx, Mapping):
        raise ValueError(f"case nginx must be a mapping{where}")
    location_directives = nginx.get("location_directives")
    if location_directives is not None and not isinstance(location_directives, str):
        raise ValueError(f"case nginx.location_directives must be a string{where}")
    _validate_nginx_files(nginx.get("files", {}), where)


def _validate_nginx_files(files: Any, where: str) -> None:
    if files is not None and not isinstance(files, Mapping):
        raise ValueError(f"case nginx.files must be a mapping{where}")
    if not isinstance(files, Mapping):
        return
    for name, content in files.items():
        _validate_nginx_file(name, content, where)


def _validate_nginx_file(name: Any, content: Any, where: str) -> None:
    file_name = str(name)
    if not file_name.strip() or file_name.startswith("/") or ".." in Path(file_name).parts:
        raise ValueError(f"case nginx.files keys must be relative safe paths{where}")
    if not isinstance(content, str):
        raise ValueError(f"case nginx.files values must be strings{where}")


def _validate_expect_string_list(value: Any, key: str, where: str) -> None:
    if value is None:
        return
    if isinstance(value, str):
        return
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return
    raise ValueError(f"case expect.phase4_log.{key} must be a string or string list{where}")


def _expect_without_variants(expect: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): value for key, value in expect.items() if str(key) != "variants"}


def _validate_expect_mapping(expect: Mapping[str, Any], where: str) -> None:
    status = expect.get("status")
    if not isinstance(status, int):
        raise ValueError(f"case requires integer expect.status{where}")
    intervention = expect.get("intervention")
    if intervention is not None and str(intervention) not in INTERVENTIONS:
        raise ValueError(f"case expect.intervention is unsupported{where}")
    transport = expect.get("transport")
    if transport is not None and str(transport) not in TRANSPORT_RESULTS:
        raise ValueError(f"case expect.transport is unsupported{where}")
    _validate_expect_audit_log(expect.get("audit_log", {}), where)
    _validate_expect_phase4_log(expect.get("phase4_log", {}), where)


def _validate_expect(case: Mapping[str, Any], where: str) -> None:
    expect = case.get("expect")
    if not isinstance(expect, Mapping):
        raise ValueError(f"case requires expect mapping{where}")
    base_expect = _expect_without_variants(expect)
    _validate_expect_mapping(base_expect, where)
    variants = expect.get("variants")
    if variants is None:
        return
    if not isinstance(variants, Mapping):
        raise ValueError(f"case expect.variants must be a mapping{where}")
    for name, override in variants.items():
        variant_name = str(name)
        if variant_name not in {"no-crs", "with-crs"}:
            raise ValueError(f"case expect.variants has unsupported variant {variant_name!r}{where}")
        if not isinstance(override, Mapping):
            raise ValueError(f"case expect.variants.{variant_name} must be a mapping{where}")
        if "variants" in override:
            raise ValueError(f"case expect.variants.{variant_name} must not contain nested variants{where}")
        merged = dict(base_expect)
        merged.update({str(key): value for key, value in override.items()})
        _validate_expect_mapping(merged, where)


def _validate_expect_audit_log(audit_log: Any, where: str) -> None:
    if audit_log is not None and not isinstance(audit_log, Mapping):
        raise ValueError(f"case expect.audit_log must be a mapping{where}")
    if isinstance(audit_log, Mapping):
        absent = audit_log.get("absent")
        if absent is not None and not isinstance(absent, bool):
            raise ValueError(f"case expect.audit_log.absent must be a boolean{where}")


def _validate_expect_phase4_log(phase4_log: Any, where: str) -> None:
    if phase4_log is not None and not isinstance(phase4_log, Mapping):
        raise ValueError(f"case expect.phase4_log must be a mapping{where}")
    if isinstance(phase4_log, Mapping):
        required = phase4_log.get("required")
        if required is not None and not isinstance(required, bool):
            raise ValueError(f"case expect.phase4_log.required must be a boolean{where}")
        _validate_expect_string_list(phase4_log.get("contains"), "contains", where)
        _validate_expect_string_list(phase4_log.get("not_contains"), "not_contains", where)


def write_rules_file(
    case: Mapping[str, Any],
    path: str | Path,
    audit_log_file: str | Path | None = None,
    audit_log_dir: str | Path | None = None,
    rules_preamble_file: str | Path | None = None,
) -> None:
    if case.get("no_crs_baseline") is True and rules_preamble_file is None:
        raise ValueError("canonical No-CRS cases require tests/rules/no-crs-baseline.conf as rules preamble")
    if case.get("no_crs_baseline") is True:
        canonical_preamble = Path(__file__).resolve().parents[2] / "tests/rules/no-crs-baseline.conf"
        if Path(rules_preamble_file).resolve() != canonical_preamble.resolve():
            raise ValueError(f"canonical No-CRS case requires rules preamble {canonical_preamble}")
    rules = str(case["rules"])
    if audit_log_file is not None:
        rules = rules.replace("@@AUDIT_LOG@@", str(audit_log_file))
    if audit_log_dir is not None:
        rules = rules.replace("@@AUDIT_LOG_DIR@@", str(audit_log_dir))
    if "@@AUDIT_LOG@@" in rules or "@@AUDIT_LOG_DIR@@" in rules:
        raise ValueError("audit log placeholders require audit log paths")
    preamble = ""
    if rules_preamble_file is not None:
        preamble_path = Path(rules_preamble_file)
        if not preamble_path.is_file():
            raise FileNotFoundError(f"rules preamble file missing: {preamble_path}")
        preamble = preamble_path.read_text(encoding="utf-8")
        if preamble and not preamble.endswith("\n"):
            preamble += "\n"
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    local_rules = rules if rules.endswith("\n") else f"{rules}\n"
    output.write_text(f"{preamble}{local_rules}", encoding="utf-8")


def request_headers(case: Mapping[str, Any]) -> Mapping[str, Any]:
    request = case["request"]
    headers = request.get("headers", {})
    if headers is None:
        return {}
    if not isinstance(headers, Mapping):
        raise ValueError("request.headers must be a mapping")
    materialized = {str(name): value for name, value in headers.items()}
    request = case["request"]
    if request.get("multipart") is not None:
        materialized["Content-Type"] = f"multipart/form-data; boundary={multipart_boundary(case)}"
    return materialized


def request_body(case: Mapping[str, Any]) -> str:
    request = case["request"]
    if "body" not in request or request.get("body") is None:
        return ""
    return str(request["body"])


def multipart_boundary(case: Mapping[str, Any]) -> str:
    request = case["request"]
    multipart = request.get("multipart")
    if not isinstance(multipart, Mapping):
        raise ValueError("request.multipart must be a mapping")
    return str(multipart["boundary"])


def multipart_parts(case: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    request = case["request"]
    multipart = request.get("multipart")
    if not isinstance(multipart, Mapping):
        return []
    parts = multipart.get("parts", [])
    if not isinstance(parts, list):
        raise ValueError("request.multipart.parts must be a list")
    return parts


def request_body_bytes(case: Mapping[str, Any]) -> bytes:
    request = case["request"]
    if request.get("multipart") is not None:
        boundary = multipart_boundary(case)
        body = bytearray()
        for part in multipart_parts(case):
            name = str(part["name"])
            filename = part.get("filename")
            content_type = part.get("content_type")
            value = part.get("body", part.get("value", ""))
            body.extend(f"--{boundary}\r\n".encode("utf-8"))
            disposition = f'Content-Disposition: form-data; name="{name}"'
            if filename not in (None, ""):
                disposition += f'; filename="{filename}"'
            body.extend(f"{disposition}\r\n".encode("utf-8"))
            if content_type not in (None, ""):
                body.extend(f"Content-Type: {content_type}\r\n".encode("utf-8"))
            body.extend(b"\r\n")
            body.extend(str(value).encode("utf-8"))
            body.extend(b"\r\n")
        body.extend(f"--{boundary}--\r\n".encode("utf-8"))
        return bytes(body)
    return request_body(case).encode("utf-8")


def response_body(case: Mapping[str, Any]) -> str:
    response = case.get("response", {})
    if response is None:
        return DEFAULT_RESPONSE_BODY
    if not isinstance(response, Mapping):
        raise ValueError("response must be a mapping")
    body = response.get("body", DEFAULT_RESPONSE_BODY)
    return str(body)


def nginx_metadata(case: Mapping[str, Any]) -> Mapping[str, Any]:
    nginx = case.get("nginx", {})
    if nginx is None:
        return {}
    if not isinstance(nginx, Mapping):
        raise ValueError("nginx must be a mapping")
    return nginx


def nginx_files(case: Mapping[str, Any]) -> Mapping[str, str]:
    files = nginx_metadata(case).get("files", {})
    if files is None:
        return {}
    if not isinstance(files, Mapping):
        raise ValueError("nginx.files must be a mapping")
    return {str(name): str(content) for name, content in files.items()}


def nginx_location_directives(case: Mapping[str, Any]) -> str:
    directives = nginx_metadata(case).get("location_directives", "")
    if directives in (None, ""):
        return ""
    return str(directives)


def _replace_nginx_placeholders(
    content: str,
    nginx_runtime_config_dir: Path,
    nginx_phase4_log_file: str | Path | None,
) -> str:
    rendered = content
    if nginx_phase4_log_file is not None:
        rendered = rendered.replace("@@NGINX_PHASE4_LOG@@", str(nginx_phase4_log_file))
    for marker in set(rendered.split("@@NGINX_FILE:")[1:]):
        name = marker.split("@@", 1)[0]
        if not name:
            continue
        target = nginx_runtime_config_dir / name
        rendered = rendered.replace(f"@@NGINX_FILE:{name}@@", str(target))
    if "@@NGINX_PHASE4_LOG@@" in rendered:
        raise ValueError("NGINX phase4 log placeholder requires a phase4 log path")
    if "@@NGINX_FILE:" in rendered:
        raise ValueError("unresolved NGINX file placeholder")
    return rendered


def write_nginx_runtime_files(
    case: Mapping[str, Any],
    location_directives_file: str | Path | None,
    runtime_config_dir: str | Path | None,
    phase4_log_file: str | Path | None = None,
) -> None:
    if location_directives_file is None or runtime_config_dir is None:
        return
    config_dir = Path(runtime_config_dir)
    config_dir.mkdir(parents=True, exist_ok=True)
    for name, content in nginx_files(case).items():
        target = config_dir / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content if content.endswith("\n") else f"{content}\n", encoding="utf-8")
    directives = _replace_nginx_placeholders(
        nginx_location_directives(case),
        config_dir,
        phase4_log_file,
    )
    output = Path(location_directives_file)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(directives if directives.endswith("\n") else f"{directives}\n", encoding="utf-8")


def _bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def expected_audit_log(case: Mapping[str, Any]) -> Mapping[str, Any]:
    expect = effective_expect(case)
    audit_log = expect.get("audit_log", {})
    if audit_log is None:
        return {}
    if not isinstance(audit_log, Mapping):
        raise ValueError("expect.audit_log must be a mapping")
    return audit_log


def expected_phase4_log(case: Mapping[str, Any]) -> Mapping[str, Any]:
    expect = effective_expect(case)
    phase4_log = expect.get("phase4_log", {})
    if phase4_log is None:
        return {}
    if not isinstance(phase4_log, Mapping):
        raise ValueError("expect.phase4_log must be a mapping")
    return phase4_log


def write_headers_file(case: Mapping[str, Any], path: str | Path) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for name, value in request_headers(case).items():
        lines.append(f"{name}: {value}\n")
    output.write_text("".join(lines), encoding="utf-8")


def write_body_file(case: Mapping[str, Any], path: str | Path) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(request_body_bytes(case))


def write_response_fixture(case: Mapping[str, Any], docroot: str | Path) -> None:
    root = Path(docroot)
    root.mkdir(parents=True, exist_ok=True)
    (root / "index.html").write_text(response_body(case), encoding="utf-8")
    (root / "__modsec_smoke_ready").write_text(READY_BODY, encoding="utf-8")


def write_shell_env(
    case: Mapping[str, Any],
    path: str | Path,
    headers_file: str | Path | None = None,
    body_file: str | Path | None = None,
    audit_log_file: str | Path | None = None,
    audit_log_dir: str | Path | None = None,
) -> None:
    request = case["request"]
    expect = effective_expect(case)
    body = request_body_bytes(case)
    audit_log = expected_audit_log(case)
    values = {
        "CASE_NAME": case["name"],
        "REQUEST_METHOD": str(request["method"]).upper(),
        "REQUEST_PATH": request["path"],
        "REQUEST_HAS_BODY": 1 if body else 0,
        "REQUEST_HEADERS_FILE": headers_file or "",
        "REQUEST_BODY_FILE": body_file or "",
        "AUDIT_LOG_FILE": audit_log_file or "",
        "AUDIT_LOG_DIR": audit_log_dir or "",
        "EXPECT_STATUS": expect["status"],
        "EXPECT_INTERVENTION": expect.get("intervention", ""),
        "EXPECT_RULE_ID": expect.get("rule_id", ""),
        "EXPECT_RESPONSE_CONTAINS": expect.get("response_contains", ""),
        "EXPECT_TRANSPORT": expect.get("transport", "http_status"),
        "EXPECT_AUDIT_LOG_REQUIRED": 1 if _bool_value(audit_log.get("required")) else 0,
    }
    lines = ["# Generated from common test case. Do not edit.\n"]
    for key, value in values.items():
        lines.append(f"{key}={shlex.quote(str(value))}\n")
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("".join(lines), encoding="utf-8")


def _capability_names(case: Mapping[str, Any]) -> list[str]:
    capabilities = case.get("capabilities", {})
    if capabilities is None:
        return []
    if isinstance(capabilities, Mapping):
        raw_names = [str(key) for key, value in capabilities.items() if _bool_value(value)]
    elif isinstance(capabilities, list):
        raw_names = [str(item) for item in capabilities]
    else:
        return []
    normalized = {
        CAPABILITY_ALIASES.get(name.strip(), name.strip().replace("_", "-"))
        for name in raw_names
        if name.strip()
    }
    return sorted(normalized)


def case_scope(path: str | Path) -> str:
    return infer_runner_scope(path)


def case_status_group(case: Mapping[str, Any]) -> str:
    status = str(case.get("status", "") or "").strip()
    return status if status else "active"


def is_default_runtime_case(case: Mapping[str, Any]) -> bool:
    if case.get("no_crs_baseline") is True:
        return os.environ.get("NO_CRS_BASELINE", "").strip().lower() in {"1", "true", "yes", "on"}
    if case.get("former_xfail") is True:
        return False
    return case_status_group(case) in {
        "active",
        "fully-imported-common",
        "imported",
        "minimal",
        "pass",
        "v2-imported",
        "v3-imported",
    }


def case_group(path: str | Path, case: Mapping[str, Any] | None = None) -> str:
    if case is None:
        try:
            loaded = _load_yaml_with_pyyaml(Path(path))
            case = loaded if loaded is not None else _load_minimal_yaml(Path(path))
        except Exception:
            return "active"
    return case_status_group(case)


def case_info(
    case: Mapping[str, Any],
    path: str | Path,
    connector: str | None = None,
    status: str | None = None,
    actual_status: int | None = None,
) -> dict[str, Any]:
    expect = effective_expect(case)
    info: dict[str, Any] = {
        "name": str(case["name"]),
        "path": str(path),
        "scope": case_scope(path),
        "group": case_group(path, case),
        "category": str(case.get("category", "")),
        "portable": case.get("portable"),
        "requires_crs": case_requires_crs(case),
        "connector": str(case.get("connector", "")),
        "case_status": str(case.get("status", "")),
        "capabilities": _capability_names(case),
        "origin": case.get("origin", []),
        "known_limitations": case.get("known_limitations", []),
        "expected_status": expect["status"],
        "expected_intervention": str(expect.get("intervention", "")),
        "actual_status": actual_status,
        "variant": modsecurity_test_variant(),
    }
    if connector is not None:
        info["executed_connector"] = connector
    if status is not None:
        info["status"] = status
        info["operation_status"] = operation_status(status)
        if status in {"pass", "fail"}:
            info["live_executed"] = True
    info["intervention"] = intervention_from_expect(expect)
    return info


def intervention_info(expect: Mapping[str, Any]) -> dict[str, Any]:
    return intervention_from_expect(expect)


def _case_dirs(connector_root: Path, connector: str, scope: str, framework_root: Path | None = None) -> list[Path]:
    return case_dirs(connector_root, connector, scope, framework_root)


def _case_path_in_scope(path: str | Path, connector: str, scope: str) -> bool:
    path_scope = case_scope(path)
    if path_scope == "common" or path_scope.startswith("common/"):
        return scope in {"common", "all"}
    if path_scope.startswith(f"{connector}/"):
        return scope in {"connector", "all"}
    return False


def force_all_cases_enabled() -> bool:
    return os.environ.get("FORCE_ALL_CASES", "").strip().lower() in {"1", "true", "yes", "on"}


def modsecurity_test_variant() -> str:
    variant = os.environ.get("MODSECURITY_TEST_VARIANT", "no-crs").strip() or "no-crs"
    if variant not in {"no-crs", "with-crs"}:
        raise ValueError(f"unsupported MODSECURITY_TEST_VARIANT: {variant}")
    return variant


def effective_expect(case: Mapping[str, Any]) -> dict[str, Any]:
    expect = case["expect"]
    if not isinstance(expect, Mapping):
        raise ValueError("case requires expect mapping")
    resolved = _expect_without_variants(expect)
    variants = expect.get("variants")
    if isinstance(variants, Mapping):
        override = variants.get(modsecurity_test_variant())
        if isinstance(override, Mapping):
            resolved.update({str(key): value for key, value in override.items()})
    return resolved


def case_requires_crs(case: Mapping[str, Any]) -> bool:
    return _bool_value(case.get("requires_crs"))


def case_connector_scopes(case: Mapping[str, Any]) -> set[str]:
    metadata = case.get("metadata")
    scopes: set[str] = set()
    if isinstance(metadata, Mapping):
        raw_scope = metadata.get("connector_scope")
        if isinstance(raw_scope, list):
            scopes.update(str(item) for item in raw_scope if str(item).strip())
        elif raw_scope not in (None, ""):
            scopes.add(str(raw_scope))
    declared_connector = case.get("connector")
    if declared_connector not in (None, ""):
        scopes.add(str(declared_connector))
    return scopes or {"common"}


def is_case_applicable(case: Mapping[str, Any], path: str | Path, connector: str, scope: str) -> bool:
    path_scope = case_scope(path)
    declared_connector = case.get("connector")
    portable = case.get("portable")
    connector_scopes = case_connector_scopes(case)
    if case_requires_crs(case) and modsecurity_test_variant() != "with-crs":
        return False
    if not force_all_cases_enabled() and not is_default_runtime_case(case):
        return False
    if path_scope == "common" or path_scope.startswith("common/"):
        if path_is_in_extra_root(path):
            if "common" in connector_scopes:
                return scope in {"common", "all"} and portable is not False
            return connector in connector_scopes and scope == "all"
        if declared_connector not in (None, "", "common"):
            return False
        if portable is False:
            return False
        return scope in {"common", "all"}
    if path_scope.startswith(f"{connector}/"):
        return scope in {"connector", "all"} and declared_connector in (None, "", connector)
    return False


def _resolve_named_case(item: str, selected_dirs: list[Path]) -> Path:
    name = item if item.endswith(".yaml") else f"{item}.yaml"
    matches = [
        path
        for directory in selected_dirs
        if directory.is_dir()
        for path in directory.rglob(name)
        if path.is_file()
    ]
    if not matches:
        raise FileNotFoundError(f"missing smoke case in selected scope: {item}")
    if len(matches) > 1:
        raise ValueError(f"ambiguous smoke case name {item}; use a path")
    return matches[0].resolve()


def _resolve_case_item(item: str, root: Path, connector: str, scope: str, selected_dirs: list[Path]) -> Path:
    candidate = Path(item)
    if not candidate.is_absolute() and "/" not in item:
        return _resolve_named_case(item, selected_dirs)
    if candidate.is_absolute():
        path = candidate
    else:
        scoped_matches = [
            directory / candidate
            for directory in selected_dirs
            if (directory / candidate).is_file()
        ]
        if len(scoped_matches) == 1:
            path = scoped_matches[0]
        else:
            path = root / candidate
    if not path.is_file():
        raise FileNotFoundError(f"missing smoke case: {item}")
    resolved = path.resolve()
    if not _case_path_in_scope(resolved, connector, scope):
        raise ValueError(f"smoke case is outside selected scope: {item}")
    return resolved


def _selected_case_candidates(
    root: Path,
    connector: str,
    scope: str,
    selected_dirs: list[Path],
    smoke_cases: str,
    test_case: str,
) -> list[Path]:
    if test_case:
        return [_resolve_case_item(test_case, root, connector, scope, selected_dirs)]
    if smoke_cases.strip():
        return [
            _resolve_case_item(item, root, connector, scope, selected_dirs)
            for item in smoke_cases.split()
        ]
    return [
        path
        for directory in selected_dirs
        if directory.is_dir()
        for path in sorted(directory.rglob("*.yaml"))
    ]


def discover_case_files(
    repo_root: str | Path,
    connector: str,
    scope: str = "all",
    smoke_cases: str = "",
    test_case: str = "",
    framework_root: str | Path | None = None,
) -> list[Path]:
    root = Path(repo_root).resolve()
    common_root = Path(framework_root).resolve() if framework_root else None
    selected_dirs = _case_dirs(root, connector, scope, common_root)
    candidates = _selected_case_candidates(root, connector, scope, selected_dirs, smoke_cases, test_case)
    return [
        path
        for path in candidates
        if is_case_applicable(load_case(path), path, connector, scope)
    ]


def response_status(response: Any) -> int | None:
    if isinstance(response, int):
        return response
    if isinstance(response, Mapping):
        status = response.get("status")
        return status if isinstance(status, int) else None
    status = getattr(response, "status", None)
    return status if isinstance(status, int) else None


def response_transport(response: Any) -> str:
    if isinstance(response, Mapping):
        transport = response.get("transport")
        if transport not in (None, ""):
            return str(transport)
    return "http_status"


def assert_case_response(case: Mapping[str, Any], response: Any) -> list[str]:
    expect = effective_expect(case)
    expected_status = expect["status"]
    expected_transport = str(expect.get("transport", "http_status"))
    actual_status = response_status(response)
    actual_transport = response_transport(response)
    errors: list[str] = []
    if expected_transport in {"connection_aborted", "aborted"}:
        if actual_transport not in {"connection_aborted", "aborted"}:
            errors.append(
                f"expected transport {expected_transport}, observed {actual_transport}"
            )
        return errors
    if actual_transport in {"connection_aborted", "aborted"}:
        errors.append(f"expected HTTP {expected_status}, observed transport {actual_transport}")
        return errors
    if actual_status != expected_status:
        errors.append(f"expected HTTP {expected_status}, observed {actual_status}")
    if str(expect.get("intervention", "")) == "none" and actual_status != 200:
        errors.append(f"expected pass-through HTTP 200, observed {actual_status}")
    return errors


def assert_response_body(case: Mapping[str, Any], body_file: str | Path | None) -> list[str]:
    expected = effective_expect(case).get("response_contains")
    if expected in (None, ""):
        return []
    if body_file is None:
        return ["response body expectation requires a response body file"]
    path = Path(body_file)
    if not path.exists():
        return [f"response body file missing: {path}"]
    body = path.read_text(encoding="utf-8", errors="replace")
    if str(expected) not in body:
        return [f"expected response body to contain {expected!r}"]
    return []


def _wait_for_file_content(path: Path, timeout_seconds: float) -> str:
    deadline = time.monotonic() + timeout_seconds
    while True:
        if path.exists():
            content = path.read_text(encoding="utf-8", errors="replace")
            if content:
                return content
        if time.monotonic() >= deadline:
            return ""
        time.sleep(0.1)


def _assert_audit_log_absent(path: Path, timeout_seconds: float) -> list[str]:
    if _wait_for_file_content(path, timeout_seconds):
        return [f"expected audit log to be absent or empty: {path}"]
    return []


def _assert_audit_log_fields(audit_log: Mapping[str, Any], content: str) -> list[str]:
    errors: list[str] = []
    for key, value in audit_log.items():
        if key == "required" or value in (None, ""):
            continue
        expected = str(value)
        if expected not in content:
            errors.append(f"expected audit log field {key} to contain {expected!r}")
    return errors


def assert_audit_log(
    case: Mapping[str, Any],
    audit_log_file: str | Path | None,
    timeout_seconds: float = 2.0,
) -> list[str]:
    audit_log = expected_audit_log(case)
    if _bool_value(audit_log.get("absent")):
        if audit_log_file is None:
            return []
        return _assert_audit_log_absent(Path(audit_log_file), timeout_seconds)
    if not _bool_value(audit_log.get("required")):
        return []
    if audit_log_file is None:
        return ["audit log expectation requires an audit log file"]
    path = Path(audit_log_file)
    content = _wait_for_file_content(path, timeout_seconds)
    if not content:
        return [f"audit log file missing or empty: {path}"]
    return _assert_audit_log_fields(audit_log, content)


def _string_list(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def assert_phase4_log(
    case: Mapping[str, Any],
    phase4_log_file: str | Path | None,
    timeout_seconds: float = 2.0,
) -> list[str]:
    phase4_log = expected_phase4_log(case)
    if not phase4_log:
        return []
    if phase4_log_file is None:
        return ["phase4 log expectation requires a phase4 log file"]
    path = Path(phase4_log_file)
    content = _wait_for_file_content(path, timeout_seconds)
    if _bool_value(phase4_log.get("required")) and not content:
        return [f"phase4 log file missing or empty: {path}"]
    errors: list[str] = []
    for expected in _string_list(phase4_log.get("contains")):
        if expected not in content:
            errors.append(f"expected phase4 log to contain {expected!r}")
    for unexpected in _string_list(phase4_log.get("not_contains")):
        if unexpected in content:
            errors.append(f"expected phase4 log not to contain {unexpected!r}")
    return errors


def phase4_log_metadata(phase4_log_file: str | Path | None) -> dict[str, Any]:
    if phase4_log_file is None:
        return {}
    path = Path(phase4_log_file)
    if not path.exists():
        return {}
    metadata: dict[str, Any] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and item.get("event") == "phase4_intervention":
            metadata = item
    return metadata


def assert_case_artifacts(
    case: Mapping[str, Any],
    response: Any,
    response_body_file: str | Path | None = None,
    audit_log_file: str | Path | None = None,
    phase4_log_file: str | Path | None = None,
) -> list[str]:
    errors: list[str] = []
    errors.extend(assert_case_response(case, response))
    errors.extend(assert_response_body(case, response_body_file))
    errors.extend(assert_audit_log(case, audit_log_file))
    errors.extend(assert_phase4_log(case, phase4_log_file))
    return errors


class RunnerCore:
    """Minimal orchestration around a connector adapter."""

    def __init__(self, adapter: ConnectorAdapter) -> None:
        self.adapter = adapter

    def run_case(self, case: Mapping[str, Any]) -> RunnerResult:
        validate_case(case)
        self.adapter.prepare()
        try:
            self.adapter.apply_config(case.get("config", {}))
            self.adapter.apply_rules(str(case.get("rules", "")))
            self.adapter.start()
            response = self.adapter.send_request(case.get("request", {}))
            artifacts = self.adapter.collect_artifacts()
            errors = assert_case_artifacts(case, response)
            return RunnerResult(
                response=response,
                artifacts=artifacts,
                passed=not errors,
                errors=errors,
            )
        finally:
            self.adapter.stop()
            self.adapter.cleanup()
