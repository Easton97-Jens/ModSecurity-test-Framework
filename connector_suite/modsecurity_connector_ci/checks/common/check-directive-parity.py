#!/usr/bin/env python3
"""Check global directive spec/adapter parity without enforcing connector adoption."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
from pathlib import Path
import sys
import re

ROOT = connector_root()
SPEC_H = source_path('common/include/msconnector/directive_spec.h', root=ROOT)
SPEC_C = source_path('common/src/directive_spec.c', root=ROOT)
ADAPTER_H = source_path('common/include/msconnector/directive_adapter.h', root=ROOT)
ADAPTER_C = source_path('common/src/directive_adapter.c', root=ROOT)
DIRECTIVES_H = source_path('common/include/msconnector/directives.h', root=ROOT)
APACHE_CONFIG_C = source_path('connectors/apache/src/msc_config.c', root=ROOT)
NGINX_MODULE_C = source_path('connectors/nginx/src/ngx_http_modsecurity_module.c', root=ROOT)
KNOWN = [
    "modsecurity",
    "modsecurity_rules",
    "modsecurity_rules_file",
    "modsecurity_rules_remote",
    "modsecurity_transaction_id",
    "modsecurity_transaction_id_expr",
    "modsecurity_use_error_log",
    "modsecurity_phase4_mode",
    "modsecurity_phase4_log",
]
NGINX_DIRECTIVE_NOT_APPLICABLE: dict[str, str] = {
    "modsecurity_transaction_id_expr": "Apache expression syntax is not supported by NGINX; use modsecurity_transaction_id with NGINX variables instead.",
}

POLICY_FOR_TYPE = {
    "MSCONNECTOR_DIRECTIVE_VALUE_BOOL": {"MSCONNECTOR_DIRECTIVE_ARG_ONE"},
    "MSCONNECTOR_DIRECTIVE_VALUE_STRING": {"MSCONNECTOR_DIRECTIVE_ARG_ONE"},
    "MSCONNECTOR_DIRECTIVE_VALUE_PATH": {"MSCONNECTOR_DIRECTIVE_ARG_ONE"},
    "MSCONNECTOR_DIRECTIVE_VALUE_ENUM": {"MSCONNECTOR_DIRECTIVE_ARG_ONE"},
    "MSCONNECTOR_DIRECTIVE_VALUE_SIZE": {"MSCONNECTOR_DIRECTIVE_ARG_ONE"},
}


def parse_quoted_macro_definitions(text: str) -> dict[str, str]:
    macros: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("#define "):
            continue

        parts = line.split(None, 2)
        if len(parts) != 3:
            continue

        name = parts[1]
        raw_value = parts[2].strip()
        if not name.startswith("MSCONNECTOR_DIRECTIVE_"):
            continue
        if len(raw_value) < 2 or not raw_value.startswith('"'):
            continue

        end = raw_value.find('"', 1)
        if end == -1:
            continue

        macros[name] = raw_value[1:end]
    return macros



def parse_apache_directive_macros(text: str) -> set[str]:
    macros: set[str] = set()
    for match in re.finditer(r"AP_INIT_[A-Z0-9_]+\(\s*(MSCONNECTOR_DIRECTIVE_[A-Z0-9_]+)", text, re.MULTILINE):
        macros.add(match.group(1))
    return macros

def parse_nginx_directive_macros(text: str) -> set[str]:
    return set(re.findall(r"ngx_string\(\s*(MSCONNECTOR_DIRECTIVE_[A-Z0-9_]+)\s*\)", text))

def fields_from_initializer_line(raw_line: str) -> list[str]:
    line = raw_line.strip().strip("{} ,")
    if not line:
        return []
    return [field.strip() for field in line.split(",")]


def collect_initializer_entries(text: str) -> list[str]:
    entries: list[str] = []
    current: list[str] = []
    collecting = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not collecting and not line.startswith("{"):
            continue
        collecting = True
        current.append(line)
        if "}" in line:
            entries.append(" ".join(current))
            current = []
            collecting = False
    return entries


def parse_specs(text: str, macros: dict[str, str]) -> dict[str, str]:
    specs: dict[str, str] = {}
    for entry in collect_initializer_entries(text):
        if "MSCONNECTOR_DIRECTIVE_" not in entry:
            continue
        if "MSCONNECTOR_DIRECTIVE_VALUE_" not in entry:
            continue

        fields = fields_from_initializer_line(entry)
        if len(fields) < 2:
            continue

        directive_macro = fields[0]
        value_type = fields[1]
        if directive_macro in macros and value_type.startswith("MSCONNECTOR_DIRECTIVE_VALUE_"):
            specs[macros[directive_macro]] = value_type
    return specs


def parse_adapter_entries(text: str, macros: dict[str, str]) -> list[tuple[str, str, str]]:
    entries: list[tuple[str, str, str]] = []
    for entry in collect_initializer_entries(text):
        if "MSCONNECTOR_DIRECTIVE_SCOPE_" not in entry:
            continue
        if "MSCONNECTOR_DIRECTIVE_ARG_" not in entry:
            continue

        fields = fields_from_initializer_line(entry)
        if len(fields) < 4:
            continue

        offset = 1 if fields[0] == "0" else 0
        if len(fields) <= offset + 3:
            continue

        canonical_macro = fields[offset]
        host_macro = fields[offset + 1]
        policy = fields[offset + 3]
        canonical = macros.get(canonical_macro, canonical_macro)
        host = macros.get(host_macro, host_macro)
        entries.append((canonical, host, policy))
    return entries


missing_files = [p for p in (SPEC_H, SPEC_C, ADAPTER_H, ADAPTER_C, APACHE_CONFIG_C, NGINX_MODULE_C) if not p.exists()]
if missing_files:
    for path in missing_files:
        print(f"missing directive file: {path.relative_to(ROOT)}")
    sys.exit(1)

macros = parse_quoted_macro_definitions(DIRECTIVES_H.read_text())
specs = parse_specs(SPEC_C.read_text(), macros)
entries = parse_adapter_entries(ADAPTER_C.read_text(), macros)

ok = True
canonicals = [entry[0] for entry in entries]
for name in sorted(specs):
    if name not in canonicals:
        print(f"missing directive adapter entry: {name}")
        ok = False
for name in sorted(set(canonicals)):
    if canonicals.count(name) > 1:
        print(f"duplicate canonical_name: {name}")
        ok = False
for canonical, host, policy in entries:
    if not host:
        print(f"empty host_name: {canonical}")
        ok = False
    allowed = POLICY_FOR_TYPE.get(specs.get(canonical), set())
    if canonical == "modsecurity_rules":
        allowed = {"MSCONNECTOR_DIRECTIVE_ARG_RAW", "MSCONNECTOR_DIRECTIVE_ARG_ONE_OR_MORE"}
    if allowed and policy not in allowed:
        print(f"implausible argument policy: {canonical} {policy}")
        ok = False
for name in KNOWN:
    if name not in specs or name not in canonicals:
        print(f"known directive missing: {name}")
        ok = False

apache_directives = {macros.get(macro, macro) for macro in parse_apache_directive_macros(APACHE_CONFIG_C.read_text())}
for name in sorted(apache_directives):
    if name not in specs:
        print(f"apache directive missing common spec: {name}")
        ok = False
    if name not in canonicals:
        print(f"apache directive missing common adapter: {name}")
        ok = False
for raw in re.findall(r'AP_INIT_[A-Z0-9_]+\(\s*"([^"]+)"', APACHE_CONFIG_C.read_text()):
    print(f"apache directive uses local string literal instead of common macro: {raw}")
    ok = False

nginx_text = NGINX_MODULE_C.read_text()
nginx_directives = {macros.get(macro, macro) for macro in parse_nginx_directive_macros(nginx_text)}
for surface in (set(macros.values()), set(specs), set(canonicals), apache_directives, nginx_directives):
    if "modsecurity_phase4_body_limit" in surface:
        print("removed directive registered: modsecurity_phase4_body_limit")
        ok = False
expected_nginx_directives = set(KNOWN) - set(NGINX_DIRECTIVE_NOT_APPLICABLE)
for name in sorted(expected_nginx_directives):
    if name not in nginx_directives:
        print(f"nginx directive missing from registration: {name}")
        ok = False
for name in sorted(NGINX_DIRECTIVE_NOT_APPLICABLE):
    if name in nginx_directives:
        print(f"nginx directive marked not applicable but registered: {name}")
        ok = False
for name in sorted(nginx_directives):
    if name not in specs:
        print(f"nginx directive missing common spec: {name}")
        ok = False
    if name not in canonicals:
        print(f"nginx directive missing common adapter: {name}")
        ok = False
for raw in re.findall(r'ngx_string\(\s*"([^"]+)"', nginx_text):
    if raw in macros.values():
        print(f"nginx directive uses local string literal instead of common macro: {raw}")
        ok = False

print("connector directive adoption: Apache and NGINX directive names checked against common macros/specs/adapters")
if not ok:
    sys.exit(1)
print("directive-parity: common directive spec/adapter parity present")
