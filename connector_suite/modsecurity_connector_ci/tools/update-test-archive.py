#!/usr/bin/env python3
"""Describe retained definitions without importing or automatically selecting them."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess

from modsecurity_test_framework.connector_context import test_root


GO_MODULES = ("connectors/envoy/ext_proc", "connectors/traefik/native_middleware",
              "connectors/traefik/response_observer", "connectors/traefik/composite_middleware")


def module_name(physical: str) -> str:
    if physical.startswith("connector_suite/adapters/"):
        return physical.removesuffix(".py").replace("/", ".")
    if physical.startswith("tests/"):
        return "modsecurity_test_framework.selftests." + physical.removeprefix("tests/").removesuffix(".py").replace("/", ".")
    return physical.removeprefix("connector_suite/").removesuffix(".py").replace("/", ".")


def python_definitions(path: Path, name: str, python_targets: set[str]):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    module = name.removesuffix(".py").replace("/", ".")
    definitions, selected = [], []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        for method in node.body:
            if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) and method.name.startswith("test_"):
                target = f"{module}.{node.name}.{method.name}"
                (selected if target in python_targets else definitions).append(target)
    return definitions, selected


def go_definitions(path: Path, logical: str, go_targets):
    module = next((name for name in GO_MODULES if logical.startswith(name + "/")), None)
    methods = re.findall(r"^func (Test\w+|Fuzz\w+)\(", path.read_text(), re.MULTILINE)
    if module is None:
        return methods, []
    relative = Path(logical.removeprefix(module + "/")).parent.as_posix()
    package = "." if relative == "." else "./" + relative
    return ([name for name in methods if (module, package, name) not in go_targets],
            [name for name in methods if (module, package, name) in go_targets])


def _retained_definitions(path, physical, logical, python_targets, go_targets):
    definitions, selected = [], []
    if path.suffix == ".py" and (path.name.startswith("test_") or path.name.endswith("_test.py")):
        definitions, selected = python_definitions(path, module_name(physical) + ".py", python_targets)
    elif path.name.endswith("_test.go"):
        definitions, selected = go_definitions(path, logical, go_targets)
    return definitions, selected


def _archive_sources(root, files, old_names, python_targets, go_targets):
    retained, native, catalogues = [], [], []
    for physical in files:
        path = root / physical
        if physical.startswith("tools/MRTS/") or path.is_symlink() or not path.is_file():
            continue
        logical = old_names.get(physical, "framework/" + physical)
        definitions, selected = _retained_definitions(path, physical, logical, python_targets, go_targets)
        if definitions or selected:
            retained.append({"source": logical, "framework_path": physical,
                             "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                             "on_demand_definitions": definitions,
                             "contains_selected_definitions": selected})
        if path.suffix in {".c", ".cc", ".cpp", ".inc"} and physical.startswith(("connector_suite/", "connector_native_tests/")):
            native.append({"source": logical, "framework_path": physical,
                           "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        if physical.startswith("tests/cases/") and path.suffix in {".yaml", ".yml"}:
            # Existing Framework catalogues remain declarative inputs. This list
            # describes availability, never an extra automatic selection.
            catalogues.append(physical)
    return retained, native, catalogues


def _extracted_definitions(root, manifest):
    extracted = []
    for definition in manifest["definitions"]:
        physical = "connector_native_tests/" + str(Path(definition["source"]).with_suffix(".inc"))
        if not (root / physical).is_file():
            raise ValueError("extracted native definition has no preserved Framework source")
        extracted.append({**definition, "framework_path": physical,
                          "availability_only": True, "automatic_case": False})
    return extracted


def archive() -> dict:
    root = test_root()
    inventory_bytes = (root / "connector_suite/config/testing/active-cases.json").read_bytes()
    inventory = json.loads(inventory_bytes)
    executions = inventory["executions"]
    python_targets = {item["selector"]["target"] for item in executions if item["selector"]["kind"] == "python"}
    go_targets = {(item["selector"]["module"], item["selector"]["package"], item["selector"]["test"].split("/")[0])
                  for item in executions if item["selector"]["kind"] == "go"}
    mapping = json.loads((root / "connector_suite/source-map.json").read_text())["paths"]
    old_names = {new: old for old, new in mapping.items()}
    raw = subprocess.check_output(["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"])
    files = sorted({name.decode() for name in raw.split(b"\0") if name})
    retained, native, catalogues = _archive_sources(root, files, old_names, python_targets, go_targets)
    manifest = json.loads((root / "connector_native_tests/extraction-manifest.json").read_text())
    extracted = _extracted_definitions(root, manifest)
    return {"schema_version": 2, "generator": "connector_suite/modsecurity_connector_ci/tools/update-test-archive.py",
            "purpose": "Framework-owned definition archive; connector_suite/config/testing/active-cases.json alone selects Connector defaults.",
            "inventory_sha256": hashlib.sha256(inventory_bytes).hexdigest(),
            "counting": "Definitions, expanded cases, execution selectors and actual runs are distinct. Retries do not create unique cases.",
            "disposition": "Retained specialist definitions require explicit on-demand selection; existing Framework self-test entrypoints keep their own scope. No recorded execution or new PASS.",
            "on_demand_definition_count": sum(len(item["on_demand_definitions"]) for item in retained),
            "sources": retained, "native_sources": native, "framework_case_sources": catalogues,
            "native_extraction_manifest_revision": manifest["source_revision"],
            "native_extracted_definitions": extracted,
            "native_preserved_function_count": manifest["preserved_function_count"],
            "native_preserved_function_lines": manifest["preserved_function_lines"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    destination = test_root() / "connector_suite/reports/testing/test-selection-archive.generated.json"
    expected = json.dumps(archive(), indent=2, sort_keys=True) + "\n"
    if args.check:
        if not destination.is_file() or destination.read_text() != expected:
            raise SystemExit("Specialist archive differs from its inventory/source generator inputs")
        print("Specialist archive matches current inventory and retained source definitions")
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(expected)
        print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
