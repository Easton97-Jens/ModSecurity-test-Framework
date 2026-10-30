#!/usr/bin/env python3
"""Generate the source/case migration map; never select or execute a test.

Inputs are explicit source roots, fixed original Git bases, source-map.json,
the current inventory, and actual Make/workflow/action source. Run with the
Framework-owned Python, -P and Framework-only PYTHONPATH. --check is read-only.
"""

from __future__ import annotations

import argparse
import ast
import csv
import fnmatch
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from modsecurity_test_framework.connector_integration import git_object_identity
from modsecurity_connector_ci.lib.active_test_inventory import (
    _expand_indexed_sources,
    _keys,
)

from modsecurity_test_framework.connector_context import (
    connector_root,
    test_root,
    source_path,
    load_source,
)

_ACTIVE_INVENTORY_SOURCE = (
    "connector_suite/modsecurity_connector_ci/lib/active_test_inventory.py"
)
_CONNECTOR_MAKEFILE_SOURCE = "connector_suite/connector.mk"
_CONNECTOR_CLI_SOURCE = "modsecurity_test_framework/connector.py"
_UNASSESSED_TEXT = "not assessed"


INITIAL_BASE = "c5993ed9a7b59fc0bd58f105595ec79f596c88d6"
UPDATED_BASE = "ec18f9e92286379a2410e917f76e6a5502675804"
FRAMEWORK_BASE = "3a4f2281568139d94fda6b51dc2e07bb8fc06c67"
SHIMS = {
    "ci/runtime/broker/nginx_exact_head_root_launcher.py",
    "ci/runtime/broker/nginx_exact_head_result_collector.py",
}
INVENTORY = "config/testing/active-cases.json"
NAMESPACES = (
    ("tests.", "modsecurity_connector_tests."),
    ("ci.", "modsecurity_connector_ci."),
    ("connectors.", "connector_suite.adapters."),
)


def caller_source_rows(owner, path, text, markers):
    rows = []
    target = None
    for line, command in enumerate(text.splitlines(), 1):
        if re.match(r"^[A-Za-z0-9_.%/-]+(?: [A-Za-z0-9_.%/-]+)*:", command):
            target = command.split(":", 1)[0]
        if not any(marker in command for marker in markers):
            continue
        identity = owner + ":" + path + ":" + str(line)
        rows.append(
            {
                "id": identity,
                "owner": owner,
                "path": path,
                "line": line,
                "make_target": target
                if path.endswith(("Makefile", "connector.mk"))
                else None,
                "source_line": caller_source_line(command)
                if owner in {"Connector", "Framework"}
                else command.strip(),
                "admission_only": "--check" in command,
                "source_kind": caller_source_kind(path),
                "selection_note": "source caller only; execution and automatic case admission are separate",
            }
        )
    return rows


def python_source_locations(selector, framework, mapping):
    old = []
    module = selector["target"].rsplit(".", 2)[0]
    old, direct = mapped_python_location(module, framework, mapping)
    if direct is not None:
        return old, direct
    if not old and module.startswith("modsecurity_test_framework.selftests."):
        return [], [
            "tests/"
            + module.removeprefix("modsecurity_test_framework.selftests.").replace(
                ".", "/"
            )
            + ".py"
        ]
    return old, None


def mapped_python_location(module, framework, mapping):
    old = []
    for legacy, modern in NAMESPACES:
        if module.startswith(modern):
            logical = (legacy + module[len(modern) :]).replace(".", "/") + ".py"
            if logical not in mapping:
                physical = (
                    (
                        ""
                        if module.startswith("connector_suite.")
                        else "connector_suite/"
                    )
                    + module.replace(".", "/")
                    + ".py"
                )
                if not (framework / physical).is_file():
                    raise ValueError(
                        "new regression source location is unavailable: " + physical
                    )
                return [], [physical]
            old = [logical]
            break
    return old, None


def python_prerequisite_nodes(text, selector, parsed):
    tree = parsed if parsed is not None else ast.parse(text)
    wanted = (selector or {}).get("target", "").rsplit(".", 2)[-2:]
    nodes = [
        node
        for node in tree.body
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    selected_class = next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef)
            and len(wanted) == 2
            and node.name == wanted[0]
        ),
        None,
    )
    if selected_class is not None:
        nodes.extend(
            node
            for node in selected_class.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name in {wanted[-1], "setUp", "setUpClass"}
        )
    elif selector is None:
        nodes = list(tree.body)
    return nodes


def python_prerequisite_imports(node, add):
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif node.module and node.level == 0:
            modules = [node.module]
        else:
            modules = []
        for module in modules:
            if module.split(".", 1)[0] not in sys.stdlib_module_names | {"__future__"}:
                add(
                    "dependency",
                    "Python import: " + module,
                    node.lineno,
                    "source import in module/selected definition; surrounding guards may make it conditional",
                )


def subprocess_prerequisites(node, add):
    argument = (
        node.args[0]
        if node.args
        else next(
            (keyword.value for keyword in node.keywords if keyword.arg == "args"),
            None,
        )
    )
    values = (
        [
            item.value
            for item in argument.elts
            if isinstance(item, ast.Constant) and isinstance(item.value, str)
        ]
        if isinstance(argument, (ast.List, ast.Tuple))
        else []
    )
    executable = (
        values[0]
        if isinstance(argument, (ast.List, ast.Tuple))
        and argument.elts
        and isinstance(argument.elts[0], ast.Constant)
        and isinstance(argument.elts[0].value, str)
        else None
    )
    subprocess_argument_prerequisites(node, executable, values, add)


def subprocess_argument_prerequisites(node, executable, values, add):
    add(
        "tool",
        executable or "computed subprocess executable",
        node.lineno,
        "if this source call executes without a test replacement",
    )
    if executable and Path(executable).name in {
        "nginx",
        "httpd",
        "apache2",
        "haproxy",
        "envoy",
        "traefik",
        "lighttpd",
    }:
        add(
            "host",
            Path(executable).name,
            node.lineno,
            "if the selected test actually launches this host",
        )
    if executable and Path(executable).name in {
        "sudo",
        "unshare",
        "bwrap",
        "nsenter",
    }:
        add(
            "privilege-or-isolation",
            Path(executable).name,
            node.lineno,
            "subject to the declared isolation/privilege policy; no grant inferred",
        )
    if (
        executable
        and Path(executable).name
        in {"pkg-config", "cc", "gcc", "clang", "c++", "g++", "clang++"}
        and any("modsecurity" in value.lower() for value in values)
    ):
        add(
            "SDK-or-build-input",
            "ModSecurity source/SDK input referenced by subprocess",
            node.lineno,
            "if this source call executes; not a host capability claim",
        )


def python_prerequisites(nodes, add):
    for root in nodes:
        for node in ast.walk(root):
            python_prerequisite_imports(node, add)
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            if (
                isinstance(function, ast.Attribute)
                and isinstance(function.value, ast.Name)
                and function.value.id == "subprocess"
                and function.attr in {"run", "Popen", "check_call", "check_output"}
            ):
                subprocess_prerequisites(node, add)
            elif (
                isinstance(function, ast.Attribute)
                and isinstance(function.value, ast.Name)
                and function.value.id == "os"
                and function.attr in {"geteuid", "getuid", "getgid"}
            ):
                add(
                    "privilege-or-isolation",
                    "UID/GID guard",
                    node.lineno,
                    "the surrounding predicate determines accepted identity; root is not inferred",
                )


def shell_selected_host_prerequisites(lines, selector, add):
    arguments = (selector or {}).get("args", [])
    for number, line in enumerate(lines, 1):
        assignment = re.match(
            r"\s*([A-Za-z_](?a:\w)*)=\$\{([1-9])(?::[?+-][^}]*)?\}", line
        )
        if assignment is None or int(assignment[2]) > len(arguments):
            continue
        value = arguments[int(assignment[2]) - 1]
        variable = assignment[1]
        case = next(
            (
                index
                for index in range(number, len(lines))
                if re.search(
                    r"\bcase\s+[\"']?\$\{?" + re.escape(variable) + r"\}?[\"']?\s+in\b",
                    lines[index],
                )
            ),
            None,
        )
        if case is None:
            continue
        end = next(
            (
                index
                for index in range(case + 1, len(lines))
                if lines[index].strip() == "esac"
            ),
            len(lines),
        )
        arm = next(
            (
                index
                for index in range(case + 1, end)
                if re.search(
                    r"(?:^|[|\s])" + re.escape(value) + r"(?:[|)])", lines[index]
                )
            ),
            None,
        )
        if arm is not None and value in {
            "apache",
            "nginx",
            "haproxy",
            "envoy",
            "traefik",
            "lighttpd",
        }:
            add(
                "host",
                "selected host adapter: " + value,
                arm + 1,
                "selector argument "
                + str(assignment[2])
                + " is validated by this shell case; stage-specific host/build prerequisites still require their source guards",
            )


def shell_command_prerequisites(lines, add):
    for line_number, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        for match in re.finditer(
            r"\bcommand\s+-v\s+[\"']?([A-Za-z0-9_./+${}-]+)", line
        ):
            add(
                "tool",
                match.group(1),
                line_number,
                "conditional command-presence check in selected source; inspect branch",
            )
        if re.search(
            r"\b(?:require_modsecurity_v3|find_modsecurity_v3_prefix)\b|pkg-config[^\n]*modsecurity",
            line,
        ):
            add(
                "SDK-or-build-input",
                "ModSecurity source/SDK declaration",
                line_number,
                "conditional SDK discovery/requirement in selected source",
            )
        if re.search(r"(?:\$\{?(?:CC|CXX)\}?|\$\((?:CC|CXX)\))", line):
            add(
                "tool",
                "source-selected C/C++ compiler",
                line_number,
                "if the compiler invocation branch executes; flags stay source-owned",
            )
        if re.search(r"\b(?:sudo|unshare|bwrap|nsenter)\b|\$\(id -u\)", line):
            add(
                "privilege-or-isolation",
                "source-declared identity/isolation command",
                line_number,
                "surrounding guard defines authorization; no privilege is granted",
            )


def inventory_driver_kind(argv, prefix):
    kind = None
    if prefix[:2] == ["go", "test"]:
        kind = "go"
    elif prefix[0] == "sh":
        kind = "native"
    elif (
        isinstance(argv.elts[0], ast.Attribute)
        and isinstance(argv.elts[0].value, ast.Name)
        and argv.elts[0].value.id == "sys"
        and argv.elts[0].attr == "executable"
        and prefix[1:3] == ["-P", "-c"]
    ):
        kind = "python"
    return kind


def execution_prerequisites(rows, execution, selector, drivers):
    requirements = {
        "profile": {
            "status": "inventory-declared case-profile metadata; not runtime --profile values",
            "case_profiles": sorted(
                {
                    profile
                    for candidate in rows.values()
                    if candidate["execution_id"] == execution
                    for profile in candidate["profiles"]
                }
            ),
            "runtime_profile": "explicit public-adapter --profile/CONNECTOR_TEST_PROFILE input; inspect source callers",
        },
        "pinned_checkout": {
            "status": "required for public Connector inventory invocation",
            "Framework": "explicit TEST_ROOT; Connector-pinned or separately selected development revision",
            "Connector": "explicit CONNECTOR_ROOT and CONNECTOR_REVISION matching its exact HEAD",
            "independent_Framework_entrypoints": "may have different checkout needs; inspect actual caller",
        },
        "external_output": {
            "status": "required for public Connector inventory invocation",
            "contract": "existing trusted non-symlink output ancestry outside both source checkouts",
        },
        "execution_driver": {
            "kind": selector["kind"],
            "selector": selector,
            "source_evidence": drivers[selector["kind"]],
            "status": "selector-declared; tool availability not assessed",
        },
        "source_declarations": [],
        "unresolved": [
            "transitive helper dependencies and branch execution are not proved by static declarations",
            "SDK/tool/host readiness, privilege eligibility and dependency installation are not assessed",
        ],
    }
    return requirements


def go_toolchain_prerequisites(product, selector, requirements):
    module_file = product / selector["module"] / "go.mod"
    if module_file.is_file() and not module_file.is_symlink():
        for number, line in enumerate(module_file.read_text().splitlines(), 1):
            if re.match(r"^(?:go|toolchain)\s+", line):
                requirements["source_declarations"].append(
                    {
                        "category": "toolchain",
                        "value": line.strip(),
                        "status": "selected module declaration; availability not assessed",
                        "evidence": source_reference(
                            "Connector",
                            str(module_file.relative_to(product)),
                            number,
                            line,
                        ),
                    }
                )


def source_prerequisites(new, framework, parsed_sources, selector, requirements):
    for relative in new:
        if relative not in parsed_sources:
            text = (framework / relative).read_text()
            parsed_sources[relative] = (
                text,
                ast.parse(text) if relative.endswith(".py") else None,
            )
        text, parsed = parsed_sources[relative]
        requirements["source_declarations"].extend(
            declared_prerequisites(
                "Framework", relative, text, selector=selector, parsed=parsed
            )
        )


def prerequisite_categories(requirements):
    categories = {}
    for category, source_categories in {
        "SDK": {"SDK-or-build-input"},
        "tool": {"tool", "toolchain"},
        "host": {"host"},
        "privileges": {"privilege-or-isolation"},
        "dependencies": {"SDK-or-build-input", "toolchain", "dependency"},
    }.items():
        indices = [
            index
            for index, item in enumerate(requirements["source_declarations"])
            if item["category"] in source_categories
        ]
        categories[category] = {
            "source_declaration_indices": indices,
            "status": "conditional source declarations; readiness not assessed"
            if indices
            else "not statically established; transitive/branch requirements unresolved",
        }
    categories["tool"]["selector_driver_tool"] = requirements["execution_driver"].get(
        "tool"
    )
    for category, key in (
        ("profile", "profile"),
        ("pinned_checkout", "pinned_checkout"),
        ("external_outputs", "external_output"),
    ):
        categories[category] = {"catalog_field": key}
    return categories


def discovery_candidate(relative, caller, command):
    if (
        relative.endswith(".py")
        and caller["owner"] == "Framework"
        and "unittest discover" in command
    ):
        start = re.search(r"(?:^|\s)-s\s+[\"']?([^\s\"']+)", command)
        pattern = re.search(r"(?:^|\s)-p\s+[\"']?([^\s\"']+)", command)
        if start:
            directory = (
                start[1]
                .removeprefix("$(TEST_ROOT)/")
                .removeprefix("$(FRAMEWORK_ROOT)/")
            )
            directory = directory.removeprefix("./").rstrip("/")
            if relative.startswith(directory + "/") and fnmatch.fnmatch(
                Path(relative).name, pattern[1] if pattern else "test*.py"
            ):
                return True
    return False


def python_definition_routes(archive, callers, framework, binding_index, caller_tokens):
    routes = []
    for source in archive["sources"]:
        relative = source["framework_path"]
        direct = []
        discoveries = []
        source_text = (framework / relative).read_text()
        definitions = sorted(
            set(
                source["on_demand_definitions"]
                + source["contains_selected_definitions"]
            )
        )
        source_executions = sorted(binding_index.get(relative, ()))
        for caller in callers:
            command = caller["source_line"]
            if set(definitions) & caller_tokens[caller["id"]]:
                direct.append(caller["id"])
            if discovery_candidate(relative, caller, command):
                discoveries.append(caller["id"])
        routes.append(
            {
                "archive_source": source["source"],
                "framework_path": relative,
                "definition_ids": definitions,
                "direct_caller_ids": sorted(set(direct)),
                "archive_declared_selected_definition_ids": source[
                    "contains_selected_definitions"
                ],
                "source_binding_execution_ids": source_executions,
                "discovery_candidate_caller_ids": sorted(set(discoveries)),
                "source_load_tests_filter": bool(
                    re.search(r"^\s*def load_tests\(", source_text, re.MULTILINE)
                )
                if relative.endswith(".py")
                else None,
                "automatic_selection": "not inferred; source-owned load_tests and the Connector inventory remain authoritative",
                "observed_execution": _UNASSESSED_TEXT,
            }
        )
    return routes


def native_definition_routes(archive, callers, binding_index):
    routes = []
    for source in archive["native_sources"]:
        relative = source["framework_path"]
        references = sorted(
            {
                caller["id"]
                for caller in callers
                if relative in caller["source_line"]
                or source["source"] in caller["source_line"]
            }
        )
        executions = sorted(binding_index.get(relative, ()))
        routes.append(
            {
                "archive_source": source["source"],
                "framework_path": relative,
                "source_reference_caller_ids": references,
                "source_binding_execution_ids": executions,
                "definition_ids": [
                    entry["symbol"]
                    for entry in archive["native_extracted_definitions"]
                    if entry["framework_path"] == relative
                ],
                "symbol_reference_caller_ids": {
                    entry["symbol"]: sorted(
                        {
                            caller["id"]
                            for caller in callers
                            if re.search(
                                r"\b" + re.escape(entry["symbol"]) + r"\b",
                                caller["source_line"],
                            )
                        }
                    )
                    for entry in archive["native_extracted_definitions"]
                    if entry["framework_path"] == relative
                },
                "automatic_selection": "not inferred; native source/reference or preserved helper availability is not a selected or executed independent case",
                "observed_execution": _UNASSESSED_TEXT,
            }
        )
    return routes


def mapped_file_records(mapping, framework, product, initial_blobs, updated_blobs):
    files = []
    for old, new in sorted(mapping.items()):
        file = framework / new
        if file.is_symlink() or not file.is_file():
            raise ValueError("mapped Framework file is missing or linked: " + new)
        retained = (product / old).exists()
        if retained and old not in SHIMS:
            raise ValueError("unexpected duplicate Connector test source: " + old)
        files.append(
            {
                "old_path": old,
                "new_framework_path": new,
                "sha256_framework_source": digest(file.read_bytes()),
                "sha256_before": digest(initial_blobs[old])
                if initial_blobs[old] is not None
                else None,
                "present_at_initial_base": initial_blobs[old] is not None,
                "sha256_updated_base": digest(updated_blobs[old]),
                "retained_authenticated_product_entrypoint": retained,
            }
        )
    return files


def public_entrypoint_records(framework):
    entrypoints = []
    for relative in (
        _CONNECTOR_CLI_SOURCE,
        _CONNECTOR_MAKEFILE_SOURCE,
    ):
        for line, text in enumerate((framework / relative).read_text().splitlines(), 1):
            if (
                "def main(" in text
                or "--on-demand" in text
                or "ACTIVE_TEST_RUNNER =" in text
            ):
                entrypoints.append(
                    {
                        "id": "Framework:" + relative + ":" + str(line),
                        "owner": "Framework",
                        "path": relative,
                        "line": line,
                        "source_line": text.strip(),
                    }
                )
    return entrypoints


def case_records(
    current, framework, mapping, baseline, callers, entrypoints, previous_callers
):
    cases = []
    for name, row in sorted(current.items()):
        old, new = locations(row, framework, mapping)
        prior = baseline.get(name)
        ids = related(row, callers)
        cases.append(
            {
                **{key: value for key, value in row.items() if key != "sources"},
                "inventory_source_binding_execution": row["execution_id"],
                "old_path": old,
                "new_framework_path": new,
                "actual_callers": ids,
                "prerequisites": {
                    "catalog_execution_id": row["execution_id"],
                    "declared_case_profiles": row["profiles"],
                    "availability": _UNASSESSED_TEXT,
                    "source": "prerequisite_catalog",
                },
                "public_entrypoints": [item["id"] for item in entrypoints],
                "migration_disposition": "preserved" if prior else "added-on-demand",
                "old_selector": prior["selector"] if prior else None,
                "old_caller_ids": related(prior, previous_callers) if prior else [],
                "current_caller_ids": ids,
                "public_entrypoint_requires_explicit_on_demand": row["selection"]
                == "on-demand",
                "execution_assessment": "not assessed; inspect separate revision-bound run receipts",
            }
        )
    return cases


def archive_availability(framework):
    archive = load_source(
        framework
        / "connector_suite/modsecurity_connector_ci/tools/update-test-archive.py"
    ).archive()
    archive_bytes = (json.dumps(archive, indent=2, sort_keys=True) + "\n").encode()
    archive_path = (
        "connector_suite/reports/testing/test-selection-archive.generated.json"
    )
    if (
        not (framework / archive_path).is_file()
        or (framework / archive_path).read_bytes() != archive_bytes
    ):
        raise ValueError(
            "refresh the definition archive through its generator before generating the migration map"
        )
    availability = {
        "artifact": archive_path,
        "sha256": digest(archive_bytes),
        "python_go_source_sets": len(archive["sources"]),
        "native_sources": len(archive["native_sources"]),
        "framework_yaml_sources": len(archive["framework_case_sources"]),
        "native_preserved_function_count": archive["native_preserved_function_count"],
        "native_preserved_function_lines": archive["native_preserved_function_lines"],
        "scope": "The linked archive enumerates all definitions and source identities, including plain native functions. Availability is not automatic selection or observed execution.",
    }
    return archive, availability


def case_table(cases, prerequisites):
    columns = (
        "test_id",
        "purpose",
        "selection",
        "execution_id",
        "actual_callers",
        "old_path",
        "new_framework_path",
        "migration_disposition",
        "selector",
        "old_caller_ids",
        "current_caller_ids",
        "public_entrypoints",
        "prerequisites",
        "prerequisite_tools",
        "prerequisite_sdk",
        "prerequisite_host",
        "prerequisite_profiles",
        "prerequisite_privileges",
        "prerequisite_dependencies",
        "prerequisite_checkouts",
        "prerequisite_external_outputs",
    )
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream, fieldnames=columns, delimiter="\t", lineterminator="\n"
    )
    writer.writeheader()
    for row in cases:
        table_row = {
            **row,
            **prerequisite_summary(row, prerequisites[row["execution_id"]]),
        }
        writer.writerow(
            {
                key: table_row[key]
                if isinstance(table_row[key], str)
                else encoded(table_row[key])
                for key in columns
            }
        )
    return stream.getvalue()


def go_source_locations(selector, sources):
    old = []
    name = selector["test"].split("/")[0]
    for logical in sources:
        if logical.endswith("_test.go"):
            file = source_path(logical)
            if re.search(
                r"^func\s+" + re.escape(name) + r"\(",
                file.read_text(),
                re.MULTILINE,
            ):
                old.append(logical)
    return old


def inventory_driver_argv(node):
    if not isinstance(node, (ast.Return, ast.Assign)):
        return None
    value = node.value
    # The Python/native drivers return (argv, cwd); Go builds argv first.
    argv = value.elts[0] if isinstance(value, ast.Tuple) and value.elts else value
    if not isinstance(argv, ast.List) or not argv.elts:
        return None
    return argv


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(root, *args, data=None):
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    env.update(
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_NO_LAZY_FETCH="1",
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_OPTIONAL_LOCKS="0",
        GIT_TERMINAL_PROMPT="0",
    )
    return subprocess.run(
        ["git", "--no-replace-objects", "-C", str(root), *args],
        input=data,
        capture_output=True,
        check=True,
        env=env,
    ).stdout


def original_sources(root, revision, paths):
    """Batch-read fixed Git blobs and independently verify their blob preimages."""
    names = sorted(set(paths))
    raw = git(
        root,
        "cat-file",
        "--batch",
        data="".join(revision + ":" + name + "\n" for name in names).encode(),
    )
    cursor, result = 0, {}
    for name in names:
        end = raw.index(b"\n", cursor)
        header = raw[cursor:end].decode().split()
        if len(header) != 3 or header[1] != "blob":
            raise ValueError(
                "original source is not a Git blob: " + revision + ":" + name
            )
        size = int(header[2])
        cursor = end + 1
        body = raw[cursor : cursor + size]
        cursor += size
        if raw[cursor : cursor + 1] != b"\n":
            raise ValueError("invalid Git batch boundary")
        cursor += 1
        if git_object_identity("blob", body) != header[0]:
            raise ValueError("original Git source blob identity differs: " + name)
        result[name] = body
    if cursor != len(raw):
        raise ValueError("unexpected Git batch output")
    return result


def flatten(inventory):
    cases = {}
    for section, selection in (
        ("executions", "standard"),
        ("offline_unit_exceptions", "on-demand"),
    ):
        for execution in inventory[section]:
            for case in execution["cases"]:
                if case["id"] in cases:
                    raise ValueError("duplicate case ID in migration input")
                cases[case["id"]] = {
                    "test_id": case["id"],
                    "purpose": case["requirement"],
                    "selection": selection,
                    "execution_id": execution["id"],
                    "selector": execution["selector"],
                    "groups": execution["groups"],
                    "profiles": case["profiles"],
                    "sources": execution["sources"],
                }
    return cases


def counts(inventory):
    return {
        "standard_cases": sum(len(x["cases"]) for x in inventory["executions"]),
        "standard_executions": len(inventory["executions"]),
        "on_demand_cases": sum(
            len(x["cases"]) for x in inventory["offline_unit_exceptions"]
        ),
        "on_demand_executions": len(inventory["offline_unit_exceptions"]),
    }


def projected(selector):
    value = dict(selector)
    if value["kind"] == "python":
        for old, new in NAMESPACES:
            if value["target"].startswith(old):
                value["target"] = new + value["target"][len(old) :]
                break
    return value


def preserve(original, current):
    for name, row in original.items():
        if name not in current:
            raise ValueError("original case is missing: " + name)
        candidate = current[name]
        for key in (
            "test_id",
            "purpose",
            "selection",
            "execution_id",
            "groups",
            "profiles",
        ):
            if row[key] != candidate[key]:
                raise ValueError("original case contract changed: " + name + ":" + key)
        if projected(row["selector"]) != candidate["selector"]:
            raise ValueError(
                "selector differs beyond the closed namespace projection: " + name
            )
    for name in current.keys() - original.keys():
        if current[name]["selection"] != "on-demand":
            raise ValueError("new case was automatically activated: " + name)


def caller_source_line(command):
    # Parent must point at the future Framework commit containing this map.
    # Keep actual source locations/commands while projecting only that cyclic
    # revision value to its existing gitlink binding. Historical Parent pins
    # and the separate historical framework_sha=99a... remain literal.
    return re.sub(
        r"(Easton97-Jens/ModSecurity-test-Framework/[^\s@]+@)"
        r"(?:[a-f0-9]{40}|__FRAMEWORK_MIGRATION_SHA__|TASK_FRAMEWORK_SHA)",
        r"\1<connector-framework-gitlink>",
        command.strip(),
    )


def caller_source_kind(path):
    if path.endswith(("Makefile", ".mk")):
        return "make"
    if path.startswith(".github/workflows/"):
        return "ci-workflow"
    if path.startswith(".github/actions/"):
        return "ci-action"
    if path.startswith("connector_native_tests/"):
        return "native-adapter"
    if path.endswith(".sh"):
        return "native-shell-selector"
    return "python-runner-or-discovery"


def caller_lines(sources):
    rows = []
    markers = (
        "ACTIVE_TEST_RUNNER",
        "run-active-tests.py",
        "modsecurity_test_framework.connector",
        "framework-native-selftest",
        "framework-go-test",
        "connector_native_tests/",
        "ModSecurity-test-Framework/.github/",
        "$(TEST_ROOT)/connector_suite/",
        "unittest",
        "$(MAKE)",
        "make ",
        "go test",
        "pytest",
        "self_test",
        "module_load_tests",
        "python_discovery_suite",
        "CONNECTOR_TEST_PROFILE",
        'selector["target"]',
        'selector["script"]',
        'selector["module"]',
        'return ["sh", str(script)',
    )
    for owner, path, text in sorted(sources):
        rows.extend(caller_source_rows(owner, path, text, markers))
    return rows


def related(row, callers):
    selector = row["selector"]
    matches = []
    for caller in callers:
        command = caller["source_line"]

        def exact_token(value):
            return value in command and re.search(
                r"(?<![A-Za-z0-9_.])" + re.escape(value) + r"(?![A-Za-z0-9_.])", command
            )

        named = (
            exact_token(row["execution_id"])
            or exact_token(row["test_id"])
            or (selector["kind"] == "python" and exact_token(selector["target"]))
            or (selector["kind"] == "native" and exact_token(selector["script"]))
            or (selector["kind"] == "go" and exact_token(selector["module"]))
        )
        grouped = "--group" in command and any(
            re.search(
                r"--group\s+[\"']?" + re.escape(group) + r"(?:[\"']?\s|$)", command
            )
            for group in row["groups"]
        )
        # A default group invocation cannot activate archived cases sharing a group.
        selector_dispatch = caller.get("selector_kind") == selector["kind"]
        if (
            named
            or selector_dispatch
            or (
                grouped and (row["selection"] == "standard" or "--on-demand" in command)
            )
        ):
            matches.append(caller["id"])
    return matches


def locations(row, framework, mapping):
    selector = row["selector"]
    old = []
    if selector["kind"] == "python":
        old, direct = python_source_locations(selector, framework, mapping)
        if direct is not None:
            return old, direct
    elif selector["kind"] == "native":
        old = [selector["script"]]
    else:
        old = go_source_locations(selector, row["sources"])
    new = [
        mapping.get(name, name.removeprefix("modules/ModSecurity-test-Framework/"))
        for name in old
    ]
    if not new or any(not (framework / name).is_file() for name in new):
        raise ValueError("case source location is unavailable: " + row["test_id"])
    return old, new


def source_reference(owner, path, line, text):
    """Retain actual declaration locations without introducing a Framework pin cycle."""
    return {
        "owner": owner,
        "path": path,
        "line": line,
        "source_line": caller_source_line(text),
    }


def declared_prerequisites(owner, path, text, selector=None, parsed=None):
    """Extract conditional executable/guard declarations, never readiness or PASS.

    Python string fixtures and filename/group names are not dependency evidence.
    Only subprocess calls in the selected definition/setup/module initialization
    are inspected. Unresolved helper calls remain explicitly unresolved.
    """
    declarations = []
    lines = text.splitlines()

    def add(category, value, line, condition):
        declarations.append(
            {
                "category": category,
                "value": value,
                "condition": condition,
                "status": "source-declared; availability not assessed",
                "evidence": source_reference(owner, path, line, lines[line - 1]),
            }
        )

    if path.endswith(".py"):
        nodes = python_prerequisite_nodes(text, selector, parsed)
        python_prerequisites(nodes, add)
    elif path.endswith((".sh", "Makefile", ".mk")):
        shell_selected_host_prerequisites(lines, selector, add)
        shell_command_prerequisites(lines, add)
    unique = {encoded(item): item for item in declarations}
    return [unique[key] for key in sorted(unique)]


def inventory_driver_declarations(text):
    """Bind each selector kind to the actual AST argv construction, not line layout."""
    path = _ACTIVE_INVENTORY_SOURCE
    result = {}
    for node in ast.walk(ast.parse(text)):
        argv = inventory_driver_argv(node)
        if argv is None:
            continue
        prefix = [
            element.value if isinstance(element, ast.Constant) else None
            for element in argv.elts
        ]
        kind = inventory_driver_kind(argv, prefix)
        if kind is None:
            continue
        if kind in result:
            raise ValueError("inventory driver declaration is ambiguous: " + kind)
        source = ast.get_source_segment(text, node) or ast.unparse(node)
        result[kind] = {
            "id": "Framework:" + path + ":" + str(node.lineno),
            "owner": "Framework",
            "path": path,
            "line": node.lineno,
            "source_line": caller_source_line(source),
            "selector_kind": kind,
            "source_kind": "inventory-selector-dispatch",
            "make_target": None,
            "admission_only": False,
            "selection_note": "exact inventory selector argv construction; admission still selects cases",
        }
    if set(result) != {"python", "native", "go"}:
        raise ValueError(
            "review generator prerequisites for changed inventory selector drivers"
        )
    return result


def prerequisite_catalog(rows, product, framework, mapping):
    """Deduplicate per-execution conditions while retaining per-Test-ID references."""
    catalog = {}
    parsed_sources = {}
    driver_path = _ACTIVE_INVENTORY_SOURCE
    drivers = inventory_driver_declarations((framework / driver_path).read_text())
    for row in sorted(
        rows.values(), key=lambda value: (value["execution_id"], value["test_id"])
    ):
        execution = row["execution_id"]
        if execution in catalog:
            continue
        _old, new = locations(row, framework, mapping)
        selector = row["selector"]
        requirements = execution_prerequisites(rows, execution, selector, drivers)
        if selector["kind"] == "python":
            requirements["execution_driver"]["tool"] = (
                "Framework-compatible Python interpreter"
            )
        elif selector["kind"] == "native":
            requirements["execution_driver"]["tool"] = (
                "sh (exact native inventory argv driver)"
            )
        elif selector["kind"] == "go":
            requirements["execution_driver"]["tool"] = (
                "Go test driver with external test overlay"
            )
            go_toolchain_prerequisites(product, selector, requirements)
        source_prerequisites(new, framework, parsed_sources, selector, requirements)
        categories = prerequisite_categories(requirements)
        requirements["requirement_categories"] = categories
        catalog[execution] = requirements
    return catalog


def prerequisite_summary(row, prerequisites):
    """Keep TSV prerequisites readable without claiming unknown inputs are absent."""

    def summary(categories):
        values = sorted(
            {
                item["value"]
                for item in prerequisites["source_declarations"]
                if item["category"] in categories
            }
        )
        return (
            "Conditional source declarations: "
            + "; ".join(values)
            + "; availability not assessed"
            if values
            else "Not statically established; transitive/branch requirements unresolved"
        )

    return {
        "prerequisite_tools": "Driver: "
        + prerequisites["execution_driver"].get("tool", "source-selected")
        + "; "
        + summary({"tool", "toolchain"}),
        "prerequisite_sdk": summary({"SDK-or-build-input"}),
        "prerequisite_host": summary({"host"}),
        "prerequisite_profiles": "Case-profile metadata: "
        + ", ".join(row["profiles"])
        + "; runtime --profile is explicit and separate",
        "prerequisite_privileges": summary({"privilege-or-isolation"}),
        "prerequisite_dependencies": summary(
            {"dependency", "toolchain", "SDK-or-build-input"}
        ),
        "prerequisite_checkouts": "Public inventory invocation: explicit pinned/development TEST_ROOT plus CONNECTOR_ROOT/CONNECTOR_REVISION exact HEAD; independent Framework callers have their own contract",
        "prerequisite_external_outputs": "Public inventory invocation: existing trusted non-symlink output ancestry outside both checkouts",
    }


def current_caller_sources(product, framework, rows):
    """Read current maintained sources, including newly added thin entrypoints."""
    paths = git(
        product,
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "--",
        "Makefile",
        "common/**/Makefile",
        "connectors/**/Makefile",
        ".github/workflows/*.yml",
        ".github/workflows/*.yaml",
    )
    sources = [
        ("Connector", relative, (product / relative).read_text())
        for relative in sorted(set(paths.decode().splitlines()))
        if (product / relative).is_file() and not (product / relative).is_symlink()
    ]
    fixed = (
        "Makefile",
        _CONNECTOR_MAKEFILE_SOURCE,
        _CONNECTOR_CLI_SOURCE,
        _ACTIVE_INVENTORY_SOURCE,
        "connector_native_tests/invoke.py",
        "connector_native_tests/go_invoke.py",
        "connector_native_tests/run.py",
        "modsecurity_test_framework/connector_integration.py",
    )
    sources.extend(
        ("Framework", relative, (framework / relative).read_text())
        for relative in fixed
    )
    scripts = sorted(
        {
            row["selector"]["script"]
            for row in rows.values()
            if row["selector"]["kind"] == "native"
        }
    )
    sources.extend(
        (
            "Framework",
            str(source_path(relative).relative_to(framework)),
            source_path(relative).read_text(),
        )
        for relative in scripts
    )
    for directory, pattern in (
        (".github/actions", "action.yml"),
        (".github/actions", "action.yaml"),
        (".github/workflows", "*.yml"),
        (".github/workflows", "*.yaml"),
    ):
        sources.extend(
            ("Framework", str(path.relative_to(framework)), path.read_text())
            for path in sorted((framework / directory).rglob(pattern))
            if path.is_file() and not path.is_symlink()
        )
    return sorted(set(sources))


def definition_routes(archive, callers, framework, rows, mapping):
    """Prove source/discovery routes without turning availability into selection."""
    routes = []
    caller_tokens = {
        caller["id"]: set(
            re.findall(
                r"\b[A-Za-z_](?a:\w)*(?:\.[A-Za-z_](?a:\w)*)*\b",
                caller["source_line"],
            )
        )
        for caller in callers
    }
    binding_index = {}
    for row in rows.values():
        for logical in row["sources"]:
            relative = mapping.get(
                logical, logical.removeprefix("modules/ModSecurity-test-Framework/")
            )
            binding_index.setdefault(relative, set()).add(row["execution_id"])
    routes.extend(
        python_definition_routes(
            archive, callers, framework, binding_index, caller_tokens
        )
    )
    routes.extend(native_definition_routes(archive, callers, binding_index))
    return routes


def requirement_ownership(mapping, sources, framework):
    """Keep the user-requested packets separate using actual source paths only."""
    mapped = sorted(set(mapping.values()))
    current = sorted({(owner, path) for owner, path, _ in sources})
    shared = [
        path
        for path in mapped
        if path.startswith(
            (
                "connector_suite/modsecurity_connector_ci/lib/",
                "connector_suite/modsecurity_connector_ci/provisioning/",
            )
        )
    ]
    shared.extend(
        path
        for path in (
            _CONNECTOR_CLI_SOURCE,
            "modsecurity_test_framework/connector_context.py",
            "modsecurity_test_framework/workflow_sources.py",
            "connector_native_tests/invoke.py",
            "connector_native_tests/go_invoke.py",
            "connector_native_tests/run.py",
        )
        if (framework / path).is_file()
    )
    mrts = [
        path
        for path in (
            "ci/provisioning/mrts-package.py",
            "ci/provisioning/mrts_definition_guard.py",
            "ci/provisioning/import-mrts-cases.py",
            "ci/lib/mrts_results.py",
            "ci/lib/runtime_path_safety.py",
            "connector_suite/modsecurity_connector_tests/test_mrts_native_package_handoff.py",
        )
        if (framework / path).is_file()
    ]
    mrts_packet = [
        "ci/provisioning/mrts-package.py",
        "ci/provisioning/mrts_definition_guard.py",
        "ci/lib/mrts_results.py",
        "ci/lib/mrts_path_safety.py",
        "tests/security_regression/test_mrts_package.py",
        "tests/security_regression/test_mrts_definition_guard.py",
        "docs/mrts-preparation.md",
        "docs/mrts-preparation.de.md",
        "docs/reference/variables.md",
        "docs/reference/variables.de.md",
        "reports/audits/change-records/20261030-01-mrts-package-integrity.md",
        "reports/audits/change-records/20261030-01-mrts-package-integrity.de.md",
    ]
    integration = [
        path
        for path in (
            "modsecurity_test_framework/connector_integration.py",
            "tests/connector_adapter/test_connector_integration.py",
            _CONNECTOR_MAKEFILE_SOURCE,
        )
        if (framework / path).is_file()
    ]
    return [
        {
            "requirement_id": "migration.test-ownership",
            "owner": "Framework",
            "purpose": "complete test and test-infrastructure relocation with source/case preservation",
            "framework_paths": mapped,
            "source_map": "connector_suite/source-map.json",
        },
        {
            "requirement_id": "migration.shared-test-mechanics",
            "owner": "Framework",
            "purpose": "shared loading, dispatch, validation, provisioning and process/result mechanics",
            "framework_paths": sorted(set(shared)),
        },
        {
            "requirement_id": "migration.mrts-separate-packet",
            "owner": "Framework (separate MRTS-focused followup worktree/PR)",
            "purpose": "recursive definitions, complete validation-source binding and import regression preservation",
            "framework_gitlink_path": "tools/MRTS",
            "framework_integration_paths": mrts,
            "separate_framework_packet_paths": mrts_packet,
            "packet_path_presence_in_selected_framework": {
                path: (framework / path).is_file()
                and not (framework / path).is_symlink()
                for path in mrts_packet
            },
            "tool_repository_disposition": "pinned read-only; no MRTS repository source change",
            "packet_status": "separate worktree/PR delivery; no merge or runtime result inferred",
            "scope": "this generator neither reads nor changes MRTS source",
        },
        {
            "requirement_id": "migration.connector-thin-integration",
            "owner": "Connector",
            "purpose": "productive build/delivery ownership and small pinned Framework callers",
            "connector_paths": [
                path for owner, path in current if owner == "Connector"
            ],
            "authenticated_retained_paths": sorted(SHIMS),
        },
        {
            "requirement_id": "migration.clean-pair-integration",
            "owner": "Framework with dependent Connector pin",
            "purpose": "real clean-checkout recorded-pin combination and separately reported development override",
            "framework_paths": integration,
            "make_target": "test-framework-integration-probe",
            "execution_status": "not assessed; source presence is not a clean-pair integration PASS",
        },
    ]


def generate():
    product, framework = connector_root(), test_root()
    mapping_bytes = (framework / "connector_suite/source-map.json").read_bytes()
    mapping = json.loads(mapping_bytes)["paths"]
    inventory_bytes = source_path(INVENTORY).read_bytes()
    inventory = json.loads(inventory_bytes)
    if type(inventory.get("schema_version")) is not int or inventory[
        "schema_version"
    ] not in {4, 5}:
        raise ValueError("current migration inventory requires schema 4 or 5")
    _keys(
        inventory,
        {
            "schema_version",
            "executions",
            "offline_unit_exceptions",
            "source_bindings",
            "connector_source_paths",
        },
        "current migration inventory",
    )
    _expand_indexed_sources(
        inventory, inventory["executions"] + inventory["offline_unit_exceptions"]
    )
    tracked = git(product, "ls-tree", "-rz", "--name-only", UPDATED_BASE).split(b"\0")
    originals = [
        name.decode()
        for name in tracked
        if name
        and (
            name.decode().startswith(".github/workflows/")
            or name.decode().endswith("Makefile")
        )
    ]
    updated_blobs = original_sources(
        product, UPDATED_BASE, [*mapping, INVENTORY, *originals]
    )
    initial_paths = set(
        git(product, "ls-tree", "-rz", "--name-only", INITIAL_BASE).split(b"\0")
    )
    initial_blobs = original_sources(
        product,
        INITIAL_BASE,
        [name for name in mapping if name.encode() in initial_paths] + [INVENTORY],
    )
    initial_blobs.update(
        {name: None for name in mapping if name.encode() not in initial_paths}
    )
    initial_inventory = json.loads(initial_blobs[INVENTORY])
    updated_inventory = json.loads(updated_blobs[INVENTORY])
    baseline, updated, current = (
        flatten(initial_inventory),
        flatten(updated_inventory),
        flatten(inventory),
    )
    preserve(baseline, current)
    preserve(updated, current)
    if counts(initial_inventory) != counts(updated_inventory):
        raise ValueError("the updated original base changed selection counts")
    files = mapped_file_records(
        mapping, framework, product, initial_blobs, updated_blobs
    )
    previous_callers = caller_lines(
        ("Connector-updated-base", path, updated_blobs[path].decode())
        for path in originals
    )
    current_sources = current_caller_sources(product, framework, current)
    callers_by_id = {row["id"]: row for row in caller_lines(current_sources)}
    driver_path = _ACTIVE_INVENTORY_SOURCE
    for declaration in inventory_driver_declarations(
        (framework / driver_path).read_text()
    ).values():
        callers_by_id[declaration["id"]] = declaration
    callers = [callers_by_id[key] for key in sorted(callers_by_id)]
    # The actual public API's parser and Make delegator are entrypoint sources,
    # not proof that any particular archived selector ran.
    entrypoints = public_entrypoint_records(framework)
    prerequisites = prerequisite_catalog(current, product, framework, mapping)
    cases = case_records(
        current, framework, mapping, baseline, callers, entrypoints, previous_callers
    )
    archive, availability = archive_availability(framework)
    document = {
        "schema_version": 3,
        "generator": "connector_suite/modsecurity_connector_ci/tools/build-migration-map.py",
        "connector_revision": INITIAL_BASE,
        "updated_connector_base_revision": UPDATED_BASE,
        "framework_revision": FRAMEWORK_BASE,
        "updated_framework_base_revision": "1d1e73fb069598e0f0f809d0bf16b5e59047ff88",
        "latest_framework_integration_base_revision": "d3b47aec9410f7adc3bb40df1ea413c00c438e89",
        "counts": {
            **counts(initial_inventory),
            "source_bindings": len(initial_inventory["source_bindings"]),
            "migrated_files": len(files),
        },
        "current_counts": {
            **counts(inventory),
            "fixed_framework_sources": len(inventory["source_bindings"]),
            "revision_bound_product_sources": len(
                inventory.get("connector_source_paths", [])
            ),
        },
        "inputs": {
            "source_map_sha256": digest(mapping_bytes),
            "current_inventory_sha256": digest(inventory_bytes),
            "initial_inventory_sha256": digest(initial_blobs[INVENTORY]),
            "updated_base_inventory_sha256": digest(updated_blobs[INVENTORY]),
        },
        "preservation": {
            "original_case_ids": len(baseline),
            "preserved_case_ids": len(baseline),
            "selector_projection": list(NAMESPACES),
            "new_cases_on_demand_only": True,
        },
        "files": files,
        "cases": cases,
        "old_callers": previous_callers,
        "callers": callers,
        "public_entrypoints": entrypoints,
        "availability": availability,
        "prerequisite_catalog": prerequisites,
        "prerequisite_semantics": "Per-Test-ID prerequisites reference an execution catalog. Guaranteed public-adapter inputs are separate from conditional source declarations; unresolved transitive/branch requirements and readiness remain explicit. No filename/group is used to claim a host/SDK/privilege prerequisite or PASS.",
        "definition_caller_routes": definition_routes(
            archive, callers, framework, current, mapping
        ),
        "requirement_file_ownership": requirement_ownership(
            mapping, current_sources, framework
        ),
        "caller_source_providers": [
            {"owner": owner, "path": path} for owner, path, _ in current_sources
        ],
        "caller_revision_projection": "Current Framework-owned action/workflow revision tokens alone are displayed as <connector-framework-gitlink> to avoid a cross-repository self-reference. Actual owner/path/line and selector text remain source-derived; historical Parent broker pins remain literal.",
        "execution_note": "Availability, declared selection, callers and observed execution are distinct. This generator runs no tests and assigns no PASS. Existing Framework self-tests retain their own entrypoints; archive availability adds no automatic Connector cases. Runtime receipts remain external and revision-bound.",
    }
    table = case_table(cases, prerequisites)
    return document, table


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    document, table = generate()
    root = test_root() / "connector_suite"
    outputs = {
        root / "migration-baseline.json": json.dumps(document, indent=2, sort_keys=True)
        + "\n",
        root / "test-map.tsv": table,
    }
    for path, text in outputs.items():
        if path.is_symlink() or path.parent.is_symlink():
            raise ValueError(
                "migration output must stay in its regular Framework source directory"
            )
        if args.check:
            if not path.is_file() or path.read_text() != text:
                raise SystemExit(
                    "Migration map differs from its immutable bases/current source inputs: "
                    + str(path)
                )
        else:
            path.write_text(text)
    print(
        encoded(
            {
                "original": document["counts"],
                "current": document["current_counts"],
                "preserved_case_ids": document["preservation"]["preserved_case_ids"],
                "check": args.check,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
