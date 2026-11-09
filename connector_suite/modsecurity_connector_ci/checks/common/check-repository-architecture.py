#!/usr/bin/env python3
"""Check the bounded, literal repository architecture contract (not a compiler graph)."""

from __future__ import annotations

import argparse
import ast
import configparser
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
from urllib.parse import unquote, urlparse

MODEL = {
    "schema_version": 1,
    "rules": [
        "common-host-neutral",
        "product-without-test-infrastructure",
        "no-parent-gitlink",
    ],
    "ownership": {
        "common": "common",
        "product": ["common", "connectors"],
        "framework_gitlink": "modules/ModSecurity-test-Framework",
    },
    "external_header_namespaces": ["modsecurity/"],
    "contracts": {
        "connector": ["docs/architecture.md", "docs/test-ownership-migration.md"],
        "framework": ["docs/architecture.md"],
    },
}
C_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
SOURCE_SUFFIXES = C_SUFFIXES | {".py", ".go", ".sh", ".cmake", ".mk", ".m4", ".in"}
MAKE_NAMES = {"Makefile", "makefile", "GNUmakefile", "Makefile.am"}
BUILD_NAMES = MAKE_NAMES | {
    "go.mod",
    "CMakeLists.txt",
    "meson.build",
    "BUILD",
    "BUILD.bazel",
    "configure.ac",
    "config",
}
FRAMEWORK = re.compile(
    r"ModSecurity-test-Framework|modsecurity_test_framework|modsecurity_connector_(?:ci|tests)"
)
HOST_HEADER_NAMES = {
    "nginx.h",
    "httpd.h",
    "ap_config.h",
    "util_filter.h",
    *(
        f"http_{part}.h"
        for part in (
            "config",
            "protocol",
            "request",
            "connection",
            "core",
            "log",
            "main",
            "vhost",
        )
    ),
}
HOST_DIRECTORY = re.compile(
    r"(?:^|/)(?:apache2?|nginx|haproxy|envoy|lighttpd|traefik)/"
)
INCLUDE = re.compile(r'^\s*#\s*include\s*([<"])([^>"\n]+)[>"]', re.MULTILINE)
MAKE_REFERENCE = re.compile(r"\$[({]([A-Za-z_](?a:\w)*)[)}]")
PRODUCT_INPUT_VARIABLE = re.compile(
    r"(?:^|_)(?:sources?|srcs?|objs?|objects?|includes?)(?:_|$)",
    re.IGNORECASE,
)
PRODUCT_FLAG_VARIABLE = re.compile(
    r"(?:^|_)(?:ldadd|libadd|ldlibs|libs|ldflags|cflags|cxxflags|cppflags)(?:_|$)",
    re.IGNORECASE,
)


class ContractError(ValueError):
    """Invalid input prevents the promised architecture comparison."""


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate model key")
        result[key] = value
    return result


def regular_text(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ContractError(f"required regular file missing: {path}")
    return path.read_text(encoding="utf-8")


def without_c_comments(text: str) -> str:
    # Keep strings intact: dependency literals inside them are relevant.
    return re.sub(
        r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"',
        lambda match: match[0] if match[0].startswith('"') else " ",
        text.replace("\\\n", ""),
        flags=re.DOTALL,
    )


def make_assignments(lines: list[str]) -> list[tuple[str, str]]:
    assignments = []
    for line in lines:
        if line.startswith("\t"):
            continue
        match = re.match(
            r"\s*(?:(?:override|export)\s+)?([A-Za-z_](?a:\w)*)\s*[:+?]?=(.*)",
            line,
        )
        if match:
            assignments.append(match.groups())
    return assignments


def make_references(text: str) -> set[str]:
    return set(MAKE_REFERENCE.findall(text))


def framework_variables(assignments: list[tuple[str, str]]) -> set[str]:
    tainted = {name for name, value in assignments if FRAMEWORK.search(value)}
    while True:
        expanded = tainted | {
            name for name, value in assignments if make_references(value) & tainted
        }
        if expanded == tainted:
            return tainted
        tainted = expanded


def make_graph_edge(line: str, tainted: set[str]) -> str | None:
    if re.match(r"\s*-?s?include\s", line):
        return "ModSecurity-test-Framework included Make graph"
    if ":" not in line or "=" in line:
        return None
    prerequisites = line.split(":", 1)[1]
    if FRAMEWORK.search(prerequisites) or make_references(prerequisites) & tainted:
        return "ModSecurity-test-Framework target prerequisite"
    return None


def recipe_segments(line: str) -> list[list[str]]:
    lexer = shlex.shlex(line.lstrip("\t@+- "), posix=True, punctuation_chars=";&|")
    lexer.whitespace_split = True
    segments, segment = [], []
    for token in lexer:
        if token and all(character in ";&|" for character in token):
            segments.append(segment)
            segment = []
        else:
            segment.append(token)
    return segments + [segment]


def recipe_executable(tokens: list[str]) -> list[str]:
    while tokens and (
        tokens[0] in {"then", "do", "!"} or re.match(r"[A-Za-z_](?a:\w)*=", tokens[0])
    ):
        tokens = tokens[1:]
    return tokens


def compile_or_link_command(command: str) -> bool:
    return any(
        pattern.search(command)
        for pattern in (
            re.compile(r"\$[({]?(?:CC|CXX|LD|AR)[)}]?"),
            re.compile(r"(?:^|\s)(?:cc|gcc|clang|g\+\+|clang\+\+|ld|ar)(?:\s|$)"),
            re.compile(r"\bgo\s+build\b"),
        )
    )


def framework_test_script(tokens: list[str], tainted: set[str]) -> bool:
    executable = tokens[0]
    script = (
        tokens[1]
        if executable in {"sh", "bash", "$(PYTHON)"} and len(tokens) > 1
        else executable
    )
    if script == "-P" and len(tokens) > 2:
        script = tokens[2]
    if "/connector_suite/" not in script:
        return False
    if not (FRAMEWORK.search(script) or make_references(script) & tainted):
        return False
    if any(part in script for part in ("/harness/", "/tests/", "/checks/")):
        return True
    return any(part in script for part in ("/scripts/", "/build/")) and bool(
        re.search(r"(?:test|check|smoke|runtime)", Path(script).name)
    )


def make_recipe_edge(
    tokens: list[str], tainted: set[str], values: dict[str, str], valid_runner: bool
) -> str | None:
    command = " ".join(tokens)
    references = make_references(command)
    if not (FRAMEWORK.search(command) or references & tainted):
        return None
    tokens = recipe_executable(tokens)
    if not tokens:
        return None
    if compile_or_link_command(command):
        return "ModSecurity-test-Framework compile/link sink: " + command
    if tokens[0] == "$(ACTIVE_TEST_RUNNER)" and valid_runner:
        return None
    if tokens[0] == "$(MAKE)" and recursive_test_command(tokens[1:]):
        return None
    if framework_test_script(tokens, tainted):
        return None
    # Data operands cannot exempt compilation/linking: those sinks were checked first.
    data_refs = {
        name
        for name in references
        if re.search(r"\.(?:json|conf|txt)[\s)]*$", values.get(name, ""))
    }
    if not FRAMEWORK.search(command) and references & tainted <= data_refs:
        return None
    return "ModSecurity-test-Framework recipe dependency: " + command


def product_artifact_variable(name: str) -> bool:
    """Classify literal artifact inputs or compiler/linker flags with the same boundaries."""
    return bool(
        PRODUCT_INPUT_VARIABLE.search(name) or PRODUCT_FLAG_VARIABLE.search(name)
    )


def make_dependencies(text: str) -> list[str]:
    """Follow literal Make variable edges into artifact inputs and recipes.

    Test-runner variables and test/check delegation are valid. This is not a
    Make evaluator: computed variable names/functions and included graphs need
    their native build checks.
    """
    lines = [line.split("#", 1)[0] for line in text.replace("\\\n", " ").splitlines()]
    assignments = make_assignments(lines)
    tainted = framework_variables(assignments)
    edges = [
        f"ModSecurity-test-Framework artifact variable {name}"
        for name, _ in assignments
        if name in tainted and product_artifact_variable(name)
    ]
    values = dict(assignments)
    # Only the exact public test-runner command permits this recipe exception.
    valid_runner = bool(
        re.fullmatch(
            r"\$\(PYTHON\)\s+(?:-P\s+)?-m\s+modsecurity_test_framework\.connector",
            values.get("ACTIVE_TEST_RUNNER", "").strip(),
        )
    )
    for line in lines:
        if not (FRAMEWORK.search(line) or make_references(line) & tainted):
            continue
        if line.startswith("\t"):
            candidates = [
                make_recipe_edge(tokens, tainted, values, valid_runner)
                for tokens in recipe_segments(line)
            ]
        else:
            candidates = [make_graph_edge(line, tainted)]
        edges.extend(edge for edge in candidates if edge is not None)
    return edges


def recursive_test_command(tokens: list[str]) -> bool:
    targets = []
    skip = False
    for token in tokens:
        if skip:
            skip = False
        elif token in {"-C", "--directory", "-f", "--file", "-j"}:
            skip = True
        elif token.startswith("-") or "=" in token:
            continue
        else:
            targets.append(token)
    return bool(targets) and all(
        re.fullmatch(
            r"(?:test|check|self-test|framework-native-selftest|framework-go-test)(?:[-_][A-Za-z0-9_-]+)?",
            target,
        )
        for target in targets
    )


def source_file(path: Path) -> bool:
    if path.suffix not in SOURCE_SUFFIXES and path.name not in BUILD_NAMES:
        return False
    text = regular_text(path)
    return path.suffix != ".in" or text.startswith("#!")


def sources(root: Path, relative: str) -> list[Path]:
    directory = root / relative
    if directory.is_symlink() or not directory.is_dir():
        raise ContractError(f"required source directory missing: {relative}")
    selected = []
    for current, directories, files in os.walk(directory, followlinks=False):
        if any((Path(current) / name).is_symlink() for name in directories):
            raise ContractError("symlink in required source scope")
        selected.extend(
            Path(current) / name for name in files if source_file(Path(current) / name)
        )
    if not selected:
        raise ContractError(f"empty required source scope: {relative}")
    return sorted(selected)


PYTHON_LOADERS = {
    "__import__",
    "importlib.import_module",
    "importlib.util.spec_from_file_location",
    "ctypes.CDLL",
    "ctypes.PyDLL",
    "runpy.run_path",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "sys.path.append",
    "sys.path.insert",
}


def python_aliases(tree: ast.AST) -> dict[str, str]:
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            aliases.update(
                (alias.asname or alias.name, alias.name) for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom):
            aliases.update(
                (alias.asname or alias.name, (node.module or "") + "." + alias.name)
                for alias in node.names
            )
    return aliases


def python_call_literals(node: ast.Call, aliases: dict[str, str]) -> list[str]:
    prefix, separator, tail = ast.unparse(node.func).partition(".")
    name = aliases.get(prefix, prefix) + separator + tail
    if name not in PYTHON_LOADERS:
        return []
    arguments = node.args + [keyword.value for keyword in node.keywords]
    return [
        item.value
        for argument in arguments
        for item in ast.walk(argument)
        if isinstance(item, ast.Constant) and isinstance(item.value, str)
    ]


def python_dependencies(path: Path, text: str) -> list[str]:
    tree = ast.parse(text, filename=str(path))
    aliases = python_aliases(tree)
    values = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            values.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            values.append(node.module or "")
        elif isinstance(node, ast.Call):
            values.extend(python_call_literals(node, aliases))
    return values


def go_dependencies(text: str) -> list[str]:
    stripped = without_c_comments(text)
    clauses = re.findall(
        r'\bimport\s*(\([^)]*\)|(?:[A-Za-z_.](?a:\w)*\s+)?["`][^"`\n]+["`])',
        stripped,
        re.DOTALL,
    )
    return (
        [
            literal
            for clause in clauses
            for literal in re.findall(r'["`]([^"`\n]+)["`]', clause)
        ]
        + re.findall(r'\bplugin\.Open\s*\(\s*"([^"\n]+)"', stripped)
        + re.findall(r"#cgo\s+[^\n]*", text)
    )


SHELL_COMMAND_START = re.compile(r"(?:[;&|]|^|\bthen\b)", re.MULTILINE)
SHELL_ASSIGNMENT = re.compile(r"[A-Za-z_](?a:\w)*=\S+\s+")
SHELL_EXEC = re.compile(r"exec\s+")
SHELL_INTERPRETER = re.compile(r"(?:python[0-9.]*|sh|bash|source|\.)\s+")
SHELL_OPTION = re.compile(r"-[A-Za-z]+\s+")
SHELL_OPERAND = re.compile(r"""["']?([^\s;|&"']+)""")


def shell_interpreter_operand(text: str, position: int) -> tuple[str, int] | None:
    if interpreter := SHELL_INTERPRETER.match(text, position):
        option_position = interpreter.end()
        positions = [option_position]
        while option := SHELL_OPTION.match(text, option_position):
            option_position = option.end()
            positions.append(option_position)
        for candidate in reversed(positions):
            if operand := SHELL_OPERAND.match(text, candidate):
                return operand[1], operand.end()
    if operand := SHELL_OPERAND.match(text, position):
        return operand[1], operand.end()
    return None


def shell_assignment_operand(text: str, position: int) -> tuple[str, int] | None:
    # The former single regex could backtrack over assignments if the remainder
    # had no operand. Try the same greedy positions in the same order.
    positions = [position]
    while match := SHELL_ASSIGNMENT.match(text, position):
        position = match.end()
        positions.append(position)
    for candidate in reversed(positions):
        if operand := shell_interpreter_operand(text, candidate):
            return operand
    return None


def shell_operand(text: str, start: int) -> tuple[str, int] | None:
    position = re.compile(r"\s*").match(text, start).end()
    if execute := SHELL_EXEC.match(text, position):
        operand = shell_assignment_operand(text, execute.end())
        if operand is not None:
            return operand
    return shell_assignment_operand(text, position)


def shell_dependencies(text: str) -> list[str]:
    # Direct literal executables/source operands; not a POSIX evaluator.
    # Variable-produced command names and eval require native shell checks.
    text = text.replace("\\\n", " ")
    values = []
    position = 0
    while position <= len(text) and (
        start := SHELL_COMMAND_START.search(text, position)
    ):
        operand = shell_operand(text, start.end())
        if operand is None:
            position = start.start() + 1
        else:
            value, position = operand
            values.append(value)
    return values


def dependency_literals(path: Path, text: str) -> list[str]:
    if path.name in MAKE_NAMES or path.suffix == ".mk":
        return make_dependencies(text)
    if path.suffix == ".py":
        return python_dependencies(path, text)
    if path.suffix in C_SUFFIXES:
        stripped = without_c_comments(text)
        return [match[1] for match in INCLUDE.findall(stripped)] + re.findall(
            r'\b(?:dlopen|LoadLibrary[AW]?)\s*\(\s*"([^"\n]+)"', stripped
        )
    if path.suffix == ".go":
        return go_dependencies(text)
    if path.suffix in {".sh", ".in"}:
        return shell_dependencies(text)
    if path.name == "CMakeLists.txt" or path.suffix == ".cmake":
        return re.findall(
            r"\b(?:add_library|add_executable|target_sources|target_link_libraries|target_include_directories|include)\s*\((.*?)\)",
            text,
            re.DOTALL | re.IGNORECASE,
        )
    return [
        line.split("#", 1)[0]
        for line in text.splitlines()
        if not re.match(r"\s*(?:dnl\b|AC_MSG_\w+\s*\(|message\s*\(|#)", line)
    ]


def host_header(name: str) -> bool:
    filename = name.rsplit("/", 1)[-1]
    return (
        filename in HOST_HEADER_NAMES
        or filename.startswith("ngx_")
        and filename.endswith(".h")
        or bool(HOST_DIRECTORY.search(name))
    )


def common_include(
    product: Path, path: Path, delimiter: str, name: str
) -> tuple[str | None, Path | None]:
    if host_header(name) or "connectors/" in name:
        return f"common-host-neutral: {path.relative_to(product)} includes {name}", None
    candidates = [path.parent / name, product / "common/include" / name, product / name]
    resolved = next((item.resolve() for item in candidates if item.is_file()), None)
    if resolved is not None:
        if not resolved.is_relative_to(product / "common"):
            return f"common-host-neutral: dependency outside Common: {name}", None
        return None, resolved
    if name.startswith(tuple(MODEL["external_header_namespaces"])):
        return None, None
    if delimiter == '"' or name.startswith("msconnector/"):
        raise ContractError(f"unresolved Common local dependency: {name}")
    # Unresolved angle includes are external SDK/standard-library contracts.
    return None, None


def common_dependencies(product: Path, initial: list[Path]) -> tuple[list[str], int]:
    violations = []
    visited = set()
    pending = [path for path in initial if path.suffix in C_SUFFIXES]
    if not pending:
        raise ContractError("empty required Common C-family source scope")
    while pending:
        path = pending.pop().resolve()
        if path in visited:
            continue
        visited.add(path)
        text = without_c_comments(regular_text(path))
        if any(
            re.match(r"\s*#\s*include\b", line) and not INCLUDE.match(line)
            for line in text.splitlines()
        ):
            raise ContractError("unresolved nonliteral Common include operand")
        for match in INCLUDE.finditer(text):
            violation, dependency = common_include(product, path, *match.groups())
            if violation is not None:
                violations.append(violation)
            if dependency is not None:
                pending.append(dependency)
    return violations, len(visited)


def git_directory(root: Path) -> Path | None:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--git-common-dir"],
        capture_output=True,
        text=True,
    )
    return (root / result.stdout.strip()).resolve() if result.returncode == 0 else None


def framework_gitlinks(framework: Path) -> set[str]:
    top = subprocess.run(
        ["git", "-C", str(framework), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
    )
    if Path(top.stdout.strip()).resolve() != framework:
        raise ContractError("Framework root must be its actual Git top-level")
    completed = subprocess.run(
        ["git", "-C", str(framework), "ls-files", "--stage", "-z"],
        capture_output=True,
        check=True,
    )
    return {
        row.split("\t", 1)[1]
        for row in completed.stdout.decode().split("\0")
        if row.startswith("160000 ")
    }


def parent_gitlink(product: Path, framework: Path, url: str) -> bool:
    if re.search(r"(?:^|[/:])ModSecurity-conector(?:\.git)?/?$", url, re.IGNORECASE):
        return True
    parsed = urlparse(url)
    if parsed.scheme != "file" and (parsed.scheme or ":" in url):
        return False
    local = Path(unquote(parsed.path))
    local = (
        (framework / local).resolve() if not local.is_absolute() else local.resolve()
    )
    if not local.is_dir():
        raise ContractError("unresolved local gitlink repository")
    return local == product or (
        git_directory(product) is not None
        and git_directory(local) == git_directory(product)
    )


def reverse_gitlinks(product: Path, framework: Path) -> list[str]:
    links = framework_gitlinks(framework)
    if not links and not (framework / ".gitmodules").exists():
        return []
    modules = configparser.ConfigParser(interpolation=None, strict=True)
    modules.read_string(regular_text(framework / ".gitmodules"))
    declared = set()
    violations = []
    for section in modules.sections():
        path = modules.get(section, "path")
        declared.add(path)
        if parent_gitlink(product, framework, modules.get(section, "url")):
            violations.append(f"no-parent-gitlink: {path}")
    if links - declared:
        raise ContractError("gitlink without resolvable .gitmodules declaration")
    return violations


def check(
    product: Path, framework: Path, model_path: Path
) -> tuple[list[str], int, int]:
    model = json.loads(regular_text(model_path), object_pairs_hook=unique_object)
    if model != MODEL or type(model.get("schema_version")) is not int:
        raise ContractError(
            "model must contain the exact version-1 mandatory rules and ownership contract"
        )
    for owner, paths in model["contracts"].items():
        root = product if owner == "connector" else framework
        for relative in paths:
            if not regular_text(root / relative).strip():
                raise ContractError("empty versioned architecture contract")
    common = sources(product, "common")
    productive = common + sources(product, "connectors")
    violations, traversed = common_dependencies(product, common)
    for path in productive:
        text = regular_text(path)
        if any(FRAMEWORK.search(value) for value in dependency_literals(path, text)):
            violations.append(
                f"product-without-test-infrastructure: {path.relative_to(product)}"
            )
    violations.extend(reverse_gitlinks(product, framework))
    return violations, len(productive), traversed


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--connector-root", required=True, type=Path)
    parser.add_argument("--framework-root", required=True, type=Path)
    parser.add_argument("--model", type=Path)
    args = parser.parse_args(argv)
    product, framework = args.connector_root.resolve(), args.framework_root.resolve()
    model = (
        args.model
        or framework / "connector_suite/config/testing/repository-architecture.json"
    )
    try:
        if product == framework:
            raise ContractError("product and Framework must be separate repositories")
        violations, count, headers = check(product, framework, model)
    except (
        OSError,
        ValueError,
        SyntaxError,
        configparser.Error,
        subprocess.SubprocessError,
    ) as error:
        print(f"repository-architecture: ERROR: {error}", file=sys.stderr)
        return 2
    if violations:
        for violation in violations:
            print(f"repository-architecture: FAIL: {violation}", file=sys.stderr)
        return 1
    print(
        f"repository-architecture: PASS: {count} product files, {headers} Common C-family files; literal static scope"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
