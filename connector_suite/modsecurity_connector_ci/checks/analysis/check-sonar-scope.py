#!/usr/bin/env python3
"""Check explicit Parent Sonar scope and Python-version drift without a scanner.

This is a tracked-file/configuration check, not proof of analyzer execution.
Only Sonar's documented *, ** and ? path patterns are accepted here.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, source_path

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = connector_root()
CFAMILY_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh", ".hxx"}
CODE_SUFFIXES = CFAMILY_SUFFIXES | {".py", ".go", ".sh", ".bash"}
CONFIG_SUFFIXES = {".json", ".yaml", ".yml"}
# Framework owns the migrated test/fuzz roots and analyzes them in its own project.
# Every tracked Parent path still passes classification, including any future tests.
COMPONENTS = ("common", "connectors", "ci", "scripts", ".github", "examples", "config")
# The user-selected root boundaries are independent of configurable patterns.
EXCLUDED_ROOTS = ("modules", "reports")


def properties(path: Path) -> dict[str, str]:
    """Read the deliberately simple, single-line checked-in property contract."""
    result: dict[str, str] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        if "=" not in line or line.endswith("\\"):
            raise ValueError(f"unsupported property syntax on line {number}")
        key, value = (part.strip() for part in line.split("=", 1))
        if key in result:
            raise ValueError(f"duplicate property: {key}")
        result[key] = value
    return result


def patterns(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def matches(path: str, pattern: str) -> bool:
    """Match Sonar's slash-separated wildcard syntax, including zero directories."""
    if not pattern or any(char in pattern for char in "[]\\"):
        raise ValueError(f"unsupported scope pattern: {pattern!r}")
    expression: list[str] = []
    index = 0
    while index < len(pattern):
        if pattern[index:index + 3] == "**/":
            expression.append("(?:.*/)?")
            index += 3
        elif pattern[index:index + 2] == "**":
            expression.append(".*")
            index += 2
        elif pattern[index] == "*":
            expression.append("[^/]*")
            index += 1
        elif pattern[index] == "?":
            expression.append("[^/]")
            index += 1
        else:
            expression.append(re.escape(pattern[index]))
            index += 1
    return re.fullmatch("".join(expression), path) is not None


def selected(path: str, scope_patterns: list[str]) -> bool:
    return any(matches(path, pattern) for pattern in scope_patterns)


def expected_test(path: str) -> bool:
    """Express the repository's test ownership independently of scope patterns."""
    file = Path(path)
    return (
        file.suffix == ".go" and file.name.endswith("_test.go")
        or file.suffix == ".py" and (
            path.startswith("tests/")
            or file.name.startswith("test_")
            or file.name.endswith("_test.py")
        )
    )


def maintained_analyzable(path: str) -> bool:
    """Identify expected code/config independently of the requested scan scope."""
    file = Path(path)
    if file.suffix in CODE_SUFFIXES or file.name == "go.mod":
        return True
    return file.suffix in CONFIG_SUFFIXES


def validate_settings(config: dict[str, str], python_pin: str) -> None:
    """Keep manual scanner scope, project identity, and language versions aligned."""
    required = {
        "sonar.projectKey": "Easton97-Jens_ModSecurity-conector",
        "sonar.organization": "easton97-jens",
        "sonar.scanner.autoconfig.enabled": "false",
        "sonar.sources": ".",
        "sonar.tests": ".",
        "sonar.scm.exclusions.disabled": "true",
    }
    for key, value in required.items():
        if config.get(key) != value:
            raise ValueError(f"{key} must be {value!r}")
    if not re.fullmatch(r"\d+\.\d+\.\d+", python_pin):
        raise ValueError(".python-version must contain the exact reviewed patch")
    if config.get("sonar.python.version") != python_pin.rsplit(".", 1)[0]:
        raise ValueError("sonar.python.version must match .python-version major.minor")
    if "sonar.cfamily.compile-commands" in config:
        raise ValueError("a compilation database requires a separately verified full-Parent build contract")


def verify_classification(path: str, test: bool, production: bool) -> None:
    """Reject maintained code loss and classification that hides CFamily tests."""
    file = Path(path)
    if test and production:
        raise ValueError(f"source/test overlap: {path}")
    if expected_test(path) != test:
        raise ValueError(f"incorrect test classification: {path}")
    if not test and not production:
        category = "maintained source" if maintained_analyzable(path) else "tracked Parent file"
        raise ValueError(f"{category} excluded: {path}")
    if file.suffix in CFAMILY_SUFFIXES and not production:
        raise ValueError(f"CFamily file must remain in source scope: {path}")


def verify_excluded_boundary(boundary: str, source_exclusions: list[str], test_exclusions: list[str]) -> None:
    """Exclude each selected root from both source and test indexing."""
    label = "independent submodule" if boundary == "modules" else "root reports"
    if not selected(boundary + "/placeholder.c", source_exclusions):
        raise ValueError(f"{label} source contents must be excluded")
    if not selected(boundary + "/test_placeholder.py", test_exclusions):
        raise ValueError(f"{label} test contents must be excluded")


def classify_paths(config: dict[str, str], tracked: list[str]) -> tuple[list[str], list[str], list[str]]:
    """Partition tracked paths using Sonar's automatic test-source exclusion rule."""
    test_inclusions = patterns(config.get("sonar.test.inclusions", ""))
    test_exclusions = patterns(config.get("sonar.test.exclusions", ""))
    source_exclusions = patterns(config.get("sonar.exclusions", ""))
    source_inclusions = patterns(config.get("sonar.inclusions", ""))
    source: list[str] = []
    tests: list[str] = []
    excluded: list[str] = []
    for path in tracked:
        boundary = path.split("/", 1)[0]
        if boundary in EXCLUDED_ROOTS:
            verify_excluded_boundary(boundary, source_exclusions, test_exclusions)
            excluded.append(path)
            continue
        test = selected(path, test_inclusions) and not selected(path, test_exclusions)
        production = (
            not selected(path, source_exclusions)
            and (not source_inclusions or selected(path, source_inclusions))
            and not selected(path, test_inclusions)
        )
        verify_classification(path, test, production)
        if test:
            tests.append(path)
        elif production:
            source.append(path)
        else:
            excluded.append(path)
    expected_exclusions = [boundary + "/**" for boundary in EXCLUDED_ROOTS]
    if source_exclusions != expected_exclusions or test_exclusions != expected_exclusions:
        raise ValueError("source/test exclusions must contain only root modules/** and reports/**")
    return source, tests, excluded


def validate(config: dict[str, str], python_pin: str, tracked: list[str]) -> dict[str, object]:
    """Return observed classification or fail on loss of maintained code/tests."""
    validate_settings(config, python_pin)
    source, tests, excluded = classify_paths(config, tracked)
    for component in COMPONENTS:
        if not any(
            path.startswith(component + "/") and maintained_analyzable(path)
            for path in source + tests
        ):
            raise ValueError(f"component missing analyzable code/config: {component}")
    modules = sorted(path for path in source if Path(path).name == "go.mod")
    if len(modules) != 4:
        raise ValueError(f"review Go module inventory (expected four, found {len(modules)})")
    return {
        "evidence_layer": "tracked configuration scope; analyzer execution not verified",
        "source_files": len(source),
        "test_files": len(tests),
        "source_suffixes": dict(sorted(Counter(Path(path).suffix or "(none)" for path in source).items())),
        "test_suffixes": dict(sorted(Counter(Path(path).suffix for path in tests).items())),
        "cfamily_translation_units": sum(Path(path).suffix in {".c", ".cc", ".cpp", ".cxx"} for path in source),
        "go_modules": modules,
        "source_paths": source,
        "test_paths": tests,
        "excluded_tracked_files": excluded,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print the complete tracked-file inventory")
    args = parser.parse_args()
    try:
        tracked = subprocess.run(
            ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True,
        ).stdout.decode("utf-8").rstrip("\0").split("\0")
        result = validate(
            properties(source_path('sonar-project.properties', root=ROOT)),
            (source_path('.python-version', root=ROOT)).read_text(encoding="utf-8").strip(),
            tracked,
        )
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Sonar scope check failed: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Sonar scope passed: {result['source_files']} sources, {result['test_files']} tests, "
              f"{result['cfamily_translation_units']} CFamily translation units, four Go modules")
        print(result["evidence_layer"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
