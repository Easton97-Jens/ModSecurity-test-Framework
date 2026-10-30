"""Explicit source and fixture locations for the connector test adapter.

Framework self-tests do not construct this context. Connector tests require an
explicit checkout and revision; the Framework never searches for a parent repo.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import importlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess


class ContextError(ValueError):
    """An explicit test invocation has invalid source provenance or locations."""


def _directory(value: str, label: str) -> Path:
    if not value:
        raise ContextError(f"{label} is required explicitly")
    raw = Path(value)
    if not raw.is_absolute() or ".." in raw.parts:
        raise ContextError(f"{label} must be an absolute directory")
    resolved = raw.resolve(strict=True)
    if not resolved.is_dir():
        raise ContextError(f"{label} must be an existing directory")
    return resolved


def test_root() -> Path:
    """Return the explicitly supplied Framework checkout, never the product."""
    root = _directory(os.environ.get("TEST_ROOT", ""), "TEST_ROOT")
    if not (root / "modsecurity_test_framework" / "__init__.py").is_file():
        raise ContextError("TEST_ROOT must identify the pinned Framework checkout")
    return root


@lru_cache(maxsize=8)
def _checkout(value: str, expected_revision: str) -> Path:
    root = _directory(value, "CONNECTOR_ROOT")
    if not re.fullmatch(r"[a-f0-9]{40}(?:[a-f0-9]{24})?", expected_revision):
        raise ContextError("CONNECTOR_REVISION must be an exact source revision")
    completed = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--show-toplevel", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    )
    values = completed.stdout.splitlines()
    if values != [str(root), expected_revision]:
        raise ContextError(
            "CONNECTOR_ROOT or CONNECTOR_REVISION does not match the checkout"
        )
    if not (root / "connectors").is_dir() or not (root / "common" / "include").is_dir():
        raise ContextError("CONNECTOR_ROOT is not a connector product checkout")
    return root


def connector_root() -> Path:
    """Validate the checkout selected by the caller, including its revision."""
    return _checkout(
        os.environ.get("CONNECTOR_ROOT", ""), os.environ.get("CONNECTOR_REVISION", "")
    )


def validate_checkout() -> Path:
    """Revalidate source HEAD before admission and every executed child."""
    _checkout.cache_clear()
    return connector_root()


def framework_revision() -> str:
    """Bind Framework source to its own explicit Git checkout before guards."""
    root = test_root()
    completed = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--show-toplevel", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    )
    values = completed.stdout.splitlines()
    if len(values) != 2 or values[0] != str(root):
        raise ContextError("TEST_ROOT must identify its own Framework Git checkout")
    revision = values[1]
    if not re.fullmatch(r"[a-f0-9]{40}(?:[a-f0-9]{24})?", revision):
        raise ContextError("Framework checkout has no exact source revision")
    requested = os.environ.get("FRAMEWORK_REVISION")
    if requested and requested != revision:
        raise ContextError("FRAMEWORK_REVISION does not match the explicit checkout")
    return revision


@lru_cache(maxsize=8)
def _source_map(framework: Path) -> dict[str, str]:
    value = json.loads((framework / "connector_suite" / "source-map.json").read_text())
    if value.get("schema_version") != 1 or not isinstance(value.get("paths"), dict):
        raise ContextError("invalid Framework connector source map")
    paths = value["paths"]
    for old, new in paths.items():
        _relative(old)
        _relative(new)
        if not new.startswith(
            ("connector_suite/", "tests/", ".github/workflows/", ".github/actions/")
        ):
            raise ContextError(
                "mapped test source must stay in Framework test-owned directories"
            )
    if len(set(paths.values())) != len(paths):
        raise ContextError("mapped test sources must be unique")
    return paths


@lru_cache(maxsize=8)
def _connector_relocations(framework: Path) -> dict[str, str]:
    value = json.loads((framework / "connector_suite/source-map.json").read_text())
    paths = value.get("connector_paths", {})
    if not isinstance(paths, dict):
        raise ContextError("invalid product source relocation map")
    for old, new in paths.items():
        _relative(old)
        _relative(new)
    return paths


def _relative(value: str | Path) -> str:
    value = str(value)
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or "\\" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ContextError("test source must be a canonical relative path")
    return value


def _migrated_directory_path(name: str, framework: Path) -> Path | None:
    """Resolve only the reviewed whole-directory migrations."""
    directories = {
        "tests": "connector_suite/modsecurity_connector_tests",
        "ci/checks": "connector_suite/modsecurity_connector_ci/checks",
        "ci/runtime": "connector_suite/modsecurity_connector_ci/runtime",
        "ci/evidence": "connector_suite/modsecurity_connector_ci/evidence",
        "ci/provisioning/cache": "connector_suite/modsecurity_connector_ci/provisioning/cache",
        "ci/provisioning/components": "connector_suite/modsecurity_connector_ci/provisioning/components",
        "common/rules": "connector_suite/common/rules",
        "common/scripts": "connector_suite/common/scripts",
        "config/testing": "connector_suite/config/testing",
    }
    for old, new in directories.items():
        if name == old or name.startswith(old + "/"):
            return framework / new / name[len(old) :].lstrip("/")
    return None


def _mapped_source_path(name: str, product: Path, framework: Path) -> Path:
    """Apply mount, relocation, exact-source and directory precedence."""
    framework_mount = "modules/ModSecurity-test-Framework"
    if name == framework_mount:
        return framework
    if name.startswith(framework_mount + "/"):
        return framework / name.removeprefix(framework_mount + "/")
    relocated = _connector_relocations(framework).get(name)
    if relocated is not None:
        return product / relocated
    paths = _source_map(framework)
    if name in paths:
        return framework / paths[name]
    # Whole migrated directories may be passed to discovery/fixture compilers.
    directory = _migrated_directory_path(name, framework)
    if directory is not None:
        return directory
    if name.startswith("connectors/") and "/harness" in name:
        # Production launchers retained in the Connector take precedence.
        candidate = product / name
        if candidate.exists():
            return candidate
        return framework / "connector_suite/adapters" / name.removeprefix("connectors/")
    return product / name


def source_path(relative: str | Path, *, root: Path | None = None) -> Path:
    """Resolve a reviewed logical source without conflating product and tests.

    Explicit unit-fixture roots remain isolated from the real checkout. The
    source map preserves legacy source IDs while their ownership moves.
    """
    name = _relative(relative)
    selected = os.environ.get("CONNECTOR_ROOT", "")
    if root is not None and (
        not selected or root.resolve() != Path(selected).resolve()
    ):
        return root / name
    product = connector_root()
    if root is not None and root.resolve() != product:
        return root / name
    framework = test_root()
    return _mapped_source_path(name, product, framework)


def load_tool(relative: str):
    """Import a migrated tool under its stable, unique package namespace."""
    name = _relative(relative)
    migrated = _source_map(test_root()).get(name)
    if migrated is None or not migrated.endswith(".py"):
        raise ContextError("tool must name a Framework-owned Python source")
    qualified = (
        migrated.removeprefix("connector_suite/")
        if migrated.startswith(
            (
                "connector_suite/modsecurity_connector_ci/",
                "connector_suite/modsecurity_connector_tests/",
            )
        )
        else migrated
    )
    package = qualified.removesuffix(".py").replace("/", ".")
    return importlib.import_module(package)


def _resolve_legacy_source(selected: Path) -> Path:
    """Map an absent legacy absolute ID without searching unrelated owners."""
    # Legacy absolute source IDs are resolved by the same reviewed ownership
    # map as inventory bindings. Never search ancestors or arbitrary modules.
    if selected.is_absolute() and not selected.exists() and not selected.is_symlink():
        product = connector_root()
        if selected.is_relative_to(product) and not selected.is_relative_to(
            test_root()
        ):
            mapped = source_path(selected.relative_to(product).as_posix(), root=product)
            if mapped.is_relative_to(test_root()):
                selected = mapped
    return selected


def _source_module_path(selected: Path, framework: Path) -> Path:
    """Choose the owned package path with the existing namespace precedence."""
    suite = framework / "connector_suite"
    if selected.is_relative_to(suite):
        relative = selected.relative_to(suite)
        if relative.parts[0] not in {
            "modsecurity_connector_tests",
            "modsecurity_connector_ci",
        }:
            relative = Path("connector_suite") / relative
    elif selected.is_relative_to(framework):
        relative = selected.relative_to(framework)
        if relative.parts[:2] == ("tests", "runners"):
            relative = Path("modsecurity_test_framework/runners") / Path(
                *relative.parts[2:]
            )
        elif relative.parts[:2] == ("tests", "normalizers"):
            relative = Path("modsecurity_test_framework/normalizers") / Path(
                *relative.parts[2:]
            )
        elif relative.parts[:2] == ("ci", "lib"):
            relative = Path("modsecurity_test_framework/support") / Path(
                *relative.parts[2:]
            )
    else:
        relative = Path(
            "modsecurity_test_framework/product_sources"
        ) / selected.relative_to(connector_root())
    return relative


def _import_source_module(name: str, selected: Path, fresh: bool):
    """Verify namespace and origin before import, then verify the result."""
    if name.startswith("modsecurity_test_framework.product_sources."):
        namespace = importlib.import_module(
            "modsecurity_test_framework.product_sources"
        )
        if tuple(namespace.__path__) != (str(connector_root()),):
            raise ContextError("product namespace belongs to another explicit checkout")
    specification = importlib.util.find_spec(name)
    if (
        specification is None
        or specification.origin is None
        or Path(specification.origin).resolve(strict=True) != selected
    ):
        raise ContextError("Python module origin differs before source execution")
    module = importlib.import_module(name)
    if Path(module.__file__).resolve(strict=True) != selected:
        raise ContextError("Python module source collides with the selected source")
    return importlib.reload(module) if fresh else module


def load_source(path: str | Path, *, fresh: bool = True):
    """Load a reviewed source through normal, collision-checked package imports.

    Callers never select ad-hoc module aliases or modify Python's search path or
    module table. A fresh load uses Python's public reload operation.
    """
    selected = Path(path)
    selected = _resolve_legacy_source(selected)
    if not selected.is_absolute() or selected.is_symlink() or not selected.is_file():
        raise ContextError("tool source must be an absolute regular source file")
    framework = test_root()
    selected = selected.resolve(strict=True)
    relative = _source_module_path(selected, framework)
    if relative.suffix != ".py":
        raise ContextError("tool source must identify a Python module")
    name = ".".join(relative.with_suffix("").parts)
    return _import_source_module(name, selected, fresh)


@dataclass(frozen=True)
class ConnectorContext:
    connector: Path
    tests: Path
    revision: str
    profile: str
    output: Path

    @classmethod
    def from_environment(cls) -> "ConnectorContext":
        connector, tests = validate_checkout(), test_root()
        profile = os.environ.get("CONNECTOR_TEST_PROFILE", "")
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,127}", profile):
            raise ContextError("CONNECTOR_TEST_PROFILE is required explicitly")
        output = _directory(
            os.environ.get("CONNECTOR_TEST_OUTPUT_ROOT", ""),
            "CONNECTOR_TEST_OUTPUT_ROOT",
        )
        if any(output == root or root in output.parents for root in (connector, tests)):
            raise ContextError("test output must be external to both source checkouts")
        return cls(connector, tests, os.environ["CONNECTOR_REVISION"], profile, output)
