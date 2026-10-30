#!/usr/bin/env python3
"""Resolve isolated runtime paths for one connector and canonical run.

The resolver is intentionally side-effect free.  Callers provide five base
directories and receive paths scoped to exactly one validated connector and
run identifier.  The component cache is the sole shared path; it is exposed
below ``<cache-root>/shared`` so callers cannot accidentally place mutable
connector artifacts beside shared component entries.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

# Keep lifecycle-base validation aligned with the Parent runtime-path policy.


from modsecurity_connector_ci.lib.runtime_path_utils import is_safe_runtime_root


CONNECTORS = frozenset(("apache", "nginx", "haproxy", "envoy", "traefik", "lighttpd"))
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
class RuntimePathError(ValueError):
    """The requested connector/runtime path layout is unsafe or ambiguous."""


def _raw_string(value: str | Path | None, label: str) -> str:
    if value is None:
        raise RuntimePathError(f"{label} is required")
    text = str(value)
    if not text or not text.strip():
        raise RuntimePathError(f"{label} must not be empty")
    if text != text.strip():
        raise RuntimePathError(f"{label} must not include leading or trailing whitespace")
    if "\x00" in text:
        raise RuntimePathError(f"{label} must not contain a NUL byte")
    return text


def validate_connector(connector: str) -> str:
    value = _raw_string(connector, "connector")
    if value not in CONNECTORS:
        choices = ", ".join(sorted(CONNECTORS))
        raise RuntimePathError(f"invalid connector {value!r}; expected one of: {choices}")
    return value


def validate_run_id(run_id: str) -> str:
    value = _raw_string(run_id, "run_id")
    if not RUN_ID_PATTERN.fullmatch(value) or ".." in value:
        raise RuntimePathError(
            "invalid run_id; use 1-128 ASCII letters, digits, dots, underscores, or hyphens "
            "without traversal segments"
        )
    return value


def _has_traversal_component(path: Path) -> bool:
    return any(part == ".." for part in path.parts)


def normalize_base(
    value: str | Path,
    *,
    label: str,
    cwd: Path | None = None,
) -> Path:
    """Resolve an absolute or safe relative base without creating it."""

    raw = _raw_string(value, label)
    # Backslashes are not path separators on this platform, but rejecting them
    # avoids accepting a traversal-looking cross-platform path as a filename.
    if "\\" in raw:
        raise RuntimePathError(f"{label} must not contain a backslash")
    supplied = Path(raw)
    if _has_traversal_component(supplied):
        raise RuntimePathError(f"{label} must not contain a traversal component")

    base_cwd = (cwd or Path.cwd()).resolve(strict=False)
    if not base_cwd.is_absolute():
        raise RuntimePathError("resolver working directory must be absolute")
    resolved = (supplied if supplied.is_absolute() else base_cwd / supplied).resolve(strict=False)
    return resolved


def normalize_invocation_root(value: str | Path, *, cwd: Path | None = None) -> Path:
    """Return one narrow external root that owns all writable lifecycle bases."""
    raw = _raw_string(value, "invocation_root")
    if not Path(raw).is_absolute():
        raise RuntimePathError("invocation_root must be absolute")
    root = normalize_base(raw, label="invocation_root", cwd=cwd)
    if not is_safe_runtime_root(root):
        raise RuntimePathError(f"invocation_root is unsafe for runtime writes: {root}")
    return root


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def roots_overlap(first: Path, second: Path) -> bool:
    """Return whether two normalized roots are equal or one contains the other."""

    return first == second or _is_within(first, second) or _is_within(second, first)


def _connector_tokens(path: Path) -> set[str]:
    tokens: set[str] = set()
    for part in path.parts:
        tokens.update(token.lower() for token in re.split(r"[^A-Za-z0-9]+", part) if token)
    return tokens


def reject_foreign_connector_path(path: Path, connector: str, label: str) -> None:
    foreign = sorted((_connector_tokens(path) & CONNECTORS) - {connector})
    if foreign:
        raise RuntimePathError(
            f"{label} contains foreign connector path token(s): {', '.join(foreign)}"
        )


def _require_distinct_bases(roots: Mapping[str, Path]) -> None:
    items = tuple(roots.items())
    for index, (left_name, left) in enumerate(items):
        for right_name, right in items[index + 1 :]:
            if roots_overlap(left, right):
                raise RuntimePathError(
                    f"root overlap: {left_name}={left} overlaps {right_name}={right}"
                )


@dataclass(frozen=True)
class RuntimePaths:
    """Resolved bases and their isolated connector/run descendants."""

    connector: str
    run_id: str
    invocation_root: Path
    evidence_base: Path
    build_base: Path
    run_base: Path
    log_base: Path
    cache_base: Path
    evidence_run_root: Path
    connector_build_root: Path
    connector_run_root: Path
    connector_log_root: Path
    shared_component_cache: Path

    def as_json(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "connector": self.connector,
            "run_id": self.run_id,
            "invocation_root": str(self.invocation_root),
            "bases": {
                "evidence_root": str(self.evidence_base),
                "build_root": str(self.build_base),
                "run_root": str(self.run_base),
                "log_root": str(self.log_base),
                "cache_root": str(self.cache_base),
            },
            "evidence_root": str(self.evidence_run_root),
            "build_root": str(self.connector_build_root),
            "run_root": str(self.connector_run_root),
            "log_root": str(self.connector_log_root),
            "cache_root": str(self.cache_base),
            "evidence_run_root": str(self.evidence_run_root),
            "connector_build_root": str(self.connector_build_root),
            "connector_run_root": str(self.connector_run_root),
            "connector_log_root": str(self.connector_log_root),
            "shared_component_cache": str(self.shared_component_cache),
            "shell_assignments": self.shell_values(),
        }

    def shell_values(self) -> dict[str, str]:
        return {
            "EVIDENCE_RUN_ROOT": str(self.evidence_run_root),
            "CONNECTOR_BUILD_ROOT": str(self.connector_build_root),
            "CONNECTOR_RUN_ROOT": str(self.connector_run_root),
            "CONNECTOR_LOG_ROOT": str(self.connector_log_root),
            "SHARED_COMPONENT_CACHE": str(self.shared_component_cache),
        }

    def shell_assignments(self) -> str:
        return "\n".join(
            f"export {name}={shlex.quote(value)}" for name, value in self.shell_values().items()
        ) + "\n"


def resolve_runtime_paths(
    *,
    connector: str,
    run_id: str,
    invocation_root: str | Path,
    evidence_root: str | Path,
    build_root: str | Path,
    run_root: str | Path,
    log_root: str | Path,
    cache_root: str | Path,
    cwd: Path | None = None,
) -> RuntimePaths:
    """Resolve and validate all paths required by one connector lifecycle run."""

    selected_connector = validate_connector(connector)
    selected_run_id = validate_run_id(run_id)
    selected_invocation_root = normalize_invocation_root(invocation_root, cwd=cwd)
    bases = {
        "evidence_root": normalize_base(evidence_root, label="evidence_root", cwd=cwd),
        "build_root": normalize_base(build_root, label="build_root", cwd=cwd),
        "run_root": normalize_base(run_root, label="run_root", cwd=cwd),
        "log_root": normalize_base(log_root, label="log_root", cwd=cwd),
        "cache_root": normalize_base(cache_root, label="cache_root", cwd=cwd),
    }
    for label, path in bases.items():
        if not _is_within(path, selected_invocation_root):
            raise RuntimePathError(
                f"{label} must remain inside invocation_root={selected_invocation_root}: {path}"
            )
        reject_foreign_connector_path(path, selected_connector, label)
    _require_distinct_bases(bases)

    evidence_run_root = bases["evidence_root"] / selected_connector / selected_run_id
    connector_build_root = bases["build_root"] / selected_connector / selected_run_id
    connector_run_root = bases["run_root"] / selected_connector / selected_run_id
    connector_log_root = bases["log_root"] / selected_connector / selected_run_id
    shared_component_cache = bases["cache_root"] / "shared"

    resolved_outputs = {
        "evidence_run_root": evidence_run_root,
        "connector_build_root": connector_build_root,
        "connector_run_root": connector_run_root,
        "connector_log_root": connector_log_root,
        "shared_component_cache": shared_component_cache,
    }
    _require_distinct_bases(resolved_outputs)
    for label, path in resolved_outputs.items():
        if not path.is_absolute():
            raise RuntimePathError(f"{label} did not resolve to an absolute path")

    return RuntimePaths(
        connector=selected_connector,
        run_id=selected_run_id,
        invocation_root=selected_invocation_root,
        evidence_base=bases["evidence_root"],
        build_base=bases["build_root"],
        run_base=bases["run_root"],
        log_base=bases["log_root"],
        cache_base=bases["cache_root"],
        evidence_run_root=evidence_run_root,
        connector_build_root=connector_build_root,
        connector_run_root=connector_run_root,
        connector_log_root=connector_log_root,
        shared_component_cache=shared_component_cache,
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connector", required=True, choices=sorted(CONNECTORS))
    parser.add_argument("--run-id", required=True)
    parser.add_argument(
        "--invocation-root",
        required=True,
        help="narrow external root that owns every writable lifecycle base",
    )
    parser.add_argument("--evidence-root", required=True, help="base directory for canonical evidence")
    parser.add_argument("--build-root", required=True, help="base directory for connector build artifacts")
    parser.add_argument("--run-root", required=True, help="base directory for connector host runs")
    parser.add_argument("--log-root", required=True, help="base directory for connector logs")
    parser.add_argument("--cache-root", required=True, help="base directory for the shared component cache")
    parser.add_argument(
        "--format",
        choices=("json", "shell"),
        default="json",
        help="write JSON metadata or shell export assignments (default: json)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        paths = resolve_runtime_paths(
            connector=args.connector,
            run_id=args.run_id,
            invocation_root=args.invocation_root,
            evidence_root=args.evidence_root,
            build_root=args.build_root,
            run_root=args.run_root,
            log_root=args.log_root,
            cache_root=args.cache_root,
        )
    except RuntimePathError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2

    if args.format == "shell":
        sys.stdout.write(paths.shell_assignments())
    else:
        json.dump(paths.as_json(), sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
