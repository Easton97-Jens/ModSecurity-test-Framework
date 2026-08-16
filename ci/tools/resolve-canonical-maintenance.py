#!/usr/bin/env python3
"""Resolve the shared common-version maintenance plan.

The command is read-only unless ``--apply-safe-updates`` is explicitly
selected with a caller-bound plan digest.  It has no GitHub client and cannot
create or mutate review issues.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any, Sequence


SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
MODULE_NAME = "framework_canonical_maintenance"


class CliError(ValueError):
    """A caller supplied an unsafe or inconsistent command line."""


def _load_orchestrator(root: Path) -> Any:
    path = _safe_path(
        root / "ci" / "tools" / "canonical_maintenance.py", root, "orchestrator"
    )
    spec = importlib.util.spec_from_file_location(MODULE_NAME, path)
    if spec is None or spec.loader is None:
        raise CliError("canonical maintenance orchestrator is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[MODULE_NAME] = module
    spec.loader.exec_module(module)
    return module


def _real_root(path: Path) -> Path:
    candidate = Path(os.path.abspath(path))
    try:
        details = candidate.lstat()
    except OSError as exc:
        raise CliError(f"maintenance root is unavailable: {candidate}") from exc
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
        raise CliError("maintenance root must be a real directory")
    return _safe_path(candidate, Path(candidate.anchor), "maintenance root")


def _safe_path(path: Path, anchor: Path, label: str) -> Path:
    """Reject symlinked ancestors while keeping missing output leaves valid."""

    absolute = Path(os.path.abspath(path))
    trusted_anchor = Path(os.path.abspath(anchor))
    try:
        absolute.relative_to(trusted_anchor)
    except ValueError as exc:
        raise CliError(f"{label} must remain below its approved root") from exc
    _validate_ancestors(absolute, trusted_anchor, label)
    return absolute


def _validate_ancestors(path: Path, anchor: Path, label: str) -> None:
    current = path
    while current != anchor:
        try:
            details = current.lstat()
        except FileNotFoundError:
            current = current.parent
            continue
        except OSError as exc:
            raise CliError(f"cannot inspect {label}: {current}") from exc
        if stat.S_ISLNK(details.st_mode):
            raise CliError(f"{label} contains a symlink path component: {current}")
        if current != path and not stat.S_ISDIR(details.st_mode):
            raise CliError(f"{label} contains a non-directory ancestor: {current}")
        current = current.parent


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _output_path(value: str, root: Path, *, label: str) -> Path | None:
    if value == "-":
        return None
    path = Path(value)
    if path.is_absolute():
        resolved = Path(os.path.abspath(path))
    else:
        resolved = Path(os.path.abspath(root / path))
    runner_temp = os.environ.get("RUNNER_TEMP")
    allowed_root = root if _is_within(resolved, root) else None
    if runner_temp:
        runner_root = Path(os.path.abspath(runner_temp))
        if _is_within(resolved, runner_root):
            allowed_root = runner_root
    if allowed_root is None:
        raise CliError(f"{label} must be inside the repository or RUNNER_TEMP")
    resolved = _safe_path(resolved, allowed_root, label)
    if resolved == allowed_root:
        raise CliError(f"{label} must name a file")
    try:
        details = resolved.lstat()
    except FileNotFoundError:
        details = None
    except OSError as exc:
        raise CliError(f"cannot inspect {label}: {resolved}") from exc
    if details is not None and (
        stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode)
    ):
        raise CliError(f"{label} must not be a symlink or special file")
    return resolved


def _atomic_write(path: Path, data: bytes) -> None:
    """Write a validated output without following a destination symlink."""

    mode = 0o600
    _safe_path(path.parent, Path(path.parent.anchor), "atomic output parent")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
        raise CliError(f"atomic output failed for {path}") from exc


def _load_plan(path: Path) -> dict[str, Any]:
    try:
        details = path.lstat()
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
            raise CliError("maintenance plan must be a regular non-symlink file")
        data = path.read_bytes()
        value = json.loads(data.decode("utf-8"))
    except CliError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CliError(f"cannot read maintenance plan: {path}") from exc
    if not isinstance(value, dict):
        raise CliError("maintenance plan must be a JSON object")
    return value


def _json_bytes(plan: dict[str, Any]) -> bytes:
    return (
        json.dumps(plan, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("utf-8")


def _validate_timeout(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.timeout <= 0 or args.timeout > 300:
        parser.error("--timeout must be greater than 0 and at most 300 seconds")


def _validate_apply_options(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> None:
    if args.apply_safe_updates and not args.plan:
        parser.error("--apply-safe-updates requires --plan PATH")
    if args.apply_safe_updates and args.plan == "-":
        parser.error("--apply-safe-updates requires a plan file, not stdout")
    if args.apply_safe_updates and args.markdown is not None:
        parser.error("--apply-safe-updates cannot be combined with --markdown")
    if args.apply_safe_updates and args.check:
        parser.error("--apply-safe-updates cannot be combined with --check")
    if args.apply_safe_updates and args.component:
        parser.error("--apply-safe-updates cannot be combined with --component")


def _validate_digest(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if (
        args.expected_plan_sha256 is not None
        and SHA256_RE.fullmatch(args.expected_plan_sha256) is None
    ):
        parser.error("--expected-plan-sha256 must be a lowercase SHA-256")
    if args.apply_safe_updates and args.expected_plan_sha256 is None:
        parser.error("--apply-safe-updates requires --expected-plan-sha256")


def _validate_output_options(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> None:
    if args.markdown is not None and args.plan == "-":
        parser.error("--markdown cannot share --plan stdout")


def _validate_args(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> argparse.Namespace:
    _validate_timeout(args, parser)
    _validate_apply_options(args, parser)
    _validate_digest(args, parser)
    _validate_output_options(args, parser)
    return args


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--component", action="append", default=[], metavar="NAME")
    parser.add_argument(
        "--check",
        action="store_true",
        help="resolve and validate without writing source files",
    )
    parser.add_argument(
        "--plan", metavar="PATH", help="JSON plan output path, or '-' for stdout"
    )
    parser.add_argument(
        "--markdown",
        nargs="?",
        const="-",
        metavar="PATH",
        help="render Markdown to PATH, or stdout",
    )
    parser.add_argument(
        "--apply-safe-updates",
        action="store_true",
        help="apply only the caller-bound safe updates in --plan",
    )
    parser.add_argument("--expected-plan-sha256", metavar="SHA256")
    return _validate_args(parser.parse_args(argv), parser)


def _write_outputs(args: argparse.Namespace, root: Path, plan: dict[str, Any]) -> None:
    plan_path = (
        _output_path(args.plan, root, label="--plan output") if args.plan else None
    )
    markdown_path = (
        _output_path(args.markdown, root, label="--markdown output")
        if args.markdown is not None and args.markdown != "-"
        else None
    )
    if args.plan:
        data = _json_bytes(plan)
        if plan_path is None:
            sys.stdout.buffer.write(data)
        else:
            _atomic_write(plan_path, data)
    elif args.markdown is None:
        sys.stdout.buffer.write(_json_bytes(plan))
    if args.markdown is not None:
        orchestrator = _load_orchestrator(root)
        markdown = orchestrator.render_plan_markdown(plan).encode("utf-8")
        if markdown_path is None:
            sys.stdout.buffer.write(markdown)
        else:
            _atomic_write(markdown_path, markdown)


def run(args: argparse.Namespace) -> int:
    root = _real_root(args.root)
    orchestrator = _load_orchestrator(root)
    plan_path = (
        _output_path(args.plan, root, label="--plan output") if args.plan else None
    )
    if args.apply_safe_updates:
        if plan_path is None:
            raise CliError("--apply-safe-updates requires a regular plan file")
        plan = _load_plan(plan_path)
        changed = orchestrator.apply_safe_updates(
            root, plan, expected_plan_sha256=args.expected_plan_sha256
        )
        print(json.dumps({"applied": changed}, sort_keys=True))
        return 0

    plan = orchestrator.build_plan(
        root,
        components=tuple(args.component),
        timeout=args.timeout,
    )
    if (
        args.expected_plan_sha256 is not None
        and plan.get("plan_sha256") != args.expected_plan_sha256
    ):
        raise CliError(
            "resolved maintenance plan does not match the caller-bound SHA-256"
        )
    _write_outputs(args, root, plan)
    return 0 if plan.get("maintenance_outcome") != "fatal" else 2


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return run(parse_args(argv))
    except (OSError, ValueError) as exc:
        print(f"resolve-canonical-maintenance: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
