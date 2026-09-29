"""Constrain MRTS definition globals at the Framework-owned entry point.

This is a wrapper mitigation for intake B03, not a patch to the MRTS submodule
or a sandbox for operator-selected generator code. The caller still owns the
output-root and trusted-generator contracts.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import yaml

# Source contract: MRTS README "Global keywords" and RuleGenerator at the
# gitlink recorded by this Framework. Keep the documented historical spelling
# and implemented spelling; do not silently translate either one.
ALLOWED_GLOBAL_KEYS = frozenset(
    {
        "version",
        "baseid",
        "default_operator",
        "templates",
        "default_test_phase_methods",
        "default_tests_phase_methods",
        "default_constants",
    }
)
BLOCKED = 77


class DefinitionRejected(ValueError):
    """A definition cannot cross the Framework-to-MRTS boundary."""


def load_definition(path: Path, position: int) -> dict:
    """Parse once; never derive the configuration schema from object attributes."""
    try:
        with path.open("r", encoding="utf-8") as stream:
            document = yaml.safe_load(stream)
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        # Do not include YAML contents or a user-controlled path in diagnostics.
        raise DefinitionRejected(
            f"definition {position}: unreadable or invalid YAML"
        ) from error
    if not isinstance(document, dict):
        raise DefinitionRejected(f"definition {position}: expected a mapping")
    global_config = document.get("global")
    if global_config is None:
        return document
    if not isinstance(global_config, dict):
        # In MRTS, constant substitution precedes loading global settings.
        # Disallow scalar whole-global substitution at this earlier boundary.
        raise DefinitionRejected(f"definition {position}: global must be a mapping")
    if any(
        not isinstance(key, str) or key not in ALLOWED_GLOBAL_KEYS
        for key in global_config
    ):
        raise DefinitionRejected(f"definition {position}: unsupported global setting")
    return document


def run_guarded(
    generator: Path,
    definition_paths: list[Path],
    rules_out: Path,
    tests_out: Path,
    snapshot_root: Path,
) -> int:
    """Run the trusted generator only on private snapshots of validated data."""
    if not definition_paths:
        raise DefinitionRejected("no definitions supplied")
    # Match MRTS's lexical flist.sort(), including cross-file global state.
    definitions = [
        load_definition(path, index)
        for index, path in enumerate(sorted(definition_paths, key=str), start=1)
    ]
    if not generator.is_file():
        raise DefinitionRejected("MRTS generator is unavailable")
    if not all(path.is_dir() for path in (rules_out, tests_out, snapshot_root)):
        raise DefinitionRejected("expected existing output and snapshot directories")

    # These are path operands, never interpreter or generator options. Existing
    # relative names (including leading '-') remain usable, but only their
    # absolute resolved paths cross the subprocess argument boundary. Resolving
    # the snapshot root also makes every generated -r operand absolute.
    generator = generator.resolve(strict=True)
    rules_out = rules_out.resolve(strict=True)
    tests_out = tests_out.resolve(strict=True)
    snapshot_root = snapshot_root.resolve(strict=True)

    with tempfile.TemporaryDirectory(
        prefix="mrts-validated-", dir=snapshot_root
    ) as temporary:
        directory = Path(temporary)
        os.chmod(directory, 0o700)
        width = max(6, len(str(len(definitions))))
        snapshots = []
        for index, document in enumerate(definitions):
            snapshot = directory / f"{index:0{width}d}.yaml"
            descriptor = os.open(
                snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                yaml.safe_dump(document, stream, sort_keys=False, allow_unicode=True)
            snapshots.append(str(snapshot))
        # The original files are never reopened by the generator. This closes
        # validation/use replacement of definition data, not same-UID process
        # isolation or arbitrary operator-selected generator behavior. End the
        # interpreter's option parsing before the selected script as well.
        completed = subprocess.run(
            [
                sys.executable,
                "--",
                str(generator),
                "-r",
                *snapshots,
                "-e",
                str(rules_out),
                "-t",
                str(tests_out),
            ],
            check=False,
        )
        return completed.returncode if completed.returncode >= 0 else 128 - completed.returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generator", type=Path, required=True)
    parser.add_argument("--snapshot-root", type=Path, required=True)
    parser.add_argument("--rules-out", type=Path, required=True)
    parser.add_argument("--tests-out", type=Path, required=True)
    parser.add_argument("definitions", type=Path, nargs="+")
    args = parser.parse_args(argv)
    try:
        return run_guarded(
            args.generator,
            args.definitions,
            args.rules_out,
            args.tests_out,
            args.snapshot_root,
        )
    except DefinitionRejected as error:
        print(f"BLOCKED: {error}", file=sys.stderr)
        return BLOCKED
    except (OSError, UnicodeError, yaml.YAMLError):
        print("BLOCKED: unable to prepare or execute validated MRTS input", file=sys.stderr)
        return BLOCKED


if __name__ == "__main__":
    raise SystemExit(main())
