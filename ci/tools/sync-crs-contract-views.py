#!/usr/bin/env python3
"""Synchronize With-CRS/No-MRTS contract views from ``common.sh``.

The tool performs no shell execution and no network access.  It updates only
the explicitly listed contract views, atomically and idempotently.
"""

from __future__ import annotations

import argparse
from functools import partial
import os
from pathlib import Path
import re
import tempfile

from crs_contract_pins import CrsPins, load_crs_pins, require_regular_file_within_root


ROOT = Path(__file__).resolve().parents[2]
TARGETS = (
    ROOT
    / "tests/schemas/five-connectors-with-crs-no-mrts/normalized-event.schema.json",
    ROOT / "tests/schemas/five-connectors-with-crs-no-mrts/manifest.schema.json",
    ROOT / "tests/schemas/five-connectors-with-crs-no-mrts/receipt.schema.json",
    ROOT / "tests/cases/security/crs/crs_sqli_anomaly_block.yaml",
)
_JSON_KEYS = (
    "crs_repository",
    "crs_release_tag",
    "crs_commit",
    "crs_rule_file_sha256",
)
_YAML_KEYS = ("repository", "release_tag", "commit", "rule_file_sha256")
_JSON_VIEW_KEYS = {
    "normalized-event.schema.json": (*_JSON_KEYS, "crs_git_ref"),
    "manifest.schema.json": _JSON_KEYS,
    "receipt.schema.json": ("crs_commit",),
}


def _replace_json_value(match: re.Match[str], *, value: str) -> str:
    return f"{match.group('prefix')}{value!r}".replace("'", '"')


def _replace_json(text: str, pins: CrsPins, path: Path) -> str:
    values = {
        "crs_repository": pins.repository,
        "crs_release_tag": pins.release_tag,
        "crs_commit": pins.commit,
        "crs_rule_file_sha256": pins.rule_file_sha256,
        "crs_git_ref": pins.release_tag,
    }
    try:
        keys = _JSON_VIEW_KEYS[path.name]
    except KeyError as error:
        raise ValueError(f"unrecognized generated JSON view: {path}") from error
    for key in keys:
        pattern = re.compile(rf'(?P<prefix>"{key}"\s*:\s*\{{\s*"const"\s*:\s*)"[^"]*"')
        text, count = pattern.subn(
            partial(_replace_json_value, value=values[key]),
            text,
        )
        if count != 1:
            raise ValueError(
                f"expected one generated {key} view in {path}, found {count}"
            )
    return text


def _replace_yaml(text: str, pins: CrsPins, path: Path) -> str:
    values = {
        "repository": pins.repository,
        "release_tag": pins.release_tag,
        "commit": pins.commit,
        "rule_file_sha256": pins.rule_file_sha256,
    }
    start = text.find("  provenance:\n")
    if start < 0:
        raise ValueError(f"missing provenance view in {path}")
    end = text.find("\n  evidence:\n", start)
    if end < 0:
        raise ValueError(f"missing evidence boundary in {path}")
    prefix, block, suffix = text[:start], text[start:end], text[end:]
    for key in _YAML_KEYS:
        pattern = re.compile(rf"^(\s+{key}:\s*)[^\n]*$", re.MULTILINE)
        block, count = pattern.subn(rf"\g<1>{values[key]}", block)
        if count != 1:
            raise ValueError(
                f"expected one generated {key} view in {path}, found {count}"
            )
    return prefix + block + suffix


def _render(path: Path, pins: CrsPins, root: Path) -> str:
    path = require_regular_file_within_root(path, root)
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return _replace_json(text, pins, path)
    return _replace_yaml(text, pins, path)


def _atomic_write(path: Path, text: str, root: Path) -> None:
    path = require_regular_file_within_root(path, root)
    if path.read_text(encoding="utf-8") == text:
        return
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as handle:
        temporary = Path(handle.name)
        handle.write(text)
        handle.flush()
    os.chmod(temporary, path.stat().st_mode & 0o777)
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    if args.check == args.write:
        parser.error("select exactly one of --check or --write")
    root = Path(os.path.abspath(args.root))
    common = root / "ci/lib/common.sh"
    pins = load_crs_pins(common, root=root)
    targets = tuple(root / target.relative_to(ROOT) for target in TARGETS)
    changed = []
    for target in targets:
        validated_target = require_regular_file_within_root(target, root)
        rendered = _render(validated_target, pins, root)
        if rendered != validated_target.read_text(encoding="utf-8"):
            changed.append(validated_target)
            if args.write:
                _atomic_write(validated_target, rendered, root)
    if changed and args.check:
        for target in changed:
            print(f"OUT OF DATE: {target.relative_to(root)}")
        return 1
    print(f"CRS contract views: {'UPDATED' if args.write and changed else 'PASS'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
