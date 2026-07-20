#!/usr/bin/env python3
"""Validate the Framework's security-data-flow normalizer contracts."""

from __future__ import annotations

import importlib.util
import json
import py_compile
import sys
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[3]
NORMALIZER_FILES = (
    "tests/normalizers/security_event_normalizer.py",
    "tests/normalizers/decision_jsonl_normalizer.py",
    "tests/normalizers/integrity_hash_chain_normalizer.py",
)
BODY_PAYLOAD_FIELDS = (
    "request_body",
    "response_body",
    "body_payload",
    "raw_body",
)
PAYLOAD_SAMPLE = '{"request_body":"x","response_body":"y","body_payload":"z","raw_body":"r"}\n'

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def load_module(path: Path) -> ModuleType:
    """Import one verified normalizer file using a path-stable module name."""

    specification = importlib.util.spec_from_file_location(path.stem, path)
    if specification is None or specification.loader is None:
        raise ImportError(f"cannot construct module specification for {path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def compile_and_load_normalizers() -> tuple[list[ModuleType], list[str]]:
    """Compile and import the complete fixed normalizer inventory."""

    modules: list[ModuleType] = []
    errors: list[str] = []
    for relative_path in NORMALIZER_FILES:
        path = ROOT / relative_path
        if not path.exists():
            errors.append(f"missing {relative_path}")
            continue
        try:
            py_compile.compile(str(path), doraise=True)
        except Exception as error:
            errors.append(f"{relative_path}: compile failed: {error}")
            continue
        try:
            modules.append(load_module(path))
        except Exception as error:
            errors.append(f"{relative_path}: import failed: {error}")
    return modules, errors


def self_test_errors(modules: list[ModuleType]) -> list[str]:
    """Run each normalizer's mandatory local contract check."""

    errors: list[str] = []
    for module in modules:
        self_test = getattr(module, "self_test", None)
        if not callable(self_test):
            errors.append(f"{module.__name__}: missing self_test")
            continue
        try:
            self_test()
        except Exception as error:
            errors.append(f"{module.__name__}: self_test failed: {error}")
    return errors


def body_payload_errors(security_event_normalizer: ModuleType) -> list[str]:
    """Require the event normalizer to reject every sensitive body field."""

    _, errors = security_event_normalizer.normalize_jsonl(PAYLOAD_SAMPLE)
    return [
        f"body payload field not detected: {field}"
        for field in BODY_PAYLOAD_FIELDS
        if not any(field in error for error in errors)
    ]


def integrity_hash_chain_errors(integrity_hash_chain: ModuleType) -> list[str]:
    """Prove that a minimal canonical hash-chain record rejects tampering."""

    record = {"sequence": 1, "previous_event_hash": "", "event": "start"}
    record["event_hash"] = integrity_hash_chain.compute_event_hash(record)
    tampered = json.dumps(record).replace("start", "tampered")
    if integrity_hash_chain.validate_hash_chain(tampered)[1]:
        return []
    return ["tamper data was not detected"]


def main() -> int:
    modules, errors = compile_and_load_normalizers()
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    security_event_normalizer, _, integrity_hash_chain = modules
    errors.extend(self_test_errors(modules))
    errors.extend(body_payload_errors(security_event_normalizer))
    errors.extend(integrity_hash_chain_errors(integrity_hash_chain))
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    print("OK: security-data-flow normalizers validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
