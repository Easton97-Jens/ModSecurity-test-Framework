#!/usr/bin/env python3
"""Smoke-check the MRTS importer without MRTS or connector runtime."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


FRAMEWORK_ROOT = Path(__file__).resolve().parents[3]
RUNNER_DIR = FRAMEWORK_ROOT / "tests" / "runners"
if str(RUNNER_DIR) not in sys.path:
    sys.path.insert(0, str(RUNNER_DIR))

from runner_core import load_case


def run_import(output_dir: Path, classifications_file: Path | None = None) -> subprocess.CompletedProcess[str]:
    fixture_root = FRAMEWORK_ROOT / "tests" / "fixtures" / "mrts"
    command = [
        sys.executable,
        str(FRAMEWORK_ROOT / "ci" / "provisioning" / "import-mrts-cases.py"),
        "--framework-root",
        str(FRAMEWORK_ROOT),
        "--mrts-ftw-dir",
        str(fixture_root / "ftw"),
        "--mrts-rules-dir",
        str(fixture_root / "rules"),
        "--output-dir",
        str(output_dir),
    ]
    if classifications_file is not None:
        command.extend(["--classifications-file", str(classifications_file)])
    return subprocess.run(
        command,
        check=True,
        text=True,
        capture_output=True,
    )


def assert_case(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="mrts-importer-") as tmp:
        output_dir = Path(tmp) / "cases"
        run_import(output_dir)
        paths = sorted(output_dir.glob("*.yaml"))
        cases = {load_case(path)["name"]: load_case(path) for path in paths}

        assert_case(len(cases) == 4, f"expected 4 cases, got {len(cases)}")
        assert_case("mrts_mrts_fixture_duplicate" in cases, "missing deterministic duplicate base name")
        assert_case("mrts_mrts_fixture_duplicate_2" in cases, "missing duplicate suffix")

        args_case = cases["mrts_mrts_fixture_duplicate"]
        assert_case(args_case["status"] == "active", "ARGS fixture should be active")
        assert_case(args_case["metadata"]["phase"] == 2, "ARGS phase should be 2")
        assert_case("ARGS" in args_case["metadata"]["variables"], "ARGS variable missing")
        assert_case(args_case["metadata"]["topic"] == "Operators", "t:none operator rule should classify as operators")
        assert_case(args_case["request"]["path"] == "/?q=attack", "GET data should become query string")
        assert_case(args_case["rules"].strip() == "SecRuleEngine On", "case should not duplicate generated MRTS rules")

        header_case = cases["mrts_mrts_fixture_duplicate_2"]
        assert_case(header_case["status"] == "active", "header fixture should be active")
        assert_case(header_case["metadata"]["phase"] == 1, "header phase should be 1")
        assert_case("REQUEST_HEADERS" in header_case["metadata"]["variables"], "REQUEST_HEADERS missing")

        response_case = cases["mrts_mrts_fixture_response_body"]
        assert_case(response_case["status"] == "pending", "RESPONSE_BODY fixture should stay pending")
        assert_case(response_case.get("reason") == "MRTS classification incomplete", "missing pending reason")
        assert_case("RESPONSE_BODY" in response_case["metadata"]["variables"], "RESPONSE_BODY missing")

        fallback_case = cases["mrts_mrts_fixture_unclassified"]
        assert_case(fallback_case["status"] == "pending", "unclassified fixture should be pending")
        assert_case(fallback_case["metadata"]["topic"] == "MRTS generated / unclassified", "fallback topic mismatch")

        bad_overlay = Path(tmp) / "bad-classifications.yaml"
        bad_overlay.write_text(
            "\n".join(
                [
                    "version: 1",
                    "cases:",
                    "  mrts_mrts_fixture_duplicate:",
                    "    expected_status: 200",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        try:
            run_import(Path(tmp) / "bad-cases", bad_overlay)
        except subprocess.CalledProcessError as exc:
            assert_case("expected_status" in (exc.stderr or ""), "forbidden overlay key error should mention expected_status")
        else:
            raise AssertionError("forbidden overlay key should fail import")

        print(json.dumps({"status": "pass", "imported": len(cases)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
