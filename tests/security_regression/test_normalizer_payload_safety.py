"""Regression coverage for fail-closed body-payload normalizer output."""

from __future__ import annotations

import json
from pathlib import Path
import os
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
EVENT_NORMALIZER = ROOT / "tests" / "normalizers" / "security_event_normalizer.py"
DECISION_NORMALIZER = ROOT / "tests" / "normalizers" / "decision_jsonl_normalizer.py"
HASH_CHAIN_NORMALIZER = ROOT / "tests" / "normalizers" / "integrity_hash_chain_normalizer.py"


class NormalizerPayloadSafetyTests(unittest.TestCase):
    def run_normalizer(self, path: Path, payload: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(path)],
            cwd=ROOT,
            input=payload,
            text=True,
            capture_output=True,
            env={
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": str(ROOT),
            },
            check=False,
        )

    def test_event_and_decision_normalizers_do_not_emit_rejected_body_fields(self) -> None:
        payloads = (
            '{"request_body":"fixture-body","decision":"block"}\n',
            '{"details":{"RequestBody":"fixture-body"},"decision":"block"}\n',
            '{"response-body":"fixture-body","decision":"block"}\n',
        )
        for normalizer in (EVENT_NORMALIZER, DECISION_NORMALIZER):
            for payload in payloads:
                with self.subTest(normalizer=normalizer.name, payload=payload):
                    result = self.run_normalizer(normalizer, payload)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertNotIn("fixture-body", result.stderr)
                    self.assertIn("body payload field is not allowed", result.stderr)

    def test_hash_chain_normalizer_rejects_body_fields_without_output(self) -> None:
        from tests.normalizers import integrity_hash_chain_normalizer as hash_chain

        record = {
            "sequence": 1,
            "previous_event_hash": "",
            "event": "fixture",
            "ResponseBody": "fixture-body",
        }
        record["event_hash"] = hash_chain.compute_event_hash(record)
        result = self.run_normalizer(HASH_CHAIN_NORMALIZER, json.dumps(record) + "\n")

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertNotIn("fixture-body", result.stderr)
        self.assertIn("body payload field is not allowed", result.stderr)

    def test_valid_event_remains_normalizable(self) -> None:
        result = self.run_normalizer(
            EVENT_NORMALIZER,
            '{"event":"fixture","timestamp":"2026-08-20T00:00:00Z"}\n',
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("<timestamp>", result.stdout)


if __name__ == "__main__":
    unittest.main()
