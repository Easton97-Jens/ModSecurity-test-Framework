"""Static Parent Makefile contracts for Phase-4 evidence promotion gates."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import re
from pathlib import Path
import unittest


ROOT = connector_root()


class FullLifecycleGateWiringTest(unittest.TestCase):
    def target_body(self, name: str) -> str:
        makefile = (source_path('Makefile', root=ROOT)).read_text(encoding="utf-8")
        match = re.search(
            rf"^{re.escape(name)}:.*?(?=^\S|\Z)",
            makefile,
            flags=re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match, f"missing Makefile target: {name}")
        return match.group(0)

    def test_strict_phase4_targets_invoke_parent_identity_checks(self) -> None:
        makefile = (source_path('Makefile', root=ROOT)).read_text(encoding="utf-8")
        self.assertIn("define RUN_PARENT_FULL_LIFECYCLE_EVIDENCE_CHECK", makefile)
        macro = makefile.split(
            "define RUN_STRICT_FULL_LIFECYCLE_EVIDENCE_CHECK\n", 1
        )[1].split("\nendef", 1)[0]
        self.assertIn(
            "$(call RUN_PARENT_FULL_LIFECYCLE_EVIDENCE_CHECK,profile)", macro
        )
        expected = {
            "check-first-byte-before-response-end": "first-byte",
            "check-no-full-response-buffering": "no-full-buffer",
            "check-full-lifecycle-promotion": "promotion",
        }
        for target, parent_check in expected.items():
            with self.subTest(target=target):
                body = self.target_body(target)
                self.assertIn(
                    f"$(call RUN_PARENT_FULL_LIFECYCLE_EVIDENCE_CHECK,{parent_check})",
                    body,
                )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
