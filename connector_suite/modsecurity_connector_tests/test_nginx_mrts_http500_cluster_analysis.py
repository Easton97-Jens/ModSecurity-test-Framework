from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = connector_root()
GENERATOR_PATH = source_path('ci/evidence/reports/generate-nginx-mrts-http500-cluster-analysis.py', root=ROOT)
GENERATOR = load_source(GENERATOR_PATH)


class NginxMrtsHttp500ClusterAnalysisTest(unittest.TestCase):
    def test_permission_patterns_keep_index_directory_and_failed_cases_distinct(self) -> None:
        permission_line = (
            f'2026/06/16 12:00:00 [crit] open() "/srv/{GENERATOR.DOCROOT_INDEX_PATH}" '
            f"failed (13: {GENERATOR.PERMISSION_DENIED_TEXT})"
        )

        self.assertEqual(GENERATOR.DOCROOT_INDEX_PATH, "htdocs/index.html")
        self.assertEqual(GENERATOR.PERMISSION_DENIED_TEXT, "Permission denied")
        self.assertFalse(Path(GENERATOR.DOCROOT_INDEX_PATH).is_absolute())
        self.assertEqual(Path(GENERATOR.DOCROOT_INDEX_PATH).parts, ("htdocs", "index.html"))
        self.assertEqual(
            GENERATOR.patterns_for_error_line(permission_line),
            ["docroot_index_permission_denied", "nginx_crit_permission_denied"],
        )
        self.assertEqual(
            GENERATOR.patterns_for_error_line(
                f'open() "/srv/htdocs/other.html" failed (13: {GENERATOR.PERMISSION_DENIED_TEXT})'
            ),
            ["docroot_directory_permission_denied"],
        )
        self.assertEqual(
            GENERATOR.patterns_for_error_line(
                f'open() "/srv/{GENERATOR.DOCROOT_INDEX_PATH}" failed (2: No such file)'
            ),
            ["generic_failed"],
        )

    def test_representative_excerpt_keeps_date_filter_selection_and_truncation(self) -> None:
        matching_permission_line = (
            f'2026/06/16 12:00:01 [crit] open() "/srv/{GENERATOR.DOCROOT_INDEX_PATH}" '
            f"failed (13: {GENERATOR.PERMISSION_DENIED_TEXT}) "
            + ("x" * 700)
        )
        warning_line = "2026/06/16 12:00:02 ModSecurity: Warning. matched test rule"
        with tempfile.TemporaryDirectory() as temporary:
            self.enterContext(mock.patch.object(GENERATOR, "INPUTS", GENERATOR.EvidenceInputs((Path(temporary),))))
            error_log = Path(temporary) / "error.log"
            error_log.write_text(
                "\n".join(
                    (
                        f"2026/06/15 12:00:00 [crit] old {GENERATOR.DOCROOT_INDEX_PATH} "
                        f"{GENERATOR.PERMISSION_DENIED_TEXT}",
                        "2026/06/16 12:00:00 ordinary final-run line",
                        matching_permission_line,
                        warning_line,
                    )
                )
                + "\n",
                encoding="utf-8",
            )

            excerpt = GENERATOR.representative_error_excerpt(
                {"nginx_error_log_path": str(error_log)},
                "2026/06/16",
            )

        self.assertEqual(excerpt, [matching_permission_line[:600], warning_line])

    def test_permissions_probe_keeps_relative_docroot_path_segments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            self.enterContext(mock.patch.object(GENERATOR, "INPUTS", GENERATOR.EvidenceInputs((Path(temporary),))))
            harness_root = Path(temporary) / "harness"
            evidence_path = harness_root / "logs" / "nginx" / "result.json"
            index_path = harness_root / "runtime" / "case-1" / "htdocs" / "index.html"
            evidence_path.parent.mkdir(parents=True)
            evidence_path.write_text("{}\n", encoding="utf-8")
            index_path.parent.mkdir(parents=True)
            index_path.write_text("index\n", encoding="utf-8")

            probe = GENERATOR.permissions_probe({"evidence_path": str(evidence_path), "name": "case-1"})

        self.assertEqual(probe["index_path"], str(index_path))
        self.assertEqual(probe["path_components"][-1]["path"], str(index_path))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
