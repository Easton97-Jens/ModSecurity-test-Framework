import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


def load_module():
    spec = importlib.util.spec_from_file_location(
        "generate_phase_work_queue_sonar_test",
        ROOT / "ci/reporting/generate-phase-work-queue.py",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class GeneratePhaseWorkQueueSonarTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def write_default_inputs(self, root: Path) -> Path:
        canonical = root / "reports/testing/generated/canonical"
        canonical.mkdir(parents=True)
        (canonical / "connector_work_queue.generated.json").write_text(
            json.dumps({"entries": [], "guardrails": {}}), encoding="utf-8"
        )
        return canonical

    def call_main(self, connector_root: Path, *extra_args: str) -> int:
        argv = [
            "generate-phase-work-queue.py",
            "--framework-root",
            str(ROOT),
            "--connector-root",
            str(connector_root),
            *extra_args,
        ]
        with mock.patch.object(sys, "argv", argv):
            return self.module.main()

    def test_phase_coverage_pattern_has_bounded_columns_and_parses_valid_rows(self):
        self.assertNotIn(".*?", self.module.PHASE_ROW_RE.pattern)
        with tempfile.TemporaryDirectory() as tmp:
            coverage = Path(tmp) / "phase-coverage.md"
            coverage.write_text(
                "| 1 | 42 | ARGS(5), REQUEST_HEADERS(3) | PASS:40, FAIL:2 |\n",
                encoding="utf-8",
            )
            parsed = self.module.parse_phase_coverage(coverage)

        self.assertEqual(parsed["1"]["case_count"], 42)
        self.assertEqual(parsed["1"]["top_variables"], {"ARGS": 5, "REQUEST_HEADERS": 3})
        self.assertEqual(parsed["1"]["status_distribution"], {"PASS": 40, "FAIL": 2})

    def test_status_normalization_has_no_duplicate_status_literal(self):
        source = (ROOT / "ci/reporting/generate-phase-work-queue.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn('"NOT_EXECUTABLE", "NOT_EXECUTABLE"', source)
        self.assertEqual(self.module.status_value({"runtime_status": "not-executed"}), "NOT_EXECUTABLE")
        self.assertEqual(self.module.status_value({"runtime_status": "not-executable"}), "NOT_EXECUTABLE")

    def test_direction_priority_and_normalization_preserve_policy_order(self):
        report_only = {
            "classification": self.module.REPORT_ONLY_CLASSIFICATION,
            "work_direction": ["intervention_blocking"],
        }
        phase_two = {
            "phase": "2",
            "functional_area": ["request_body_json"],
            "work_direction": ["intervention_blocking"],
        }
        fallback = {"phase": "unknown", "work_direction": ["zeta", "alpha"]}
        clustered_entries = [
            {
                "case_id": "case-a",
                "connector": connector,
                "phase": "1",
                "functional_area": ["action_intervention"],
                "failure_pattern": ["expected_block_got_200"],
                "runtime_status": "FAIL",
            }
            for connector in ("apache", "nginx")
        ]

        self.assertEqual(self.module.phase_work_direction(report_only), ["classification_only"])
        self.assertEqual(self.module.phase_work_direction(phase_two), ["json_processor"])
        self.assertEqual(self.module.phase_work_direction(fallback), ["alpha", "zeta"])

        normalized = self.module.normalize_entries(clustered_entries)
        self.assertEqual([entry["priority"] for entry in normalized], ["P0", "P0"])
        self.assertEqual(
            [entry["work_direction"] for entry in normalized],
            [["intervention_blocking"], ["intervention_blocking"]],
        )

    def test_priority_precedence_preserves_all_decision_classes(self):
        p0_entry = {
            "case_id": "case-a",
            "connector": "apache",
            "phase": "1",
            "functional_area": ["action_intervention"],
            "failure_pattern": ["expected_block_got_200"],
            "runtime_status": "FAIL",
        }
        p0_cluster = self.module.simple_blocking_cluster_key(p0_entry)
        cases = [
            (
                {
                    "classification": self.module.REPORT_ONLY_CLASSIFICATION,
                    "phase": "4",
                },
                set(),
                set(),
                self.module.REPORT_ONLY_PRIORITY,
            ),
            (
                {"classification": "phase1_request_body_unavailable"},
                set(),
                set(),
                "P3",
            ),
            ({"phase": "4"}, set(), set(), "P3"),
            ({"source_kind": "golden-only"}, set(), set(), "P3"),
            (p0_entry, {p0_cluster}, set(), "P0"),
            ({"source_kind": "runtime-job", "runtime_status": "BLOCKED"}, set(), set(), "P1"),
            ({"connector": "apache", "failure_pattern": ["burst"]}, set(), {("apache", "burst")}, "P1"),
            ({"connector": "nginx", "failure_pattern": ["expected_200_got_404"]}, set(), set(), "P1"),
            ({"connector": "haproxy", "failure_pattern": ["request_got_501"]}, set(), set(), "P1"),
            ({"failure_pattern": ["expected_block_got_200"]}, set(), set(), "P1"),
            ({"phase": "3"}, set(), set(), "P2"),
            ({"functional_area": ["request_body_xml"]}, set(), set(), "P2"),
            ({}, set(), set(), "P3"),
        ]

        self.assertIsNotNone(p0_cluster)
        for entry, p0_clusters, high_volume, expected in cases:
            with self.subTest(entry=entry):
                self.assertEqual(
                    self.module.choose_priority(entry, p0_clusters, high_volume),
                    expected,
                )

    def test_main_writes_fixed_reports_under_the_connector_root(self):
        source = (ROOT / "ci/reporting/generate-phase-work-queue.py").read_text(
            encoding="utf-8"
        )
        main_source = source[source.index("def main() -> int:") :]
        self.assertIn("write_generated_report_file(", main_source)
        self.assertNotIn(".write_text(", main_source)

        with tempfile.TemporaryDirectory() as tmp:
            connector_root = Path(tmp) / "connector"
            connector_root.mkdir()
            canonical = self.write_default_inputs(connector_root)

            self.assertEqual(self.call_main(connector_root), 0)

            generated_json = canonical / "phase_work_queue.generated.json"
            generated_markdown = canonical / "phase_work_queue.generated.md"
            self.assertTrue(generated_json.is_file())
            self.assertTrue(generated_markdown.is_file())
            self.assertEqual(json.loads(generated_json.read_text(encoding="utf-8"))["data"]["summary"]["runtime_entries"], 0)

    def test_main_rejects_an_unapproved_output_root_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            temporary_root = Path(tmp)
            connector_root = temporary_root / "connector"
            outside_root = temporary_root / "outside"
            connector_root.mkdir()
            outside_root.mkdir()
            outside_canonical = self.write_default_inputs(outside_root)

            with self.assertRaises(ValueError):
                self.call_main(connector_root, "--output-root", str(outside_root))

            self.assertFalse((outside_canonical / "phase_work_queue.generated.json").exists())

    def test_main_rejects_a_symlinked_generated_report_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            temporary_root = Path(tmp)
            connector_root = temporary_root / "connector"
            generated_root = connector_root / "reports/testing/generated"
            outside_root = temporary_root / "outside"
            generated_root.mkdir(parents=True)
            outside_root.mkdir()
            (generated_root / "canonical").symlink_to(outside_root, target_is_directory=True)

            with self.assertRaises(ValueError):
                self.call_main(connector_root)

            self.assertFalse((outside_root / "phase_work_queue.generated.json").exists())

    def test_publicly_writable_roots_are_not_approved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "public"
            root.mkdir()
            root.chmod(0o777)
            try:
                with self.assertRaises(ValueError):
                    self.module.existing_private_root(root, "test root")
            finally:
                root.chmod(0o700)

    def test_approved_roots_reject_symlinks_and_foreign_frameworks(self):
        with tempfile.TemporaryDirectory() as tmp:
            temporary_root = Path(tmp)
            target = temporary_root / "target"
            link = temporary_root / "link"
            target.mkdir()
            link.symlink_to(target, target_is_directory=True)

            with self.assertRaises(ValueError):
                self.module.existing_private_root(link, "symlinked root")
            with self.assertRaises(ValueError):
                self.module.configured_framework_root(target)

    def test_secure_writer_replaces_a_final_symlink_without_following_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            temporary_root = Path(tmp)
            output_directory = temporary_root / "output"
            output_directory.mkdir()
            outside_file = temporary_root / "outside.json"
            outside_file.write_text("unchanged", encoding="utf-8")
            output_name = "phase_work_queue.generated.json"
            (output_directory / output_name).symlink_to(outside_file)

            self.module.write_generated_report_file(output_directory, output_name, "safe replacement\n")

            output = output_directory / output_name
            self.assertFalse(output.is_symlink())
            self.assertEqual(output.read_text(encoding="utf-8"), "safe replacement\n")
            self.assertEqual(outside_file.read_text(encoding="utf-8"), "unchanged")


if __name__ == "__main__":
    unittest.main()
