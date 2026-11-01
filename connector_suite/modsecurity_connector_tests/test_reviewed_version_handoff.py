"""Fail early on NGINX writer and ModSecurity source/guide projection drift."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest

ROOT = connector_root()
CHECKER = load_source(source_path('ci/tools/check-reviewed-version-handoff.py', root=ROOT))


class ReviewedVersionHandoffTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="reviewed-version-handoff-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.common = (
            'ENVOY_VERSION="1.2.3"\n'
            'NGINX_RELEASE_TAG="release-1.31.6"\n'
            'MODSECURITY_V3_APPROVED_REPO_URL="https://github.com/owasp-modsecurity/ModSecurity.git"\n'
            'MODSECURITY_V3_RELEASE_TAG="v3.0.16"\n'
            'MODSECURITY_V3_APPROVED_COMMIT="' + 'a' * 40 + '"\n'
        )
        self.write(CHECKER.COMMON, self.common)
        self.approve(self.common)
        self.write(CHECKER.WRITER, 'EXPECTED_NGINX_VERSION = "1.31.6"\n')
        self.write(CHECKER.WORKFLOW, 'jobs:\n  nginx-exact-head:\n    env:\n      NGINX_RELEASE_TAG: release-1.31.6\n')
        self.guides()

    def write(self, path: str, text: str) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def approve(self, _common: str) -> None:
        # Fixture-only closed source registry; no structural digest is approved.
        mutable_fields = ("ENVOY_VERSION", *CHECKER.MODSECURITY_KEYS)
        self.write(CHECKER.VERIFIER, f"MUTABLE_SOURCE_FIELDS = {mutable_fields!r}\n")

    def guides(self, release: str = "v3.0.16", commit: str = "a" * 40) -> None:
        commands = [f'MODSECURITY_REF="{release}"', f'MODSECURITY_COMMIT="{commit}"']
        for path in CHECKER.GUIDE_SOURCES:
            self.write(path, "COMMANDS = " + repr(commands) + "\n")
        for path in CHECKER.GUIDES:
            self.write(path, "```sh\n" + "\n".join(commands) + "\n```\n")

    def test_current_checkout_is_consistent(self) -> None:
        result = CHECKER.inspect_handoff(ROOT)
        self.assertEqual(result["status"], "consistent")

    def test_matching_fixture_is_read_only(self) -> None:
        before = {str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        result = CHECKER.inspect_handoff(self.root)
        self.assertEqual(result["modsecurity_release"], "v3.0.16")
        self.assertEqual(before, {str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()})

    def test_writer_drift_is_detected_before_runtime(self) -> None:
        self.write(CHECKER.WRITER, 'EXPECTED_NGINX_VERSION = "1.31.5"\n')
        with self.assertRaisesRegex(CHECKER.HandoffError, "evidence writer"):
            CHECKER.inspect_handoff(self.root)

    def test_workflow_drift_is_detected(self) -> None:
        self.write(CHECKER.WORKFLOW, "      NGINX_RELEASE_TAG: release-1.31.5\n")
        with self.assertRaisesRegex(CHECKER.HandoffError, "workflow release"):
            CHECKER.inspect_handoff(self.root)

    def test_modsecurity_change_uses_bounded_data_path(self) -> None:
        self.write(CHECKER.COMMON, self.common.replace("v3.0.16", "v3.0.99"))
        with self.assertRaisesRegex(CHECKER.HandoffError, "tag/commit drift"):
            CHECKER.inspect_handoff(self.root)

    def test_reviewed_modsecurity_change_requires_matching_guides(self) -> None:
        changed = self.common.replace("v3.0.16", "v3.0.99").replace("a" * 40, "b" * 40)
        self.write(CHECKER.COMMON, changed)
        with self.assertRaisesRegex(CHECKER.HandoffError, "tag/commit drift"):
            CHECKER.inspect_handoff(self.root)
        self.guides("v3.0.99", "b" * 40)
        self.assertEqual(CHECKER.inspect_handoff(self.root)["status"], "consistent")

    def test_each_documentation_projection_is_checked(self) -> None:
        for path in (*CHECKER.GUIDE_SOURCES, *CHECKER.GUIDES):
            with self.subTest(path=path):
                self.guides()
                self.write(path, (self.root / path).read_text().replace("a" * 40, "b" * 40))
                with self.assertRaisesRegex(CHECKER.HandoffError, "tag/commit drift"):
                    CHECKER.inspect_handoff(self.root)

    def test_missing_and_duplicate_pins_are_rejected(self) -> None:
        for changed in (self.common.replace('NGINX_RELEASE_TAG="release-1.31.6"\n', ""),
                        self.common + 'MODSECURITY_V3_RELEASE_TAG="v3.0.16"\n'):
            with self.subTest(changed=changed):
                self.write(CHECKER.COMMON, changed)
                self.approve(changed)
                with self.assertRaises(CHECKER.HandoffError):
                    CHECKER.inspect_handoff(self.root)

    def test_nonliteral_shell_pin_is_never_executed(self) -> None:
        changed = self.common.replace('v3.0.16', '$(touch sentinel)')
        self.write(CHECKER.COMMON, changed)
        self.approve(changed)
        with self.assertRaisesRegex(CHECKER.HandoffError, "unsafe value"):
            CHECKER.inspect_handoff(self.root)
        self.assertFalse((self.root / "sentinel").exists())

    def test_repository_major_version_and_commit_shapes_are_rejected(self) -> None:
        for before, after in ((CHECKER.OFFICIAL_REPOSITORY, "https://example.invalid/ModSecurity.git"),
                              ("v3.0.16", "v4.0.0"), ("a" * 40, "master")):
            with self.subTest(after=after):
                changed = self.common.replace(before, after)
                self.write(CHECKER.COMMON, changed)
                self.approve(changed)
                with self.assertRaises(CHECKER.HandoffError):
                    CHECKER.inspect_handoff(self.root)

    def test_mutable_version_data_is_accepted(self) -> None:
        self.write(CHECKER.COMMON, self.common.replace("1.2.3", "1.2.4"))
        self.assertEqual(CHECKER.inspect_handoff(self.root)["status"], "consistent")

    def test_new_shell_structure_is_not_blocked_by_a_fixed_digest(self) -> None:
        self.write(CHECKER.COMMON, self.common + "\nfuture_helper() { :; }\n")
        self.assertEqual(CHECKER.inspect_handoff(self.root)["status"], "consistent")

    def test_unregistered_modsecurity_field_is_rejected_from_mutable_registry(self) -> None:
        verifier = (self.root / CHECKER.VERIFIER).read_text()
        mutable_line = next(
            line
            for line in verifier.splitlines()
            if line.startswith("MUTABLE_SOURCE_FIELDS = ")
        )
        expanded_line = mutable_line[:-1] + ", 'MODSECURITY_GIT_REF')"
        self.write(CHECKER.VERIFIER, verifier.replace(mutable_line, expanded_line, 1))
        with self.assertRaisesRegex(
            CHECKER.HandoffError, "exact ModSecurity-v3 provenance tuple"
        ):
            CHECKER.inspect_handoff(self.root)

    def test_symlinked_source_is_rejected(self) -> None:
        path = self.root / CHECKER.COMMON
        target = self.root / "moved-common.sh"
        path.rename(target)
        path.symlink_to(target)
        with self.assertRaisesRegex(CHECKER.HandoffError, "symlink"):
            CHECKER.inspect_handoff(self.root)

    def test_conflicting_and_missing_documentation_assignments_are_rejected(self) -> None:
        path = CHECKER.GUIDE_SOURCES[0]
        for source in ("COMMANDS = []\n", 'COMMANDS = [\'MODSECURITY_REF="v3.0.16"\', '
                       '\'MODSECURITY_REF="v3.0.99"\', \'MODSECURITY_COMMIT="' + 'a' * 40 + '"\']\n'):
            with self.subTest(source=source):
                self.write(path, source)
                with self.assertRaises(CHECKER.HandoffError):
                    CHECKER.inspect_handoff(self.root)

    def test_cli_reports_failure_not_a_pass(self) -> None:
        self.write(CHECKER.WRITER, 'EXPECTED_NGINX_VERSION = "1.31.5"\n')
        with contextlib.redirect_stderr(io.StringIO()):
            result = CHECKER.main(["--repo-root", str(self.root)])
        self.assertEqual(result, 2)

    def test_nonregular_source_is_rejected(self) -> None:
        path = self.root / CHECKER.COMMON
        path.unlink()
        path.mkdir()
        with self.assertRaisesRegex(CHECKER.HandoffError, "not a regular file"):
            CHECKER.inspect_handoff(self.root)

    def test_oversized_source_is_rejected(self) -> None:
        self.write(CHECKER.COMMON, "x" * (CHECKER.MAX_BYTES + 1))
        with self.assertRaisesRegex(CHECKER.HandoffError, "exceeds bound"):
            CHECKER.inspect_handoff(self.root)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
