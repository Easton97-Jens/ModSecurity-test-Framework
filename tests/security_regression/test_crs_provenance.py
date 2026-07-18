import importlib.util
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FETCH_CRS = ROOT / "ci/provisioning/fetch-crs.sh"
COMMON_SH = ROOT / "ci/lib/common.sh"


def load_common_version_tool():
    spec = importlib.util.spec_from_file_location("check_common_versions_crs_test", ROOT / "ci/tools/check-common-versions.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class CrsProvenanceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        common_text = COMMON_SH.read_text(encoding="utf-8")
        cls.approved_repo = cls.approved_value(common_text, "CRS_APPROVED_REPO_URL")
        cls.approved_ref = cls.approved_value(common_text, "CRS_APPROVED_GIT_REF")
        cls.approved_commit = cls.approved_value(common_text, "CRS_APPROVED_GIT_COMMIT")

    @staticmethod
    def approved_value(common_text, variable):
        match = re.search(rf"^{variable}='([^']+)'$", common_text, re.MULTILINE)
        if match is None:
            raise AssertionError(f"missing {variable} in ci/lib/common.sh")
        return match.group(1)

    def run_fetch(self, overrides=None, existing=False, fake_head=None):
        with tempfile.TemporaryDirectory(prefix="crs-provenance-") as temporary_root:
            root = Path(temporary_root)
            source_root = root / "source"
            crs_source_dir = source_root / "coreruleset"
            fake_bin = root / "bin"
            fake_bin.mkdir()
            log_path = root / "git.log"
            fake_git = fake_bin / "git"
            fake_git.write_text(
                textwrap.dedent(
                    """\
                    #!/bin/sh
                    set -eu
                    : "${FAKE_GIT_LOG:?FAKE_GIT_LOG must be set}"
                    printf '%s' "$1" >> "$FAKE_GIT_LOG"
                    for argument in "$@"; do
                        printf ' <%s>' "$argument" >> "$FAKE_GIT_LOG"
                    done
                    printf '\\n' >> "$FAKE_GIT_LOG"
                    if [ "$1" = "-C" ]; then
                        shift 2
                    fi
                    case "$1" in
                        init)
                            mkdir -p "$2/.git"
                            ;;
                        config)
                            printf '%s\\n' "$FAKE_GIT_ORIGIN"
                            ;;
                        rev-parse)
                            printf '%s\\n' "$FAKE_GIT_HEAD"
                            ;;
                    esac
                    """
                ),
                encoding="utf-8",
            )
            fake_git.chmod(0o700)
            if existing:
                (crs_source_dir / ".git").mkdir(parents=True)

            environment = os.environ.copy()
            for variable in ("CRS_REPO_URL", "CRS_GIT_REF", "CRS_GIT_COMMIT"):
                environment.pop(variable, None)
            environment.update(
                {
                    "PATH": f"{fake_bin}{os.pathsep}{environment.get('PATH', '')}",
                    "FAKE_GIT_LOG": str(log_path),
                    "FAKE_GIT_ORIGIN": self.approved_repo,
                    "FAKE_GIT_HEAD": fake_head or self.approved_commit,
                    "FRAMEWORK_ROOT": str(ROOT),
                    "CONNECTOR_ROOT": str(ROOT),
                    "CI_ROOT": str(ROOT / "ci"),
                    "VERIFIED_RUN_ROOT": str(root),
                    "SOURCE_ROOT": str(source_root),
                    "CRS_SOURCE_DIR": str(crs_source_dir),
                    "BUILD_ROOT": str(root / "build"),
                    "TMP_ROOT": str(root / "tmp"),
                    "LOG_ROOT": str(root / "logs"),
                }
            )
            environment.update(overrides or {})
            result = subprocess.run(
                ["sh", str(FETCH_CRS)],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            log = log_path.read_text(encoding="utf-8") if log_path.exists() else ""
            return result, log

    def test_fetch_crs_rejects_mutable_source_identifiers_before_git(self):
        mutable_inputs = [
            ("CRS_GIT_COMMIT", self.approved_ref),
            ("CRS_GIT_COMMIT", "main"),
            ("CRS_GIT_COMMIT", f"refs/tags/{self.approved_ref}"),
            ("CRS_GIT_COMMIT", "refs/heads/main"),
            ("CRS_GIT_COMMIT", self.approved_commit[:12]),
            ("CRS_GIT_COMMIT", "f" * 40),
            ("CRS_GIT_REF", "main"),
            ("CRS_REPO_URL", "https://github.com/example/unreviewed-crs.git"),
        ]
        for variable, value in mutable_inputs:
            with self.subTest(variable=variable, value=value):
                result, log = self.run_fetch({variable: value})
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertEqual(log, "", "a rejected source identifier reached Git")

    def test_fetch_crs_uses_only_the_reviewed_commit_for_new_and_existing_checkouts(self):
        for existing in (False, True):
            with self.subTest(existing=existing):
                result, log = self.run_fetch(existing=existing)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("<fetch> <--depth> <1> <origin>", log)
                self.assertIn(self.approved_commit, log)
                self.assertIn("<checkout> <--detach>", log)
                self.assertIn("<rev-parse> <--verify> <HEAD^{commit}>", log)
                self.assertIn("<submodule> <update> <--init> <--recursive>", log)
                self.assertNotIn("--branch", log)
                self.assertNotIn(self.approved_ref, log)

    def test_fetch_crs_rejects_a_checked_out_commit_mismatch_before_submodules(self):
        result, log = self.run_fetch(existing=True, fake_head="f" * 40)
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertIn("<rev-parse> <--verify> <HEAD^{commit}>", log)
        self.assertNotIn("<submodule> <update>", log)

    def test_version_updater_requires_reviewed_tag_and_commit_pair(self):
        tool = load_common_version_tool()
        _, entries = tool.parse_common(COMMON_SH)

        class NewerReleaseClient:
            def get_json(self, _url):
                return {"tag_name": "v4.29.0"}

        result = tool.check_crs_release_provenance(entries, NewerReleaseClient())
        self.assertEqual(result.status, tool.STATUS_UNKNOWN)
        self.assertEqual(result.updates, [])
        self.assertEqual(result.variables, ["CRS_REPO_URL", "CRS_GIT_REF", "CRS_GIT_COMMIT"])
        self.assertIn("provenance", result.message)


if __name__ == "__main__":
    unittest.main()
