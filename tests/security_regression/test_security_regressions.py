import importlib.util
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_check_common():
    spec = importlib.util.spec_from_file_location("check_common_versions", ROOT / "ci/tools/check-common-versions.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SecurityRegressionTests(unittest.TestCase):
    def test_malicious_release_tags_rejected(self):
        mod = load_check_common()
        malicious = [
            "v4.28.0$(touch /tmp/pwned)",
            'v4.28.0"id`',
            'v4.28.0"; touch /tmp/pwned; "',
            "../../evil",
            "v4.28.0#comment",
        ]
        for tag in malicious:
            with self.subTest(tag=tag):
                with self.assertRaises(mod.UpstreamError):
                    mod.release_tag_name({"tag_name": tag}, "owner/repo")

    def test_connector_generated_report_utils_not_imported(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            connector = tmp_path / "connector"
            connector_ci = connector / "ci"
            connector_ci.mkdir(parents=True)
            marker = tmp_path / "pwned"
            (connector_ci / "generated_report_utils.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n",
                encoding="utf-8",
            )
            output = tmp_path / "out"
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "ci/reporting/generate-connector-work-queue.py"),
                    "--framework-root",
                    str(ROOT),
                    "--connector-root",
                    str(connector),
                    "--output-root",
                    str(output),
                    "--full-runtime-matrix",
                    str(tmp_path / "missing.json"),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertFalse(marker.exists())

    def test_common_blocks_shared_tmp_and_var_tmp_runtime_paths(self):
        script = textwrap.dedent(
            f"""
            . {ROOT}/ci/lib/common.sh
            assert_safe_runtime_path /tmp/ModSecurity-conector-verified/bin poisoned >/dev/null 2>&1 && exit 1
            assert_safe_runtime_path /var/tmp/ModSecurity-conector-verified/bin poisoned >/dev/null 2>&1 && exit 1
            safe_remove_runtime_path /var/tmp poisoned-root test >/dev/null 2>&1 && exit 1
            exit 0
            """
        )
        subprocess.run(["sh", "-c", script], cwd=ROOT, check=True)

    def test_connector_smoke_no_default_shared_tmp_discovery(self):
        script = textwrap.dedent(
            f"""
            CONNECTOR_SMOKE_SCRIPT_DIR={ROOT}/ci
            FRAMEWORK_ROOT={ROOT}
            . {ROOT}/ci/lib/connector-smoke-common.sh
            roots=$(connector_smoke_default_verified_roots || true)
            [ -z "$roots" ] || exit 1
            exit 0
            """
        )
        subprocess.run(["sh", "-c", script], cwd=ROOT, check=True)


if __name__ == "__main__":
    unittest.main()
