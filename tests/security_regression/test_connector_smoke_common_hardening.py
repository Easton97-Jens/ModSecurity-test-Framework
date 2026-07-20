import os
import shlex
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SMOKE_COMMON = ROOT / "ci/lib/connector-smoke-common.sh"


def source_smoke_common() -> str:
    return f". {shlex.quote(str(SMOKE_COMMON))}"


class ConnectorSmokeCommonHardeningTests(unittest.TestCase):
    def run_shell(self, script: str, *, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        if environment:
            env.update(environment)
        return subprocess.run(
            ["sh", "-c", textwrap.dedent(script)],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_malicious_runtime_selectors_cannot_execute_shell_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            flag_marker = tmp_path / "flag-selector-executed"
            lookup_marker = tmp_path / "lookup-selector-executed"
            malicious_flag = f"ENVOY_BIN$(touch {shlex.quote(str(flag_marker))})"
            malicious_lookup = f"ENVOY_BIN$(touch {shlex.quote(str(lookup_marker))})"
            result = self.run_shell(
                f"""
                {source_smoke_common()}
                malicious_flag={shlex.quote(malicious_flag)}
                malicious_lookup={shlex.quote(malicious_lookup)}
                if connector_smoke_runtime_env_was_set "$malicious_flag"; then
                    exit 1
                fi
                if find_runtime_binary "$malicious_lookup" envoy; then
                    exit 1
                fi
                """,
                environment={"FRAMEWORK_ROOT": str(ROOT)},
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertFalse(flag_marker.exists())
            self.assertFalse(lookup_marker.exists())

    def test_explicit_envoy_override_is_resolved_without_dynamic_evaluation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "envoy"
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary.chmod(0o755)
            result = self.run_shell(
                f"""
                {source_smoke_common()}
                connector_smoke_runtime_env_was_set ENVOY_BIN
                resolved=$(find_runtime_binary ENVOY_BIN envoy)
                [ "$resolved" = {shlex.quote(str(binary))} ]
                """,
                environment={"FRAMEWORK_ROOT": str(ROOT), "ENVOY_BIN": str(binary)},
            )
            self.assertEqual(0, result.returncode, result.stderr)

    def test_foreign_ci_root_cannot_supply_common_helper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            marker = tmp_path / "foreign-common-sourced"
            foreign_ci = tmp_path / "foreign" / "ci"
            (foreign_ci / "lib").mkdir(parents=True)
            (foreign_ci / "lib" / "common.sh").write_text(
                f"touch {shlex.quote(str(marker))}\n",
                encoding="utf-8",
            )
            result = self.run_shell(
                f"""
                {source_smoke_common()}
                [ "$CI_ROOT" = {shlex.quote(str(ROOT / 'ci'))} ]
                """,
                environment={"FRAMEWORK_ROOT": str(ROOT), "CI_ROOT": str(foreign_ci)},
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertFalse(marker.exists())

    def test_missing_framework_root_fails_before_foreign_common_is_sourced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            marker = tmp_path / "foreign-common-sourced"
            foreign_ci = tmp_path / "foreign" / "ci"
            (foreign_ci / "lib").mkdir(parents=True)
            (foreign_ci / "lib" / "common.sh").write_text(
                f"touch {shlex.quote(str(marker))}\n",
                encoding="utf-8",
            )
            result = self.run_shell(
                f"""
                unset FRAMEWORK_ROOT
                {source_smoke_common()}
                """,
                environment={"CI_ROOT": str(foreign_ci)},
            )
            self.assertNotEqual(0, result.returncode)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
