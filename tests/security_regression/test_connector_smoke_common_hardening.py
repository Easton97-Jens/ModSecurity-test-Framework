import hashlib
import os
import shlex
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SMOKE_COMMON = ROOT / "ci/lib/connector-smoke-common.sh"
COMMON = ROOT / "ci/lib/common.sh"
RUNTIME_COMPONENT_COMMON = ROOT / "ci/lib/runtime-component-common.sh"


def source_smoke_common() -> str:
    return f". {shlex.quote(str(SMOKE_COMMON))}"


def reviewed_runtime_pins() -> dict[str, str]:
    result = subprocess.run(
        [
            "sh",
            "-c",
            '. "$1"; printf "%s\\n" '
            '"$LIGHTTPD_VERSION|$LIGHTTPD_SHA256|$HAPROXY_VERSION|'
            '$HAPROXY_SOURCE_URL|$HAPROXY_SHA256|$ENVOY_SHA256"',
            "sh",
            str(COMMON),
        ],
        cwd=ROOT,
        env={"PATH": os.defpath},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    lighttpd_version, lighttpd_sha, haproxy_version, haproxy_url, haproxy_sha, envoy_sha = (
        result.stdout.strip().split("|", 5)
    )
    return {
        "lighttpd_version": lighttpd_version,
        "lighttpd_sha": lighttpd_sha,
        "haproxy_version": haproxy_version,
        "haproxy_url": haproxy_url,
        "haproxy_sha": haproxy_sha,
        "envoy_sha": envoy_sha,
    }


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
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(flag_marker.exists())
            self.assertFalse(lookup_marker.exists())

    def test_path_shadowed_sha256sum_cannot_approve_an_arbitrary_envoy_binary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            pins = reviewed_runtime_pins()
            component_root = tmp_path / "component"
            reviewed_binary = component_root / "bin" / "envoy"
            reviewed_binary.parent.mkdir(parents=True)
            reviewed_binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            reviewed_binary.chmod(0o755)
            fake_bin = tmp_path / "bin"
            fake_bin.mkdir()
            fake_sha = fake_bin / "sha256sum"
            marker = tmp_path / "path-sha256sum-was-used"
            fake_sha.write_text(
                "#!/bin/sh\n"
                f"printf used > {shlex.quote(str(marker))}\n"
                "printf '%s  %s\\n' "
                f"{shlex.quote(pins['envoy_sha'])} "
                "\"$1\"\n",
                encoding="utf-8",
            )
            fake_sha.chmod(0o755)
            result = self.run_shell(
                f"""
                {source_smoke_common()}
                if find_runtime_binary ENVOY_BIN envoy; then exit 1; fi
                """,
                environment={
                    "FRAMEWORK_ROOT": str(ROOT),
                    "ENVOY_COMPONENT_ROOT": str(component_root),
                    "ENVOY_BIN": str(reviewed_binary),
                    "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                },
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(marker.exists(), result.stdout + result.stderr)
            self.assertIn("reviewed artifact digest", result.stderr)

    def test_runtime_provenance_writer_rejects_symlinks_and_replaces_regular_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cache"
            root.mkdir(parents=True)
            outside = Path(tmp) / "outside"
            outside.write_text("unchanged\n", encoding="utf-8")
            symlinked = root / "symlinked.provenance"
            symlinked.symlink_to(outside)
            rejected = self.run_shell(
                f"""
                . {shlex.quote(str(COMMON))}
                . {shlex.quote(str(RUNTIME_COMPONENT_COMMON))}
                printf '%s\\n' replacement | runtime_component_write_provenance_file \\
                    {shlex.quote(str(symlinked))} {shlex.quote(str(root))} test-provenance
                """,
                environment={
                    "FRAMEWORK_ROOT": str(ROOT),
                    "CONNECTOR_COMPONENT_CACHE": str(root),
                    "BUILD_ROOT": str(root / "build"),
                    "TMP_ROOT": str(root / "tmp"),
                    "LOG_ROOT": str(root / "logs"),
                },
            )
            self.assertEqual(rejected.returncode, 77, rejected.stdout + rejected.stderr)
            self.assertTrue(symlinked.is_symlink())
            self.assertEqual(outside.read_text(encoding="utf-8"), "unchanged\n")

            regular = root / "regular.provenance"
            regular.write_text("old\n", encoding="utf-8")
            accepted = self.run_shell(
                f"""
                . {shlex.quote(str(COMMON))}
                . {shlex.quote(str(RUNTIME_COMPONENT_COMMON))}
                printf '%s\\n' replacement | runtime_component_write_provenance_file \\
                    {shlex.quote(str(regular))} {shlex.quote(str(root))} test-provenance
                """,
                environment={
                    "FRAMEWORK_ROOT": str(ROOT),
                    "CONNECTOR_COMPONENT_CACHE": str(root),
                    "BUILD_ROOT": str(root / "build"),
                    "TMP_ROOT": str(root / "tmp"),
                    "LOG_ROOT": str(root / "logs"),
                },
            )
            self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
            self.assertFalse(regular.is_symlink())
            self.assertEqual(regular.read_text(encoding="utf-8"), "replacement\n")

    def test_explicit_envoy_override_outside_reviewed_stage_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            binary = tmp_path / "foreign" / "envoy"
            binary.parent.mkdir()
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary.chmod(0o755)
            result = self.run_shell(
                f"""
                {source_smoke_common()}
                if find_runtime_binary ENVOY_BIN envoy; then exit 1; fi
                """,
                environment={
                    "FRAMEWORK_ROOT": str(ROOT),
                    "ENVOY_BIN": str(binary),
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("reviewed staged path", result.stderr)

    def test_explicit_lighttpd_binary_accepts_matching_provenance_and_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pins = reviewed_runtime_pins()
            component_root = root / "lighttpd-component"
            private_root = root / "lighttpd-private"
            binary = private_root / "bin" / "lighttpd"
            binary.parent.mkdir(parents=True)
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary.chmod(0o755)
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            (private_root / ".lighttpd-binary.provenance").write_text(
                f"lighttpd_version={pins['lighttpd_version']}\n"
                f"lighttpd_source_sha256={pins['lighttpd_sha']}\n"
                f"lighttpd_binary_sha256={digest}\n",
                encoding="utf-8",
            )
            result = self.run_shell(
                f"""
                {source_smoke_common()}
                resolved=$(find_runtime_binary LIGHTTPD_BIN lighttpd)
                [ "$resolved" = {shlex.quote(str(binary))} ]
                """,
                environment={
                    "FRAMEWORK_ROOT": str(ROOT),
                    "LIGHTTPD_COMPONENT_ROOT": str(component_root),
                    "BUILD_ROOT": str(root / "build"),
                    "LIGHTTPD_CONNECTOR_BUILD_ROOT": str(private_root),
                    "LIGHTTPD_BIN": str(binary),
                },
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_explicit_lighttpd_binary_rejects_stale_digest_or_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pins = reviewed_runtime_pins()
            component_root = root / "lighttpd-component"
            binary = component_root / "bin" / "lighttpd"
            binary.parent.mkdir(parents=True)
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary.chmod(0o755)
            (component_root / ".lighttpd-binary.provenance").write_text(
                "lighttpd_version=stale\n"
                f"lighttpd_source_sha256={pins['lighttpd_sha']}\n"
                f"lighttpd_binary_sha256={hashlib.sha256(binary.read_bytes()).hexdigest()}\n",
                encoding="utf-8",
            )
            result = self.run_shell(
                f"""
                {source_smoke_common()}
                if find_runtime_binary LIGHTTPD_BIN lighttpd; then exit 1; fi
                """,
                environment={
                    "FRAMEWORK_ROOT": str(ROOT),
                    "LIGHTTPD_COMPONENT_ROOT": str(component_root),
                    "LIGHTTPD_BIN": str(binary),
                },
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_explicit_haproxy_binary_accepts_matching_provenance_and_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pins = reviewed_runtime_pins()
            runtime_root = root / "haproxy-runtime"
            binary = runtime_root / "sbin" / "haproxy"
            binary.parent.mkdir(parents=True)
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary.chmod(0o755)
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            (runtime_root / "haproxy.provenance").write_text(
                f"haproxy_version={pins['haproxy_version']}\n"
                f"haproxy_source_url={pins['haproxy_url']}\n"
                f"haproxy_sha256={pins['haproxy_sha']}\n"
                f"haproxy_binary_sha256={digest}\n",
                encoding="utf-8",
            )
            result = self.run_shell(
                f"""
                {source_smoke_common()}
                resolved=$(find_runtime_binary HAPROXY_BIN haproxy)
                [ "$resolved" = {shlex.quote(str(binary))} ]
                """,
                environment={
                    "FRAMEWORK_ROOT": str(ROOT),
                    "HAPROXY_RUNTIME_DIR": str(runtime_root),
                    "HAPROXY_BIN": str(binary),
                },
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_explicit_haproxy_binary_rejects_tampered_binary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pins = reviewed_runtime_pins()
            runtime_root = root / "haproxy-runtime"
            binary = runtime_root / "sbin" / "haproxy"
            binary.parent.mkdir(parents=True)
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary.chmod(0o755)
            (runtime_root / "haproxy.provenance").write_text(
                f"haproxy_version={pins['haproxy_version']}\n"
                f"haproxy_source_url={pins['haproxy_url']}\n"
                f"haproxy_sha256={pins['haproxy_sha']}\n"
                f"haproxy_binary_sha256={hashlib.sha256(binary.read_bytes()).hexdigest()}\n",
                encoding="utf-8",
            )
            binary.write_text("#!/bin/sh\necho tampered\n", encoding="utf-8")
            result = self.run_shell(
                f"""
                {source_smoke_common()}
                if find_runtime_binary HAPROXY_BIN haproxy; then exit 1; fi
                """,
                environment={
                    "FRAMEWORK_ROOT": str(ROOT),
                    "HAPROXY_RUNTIME_DIR": str(runtime_root),
                    "HAPROXY_BIN": str(binary),
                },
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_configured_binary_does_not_fall_back_to_build_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            planted = root / "build" / "bin" / "envoy"
            planted.parent.mkdir(parents=True)
            planted.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            planted.chmod(0o755)
            result = self.run_shell(
                f"""
                {source_smoke_common()}
                ENVOY_BIN={shlex.quote(str(root / 'missing' / 'envoy'))}
                ENVOY_BIN_WAS_SET=0
                BUILD_ROOT={shlex.quote(str(root / 'build'))}
                if find_runtime_binary ENVOY_BIN envoy; then
                    exit 1
                fi
                """,
                environment={"FRAMEWORK_ROOT": str(ROOT)},
            )
            self.assertEqual(result.returncode, 0, result.stderr)

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
            self.assertEqual(result.returncode, 0, result.stderr)
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
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
