from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "ci/tools/check-runtime-component-lock.py"
LOCK = ROOT / "ci/provisioning/runtime-component-lock.json"
COMMON = ROOT / "ci/lib/common.sh"
MANIFEST = ROOT / "ci/provisioning/runtime-components.manifest.json"


class RuntimeComponentLockTests(unittest.TestCase):
    def run_checker(
        self,
        lock: Path = LOCK,
        common: Path = COMMON,
        manifest: Path = MANIFEST,
        extra_args: tuple[str, ...] = (),
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(CHECKER),
                "--lock",
                str(lock),
                "--common",
                str(common),
                "--manifest",
                str(manifest),
                *extra_args,
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def mutate_lock(self, mutation) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "lock.json"
            value = json.loads(LOCK.read_text(encoding="utf-8"))
            mutation(value)
            lock.write_text(json.dumps(value), encoding="utf-8")
            return self.run_checker(lock)

    @staticmethod
    def profile(value: dict[str, object], identifier: str) -> dict[str, object]:
        return next(item for item in value["profiles"] if item["id"] == identifier)

    def test_reviewed_profiles_pass(self):
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_known_version_drifts_are_blocked(self):
        cases = (
            ("nginx-h1", "1.31.2"),
            ("envoy-ext-proc", "1.38.2"),
            ("traefik-native", "3.7.5"),
        )
        for identifier, old_version in cases:
            with self.subTest(identifier=identifier):
                result = self.mutate_lock(
                    lambda value, identifier=identifier, old_version=old_version: self.profile(
                        value, identifier
                    ).update({"version": old_version})
                )
                self.assertEqual(result.returncode, 77)
                self.assertIn("version drift", result.stderr)

    def test_exact_htx_pin_cannot_fall_back_to_generic_haproxy_pin(self):
        result = self.mutate_lock(
            lambda value: self.profile(value, "haproxy-htx").update({"version": "3.2.22"})
        )
        self.assertEqual(result.returncode, 77)
        self.assertIn("haproxy-htx version drift", result.stderr)

    def test_wrong_architecture_and_asset_are_blocked(self):
        architecture = self.mutate_lock(
            lambda value: self.profile(value, "envoy-ext-authz").update({"arch": "arm64"})
        )
        self.assertEqual(architecture.returncode, 77)
        self.assertIn("unsupported platform", architecture.stderr)

        asset = self.mutate_lock(
            lambda value: self.profile(value, "traefik-forwardauth").update(
                {"asset_name": "traefik_v3.7.10_linux_arm64.tar.gz"}
            )
        )
        self.assertEqual(asset.returncode, 77)
        self.assertIn("asset does not match", asset.stderr)

    def test_missing_or_invalid_sha256_is_blocked(self):
        for digest in ("", "not-a-sha256"):
            with self.subTest(digest=digest):
                result = self.mutate_lock(
                    lambda value, digest=digest: self.profile(value, "haproxy-spoe-spop").update(
                        {"sha256": digest}
                    )
                )
                self.assertEqual(result.returncode, 77)
                self.assertIn("SHA-256 is missing or invalid", result.stderr)

    def test_runtime_manifest_drift_is_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.json"
            value = json.loads(MANIFEST.read_text(encoding="utf-8"))
            next(item for item in value["components"] if item["name"] == "envoy")[
                "version"
            ] = "1.38.2"
            manifest.write_text(json.dumps(value), encoding="utf-8")
            result = self.run_checker(manifest=manifest)
        self.assertEqual(result.returncode, 77)
        self.assertIn("manifest envoy version drift", result.stderr)

    def test_runtime_environment_overrides_must_match_the_locked_profile(self):
        accepted = self.run_checker(
            extra_args=(
                "--environment-profile", "envoy-ext-authz",
                "--environment-value", "ENVOY_VERSION=1.39.0",
                "--environment-value", "ENVOY_DOWNLOAD_URL=https://github.com/envoyproxy/envoy/releases/download/v1.39.0/envoy-1.39.0-linux-x86_64",
                "--environment-value", "ENVOY_SHA256=4409dadc87931d8f8676314cbd83071cb65125fb4feac3f6335800580dfa9218",
            )
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)

        rejected = self.run_checker(
            extra_args=(
                "--environment-profile", "envoy-ext-authz",
                "--environment-value", "ENVOY_VERSION=1.38.2",
                "--environment-value", "ENVOY_DOWNLOAD_URL=https://github.com/envoyproxy/envoy/releases/download/v1.39.0/envoy-1.39.0-linux-x86_64",
                "--environment-value", "ENVOY_SHA256=4409dadc87931d8f8676314cbd83071cb65125fb4feac3f6335800580dfa9218",
            )
        )
        self.assertEqual(rejected.returncode, 77)
        self.assertIn("ENVOY_VERSION drift", rejected.stderr)

    def test_nginx_runtime_environment_must_match_the_locked_profile(self):
        accepted = self.run_checker(
            extra_args=(
                "--environment-profile", "nginx-h1",
                "--environment-value", "NGINX_RELEASE_TAG=release-1.31.3",
                "--environment-value", "NGINX_RELEASE_ASSET_NAME=nginx-1.31.3.tar.gz",
                "--environment-value", "NGINX_SHA256=a7657c50811c2d92d9895395e8b873ef60398142c4db21eb647811c38f6dd525",
            )
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)

        rejected = self.run_checker(
            extra_args=(
                "--environment-profile", "nginx-h1",
                "--environment-value", "NGINX_RELEASE_TAG=release-1.31.2",
                "--environment-value", "NGINX_RELEASE_ASSET_NAME=nginx-1.31.3.tar.gz",
                "--environment-value", "NGINX_SHA256=a7657c50811c2d92d9895395e8b873ef60398142c4db21eb647811c38f6dd525",
            )
        )
        self.assertEqual(rejected.returncode, 77)
        self.assertIn("NGINX_RELEASE_TAG drift", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
