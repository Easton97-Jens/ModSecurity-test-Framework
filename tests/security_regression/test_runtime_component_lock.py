from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "ci/tools/check-runtime-component-lock.py"
SYNCHRONIZER = ROOT / "ci/tools/sync-runtime-components.py"
LOCK = ROOT / "ci/provisioning/runtime-component-lock.json"
COMMON = ROOT / "ci/lib/common.sh"
MANIFEST = ROOT / "ci/provisioning/runtime-components.manifest.json"


class RuntimeComponentLockTests(unittest.TestCase):
    def run_checker(
        self,
        checker: Path = CHECKER,
        lock: Path = LOCK,
        common: Path = COMMON,
        manifest: Path = MANIFEST,
        extra_args: tuple[str, ...] = (),
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(checker),
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
            fixture = Path(directory)
            (fixture / "ci/lib").mkdir(parents=True)
            (fixture / "ci/provisioning").mkdir()
            (fixture / "ci/tools").mkdir()
            common = fixture / "ci/lib/common.sh"
            checker = fixture / "ci/tools/check-runtime-component-lock.py"
            synchronizer = fixture / "ci/tools/sync-runtime-components.py"
            manifest = fixture / "ci/provisioning/runtime-components.manifest.json"
            lock = fixture / "ci/provisioning/runtime-component-lock.json"
            shutil.copy2(COMMON, common)
            shutil.copy2(CHECKER, checker)
            shutil.copy2(SYNCHRONIZER, synchronizer)
            shutil.copy2(MANIFEST, manifest)
            value = json.loads(LOCK.read_text(encoding="utf-8"))
            mutation(value)
            lock.write_text(json.dumps(value), encoding="utf-8")
            return self.run_checker(checker, lock, common, manifest)

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

    def test_profile_inventory_rejects_missing_duplicate_and_unknown_profiles(self):
        cases = (
            ("missing", lambda value: value["profiles"].pop()),
            ("duplicate", lambda value: value["profiles"].append(value["profiles"][0].copy())),
            ("unknown", lambda value: value["profiles"].append({"id": "future-runtime"})),
        )
        for label, mutation in cases:
            with self.subTest(label=label):
                result = self.mutate_lock(mutation)
                self.assertEqual(result.returncode, 77)
                self.assertIn("lock profiles mismatch", result.stderr)

    def test_manifest_missing_unknown_or_duplicate_component_is_blocked(self):
        for label, mutation, expected in (
            (
                "missing",
                lambda value: value["components"].pop(),
                "manifest is missing",
            ),
            (
                "unknown",
                lambda value: value["components"].append({"name": "future-runtime"}),
                "unknown component",
            ),
            (
                "duplicate",
                lambda value: value["components"].append(value["components"][0].copy()),
                "duplicate component",
            ),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                fixture = Path(directory)
                (fixture / "ci/lib").mkdir(parents=True)
                (fixture / "ci/provisioning").mkdir()
                (fixture / "ci/tools").mkdir()
                common = fixture / "ci/lib/common.sh"
                checker = fixture / "ci/tools/check-runtime-component-lock.py"
                synchronizer = fixture / "ci/tools/sync-runtime-components.py"
                lock = fixture / "ci/provisioning/runtime-component-lock.json"
                manifest = fixture / "ci/provisioning/runtime-components.manifest.json"
                shutil.copy2(COMMON, common)
                shutil.copy2(CHECKER, checker)
                shutil.copy2(SYNCHRONIZER, synchronizer)
                shutil.copy2(LOCK, lock)
                value = json.loads(MANIFEST.read_text(encoding="utf-8"))
                mutation(value)
                manifest.write_text(json.dumps(value), encoding="utf-8")
                result = self.run_checker(checker, lock, common, manifest)
            self.assertEqual(result.returncode, 77)
            self.assertIn(expected, result.stderr)

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

    def test_same_filename_from_a_different_download_host_is_blocked(self):
        result = self.mutate_lock(
            lambda value: self.profile(value, "envoy-ext-authz").update(
                {
                    "download_url": (
                        "https://mirror.invalid/envoy-1.39.0-linux-x86_64"
                    )
                }
            )
        )
        self.assertEqual(result.returncode, 77)
        self.assertIn("envoy-ext-authz download URL drift", result.stderr)

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
            fixture = Path(directory)
            (fixture / "ci/lib").mkdir(parents=True)
            (fixture / "ci/provisioning").mkdir()
            (fixture / "ci/tools").mkdir()
            common = fixture / "ci/lib/common.sh"
            checker = fixture / "ci/tools/check-runtime-component-lock.py"
            synchronizer = fixture / "ci/tools/sync-runtime-components.py"
            lock = fixture / "ci/provisioning/runtime-component-lock.json"
            manifest = fixture / "ci/provisioning/runtime-components.manifest.json"
            shutil.copy2(COMMON, common)
            shutil.copy2(CHECKER, checker)
            shutil.copy2(SYNCHRONIZER, synchronizer)
            shutil.copy2(LOCK, lock)
            value = json.loads(MANIFEST.read_text(encoding="utf-8"))
            next(item for item in value["components"] if item["name"] == "envoy")[
                "version"
            ] = "1.38.2"
            manifest.write_text(json.dumps(value), encoding="utf-8")
            result = self.run_checker(checker, lock, common, manifest)
        self.assertEqual(result.returncode, 77)
        self.assertIn("manifest envoy version drift", result.stderr)

    def test_lock_and_manifest_must_stay_under_the_framework_source_root(self):
        with tempfile.TemporaryDirectory() as directory:
            outside = Path(directory) / "outside.json"
            outside.write_text(LOCK.read_text(encoding="utf-8"), encoding="utf-8")
            result = self.run_checker(lock=outside)
        self.assertEqual(result.returncode, 77)
        self.assertIn("below the Framework source root", result.stderr)

    def test_symlinked_lock_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            (fixture / "ci/lib").mkdir(parents=True)
            (fixture / "ci/provisioning").mkdir()
            (fixture / "ci/tools").mkdir()
            common = fixture / "ci/lib/common.sh"
            checker = fixture / "ci/tools/check-runtime-component-lock.py"
            synchronizer = fixture / "ci/tools/sync-runtime-components.py"
            manifest = fixture / "ci/provisioning/runtime-components.manifest.json"
            lock = fixture / "ci/provisioning/runtime-component-lock.json"
            target = fixture / "lock-target.json"
            shutil.copy2(COMMON, common)
            shutil.copy2(CHECKER, checker)
            shutil.copy2(SYNCHRONIZER, synchronizer)
            shutil.copy2(MANIFEST, manifest)
            shutil.copy2(LOCK, target)
            lock.symlink_to(target)
            result = self.run_checker(checker, lock, common, manifest)
        self.assertEqual(result.returncode, 77)
        self.assertIn("below the Framework source root", result.stderr)

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
