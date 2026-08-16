from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "ci/tools/sync-runtime-components.py"
MANIFEST = ROOT / "ci/provisioning/runtime-components.manifest.json"
LOCK = ROOT / "ci/provisioning/runtime-component-lock.json"
COMMON = ROOT / "ci/lib/common.sh"


class RuntimeComponentSyncTests(unittest.TestCase):
    def run_tool(
        self, mode: str, *, common=COMMON, manifest=MANIFEST, lock=LOCK, test_root=None
    ):
        if test_root is None and common != COMMON:
            test_root = common.parents[2]
        command = [
            sys.executable,
            str(TOOL),
            mode,
            "--common-sh",
            str(common),
            "--manifest",
            str(manifest),
            "--lock",
            str(lock),
        ]
        if test_root is not None and test_root is not False:
            command.extend(["--test-root", str(test_root)])
        return subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        common = root / "ci/lib/common.sh"
        manifest = root / "ci/provisioning/runtime-components.manifest.json"
        lock = root / "ci/provisioning/runtime-component-lock.json"
        common.parent.mkdir(parents=True)
        manifest.parent.mkdir(parents=True)
        shutil.copy2(COMMON, common)
        shutil.copy2(MANIFEST, manifest)
        shutil.copy2(LOCK, lock)
        return temporary, common, manifest, lock

    @staticmethod
    def load(path):
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def dump(path, document):
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    def test_checked_in_inventory_is_current_and_includes_lighttpd(self):
        result = self.run_tool("--check")
        self.assertEqual(result.returncode, 0, result.stderr)
        lock = json.loads(LOCK.read_text(encoding="utf-8"))
        profiles = {p["id"]: p for p in lock["profiles"]}
        self.assertEqual(
            set(profiles),
            {
                "nginx-h1",
                "haproxy-htx",
                "haproxy-spoe-spop",
                "envoy-ext-authz",
                "envoy-ext-proc",
                "traefik-forwardauth",
                "traefik-native",
                "lighttpd-sidecar",
            },
        )
        self.assertIn("lighttpd-sidecar", profiles)
        self.assertNotEqual(
            profiles["haproxy-htx"]["version"], profiles["haproxy-spoe-spop"]["version"]
        )
        self.assertNotEqual(
            profiles["haproxy-htx"]["sha256"], profiles["haproxy-spoe-spop"]["sha256"]
        )
        self.assertNotEqual(
            profiles["haproxy-htx"]["download_url"],
            profiles["haproxy-spoe-spop"]["download_url"],
        )
        self.assertEqual(
            profiles["haproxy-htx"]["source_url"],
            profiles["haproxy-htx"]["download_url"],
        )
        self.assertEqual(
            profiles["lighttpd-sidecar"]["asset_name"], "lighttpd-1.4.85.tar.xz"
        )

        manifest = self.load(MANIFEST)
        lighttpd = next(
            item for item in manifest["components"] if item["name"] == "lighttpd"
        )
        self.assertTrue(
            lighttpd["sha256_url"].endswith(f"lighttpd-{lighttpd['version']}.sha256sum")
        )
        self.assertEqual(
            lighttpd["source_stage_dir"],
            "$BUILD_ROOT/lighttpd-connector/src/lighttpd-1.4.85",
        )

    def test_write_is_idempotent(self):
        temporary, common, manifest, lock = self.fixture()
        with temporary:
            document = self.load(manifest)
            lighttpd = next(
                item for item in document["components"] if item["name"] == "lighttpd"
            )
            lighttpd["operator_note"] = "fixture metadata must survive synchronization"
            lighttpd["version"] = "1.4.84"
            self.dump(manifest, document)
            result = self.run_tool(
                "--write",
                common=common,
                manifest=manifest,
                lock=lock,
                test_root=common.parents[2],
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            synchronized = self.load(manifest)
            synchronized_lighttpd = next(
                item
                for item in synchronized["components"]
                if item["name"] == "lighttpd"
            )
            self.assertEqual(
                synchronized_lighttpd["operator_note"],
                "fixture metadata must survive synchronization",
            )
            self.assertEqual(synchronized_lighttpd["version"], "1.4.85")
            self.assertEqual(
                self.run_tool(
                    "--check",
                    common=common,
                    manifest=manifest,
                    lock=lock,
                    test_root=common.parents[2],
                ).returncode,
                0,
            )
            manifest_bytes = manifest.read_bytes()
            lock_bytes = lock.read_bytes()
            second = self.run_tool(
                "--write",
                common=common,
                manifest=manifest,
                lock=lock,
                test_root=common.parents[2],
            )
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(manifest_bytes, manifest.read_bytes())
            self.assertEqual(lock_bytes, lock.read_bytes())

    def test_nested_symlink_metadata_parent_is_rejected(self):
        temporary, common, manifest, lock = self.fixture()
        with temporary:
            outside = Path(tempfile.mkdtemp())
            outside_manifest = outside / "runtime-components.manifest.json"
            shutil.copy2(manifest, outside_manifest)
            manifest.unlink()
            manifest.symlink_to(outside_manifest)
            result = self.run_tool(
                "--check",
                common=common,
                manifest=manifest,
                lock=lock,
                test_root=common.parents[2],
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("manifest", result.stderr)

    def test_common_symlink_and_parent_escape_are_rejected_before_read(self):
        temporary, common, manifest, lock = self.fixture()
        with temporary:
            outside = Path(tempfile.mkdtemp())
            outside_common = outside / "common.sh"
            shutil.copy2(common, outside_common)
            common.unlink()
            common.symlink_to(outside_common)
            symlink_result = self.run_tool(
                "--check",
                common=common,
                manifest=manifest,
                lock=lock,
                test_root=common.parents[2],
            )
            self.assertNotEqual(symlink_result.returncode, 0)
            self.assertIn("common", symlink_result.stderr)

            common.unlink()
            shutil.copy2(COMMON, common)
            escaped_manifest = outside / "outside-manifest.json"
            shutil.copy2(manifest, escaped_manifest)
            escape_result = self.run_tool(
                "--check",
                common=common,
                manifest=escaped_manifest,
                lock=lock,
                test_root=common.parents[2],
            )
            self.assertNotEqual(escape_result.returncode, 0)
            self.assertIn("manifest", escape_result.stderr)

    def test_external_canonical_shaped_common_requires_explicit_test_root(self):
        temporary, common, manifest, lock = self.fixture()
        with temporary:
            result = self.run_tool(
                "--check",
                common=common,
                manifest=manifest,
                lock=lock,
                test_root=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("approved Framework checkout", result.stderr)

    def test_haproxy_release_root_must_be_the_official_root(self):
        temporary, common, manifest, lock = self.fixture()
        with temporary:
            source = common.read_text(encoding="utf-8")
            source = source.replace(
                'HAPROXY_RELEASE_ROOT_URL="https://www.haproxy.org/download"',
                'HAPROXY_RELEASE_ROOT_URL="https://attacker.example/download"',
                1,
            )
            common.write_text(source, encoding="utf-8")
            result = self.run_tool(
                "--check", common=common, manifest=manifest, lock=lock
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("official root", result.stderr)

    def test_common_pin_mutations_are_rejected(self):
        mutations = {
            'ENVOY_VERSION="1.39.0"': 'ENVOY_VERSION="1.39.1"',
            'ENVOY_SOURCE_URL="https://github.com/envoyproxy/envoy/releases"': 'ENVOY_SOURCE_URL="https://example.invalid/envoy/releases"',
            'ENVOY_SHA256="4409dadc87931d8f8676314cbd83071cb65125fb4feac3f6335800580dfa9218"': 'ENVOY_SHA256="0009dadc87931d8f8676314cbd83071cb65125fb4feac3f6335800580dfa9218"',
        }
        for needle, replacement in mutations.items():
            with self.subTest(needle=needle):
                temporary, common, manifest, lock = self.fixture()
                with temporary:
                    source = common.read_text(encoding="utf-8")
                    self.assertIn(needle, source)
                    common.write_text(
                        source.replace(needle, replacement, 1), encoding="utf-8"
                    )
                    result = self.run_tool(
                        "--check", common=common, manifest=manifest, lock=lock
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_explicit_release_series_and_derived_urls_are_projected(self):
        result = self.run_tool("--check")
        self.assertEqual(result.returncode, 0, result.stderr)
        lock = self.load(LOCK)
        profiles = {item["id"]: item for item in lock["profiles"]}
        self.assertEqual(profiles["haproxy-spoe-spop"]["series"], "3.2")
        self.assertEqual(profiles["haproxy-htx"]["series"], "3.2")
        self.assertEqual(profiles["lighttpd-sidecar"]["series"], "1.4")
        lighttpd = next(
            item
            for item in self.load(MANIFEST)["components"]
            if item["name"] == "lighttpd"
        )
        self.assertEqual(
            lighttpd["release_root_url"], "https://download.lighttpd.net/lighttpd"
        )
        self.assertEqual(
            lighttpd["series_base_url"],
            "https://download.lighttpd.net/lighttpd/releases-1.4.x",
        )
        self.assertNotIn("//latest.txt", lighttpd["latest_url"])

    def test_series_version_mismatch_and_malformed_series_are_rejected(self):
        mutations = {
            'LIGHTTPD_SERIES="1.4"': 'LIGHTTPD_SERIES="1.5"',
            'HAPROXY_SERIES="3.2"': 'HAPROXY_SERIES="3.x"',
            'HAPROXY_HTX_VERSION="3.2.21"': 'HAPROXY_HTX_VERSION="2.2.21"',
        }
        for needle, replacement in mutations.items():
            with self.subTest(needle=needle):
                temporary, common, manifest, lock = self.fixture()
                with temporary:
                    source = common.read_text(encoding="utf-8")
                    self.assertIn(needle, source)
                    common.write_text(
                        source.replace(needle, replacement, 1), encoding="utf-8"
                    )
                    result = self.run_tool(
                        "--check", common=common, manifest=manifest, lock=lock
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_common_sh_series_guard_rejects_mutation_before_runtime_use(self):
        command = (
            f'. "{COMMON}"; LIGHTTPD_VERSION=1.5.85; ci_validate_runtime_series_config'
        )
        result = subprocess.run(
            ["sh", "-c", command], cwd=ROOT, text=True, capture_output=True, check=False
        )
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertIn("does not match declared series", result.stdout)

    def test_platforms_are_rendered_from_canonical_artifact_platform_variables(self):
        temporary, common, manifest, lock = self.fixture()
        with temporary:
            source = common.read_text(encoding="utf-8")
            source = source.replace(
                'ENVOY_ARTIFACT_PLATFORM="linux-x86_64"',
                'ENVOY_ARTIFACT_PLATFORM="linux_arm64"',
                1,
            ).replace(
                'TRAEFIK_ARTIFACT_PLATFORM="linux_amd64"',
                'TRAEFIK_ARTIFACT_PLATFORM="linux_arm64"',
                1,
            )
            common.write_text(source, encoding="utf-8")
            result = self.run_tool(
                "--write", common=common, manifest=manifest, lock=lock
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            rendered_lock = self.load(lock)
            self.assertEqual(rendered_lock["platform"], "linux-arm64")
            self.assertTrue(
                all(item["os"] == "linux" for item in rendered_lock["profiles"])
            )
            self.assertTrue(
                all(item["arch"] == "arm64" for item in rendered_lock["profiles"])
            )
            rendered_manifest = self.load(manifest)
            platforms = {
                item["name"]: item["artifact_platform"]
                for item in rendered_manifest["components"]
                if "artifact_platform" in item
            }
            self.assertEqual(
                platforms, {"envoy": "linux/arm64", "traefik": "linux/arm64"}
            )

    def test_malicious_top_level_common_line_is_not_executed(self):
        temporary, common, manifest, lock = self.fixture()
        with temporary:
            marker = common.parents[2] / "parser-must-not-execute"
            source = common.read_text(encoding="utf-8")
            common.write_text(source + f"\ntouch {marker}\n", encoding="utf-8")
            result = self.run_tool(
                "--check", common=common, manifest=manifest, lock=lock
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(marker.exists(), "the parser must never source common.sh")

    def test_disallowed_assignment_expression_is_rejected_without_execution(self):
        temporary, common, manifest, lock = self.fixture()
        with temporary:
            marker = common.parents[2] / "disallowed-assignment-expression"
            source = common.read_text(encoding="utf-8")
            common.write_text(
                source + f'\nENVOY_VERSION="$(touch {marker}; printf 1.39.0)"\n',
                encoding="utf-8",
            )
            result = self.run_tool(
                "--check", common=common, manifest=manifest, lock=lock
            )
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertIn("malformed canonical assignment", result.stderr)
            self.assertFalse(marker.exists(), "the parser must never source common.sh")

    def test_lock_manifest_digest_platform_and_asset_mutations_are_rejected(self):
        lock_mutations = {
            "platform": lambda d: d.__setitem__("platform", "linux-arm64"),
            "os": lambda d: d["profiles"][0].__setitem__("os", "windows"),
            "arch": lambda d: d["profiles"][0].__setitem__("arch", "arm64"),
            "asset": lambda d: d["profiles"][0].__setitem__(
                "asset_name", "wrong.tar.gz"
            ),
            "digest": lambda d: d["profiles"][0].__setitem__("sha256", "0" * 64),
        }
        for label, mutate in lock_mutations.items():
            with self.subTest(lock_field=label):
                temporary, common, manifest, lock = self.fixture()
                with temporary:
                    document = self.load(lock)
                    mutate(document)
                    self.dump(lock, document)
                    result = self.run_tool(
                        "--check", common=common, manifest=manifest, lock=lock
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout)
        manifest_mutations = {
            "version": lambda i: i.__setitem__("version", "1.4.84"),
            "digest": lambda i: i.__setitem__("sha256", "0" * 64),
            "download": lambda i: i.__setitem__(
                "download_url", "https://example.invalid/lighttpd.tar.xz"
            ),
            "asset": lambda i: i.__setitem__("archive_name", "lighttpd-1.4.84.tar.xz"),
        }
        for label, mutate in manifest_mutations.items():
            with self.subTest(manifest_field=label):
                temporary, common, manifest, lock = self.fixture()
                with temporary:
                    document = self.load(manifest)
                    lighttpd = next(
                        item
                        for item in document["components"]
                        if item["name"] == "lighttpd"
                    )
                    mutate(lighttpd)
                    self.dump(manifest, document)
                    result = self.run_tool(
                        "--check", common=common, manifest=manifest, lock=lock
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_missing_duplicate_and_unknown_lock_coverage_is_rejected(self):
        for label in ("missing", "duplicate", "unknown"):
            with self.subTest(coverage=label):
                temporary, common, manifest, lock = self.fixture()
                with temporary:
                    document = self.load(lock)
                    if label == "missing":
                        document["profiles"].pop()
                    else:
                        profile = dict(document["profiles"][0])
                        if label == "unknown":
                            profile["id"] = "unknown-profile"
                        document["profiles"].append(profile)
                    self.dump(lock, document)
                    result = self.run_tool(
                        "--check", common=common, manifest=manifest, lock=lock
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_unknown_manifest_component_reports_coverage_error(self):
        temporary, common, manifest, lock = self.fixture()
        with temporary:
            document = self.load(manifest)
            document["components"].append({"name": "unknown-component"})
            self.dump(manifest, document)
            result = self.run_tool(
                "--check", common=common, manifest=manifest, lock=lock
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("unknown", result.stderr)

    def test_duplicate_manifest_component_reports_coverage_error(self):
        temporary, common, manifest, lock = self.fixture()
        with temporary:
            document = self.load(manifest)
            document["components"].append(dict(document["components"][0]))
            self.dump(manifest, document)
            result = self.run_tool(
                "--check", common=common, manifest=manifest, lock=lock
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("duplicate", result.stderr)

    def test_missing_manifest_component_reports_coverage_error(self):
        temporary, common, manifest, lock = self.fixture()
        with temporary:
            document = self.load(manifest)
            document["components"] = [
                item for item in document["components"] if item["name"] != "envoy"
            ]
            self.dump(manifest, document)
            result = self.run_tool(
                "--check", common=common, manifest=manifest, lock=lock
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("coverage", result.stderr)


if __name__ == "__main__":
    unittest.main()
