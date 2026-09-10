from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.security_regression.common_version_fixture_support import (
    read_single_common_assignment,
    replace_single_common_assignment,
)

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

    def assert_mutations_rejected(self, mutations):
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
        self.assertEqual(profiles["haproxy-htx"]["profile"], "htx")
        self.assertEqual(profiles["haproxy-spoe-spop"]["profile"], "spoe/spop")
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

    def test_haproxy_profiles_remain_distinct_when_their_release_values_coincide(self):
        temporary, common, manifest, lock = self.fixture()
        with temporary:
            source = common.read_text(encoding="utf-8")
            source = replace_single_common_assignment(
                source,
                "HAPROXY_HTX_VERSION",
                read_single_common_assignment(source, "HAPROXY_VERSION"),
            )
            source = replace_single_common_assignment(
                source,
                "HAPROXY_HTX_SHA256",
                read_single_common_assignment(source, "HAPROXY_SHA256"),
            )
            common.write_text(source, encoding="utf-8")
            result = self.run_tool(
                "--write", common=common, manifest=manifest, lock=lock
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            profiles = {item["id"]: item for item in self.load(lock)["profiles"]}
            htx = profiles["haproxy-htx"]
            generic = profiles["haproxy-spoe-spop"]
            self.assertEqual(htx["profile"], "htx")
            self.assertEqual(generic["profile"], "spoe/spop")
            self.assertEqual(htx["version"], generic["version"])
            self.assertEqual(htx["sha256"], generic["sha256"])
            self.assertEqual(htx["download_url"], generic["download_url"])

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
        source = COMMON.read_text(encoding="utf-8")
        envoy_version = read_single_common_assignment(source, "ENVOY_VERSION")
        envoy_source_url = read_single_common_assignment(source, "ENVOY_SOURCE_URL")
        envoy_sha256 = read_single_common_assignment(source, "ENVOY_SHA256")
        version_prefix, version_patch = envoy_version.rsplit(".", 1)
        drifted_version = f"{version_prefix}.{int(version_patch) + 1}"
        drifted_sha256 = f"{'1' if envoy_sha256[0] == '0' else '0'}{envoy_sha256[1:]}"
        mutations = {
            f'ENVOY_VERSION="{envoy_version}"': f'ENVOY_VERSION="{drifted_version}"',
            f'ENVOY_SOURCE_URL="{envoy_source_url}"': 'ENVOY_SOURCE_URL="https://example.invalid/envoy/releases"',
            f'ENVOY_SHA256="{envoy_sha256}"': f'ENVOY_SHA256="{drifted_sha256}"',
        }
        self.assert_mutations_rejected(mutations)

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
        source = COMMON.read_text(encoding="utf-8")
        lighttpd_series = read_single_common_assignment(source, "LIGHTTPD_SERIES")
        haproxy_series = read_single_common_assignment(source, "HAPROXY_SERIES")
        haproxy_htx_version = read_single_common_assignment(
            source, "HAPROXY_HTX_VERSION"
        )
        lighttpd_major, lighttpd_minor = lighttpd_series.rsplit(".", 1)
        htx_major, htx_remainder = haproxy_htx_version.split(".", 1)
        drifted_htx_major = "0" if htx_major != "0" else "1"
        mutations = {
            f'LIGHTTPD_SERIES="{lighttpd_series}"': (
                f'LIGHTTPD_SERIES="{lighttpd_major}.{int(lighttpd_minor) + 1}"'
            ),
            f'HAPROXY_SERIES="{haproxy_series}"': (
                f'HAPROXY_SERIES="{haproxy_series.split(".", 1)[0]}.x"'
            ),
            f'HAPROXY_HTX_VERSION="{haproxy_htx_version}"': (
                f'HAPROXY_HTX_VERSION="{drifted_htx_major}.{htx_remainder}"'
            ),
        }
        self.assert_mutations_rejected(mutations)

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
