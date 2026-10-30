"""Regression tests for the static Framework-to-Parent pin synchronizer."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import hashlib
import copy
import json
import os
from pathlib import Path
import py_compile
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from modsecurity_connector_tests.framework_component_fixture import set_framework_component_fixture
from modsecurity_connector_tests.framework_sha_fixture import set_framework_sha_fixture
from modsecurity_connector_ci.lib import active_inventory_updates as inventory_updates
from modsecurity_connector_ci.lib.active_test_inventory import load_inventory


ROOT = connector_root()
SYNC = load_source(source_path('ci/tools/sync-framework-component-versions.py', root=ROOT))


CANDIDATE_GRAMMAR_PROVENANCE = "d4f7b69dc264852eac74e1439c0887fcb9fbe372"
TEST_PARENT_FRAMEWORK_SHA = "b" * 40
NEW_FRAMEWORK_SHA = "a" * 40

# This is an offline grammar fixture. The SHA identifies the reproduced
# Framework candidate's assignment structure only; it is never an input or
# allowlisted version value.
CURRENT_CANDIDATE_COMMON = """\
ENVOY_VERSION="1.39.1"
LIGHTTPD_SERIES="1.4"
LIGHTTPD_RELEASE_ROOT_URL="https://download.lighttpd.net/lighttpd"
LIGHTTPD_SERIES_BASE_URL="$LIGHTTPD_RELEASE_ROOT_URL/releases-$LIGHTTPD_SERIES.x"
LIGHTTPD_VERSION="1.4.85"
LIGHTTPD_SOURCE_URL="$LIGHTTPD_SERIES_BASE_URL/"
LIGHTTPD_ARCHIVE_NAME="lighttpd-$LIGHTTPD_VERSION.tar.xz"
LIGHTTPD_DOWNLOAD_URL="$LIGHTTPD_SOURCE_URL$LIGHTTPD_ARCHIVE_NAME"
LIGHTTPD_SHA256="18de51b393bac4a6827879e1a7ff377c169e414bae92cd245091d80fc2601d13"
HAPROXY_SERIES="3.2"
HAPROXY_RELEASE_ROOT_URL="https://www.haproxy.org/download"
HAPROXY_SERIES_BASE_URL="$HAPROXY_RELEASE_ROOT_URL/$HAPROXY_SERIES/src"
HAPROXY_VERSION="3.2.23"
HAPROXY_ARCHIVE_NAME="haproxy-$HAPROXY_VERSION.tar.gz"
HAPROXY_SOURCE_URL="$HAPROXY_SERIES_BASE_URL/$HAPROXY_ARCHIVE_NAME"
HAPROXY_SHA256="82d14ef33571e4edeb9197516c0d058a3775fb80541e46afe4377428e461fef0"
HAPROXY_HTX_SERIES="3.2"
HAPROXY_HTX_SERIES_BASE_URL="$HAPROXY_RELEASE_ROOT_URL/$HAPROXY_HTX_SERIES/src"
HAPROXY_HTX_VERSION="3.2.23"
HAPROXY_HTX_ARCHIVE_NAME="haproxy-$HAPROXY_HTX_VERSION.tar.gz"
HAPROXY_HTX_SOURCE_URL="$HAPROXY_HTX_SERIES_BASE_URL/$HAPROXY_HTX_ARCHIVE_NAME"
HAPROXY_HTX_SHA256="82d14ef33571e4edeb9197516c0d058a3775fb80541e46afe4377428e461fef0"
NGINX_SOURCE_MODE="github-release"
NGINX_SOURCE_REPO_URL="https://github.com/nginx/nginx"
NGINX_RELEASE_TAG="release-1.31.6"
NGINX_SOURCE_GIT_REF="$NGINX_RELEASE_TAG"
NGINX_RELEASE_ASSET_NAME="nginx-${NGINX_RELEASE_TAG#release-}.tar.gz"
NGINX_SHA256="974ed5298a5e398e008704ed5db284e655fc270c596493dbccada452448fc9f1"
NGINX_QUIC_TLS_LIBRARY="${NGINX_QUIC_TLS_LIBRARY:-openssl}"
NGINX_QUIC_TLS_VERSION="4.0.1"
NGINX_QUIC_TLS_ARCHIVE_NAME="openssl-$NGINX_QUIC_TLS_VERSION.tar.gz"
NGINX_QUIC_TLS_SOURCE_URL="https://github.com/openssl/openssl/releases/download/openssl-$NGINX_QUIC_TLS_VERSION/$NGINX_QUIC_TLS_ARCHIVE_NAME"
NGINX_QUIC_TLS_SOURCE_SHA256="2db3f3a0d6ea4b59e1f094ace2c8cd536dffb87cdc39084c5afa1e6f7f37dd09"
CRS_APPROVED_REPO_URL="https://github.com/coreruleset/coreruleset.git"
CRS_APPROVED_COMMIT="ab3ccd5fcd691424ba3f320d4040c61417270193"
CRS_RELEASE_TAG="v4.29.0"
MODSECURITY_V3_APPROVED_REPO_URL="https://github.com/owasp-modsecurity/ModSecurity.git"
MODSECURITY_V3_APPROVED_COMMIT="7ea9fefbe0ba409d8733b4d682c8c4c059cd028d"
MODSECURITY_V3_RELEASE_TAG="v3.0.16"
"""


def replace_rhs(common: str, name: str, rhs: str) -> str:
    replacement = f"{name}={rhs}"
    updated, count = re.subn(
        rf"(?m)^{re.escape(name)}=.*$",
        lambda _match: replacement,
        common,
    )
    if count != 1:
        raise ValueError(f"missing or duplicate fixture assignment: {name}")
    return updated


def future_series_common() -> str:
    common = CURRENT_CANDIDATE_COMMON
    for name, rhs in (
        ("LIGHTTPD_SERIES", '"1.5"'),
        ("LIGHTTPD_VERSION", '"1.5.0"'),
        ("LIGHTTPD_SHA256", '"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"'),
        ("HAPROXY_SERIES", '"3.3"'),
        ("HAPROXY_VERSION", '"3.3.1"'),
        ("HAPROXY_SHA256", '"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"'),
        ("HAPROXY_HTX_VERSION", '"3.2.24"'),
        ("HAPROXY_HTX_SHA256", '"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"'),
    ):
        common = replace_rhs(common, name, rhs)
    return common


class SyncFrameworkVersionsTests(unittest.TestCase):
    def setUp(self) -> None:
        runner_temp = os.environ.get("RUNNER_TEMP")
        temporary_root = runner_temp if runner_temp and Path(runner_temp).is_dir() else None
        self.temp = tempfile.TemporaryDirectory(dir=temporary_root)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        shutil.copytree(
            ROOT,
            self.root,
            ignore=shutil.ignore_patterns(
                ".git", "ModSecurity-test-Framework", "__pycache__", ".pytest_cache", ".rsync-tmp"
            ),
        )
        # These legacy grammar fixtures deliberately reset independent pins.
        # They do not claim an admitted Parent inventory. Companion-specific
        # regressions below construct a fresh admitted selection explicitly.
        for relative in inventory_updates.COMPANIONS:
            (self.root / relative).unlink(missing_ok=True)
        # Test identities are independent of both live pins and grammar provenance.
        set_framework_sha_fixture(self.root, TEST_PARENT_FRAMEWORK_SHA)
        set_framework_component_fixture(self.root)
        self.common = Path(self.temp.name) / "framework/ci/lib/common.sh"
        self.common.parent.mkdir(parents=True)
        self.write_common(CURRENT_CANDIDATE_COMMON)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_common(self, contents: str) -> None:
        self.common.write_text(contents, encoding="utf-8")

    def target_bytes(self) -> dict[Path, bytes]:
        return {
            self.root / spec.relative_path: (self.root / spec.relative_path).read_bytes()
            for spec in SYNC.TARGET_REGISTRY
        }

    def framework_sha_projection_bytes(self) -> dict[Path, bytes]:
        return {
            self.root / spec.relative_path: (self.root / spec.relative_path).read_bytes()
            for spec in SYNC.FRAMEWORK_SHA_PROJECTION_TARGETS
        }

    def all_target_bytes(self) -> dict[Path, bytes]:
        return self.target_bytes() | self.framework_sha_projection_bytes()

    def install_admitted_inventory(self) -> str:
        """Create a genuine, private trusted-base repository for publication."""
        fixture = self.root / "tests/companion_fixture.py"
        fixture.write_text("import unittest\nclass Control(unittest.TestCase):\n"
                           "    def test_core(self): pass\n    def test_offline(self): pass\n")
        paths = ("tests/companion_fixture.py",
                 "tests/test_compiler_guides.py", "tests/test_prepare_runtime_components.py")
        sources = [{"path": name, "sha256": hashlib.sha256((self.root / name).read_bytes()).hexdigest()}
                   for name in paths]
        def execution(identifier, method):
            return {"id": identifier, "groups": ["offline-unit" if method == "test_offline" else "control"],
                    "sources": list(paths),
                    "selector": {"kind": "python", "target": "tests.companion_fixture.Control." + method},
                    "cases": [{"id": identifier + ".case", "requirement": "Keep the admitted selection.",
                               "profiles": ["parent"]}]}
        core = execution("fixture.core", "test_core")
        offline = execution("offline.fixture", "test_offline")
        offline["expected_subtests"] = 0
        inventory = {"schema_version": 3, "source_bindings": sources,
                     "executions": [core], "offline_unit_exceptions": [offline]}
        (self.root / inventory_updates.INVENTORY).parent.mkdir(parents=True, exist_ok=True)
        (self.root / inventory_updates.INVENTORY).write_text(json.dumps(inventory, indent=2) + "\n")
        self.git("init", "-q")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("add", "--all")
        archive = {"inventory_sha256": hashlib.sha256((self.root / inventory_updates.INVENTORY).read_bytes()).hexdigest(),
                   "sources": [{"source": name, "source_sha256": hashlib.sha256((self.root / name).read_bytes()).hexdigest()}
                               for name in paths]}
        (self.root / inventory_updates.ARCHIVE).parent.mkdir(parents=True, exist_ok=True)
        (self.root / inventory_updates.ARCHIVE).write_text(json.dumps(archive, indent=2, sort_keys=True) + "\n")
        self.git("add", "--all")
        self.git("commit", "-qm", "admitted trusted baseline")
        load_inventory(self.root)
        return self.git("rev-parse", "HEAD").strip()

    def git(self, *arguments: str) -> str:
        return subprocess.check_output(["git", "-C", str(self.root), *arguments], text=True, timeout=30)

    def publication_bytes(self) -> dict[Path, bytes]:
        return self.all_target_bytes() | {self.root / name: (self.root / name).read_bytes()
                                          for name in inventory_updates.COMPANIONS}

    def nginx_owned_bytes(self) -> dict[Path, bytes]:
        relative_paths = (
            ".github/workflows/nginx-root-broker.yml",
            ".github/workflows/test-full-smoke-sequential.yml",
            "ci/checks/evidence/check-runtime-producer-readiness.py",
            "ci/provisioning/components/prepare-runtime-components.py",
            "ci/runtime/broker/nginx_root_broker.py",
            "ci/runtime/broker/protected_nginx_broker_caller.py",
        )
        for relative in relative_paths:
            destination = self.root / relative
            if not destination.exists():
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(source_path(relative, root=ROOT).read_bytes())
        return {
            self.root / relative: (self.root / relative).read_bytes()
            for relative in relative_paths
        }

    def nginx_pin_lines(self) -> dict[Path, tuple[str, ...]]:
        return {
            path: tuple(
                line for line in contents.decode("utf-8").splitlines()
                if "NGINX_" in line
            )
            for path, contents in self.nginx_owned_bytes().items()
        }

    def test_framework_sha_fixture_is_independent_and_byte_idempotent(self) -> None:
        self.assertNotEqual(TEST_PARENT_FRAMEWORK_SHA, CANDIDATE_GRAMMAR_PROVENANCE)
        before = self.all_target_bytes()
        set_framework_sha_fixture(self.root, "c" * 40)
        self.assertNotEqual(before, self.all_target_bytes())
        set_framework_sha_fixture(self.root, TEST_PARENT_FRAMEWORK_SHA)
        self.assertEqual(before, self.all_target_bytes())
        set_framework_sha_fixture(self.root, TEST_PARENT_FRAMEWORK_SHA)
        self.assertEqual(before, self.all_target_bytes())

    def test_framework_sha_fixture_rejects_invalid_lock_without_writes(self) -> None:
        lock = self.root / "ci/tooling/project-versions.lock.json"
        lock.write_text('{"schema_version": 1, "framework_sha": "invalid"}')
        before = self.all_target_bytes()
        with self.assertRaises(ValueError):
            set_framework_sha_fixture(self.root, TEST_PARENT_FRAMEWORK_SHA)
        self.assertEqual(before, self.all_target_bytes())

    def test_framework_sha_fixture_preserves_supported_go_release_versions(self) -> None:
        lock = self.root / "ci/tooling/project-versions.lock.json"
        payload = json.loads(lock.read_text())
        for version in ("1.0.0", "2.0.1"):
            with self.subTest(version=version):
                payload["go_version"] = version
                lock.write_text(json.dumps(payload) + "\n")
                set_framework_sha_fixture(self.root, "c" * 40)
                self.assertEqual(json.loads(lock.read_text())["go_version"], version)

    def test_current_candidate_grammar_fixture_resolves_as_data(self) -> None:
        values = SYNC.parse_common(self.common)
        self.assertEqual(
            CANDIDATE_GRAMMAR_PROVENANCE,
            "d4f7b69dc264852eac74e1439c0887fcb9fbe372",
        )
        self.assertEqual(values["LIGHTTPD_SERIES"], "1.4")
        self.assertEqual(
            values["LIGHTTPD_SERIES_BASE_URL"],
            "https://download.lighttpd.net/lighttpd/releases-1.4.x",
        )
        self.assertEqual(
            values["LIGHTTPD_SOURCE_URL"],
            "https://download.lighttpd.net/lighttpd/releases-1.4.x/",
        )
        self.assertEqual(
            values["LIGHTTPD_DOWNLOAD_URL"],
            "https://download.lighttpd.net/lighttpd/releases-1.4.x/lighttpd-1.4.85.tar.xz",
        )
        self.assertEqual(values["HAPROXY_SOURCE_URL"].split("/")[-2], "src")
        self.assertEqual(values["HAPROXY_HTX_VERSION"], "3.2.23")
        self.assertEqual(
            values["MODSECURITY_V3_APPROVED_REPO_URL"],
            "https://github.com/owasp-modsecurity/ModSecurity.git",
        )
        self.assertEqual(values["MODSECURITY_V3_RELEASE_TAG"], "v3.0.16")
        self.assertEqual(
            values["MODSECURITY_V3_APPROVED_COMMIT"],
            "7ea9fefbe0ba409d8733b4d682c8c4c059cd028d",
        )
        self.assertFalse(any(name.startswith("NGINX_") for name in values))

    def test_unconsumed_framework_pins_are_ignored_as_data(self) -> None:
        self.write_common(
            CURRENT_CANDIDATE_COMMON
            + 'GO_FTW_SERIES="9.9"\nGO_FTW_RELEASE_TAG="$GO_FTW_SERIES"\n'
        )
        values = SYNC.parse_common(self.common)
        self.assertNotIn("GO_FTW_SERIES", values)
        self.assertEqual(values["LIGHTTPD_VERSION"], "1.4.85")

    def test_framework_nginx_assignments_are_unconsumed_data(self) -> None:
        common = CURRENT_CANDIDATE_COMMON
        for name, rhs in (
            ("NGINX_RELEASE_TAG", '"release-9.99.99"'),
            ("NGINX_SOURCE_GIT_REF", '"$(id)"'),
            (
                "NGINX_QUIC_TLS_LIBRARY",
                '"${NGINX_QUIC_TLS_LIBRARY:-attacker}"',
            ),
        ):
            common = replace_rhs(common, name, rhs)
        self.write_common(common)
        values = SYNC.parse_common(self.common)
        self.assertFalse(any(name.startswith("NGINX_") for name in values))
        self.assertFalse(
            any(field.name.startswith("NGINX_") for field in SYNC.SOURCE_REGISTRY)
        )
        self.assertFalse(
            any(
                source_name.startswith("NGINX_")
                for spec in SYNC.TARGET_REGISTRY
                for _target_name, source_name in spec.fields
            )
        )
        self.assertFalse(
            any("nginx" in spec.relative_path.lower() and spec.syntax != "framework-workflow"
                for spec in SYNC.FRAMEWORK_SHA_PROJECTION_TARGETS)
        )

    def test_modsecurity_v3_tuple_projects_only_registered_guide_sources(self) -> None:
        nginx_before = self.nginx_pin_lines()
        common = replace_rhs(
            CURRENT_CANDIDATE_COMMON,
            "MODSECURITY_V3_RELEASE_TAG",
            '"v3.0.17"',
        )
        common = replace_rhs(
            common,
            "MODSECURITY_V3_APPROVED_COMMIT",
            '"1925753989ccce977cdaae417b55c9726c7cf02c"',
        )
        self.write_common(common)
        changed = SYNC.synchronize(self.root, self.common, True)
        self.assertIn("scripts/generate_compiler_guides.py", changed)
        self.assertNotIn("tests/test_compiler_guides.py", changed)
        self.assertIn('MODSECURITY_REF=\\"v3.0.16\\"', (self.root / "tests/test_compiler_guides.py").read_text())
        for relative in ("scripts/generate_compiler_guides.py",):
            rendered = (self.root / relative).read_text(encoding="utf-8")
            self.assertIn('MODSECURITY_REF=\\"v3.0.17\\"', rendered)
            self.assertIn(
                'MODSECURITY_COMMIT=\\"1925753989ccce977cdaae417b55c9726c7cf02c\\"',
                rendered,
            )
        self.assertEqual(nginx_before, self.nginx_pin_lines())

    def test_resolution_budget_rejects_fanout_before_semantic_validation(self) -> None:
        reference = "$LIGHTTPD_SERIES_BASE_URL"
        repetitions = SYNC.MAX_RESOLVED_VALUE_BYTES // len(
            "https://download.lighttpd.net/lighttpd/releases-1.4.x"
        ) + 1
        self.write_common(
            replace_rhs(
                CURRENT_CANDIDATE_COMMON,
                "LIGHTTPD_SOURCE_URL",
                '"' + reference * repetitions + '"',
            )
        )
        self.assertLess(
            len(self.common.read_bytes()), SYNC.MAX_COMMON_BYTES
        )
        with self.assertRaisesRegex(SYNC.SyncError, "byte budget"):
            SYNC.parse_common(self.common)

    def test_resolution_budget_allows_normal_candidate_values(self) -> None:
        values = SYNC.parse_common(self.common)
        self.assertLess(
            sum(len(value) for value in values.values()),
            SYNC.MAX_RESOLVED_TOTAL_BYTES,
        )
        self.assertLess(
            max(map(len, values.values())),
            SYNC.MAX_RESOLVED_VALUE_BYTES,
        )

    def test_positive_future_series_map_and_sync_separates_generic_and_htx(self) -> None:
        nginx_before = self.nginx_pin_lines()
        self.write_common(future_series_common())
        changed = SYNC.synchronize(self.root, self.common, True)
        self.assertTrue(
            {
                "connectors/lighttpd/lighttpd-version.contract",
                "connectors/lighttpd/SOURCE_MAP.json",
                "connectors/haproxy/htx-overlay/version-contract.json",
            }.issubset(changed)
        )
        runtime = (self.root / "ci/provisioning/components/prepare-runtime-components.py").read_text()
        self.assertIn('DEFAULT_NGINX_QUIC_TLS_VERSION = "4.0.1"', runtime)
        self.assertIn('DEFAULT_HAPROXY_VERSION = "3.2.23"', runtime)
        haproxy_tests = (self.root / "tests/test_prepare_runtime_components.py").read_text()
        self.assertIn('TEST_HAPROXY_LOCKED_VERSION = "3.2.23"', haproxy_tests)
        self.assertIn(
            'TEST_HAPROXY_LOCKED_SOURCE_URL = "https://www.haproxy.org/'
            'download/3.2/src/haproxy-3.2.23.tar.gz"',
            haproxy_tests,
        )
        self.assertIn('TEST_HAPROXY_LOCKED_SHA256 = "82d14ef33571e4edeb9197516c0d058a3775fb80541e46afe4377428e461fef0"', haproxy_tests)
        contract = (self.root / "connectors/lighttpd/lighttpd-version.contract").read_text()
        self.assertIn("LIGHTTPD_SERIES=1.5", contract)
        self.assertIn("LIGHTTPD_VERSION=1.5.0", contract)
        self.assertIn(
            "LIGHTTPD_DOWNLOAD_URL=https://download.lighttpd.net/lighttpd/releases-1.5.x/lighttpd-1.5.0.tar.xz",
            contract,
        )
        source_map = json.loads((self.root / "connectors/lighttpd/SOURCE_MAP.json").read_text())
        self.assertEqual(source_map["upstream"]["series"], "1.5")
        self.assertEqual(
            source_map["upstream"]["download_url"],
            "https://download.lighttpd.net/lighttpd/releases-1.5.x/lighttpd-1.5.0.tar.xz",
        )
        htx = json.loads(
            (self.root / "connectors/haproxy/htx-overlay/version-contract.json").read_text()
        )
        self.assertEqual(htx["version"], "3.2.24")
        self.assertEqual(
            htx["source_url"],
            "https://www.haproxy.org/download/3.2/src/haproxy-3.2.24.tar.gz",
        )
        self.assertEqual(
            htx["sha256"],
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        )
        self.assertNotEqual(htx["version"], "3.3.1")
        self.assertNotIn("$", contract)
        self.assertNotIn("$", json.dumps(source_map, sort_keys=True))
        self.assertNotIn("$", json.dumps(htx, sort_keys=True))
        self.assertEqual(nginx_before, self.nginx_pin_lines())
        for relative in (
            "ci/provisioning/components/prepare-runtime-components.py",
            "tests/test_prepare_runtime_components.py",
            "ci/runtime/broker/nginx_root_broker.py",
            "ci/runtime/broker/protected_nginx_broker_caller.py",
        ):
            py_compile.compile(str(self.root / relative), doraise=True)

    def test_framework_nginx_tuple_cannot_change_parent(self) -> None:
        before = self.nginx_owned_bytes()
        common = CURRENT_CANDIDATE_COMMON
        for name, rhs in (
            ("NGINX_SOURCE_MODE", '"untrusted"'),
            ("NGINX_SOURCE_REPO_URL", '"https://evil.example/nginx"'),
            ("NGINX_RELEASE_TAG", '"release-1.31.4"'),
            ("NGINX_SOURCE_GIT_REF", '"release-1.31.4"'),
            ("NGINX_RELEASE_ASSET_NAME", '"nginx-1.31.4.tar.gz"'),
            (
                "NGINX_SHA256",
                '"e6f20b644a17a643f059ae6467a1971fe2811587d025e071068753a1f1e3b3c3"',
            ),
            ("NGINX_QUIC_TLS_VERSION", '"99.0.0"'),
        ):
            common = replace_rhs(common, name, rhs)
        self.write_common(common)
        self.assertEqual(SYNC.synchronize(self.root, self.common, True), [])
        self.assertEqual(before, self.nginx_owned_bytes())

    def test_framework_sha_projection_updates_only_revision_lock(self) -> None:
        """The revision identity now includes explicit remote integration pins."""
        generic_before = self.target_bytes()
        nginx_before = self.nginx_owned_bytes()
        projection_before = self.framework_sha_projection_bytes()
        lock = self.root / "ci/tooling/project-versions.lock.json"
        retained_before = {key: value for key, value in json.loads(lock.read_bytes()).items() if key != "framework_sha"}
        workflows_before = {p: p.read_bytes() for p in (self.root / ".github/workflows").glob("*.yml")}
        expected = [spec.relative_path for spec in SYNC.FRAMEWORK_SHA_PROJECTION_TARGETS]
        self.assertEqual(SYNC.synchronize(self.root, self.common, False, NEW_FRAMEWORK_SHA), expected)
        self.assertEqual(projection_before, self.framework_sha_projection_bytes())
        self.assertEqual(SYNC.synchronize(self.root, self.common, True, NEW_FRAMEWORK_SHA), expected)
        payload = json.loads(lock.read_bytes())
        self.assertEqual(payload["framework_sha"], NEW_FRAMEWORK_SHA)
        self.assertEqual({key: value for key, value in payload.items() if key != "framework_sha"}, retained_before)
        projected = {self.root / spec.relative_path for spec in SYNC.FRAMEWORK_SHA_PROJECTION_TARGETS
                     if spec.syntax == "framework-workflow"}
        self.assertEqual({path: (body.replace(TEST_PARENT_FRAMEWORK_SHA.encode(), NEW_FRAMEWORK_SHA.encode())
                                if path in projected else body)
                          for path, body in workflows_before.items()},
                         {p: p.read_bytes() for p in workflows_before})
        self.assertEqual(generic_before, self.target_bytes())
        self.assertEqual({path: (body.replace(TEST_PARENT_FRAMEWORK_SHA.encode(), NEW_FRAMEWORK_SHA.encode())
                                if path in projected else body)
                          for path, body in nginx_before.items()}, self.nginx_owned_bytes())
        self.assertEqual(SYNC.synchronize(self.root, self.common, False, NEW_FRAMEWORK_SHA), [])

    def test_framework_sha_projection_rejects_malformed_lock_without_writes(self) -> None:
        lock = self.root / "ci/tooling/project-versions.lock.json"
        original = lock.read_bytes()
        payload = json.loads(original)
        cases = (
            b"{", b"[]",
            json.dumps({"schema_version": 1, "framework_sha": TEST_PARENT_FRAMEWORK_SHA}).encode(),
            json.dumps(payload | {"unknown": "data"}).encode(),
            json.dumps(payload | {"schema_version": True}).encode(),
            json.dumps(payload | {"mrts_sha": "A" * 40}).encode(),
            json.dumps(payload | {"python_version": "3.13.7"}).encode(),
            json.dumps(payload | {"go_version": "latest"}).encode(),
            ('{"schema_version":1,"framework_sha":"' + TEST_PARENT_FRAMEWORK_SHA
             + '","framework_sha":"' + NEW_FRAMEWORK_SHA + '","mrts_sha":"' + payload["mrts_sha"] + '"}').encode(),
        )
        self.write_common(CURRENT_CANDIDATE_COMMON.replace('ENVOY_VERSION="1.39.1"', 'ENVOY_VERSION="1.40.1"'))
        for contents in cases:
            with self.subTest(contents=contents):
                lock.write_bytes(contents)
                before = self.all_target_bytes()
                with self.assertRaises(SYNC.SyncError):
                    SYNC.synchronize(self.root, self.common, True, NEW_FRAMEWORK_SHA)
                self.assertEqual(before, self.all_target_bytes())
        lock.write_bytes(original)
        with self.assertRaises(SYNC.SyncError):
            SYNC.synchronize(self.root, self.common, True, "A" * 40)
        before = self.target_bytes()
        lock.unlink()
        with self.assertRaises((SYNC.SyncError, OSError)):
            SYNC.synchronize(self.root, self.common, True, NEW_FRAMEWORK_SHA)
        self.assertEqual(before, self.target_bytes())

    def test_framework_revision_lock_symlink_is_rejected_before_writes(self) -> None:
        lock = self.root / "ci/tooling/project-versions.lock.json"
        outside = Path(self.temp.name) / "outside-lock.json"
        outside.write_bytes(lock.read_bytes())
        lock.unlink()
        lock.symlink_to(outside)
        before = self.target_bytes()
        original_outside = outside.read_bytes()
        with self.assertRaises(SYNC.SyncError):
            SYNC.synchronize(self.root, self.common, True, NEW_FRAMEWORK_SHA)
        self.assertEqual(before, self.target_bytes())
        self.assertEqual(original_outside, outside.read_bytes())

    def test_framework_sha_fixture_refuses_original_checkout(self) -> None:
        with self.assertRaisesRegex(ValueError, "source checkout"):
            set_framework_sha_fixture(ROOT, NEW_FRAMEWORK_SHA)

    def run_copied_cli(self, arguments: tuple[str, ...]) -> int:
        result = subprocess.run(
            [sys.executable, str(self.root / "ci/tools/sync-framework-component-versions.py"), *arguments],
            capture_output=True, text=True, check=False, timeout=30,
        )
        if result.returncode not in (0, 1, 2):
            self.fail(f"copied CLI crashed: {result.stdout} {result.stderr}")
        return result.returncode

    def test_cli_rejects_alternate_and_symlinked_repository_roots_before_io(self) -> None:
        link = Path(self.temp.name) / "linked-repository"
        link.symlink_to(ROOT, target_is_directory=True)
        before = self.all_target_bytes()
        for alternative in (self.root, link):
            with self.subTest(alternative=alternative):
                with mock.patch.object(SYNC, "synchronize") as synchronize:
                    self.assertEqual(SYNC.main(("--sync", "--repo-root", str(alternative),
                                               "--framework-common", str(self.common))), 2)
                    synchronize.assert_not_called()
        self.assertEqual(before, self.all_target_bytes())

    def test_cli_passes_only_its_fixed_repository_root_to_writer(self) -> None:
        with mock.patch.object(SYNC, "synchronize", return_value=[]) as synchronize:
            self.assertEqual(SYNC.main(("--validate", "--repo-root", str(ROOT),
                                       "--framework-common", str(self.common))), 0)
            synchronize.assert_called_once_with(ROOT, self.common, False, None)

    def test_cli_validate_sync_check_and_second_sync_are_byte_idempotent(self) -> None:
        framework_sha_arguments = ("--framework-sha", NEW_FRAMEWORK_SHA)
        projection_before = self.framework_sha_projection_bytes()
        self.assertEqual(
            self.run_copied_cli(
                (
                    "--validate",
                    "--repo-root",
                    str(self.root),
                    "--framework-common",
                    str(self.common),
                    *framework_sha_arguments,
                )
            ),
            0,
        )
        self.assertEqual(projection_before, self.framework_sha_projection_bytes())
        self.write_common(future_series_common())
        sync_arguments = (
            "--sync",
            "--repo-root",
            str(self.root),
            "--framework-common",
            str(self.common),
            *framework_sha_arguments,
        )
        self.assertEqual(self.run_copied_cli(sync_arguments), 0)
        after_first_sync = self.all_target_bytes()
        self.assertEqual(
            self.run_copied_cli(
                (
                    "--check",
                    "--repo-root",
                    str(self.root),
                    "--framework-common",
                    str(self.common),
                    *framework_sha_arguments,
                )
            ),
            0,
        )
        self.assertEqual(self.run_copied_cli(sync_arguments), 0)
        self.assertEqual(after_first_sync, self.all_target_bytes())

    def test_noop_after_sync(self) -> None:
        self.write_common(future_series_common())
        SYNC.synchronize(self.root, self.common, True)
        self.assertEqual(SYNC.synchronize(self.root, self.common, False), [])

    def test_unsafe_or_unknown_known_expressions_fail_closed(self) -> None:
        cycle = replace_rhs(
            CURRENT_CANDIDATE_COMMON,
            "LIGHTTPD_SERIES_BASE_URL",
            '"$LIGHTTPD_SOURCE_URL"',
        )
        cases = {
            "unknown reference": replace_rhs(
                CURRENT_CANDIDATE_COMMON, "LIGHTTPD_SOURCE_URL", '"$UNKNOWN_SOURCE"'
            ),
            "ambiguous unbraced reference": replace_rhs(
                CURRENT_CANDIDATE_COMMON,
                "LIGHTTPD_DOWNLOAD_URL",
                '"$LIGHTTPD_SOURCE_URLlighttpd-$LIGHTTPD_VERSION.tar.xz"',
            ),
            "missing required": re.sub(
                r"(?m)^HAPROXY_HTX_SHA256=.*\n", "", CURRENT_CANDIDATE_COMMON
            ),
            "duplicate": CURRENT_CANDIDATE_COMMON + 'ENVOY_VERSION="1.40.0"\n',
            "cycle": cycle,
            "command substitution": replace_rhs(
                CURRENT_CANDIDATE_COMMON, "LIGHTTPD_SOURCE_URL", '"$(id)"'
            ),
            "backticks": replace_rhs(
                CURRENT_CANDIDATE_COMMON, "LIGHTTPD_SOURCE_URL", '"`id`"'
            ),
            "semicolon": replace_rhs(
                CURRENT_CANDIDATE_COMMON, "LIGHTTPD_SOURCE_URL", '"value;id"'
            ),
            "pipe": replace_rhs(
                CURRENT_CANDIDATE_COMMON, "LIGHTTPD_SOURCE_URL", '"value|id"'
            ),
            "ampersand": replace_rhs(
                CURRENT_CANDIDATE_COMMON, "LIGHTTPD_SOURCE_URL", '"value&id"'
            ),
            "double pipe": replace_rhs(
                CURRENT_CANDIDATE_COMMON, "LIGHTTPD_SOURCE_URL", '"value||id"'
            ),
            "redirection": replace_rhs(
                CURRENT_CANDIDATE_COMMON, "LIGHTTPD_SOURCE_URL", '"value>file"'
            ),
            "input redirection": replace_rhs(
                CURRENT_CANDIDATE_COMMON, "LIGHTTPD_SOURCE_URL", '"value<file"'
            ),
            "here document": replace_rhs(
                CURRENT_CANDIDATE_COMMON, "LIGHTTPD_SOURCE_URL", '"value<<EOF"'
            ),
            "arithmetic": replace_rhs(
                CURRENT_CANDIDATE_COMMON, "LIGHTTPD_SOURCE_URL", '"$((1 + 1))"'
            ),
            "process substitution": replace_rhs(
                CURRENT_CANDIDATE_COMMON, "LIGHTTPD_SOURCE_URL", '"<(id)"'
            ),
            "eval": replace_rhs(
                CURRENT_CANDIDATE_COMMON, "LIGHTTPD_SOURCE_URL", '"eval value"'
            ),
            "indented known assignment": CURRENT_CANDIDATE_COMMON.replace(
                'ENVOY_VERSION="1.39.1"', '  ENVOY_VERSION="1.39.1"'
            ),
        }
        for label, malformed in cases.items():
            with self.subTest(label=label):
                self.write_common(malformed)
                with self.assertRaises(SYNC.SyncError):
                    SYNC.parse_common(self.common)

    def test_ambiguous_unbraced_reference_fails_before_sync_writes(self) -> None:
        before = self.target_bytes()
        self.write_common(
            replace_rhs(
                CURRENT_CANDIDATE_COMMON,
                "LIGHTTPD_DOWNLOAD_URL",
                '"$LIGHTTPD_SOURCE_URLlighttpd-$LIGHTTPD_VERSION.tar.xz"',
            )
        )
        with self.assertRaisesRegex(SYNC.SyncError, "ambiguous source variable reference"):
            SYNC.synchronize(self.root, self.common, True)
        self.assertEqual(before, self.target_bytes())

    def test_semantic_tuple_controls_fail_closed(self) -> None:
        cases = {
            "manipulated root": replace_rhs(
                CURRENT_CANDIDATE_COMMON,
                "LIGHTTPD_RELEASE_ROOT_URL",
                '"https://evil.example/lighttpd"',
            ),
            "credentials": replace_rhs(
                CURRENT_CANDIDATE_COMMON,
                "LIGHTTPD_RELEASE_ROOT_URL",
                '"https://user@download.lighttpd.net/lighttpd"',
            ),
            "query": replace_rhs(
                CURRENT_CANDIDATE_COMMON,
                "LIGHTTPD_RELEASE_ROOT_URL",
                '"https://download.lighttpd.net/lighttpd?query=1"',
            ),
            "fragment": replace_rhs(
                CURRENT_CANDIDATE_COMMON,
                "LIGHTTPD_RELEASE_ROOT_URL",
                '"https://download.lighttpd.net/lighttpd#fragment"',
            ),
            "foreign source host": replace_rhs(
                CURRENT_CANDIDATE_COMMON,
                "LIGHTTPD_SOURCE_URL",
                '"https://example.org/lighttpd/releases-1.4.x/"',
            ),
            "double source slash": replace_rhs(
                CURRENT_CANDIDATE_COMMON,
                "LIGHTTPD_SOURCE_URL",
                '"https://download.lighttpd.net/lighttpd/releases-1.4.x//"',
            ),
            "series version mismatch": replace_rhs(
                CURRENT_CANDIDATE_COMMON, "LIGHTTPD_SERIES", '"1.5"'
            ),
            "wrong archive": replace_rhs(
                CURRENT_CANDIDATE_COMMON, "LIGHTTPD_ARCHIVE_NAME", '"lighttpd-1.4.84.tar.xz"'
            ),
            "wrong download": replace_rhs(
                CURRENT_CANDIDATE_COMMON,
                "LIGHTTPD_DOWNLOAD_URL",
                '"https://download.lighttpd.net/lighttpd/releases-1.4.x/lighttpd-1.4.85.zip"',
            ),
            "generic haproxy mismatch": replace_rhs(
                CURRENT_CANDIDATE_COMMON, "HAPROXY_SERIES", '"3.3"'
            ),
            "htx haproxy mismatch": replace_rhs(
                CURRENT_CANDIDATE_COMMON, "HAPROXY_HTX_SERIES", '"3.3"'
            ),
            "invalid sha": replace_rhs(
                CURRENT_CANDIDATE_COMMON,
                "LIGHTTPD_SHA256",
                '"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"',
            ),
            "non-ascii digits": replace_rhs(
                CURRENT_CANDIDATE_COMMON, "LIGHTTPD_VERSION", '"١.4.85"'
            ),
            "foreign modsecurity repository": replace_rhs(
                CURRENT_CANDIDATE_COMMON,
                "MODSECURITY_V3_APPROVED_REPO_URL",
                '"https://example.invalid/ModSecurity.git"',
            ),
            "non-v3 modsecurity tag": replace_rhs(
                CURRENT_CANDIDATE_COMMON,
                "MODSECURITY_V3_RELEASE_TAG",
                '"v4.0.0"',
            ),
            "non-lowercase modsecurity commit": replace_rhs(
                CURRENT_CANDIDATE_COMMON,
                "MODSECURITY_V3_APPROVED_COMMIT",
                '"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"',
            ),
        }
        for label, malformed in cases.items():
            with self.subTest(label=label):
                self.write_common(malformed)
                with self.assertRaises(SYNC.SyncError):
                    SYNC.parse_common(self.common)

    def test_parse_or_validation_failure_never_writes_targets(self) -> None:
        before = self.target_bytes()
        self.write_common(
            replace_rhs(
                CURRENT_CANDIDATE_COMMON,
                "LIGHTTPD_RELEASE_ROOT_URL",
                '"https://evil.example/lighttpd"',
            )
        )
        with self.assertRaises(SYNC.SyncError):
            SYNC.synchronize(self.root, self.common, True)
        self.assertEqual(before, self.target_bytes())

    def test_missing_target_is_rejected_atomically(self) -> None:
        target = self.root / "connectors/envoy/config/envoy-ext-proc-versions.env"
        target.write_text(
            target.read_text().replace("CRS_APPROVED_COMMIT =", "CRS_APPROVED_COMMIT_REMOVED =", 1),
            encoding="utf-8",
        )
        before = self.target_bytes()
        with self.assertRaises(SYNC.SyncError):
            SYNC.synchronize(self.root, self.common, True)
        self.assertEqual(before, self.target_bytes())

    def test_symlinked_candidate_or_target_is_rejected_without_writes(self) -> None:
        before = self.target_bytes()
        candidate_link = Path(self.temp.name) / "candidate-link.sh"
        candidate_link.symlink_to(self.common)
        self.assertEqual(
            self.run_copied_cli(
                ("--validate", "--repo-root", str(self.root), "--framework-common", str(candidate_link))
            ),
            2,
        )
        target = self.root / "connectors/envoy/config/envoy-ext-proc-versions.env"
        outside = Path(self.temp.name) / "outside.env"
        outside.write_bytes(b"ENVOY_RELEASE=outside\n")
        target.unlink()
        target.symlink_to(outside)
        with self.assertRaises(SYNC.SyncError):
            SYNC.synchronize(self.root, self.common, True)
        self.assertEqual(outside.read_bytes(), b"ENVOY_RELEASE=outside\n")
        for path, contents in before.items():
            if path != target:
                self.assertEqual(path.read_bytes(), contents)

    def test_candidate_outside_explicit_allowed_root_is_rejected(self) -> None:
        outside = Path(self.temp.name) / "outside-common.sh"
        outside.write_text(CURRENT_CANDIDATE_COMMON, encoding="utf-8")
        with self.assertRaises(SYNC.SyncError):
            SYNC._read_regular(
                outside,
                "candidate common.sh",
                allowed_root=self.root,
            )

    def test_framework_candidate_must_be_below_runner_temp_root(self) -> None:
        with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.root)}):
            with self.assertRaises(SYNC.SyncError):
                SYNC.parse_common(self.common)

    def test_special_target_and_symlinked_parent_are_rejected(self) -> None:
        target = self.root / "connectors/envoy/config/envoy-ext-proc-versions.env"
        target.unlink()
        os.mkfifo(target)
        with self.assertRaises(SYNC.SyncError):
            SYNC.synchronize(self.root, self.common, True)
        target.unlink()

        directory = self.root / "connectors/lighttpd"
        moved = self.root / "connectors/lighttpd-original"
        directory.rename(moved)
        directory.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(SYNC.SyncError):
            SYNC.synchronize(self.root, self.common, True)

    def test_replacement_failure_rolls_back_and_preserves_modes(self) -> None:
        self.write_common(future_series_common())
        target = self.root / "connectors/envoy/config/envoy-ext-proc-versions.env"
        target.chmod(0o755)
        before = self.target_bytes()
        original_replace = SYNC._replace_file
        calls = 0

        def fail_second(*args: object) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected replacement failure")
            original_replace(*args)  # type: ignore[arg-type]

        with mock.patch.object(SYNC, "_replace_file", side_effect=fail_second):
            with self.assertRaises(SYNC.SyncError):
                SYNC.synchronize(self.root, self.common, True)
        self.assertEqual(before, self.target_bytes())
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)
        self.assertEqual(list(target.parent.glob(f".{target.name}.*")), [])

    def test_directory_fsync_failure_rolls_back_the_already_replaced_target(self) -> None:
        self.write_common(future_series_common())
        before = self.all_target_bytes()
        original_fsync = SYNC._fsync_directory
        calls = 0

        def fail_first(path: Path) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("injected post-replace directory fsync failure")
            original_fsync(path)

        with mock.patch.object(SYNC, "_fsync_directory", side_effect=fail_first):
            with self.assertRaisesRegex(SYNC.SyncError, "completed changes were rolled back"):
                SYNC.synchronize(self.root, self.common, True, NEW_FRAMEWORK_SHA)
        self.assertEqual(before, self.all_target_bytes())
        self.assertEqual(calls, 2)

    def test_rollback_preserves_concurrent_in_place_edits(self) -> None:
        self.write_common(future_series_common())
        target = self.root / "connectors/envoy/config/envoy-ext-proc-versions.env"
        original = target.read_bytes()
        prepared = SYNC.RenderedTarget(target, original, original + b"# replacement\n", stat.S_IMODE(target.stat().st_mode))
        concurrent = b"# concurrent edit after replacement\n"

        def change_after_replace(_path: Path) -> None:
            target.write_bytes(concurrent)
            raise OSError("injected failure after concurrent edit")

        with mock.patch.object(SYNC, "_fsync_directory", side_effect=change_after_replace):
            with self.assertRaisesRegex(SYNC.SyncError, "rollback incomplete"):
                SYNC._commit_rendered([prepared])
        self.assertNotEqual(original, concurrent)
        self.assertEqual(target.read_bytes(), concurrent)

    def test_rollback_preserves_concurrent_metadata_changes(self) -> None:
        self.write_common(future_series_common())
        target = self.root / "connectors/envoy/config/envoy-ext-proc-versions.env"
        original = target.read_bytes()
        prepared = SYNC.RenderedTarget(target, original, original + b"# replacement\n", stat.S_IMODE(target.stat().st_mode))

        def touch_after_replace(_path: Path) -> None:
            metadata = target.stat()
            os.utime(target, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1))
            raise OSError("injected failure after concurrent metadata change")

        with mock.patch.object(SYNC, "_fsync_directory", side_effect=touch_after_replace):
            with self.assertRaisesRegex(SYNC.SyncError, "rollback incomplete"):
                SYNC._commit_rendered([prepared])
        self.assertNotEqual(target.read_bytes(), original)

    def test_changed_project_lock_rejected_before_component_replacements(self) -> None:
        self.write_common(future_series_common())
        rendered = SYNC._render_targets(self.root, SYNC.parse_common(self.common), NEW_FRAMEWORK_SHA)
        lock = self.root / "ci/tooling/project-versions.lock.json"
        payload = json.loads(lock.read_bytes())
        payload["python_version"] = "3.15.8"
        lock.write_text(json.dumps(payload, indent=2) + "\n")
        before = self.all_target_bytes()
        with self.assertRaisesRegex(SYNC.SyncError, "changed concurrently"):
            SYNC._commit_rendered(rendered)
        self.assertEqual(before, self.all_target_bytes())

    def test_project_publishers_share_tooling_directory_lock(self) -> None:
        import fcntl
        directory = self.root / "ci/tooling"
        competing = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.addCleanup(os.close, competing)
        original_render = SYNC._render_targets

        def assert_locked(*args):
            with self.assertRaises(BlockingIOError):
                fcntl.flock(competing, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return original_render(*args)

        with mock.patch.object(SYNC, "_render_targets", side_effect=assert_locked):
            SYNC.synchronize(self.root, self.common, True, NEW_FRAMEWORK_SHA)
        fcntl.flock(competing, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(competing, fcntl.LOCK_UN)

    def verify_legacy_publication(self, base: str, *, staged: bool = False) -> None:
        original = {name: inventory_updates.trusted_blob(self.root, base, name)
                    for name in inventory_updates.COMPANIONS}
        proposed = {}
        for name in inventory_updates.COMPANIONS:
            if staged:
                proposed[name] = inventory_updates.index_blob(self.root, name)
            else:
                path = self.root / name
                if stat.S_IMODE(path.lstat().st_mode) != 0o644:
                    raise inventory_updates.InventoryUpdateError("Framework companion requires mode 100644")
                proposed[name] = inventory_updates.read_regular(self.root, name)
        inventory_updates.verify_companions(
            original[inventory_updates.INVENTORY], original[inventory_updates.ARCHIVE],
            {}, {}, frozenset(), proposed)

    def test_framework_update_preserves_admitted_selection_and_native_archive(self) -> None:
        base = self.install_admitted_inventory()
        before = {name: (self.root / name).read_bytes() for name in inventory_updates.COMPANIONS}
        candidate = replace_rhs(future_series_common(), "MODSECURITY_V3_RELEASE_TAG", '"v3.0.17"')
        candidate = replace_rhs(candidate, "MODSECURITY_V3_APPROVED_COMMIT", '"' + "f" * 40 + '"')
        self.write_common(candidate)
        changed = SYNC.synchronize(self.root, self.common, True, NEW_FRAMEWORK_SHA)
        self.assertFalse(inventory_updates.COMPANIONS & set(changed))
        self.assertEqual({name: (self.root / name).read_bytes() for name in inventory_updates.COMPANIONS}, before)
        self.assertEqual(len(load_inventory(self.root).case_ids), 2)
        # Product maintenance cannot rewrite Framework selection mechanics.
        # Their retained bindings must still authenticate the actual sources,
        # rather than merely remain byte-identical to a stale baseline.
        inventory = json.loads((self.root / inventory_updates.INVENTORY).read_bytes())
        self.assertEqual(inventory["source_bindings"], [
            {"path": row["path"], "sha256": hashlib.sha256((self.root / row["path"]).read_bytes()).hexdigest()}
            for row in json.loads(before[inventory_updates.INVENTORY])["source_bindings"]
        ])
        expected_archive = json.loads(before[inventory_updates.ARCHIVE])
        expected_archive["inventory_sha256"] = hashlib.sha256(
            (self.root / inventory_updates.INVENTORY).read_bytes()).hexdigest()
        for row in expected_archive["sources"]:
            row["source_sha256"] = hashlib.sha256((self.root / row["source"]).read_bytes()).hexdigest()
        self.assertEqual(json.loads((self.root / inventory_updates.ARCHIVE).read_bytes()), expected_archive)
        self.verify_legacy_publication(base)
        SYNC.verify_primary_changes(self.root, self.common, NEW_FRAMEWORK_SHA, base)
        verification = ("--verify-primary", "--base", base, "--framework-sha", NEW_FRAMEWORK_SHA,
                        "--framework-common", str(self.common))
        self.assertEqual(self.run_copied_cli(verification), 0)
        self.git("add", "--all")
        self.verify_legacy_publication(base, staged=True)
        SYNC.verify_primary_changes(self.root, self.common, NEW_FRAMEWORK_SHA, base, staged=True)
        self.assertEqual(self.run_copied_cli((*verification, "--staged")), 0)
        self.assertEqual(SYNC.synchronize(self.root, self.common, True, NEW_FRAMEWORK_SHA), [])

    def test_framework_publication_rejects_forged_sources_selection_and_modes(self) -> None:
        base = self.install_admitted_inventory()
        SYNC.synchronize(self.root, self.common, True, NEW_FRAMEWORK_SHA)
        good = self.publication_bytes()
        inventory_path = self.root / inventory_updates.INVENTORY
        archive_path = self.root / inventory_updates.ARCHIVE
        primary = self.root / "scripts/generate_compiler_guides.py"
        for mutation in ("primary-bytes", "selector", "source-path", "missing-companions", "mode"):
            with self.subTest(mutation=mutation):
                for path, data in good.items():
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
                    path.chmod(0o644)
                if mutation == "primary-bytes":
                    primary.write_bytes(primary.read_bytes() + b"# unrelated content must not be blessed\n")
                elif mutation in {"selector", "source-path"}:
                    inventory = json.loads(inventory_path.read_bytes())
                    if mutation == "selector":
                        inventory["executions"][0]["selector"]["target"] = "tests.companion_fixture.Control.test_offline"
                    else:
                        inventory["source_bindings"][0]["path"] = "tests/forged_fixture.py"
                    inventory_path.write_text(json.dumps(inventory, indent=2) + "\n")
                    archive = json.loads(archive_path.read_bytes())
                    archive["inventory_sha256"] = hashlib.sha256(inventory_path.read_bytes()).hexdigest()
                    archive_path.write_text(json.dumps(archive, indent=2, sort_keys=True) + "\n")
                elif mutation == "missing-companions":
                    inventory_path.unlink()
                    archive_path.unlink()
                else:
                    archive_path.chmod(0o755)

                def verify(staged=False):
                    # Product and Framework prove their own independently
                    # owned bytes; neither validator delegates authority.
                    SYNC.verify_primary_changes(self.root, self.common, NEW_FRAMEWORK_SHA, base, staged=staged)
                    self.verify_legacy_publication(base, staged=staged)

                with self.assertRaises((SYNC.SyncError, inventory_updates.InventoryUpdateError, OSError, ValueError)):
                    verify()
                self.git("add", "--all")
                for path, data in good.items():
                    path.write_bytes(data)
                    path.chmod(0o644)
                verify()
                with self.assertRaises((SYNC.SyncError, inventory_updates.InventoryUpdateError, OSError, ValueError)):
                    verify(staged=True)

    def test_framework_sync_rejects_stale_companions_before_primary_writes(self) -> None:
        base = self.install_admitted_inventory()
        baseline = self.publication_bytes()
        inventory_path = self.root / inventory_updates.INVENTORY
        archive_path = self.root / inventory_updates.ARCHIVE
        for mutation in ("source-digest", "archive-digest", "archive-source-digest", "one-companion-missing"):
            with self.subTest(mutation=mutation):
                for path, data in baseline.items():
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
                if mutation == "source-digest":
                    payload = json.loads(inventory_path.read_bytes())
                    payload["source_bindings"][0]["sha256"] = "0" * 64
                    inventory_path.write_text(json.dumps(payload, indent=2) + "\n")
                elif mutation == "archive-digest":
                    payload = json.loads(archive_path.read_bytes())
                    payload["inventory_sha256"] = "0" * 64
                    archive_path.write_text(json.dumps(payload, indent=2) + "\n")
                elif mutation == "archive-source-digest":
                    payload = json.loads(archive_path.read_bytes())
                    payload["sources"][0]["source_sha256"] = "0" * 64
                    archive_path.write_text(json.dumps(payload, indent=2) + "\n")
                else:
                    archive_path.unlink()
                before = self.all_target_bytes()
                with self.assertRaises((inventory_updates.InventoryUpdateError, OSError, ValueError)):
                    self.verify_legacy_publication(base)
                self.assertEqual(self.all_target_bytes(), before)

    def test_framework_companion_failure_rolls_back_primary_and_companions(self) -> None:
        self.install_admitted_inventory()
        fixture = self.root / "tests/companion_fixture.py"
        before = self.publication_bytes() | {fixture: fixture.read_bytes()}
        original_replace = inventory_updates.atomic_write
        archive_path = inventory_updates.ARCHIVE
        def fail_archive(root, name, *arguments):
            if name == archive_path:
                raise OSError("injected final companion write failure")
            return original_replace(root, name, *arguments)
        with mock.patch.object(inventory_updates, "atomic_write", side_effect=fail_archive):
            with self.assertRaisesRegex(OSError, "injected final companion"):
                inventory_updates.apply_fixture_update(self.root, {"tests/companion_fixture.py": fixture.read_bytes() + b"# reviewed fixture change\n"})
        self.assertEqual(self.publication_bytes() | {fixture: fixture.read_bytes()}, before)
        load_inventory(self.root)

    def test_framework_postwrite_admission_failure_rolls_back_transaction(self) -> None:
        self.install_admitted_inventory()
        fixture = self.root / "tests/companion_fixture.py"
        before = self.publication_bytes() | {fixture: fixture.read_bytes()}
        original_admit = inventory_updates._admit
        calls = 0
        def fail_final(root):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ValueError("injected final admission failure")
            return original_admit(root)
        with mock.patch.object(inventory_updates, "_admit", side_effect=fail_final):
            with self.assertRaisesRegex(ValueError, "injected final admission"):
                inventory_updates.apply_fixture_update(self.root, {"tests/companion_fixture.py": fixture.read_bytes() + b"# reviewed fixture change\n"})
        self.assertEqual(self.publication_bytes() | {fixture: fixture.read_bytes()}, before)
        load_inventory(self.root)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
