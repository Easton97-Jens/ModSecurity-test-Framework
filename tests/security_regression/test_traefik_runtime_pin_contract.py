"""Regression coverage for the canonical Traefik release-archive boundary."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
from pathlib import Path

from tests.security_regression.common_version_fixture_support import (
    replace_single_common_assignment,
    write_common_fixture,
)


ROOT = Path(__file__).resolve().parents[2]
COMMON_SOURCE = ROOT / "ci" / "lib" / "common.sh"
PATH_BOOTSTRAP = ROOT / "ci" / "lib" / "path-bootstrap.sh"
PATH_HELPER = ROOT / "ci" / "lib" / "path.sh"
RUNTIME_COMPONENT_HELPER = ROOT / "ci" / "lib" / "runtime-component-common.sh"
CONNECTOR_SMOKE_HELPER = ROOT / "ci" / "lib" / "connector-smoke-common.sh"
RUNTIME_COMPONENT_LOCK_CHECKER = (
    ROOT / "ci" / "tools" / "check-runtime-component-lock.py"
)
RUNTIME_COMPONENT_SYNCHRONIZER = ROOT / "ci" / "tools" / "sync-runtime-components.py"
RUNTIME_COMPONENT_LOCK = ROOT / "ci" / "provisioning" / "runtime-component-lock.json"
RUNTIME_COMPONENT_MANIFEST = (
    ROOT / "ci" / "provisioning" / "runtime-components.manifest.json"
)
PREPARE_TRAEFIK = ROOT / "ci" / "provisioning" / "prepare-traefik-runtime.sh"
SYNC_MANIFEST = ROOT / "ci" / "tools" / "sync-traefik-runtime-manifest.py"


def load_traefik_lock_tuple() -> dict[str, str]:
    """Return the single tuple all active Traefik profiles must share."""
    lock = json.loads(RUNTIME_COMPONENT_LOCK.read_text(encoding="utf-8"))
    profiles = [
        profile
        for profile in lock.get("profiles", [])
        if isinstance(profile, dict) and profile.get("component") == "traefik"
    ]
    if not profiles:
        raise RuntimeError("runtime component lock has no Traefik profile")

    fields = ("version", "asset_name", "sha256", "os", "arch")
    tuple_values: dict[str, str] = {}
    for field in fields:
        value = profiles[0].get(field)
        if not isinstance(value, str) or not value:
            raise RuntimeError(f"Traefik lock profile has no valid {field}")
        tuple_values[field] = value

    for profile in profiles[1:]:
        for field, expected in tuple_values.items():
            if profile.get(field) != expected:
                raise RuntimeError(
                    f"Traefik lock profiles disagree on {field}: "
                    f"expected {expected!r}, found {profile.get(field)!r}"
                )
    return tuple_values


TRAEFIK_LOCK_TUPLE = load_traefik_lock_tuple()
PINNED_VERSION = TRAEFIK_LOCK_TUPLE["version"]
PINNED_SHA256 = TRAEFIK_LOCK_TUPLE["sha256"]
PINNED_PLATFORM = "_".join(
    (TRAEFIK_LOCK_TUPLE["os"], TRAEFIK_LOCK_TUPLE["arch"])
)
PINNED_ARCHIVE = TRAEFIK_LOCK_TUPLE["asset_name"]
INVALID_VERSION = "0.0.0" if PINNED_VERSION != "0.0.0" else "0.0.1"
INVALID_PLATFORM = "linux_arm64" if PINNED_PLATFORM != "linux_arm64" else "linux_amd64"
NON_CANONICAL_SHA256 = "0" * 64 if PINNED_SHA256 != "0" * 64 else "1" * 64


def load_sync_manifest():
    spec = importlib.util.spec_from_file_location(
        "sync_traefik_runtime_manifest_contract", SYNC_MANIFEST
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load Traefik manifest synchronizer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TraefikRuntimePinContractTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="traefik-runtime-pin-", dir=os.environ.get("TEST_TMPDIR")
        )
        self.temporary_root = Path(self.temporary.name)
        self.common_root = self.temporary_root / "common-only"
        self.common = write_common_fixture(
            self.common_root, COMMON_SOURCE.read_text(encoding="utf-8"), {}
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_common_guard(
        self, overrides: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        for name in (
            "TRAEFIK_VERSION",
            "TRAEFIK_SOURCE_URL",
            "TRAEFIK_DOWNLOAD_URL",
            "TRAEFIK_SHA256",
            "TRAEFIK_SHA256_URL",
            "TRAEFIK_ARTIFACT_PLATFORM",
            "TRAEFIK_ARCHIVE_NAME",
            "TRAEFIK_BIN",
            "TRAEFIK_ARCHIVE",
        ):
            environment.pop(name, None)
        environment["COMMON_SH"] = str(self.common)
        if overrides:
            environment.update(overrides)
        return subprocess.run(
            [
                "sh",
                "-eu",
                "-c",
                '. "$COMMON_SH"\nci_require_traefik_pinned_provenance',
            ],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

    def create_framework_fixture(
        self, name: str, common_source: str | None = None
    ) -> tuple[Path, Path, Path]:
        fixture_root = self.temporary_root / name
        fixture_common = write_common_fixture(
            fixture_root,
            common_source
            if common_source is not None
            else COMMON_SOURCE.read_text(encoding="utf-8"),
            {},
        )
        lib_root = fixture_root / "ci" / "lib"
        provisioning_root = fixture_root / "ci" / "provisioning"
        tools_root = fixture_root / "ci" / "tools"
        provisioning_root.mkdir(parents=True, exist_ok=True)
        tools_root.mkdir(parents=True, exist_ok=True)
        shutil.copy2(PATH_BOOTSTRAP, lib_root / "path-bootstrap.sh")
        shutil.copy2(PATH_HELPER, lib_root / "path.sh")
        shutil.copy2(RUNTIME_COMPONENT_HELPER, lib_root / "runtime-component-common.sh")
        shutil.copy2(CONNECTOR_SMOKE_HELPER, lib_root / "connector-smoke-common.sh")
        shutil.copy2(
            RUNTIME_COMPONENT_LOCK_CHECKER,
            tools_root / "check-runtime-component-lock.py",
        )
        shutil.copy2(
            RUNTIME_COMPONENT_SYNCHRONIZER, tools_root / "sync-runtime-components.py"
        )
        shutil.copy2(
            RUNTIME_COMPONENT_LOCK, provisioning_root / "runtime-component-lock.json"
        )
        shutil.copy2(
            RUNTIME_COMPONENT_MANIFEST,
            provisioning_root / "runtime-components.manifest.json",
        )
        fixture_prepare = provisioning_root / "prepare-traefik-runtime.sh"
        shutil.copy2(PREPARE_TRAEFIK, fixture_prepare)
        (fixture_root / "Makefile").write_text("# fixture\n", encoding="utf-8")
        (fixture_root / "tests").mkdir()
        return fixture_root, fixture_common, fixture_prepare

    def write_fake_traefik_archive(self, root: Path, archive: Path) -> str:
        source_binary = root / "archive-source" / "traefik"
        source_binary.parent.mkdir(parents=True, exist_ok=True)
        source_binary.write_text(
            f"#!/bin/sh\nif [ \"${{1:-}}\" = version ]; then printf 'Version: {PINNED_VERSION}\\n'; fi\n",
            encoding="utf-8",
        )
        source_binary.chmod(0o755)
        archive.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(source_binary, arcname="traefik")
        return hashlib.sha256(archive.read_bytes()).hexdigest()

    def preparer_environment(self, fixture_root: Path) -> dict[str, str]:
        verified_root = self.temporary_root / f"{fixture_root.name}-verified"
        environment = os.environ.copy()
        for name in (
            "CACHE_ROOT",
            "VERIFIED_COMPONENT_CACHE",
            "CONNECTOR_COMPONENT_CACHE",
            "TRAEFIK_VERSION",
            "TRAEFIK_SOURCE_URL",
            "TRAEFIK_DOWNLOAD_URL",
            "TRAEFIK_SHA256",
            "TRAEFIK_SHA256_URL",
            "TRAEFIK_ARTIFACT_PLATFORM",
            "TRAEFIK_ARCHIVE_NAME",
            "TRAEFIK_ARCHIVE",
            "TRAEFIK_BIN",
        ):
            environment.pop(name, None)
        environment.update(
            {
                "FRAMEWORK_ROOT": str(fixture_root),
                "CONNECTOR_ROOT": str(fixture_root),
                "VERIFIED_RUN_ROOT": str(verified_root),
                "BUILD_ROOT": str(verified_root / "build"),
                "ALLOW_RUNTIME_DOWNLOADS": "0",
            }
        )
        return environment

    def fixture_verified_root(self, fixture_root: Path) -> Path:
        return self.temporary_root / f"{fixture_root.name}-verified"

    def set_fixture_traefik_sha256(
        self, fixture_root: Path, common: Path, sha256: str
    ) -> None:
        common.write_text(
            replace_single_common_assignment(
                common.read_text(encoding="utf-8"), "TRAEFIK_SHA256", sha256
            ),
            encoding="utf-8",
        )
        lock_path = fixture_root / "ci" / "provisioning" / "runtime-component-lock.json"
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        lock_profiles = [
            profile for profile in lock["profiles"] if profile["component"] == "traefik"
        ]
        self.assertEqual(len(lock_profiles), 2)
        for profile in lock_profiles:
            profile["sha256"] = sha256
        lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")

        manifest_path = (
            fixture_root / "ci" / "provisioning" / "runtime-components.manifest.json"
        )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest_components = [
            component
            for component in manifest["components"]
            if component["name"] == "traefik"
        ]
        self.assertEqual(len(manifest_components), 1)
        manifest_components[0]["sha256"] = sha256
        manifest_path.write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )

    def run_preparer(
        self, fixture_root: Path, prepare: Path
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(prepare)],
            cwd=fixture_root,
            env=self.preparer_environment(fixture_root),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

    def run_resolver(
        self, fixture_root: Path, common: Path
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "sh",
                "-eu",
                "-c",
                '. "$COMMON_SH"\nrequire_or_provision_traefik',
            ],
            cwd=fixture_root,
            env={**self.preparer_environment(fixture_root), "COMMON_SH": str(common)},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

    def write_minimal_manifest(self, path: Path) -> None:
        path.write_text(
            json.dumps({"schema_version": 1, "components": [{"name": "traefik"}]}),
            encoding="utf-8",
        )

    def run_sync(
        self, mode: str, common: Path, manifest: Path
    ) -> subprocess.CompletedProcess[str]:
        if (
            common.name == "common.sh"
            and common.parent.name == "lib"
            and common.parent.parent.name == "ci"
        ):
            test_root = common.parents[2]
        else:
            test_root = common.parent
        return subprocess.run(
            [
                "python3",
                str(SYNC_MANIFEST),
                mode,
                "--common-sh",
                str(common),
                "--manifest",
                str(manifest),
                "--test-root",
                str(test_root),
            ],
            cwd=ROOT,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

    def test_canonical_tuple_is_the_current_reviewed_linux_amd64_archive(self) -> None:
        source = self.common.read_text(encoding="utf-8")

        self.assertEqual(
            PINNED_ARCHIVE,
            f"traefik_v{PINNED_VERSION}_{PINNED_PLATFORM}.tar.gz",
        )
        self.assertIn(f'TRAEFIK_VERSION="{PINNED_VERSION}"', source)
        self.assertIn(f'TRAEFIK_SHA256="{PINNED_SHA256}"', source)
        self.assertIn(f'TRAEFIK_ARTIFACT_PLATFORM="{PINNED_PLATFORM}"', source)
        self.assertIn(
            'TRAEFIK_ARCHIVE_NAME="traefik_v${TRAEFIK_VERSION}_${TRAEFIK_ARTIFACT_PLATFORM}.tar.gz"',
            source,
        )
        self.assertIn("ci_require_traefik_pinned_provenance", source)

        completed = self.run_common_guard()

        self.assertEqual(completed.returncode, 0, completed.stdout)

    def test_environment_tuple_overrides_and_partial_tuples_fail_closed(self) -> None:
        invalid = {
            "old-version": {"TRAEFIK_VERSION": INVALID_VERSION},
            "empty-version": {"TRAEFIK_VERSION": ""},
            "foreign-source": {
                "TRAEFIK_SOURCE_URL": "https://mirror.example.invalid/traefik"
            },
            "wrong-download": {
                "TRAEFIK_DOWNLOAD_URL": f"https://github.com/traefik/traefik/releases/download/v{INVALID_VERSION}/other.tar.gz"
            },
            "missing-sha": {"TRAEFIK_SHA256": ""},
            "malformed-sha": {"TRAEFIK_SHA256": "not-a-sha256"},
            "wrong-platform": {"TRAEFIK_ARTIFACT_PLATFORM": INVALID_PLATFORM},
            "wrong-archive": {
                "TRAEFIK_ARCHIVE_NAME": f"traefik_v{PINNED_VERSION}_{INVALID_PLATFORM}.tar.gz"
            },
            "unverified-binary": {"TRAEFIK_BIN": "/tmp/arbitrary-traefik"},
            "self-consistent-replacement": {
                "TRAEFIK_VERSION": INVALID_VERSION,
                "TRAEFIK_SOURCE_URL": "https://github.com/traefik/traefik/releases",
                "TRAEFIK_DOWNLOAD_URL": f"https://github.com/traefik/traefik/releases/download/v{INVALID_VERSION}/traefik_v{INVALID_VERSION}_{PINNED_PLATFORM}.tar.gz",
                "TRAEFIK_SHA256": "a" * 64,
                "TRAEFIK_SHA256_URL": f"https://github.com/traefik/traefik/releases/download/v{INVALID_VERSION}/traefik_v{INVALID_VERSION}_checksums.txt",
                "TRAEFIK_ARTIFACT_PLATFORM": PINNED_PLATFORM,
                "TRAEFIK_ARCHIVE_NAME": f"traefik_v{INVALID_VERSION}_{PINNED_PLATFORM}.tar.gz",
            },
        }
        for case, overrides in invalid.items():
            with self.subTest(case=case):
                completed = self.run_common_guard(overrides)

                self.assertEqual(completed.returncode, 77, completed.stdout)
                self.assertIn("BLOCKED:", completed.stdout)

    def test_other_active_pin_environment_overrides_fail_closed(self) -> None:
        completed = self.run_common_guard(
            {"PCRE2_SHA256_URL": "https://mirror.example.invalid/pcre2.sha256"}
        )

        self.assertEqual(completed.returncode, 77, completed.stdout)
        self.assertIn("PCRE2_SHA256_URL override is not permitted", completed.stdout)

    def test_post_source_mutations_and_internal_missing_metadata_fail_closed(
        self,
    ) -> None:
        post_source = subprocess.run(
            [
                "sh",
                "-eu",
                "-c",
                "\n".join(
                    (
                        '. "$COMMON_SH"',
                        f'TRAEFIK_DOWNLOAD_URL="https://github.com/traefik/traefik/releases/download/v{INVALID_VERSION}/other.tar.gz"',
                        "ci_require_traefik_pinned_provenance",
                    )
                ),
            ],
            cwd=ROOT,
            env={**os.environ, "COMMON_SH": str(self.common)},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        self.assertEqual(post_source.returncode, 77, post_source.stdout)
        self.assertIn("BLOCKED:", post_source.stdout)

        for case, replacement in {
            "missing": "",
            "malformed": "not-a-sha256",
            "wrong-platform": INVALID_PLATFORM,
        }.items():
            with self.subTest(case=case):
                variable = (
                    "TRAEFIK_ARTIFACT_PLATFORM"
                    if case == "wrong-platform"
                    else "TRAEFIK_SHA256"
                )
                fixture_source = replace_single_common_assignment(
                    COMMON_SOURCE.read_text(encoding="utf-8"), variable, replacement
                )
                fixture = write_common_fixture(
                    self.temporary_root / f"invalid-{case}", fixture_source, {}
                )
                self.common = fixture
                completed = self.run_common_guard()

                self.assertEqual(completed.returncode, 77, completed.stdout)
                self.assertIn("BLOCKED:", completed.stdout)

    def test_verified_canonical_archive_stages_and_runs_normally_offline(self) -> None:
        fixture_root, common, prepare = self.create_framework_fixture("normal")
        archive = (
            self.fixture_verified_root(fixture_root)
            / "cache-v2"
            / "shared"
            / "traefik"
            / "downloads"
            / PINNED_ARCHIVE
        )
        digest = self.write_fake_traefik_archive(fixture_root, archive)
        self.set_fixture_traefik_sha256(fixture_root, common, digest)

        completed = self.run_preparer(fixture_root, prepare)
        staged = (
            self.fixture_verified_root(fixture_root)
            / "build"
            / "traefik-connector"
            / "bin"
            / "traefik"
        )

        self.assertEqual(completed.returncode, 0, completed.stdout)
        self.assertTrue(staged.is_file(), completed.stdout)
        version = subprocess.run(
            [str(staged), "version"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        self.assertEqual(version.returncode, 0, version.stdout)
        self.assertIn(PINNED_VERSION, version.stdout)

    def test_bad_archive_digest_fails_before_extraction_or_staging(self) -> None:
        fixture_root, common, prepare = self.create_framework_fixture("wrong-digest")
        archive = (
            self.fixture_verified_root(fixture_root)
            / "cache-v2"
            / "shared"
            / "traefik"
            / "downloads"
            / PINNED_ARCHIVE
        )
        self.write_fake_traefik_archive(fixture_root, archive)
        self.set_fixture_traefik_sha256(fixture_root, common, "0" * 64)

        completed = self.run_preparer(fixture_root, prepare)
        component_root = archive.parents[1]

        self.assertEqual(completed.returncode, 77, completed.stdout)
        self.assertIn("SHA256 verification failed", completed.stdout)
        self.assertFalse((component_root / "bin" / "traefik").exists())
        self.assertFalse((component_root / "extract").exists())

    def test_missing_archive_propagates_the_blocked_status_from_the_resolver(
        self,
    ) -> None:
        fixture_root, common, _prepare = self.create_framework_fixture(
            "missing-archive"
        )

        completed = self.run_resolver(fixture_root, common)
        component_root = (
            self.fixture_verified_root(fixture_root) / "cache-v2" / "shared" / "traefik"
        )

        self.assertEqual(completed.returncode, 77, completed.stdout)
        self.assertIn("BLOCKED:", completed.stdout)
        self.assertFalse((component_root / "bin" / "traefik").exists())

    def test_same_version_bare_binary_cannot_bypass_archive_verification(self) -> None:
        fixture_root, _common, _prepare = self.create_framework_fixture("bare-binary")
        binary = (
            self.fixture_verified_root(fixture_root)
            / "cache-v2"
            / "shared"
            / "traefik"
            / "bin"
            / "traefik"
        )
        marker = fixture_root / "bare-binary-executed"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_text(
            textwrap.dedent(
                """\
                #!/bin/sh
                printf 'executed\\n' > "$MARKER"
                printf 'Version: {PINNED_VERSION}\\n'
                """
            ).replace("{PINNED_VERSION}", PINNED_VERSION),
            encoding="utf-8",
        )
        binary.chmod(0o755)
        environment = self.preparer_environment(fixture_root)
        environment.update(
            {
                "SMOKE_COMMON": str(
                    fixture_root / "ci" / "lib" / "connector-smoke-common.sh"
                ),
                "MARKER": str(marker),
            }
        )
        completed = subprocess.run(
            [
                "sh",
                "-eu",
                "-c",
                '. "$SMOKE_COMMON"\nfind_runtime_binary TRAEFIK_BIN traefik',
            ],
            cwd=fixture_root,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

        self.assertNotEqual(completed.returncode, 0, completed.stdout)
        self.assertIn("runtime dependency is not staged locally", completed.stdout)
        self.assertFalse(marker.exists(), completed.stdout)

    def test_manifest_write_is_deterministic_and_check_reports_expected_found(
        self,
    ) -> None:
        manifest = self.temporary_root / "runtime-components.manifest.json"
        self.write_minimal_manifest(manifest)

        generated = self.run_sync("--write", self.common, manifest)
        first = manifest.read_bytes()
        checked = self.run_sync("--check", self.common, manifest)
        repeated = self.run_sync("--write", self.common, manifest)

        self.assertEqual(generated.returncode, 0, generated.stdout)
        self.assertEqual(checked.returncode, 0, checked.stdout)
        self.assertEqual(repeated.returncode, 0, repeated.stdout)
        self.assertEqual(first, manifest.read_bytes())

        document = json.loads(manifest.read_text(encoding="utf-8"))
        component = document["components"][0]
        mutations = {
            "version": INVALID_VERSION,
            "sha256": "0" * 64,
            "non-canonical-hash": NON_CANONICAL_SHA256,
            "artifact_platform": INVALID_PLATFORM.replace("_", "/"),
            "missing-archive": None,
        }
        for case, value in mutations.items():
            with self.subTest(case=case):
                candidate = json.loads(json.dumps(document))
                target = candidate["components"][0]
                if case == "missing-archive":
                    target.pop("archive_name")
                elif case == "non-canonical-hash":
                    target["sha256"] = value
                else:
                    target[case] = value
                manifest.write_text(json.dumps(candidate), encoding="utf-8")
                divergent = self.run_sync("--check", self.common, manifest)

                self.assertEqual(divergent.returncode, 1, divergent.stdout)
                self.assertIn("expected", divergent.stdout)
                self.assertIn("found", divergent.stdout)

    def test_manifest_validator_preserves_the_ascii_version_boundary(self) -> None:
        synchronizer = load_sync_manifest()
        values = synchronizer.load_canonical_tuple(COMMON_SOURCE)
        synchronizer.validate_canonical_tuple(values)

        unicode_version = "٣.٧.١٠"
        unicode_values = dict(values)
        archive = f"traefik_v{unicode_version}_{PINNED_PLATFORM}.tar.gz"
        source_url = unicode_values["TRAEFIK_SOURCE_URL"]
        unicode_values.update(
            {
                "TRAEFIK_VERSION": unicode_version,
                "TRAEFIK_ARCHIVE_NAME": archive,
                "TRAEFIK_DOWNLOAD_URL": f"{source_url}/download/v{unicode_version}/{archive}",
                "TRAEFIK_SHA256_URL": f"{source_url}/download/v{unicode_version}/traefik_v{unicode_version}_checksums.txt",
            }
        )

        self.assertIsNotNone(synchronizer.VERSION_RE.fullmatch(PINNED_VERSION))
        self.assertIsNone(synchronizer.VERSION_RE.fullmatch(unicode_version))
        with self.assertRaisesRegex(
            synchronizer.ManifestSyncError, "exact dotted release"
        ):
            synchronizer.validate_canonical_tuple(unicode_values)

    def test_manifest_tool_rejects_duplicate_manual_pin_and_invalid_source_metadata(
        self,
    ) -> None:
        manifest = self.temporary_root / "runtime-components.manifest.json"
        self.write_minimal_manifest(manifest)
        duplicate = self.temporary_root / "duplicate-common.sh"
        duplicate.write_text(
            COMMON_SOURCE.read_text(encoding="utf-8")
            + f'\nTRAEFIK_VERSION="{INVALID_VERSION}"\n',
            encoding="utf-8",
        )

        duplicate_result = self.run_sync("--check", duplicate, manifest)

        self.assertEqual(duplicate_result.returncode, 2, duplicate_result.stdout)
        self.assertIn(
            "exactly one manually maintained TRAEFIK_VERSION literal",
            duplicate_result.stdout,
        )

        invalid = self.temporary_root / "invalid-common.sh"
        invalid.write_text(
            replace_single_common_assignment(
                COMMON_SOURCE.read_text(encoding="utf-8"), "TRAEFIK_SHA256", "invalid"
            ),
            encoding="utf-8",
        )
        invalid_result = self.run_sync("--check", invalid, manifest)

        self.assertEqual(invalid_result.returncode, 2, invalid_result.stdout)
        self.assertIn("TRAEFIK_SHA256", invalid_result.stdout)


if __name__ == "__main__":
    unittest.main()
