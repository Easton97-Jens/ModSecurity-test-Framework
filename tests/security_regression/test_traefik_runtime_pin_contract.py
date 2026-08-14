"""Regression coverage for the canonical Traefik release-archive boundary."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
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
PREPARE_TRAEFIK = ROOT / "ci" / "provisioning" / "prepare-traefik-runtime.sh"
SYNC_MANIFEST = ROOT / "ci" / "tools" / "sync-traefik-runtime-manifest.py"
PINNED_VERSION = "3.7.10"
PINNED_SHA256 = "01811bb12d44f17280550f425f5e3128d6c325f2665c09e67a651ca535f490ce"
STALE_SHA256 = "9da81a928fde965c2c4678698bbc28bc3f600223b14c32b35bd480bf5ec863dc"
PINNED_PLATFORM = "linux_amd64"
PINNED_ARCHIVE = f"traefik_v{PINNED_VERSION}_{PINNED_PLATFORM}.tar.gz"


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
            common_source if common_source is not None else COMMON_SOURCE.read_text(encoding="utf-8"),
            {},
        )
        lib_root = fixture_root / "ci" / "lib"
        provisioning_root = fixture_root / "ci" / "provisioning"
        provisioning_root.mkdir(parents=True, exist_ok=True)
        shutil.copy2(PATH_BOOTSTRAP, lib_root / "path-bootstrap.sh")
        shutil.copy2(PATH_HELPER, lib_root / "path.sh")
        shutil.copy2(RUNTIME_COMPONENT_HELPER, lib_root / "runtime-component-common.sh")
        shutil.copy2(CONNECTOR_SMOKE_HELPER, lib_root / "connector-smoke-common.sh")
        fixture_prepare = provisioning_root / "prepare-traefik-runtime.sh"
        shutil.copy2(PREPARE_TRAEFIK, fixture_prepare)
        (fixture_root / "Makefile").write_text("# fixture\n", encoding="utf-8")
        (fixture_root / "tests").mkdir()
        return fixture_root, fixture_common, fixture_prepare

    def write_fake_traefik_archive(self, root: Path, archive: Path) -> str:
        source_binary = root / "archive-source" / "traefik"
        source_binary.parent.mkdir(parents=True, exist_ok=True)
        source_binary.write_text(
            "#!/bin/sh\nif [ \"${1:-}\" = version ]; then printf 'Version: 3.7.10\\n'; fi\n",
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
        return subprocess.run(
            ["python3", str(SYNC_MANIFEST), mode, "--common-sh", str(common), "--manifest", str(manifest)],
            cwd=ROOT,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

    def test_canonical_tuple_is_the_current_reviewed_linux_amd64_archive(self) -> None:
        source = self.common.read_text(encoding="utf-8")

        self.assertIn(f'TRAEFIK_VERSION="{PINNED_VERSION}"', source)
        self.assertIn(f'TRAEFIK_SHA256="{PINNED_SHA256}"', source)
        self.assertIn('TRAEFIK_ARTIFACT_PLATFORM="linux_amd64"', source)
        self.assertIn(
            'TRAEFIK_ARCHIVE_NAME="traefik_v${TRAEFIK_VERSION}_${TRAEFIK_ARTIFACT_PLATFORM}.tar.gz"',
            source,
        )
        self.assertIn("ci_require_traefik_pinned_provenance", source)

        completed = self.run_common_guard()

        self.assertEqual(completed.returncode, 0, completed.stdout)

    def test_environment_tuple_overrides_and_partial_tuples_fail_closed(self) -> None:
        invalid = {
            "old-version": {"TRAEFIK_VERSION": "3.7.5"},
            "empty-version": {"TRAEFIK_VERSION": ""},
            "foreign-source": {"TRAEFIK_SOURCE_URL": "https://mirror.example.invalid/traefik"},
            "wrong-download": {"TRAEFIK_DOWNLOAD_URL": "https://github.com/traefik/traefik/releases/download/v3.7.10/other.tar.gz"},
            "missing-sha": {"TRAEFIK_SHA256": ""},
            "malformed-sha": {"TRAEFIK_SHA256": "not-a-sha256"},
            "wrong-platform": {"TRAEFIK_ARTIFACT_PLATFORM": "linux_arm64"},
            "wrong-archive": {"TRAEFIK_ARCHIVE_NAME": "traefik_v3.7.10_linux_arm64.tar.gz"},
            "unverified-binary": {"TRAEFIK_BIN": "/tmp/arbitrary-traefik"},
            "self-consistent-replacement": {
                "TRAEFIK_VERSION": "3.7.5",
                "TRAEFIK_SOURCE_URL": "https://github.com/traefik/traefik/releases",
                "TRAEFIK_DOWNLOAD_URL": "https://github.com/traefik/traefik/releases/download/v3.7.5/traefik_v3.7.5_linux_amd64.tar.gz",
                "TRAEFIK_SHA256": "a" * 64,
                "TRAEFIK_SHA256_URL": "https://github.com/traefik/traefik/releases/download/v3.7.5/traefik_v3.7.5_checksums.txt",
                "TRAEFIK_ARTIFACT_PLATFORM": "linux_amd64",
                "TRAEFIK_ARCHIVE_NAME": "traefik_v3.7.5_linux_amd64.tar.gz",
            },
        }
        for case, overrides in invalid.items():
            with self.subTest(case=case):
                completed = self.run_common_guard(overrides)

                self.assertEqual(completed.returncode, 77, completed.stdout)
                self.assertIn("BLOCKED:", completed.stdout)

    def test_post_source_mutations_and_internal_missing_metadata_fail_closed(self) -> None:
        post_source = subprocess.run(
            [
                "sh",
                "-eu",
                "-c",
                '\n'.join(
                    (
                        '. "$COMMON_SH"',
                        'TRAEFIK_DOWNLOAD_URL="https://github.com/traefik/traefik/releases/download/v3.7.10/other.tar.gz"',
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
            "wrong-platform": "linux_arm64",
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
        common_source = replace_single_common_assignment(
            common.read_text(encoding="utf-8"), "TRAEFIK_SHA256", digest
        )
        common.write_text(common_source, encoding="utf-8")

        completed = self.run_preparer(fixture_root, prepare)
        staged = archive.parents[1] / "bin" / "traefik"

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
        common.write_text(
            replace_single_common_assignment(
                common.read_text(encoding="utf-8"), "TRAEFIK_SHA256", "0" * 64
            ),
            encoding="utf-8",
        )

        completed = self.run_preparer(fixture_root, prepare)
        component_root = archive.parents[1]

        self.assertEqual(completed.returncode, 77, completed.stdout)
        self.assertIn("SHA256 verification failed", completed.stdout)
        self.assertFalse((component_root / "bin" / "traefik").exists())
        self.assertFalse((component_root / "extract").exists())

    def test_missing_archive_propagates_the_blocked_status_from_the_resolver(self) -> None:
        fixture_root, common, _prepare = self.create_framework_fixture("missing-archive")

        completed = self.run_resolver(fixture_root, common)
        component_root = self.fixture_verified_root(fixture_root) / "cache-v2" / "shared" / "traefik"

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
                printf 'Version: 3.7.10\\n'
                """
            ),
            encoding="utf-8",
        )
        binary.chmod(0o755)
        environment = self.preparer_environment(fixture_root)
        environment.update(
            {
                "SMOKE_COMMON": str(fixture_root / "ci" / "lib" / "connector-smoke-common.sh"),
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

    def test_manifest_write_is_deterministic_and_check_reports_expected_found(self) -> None:
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
            "version": "3.7.5",
            "sha256": "0" * 64,
            "old-pin-hash": STALE_SHA256,
            "artifact_platform": "linux/arm64",
            "missing-archive": None,
        }
        for case, value in mutations.items():
            with self.subTest(case=case):
                candidate = json.loads(json.dumps(document))
                target = candidate["components"][0]
                if case == "missing-archive":
                    target.pop("archive_name")
                elif case == "old-pin-hash":
                    target["sha256"] = value
                else:
                    target[case] = value
                manifest.write_text(json.dumps(candidate), encoding="utf-8")
                divergent = self.run_sync("--check", self.common, manifest)

                self.assertEqual(divergent.returncode, 1, divergent.stdout)
                self.assertIn("expected", divergent.stdout)
                self.assertIn("found", divergent.stdout)

    def test_manifest_tool_rejects_duplicate_manual_pin_and_invalid_source_metadata(self) -> None:
        manifest = self.temporary_root / "runtime-components.manifest.json"
        self.write_minimal_manifest(manifest)
        duplicate = self.temporary_root / "duplicate-common.sh"
        duplicate.write_text(
            COMMON_SOURCE.read_text(encoding="utf-8") + '\nTRAEFIK_VERSION="3.7.5"\n',
            encoding="utf-8",
        )

        duplicate_result = self.run_sync("--check", duplicate, manifest)

        self.assertEqual(duplicate_result.returncode, 2, duplicate_result.stdout)
        self.assertIn("exactly one manually maintained TRAEFIK_VERSION literal", duplicate_result.stdout)

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
