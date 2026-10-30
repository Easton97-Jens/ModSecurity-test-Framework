"""Focused v2 policy-profile and CRS-bundle contracts for the root broker."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


ROOT = connector_root()
BROKER_PATH = source_path('ci/runtime/broker/nginx_root_broker.py', root=ROOT)
BROKER = load_source(BROKER_PATH)


BROKER_SHA = "a" * 40
PARENT_SHA = "b" * 40
FRAMEWORK_SHA = "c" * 40


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TrustedNginxRootBrokerCrsProfileTest(unittest.TestCase):
    def private_dir(self, path: Path) -> Path:
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700)
        return path

    def crs_source_dir(self, path: Path) -> Path:
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o755)
        return path

    def write(self, path: Path, text: str, mode: int = 0o600) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        path.chmod(mode)
        return path

    def write_binary(self, path: Path, source: Path, mode: int = 0o600) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(source.read_bytes())
        path.chmod(mode)
        return path

    def caller_payload(self, *, variant: str, profile: str) -> dict[str, object]:
        return {
            "schema_version": BROKER.SCHEMA_VERSION_V2,
            "run_id": "broker-v2-run-1",
            "matrix_variant": variant,
            "policy_profile": profile,
            "parent_head_sha": PARENT_SHA,
            "framework_sha": FRAMEWORK_SHA,
            "protected_broker_sha": BROKER_SHA,
        }

    def prepare_arguments(self, root: Path) -> argparse.Namespace:
        build = self.private_dir(root / "trusted-build")
        binary = self.write(build / "nginx", "trusted binary\n", 0o700)
        module = self.write_binary(build / "ngx_http_modsecurity_module.so", Path("/usr/bin/true"))
        library = self.write_binary(build / BROKER.ARTIFACT_LIBRARY_NAME, Path("/usr/bin/true"))
        caller = self.write(root / "caller-manifest.json", "{}\n")
        return argparse.Namespace(
            caller_manifest=str(caller),
            trusted_build_root=str(build),
            broker_sha=BROKER_SHA,
            binary=str(binary),
            binary_sha256=digest(binary),
            module=str(module),
            module_sha256=digest(module),
            modsecurity_library=str(library),
            library_sha256=digest(library),
            nginx_version="1.31.4",
            worker_user="www-data",
            loopback="127.0.0.1",
            port=18443,
            expected_parent_head=PARENT_SHA,
            expected_framework_sha=FRAMEWORK_SHA,
            expected_run_id="broker-v2-run-1",
            expected_matrix_variant="",
        )

    def write_v2_caller(self, arguments: argparse.Namespace, *, variant: str, profile: str) -> None:
        self.write(
            Path(arguments.caller_manifest),
            json.dumps(self.caller_payload(variant=variant, profile=profile), sort_keys=True) + "\n",
        )

    def write_bundle(self, build: Path) -> tuple[Path, dict[str, object]]:
        bundle = self.private_dir(build / BROKER.CRS_BUNDLE_DIRECTORY_NAME)
        files = self.private_dir(bundle / BROKER.CRS_BUNDLE_FILES_DIRECTORY_NAME)
        contents = {
            "crs-setup.conf.example": "SecAction \"id:900000,phase:1,pass,nolog\"\n",
            "rules/REQUEST-949-BLOCKING-EVALUATION.conf": (
                "SecRule ARGS \"@rx .+\" \"id:949110,phase:2,deny,status:403,log\"\n"
            ),
        }
        records: list[dict[str, object]] = []
        for relative, content in sorted(contents.items()):
            self.private_dir((files / relative).parent)
            path = self.write(files / relative, content, 0o400)
            records.append(
                {
                    "path": relative,
                    "sha256": digest(path),
                    "size": path.stat().st_size,
                    "mode": "0644",
                    "type": "regular",
                    "bundle_commit": BROKER_SHA,
                    "crs_commit": BROKER.CRS_APPROVED_COMMIT,
                }
            )
        manifest: dict[str, object] = {
            "schema_version": BROKER.CRS_BUNDLE_SCHEMA_VERSION,
            "repository": BROKER.CRS_APPROVED_REPOSITORY,
            "release_tag": BROKER.CRS_RELEASE_TAG,
            "commit": BROKER.CRS_APPROVED_COMMIT,
            "framework_sha": FRAMEWORK_SHA,
            "broker_sha": BROKER_SHA,
            "generated_at": "2026-08-09T00:00:00Z",
            "files": records,
            "file_count": len(records),
        }
        manifest["bundle_digest"] = BROKER.crs_bundle_digest(
            repository=BROKER.CRS_APPROVED_REPOSITORY,
            release_tag=BROKER.CRS_RELEASE_TAG,
            commit=BROKER.CRS_APPROVED_COMMIT,
            framework_sha=FRAMEWORK_SHA,
            broker_sha=BROKER_SHA,
            files=records,
        )
        self.write(bundle / BROKER.CRS_BUNDLE_MANIFEST_FILENAME, json.dumps(manifest, sort_keys=True) + "\n", 0o400)
        return bundle, manifest

    def load_records(self, bundle: Path) -> list[dict[str, object]]:
        manifest = json.loads((bundle / BROKER.CRS_BUNDLE_MANIFEST_FILENAME).read_text(encoding="utf-8"))
        return BROKER.validate_crs_bundle_manifest(
            manifest,
            expected_framework_sha=FRAMEWORK_SHA,
            expected_broker_sha=BROKER_SHA,
        )

    def test_schema_v2_profiles_are_closed_and_variant_bound(self) -> None:
        no_crs = self.caller_payload(variant="no-crs", profile=BROKER.POLICY_PROFILE_NO_CRS)
        with_crs = self.caller_payload(variant="with-crs", profile=BROKER.POLICY_PROFILE_OWASP_CRS)
        self.assertEqual(BROKER.validate_caller_manifest(no_crs)["policy_profile"], BROKER.POLICY_PROFILE_NO_CRS)
        self.assertEqual(BROKER.validate_caller_manifest(with_crs)["policy_profile"], BROKER.POLICY_PROFILE_OWASP_CRS)

        invalid_schema = dict(with_crs, schema_version=99)
        with self.assertRaisesRegex(BROKER.BrokerError, "unsupported schema"):
            BROKER.validate_caller_manifest(invalid_schema)
        invalid_profile = dict(with_crs, policy_profile="latest")
        with self.assertRaisesRegex(BROKER.BrokerError, "not allowed"):
            BROKER.validate_caller_manifest(invalid_profile)
        mismatched_profile = dict(with_crs, policy_profile=BROKER.POLICY_PROFILE_NO_CRS)
        with self.assertRaisesRegex(BROKER.BrokerError, "does not match"):
            BROKER.validate_caller_manifest(mismatched_profile)
        forbidden_crs_field = dict(no_crs, crs_source_path="/caller/controlled")
        with self.assertRaisesRegex(BROKER.BrokerError, "unknown fields"):
            BROKER.validate_caller_manifest(forbidden_crs_field)

    def test_schema_v2_candidate_keeps_no_crs_clean_and_binds_the_crs_bundle(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-v2-") as temporary:
            root = Path(temporary)
            no_crs_arguments = self.prepare_arguments(root / "no-crs")
            self.write_v2_caller(
                no_crs_arguments,
                variant="no-crs",
                profile=BROKER.POLICY_PROFILE_NO_CRS,
            )
            no_crs_candidate = json.loads(BROKER.prepare_candidate(no_crs_arguments).read_text(encoding="utf-8"))
            self.assertEqual(no_crs_candidate["policy_profile"], BROKER.POLICY_PROFILE_NO_CRS)
            self.assertNotIn("crs", no_crs_candidate)

            with_crs_arguments = self.prepare_arguments(root / "with-crs")
            self.write_v2_caller(
                with_crs_arguments,
                variant="with-crs",
                profile=BROKER.POLICY_PROFILE_OWASP_CRS,
            )
            self.write_bundle(Path(with_crs_arguments.trusted_build_root))
            candidate = json.loads(BROKER.prepare_candidate(with_crs_arguments).read_text(encoding="utf-8"))
            self.assertEqual(candidate["policy_profile"], BROKER.POLICY_PROFILE_OWASP_CRS)
            self.assertEqual(
                {
                    name: record["sha256"]
                    for name, record in no_crs_candidate["artifacts"].items()
                },
                {
                    name: record["sha256"]
                    for name, record in candidate["artifacts"].items()
                },
            )
            self.assertNotEqual(
                no_crs_candidate["artifacts"]["binary"]["path"],
                candidate["artifacts"]["binary"]["path"],
            )
            self.assertNotEqual(no_crs_candidate["staging_root"], candidate["staging_root"])
            self.assertEqual(candidate["crs"]["crs_commit"], BROKER.CRS_APPROVED_COMMIT)
            self.assertEqual(candidate["crs"]["expected_crs_evidence"]["rule_id"], BROKER.CRS_EXPECTED_RULE_ID)
            staged = Path(candidate["staging_root"]) / BROKER.CRS_BUNDLE_DIRECTORY_NAME
            self.assertTrue((staged / BROKER.CRS_BUNDLE_MANIFEST_FILENAME).is_file())
            self.assertEqual(stat.S_IMODE((staged / BROKER.CRS_BUNDLE_MANIFEST_FILENAME).stat().st_mode), 0o400)

    def test_with_crs_candidate_requires_the_protected_bundle(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-v2-") as temporary:
            arguments = self.prepare_arguments(Path(temporary))
            self.write_v2_caller(
                arguments,
                variant="with-crs",
                profile=BROKER.POLICY_PROFILE_OWASP_CRS,
            )
            with self.assertRaisesRegex(BROKER.BrokerError, "protected CRS bundle root"):
                BROKER.prepare_candidate(arguments)

    def test_protected_bundle_builder_creates_a_closed_manifested_copy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-v2-") as temporary:
            trusted_build = self.private_dir(Path(temporary) / "trusted-build")
            source = self.crs_source_dir(trusted_build / BROKER.CRS_BUNDLE_SOURCE_RELATIVE)
            self.crs_source_dir(source / "rules")
            self.write(source / "crs-setup.conf.example", "SecAction \"id:900000,phase:1,pass,nolog\"\n", 0o644)
            self.write(
                source / "rules" / "REQUEST-949-BLOCKING-EVALUATION.conf",
                "SecRule ARGS \"@rx .+\" \"id:949110,phase:2,deny,status:403,log\"\n",
                0o644,
            )
            arguments = argparse.Namespace(
                trusted_build_root=str(trusted_build),
                framework_root=str(Path(temporary) / "protected-framework"),
                framework_sha=FRAMEWORK_SHA,
                broker_sha=BROKER_SHA,
            )

            with mock.patch.object(BROKER, "validate_protected_crs_contract"):
                output = BROKER.prepare_crs_bundle(arguments)

            manifest_path = output / BROKER.CRS_BUNDLE_MANIFEST_FILENAME
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            records = BROKER.validate_crs_bundle_manifest(
                manifest,
                expected_framework_sha=FRAMEWORK_SHA,
                expected_broker_sha=BROKER_SHA,
            )
            self.assertEqual([record["path"] for record in records], sorted(record["path"] for record in records))
            self.assertEqual(manifest["file_count"], 2)
            self.assertEqual(stat.S_IMODE(manifest_path.stat().st_mode), 0o400)
            copied_rule = output / BROKER.CRS_BUNDLE_FILES_DIRECTORY_NAME / "rules/REQUEST-949-BLOCKING-EVALUATION.conf"
            self.assertEqual(stat.S_IMODE(copied_rule.stat().st_mode), 0o400)

    def test_only_the_pinned_empty_after_placeholder_may_be_empty(self) -> None:
        def fixture(root: Path) -> tuple[argparse.Namespace, Path, Path, Path]:
            trusted_build = self.private_dir(root / "trusted-build")
            source = self.crs_source_dir(trusted_build / BROKER.CRS_BUNDLE_SOURCE_RELATIVE)
            rules = self.crs_source_dir(source / "rules")
            plugins = self.crs_source_dir(source / "plugins")
            self.write(source / "crs-setup.conf.example", "SecAction \"id:900000,phase:1,pass,nolog\"\n", 0o644)
            self.write(
                rules / "REQUEST-949-BLOCKING-EVALUATION.conf",
                "SecRule ARGS \"@rx .+\" \"id:949110,phase:2,deny,status:403,log\"\n",
                0o644,
            )
            arguments = argparse.Namespace(
                trusted_build_root=str(trusted_build),
                framework_root=str(root / "protected-framework"),
                framework_sha=FRAMEWORK_SHA,
                broker_sha=BROKER_SHA,
            )
            return arguments, source, rules, plugins

        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-v2-") as temporary:
            arguments, _, _, plugins = fixture(Path(temporary))
            placeholder = self.write(
                plugins / BROKER.CRS_EMPTY_AFTER_PLACEHOLDER_RELATIVE.name,
                "",
                0o644,
            )
            self.assertEqual(digest(placeholder), BROKER.CRS_EMPTY_AFTER_PLACEHOLDER_SHA256)
            with mock.patch.object(BROKER, "validate_protected_crs_contract"):
                output = BROKER.prepare_crs_bundle(arguments)
            manifest = json.loads((output / BROKER.CRS_BUNDLE_MANIFEST_FILENAME).read_text(encoding="utf-8"))
            records = BROKER.validate_crs_bundle_manifest(
                manifest,
                expected_framework_sha=FRAMEWORK_SHA,
                expected_broker_sha=BROKER_SHA,
            )
            empty_record = next(
                record
                for record in records
                if record["path"] == BROKER.CRS_EMPTY_AFTER_PLACEHOLDER_RELATIVE.as_posix()
            )
            self.assertEqual(empty_record["size"], 0)
            self.assertEqual(empty_record["sha256"], BROKER.CRS_EMPTY_AFTER_PLACEHOLDER_SHA256)
            copied_placeholder = output / BROKER.CRS_BUNDLE_FILES_DIRECTORY_NAME / BROKER.CRS_EMPTY_AFTER_PLACEHOLDER_RELATIVE
            self.assertEqual(copied_placeholder.stat().st_size, 0)
            self.assertEqual(stat.S_IMODE(copied_placeholder.stat().st_mode), 0o400)

            for field, value in (("release_tag", "v0.0.0"), ("commit", "d" * 40)):
                changed = json.loads(json.dumps(manifest))
                changed[field] = value
                with self.subTest(manifest_field=field), self.assertRaises(BROKER.BrokerError):
                    BROKER.validate_crs_bundle_manifest(
                        changed,
                        expected_framework_sha=FRAMEWORK_SHA,
                        expected_broker_sha=BROKER_SHA,
                    )

            wrong_digest = json.loads(json.dumps(manifest))
            for record in wrong_digest["files"]:
                if record["path"] == BROKER.CRS_EMPTY_AFTER_PLACEHOLDER_RELATIVE.as_posix():
                    record["sha256"] = "0" * 64
            with self.assertRaisesRegex(BROKER.BrokerError, "file size"):
                BROKER.validate_crs_bundle_manifest(
                    wrong_digest,
                    expected_framework_sha=FRAMEWORK_SHA,
                    expected_broker_sha=BROKER_SHA,
                )

            files = output / BROKER.CRS_BUNDLE_FILES_DIRECTORY_NAME
            unmanifested = files / "plugins/unmanifested-after.conf"
            self.write(unmanifested, "", 0o400)
            expected_device = files.stat().st_dev
            owner = os.geteuid()
            with self.assertRaisesRegex(BROKER.BrokerError, "extra unmanifested"):
                BROKER.validate_crs_bundle_files(
                    files,
                    records,
                    owner=owner,
                    directory_mode=0o700,
                    file_mode=0o400,
                    expected_device=expected_device,
                    label="test protected CRS bundle",
                )

        for name, relative, mode, kind in (
            ("other empty plugin", Path("plugins/other-after.conf"), 0o644, "empty"),
            ("empty rule", Path("rules/EMPTY.conf"), 0o644, "empty"),
            ("wrong placeholder mode", BROKER.CRS_EMPTY_AFTER_PLACEHOLDER_RELATIVE, 0o600, "empty"),
            ("placeholder symlink", BROKER.CRS_EMPTY_AFTER_PLACEHOLDER_RELATIVE, 0o644, "symlink"),
            ("placeholder FIFO", BROKER.CRS_EMPTY_AFTER_PLACEHOLDER_RELATIVE, 0o644, "fifo"),
        ):
            with self.subTest(source_case=name), tempfile.TemporaryDirectory(prefix="nginx-root-broker-v2-") as temporary:
                arguments, source, _, plugins = fixture(Path(temporary))
                target = source / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                if kind == "symlink":
                    replacement = self.write(plugins / "replacement-after.conf", "replacement\n", 0o644)
                    target.symlink_to(replacement)
                elif kind == "fifo":
                    os.mkfifo(target)
                else:
                    self.write(target, "", mode)
                with mock.patch.object(BROKER, "validate_protected_crs_contract"):
                    with self.assertRaises(BROKER.BrokerError):
                        BROKER.prepare_crs_bundle(arguments)

        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-v2-") as temporary:
            arguments, _, _, plugins = fixture(Path(temporary))
            self.write(plugins / "valid-after.conf", "SecAction \"id:900001,phase:1,pass,nolog\"\n", 0o644)
            with mock.patch.object(BROKER, "validate_protected_crs_contract"):
                output = BROKER.prepare_crs_bundle(arguments)
            records = BROKER.validate_crs_bundle_manifest(
                json.loads((output / BROKER.CRS_BUNDLE_MANIFEST_FILENAME).read_text(encoding="utf-8")),
                expected_framework_sha=FRAMEWORK_SHA,
                expected_broker_sha=BROKER_SHA,
            )
            self.assertIn("plugins/valid-after.conf", [record["path"] for record in records])

    def test_protected_crs_contract_binds_the_tag_and_empty_placeholder_git_blob(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-v2-") as temporary:
            root = Path(temporary)
            framework = self.private_dir(root / "framework")
            common = self.write(
                framework / "ci/lib/common.sh",
                "\n".join(
                    (
                        f'CRS_APPROVED_REPO_URL="{BROKER.CRS_APPROVED_REPOSITORY}"',
                        f'CRS_RELEASE_TAG="{BROKER.CRS_RELEASE_TAG}"',
                        f'CRS_APPROVED_COMMIT="{BROKER.CRS_APPROVED_COMMIT}"',
                        "",
                    )
                ),
                0o600,
            )
            self.assertTrue(common.is_file())
            source = self.crs_source_dir(root / "source")

            def protected_values(*, tag: str = BROKER.CRS_APPROVED_COMMIT, blob: str = BROKER.CRS_EMPTY_AFTER_PLACEHOLDER_BLOB):
                def value(directory: Path, label: str, *arguments: str) -> str:
                    if directory == framework and arguments == ("rev-parse", "HEAD"):
                        return FRAMEWORK_SHA
                    if directory == source and arguments == ("config", "--get", "remote.origin.url"):
                        return BROKER.CRS_APPROVED_REPOSITORY
                    if directory == source and arguments == ("rev-parse", "HEAD"):
                        return BROKER.CRS_APPROVED_COMMIT
                    if directory == source and arguments == ("rev-parse", f"refs/tags/{BROKER.CRS_RELEASE_TAG}^{{}}"):
                        return tag
                    if directory == source and arguments == (
                        "rev-parse",
                        f"{BROKER.CRS_APPROVED_COMMIT}:{BROKER.CRS_EMPTY_AFTER_PLACEHOLDER_RELATIVE.as_posix()}",
                    ):
                        return blob
                    self.fail(f"unexpected protected Git lookup: {directory} {label} {arguments}")
                return value

            with mock.patch.object(BROKER, "protected_git_value", side_effect=protected_values()):
                BROKER.validate_protected_crs_contract(source, framework, FRAMEWORK_SHA)
            with mock.patch.object(BROKER, "protected_git_value", side_effect=protected_values(tag="d" * 40)):
                with self.assertRaisesRegex(BROKER.BrokerError, "release tag"):
                    BROKER.validate_protected_crs_contract(source, framework, FRAMEWORK_SHA)
            with mock.patch.object(BROKER, "protected_git_value", side_effect=protected_values(blob="0" * 40)):
                with self.assertRaisesRegex(BROKER.BrokerError, "empty placeholder object"):
                    BROKER.validate_protected_crs_contract(source, framework, FRAMEWORK_SHA)

    def test_protected_bundle_builder_rejects_unsafe_fresh_source_modes(self) -> None:
        def fixture(root: Path) -> tuple[argparse.Namespace, Path, Path]:
            trusted_build = self.private_dir(root / "trusted-build")
            source = self.crs_source_dir(trusted_build / BROKER.CRS_BUNDLE_SOURCE_RELATIVE)
            rules = self.crs_source_dir(source / "rules")
            setup = self.write(
                source / "crs-setup.conf.example",
                "SecAction \"id:900000,phase:1,pass,nolog\"\n",
                0o644,
            )
            self.write(
                rules / "REQUEST-949-BLOCKING-EVALUATION.conf",
                "SecRule ARGS \"@rx .+\" \"id:949110,phase:2,deny,status:403,log\"\n",
                0o644,
            )
            return (
                argparse.Namespace(
                    trusted_build_root=str(trusted_build),
                    framework_root=str(root / "protected-framework"),
                    framework_sha=FRAMEWORK_SHA,
                    broker_sha=BROKER_SHA,
                ),
                source,
                setup,
            )

        for name, target, mode in (
            ("source file 0600", "setup", 0o600),
            ("source file 0664", "setup", 0o664),
            ("source file 0666", "setup", 0o666),
            ("source root 0700", "source", 0o700),
            ("rules directory 0700", "rules", 0o700),
            ("rules directory 0775", "rules", 0o775),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix="nginx-root-broker-v2-") as temporary:
                arguments, source, setup = fixture(Path(temporary))
                selected = {
                    "setup": setup,
                    "source": source,
                    "rules": source / "rules",
                }[target]
                selected.chmod(mode)
                with mock.patch.object(BROKER, "validate_protected_crs_contract"):
                    with self.assertRaises(BROKER.BrokerError):
                        BROKER.prepare_crs_bundle(arguments)

        for name in ("symlink", "hardlink", "fifo"):
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix="nginx-root-broker-v2-") as temporary:
                arguments, _, setup = fixture(Path(temporary))
                if name == "symlink":
                    replacement = self.write(setup.parent / "replacement.conf", "replacement\n", 0o644)
                    setup.unlink()
                    setup.symlink_to(replacement)
                elif name == "hardlink":
                    os.link(setup, setup.parent / "linked.conf")
                else:
                    setup.unlink()
                    os.mkfifo(setup)
                with mock.patch.object(BROKER, "validate_protected_crs_contract"):
                    with self.assertRaises(BROKER.BrokerError):
                        BROKER.prepare_crs_bundle(arguments)

    def test_optional_protected_crs_plugins_must_be_exact_0755_directories(self) -> None:
        def fixture(root: Path) -> tuple[Path, Path]:
            source = self.crs_source_dir(root / BROKER.CRS_BUNDLE_SOURCE_RELATIVE)
            rules = self.crs_source_dir(source / "rules")
            plugins = self.crs_source_dir(source / "plugins")
            self.write(source / "crs-setup.conf.example", "SecAction \"id:900000,phase:1,pass,nolog\"\n", 0o644)
            self.write(
                rules / "REQUEST-949-BLOCKING-EVALUATION.conf",
                "SecRule ARGS \"@rx .+\" \"id:949110,phase:2,deny,status:403,log\"\n",
                0o644,
            )
            self.write(
                plugins / "optional-plugin-before.conf",
                "SecAction \"id:900001,phase:1,pass,nolog\"\n",
                0o644,
            )
            return source, plugins

        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-v2-") as temporary:
            source, _ = fixture(Path(temporary))
            selected = BROKER.selected_crs_source_files(source, BROKER_SHA)
            self.assertIn("plugins/optional-plugin-before.conf", [record["path"] for _, record in selected])

        for mode in (0o700, 0o775):
            with self.subTest(mode=oct(mode)), tempfile.TemporaryDirectory(
                prefix="nginx-root-broker-v2-"
            ) as temporary:
                source, plugins = fixture(Path(temporary))
                plugins.chmod(mode)
                with self.assertRaisesRegex(BROKER.BrokerError, "plugins directory"):
                    BROKER.selected_crs_source_files(source, BROKER_SHA)

    def test_bundle_manifest_rejects_moving_or_wrong_provenance(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-v2-") as temporary:
            bundle, manifest = self.write_bundle(self.private_dir(Path(temporary) / "trusted-build"))
            self.assertEqual(len(self.load_records(bundle)), 2)
            for field, value, expression in (
                ("repository", "https://example.invalid/crs.git", "repository"),
                ("release_tag", "main", "release tag"),
                ("commit", "d" * 40, "commit"),
                ("framework_sha", "d" * 40, "framework SHA"),
                ("broker_sha", "d" * 40, "broker SHA"),
            ):
                changed = dict(manifest, **{field: value})
                with self.subTest(field=field):
                    with self.assertRaisesRegex(BROKER.BrokerError, expression):
                        BROKER.validate_crs_bundle_manifest(
                            changed,
                            expected_framework_sha=FRAMEWORK_SHA,
                            expected_broker_sha=BROKER_SHA,
                        )

    def test_bundle_manifest_rejects_unsafe_path_and_duplicate_records(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-v2-") as temporary:
            bundle, manifest = self.write_bundle(self.private_dir(Path(temporary) / "trusted-build"))
            for unsafe_path in ("../rules/escape.conf", "/rules/escape.conf"):
                changed = json.loads(json.dumps(manifest))
                changed["files"][0]["path"] = unsafe_path
                with self.subTest(path=unsafe_path):
                    with self.assertRaisesRegex(BROKER.BrokerError, "path"):
                        BROKER.validate_crs_bundle_manifest(
                            changed,
                            expected_framework_sha=FRAMEWORK_SHA,
                            expected_broker_sha=BROKER_SHA,
                        )
            duplicate = json.loads(json.dumps(manifest))
            duplicate["files"].append(dict(duplicate["files"][0]))
            duplicate["file_count"] = len(duplicate["files"])
            with self.assertRaisesRegex(BROKER.BrokerError, "duplicate"):
                BROKER.validate_crs_bundle_manifest(
                    duplicate,
                    expected_framework_sha=FRAMEWORK_SHA,
                    expected_broker_sha=BROKER_SHA,
                )

    def test_bundle_tree_rejects_links_special_entries_mutation_and_missing_files(self) -> None:
        def validate(files: Path, records: list[dict[str, object]]) -> None:
            BROKER.validate_crs_bundle_files(
                files,
                records,
                owner=os.geteuid(),
                directory_mode=0o700,
                file_mode=0o400,
                expected_device=files.stat().st_dev,
                label="test CRS bundle",
            )

        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-v2-") as temporary:
            root = Path(temporary)
            for kind in ("symlink", "hardlink", "fifo", "extra", "missing", "size"):
                build = self.private_dir(root / kind / "trusted-build")
                bundle, _ = self.write_bundle(build)
                records = self.load_records(bundle)
                files = bundle / BROKER.CRS_BUNDLE_FILES_DIRECTORY_NAME
                rule = files / "rules" / "REQUEST-949-BLOCKING-EVALUATION.conf"
                if kind == "symlink":
                    replacement = self.write(files / "rules" / "replacement.conf", "replacement\n", 0o400)
                    rule.unlink()
                    rule.symlink_to(replacement)
                elif kind == "hardlink":
                    os.link(rule, files / "rules" / "linked.conf")
                elif kind == "fifo":
                    os.mkfifo(files / "rules" / "special")
                elif kind == "extra":
                    self.write(files / "rules" / "extra.conf", "extra\n", 0o400)
                elif kind == "missing":
                    rule.unlink()
                else:
                    rule.chmod(0o600)
                    self.write(rule, "mutated content\n", 0o400)
                with self.subTest(kind=kind):
                    with self.assertRaises(BROKER.BrokerError):
                        validate(files, records)

    def test_broker_generated_crs_rules_only_include_the_root_owned_bundle(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-v2-") as temporary:
            bundle, _ = self.write_bundle(self.private_dir(Path(temporary) / "trusted-build"))
            records = self.load_records(bundle)
            root = Path("/var/lib/msconnector-nginx-root-broker/broker-v2-run-1")
            rendered = BROKER.render_crs_rules(
                {
                    "crs_files": root / "runtime/crs/files",
                    "audit_log": root / "runtime/logs/nginx-audit.log",
                    "audit_dir": root / "runtime/logs/nginx-audit",
                },
                records,
            )
            self.assertIn("SecAuditLogType Serial", rendered)
            self.assertIn(str(root / "runtime/crs/files/crs-setup.conf.example"), rendered)
            self.assertIn(str(root / "runtime/crs/files/rules/REQUEST-949-BLOCKING-EVALUATION.conf"), rendered)
            self.assertNotIn("941001", rendered)
            self.assertNotIn("/caller/", rendered)
            self.assertNotIn("*", rendered)

    def test_root_bundle_admission_rejects_a_file_replaced_during_copy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-v2-") as temporary:
            root = Path(temporary)
            source_files = self.private_dir(root / "source/files")
            self.private_dir(source_files / "rules")
            source = self.write(source_files / "rules" / "rule.conf", "original rule\n", 0o400)
            destination = self.private_dir(root / "destination")
            destination.chmod(0o750)
            expected = digest(source)
            source_fd = os.open(source_files, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            destination_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            original_sha256_fd = BROKER.sha256_fd
            calls = 0
            source_device = source_files.stat().st_dev
            relative = Path("rules/rule.conf")
            expected_size = source.stat().st_size
            runner_uid = os.geteuid()
            worker_gid = os.getegid()
            destination_device = destination.stat().st_dev

            def replace_after_initial_digest(descriptor: int) -> str:
                nonlocal calls
                value = original_sha256_fd(descriptor)
                calls += 1
                if calls == 1:
                    source.chmod(0o600)
                    source.write_text("replaced rule\n", encoding="utf-8")
                    source.chmod(0o400)
                return value

            try:
                with mock.patch.object(BROKER, "sha256_fd", side_effect=replace_after_initial_digest):
                    with self.assertRaisesRegex(BROKER.BrokerError, "digest mismatch after root admission"):
                        BROKER.copy_bundle_file_into_root(
                            source_fd,
                            source_device,
                            relative,
                            destination_fd,
                            expected_sha256=expected,
                            expected_size=expected_size,
                            runner_uid=runner_uid,
                            worker_gid=worker_gid,
                            destination_device=destination_device,
                            label="test CRS replacement",
                        )
            finally:
                os.close(source_fd)
                os.close(destination_fd)

    def test_audit_evidence_requires_the_expected_crs_rule_run_and_transaction(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-v2-") as temporary:
            root = self.private_dir(Path(temporary) / "broker-run-1")
            audit = self.write(
                root / "runtime/logs/nginx-audit.log",
                "\n".join(
                    (
                        "--transaction-v2-A--",
                        "GET /?id=1%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1",
                        "X-Broker-Run-ID: broker-v2-run-1",
                        "[id \"949110\"] Inbound Anomaly Score Exceeded",
                        "403",
                        "--transaction-v2-Z--",
                        "",
                    )
                ),
                0o600,
            )
            payload = {
                "runtime": {"audit_log": str(audit)},
                "broker_root": str(root),
                "worker": {"uid": os.geteuid()},
                "run_id": "broker-v2-run-1",
            }
            transaction, audit_digest = BROKER.read_crs_audit_evidence(payload)
            self.assertEqual(transaction, "transaction-v2")
            self.assertEqual(audit_digest, digest(audit))

            self.write(audit, "--wrong-A--\n403\n--wrong-Z--\n", 0o600)
            with self.assertRaisesRegex(BROKER.BrokerError, "bound to the protected run"):
                BROKER.read_crs_audit_evidence(payload)

            self.write(
                audit,
                "\n".join(
                    (
                        "--transaction-v2-A--",
                        "GET /?id=1%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1",
                        "X-Broker-Run-ID: broker-v2-run-1",
                        "[id \"949110\"] Inbound Anomaly Score Exceeded",
                        "403",
                        "--transaction-v2-Z--",
                        "--foreign-A--",
                        "foreign transaction",
                        "--foreign-Z--",
                        "",
                    )
                ),
                0o600,
            )
            with self.assertRaisesRegex(BROKER.BrokerError, "foreign transaction"):
                BROKER.read_crs_audit_evidence(payload)

    def test_with_crs_profile_refuses_a_stale_audit_file_before_requests(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-root-broker-v2-") as temporary:
            audit = self.write(Path(temporary) / "nginx-audit.log", "stale\n")
            payload = {
                "runtime": {"audit_log": str(audit)},
                "run_id": "broker-v2-run-1",
                "matrix_variant": "with-crs",
            }
            with (
                mock.patch.object(BROKER, "read_state", return_value={"started": True}),
                mock.patch.object(
                    BROKER,
                    "final_manifest_schema_and_profile",
                    return_value=(BROKER.SCHEMA_VERSION_V2, BROKER.POLICY_PROFILE_OWASP_CRS),
                ),
            ):
                with self.assertRaisesRegex(BROKER.BrokerError, "must be absent"):
                    BROKER.verify_runtime_profile(payload)

    def test_ipv6_profile_request_uses_a_real_ipv6_address_not_a_url_literal(self) -> None:
        class Response:
            status = 200

            def read(self, size: int) -> bytes:
                return b""

        class Connection:
            def request(self, method: str, path: str, headers: dict[str, str]) -> None:
                self.path = path

            def getresponse(self) -> Response:
                return Response()

            def close(self) -> None:
                return None

        payload = {"network": {"address": "::1", "port": 18443}, "run_id": "broker-v2-run-1"}
        with mock.patch.object(BROKER.http.client, "HTTPConnection", return_value=Connection()) as constructor:
            self.assertEqual(BROKER.fixed_loopback_request(payload, "/"), 200)
        self.assertEqual(constructor.call_args.args[:2], ("::1", 18443))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
