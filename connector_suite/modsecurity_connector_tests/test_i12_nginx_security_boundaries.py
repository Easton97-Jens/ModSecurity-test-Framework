"""NGINX evidence file boundaries; synthetic tests, never host qualification."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import tarfile
import unittest
from unittest.mock import patch


ROOT = connector_root()
HARNESS = source_path('ci/runtime/lifecycle/i12/nginx', root=ROOT)


def load(name):
    module = load_source(HARNESS / (name + '.py'))
    return module


BUILD = load("build_capture")
REPORT = load("report")
QUALIFY = load("qualify")
REVIEW = load("review_observations")
CONFIG = load("config_controls")


class EvidenceBoundaryTests(unittest.TestCase):
    def setUp(self):
        from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root
        configured = os.environ.get("I12_TEST_ROOT") or os.environ.get("RUNNER_TEMP")
        if not configured:
            raise ValueError("NGINX boundary tests require a private I12_TEST_ROOT or RUNNER_TEMP")
        run_root = validate_output_root(ROOT, Path(configured))
        configured_roots = patch.dict(os.environ, {
            "CODEX_TEMP_ROOT": str(run_root),
            "CODEX_RUN_ROOT": str(run_root),
        })
        configured_roots.start()
        self.addCleanup(configured_roots.stop)
        scratch = tempfile.TemporaryDirectory(prefix="nginx-boundary-", dir=run_root)
        self.addCleanup(scratch.cleanup)
        self.scratch = Path(scratch.name)
        self.image = self.scratch / "nginx"
        self.image.write_bytes(b"synthetic pinned native image\n")
        self.image.chmod(0o500)

    def archive(self, members):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for name, data, kind, mode in members:
                item = tarfile.TarInfo(name)
                item.type, item.mode, item.size = kind, mode, len(data)
                archive.addfile(item, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
        return stream.getvalue()

    def synthetic_inventory(self):
        payload = b"synthetic source\n"
        blob = hashlib.sha1(b"blob " + str(len(payload)).encode() + b"\0" + payload,
                            usedforsecurity=False).hexdigest()
        return payload, {"src/main.c": {"mode": 0o644, "git_blob": blob}}

    def test_git_inventory_requires_exact_ids_modes_paths_and_no_collisions(self):
        good = b"100644 blob " + b"a" * 40 + b"\tsrc/main.c\0"
        files, links = BUILD.tree_inventory(good + b"160000 commit " + b"b" * 40 + b"\tmodule\0")
        self.assertEqual(files["src/main.c"]["mode"], 0o644)
        self.assertEqual(links, {"module": "b" * 40})
        for invalid in (good + good, good.replace(b"100644", b"120000"),
                        good.replace(b"src/main.c", b"../escape"),
                        good.replace(b"a" * 40, b"a" * 39),
                        good + good.replace(b"src/main.c", b"src/main.c/child")):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    BUILD.tree_inventory(invalid)

    def test_archive_export_binds_exact_blobs_modes_and_gitlink_inventory(self):
        payload, files = self.synthetic_inventory()
        target = self.scratch / "export"
        target.mkdir()
        raw = self.archive([("src/", b"", tarfile.DIRTYPE, 0o755),
                            ("src/main.c", payload, tarfile.REGTYPE, 0o644)])
        inventory = BUILD.export_archive(raw, target, files, {"module": "b" * 40})
        self.assertEqual(inventory["src/main.c"], {"mode": 0o644, "sha256": hashlib.sha256(payload).hexdigest()})
        self.assertTrue((target / "module").is_dir())
        self.assertEqual(stat.S_IMODE((target / "src/main.c").stat().st_mode), 0o644)

    def test_archive_rejects_missing_extra_duplicate_link_special_mode_and_blob_changes(self):
        payload, files = self.synthetic_inventory()
        valid = ("src/main.c", payload, tarfile.REGTYPE, 0o644)
        cases = [[], [valid, valid], [("extra", payload, tarfile.REGTYPE, 0o644)],
                 [("../escape", payload, tarfile.REGTYPE, 0o644)]]
        # Each unsupported member is checked before any payload extraction.
        cases += [[("src/main.c", b"", kind, 0o644)] for kind in
                  (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE)]
        cases += [[("src/main.c", payload, tarfile.REGTYPE, 0o666)],
                  [("src/main.c", b"different", tarfile.REGTYPE, 0o644)]]
        for index, members in enumerate(cases):
            target = self.scratch / ("rejected-" + str(index))
            target.mkdir()
            with self.subTest(members=members):
                archive = self.archive(members)
                with self.assertRaises(ValueError):
                    BUILD.export_archive(archive, target, files, {})

    def test_v2_export_is_validated_by_unchanged_shared_snapshot_contract(self):
        capture = load_source(HARNESS.parent / 'capture_sources.py')
        payload, files = self.synthetic_inventory()
        archive = self.archive([("src/main.c", payload, tarfile.REGTYPE, 0o644)])
        def git(*args):
            if args[0] == "rev-parse":
                return ("b" * 40 + "\n").encode()
            if args[0] == "ls-tree":
                return ("100644 blob " + files["src/main.c"]["git_blob"] + "\tsrc/main.c\0").encode()
            if args == ("-c", "tar.umask=0022", "archive", "--format=tar", "a" * 40):
                return archive
            raise AssertionError(args)
        target = self.scratch / "v2"
        target.mkdir()
        result = BUILD.export_current(git, target, "a" * 40, capture)
        self.assertEqual(result["source_revision"], "a" * 40)
        self.assertEqual(result["source_git_tree"], "b" * 40)
        self.assertEqual(result["snapshot_file_count"], 1)
        self.assertEqual(result["source_identity_format"], "i12-disposable-source-copy-v2")
        (target / "src/main.c").write_bytes(b"tampered")
        with self.assertRaises(ValueError):
            capture.disposable(target, "irrelevant", Path("/var/tmp/codex/ModSecurity-conector"))

    def test_only_exact_observer_compatibility_transitions_are_permitted(self):
        for name, (current, before, after) in BUILD.OBSERVER_COMPATIBILITY.items():
            entry = {"before_sha256": before, "sha256": after}
            self.assertEqual(BUILD.permitted_transition(name, current, entry),
                             "explicit-historical-observer-compatibility")
            self.assertEqual(BUILD.permitted_transition(name, before, entry), "exact-profile-before")
            for changed_name, changed_current, changed_entry in (
                    ("other.c", current, entry), (name, "0" * 64, entry),
                    (name, current, {**entry, "sha256": "0" * 64})):
                with self.assertRaises(ValueError):
                    BUILD.permitted_transition(changed_name, changed_current, changed_entry)
        self.assertEqual(BUILD.permitted_transition("new.h", None,
                         {"before_sha256": None, "sha256": "a" * 64}), "exact-profile-before")

    def test_fresh_build_output_is_private_and_never_reuses_existing_directory(self):
        target = self.scratch / "build" / "fresh"
        self.assertEqual(BUILD.create_private_output(target), target)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(target.parent.stat().st_mode), 0o700)
        with self.assertRaises(FileExistsError):
            BUILD.create_private_output(target)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)

    def test_build_storage_requires_explicit_canonical_project_anchor(self):
        for value in ("", ".", "/", "relative/storage", str(self.scratch) + "/",
                      str(self.scratch) + "/../escape"):
            with self.subTest(value=value):
                with patch.dict(os.environ, {"CODEX_TEMP_ROOT": value}):
                    with self.assertRaises(ValueError):
                        BUILD.storage_root()
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                BUILD.storage_root()
        with patch.dict(os.environ, {"CODEX_TEMP_ROOT": str(self.scratch)}):
            self.assertEqual(BUILD.storage_root(), self.scratch)
            target = self.scratch / "configured-build"
            self.assertEqual(BUILD.create_private_output(target), target)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)

    def test_build_hash_reads_only_protected_regular_project_files(self):
        expected = hashlib.sha256(self.image.read_bytes()).hexdigest()
        self.assertEqual(BUILD.sha(self.image), expected)
        self.assertEqual(BUILD.command_path(self.image, self.scratch, regular=True), str(self.image))
        stage = self.scratch / "stage"
        stage.mkdir(mode=0o700)
        self.assertEqual(BUILD.command_path(stage, self.scratch, directory=True), str(stage))

        link = self.scratch / "linked-image"
        link.symlink_to(self.image)
        fifo = self.scratch / "image-fifo"
        os.mkfifo(fifo, mode=0o600)
        outside = Path("/etc/passwd")
        noncanonical = self.scratch / ".." / self.scratch.name / self.image.name
        for rejected in (link, fifo, outside, noncanonical, Path("relative-image")):
            with self.subTest(rejected=rejected), self.assertRaises(ValueError):
                BUILD.sha(rejected)
        with self.assertRaises(ValueError):
            BUILD.command_path(link, self.scratch, regular=True)

        self.image.chmod(0o666)
        try:
            with self.assertRaises(ValueError):
                BUILD.sha(self.image)
        finally:
            self.image.chmod(0o500)

    def test_fixture_compiler_uses_fixed_relative_arguments_and_retains_receipts(self):
        fixture_names = ("nginx_worker_self_maps", "nginx_common_input_fault",
                         "nginx_engine_budget_fault", "nginx_transaction_fault")
        source_root = self.scratch / "source-ordinary/tests/fixtures"
        source_root.mkdir(parents=True)
        for name in fixture_names:
            (source_root / (name + ".c")).write_text("synthetic fixture " + name)

        def compile_command(command, *, cwd, capture_output, shell):
            self.assertEqual(cwd, str(self.scratch))
            self.assertTrue(capture_output)
            self.assertIs(shell, False)
            self.assertEqual(command[:3], ["rtk", "proxy", "cc"])
            self.assertIn("-I./source-ordinary/common/include", command)
            self.assertFalse(any(str(self.scratch) in arg for arg in command))
            self.assertTrue(command[-1].startswith("./fixtures/"))
            (Path(cwd) / command[-1]).write_bytes(b"synthetic compiled fixture")
            return BUILD.subprocess.CompletedProcess(command, 0, b"compiler output", b"")

        with patch.object(BUILD.subprocess, "run", side_effect=compile_command) as compiler:
            BUILD.compile_fixtures(self.scratch)
        self.assertEqual(compiler.call_count, 4)
        receipt = json.loads((self.scratch / "fixtures/receipt.json").read_text())
        self.assertEqual(set(receipt), set(fixture_names))
        for name, entry in receipt.items():
            self.assertEqual(entry["exit"], 0)
            self.assertEqual(entry["cwd"], str(self.scratch))
            self.assertEqual(entry["source_sha256"], BUILD.sha(source_root / (name + ".c")))
            self.assertEqual(entry["library_sha256"], BUILD.sha(self.scratch / "fixtures" / (name + ".so")))
            self.assertEqual((self.scratch / "fixtures" / (name + ".stdout")).read_bytes(), b"compiler output")

    def test_fixture_compiler_rejects_untrusted_working_directory_before_execution(self):
        link = self.scratch / "linked-output"
        link.symlink_to(self.scratch, target_is_directory=True)
        for output in (link, Path(str(self.scratch) + ";injected"),
                       self.scratch / ".." / self.scratch.name, Path("/etc")):
            with self.subTest(output=output), patch.object(BUILD.subprocess, "run") as compiler:
                with self.assertRaises(ValueError):
                    BUILD.compile_fixtures(output)
                compiler.assert_not_called()
        self.assertFalse((self.scratch / "fixtures").exists())

    def test_configured_storage_anchor_cannot_itself_be_shared_sticky_transit(self):
        self.scratch.chmod(0o1777)
        self.addCleanup(self.scratch.chmod, 0o700)
        target = self.scratch / "forbidden-build"
        with patch.dict(os.environ, {"CODEX_TEMP_ROOT": str(self.scratch)}):
            with self.assertRaises(ValueError):
                BUILD.create_private_output(target)
        self.assertFalse(target.exists())

    def test_report_and_config_require_explicit_protected_storage_configuration(self):
        for variable, reader in (("CODEX_RUN_ROOT", REPORT.evidence_root),
                                 ("CODEX_TEMP_ROOT", CONFIG.artifact_root)):
            for value in ("", "relative/storage", str(self.scratch / ".." / "noncanonical")):
                with self.subTest(variable=variable, value=value):
                    with patch.dict(os.environ, {variable: value}):
                        with self.assertRaises(ValueError):
                            reader()
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaises(ValueError):
                    reader()
            self.scratch.chmod(0o777)
            try:
                with patch.dict(os.environ, {variable: str(self.scratch)}):
                    with self.assertRaises(ValueError):
                        reader()
            finally:
                self.scratch.chmod(0o700)

    def test_build_rejects_escape_links_and_writable_ancestors(self):
        rejected = (Path("/tmp/nginx-i12-untrusted-output"),
                    self.scratch / ".." / "escaped",
                    self.scratch / "unsafe output")
        for output in rejected:
            with self.subTest(output=output), self.assertRaises(ValueError):
                BUILD.create_private_output(output)
        link = self.scratch / "linked"
        link.symlink_to(self.scratch, target_is_directory=True)
        with self.assertRaises((OSError, ValueError)):
            BUILD.create_private_output(link / "fresh")
        writable = self.scratch / "writable"
        writable.mkdir(mode=0o777)
        writable.chmod(0o777)
        with self.assertRaises(ValueError):
            BUILD.create_private_output(writable / "fresh")
        self.assertEqual(stat.S_IMODE(writable.stat().st_mode), 0o777)

    def test_report_and_qualifier_accept_protected_regular_evidence(self):
        evidence = self.scratch / "receipt.json"
        evidence.write_text('{"result":"synthetic"}\n')
        self.assertEqual(REPORT.read(evidence), {"result": "synthetic"})
        reference = REPORT.reference(evidence)
        self.assertEqual(reference["sha256"], hashlib.sha256(evidence.read_bytes()).hexdigest())
        self.assertEqual(reference["bytes"], evidence.stat().st_size)
        self.assertEqual(QUALIFY.evidence_path(evidence), evidence)

    def test_evidence_readers_reject_symlinks_writable_files_and_nonfiles(self):
        link = self.scratch / "linked-image"
        link.symlink_to(self.image)
        for reader in (REPORT.evidence_path, QUALIFY.evidence_path):
            for unsafe in (link, self.scratch, Path("/etc/passwd"), self.scratch / ".." / "escape"):
                with self.subTest(reader=reader.__module__, unsafe=unsafe):
                    with self.assertRaises(ValueError):
                        reader(unsafe)
        self.image.chmod(0o666)
        for reader in (REPORT.evidence_path, QUALIFY.evidence_path):
            with self.assertRaises(ValueError):
                reader(self.image)

    def test_nested_reference_cannot_smuggle_an_external_file(self):
        with self.assertRaises(ValueError):
            QUALIFY.validate_references({"observations": [{"reference": {
                "path": "/etc/passwd", "sha256": "0" * 64}}]})

    def test_report_publication_is_limited_to_its_exact_tracked_destination(self):
        name = "ci/runtime/lifecycle/i12/nginx/evidence-20261015.json"
        self.assertEqual(REPORT.output_path(ROOT / name, name), ROOT / name)
        for destination in (self.scratch / "report.json", source_path('docs/unrelated.md', root=ROOT),
                            ROOT / "docs/../" / name):
            with self.subTest(destination=destination):
                with self.assertRaises(ValueError):
                    REPORT.output_path(destination, name)

    def test_approved_packet_destination_must_be_fresh_and_protected(self):
        destination = self.scratch / "new" / "approved"
        self.assertEqual(QUALIFY.publication_path(destination), destination)
        with self.assertRaises(ValueError):
            QUALIFY.publication_path(self.scratch)
        with self.assertRaises(ValueError):
            QUALIFY.publication_path(Path("/tmp/nginx-i12-approved"))
        link = self.scratch / "linked"
        link.symlink_to(self.scratch, target_is_directory=True)
        with self.assertRaises(ValueError):
            QUALIFY.publication_path(link / "approved")
        self.scratch.chmod(0o777)
        self.addCleanup(self.scratch.chmod, 0o700)
        with self.assertRaises(ValueError):
            QUALIFY.publication_path(self.scratch / "approved")

    def test_verification_projection_hash_binds_full_inventory_without_exposing_paths(self):
        hashes = {"private/operator/forwardauth.c": "1" * 64, "private/build.c": "2" * 64}
        source = {"checks": [{"name": "native", "status": "PASS"}], "input_sha256": hashes}
        projected = REPORT.public_summary(source)
        self.assertNotIn("input_sha256", projected)
        self.assertNotIn("private/operator", json.dumps(projected))
        self.assertEqual(projected["input_sha256_count"], 2)
        canonical = json.dumps(hashes, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.assertEqual(projected["input_sha256_set_sha256"], hashlib.sha256(canonical).hexdigest())
        changed = {**source, "input_sha256": {**hashes, "private/build.c": "3" * 64}}
        self.assertNotEqual(REPORT.public_summary(changed)["input_sha256_set_sha256"],
                            projected["input_sha256_set_sha256"])

    def test_selected_contract_projection_binds_source_inventory_without_exposing_paths(self):
        hashes = {"parent:connectors/traefik/forwardauth.c": "1" * 64}
        source = {"expected_phase": "P2", "original_source_hashes": hashes}
        projected = REPORT.public_selected_requirement(source)
        self.assertEqual(projected["expected_phase"], "P2")
        self.assertNotIn("original_source_hashes", projected)
        self.assertNotIn("forwardauth", json.dumps(projected))
        self.assertEqual(projected["original_source_hashes_count"], 1)
        self.assertEqual(projected["original_source_hashes_set_sha256"], REPORT.canonical_hash(hashes))

    def test_loaded_image_hashes_regular_protected_file_and_rejects_links_and_writable_image(self):
        metadata, digest = REVIEW.protected_image(self.image)
        self.assertEqual(metadata.st_size, self.image.stat().st_size)
        self.assertEqual(digest, hashlib.sha256(self.image.read_bytes()).hexdigest())
        link = self.scratch / "linked"
        link.symlink_to(self.image)
        with self.assertRaises((ValueError, OSError)):
            REVIEW.protected_image(link)
        self.image.chmod(0o666)
        with self.assertRaises(ValueError):
            REVIEW.protected_image(self.image)

    def test_loaded_image_rejects_writable_ancestry_and_fifo_without_blocking(self):
        fifo = self.scratch / "not-an-image"
        os.mkfifo(fifo, mode=0o600)
        with self.assertRaises(ValueError):
            REVIEW.protected_image(fifo)
        self.scratch.chmod(0o777)
        self.addCleanup(self.scratch.chmod, 0o700)
        with self.assertRaises(ValueError):
            REVIEW.protected_image(self.image)

    def test_namespace_worker_and_project_paths_resolve_to_distinct_backing_trees(self):
        admission = {"bindings": [{"target": "/mnt/artifacts", "source": str(self.scratch / "artifacts")},
                                   {"target": "/mnt", "source": str(self.scratch / "generic")}]}
        attempt = self.scratch / "attempt"
        namespace_root = Path(os.environ["CODEX_TEMP_ROOT"])
        worker_root = namespace_root.with_name("ModSecurity-nginx-i12")
        self.assertEqual(REVIEW.physical(str(worker_root / "nginx-i12-x/payload.txt"),
                                        attempt, admission),
                         attempt / "data/nginx-worker-runtime/nginx-i12-x/payload.txt")
        self.assertEqual(REVIEW.physical(str(namespace_root / "results/receipt.json"),
                                        attempt, admission), attempt / "data/results/receipt.json")
        self.assertEqual(REVIEW.physical("/mnt/artifacts/native/nginx", attempt, admission),
                         self.scratch / "artifacts/native/nginx")
        for invalid in ("/mnt/artifacts/../outside", "relative/image", "/mnt//artifacts/image"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    REVIEW.physical(invalid, attempt, admission)

    def test_configuration_arguments_must_be_canonical_owned_paths(self):
        self.assertEqual(CONFIG.trusted_path(self.image), self.image)
        self.assertEqual(CONFIG.trusted_path(self.scratch, directory=True), self.scratch)
        self.assertEqual(CONFIG.trusted_path(self.scratch / "fresh", fresh=True), self.scratch / "fresh")
        for unsafe in (str(self.image) + ';daemon on;', str(self.image) + '\nload_module bad;',
                       str(self.image) + "$(id)", "/etc/passwd", self.scratch / ".." / "escape"):
            with self.subTest(unsafe=unsafe):
                with self.assertRaises(ValueError):
                    CONFIG.trusted_path(unsafe)
        link = self.scratch / "linked"
        link.symlink_to(self.image)
        with self.assertRaises(ValueError):
            CONFIG.trusted_path(link)
        self.image.chmod(0o666)
        with self.assertRaises(ValueError):
            CONFIG.trusted_path(self.image)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
