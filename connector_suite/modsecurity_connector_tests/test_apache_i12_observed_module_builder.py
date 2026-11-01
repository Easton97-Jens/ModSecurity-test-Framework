"""Bounded identity/overlay tests; no second native build or host claim."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


MODULE = connector_root() / "ci/runtime/lifecycle/apache-i12/acceptance/build_observed_module.py"
builder = load_source(MODULE)


class OverlayTests(unittest.TestCase):
    def setUp(self):
        self.texts = {
            builder.SOURCE_FILES[0]: "P1\nADD\nFINISH\n    return msconnector_transaction_contract_record_request_metadata(&msr->contract,",
            builder.SOURCE_FILES[1]: "APPEND\n    ret = apr_bucket_read(bucket, &data, &len, block);\n"
                "    if (ret != APR_SUCCESS)\n        return ret;\n"
                "    rc = apr_bucket_read(bucket, &data, &len, APR_BLOCK_READ);\n"}
        self.anchors = [{"file": name, "original": old, "replacement": new, "occurrences_required": 1}
                        for name, old, new in [(builder.SOURCE_FILES[0], "P1", "FAULT_P1"),
                        (builder.SOURCE_FILES[0], "ADD", "FAULT_ADD"),
                        (builder.SOURCE_FILES[0], "FINISH", "FAULT_FINISH"),
                        (builder.SOURCE_FILES[1], "APPEND", "FAULT_APPEND")]]

    def test_bucket_observation_precedes_actual_read_and_null_seam_follows_success(self):
        changed = builder.instrument(self.texts, self.anchors)
        text = changed[builder.SOURCE_FILES[1]]
        for direction, expression in (("request", "ret = apr_bucket_read"), ("response", "rc = apr_bucket_read")):
            hook = 'apache_lifecycle_observe("actual_' + direction + '_apr_bucket_before_read"'
            self.assertEqual(text.count(hook), 1)
            self.assertLess(text.index(hook), text.index(expression))
        self.assertGreater(text.index("i12_apache_fault_after_bucket_read"), text.index("return ret;"))
        self.assertNotIn("FAULT", self.texts[builder.SOURCE_FILES[0]])

    def test_duplicate_read_anchor_rejected(self):
        self.texts[builder.SOURCE_FILES[1]] += "    ret = apr_bucket_read(bucket, &data, &len, block);"
        with self.assertRaisesRegex(ValueError, "exactly once"):
            builder.instrument(self.texts, self.anchors)

    def test_missing_fault_anchor_rejected(self):
        self.anchors[0]["original"] = "ABSENT"
        with self.assertRaisesRegex(ValueError, "exactly once"):
            builder.instrument(self.texts, self.anchors)

    def test_incomplete_fault_set_rejected(self):
        with self.assertRaisesRegex(ValueError, "four"):
            builder.instrument(self.texts, self.anchors[:3])

    def test_out_of_scope_anchor_rejected(self):
        self.anchors[0]["file"] = "common/runtime.c"
        with self.assertRaisesRegex(ValueError, "scope"):
            builder.instrument(self.texts, self.anchors)


class CanonicalCommandTests(unittest.TestCase):
    def command(self):
        return "libtool: compile: cc " + " ".join(sorted(builder.STRICT)) + " -c src/mod_security3.c -o src/.libs/mod_security3.o"

    def test_actual_transcript_preserves_hardening(self):
        argv = builder.compiler_argv(self.command(), "src/mod_security3.c")
        self.assertTrue(builder.STRICT.issubset(argv))

    def test_missing_hardening_rejected(self):
        command = self.command().replace("-fstack-protector-strong", "")
        with self.assertRaisesRegex(ValueError, "strict"):
            builder.compiler_argv(command, "src/mod_security3.c")

    def test_duplicate_command_rejected(self):
        command = self.command() + "\n" + self.command()
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            builder.compiler_argv(command, "src/mod_security3.c")

    def test_response_file_rejected(self):
        command = self.command() + " @options"
        with self.assertRaisesRegex(ValueError, "injection"):
            builder.compiler_argv(command, "src/mod_security3.c")

    def test_dependency_output_flags_rejected(self):
        for flags in ("-MMD -MF src/.deps/module.d", "-MFsrc/immutable.d", "-Wp,-MD,src/deps.d",
                      "-MJ src/compile.json", "--dependency-file=src/immutable.d", "-Xpreprocessor -MD"):
            command = self.command() + " " + flags
            with self.subTest(flags=flags), self.assertRaisesRegex(ValueError, "dependency output"):
                builder.compiler_argv(command, "src/mod_security3.c")

    def test_auxiliary_outputs_rejected(self):
        for flag in ("-save-temps", "-dumpdir=src/", "-fprofile-arcs", "-ftest-coverage"):
            command = self.command() + " " + flag
            with self.subTest(flag=flag), self.assertRaisesRegex(ValueError, "output"):
                builder.compiler_argv(command, "src/mod_security3.c")


class ElfValidationTests(unittest.TestCase):
    def test_apache_wrapper_scope_is_explicit_and_implemented(self):
        symbols = builder.apache_wrapped_symbols(
            connector_root() / "tests/test_native_lifecycle_observer.py")
        self.assertEqual(symbols, list(
            builder.APACHE_NATIVE_WRAPPED_SYMBOLS + builder.APACHE_HOST_WRAPPED_SYMBOLS))
        self.assertEqual(len(symbols), 28)
        self.assertTrue(set(symbols).isdisjoint(builder.SHARED_NON_APACHE_WRAPPED_SYMBOLS))

    def test_defined_wrapper_and_legitimate_host_import(self):
        builder.validate_wrapper_definitions(
            "1: 0000 16 FUNC GLOBAL DEFAULT 12 __wrap_msc_example\n"
            "2: 0000 0 NOTYPE GLOBAL DEFAULT UND ap_log_rerror_", ["msc_example"])

    def test_undefined_wrapper_rejected(self):
        with self.assertRaisesRegex(ValueError, "defined wrapper"):
            builder.validate_wrapper_definitions(
                "1: 0000 0 NOTYPE GLOBAL DEFAULT UND __wrap_msc_example", ["msc_example"])

    def test_missing_wrapper_rejected(self):
        with self.assertRaisesRegex(ValueError, "defined wrapper"):
            builder.validate_wrapper_definitions(
                "1: 0000 16 FUNC GLOBAL DEFAULT 12 unrelated", ["msc_example"])

    def test_selected_sdk_resolution_accepts_host_import_diagnostic(self):
        sdk = Path("/selected/libmodsecurity.so.3.0.14")
        result = builder.validate_sdk_resolution(
            "libmodsecurity.so.3 => /selected/libmodsecurity.so.3.0.14 (0x1)\n"
            "undefined symbol: ap_log_rerror_ (mod_security3.so)", sdk)
        self.assertEqual(result, str(sdk))

    def test_wrong_sdk_resolution_rejected(self):
        with self.assertRaisesRegex(ValueError, "different SDK"):
            builder.validate_sdk_resolution("libmodsecurity.so.3 => /other/libmodsecurity.so.3.0.14 (0x1)",
                                            Path("/selected/libmodsecurity.so.3.0.14"))

    def test_missing_or_unresolved_sdk_rejected(self):
        for output in ("libmodsecurity.so.3 => not found", "libc.so.6 => /lib/libc.so.6 (0x1)"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                builder.validate_sdk_resolution(output, Path("/selected/libmodsecurity.so.3.0.14"))


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.environment = mock.patch.dict(os.environ, {"CODEX_TEMP_ROOT": str(self.base)})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.root = self.base / "export"
        self.root.mkdir()

    def file(self, relative, content):
        path = self.base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if isinstance(content, str) else json.dumps(content))
        return {"path": str(path), "sha256": builder.sha(path)}

    def fixture(self):
        revision = "a" * 40
        symbols = list(builder.APACHE_NATIVE_WRAPPED_SYMBOLS + builder.APACHE_HOST_WRAPPED_SYMBOLS)
        paths = list(builder.SOURCE_FILES) + ["tests/test_native_lifecycle_observer.py", "ci/runtime/lifecycle/i12/manifest.json"]
        for name in paths:
            content = "SYMBOLS = " + repr(
                builder.APACHE_NATIVE_WRAPPED_SYMBOLS + builder.SHARED_NON_APACHE_WRAPPED_SYMBOLS
            ) + "\n" if name.startswith("tests/") else "fixture\n"
            self.file("export/" + name, content)
        files = {name: {"sha256": builder.sha(self.root / name)} for name in paths}
        inventory = self.file("export/inventory.json", {"files": files})
        self.file("export/.i12-disposable-source-copy.json", {"format": "i12-disposable-source-copy-v2",
            "disposable": True, "path": str(self.root), "source_revision": revision,
            "snapshot_manifest": "inventory.json", "snapshot_manifest_sha256": inventory["sha256"]})
        capture = self.file("capture.json", {"profile": "apache-current", "source_copy": str(self.root),
            "source_revision": revision, "snapshot_manifest_sha256": inventory["sha256"],
            "source_git_tree": "b" * 40,
            "capture_manifest_sha256": files["ci/runtime/lifecycle/i12/manifest.json"]["sha256"],
            "exact_written_sha256": {name: files[name]["sha256"] for name in builder.SOURCE_FILES},
            "actual_before_sha256": {name: files[name]["sha256"] for name in builder.SOURCE_FILES}})
        make = self.file("make.stdout", "fixture transcript")
        sdk = self.file("sdk.so", "SDK fixture")
        header = self.file("include/modsecurity/transaction.h", "SDK fixture header")
        objects = {}
        for index in range(33):
            item = self.file("objects/" + str(index) + ".o", "object " + str(index))
            objects[item["path"]] = item["sha256"]
        identity = self.file("identity.json", {"source_revision": revision, "git_tree": "b" * 40, "source_inventory_sha256": inventory["sha256"],
            "objects": objects, "fresh_product_translation_units": 33, "historical_objects_reused": False,
            "commands": [{"label": "make", "exit": 0, "stdout_sha256": make["sha256"]}],
            "sdk": sdk, "sdk_headers": {header["path"]: header["sha256"]}})
        helpers = {name: self.file(name + ".o", name) for name in ("common", "fault", "bucket")}
        fault = self.file("fault.json", {"exit": 0, "helper_revision": 2,
            "object_sha256": helpers["fault"]["sha256"], "external_source_anchors": [
                {"file": name, "source_sha256": files[name]["sha256"]} for name in builder.SOURCE_FILES]})
        return {"source_root": str(self.root), "output": str(self.base / "output"),
                "capture_receipt": capture, "build_identity": identity, "make_stdout": make,
                "sdk_library": sdk, "sdk_include": str(self.base / "include"), "helper_objects": helpers,
                "fault_receipt": fault, "fault_header": self.file("fault.h", "header"), "wrapped_symbols": symbols}

    def test_receipts_bind_full_snapshot_and_objects_without_mutating_source(self):
        spec = self.fixture()
        before = {str(p): builder.sha(p) for p in self.root.rglob("*") if p.is_file()}
        builder.validate_inputs(spec)
        after = {str(p): builder.sha(p) for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertFalse((self.base / "output").exists())

    def test_stale_source_rejected(self):
        spec = self.fixture()
        (self.root / builder.SOURCE_FILES[0]).write_text("changed")
        with self.assertRaisesRegex(ValueError, "snapshot changed"):
            builder.validate_inputs(spec)

    def test_post_build_full_snapshot_recheck_detects_other_source_change(self):
        spec = self.fixture()
        builder.validate_inputs(spec)
        marker = json.loads((self.root / ".i12-disposable-source-copy.json").read_text())
        snapshot = json.loads((self.root / marker["snapshot_manifest"]).read_text())
        capture = builder.bound_json(spec["capture_receipt"], (self.base,))
        (self.root / "tests/test_native_lifecycle_observer.py").write_text("modified while compiling")
        with self.assertRaisesRegex(ValueError, "snapshot changed"):
            builder.validate_source_snapshot(self.root, snapshot, capture["exact_written_sha256"])

    def test_post_build_capture_only_output_recheck(self):
        spec = self.fixture()
        marker = json.loads((self.root / ".i12-disposable-source-copy.json").read_text())
        snapshot = json.loads((self.root / marker["snapshot_manifest"]).read_text())
        written = builder.bound_json(spec["capture_receipt"], (self.base,))["exact_written_sha256"]
        output = self.file("export/generated-observer.h", "generated capture output")
        written["generated-observer.h"] = output["sha256"]
        builder.validate_source_snapshot(self.root, snapshot, written)
        (self.root / "generated-observer.h").write_text("modified while linking")
        with self.assertRaisesRegex(ValueError, "Capture output changed"):
            builder.validate_source_snapshot(self.root, snapshot, written)

    def test_stale_object_rejected(self):
        spec = self.fixture()
        (self.base / "objects/0.o").write_text("stale")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            builder.validate_inputs(spec)

    def test_outside_storage_input_rejected_before_read(self):
        spec = self.fixture()
        with tempfile.TemporaryDirectory(dir=self.base.parent) as outside:
            path = Path(outside) / "make.stdout"
            path.write_text("fixture transcript")
            spec["make_stdout"] = {"path": str(path), "sha256": builder.sha(path)}
            with mock.patch.object(builder, "sha", side_effect=AssertionError("outside file was read")) as digest:
                with self.assertRaisesRegex(ValueError, "authorized evidence roots"):
                    builder.bound(spec["make_stdout"], (self.base,))
                digest.assert_not_called()

    def test_storage_prefix_sibling_rejected(self):
        spec = self.fixture()
        with tempfile.TemporaryDirectory(prefix=self.base.name + "-sibling-", dir=self.base.parent) as sibling:
            path = Path(sibling) / "make.stdout"
            path.write_text("fixture transcript")
            spec["make_stdout"] = {"path": str(path), "sha256": builder.sha(path)}
            with self.assertRaisesRegex(ValueError, "authorized evidence roots"):
                builder.validate_inputs(spec)

    def test_parent_traversal_input_rejected(self):
        spec = self.fixture()
        spec["make_stdout"]["path"] = str(self.base / "objects" / ".." / "make.stdout")
        with self.assertRaisesRegex(ValueError, "authorized evidence roots"):
            builder.validate_inputs(spec)

    def test_final_symlink_input_rejected(self):
        spec = self.fixture()
        link = self.base / "make-link.stdout"
        link.symlink_to(self.base / "make.stdout")
        spec["make_stdout"] = {"path": str(link), "sha256": builder.sha(self.base / "make.stdout")}
        with self.assertRaisesRegex(ValueError, "follows a link"):
            builder.validate_inputs(spec)

    def test_ancestor_symlink_input_rejected(self):
        spec = self.fixture()
        alias = self.base / "alias"
        alias.symlink_to(self.base, target_is_directory=True)
        spec["make_stdout"] = {"path": str(alias / "make.stdout"),
                               "sha256": builder.sha(self.base / "make.stdout")}
        with self.assertRaisesRegex(ValueError, "follows a link"):
            builder.validate_inputs(spec)

    def test_inventory_parent_traversal_rejected(self):
        spec = self.fixture()
        marker_path = self.root / ".i12-disposable-source-copy.json"
        marker = json.loads(marker_path.read_text())
        marker["snapshot_manifest"] = "../make.stdout"
        marker_path.write_text(json.dumps(marker))
        with self.assertRaisesRegex(ValueError, "inventory member"):
            builder.validate_inputs(spec)

    def test_nonregular_input_is_rejected_before_hashing(self):
        fifo = self.base / "input.fifo"
        os.mkfifo(fifo, 0o600)
        item = {"path": str(fifo), "sha256": "0" * 64}
        with mock.patch.object(builder, "sha", side_effect=AssertionError("FIFO was hashed")) as digest:
            with self.assertRaisesRegex(ValueError, "object type"):
                builder.bound(item, (self.base,))
            digest.assert_not_called()

    def test_hash_bound_closes_descriptor_on_oversize_failure(self):
        path = self.base / "oversize.bin"
        path.write_bytes(b"four")
        actual_close = builder.os.close
        closed = []

        def close(descriptor):
            closed.append(descriptor)
            actual_close(descriptor)

        with mock.patch.object(builder, "MAX_HASHED_INPUT_BYTES", 3), \
                mock.patch.object(builder.os, "close", side_effect=close):
            with self.assertRaisesRegex(ValueError, "bounded regular"):
                builder.sha(path)
        self.assertEqual(len(closed), 1)

    def test_bound_json_parses_the_hash_checked_read(self):
        item = self.file("bound.json", {"value": "same bytes"})
        with mock.patch.object(builder, "read_regular_bytes",
                               wraps=builder.read_regular_bytes) as reader:
            self.assertEqual(builder.bound_json(item, (self.base,)), {"value": "same bytes"})
        reader.assert_called_once_with(Path(item["path"]))

    def test_wrapper_omission_rejected(self):
        spec = self.fixture()
        spec["wrapped_symbols"].pop()
        with self.assertRaisesRegex(ValueError, "Wrapper list"):
            builder.validate_inputs(spec)

    def test_wrapper_addition_and_duplicate_rejected(self):
        for value in ("unreviewed_wrapper", builder.APACHE_NATIVE_WRAPPED_SYMBOLS[0]):
            spec = self.fixture()
            spec["wrapped_symbols"].append(value)
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "Wrapper list"):
                builder.validate_inputs(spec)

    def test_shared_wrapper_contract_change_rejected(self):
        spec = self.fixture()
        path = self.root / "tests/test_native_lifecycle_observer.py"
        path.write_text("SYMBOLS = " + repr(builder.APACHE_NATIVE_WRAPPED_SYMBOLS) + "\n")
        inventory_path = self.root / "inventory.json"
        inventory = json.loads(inventory_path.read_text())
        inventory["files"]["tests/test_native_lifecycle_observer.py"]["sha256"] = builder.sha(path)
        inventory_path.write_text(json.dumps(inventory))
        marker_path = self.root / ".i12-disposable-source-copy.json"
        marker = json.loads(marker_path.read_text())
        marker["snapshot_manifest_sha256"] = builder.sha(inventory_path)
        marker_path.write_text(json.dumps(marker))
        capture = builder.bound_json(spec["capture_receipt"], (self.base,))
        capture["snapshot_manifest_sha256"] = builder.sha(inventory_path)
        spec["capture_receipt"] = self.file("capture.json", capture)
        identity = builder.bound_json(spec["build_identity"], (self.base,))
        identity["source_inventory_sha256"] = builder.sha(inventory_path)
        spec["build_identity"] = self.file("identity.json", identity)
        with self.assertRaisesRegex(ValueError, "Shared native wrapper contract changed"):
            builder.validate_inputs(spec)

    def test_output_inside_input_rejected_before_mutation(self):
        spec = self.fixture()
        spec["output"] = str(self.root / "output")
        with self.assertRaisesRegex(ValueError, "disjoint"):
            builder.validate_inputs(spec)

    def test_capture_wrong_root_rejected(self):
        spec = self.fixture()
        capture = builder.bound_json(spec["capture_receipt"], (self.base,))
        capture["source_copy"] = str(self.base / "other")
        spec["capture_receipt"] = self.file("capture.json", capture)
        with self.assertRaisesRegex(ValueError, "apache-current"):
            builder.validate_inputs(spec)

    def test_capture_tree_mismatch_rejected(self):
        spec = self.fixture()
        capture = builder.bound_json(spec["capture_receipt"], (self.base,))
        capture["source_git_tree"] = "c" * 40
        spec["capture_receipt"] = self.file("capture.json", capture)
        with self.assertRaisesRegex(ValueError, "trees disagree"):
            builder.validate_inputs(spec)

    def test_capture_manifest_change_rejected(self):
        spec = self.fixture()
        (self.root / "ci/runtime/lifecycle/i12/manifest.json").write_text("changed")
        with self.assertRaisesRegex(ValueError, "Capture manifest"):
            builder.validate_inputs(spec)

    def test_different_sdk_include_root_rejected(self):
        spec = self.fixture()
        self.file("other/include/modsecurity/transaction.h", "SDK fixture header")
        spec["sdk_include"] = str(self.base / "other/include")
        with self.assertRaisesRegex(ValueError, "selected include root"):
            builder.validate_inputs(spec)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
