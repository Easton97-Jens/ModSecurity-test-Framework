"""Exercise the observed-module build orchestration with synthetic tool outputs.

These fixtures qualify Python receipt handling, never a native Apache module.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = connector_root()
MODULE = source_path('ci/runtime/lifecycle/apache-i12/acceptance/build_observed_module.py', root=ROOT)
builder = load_source(MODULE)


class OfflineBuildTests(unittest.TestCase):
    def setUp(self):
        from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root
        storage = validate_output_root(ROOT, Path(os.environ["RUNNER_TEMP"]))
        temporary = tempfile.TemporaryDirectory(prefix="apache-offline-build-", dir=storage)
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        environment = mock.patch.dict(os.environ, {
            "CODEX_TEMP_ROOT": str(self.base), "DEPENDENCIES_OUTPUT": "forbidden.d",
            "SUNPRO_DEPENDENCIES": "forbidden-sun.d"})
        environment.start()
        self.addCleanup(environment.stop)
        self.root = self.base / "export"
        self.root.mkdir()
        self.output = self.base / "output"
        self.calls = []
        self.failure = None
        self.spec = self.fixture()
        self.spec_path = Path(self.file("spec.json", self.spec)["path"])

    def file(self, relative, content):
        path = self.base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if isinstance(content, str) else json.dumps(content))
        return {"path": str(path), "sha256": builder.sha(path)}

    def fixture(self):
        texts = {
            builder.SOURCE_FILES[0]: "P1\nADD\nFINISH\n"
                "    return msconnector_transaction_contract_record_request_metadata(&msr->contract,\n",
            builder.SOURCE_FILES[1]: "APPEND\n"
                "    ret = apr_bucket_read(bucket, &data, &len, block);\n"
                "    if (ret != APR_SUCCESS)\n        return ret;\n"
                "    rc = apr_bucket_read(bucket, &data, &len, APR_BLOCK_READ);\n"}
        texts["tests/test_native_lifecycle_observer.py"] = "SYMBOLS = " + repr(
            builder.APACHE_NATIVE_WRAPPED_SYMBOLS + builder.SHARED_NON_APACHE_WRAPPED_SYMBOLS) + "\n"
        texts["ci/runtime/lifecycle/i12/manifest.json"] = "{}\n"
        for filename in builder.OBSERVERS:
            directory = "connectors/apache/src" if filename.startswith("apache-") else "ci/runtime/lifecycle"
            texts[directory + "/" + filename] = "/* synthetic observer " + filename + " */\n"
        files = {name: {"sha256": self.file("export/" + name, text)["sha256"]}
                 for name, text in texts.items()}
        inventory = self.file("export/inventory.json", {"files": files})
        revision, tree = "a" * 40, "b" * 40
        self.file("export/.i12-disposable-source-copy.json", {
            "format": "i12-disposable-source-copy-v2", "disposable": True,
            "path": str(self.root), "source_revision": revision,
            "snapshot_manifest": "inventory.json", "snapshot_manifest_sha256": inventory["sha256"]})
        capture = self.file("capture.json", {
            "profile": "apache-current", "source_copy": str(self.root), "source_revision": revision,
            "source_git_tree": tree, "snapshot_manifest_sha256": inventory["sha256"],
            "capture_manifest_sha256": files["ci/runtime/lifecycle/i12/manifest.json"]["sha256"],
            "exact_written_sha256": {name: files[name]["sha256"] for name in builder.SOURCE_FILES},
            "actual_before_sha256": {name: files[name]["sha256"] for name in builder.SOURCE_FILES}})
        transcript = "\n".join("libtool: compile: cc " + " ".join(sorted(builder.STRICT))
            + " -c src/" + Path(name).name + " -o src/.libs/" + Path(name).stem + ".o"
            for name in builder.SOURCE_FILES)
        make = self.file("make.stdout", transcript)
        objects = {}
        names = ["export/connectors/apache/src/.libs/" + Path(name).stem + ".o"
                 for name in builder.SOURCE_FILES] + ["objects/unit-" + str(i) + ".o" for i in range(31)]
        for index, name in enumerate(names):
            item = self.file(name, "synthetic fresh object " + str(index))
            objects[item["path"]] = item["sha256"]
        self.original_objects = objects
        sdk = self.file("sdk/libmodsecurity.so.3.0.17", "synthetic SDK")
        header = self.file("include/modsecurity/transaction.h", "synthetic SDK header")
        identity = self.file("identity.json", {
            "source_revision": revision, "git_tree": tree, "source_inventory_sha256": inventory["sha256"],
            "objects": objects, "fresh_product_translation_units": 33, "historical_objects_reused": False,
            "commands": [{"label": "make", "exit": 0, "stdout_sha256": make["sha256"]}],
            "sdk": sdk, "sdk_headers": {header["path"]: header["sha256"]}})
        helpers = {name: self.file(name + ".o", "synthetic helper " + name)
                   for name in ("common", "fault", "bucket")}
        anchors = [{"file": name, "source_sha256": files[name]["sha256"],
                    "original": old, "replacement": "FAULT_" + old, "occurrences_required": 1}
                   for name, old in ((builder.SOURCE_FILES[0], "P1"), (builder.SOURCE_FILES[0], "ADD"),
                                     (builder.SOURCE_FILES[0], "FINISH"), (builder.SOURCE_FILES[1], "APPEND"))]
        fault = self.file("fault.json", {"exit": 0, "helper_revision": 2,
            "object_sha256": helpers["fault"]["sha256"], "external_source_anchors": anchors})
        return {"source_root": str(self.root), "output": str(self.output),
            "capture_receipt": capture, "build_identity": identity, "make_stdout": make,
            "sdk_library": sdk, "sdk_include": str(self.base / "include"), "helper_objects": helpers,
            "fault_receipt": fault, "fault_header": self.file("fault.h", "/* synthetic fault header */"),
            "wrapped_symbols": list(builder.APACHE_NATIVE_WRAPPED_SYMBOLS + builder.APACHE_HOST_WRAPPED_SYMBOLS)}

    def simulated_tool(self, argv, *, cwd, env, capture_output, timeout):
        self.calls.append({"argv": argv, "cwd": cwd, "env": env})
        self.assertEqual(argv[:2], ["rtk", "proxy"])
        self.assertTrue(capture_output)
        self.assertEqual(timeout, 180)
        self.assertNotIn("DEPENDENCIES_OUTPUT", env)
        self.assertNotIn("SUNPRO_DEPENDENCIES", env)
        tool = argv[2]
        stdout, stderr, status = b"", b"", 0
        if tool in {"cc", "g++"}:
            if self.failure == "recompile" and len(self.calls) == 1:
                status, stderr = 1, b"synthetic compile rejection"
            else:
                target = Path(argv[argv.index("-o") + 1])
                self.assertTrue(target.is_relative_to(self.output))
                target.write_text("synthetic output " + target.name)
                if "-shared" in argv and self.failure == "source":
                    (self.root / "ci/runtime/lifecycle/i12/manifest.json").write_text("changed by synthetic linker")
        elif tool == "readelf":
            if "-d" in argv:
                stdout = b"(FLAGS) BIND_NOW\n"
            elif "-l" in argv:
                stdout = b"GNU_STACK 0 0 0 0 0 RW 0x10\n"
                if self.failure != "relro":
                    stdout += b"GNU_RELRO 0 0 0 0 0 R 0x1\n"
            else:
                self.assertIn("-s", argv)
                stdout = "\n".join(str(index) + ": 0000 16 FUNC GLOBAL DEFAULT 12 __wrap_" + symbol
                    for index, symbol in enumerate(self.spec["wrapped_symbols"], 1)).encode()
        elif tool == "ldd":
            sdk = self.base / "wrong-sdk.so" if self.failure == "sdk" else Path(self.spec["sdk_library"]["path"])
            stdout = ("libmodsecurity.so.3 => " + str(sdk) + " (0x1)\n").encode()
        else:
            self.fail("Unexpected synthetic tool: " + tool)
        return subprocess.CompletedProcess(argv, status, stdout, stderr)

    def build(self):
        with mock.patch.object(builder.subprocess, "run", side_effect=self.simulated_tool):
            return builder.build(self.spec_path)

    def retained_receipt(self):
        return json.loads((self.output / "build-identity.json").read_text())

    def test_complete_build_preserves_flags_bindings_and_unqualified_runtime(self):
        receipt = self.build()
        self.assertEqual(len(self.calls), 11)
        self.assertEqual(receipt, self.retained_receipt())
        self.assertIsNone(receipt["runtime_qualification"])
        self.assertIs(receipt["historical_objects_reused"], False)
        self.assertIs(receipt["source_input_mutated"], False)
        self.assertEqual(receipt["product_translation_units"], 33)
        self.assertEqual(receipt["recompiled_product_translation_units"], 2)
        self.assertEqual(len(receipt["retained_product_objects"]), 31)
        self.assertEqual(len(set(self.original_objects.values())), 33)
        self.assertEqual(receipt["module_sha256"], builder.sha(Path(receipt["module"])))
        self.assertEqual(receipt["spec_sha256"], builder.sha(self.spec_path))
        self.assertEqual(receipt["builder_sha256"], builder.sha(MODULE))
        self.assertEqual(receipt["sdk_sha256"], self.spec["sdk_library"]["sha256"])
        self.assertEqual(receipt["resolved_sdk"], self.spec["sdk_library"]["path"])
        for name, record in receipt["instrumented_sources"].items():
            self.assertEqual(record["before_sha256"], builder.sha(self.root / name))
            self.assertEqual(record["after_sha256"], builder.sha(Path(record["path"])))
            self.assertNotEqual(record["before_sha256"], record["after_sha256"])
            self.assertTrue(builder.STRICT.issubset(record["canonical_argv"]))
        for path, expected in receipt["retained_product_objects"].items():
            self.assertEqual(expected, self.original_objects[path])
            self.assertEqual(expected, builder.sha(Path(path)))
        for path, record in receipt["observer_objects"].items():
            self.assertEqual(record["sha256"], builder.sha(Path(path)))
        for call, command in zip(self.calls, receipt["commands"]):
            self.assertEqual(command["argv"], call["argv"])
            self.assertEqual(command["cwd"], str(call["cwd"]))
            self.assertEqual(command["exit"], 0)
            self.assertEqual(command["stdout_sha256"], builder.sha(self.output / (command["label"] + ".stdout")))
            self.assertEqual(command["stderr_sha256"], builder.sha(self.output / (command["label"] + ".stderr")))
        for call in self.calls[:2]:
            argv = call["argv"]
            self.assertTrue(builder.STRICT.issubset(argv))
            self.assertEqual(call["cwd"], self.root / "connectors/apache")
            self.assertIn(str(self.spec["fault_header"]["path"]), argv)
            self.assertIn("-ffile-prefix-map=" + str(self.output) + "=/i12/observer-overlay", argv)
        for call in self.calls[2:6]:
            self.assertEqual(call["cwd"], self.root)
            self.assertTrue({"-Wall", "-Wextra", "-Werror", "-pthread", "-fPIC", "-fno-lto"}.issubset(call["argv"]))
        self.assertIn("-std=c++17", self.calls[5]["argv"])
        self.assertEqual(len([a for a in self.calls[6]["argv"] if a.startswith("-Wl,--wrap=")]), 28)
        self.assertEqual(receipt["input_bindings"], self.spec)

    def test_failed_first_recompile_retains_failure_without_final_module_receipt(self):
        self.failure = "recompile"
        with self.assertRaisesRegex(RuntimeError, "recompile-mod_security3"):
            self.build()
        receipt = self.retained_receipt()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(receipt["commands"][0]["exit"], 1)
        self.assertNotIn("module_sha256", receipt)
        self.assertFalse((self.output / "mod_security3.so").exists())

    def test_wrong_sdk_resolution_rejects_final_receipt(self):
        self.failure = "sdk"
        with self.assertRaisesRegex(ValueError, "different SDK"):
            self.build()
        self.assertEqual(len(self.calls), 11)
        self.assertNotIn("module_sha256", self.retained_receipt())

    def test_missing_relro_rejects_final_receipt(self):
        self.failure = "relro"
        with self.assertRaisesRegex(ValueError, "RELRO missing"):
            self.build()
        self.assertEqual(len(self.calls), 11)
        self.assertNotIn("module_sha256", self.retained_receipt())

    def test_link_time_source_change_rejected_by_full_snapshot_recheck(self):
        self.failure = "source"
        with self.assertRaisesRegex(ValueError, "Source snapshot changed"):
            self.build()
        self.assertEqual(len(self.calls), 11)
        self.assertNotIn("module_sha256", self.retained_receipt())


if os.environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
