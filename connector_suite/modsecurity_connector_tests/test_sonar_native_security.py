"""Zero-process validator controls; real compilation is separate build evidence."""
from modsecurity_test_framework.connector_context import connector_root, source_path, load_source

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = connector_root()
VALIDATOR = load_source(source_path('ci/checks/analysis/sonar-native-security/validate.py', root=ROOT))


class NativeSecurityCaptureTest(unittest.TestCase):
    """Physical provenance fixtures exercise validation without process creation."""

    def setUp(self):
        storage = Path(os.environ.get("CODEX_TEMP_ROOT", "/var/tmp/codex/ModSecurity-conector"))
        self.temporary = tempfile.TemporaryDirectory(prefix="sonar-native-unit-", dir=storage)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.checkout = self.root / "checkout"
        self.checkout.mkdir()
        self.captures = self.root / "captures"
        self.captures.mkdir()
        self.source = self.checkout / "product.c"
        self.source.write_text('#include "product.h"\nint main(void) { return VALUE; }\n')
        self.header = self.checkout / "product.h"
        self.header.write_text("#define VALUE 0\n")
        self.compiler = self.root / "gcc-15"
        self.compiler.write_bytes(b"unit-only compiler identity fixture")
        self.object = self.root / "product.o"
        self.object.write_bytes(b"unit-only object identity fixture")
        self.artifact = self.root / "product"
        self.artifact.write_bytes(b"unit-only linked artifact identity fixture")
        self.linkmap = self.root / "product.map"
        self.linkmap.write_text("LOAD " + str(self.object) + "\n")
        self.compile = self.record("compile", self.object)
        self.compile.update({"sources": self.hashes(self.source),
                             "dependencies": self.hashes(self.source, self.header),
                             "arguments": [str(self.compiler), "-std=c17", "-Wall", "-Wextra", "-Werror",
                                           "-c", str(self.source), "-o", str(self.object)]})
        self.compile["expanded_arguments"] = self.compile["arguments"]
        self.link = self.record("link", self.artifact)
        self.link.update({"inputs": self.hashes(self.object), "linker_inputs": self.hashes(self.object),
                          "link_map": self.hashes(self.linkmap)})
        self.write_record("compile", self.compile)
        self.write_record("link", self.link)
        self.contract = {"target": "unit-validator-control", "revision": "a" * 40,
                         "artifact": str(self.artifact), "sources": ["product.c"]}
        self.identity = patch.object(VALIDATOR.subprocess, "check_output", side_effect=["a" * 40 + "\n", b""])
        self.identity.start()
        self.addCleanup(self.identity.stop)

    def hashes(self, *paths):
        return {str(path): VALIDATOR.digest(path) for path in paths}

    def record(self, kind, output):
        return {"schema": 1, "kind": kind, "directory": str(self.checkout),
                "arguments": [str(self.compiler)], "expanded_arguments": [str(self.compiler)],
                "compiler_sha256": VALIDATOR.digest(self.compiler),
                "sources": {}, "dependencies": {}, "response_files": {}, "inputs": {},
                "linker_inputs": {}, "link_map": {}, "output": str(output),
                "output_sha256": VALIDATOR.digest(output)}

    def write_record(self, name, record):
        (self.captures / (name + ".json")).write_text(json.dumps(record))

    def export(self):
        return VALIDATOR.export(self.captures, self.contract, self.checkout, self.root / "export")

    def test_target_export_integrity(self):
        evidence = self.export()
        rows = json.loads((self.root / "export/compile_commands.json").read_text())
        self.assertTrue(evidence["import_eligible"])
        self.assertEqual([row["file"] for row in rows], [str(self.source)])
        self.assertEqual(rows[0]["arguments"], self.compile["arguments"])
        self.assertEqual(evidence["artifact_sha256"], VALIDATOR.digest(self.artifact))
        self.assertEqual(evidence["parent_product_headers"], [str(self.header)])
        self.assertEqual(evidence["scanner_expected_parent_translation_units"], 1)
        self.assertEqual(evidence["scanner_expected_parent_headers"], 1)
        self.assertEqual(evidence["scanner_expected_parent_indexed_inputs"], 2)
        self.assertEqual(evidence["scanner_scope"]["sonar.sources"], "product.c,product.h")

    def test_changed_header_rejected(self):
        self.header.write_text("#define VALUE 1\n")
        with self.assertRaisesRegex(ValueError, "captured input changed"):
            self.export()

    def test_missing_declared_source_rejected(self):
        (self.checkout / "required.c").write_text("int required(void) { return 0; }\n")
        self.contract["sources"].append("required.c")
        with self.assertRaisesRegex(ValueError, "source closure disagrees"):
            self.export()

    def test_unlinked_translation_unit_excluded(self):
        unrelated = self.checkout / "independent-executable.c"
        unrelated.write_text("int main(void) { return 1; }\n")
        object_file = self.root / "independent-executable.o"
        object_file.write_bytes(b"unlinked unit control")
        record = self.record("compile", object_file)
        record.update({"sources": self.hashes(unrelated), "dependencies": self.hashes(unrelated)})
        self.write_record("unrelated", record)
        evidence = self.export()
        self.assertEqual(evidence["translation_units"], 1)
        self.assertNotIn(str(unrelated), json.dumps(evidence))

    def test_dirty_checkout_rejected(self):
        VALIDATOR.subprocess.check_output.side_effect = ["a" * 40 + "\n", b" M product.c\n"]
        with self.assertRaisesRegex(ValueError, "clean exact-revision"):
            self.export()

    def test_checkout_output_rejected_without_mutation(self):
        output = self.checkout / "generated-export"
        before = sorted(path.name for path in self.checkout.iterdir())
        with self.assertRaisesRegex(ValueError, "external/disjoint from checkout"):
            VALIDATOR.export(self.captures, self.contract, self.checkout, output)
        self.assertFalse(output.exists())
        self.assertEqual(sorted(path.name for path in self.checkout.iterdir()), before)

    def test_unknown_link_producer_rejected(self):
        (self.captures / "compile.json").unlink()
        with self.assertRaisesRegex(ValueError, "missing or ambiguous captured producer"):
            self.export()

    def external_fixture(self):
        host = self.root / "nginx-unit-context"
        host.mkdir()
        source = host / "generated-module.c"
        source.write_text("/* unit-only generated host glue */\nint host_glue;\n")
        archive = self.root / "nginx-unit.tar.gz"
        archive.write_bytes(b"unit-only pinned archive identity fixture")
        pin = self.root / "framework/connector_suite/modsecurity_connector_ci/provisioning/components/prepare-runtime-components.py"
        pin.parent.mkdir(parents=True)
        original_source_path = VALIDATOR.source_path
        pin_owner = patch.object(VALIDATOR, "source_path", side_effect=lambda name, *, root: (
            pin if name == "ci/provisioning/components/prepare-runtime-components.py"
            and root == self.checkout else original_source_path(name, root=root)))
        pin_owner.start()
        self.addCleanup(pin_owner.stop)
        pin.write_text("NGINX_PINNED_RELEASE_ASSET_NAME = 'nginx-unit.tar.gz'\n"
                       + "NGINX_PINNED_RELEASE_ASSET_SHA256 = '" + VALIDATOR.digest(archive) + "'\n")
        receipt = self.root / "configure-receipt.json"
        receipt.write_text(json.dumps({"host": "nginx", "source_root": str(host),
                                      "configure_directory": str(host),
                                      "configure_arguments": ["sh", "./configure",
                                          "--add-dynamic-module=" + str(self.checkout / "connectors/nginx")],
                                      "generated_files": self.hashes(source)}))
        context = {"host": "nginx", "source_root": str(host), "archive": str(archive),
                   "archive_sha256": VALIDATOR.digest(archive), "pin_contract": str(pin),
                   "pin_contract_sha256": VALIDATOR.digest(pin), "configure_receipt": str(receipt),
                   "configure_receipt_sha256": VALIDATOR.digest(receipt)}
        self.contract.update({"external_sources": self.hashes(source), "external_context": context})
        obj = self.root / "generated-module.o"
        obj.write_bytes(b"unit-only generated object identity")
        record = self.record("compile", obj)
        record.update({"sources": self.hashes(source), "dependencies": self.hashes(source)})
        self.write_record("generated", record)
        self.link["inputs"].update(self.hashes(obj))
        self.link["linker_inputs"].update(self.hashes(obj))
        self.write_record("link", self.link)
        return source, receipt

    def test_authorized_external_generated_context(self):
        source, _ = self.external_fixture()
        evidence = self.export()
        self.assertEqual(evidence["translation_units"], 2)
        self.assertEqual(evidence["scanner_expected_parent_translation_units"], 1)
        self.assertEqual(evidence["external_build_context_sources"], [str(source)])
        self.assertEqual(evidence["scanner_scope"]["sonar.projectBaseDir"], str(self.checkout))
        self.assertEqual(evidence["scanner_scope"]["sonar.sources"], "product.c,product.h")

    def test_unadmitted_external_generated_source_rejected(self):
        _, receipt = self.external_fixture()
        value = json.loads(receipt.read_text())
        value["generated_files"] = {}
        receipt.write_text(json.dumps(value))
        self.contract["external_context"]["configure_receipt_sha256"] = VALIDATOR.digest(receipt)
        with self.assertRaisesRegex(ValueError, "unadmitted external source"):
            self.export()

    def lto_fixture(self):
        temporary = self.root / "compiler-tmp"
        temporary.mkdir(mode=0o700)
        copied = self.root / "copied-context"
        copied.mkdir()
        producer = self.checkout / "connectors/apache/build/apxs-wrapper.in"
        producer.parent.mkdir(parents=True)
        producer.write_text("# unit-only native producer identity fixture\n")
        mapping = self.root / "unit-source-map.json"
        identity = {"path": str(producer), "sha256": VALIDATOR.digest(producer)}
        mapping.write_text(json.dumps({"schema": 1, "checkout": str(self.checkout),
                                       "copy_root": str(copied), "producer": identity,
                                       "files": {}, "context_files": {}}))
        self.contract.update({"allow_gcc_internal_lto_context_limit": True,
                              "producer": {"script": "connectors/apache/build/apxs-wrapper.in",
                                           "script_sha256": VALIDATOR.digest(producer)}})
        self.link.update({"arguments": [str(self.compiler), "-flto=auto", str(self.object), "-o", str(self.artifact)],
                          "compiler_internal_transients": {str(temporary / "unit-link.ltrans0.ltrans.o"):
                                                               "gcc-lto-intermediate-not-retained",
                                                           str(temporary / "ccUNIT.debug.temp.o"):
                                                               "gcc-lto-debug-auxiliary-not-retained"},
                          "lto_context": {"mode": "apache-gcc-native-driver", "compiler_tmpdir": str(temporary),
                                          "source_map": str(mapping), "source_map_sha256": VALIDATOR.digest(mapping),
                                          "producer": identity}})
        self.link["expanded_arguments"] = self.link["arguments"]
        self.write_record("link", self.link)

    def test_bounded_internal_lto_context_preserves_parent_membership(self):
        self.lto_fixture()
        evidence = self.export()
        self.assertEqual(evidence["parent_product_sources"], [str(self.source)])
        self.assertEqual(evidence["scanner_expected_parent_translation_units"], 1)
        self.assertEqual(len(evidence["unretained_compiler_internal_inputs"]), 2)

    def test_internal_lto_limit_rejects_unknown_parent_object(self):
        self.lto_fixture()
        unknown = self.checkout / "unknown-parent.o"
        unknown.write_bytes(b"unit-only unproven Parent object")
        self.link["inputs"].update(self.hashes(unknown))
        self.link["linker_inputs"].update(self.hashes(unknown))
        self.link["arguments"].insert(2, str(unknown))
        self.linkmap.write_text("LOAD " + str(self.object) + "\nLOAD " + str(unknown) + "\n")
        self.link["link_map"] = self.hashes(self.linkmap)
        self.write_record("link", self.link)
        with self.assertRaisesRegex(ValueError, "missing or ambiguous captured producer"):
            self.export()


if os.environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)


if __name__ == "__main__":
    unittest.main()
