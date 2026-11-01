"""Pure copied-source identity/context controls; compiler proof is build-only."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = connector_root()
MAPPING = load_source(source_path('ci/checks/analysis/sonar-native-security/source_mapping.py', root=ROOT))
GO_PROVENANCE = load_source(source_path('ci/checks/analysis/sonar-native-security/go_provenance.py', root=ROOT))
BUILD_SPEC = importlib.util.spec_from_file_location(
    "sonar_native_builder_control", source_path('ci/checks/analysis/sonar-native-security/build-target.py', root=ROOT))
BUILDER = importlib.util.module_from_spec(BUILD_SPEC)
with patch.dict(sys.modules, {"source_mapping": MAPPING, "go_provenance": GO_PROVENANCE}):
    BUILD_SPEC.loader.exec_module(BUILDER)


class NativeSourceMappingTest(unittest.TestCase):
    def setUp(self):
        storage = Path(os.environ.get("CODEX_TEMP_ROOT", "/var/tmp/codex/ModSecurity-conector"))
        self.temporary = tempfile.TemporaryDirectory(prefix="sonar-source-map-unit-", dir=storage)
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        checkout, copied_root = root / "checkout", root / "copied"
        checkout.mkdir()
        copied_root.mkdir()
        self.source = checkout / "product.c"
        self.header = checkout / "product.h"
        self.copied_source = copied_root / "renamed-product.c"
        self.copied_header = copied_root / "product.h"
        self.source.write_text('#include "product.h"\nint product(void) { return VALUE; }\n')
        self.header.write_text("#define VALUE 0\n")
        self.copied_source.write_bytes(self.source.read_bytes())
        self.copied_header.write_bytes(self.header.read_bytes())
        producer = checkout / "native-producer.sh"
        producer.write_text("# unit-only producer identity fixture\n")
        archive = root / "unit-archive"
        archive.write_bytes(b"unit-only pinned context identity")
        self.manifest = {"schema": 1, "checkout": str(checkout), "copy_root": str(copied_root),
                         "producer": {"path": str(producer), "sha256": MAPPING.digest(producer)},
                         "context_files": {str(archive): MAPPING.digest(archive)},
                         "files": {str(self.copied_source): {"original": str(self.source),
                                                               "sha256": MAPPING.digest(self.source)},
                                   str(self.copied_header): {"original": str(self.header),
                                                               "sha256": MAPPING.digest(self.header)}}}
        self.root = root

    def test_original_source_and_header_context_admitted(self):
        MAPPING.verify_dependency_context([self.copied_source, self.copied_header],
                                          [self.source, self.header], self.manifest)

    def test_altered_copied_header_rejected(self):
        self.copied_header.write_text("#define VALUE 1\n")
        with self.assertRaisesRegex(ValueError, "copied source/header identity mismatch"):
            MAPPING.verify_dependency_context([self.copied_source, self.copied_header],
                                              [self.source, self.header], self.manifest)

    def test_shared_writable_ancestor_rejected(self):
        shared = self.root / "shared-parent"
        shared.mkdir()
        shared.chmod(0o777)
        output = shared / "not-created-parent/fresh-run"
        with self.assertRaisesRegex(ValueError, "untrusted shared writes"):
            BUILDER.verify_build_output_ancestry(output)
        self.assertFalse(output.exists())
        self.assertFalse(output.parent.exists())


if os.environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)


if __name__ == "__main__":
    unittest.main()
