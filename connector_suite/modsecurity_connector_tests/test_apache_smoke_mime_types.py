"""Regression contract for Apache smoke MIME configuration artifacts."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import unittest


ROOT = connector_root()
HARNESS = source_path('connectors/apache/harness/run_apache_smoke.sh', root=ROOT)


class ApacheSmokeMimeTypesTests(unittest.TestCase):
    def test_harness_materializes_both_standard_mime_locations(self) -> None:
        source = HARNESS.read_text(encoding="utf-8")
        setup = source.split(
            'if [ -f "$HTTPD_PREFIX/conf/mime.types" ]; then', 1
        )[1].split('if ! "$PYTHON_BIN" "$CASE_CLI" materialize', 1)[0]

        self.assertIn('MIME_TYPES_FILE="$RUNTIME_ROOT/conf/mime.types"', source)
        self.assertIn('MIME_TYPES_ROOT_FILE="$RUNTIME_ROOT/mime.types"', source)
        self.assertIn(
            'cp -a "$HTTPD_PREFIX/conf/mime.types" "$MIME_TYPES_FILE"', setup
        )
        self.assertIn(
            'cp -a "$HTTPD_PREFIX/conf/mime.types" "$MIME_TYPES_ROOT_FILE"', setup
        )
        self.assertIn(': > "$MIME_TYPES_FILE"', setup)
        self.assertIn(': > "$MIME_TYPES_ROOT_FILE"', setup)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
