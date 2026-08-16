from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_common_versions", ROOT / "ci/tools/check-common-versions.py"
)
assert SPEC is not None
assert SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


def entries(values: dict[str, str]):
    return {
        name: CHECKER.VariableEntry(name, 1, "", value, value, True, "assignment")
        for name, value in values.items()
    }


class DescriptorSeriesTests(unittest.TestCase):
    def test_lighttpd_rejects_duplicate_slash_series_base(self):
        values = {
            name: "x"
            for name in CHECKER.COMPONENT_DEFINITION_BY_NAME["lighttpd"].variables
        }
        values.update(
            {
                "LIGHTTPD_SERIES": "1.4",
                "LIGHTTPD_RELEASE_ROOT_URL": "https://download.lighttpd.net/lighttpd",
                "LIGHTTPD_SERIES_BASE_URL": "https://download.lighttpd.net/lighttpd/releases-1.4.x//",
                "LIGHTTPD_VERSION": "1.4.85",
            }
        )
        result = CHECKER.check_lighttpd(entries(values), object())
        self.assertEqual(result.status, CHECKER.STATUS_UNKNOWN)
        self.assertIn("duplicate slash", result.message)

    def test_haproxy_htx_tuple_is_validated_independently(self):
        values = {
            name: "x"
            for name in CHECKER.COMPONENT_DEFINITION_BY_NAME["HAProxy"].variables
        }
        values.update(
            {
                "HAPROXY_SERIES": "3.2",
                "HAPROXY_RELEASE_ROOT_URL": "https://www.haproxy.org/download",
                "HAPROXY_SERIES_BASE_URL": "https://www.haproxy.org/download/3.2/src",
                "HAPROXY_VERSION": "3.2.22",
                "HAPROXY_SOURCE_URL": "https://www.haproxy.org/download/3.2/src/haproxy-3.2.22.tar.gz",
                "HAPROXY_SHA256": "a" * 64,
                "HAPROXY_SHA256_URL": "https://www.haproxy.org/download/3.2/src/haproxy-3.2.22.tar.gz.sha256",
                "HAPROXY_HTX_SERIES": "3.2",
                "HAPROXY_HTX_SERIES_BASE_URL": "https://www.haproxy.org/download/3.2/src",
                "HAPROXY_HTX_VERSION": "3.2.21",
                "HAPROXY_HTX_ARCHIVE_NAME": "haproxy-3.2.21.tar.gz",
                "HAPROXY_HTX_SOURCE_URL": "https://www.haproxy.org/download/3.2/src/haproxy-3.2.21.tar.gz/",
                "HAPROXY_HTX_SHA256": "b" * 64,
            }
        )
        result = CHECKER.check_haproxy(entries(values), object())
        self.assertEqual(result.status, CHECKER.STATUS_UNKNOWN)
        self.assertIn("HTX source tuple", result.message)

    def test_global_descriptor_missing_pin_fails_closed(self):
        definition = CHECKER.COMPONENT_DEFINITION_BY_NAME["Canonical CI pins"]
        result = CHECKER.unified_orchestrator_component(definition, {})
        self.assertEqual(result.status, CHECKER.STATUS_BLOCKED)
        self.assertIn("missing", result.message)

    def test_json_array_transport_requires_array(self):
        client = CHECKER.HttpClient.__new__(CHECKER.HttpClient)
        client._get_text = lambda url, **kwargs: json.dumps({"not": "an array"})
        with self.assertRaises(CHECKER.UpstreamError):
            client.get_json_list("https://api.github.com/example")


if __name__ == "__main__":
    unittest.main()
