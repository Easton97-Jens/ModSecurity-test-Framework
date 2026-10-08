"""Captured-source loader controls; not connector runtime evidence."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from tests.runners import nginx_native_operation_bundle as reader


ROOT = Path(__file__).resolve().parents[2]
MAIN = "framework:tests/runners/nginx_lifecycle_sequence.py"
WIRE = "framework:tests/runners/nginx_http11_framing.py"
CASE = "transport_http11_content_length"
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"


class CapturedWireLoaderTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="captured-wire-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.runners = self.root / "tests/runners"
        self.runners.mkdir(parents=True)
        self.sources = {key: (ROOT / key.split(":", 1)[1]).read_bytes() for key in (MAIN, WIRE)}

    def load(self, sources=None):
        return reader.load_helpers(CASE, self.sources if sources is None else sources, self.root)

    def assert_parser(self, module):
        parsed = module.WIRE.parse_http11_response(RESPONSE)
        self.assertEqual((parsed["body"], parsed["framing"], parsed["declared_length"]),
                         (b"ok", "content_length", 2))
        with self.assertRaises(ValueError):
            module.WIRE.parse_http11_response(RESPONSE + b"extra")

    def test_foreign_live_sibling_is_not_executed(self):
        (self.runners / "nginx_http11_framing.py").write_bytes(
            b"raise RuntimeError('foreign live parser executed')\n")
        self.assert_parser(self.load())

    def test_missing_live_sibling_still_uses_captured_parser(self):
        self.assert_parser(self.load())

    def test_missing_captured_parser_cannot_fall_back_to_live_sibling(self):
        (self.runners / "nginx_http11_framing.py").write_bytes(self.sources[WIRE])
        with self.assertRaisesRegex(ValueError, "captured.*framing"):
            self.load({MAIN: self.sources[MAIN]})

    def test_scoped_namespace_restored_on_success_and_failure(self):
        names = ("nginx_http11_framing", "nginx_lifecycle_sequence")
        originals = {name: types.ModuleType(name) for name in names}
        with patch.dict(sys.modules, originals):
            self.assert_parser(self.load())
            self.assertTrue(all(sys.modules[name] is originals[name] for name in names))
            broken = {**self.sources, MAIN: b"raise RuntimeError('controlled helper failure')\n"}
            with self.assertRaisesRegex(RuntimeError, "controlled helper failure"):
                self.load(broken)
            self.assertTrue(all(sys.modules[name] is originals[name] for name in names))
        with patch.dict(sys.modules):
            for name in names:
                sys.modules.pop(name, None)
            self.load()
            self.assertTrue(all(name not in sys.modules for name in names))

    def test_ordinary_driver_fallback_unchanged(self):
        path = ROOT / MAIN.split(":", 1)[1]
        spec = importlib.util.spec_from_file_location("ordinary_sequence_loader_control", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assert_parser(module)


if __name__ == "__main__":
    unittest.main()
