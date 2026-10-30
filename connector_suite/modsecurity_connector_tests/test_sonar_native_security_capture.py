"""Bounded compiler environment and literal archive argument controls."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import types
from pathlib import Path
import unittest
from unittest.mock import patch


ROOT = connector_root()
CAPTURE = load_source(source_path('ci/checks/analysis/sonar-native-security/capture.py', root=ROOT))


class NativeCompilerEnvironmentTest(unittest.TestCase):
    def assert_environment_rejected(self, name, value):
        with patch.dict(os.environ, {name: value}, clear=True):
            with patch.object(CAPTURE.subprocess, "run", side_effect=AssertionError("compiler must not start")):
                with self.assertRaisesRegex(ValueError, "undeclared implicit compiler environment"):
                    CAPTURE.capture("unused-compiler", [], Path("unused-capture-root"))

    def test_implicit_environment_rejected_before_compiler(self):
        self.assert_environment_rejected("CPATH", "/unit-only-unadmitted-include")

    def test_clang_override_environment_rejected_before_compiler(self):
        self.assert_environment_rejected("CCC_OVERRIDE_OPTIONS", "+-DUNIT_UNDECLARED_FLAG")


class NativeArchiveArgumentTest(unittest.TestCase):
    def archive_fixture(self, output_name, input_name, operation="rcs"):
        archive = load_source(source_path('ci/checks/analysis/sonar-native-security/archive-capture.py', root=ROOT))
        with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as temporary:
            root = Path(temporary)
            captures = root / "captures"
            captures.mkdir(mode=0o700)
            source = root / input_name
            source.write_bytes(b"literal unit object bytes")
            output = root / output_name
            output.write_bytes(b"unit archive receipt fixture")
            expected = [str(Path(sys.executable).resolve()), "rcs", str(output), str(source)]
            with (contextlib.chdir(root),
                  patch.object(archive.sys, "argv", ["archive-capture", "--archiver", sys.executable,
                                                    "--", operation, output_name, input_name]),
                  patch.dict(os.environ, SONAR_NATIVE_CAPTURE_ROOT=str(captures)),
                  patch.object(archive.subprocess, "run") as execute,
                  patch.object(archive.subprocess, "check_output",
                               side_effect=[input_name + "\n", source.read_bytes()]) as inspect):
                self.assertEqual(archive.main(), 0)
            execute.assert_called_once_with(expected, check=True)
            self.assertEqual(inspect.call_args_list[1].args[0],
                             [expected[0], "p", str(output), str(source)])
            records = list(captures.glob("*.json"))
            self.assertEqual(len(records), 1)
            record = json.loads(records[0].read_text())
            self.assertEqual(record["arguments"], expected)
            self.assertEqual(record["expanded_arguments"], expected)
            self.assertEqual(record["members"], {input_name: str(source)})
            self.assertEqual(record["schema"], 1)
            self.assertEqual(record["kind"], "archive")

    def test_response_named_object_remains_a_literal_archive_operand(self):
        self.archive_fixture("result.a", "@literal.o")

    def test_option_named_output_remains_a_literal_archive_operand(self):
        self.archive_fixture("-literal.a", "literal.o")

    def test_supported_operation_alias_preserves_capture_receipt(self):
        self.archive_fixture("result.a", "literal.o", "-rcs")


class NativeGoOutputAuthorityTest(unittest.TestCase):
    def go_fixture(self):
        module = load_source(source_path('ci/checks/analysis/sonar-native-security/go-tool-capture.py', root=ROOT))
        temporary = tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"])
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        captures, work = root / "captures", root / "go-work"
        captures.mkdir(mode=0o700)
        work.mkdir(mode=0o700)
        (work / "b001").mkdir(mode=0o700)
        output = work / "b001/a.out"
        output.write_bytes(b"actual finalized Go link bytes")
        tool = root / "link"
        tool.symlink_to(sys.executable)
        return module, root, captures, work, output, tool

    def invoke_go(self, module, captures, work, command, execute=None):
        with (patch.object(module.sys, "argv", ["go-tool-capture", *command]),
              patch.dict(os.environ, {"SONAR_NATIVE_CAPTURE_ROOT": str(captures),
                                      "SONAR_NATIVE_GO_WORK_ROOT": str(work)}, clear=True),
              patch.object(module.subprocess, "run", side_effect=execute) as run,
              contextlib.redirect_stderr(io.StringIO())):
            if execute is None:
                run.return_value.returncode = 0
            result = module.main()
        return result, run

    def test_capture_and_work_roots_reject_before_tool(self):
        variants = ("missing-capture", "public-capture", "symlink-work", "outside-work")
        for label in variants:
            with self.subTest(label=label):
                module, root, captures, work, output, tool = self.go_fixture()
                if label == "missing-capture":
                    captures = root / "missing"
                elif label == "public-capture":
                    captures.chmod(0o777)
                elif label == "symlink-work":
                    work.rename(root / "original-work")
                    work.symlink_to(root / "original-work", target_is_directory=True)
                else:
                    work = root / "unbound-work"
                    work.mkdir(mode=0o700)
                result, execute = self.invoke_go(module, captures, work, [str(tool), "-o", str(output)])
                self.assertEqual(result, 1)
                execute.assert_not_called()

    def test_link_operand_authority_rejects_before_tool(self):
        variants = ("outside", "relative", "parent-symlink", "leaf-symlink", "missing-value",
                    "duplicate", "empty-equals", "no-output", "response-file",
                    "double-dash-override", "flag-value-confusion")
        for label in variants:
            with self.subTest(label=label):
                module, root, captures, work, output, tool = self.go_fixture()
                (work / "alias").symlink_to(work / "b001", target_is_directory=True)
                if label == "leaf-symlink":
                    output.unlink()
                    output.symlink_to(sys.executable)
                arguments = {
                    "outside": ["-o", str(root / "outside")],
                    "relative": ["-o", "relative.out"],
                    "parent-symlink": ["-o", str(work / "alias/a.out")],
                    "leaf-symlink": ["-o", str(output)],
                    "missing-value": ["-o"],
                    "duplicate": ["-o", str(output), "-o", str(output)],
                    "empty-equals": ["-o="],
                    "no-output": ["-buildid=unit"],
                    "response-file": ["-o", str(output), "@unadmitted-response"],
                    "double-dash-override": ["-o", str(output), "--o=" + str(root / "outside")],
                    "flag-value-confusion": ["-buildid", "-o", str(output)],
                }[label]
                result, execute = self.invoke_go(module, captures, work, [str(tool), *arguments])
                self.assertEqual(result, 1)
                execute.assert_not_called()
                self.assertEqual(list(captures.glob("*.json")), [])

    def test_valid_link_retains_exact_bytes_and_receipt(self):
        for label in ("separate", "equals"):
            with self.subTest(label=label):
                module, _root, captures, work, output, tool = self.go_fixture()
                arguments = ["-o", str(output)] if label == "separate" else ["-o=" + str(output)]
                command = [str(tool), *arguments, "-buildid=unit", str(work / "b001/_pkg_.a")]
                result, execute = self.invoke_go(module, captures, work, command)
                self.assertEqual(result, 0)
                execute.assert_called_once_with(command, check=False)
                records = list(captures.glob("*.json"))
                self.assertEqual(len(records), 1)
                record = json.loads(records[0].read_text())
                self.assertEqual(set(record), {"schema", "kind", "arguments", "tool_sha256", "directory",
                                               "output", "output_sha256", "retained_output"})
                self.assertEqual(record["schema"], 1)
                self.assertEqual(record["kind"], "go-tool-link")
                self.assertEqual(record["arguments"], command)
                self.assertEqual(record["output"], str(output))
                self.assertEqual(record["tool_sha256"], module.digest(tool))
                self.assertEqual(record["output_sha256"], module.digest(output))
                self.assertEqual(Path(record["retained_output"]).read_bytes(), output.read_bytes())

    def test_nonlink_and_version_probes_preserve_argv(self):
        for label in ("compile", "version", "version-full"):
            with self.subTest(label=label):
                module, root, captures, work, _output, tool = self.go_fixture()
                if label == "compile":
                    tool = root / "compile"
                    tool.symlink_to(sys.executable)
                    arguments = ["-o", str(work / "b001/_pkg_.a"), "source.go"]
                else:
                    arguments = ["-V"] if label == "version" else ["-V=full"]
                command = [str(tool), *arguments]
                result, execute = self.invoke_go(module, captures, work, command)
                self.assertEqual(result, 0)
                execute.assert_called_once_with(command, check=False)
                self.assertEqual(list(captures.glob("*.json")), [])

    def test_post_tool_link_replacements_cannot_be_retained(self):
        for label in ("symlink", "hardlink"):
            with self.subTest(label=label):
                module, root, captures, work, output, tool = self.go_fixture()
                outside = root / "outside"
                outside.write_bytes(b"unadmitted outside bytes")
                def replace_output(*args, output=output, outside=outside, label=label, **kwargs):
                    output.unlink()
                    if label == "symlink":
                        output.symlink_to(outside)
                    else:
                        os.link(outside, output)
                    return types.SimpleNamespace(returncode=0)
                result, execute = self.invoke_go(module, captures, work, [str(tool), "-o", str(output)], replace_output)
                self.assertEqual(result, 1)
                execute.assert_called_once()
                self.assertEqual(outside.read_bytes(), b"unadmitted outside bytes")
                self.assertEqual(list(captures.glob("*.json")), [])

    def test_retained_and_receipt_destinations_are_exclusive(self):
        for label in ("retained", "receipt"):
            with self.subTest(label=label):
                module, root, captures, work, output, tool = self.go_fixture()
                identifier = "a" * 32
                retained = captures / "go-postlink"
                retained.mkdir(mode=0o700)
                outside = root / "outside"
                outside.write_bytes(b"exclusive destination sentinel")
                destination = retained / identifier if label == "retained" else captures / (identifier + ".json")
                destination.symlink_to(outside)
                with patch.object(module.uuid, "uuid4", return_value=types.SimpleNamespace(hex=identifier)):
                    result, execute = self.invoke_go(module, captures, work, [str(tool), "-o", str(output)])
                self.assertEqual(result, 1)
                execute.assert_called_once()
                self.assertTrue(destination.is_symlink())
                self.assertEqual(outside.read_bytes(), b"exclusive destination sentinel")

    def test_failed_tool_status_is_returned_without_retention(self):
        module, _root, captures, work, output, tool = self.go_fixture()
        def failure(*args, **kwargs):
            return types.SimpleNamespace(returncode=17)
        result, execute = self.invoke_go(module, captures, work, [str(tool), "-o", str(output)], failure)
        self.assertEqual(result, 17)
        execute.assert_called_once()
        self.assertEqual(list(captures.glob("*.json")), [])
        self.assertFalse((captures / "go-postlink").exists())

    def test_output_change_during_held_fd_copy_is_rejected(self):
        module, _root, captures, work, output, tool = self.go_fixture()
        original_read = os.read
        changed = False
        def read_and_change(descriptor, size):
            nonlocal changed
            data = original_read(descriptor, size)
            if data and not changed:
                changed = True
                output.write_bytes(b"changed after held descriptor read")
            return data
        with patch.object(module.os, "read", side_effect=read_and_change):
            result, execute = self.invoke_go(module, captures, work, [str(tool), "-o", str(output)])
        self.assertEqual(result, 1)
        execute.assert_called_once()
        self.assertTrue(changed)
        self.assertEqual(list(captures.glob("*.json")), [])

    def test_retained_stream_constructor_failure_closes_descriptor(self):
        module, _root, captures, work, output, tool = self.go_fixture()
        before = len(list(Path("/proc/self/fd").iterdir()))
        with patch.object(module.os, "fdopen", side_effect=OSError("retained constructor failure")):
            result, execute = self.invoke_go(module, captures, work, [str(tool), "-o", str(output)])
        self.assertEqual(result, 1)
        execute.assert_called_once()
        self.assertEqual(len(list(Path("/proc/self/fd").iterdir())), before)
        self.assertEqual(list(captures.glob("*.json")), [])

    def test_receipt_stream_constructor_failure_closes_descriptor(self):
        module, _root, captures, work, output, tool = self.go_fixture()
        original = os.fdopen
        def fail_receipt(descriptor, mode, **kwargs):
            if mode == "w":
                raise OSError("receipt constructor failure")
            return original(descriptor, mode, **kwargs)
        before = len(list(Path("/proc/self/fd").iterdir()))
        with patch.object(module.os, "fdopen", side_effect=fail_receipt):
            result, execute = self.invoke_go(module, captures, work, [str(tool), "-o", str(output)])
        self.assertEqual(result, 1)
        execute.assert_called_once()
        self.assertEqual(len(list(Path("/proc/self/fd").iterdir())), before)
        receipts = list(captures.glob("*.json"))
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0].read_bytes(), b"")
        receipt_text = receipts[0].read_text()
        with self.assertRaises(json.JSONDecodeError):
            json.loads(receipt_text)

    def test_failure_preserves_same_uid_namespace_replacement(self):
        for label in ("retained", "receipt"):
            with self.subTest(label=label):
                module, _root, captures, work, output, tool = self.go_fixture()
                identifier = "b" * 32
                destination = captures / "go-postlink" / identifier if label == "retained" else captures / (identifier + ".json")
                original = os.fdopen
                def replace_then_fail(descriptor, mode, *, label=label, destination=destination, original=original, **kwargs):
                    if (label == "retained" and mode == "wb") or (label == "receipt" and mode == "w"):
                        destination.unlink()
                        destination.write_bytes(b"same uid replacement sentinel")
                        raise OSError("private fixture replacement failure")
                    return original(descriptor, mode, **kwargs)
                with (patch.object(module.uuid, "uuid4", return_value=types.SimpleNamespace(hex=identifier)),
                      patch.object(module.os, "fdopen", side_effect=replace_then_fail)):
                    result, execute = self.invoke_go(module, captures, work, [str(tool), "-o", str(output)])
                self.assertEqual(result, 1)
                execute.assert_called_once()
                self.assertEqual(destination.read_bytes(), b"same uid replacement sentinel")
                if label == "retained":
                    self.assertEqual(list(captures.glob("*.json")), [])
                else:
                    receipt_text = destination.read_text()
                    with self.assertRaises(json.JSONDecodeError):
                        json.loads(receipt_text)

    def test_partial_receipt_write_fails_without_valid_certificate(self):
        module, _root, captures, work, output, tool = self.go_fixture()
        original = os.fdopen
        class FailingReceipt:
            def __init__(self, stream):
                self.stream = stream
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.stream.close()
            def write(self, text):
                self.stream.write("{")
                self.stream.flush()
                raise OSError("partial receipt failure")
        def fail_write(descriptor, mode, **kwargs):
            stream = original(descriptor, mode, **kwargs)
            return FailingReceipt(stream) if mode == "w" else stream
        before = len(list(Path("/proc/self/fd").iterdir()))
        with patch.object(module.os, "fdopen", side_effect=fail_write):
            result, execute = self.invoke_go(module, captures, work, [str(tool), "-o", str(output)])
        self.assertEqual(result, 1)
        execute.assert_called_once()
        self.assertEqual(len(list(Path("/proc/self/fd").iterdir())), before)
        receipts = list(captures.glob("*.json"))
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0].read_bytes(), b"{")
        receipt_text = receipts[0].read_text()
        with self.assertRaises(json.JSONDecodeError):
            json.loads(receipt_text)


if os.environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)


if __name__ == "__main__":
    unittest.main()
