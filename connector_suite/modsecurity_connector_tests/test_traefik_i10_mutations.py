"""Executable Traefik I10 negative controls in external source/module copies."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import ctypes.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = connector_root()


class TraefikI10MutationTests(unittest.TestCase):
    def test_go_host_boundaries_detect_mutations(self) -> None:
        cases = (
            ("native-commit", "native_middleware", "middleware.go", "reportResponseCommit", "panic(http.ErrAbortHandler)", "return", "TestTechnicalFailureReachesMiddlewareHost/commit"),
            ("native-eos", "native_middleware", "middleware.go", "finish", "panic(http.ErrAbortHandler)", "return", "TestTechnicalFailureReachesMiddlewareHost/(response-eos|late-outcome)"),
            ("native-outcome", "native_middleware", "middleware.go", "acknowledgeApplied", "panic(http.ErrAbortHandler)", "return", "TestTechnicalFailureReachesMiddlewareHost/outcome"),
            ("native-reentry", "native_middleware", "middleware.go", None, "if state.terminalError != nil {", "if false {", "TestTechnicalFailureIsTerminalAndKeepsFirstCause"),
            ("uds-finish", "native_middleware", "engine_uds.go", None, "return closeErr", "return nil", "TestUDSTechnicalResultReachesProductiveMiddleware/(8|9)"),
            ("observer-eos", "response_observer", "observer.go", None, "panic(http.ErrAbortHandler)", "return", "TestTechnicalEOSFailureStopsCommittedObserver"),
            ("observer-immediate-ack", "response_observer", "observer.go", None, "panic(http.ErrAbortHandler)", "return", "TestImmediateOutcomeAcknowledgementFollowsHostAction"),
            ("observer-host-write", "response_observer", "observer.go", None, "s.terminalError = writeErr", "s.terminalError = nil", "TestObserverIgnoredHostWriteFailureStillStopsWithoutEOS/short=false"),
            ("observer-host-short", "response_observer", "observer.go", None, "s.terminalError = io.ErrShortWrite", "s.terminalError = nil", "TestObserverIgnoredHostWriteFailureStillStopsWithoutEOS/short=true"),
            ("observer-body", "response_observer", "observer.go", None, "s.terminalError = errProtocol", "s.terminalError = nil", "TestMiddlewareStopsBodyOnCanonicalResultFailure"),
            ("uds-result", "native_middleware", "engine_uds.go", "parseUDSResult", "if payload[1] != udsResultOK {", "if false {", "TestUDSTechnicalResultReachesProductiveMiddleware/(1|2|3|4|5|6|7|10)"),
        )
        for name, module, filename, function, old, new, selected in cases:
            with self.subTest(mutation=name), tempfile.TemporaryDirectory(
                prefix="traefik-i10-mutation-", dir=os.environ.get("TMPDIR")
            ) as directory:
                copy = Path(directory) / "module"
                shutil.copytree(source_path('connectors/traefik', root=ROOT) / module, copy)
                source = copy / filename
                content = source.read_text()
                if function is None:
                    self.assertIn(old, content)
                    content = content.replace(old, new)
                else:
                    receiver = "writer *responseWriter" if function == "finish" else "state *streamState"
                    signature = "func (" + receiver + ") " + function + "("
                    if function == "parseUDSResult":
                        signature = "func parseUDSResult("
                    start = content.index(signature)
                    end = content.find("\nfunc ", start + 5)
                    if end < 0:
                        end = len(content)
                    part = content[start:end]
                    self.assertIn(old, part)
                    content = content[:start] + part.replace(old, new) + content[end:]
                source.write_text(content)
                environment = dict(os.environ, GOTOOLCHAIN="local", GOWORK="off")
                environment.setdefault("GOCACHE", str(Path(directory) / "go-cache"))
                result = subprocess.run(
                    ["go", "test", "-mod=readonly", "-count=1", "-run", selected, "./..."],
                    cwd=copy, env=environment, capture_output=True, text=True,
                    timeout=120, check=False,
                )
                output = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0, "mutation survived")
                self.assertIn("--- FAIL:", output, output)
                self.assertNotIn("[build failed]", output, output)

    def test_c_dispatcher_and_wire_boundaries_detect_mutations(self) -> None:
        if shutil.which("cc") is None:
            self.skipTest("requires a C compiler")
        if ctypes.util.find_library("modsecurity") is None:
            self.skipTest("requires installed libmodsecurity to link retained Common runtime")

        cases = (
            ("exact-return", "if (success != 1) {", "if (!success) {"),
            ("typed-error", "if (handled == 1 && (decision->kind", "if (0 && handled == 1 && (decision->kind"),
            ("framed-caller", "return handled == 1 && frame->opcode != TRAEFIK_ENGINE_PROTOCOL_DESTROY;", "return 1;"),
            ("reentry", "session != NULL && session->failed)", "session != NULL && 0 && session->failed)"),
        )
        for name, old, new in cases:
            with self.subTest(mutation=name), tempfile.TemporaryDirectory(
                prefix="traefik-i10-c-mutation-", dir=os.environ.get("TMPDIR")
            ) as directory:
                copy = Path(directory)
                (copy / "common").symlink_to(source_path('common', root=ROOT), target_is_directory=True)
                (copy / "connectors/traefik/src").mkdir(parents=True)
                (copy / "connectors/traefik/config").mkdir()
                (copy / "tests").mkdir()
                for filename in ("profile_registry.c", "profile_registry.h"):
                    (copy / "connectors" / filename).symlink_to(source_path('connectors', root=ROOT) / filename)
                for filename in ("traefik_engine_service.c", "traefik_engine_protocol.h"):
                    shutil.copy2(source_path('connectors/traefik/src', root=ROOT) / filename, copy / "connectors/traefik/src" / filename)
                shutil.copy2(source_path('connectors/traefik/config/traefik-engine-service.conf', root=ROOT), copy / "connectors/traefik/config/traefik-engine-service.conf")
                for filename in ("test_traefik_i10_dispatcher.py", "traefik_i10_dispatcher_test.c"):
                    shutil.copy2(source_path('tests', root=ROOT) / filename, copy / "tests" / filename)
                source = copy / "connectors/traefik/src/traefik_engine_service.c"
                content = source.read_text()
                self.assertIn(old, content)
                source.write_text(content.replace(old, new))
                result = subprocess.run(
                    [os.environ.get("PYTHON", os.sys.executable), "-m", "unittest", "discover", "-s", "tests", "-p", "test_traefik_i10_dispatcher.py"],
                    cwd=copy, capture_output=True, text=True, timeout=120, check=False,
                )
                output = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0, "mutation survived")
                self.assertIn("Assertion `", output, output)
                self.assertIn("failed.", output, output)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
