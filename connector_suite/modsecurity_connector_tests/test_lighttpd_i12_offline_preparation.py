"""Exercise real diagnostic preparation on private source copies, never a host."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, source_path

import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = connector_root()
NATIVE = "ci/runtime/lifecycle/i12/lighttpd/diagnostic_native.py"
MODULE = "connectors/lighttpd/module/mod_msconnector.c"
RUNTIME = "common/runtime/msconnector_runtime.c"
REQUEST_ANCHOR = "        const handler_t rc = mod_msconnector_apply_decision(r, p, ctx, &decision);"
PREPARATION_INPUTS = (
    NATIVE, MODULE, RUNTIME,
    "ci/runtime/lifecycle/i12/lighttpd/stock_capture.py",
    "ci/runtime/lifecycle/i12/lighttpd/stock_raw_client.py",
    "ci/runtime/lifecycle/i12/lighttpd/diagnostic_native_observer.h",
    "ci/runtime/lifecycle/i12/lighttpd/diagnostic_faults.h",
    "ci/runtime/lifecycle/i12/lighttpd/diagnostic_fault_capture.py",
    "ci/runtime/lifecycle/i12/lighttpd/patched_faults.h",
    "ci/runtime/lifecycle/i12/lighttpd/diagnostic_budget_observer.h",
    "ci/runtime/lifecycle/i12/lighttpd/diagnostic_finish_observer.h",
    "ci/runtime/lifecycle/i12/lighttpd/diagnostic_terminal_control.h",
    "ci/runtime/lifecycle/i12/lighttpd/diagnostic_transport.py",
    "ci/runtime/common/response_fixture_omission.py",
    "ci/lib/i12_path_safety.py", "ci/lib/runtime_path_utils.py",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RepositoryInputs:
    """Route mutable product inputs privately; execute maintained helpers in place."""
    def __init__(self, private_repository: Path):
        self.private_repository = private_repository

    def __truediv__(self, relative: str) -> Path:
        return (self.private_repository / relative if relative in (MODULE, RUNTIME) else source_path(relative, root=ROOT))


class OfflinePreparationTests(unittest.TestCase):
    def setUp(self):
        configured = os.environ.get("I12_TEST_ROOT") or os.environ.get("RUNNER_TEMP")
        if not configured:
            raise RuntimeError("offline preparation requires an explicit private test root")
        parent = Path(configured)
        if not parent.is_absolute() or parent.resolve(strict=True) != parent:
            raise RuntimeError("offline preparation root must be canonical and absolute")
        self.temporary = tempfile.TemporaryDirectory(prefix="offline-lighttpd-prepare-", dir=parent)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.external = self.root / "external"
        self.external.mkdir(mode=0o700)
        self.runs = self.external / "runs"
        self.runs.mkdir(mode=0o700)
        self.repository = self.runs / "repository"
        self.repository.mkdir(mode=0o700)
        self.original_hashes = {name: digest(source_path(name, root=ROOT)) for name in PREPARATION_INPUTS}
        for name in PREPARATION_INPUTS:
            destination = self.repository / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_path(name, root=ROOT), destination)
        self.environment = mock.patch.dict(os.environ, {"I12_TEST_ROOT": str(self.external)})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        spec = importlib.util.spec_from_file_location("offline_lighttpd_prepare", source_path(NATIVE, root=ROOT))
        self.native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.native)
        # The actual checkout can be an external worktree rather than /root/git.
        # Add only this readonly source root; keep the real SHA/path validators.
        source_environment = mock.patch.object(self.native, "READ_ROOTS", (*self.native.READ_ROOTS, ROOT))
        source_environment.start()
        self.addCleanup(source_environment.stop)
        self.sdk = self.runs / "sdk"
        (self.sdk / "lib").mkdir(parents=True)
        (self.sdk / "include").mkdir()
        (self.sdk / "lib/libmodsecurity.so").write_bytes(b"synthetic SDK boundary bytes; not executable\n")
        host = self.runs / "lighttpd"
        host.write_bytes(b"synthetic host boundary bytes; not executable\n")
        proxy = self.runs / "mod_proxy.so"
        proxy.write_bytes(b"synthetic proxy boundary bytes; not executable\n")
        self.args = SimpleNamespace(repository=RepositoryInputs(self.repository), output=self.runs / "prepared",
                                    sdk=self.sdk, core=self.runs / "core", core_build=self.runs / "core-build",
                                    host=host, proxy_module=proxy, checkout_head="offline-current-source")
        self.commands = []
        self.export_mismatch = False
        self.compiler_failure = False
        self.symbols = ["msc_new_transaction_with_id", "msc_process_request_headers"]
        self.addCleanup(self.assert_checkout_unchanged)

    def assert_checkout_unchanged(self):
        self.assertEqual(self.original_hashes, {name: digest(source_path(name, root=ROOT)) for name in PREPARATION_INPUTS})

    def materialize(self, args, stock):
        """Stand in only for source-export/observer compilation and its outputs."""
        source = args.output / "source"
        source.mkdir(mode=0o700)
        for name in (MODULE, RUNTIME):
            destination = source / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(args.repository / name, destination)
        if self.export_mismatch:
            with (source / MODULE).open("a") as stream:
                stream.write("\n/* mismatched external export */\n")
        (source / ".i12-disposable-source-copy.json").write_text(
            json.dumps({"disposable": True, "path": str(source)}))
        (source / "i12-source-application-receipt.json").write_text(
            json.dumps({"synthetic_materialization_boundary": True, "runtime_qualified": False}))
        captured = source / ".i12-capture/lighttpd/stock-empty-drivers"
        captured.mkdir(parents=True)
        shutil.copyfile(args.repository / "ci/runtime/lifecycle/i12/lighttpd/stock_raw_client.py",
                        captured / "curl-raw-client.py")
        (captured / "observed-backend.py").write_bytes(b"# synthetic external capture output; never executed\n")
        build = args.output / "build"
        build.mkdir()
        for name in ("observer", "host", "bootstrap", "sdk"):
            (build / (name + ".o")).write_bytes(("synthetic object " + name).encode())
        (args.output / "build-binding.json").write_text(json.dumps({"wrapped_symbols": self.symbols}))

    def compiler_boundary(self, argv, directory, label, env=None):
        self.commands.append((list(argv), directory, label, dict(env)))
        if self.compiler_failure:
            raise RuntimeError("synthetic compiler boundary failure")
        destination = directory / "lighttpd-connector/modules/mod_msconnector.so"
        destination.parent.mkdir(parents=True)
        destination.write_bytes(b"synthetic compiler output; never loaded\n")

    def prepare(self):
        with mock.patch.object(self.native, "materialize_current", side_effect=self.materialize) as materialize, \
                mock.patch.object(self.native, "command", side_effect=self.compiler_boundary):
            self.native.prepare(self.args)
        materialize.assert_called_once()

    def test_real_overlays_strip_to_current_product_and_bind_outputs(self):
        self.assertEqual(Path(self.native.__file__), source_path(NATIVE, root=ROOT))
        self.prepare()
        output = self.args.output
        source = output / "source"
        observed = (source / MODULE).read_text()
        original = (ROOT / MODULE).read_text()
        # Undo the actual terminal and observation deltas independently of the receipt.
        terminal = '''    {
        const int control = i12_diagnostic_terminal_control(ctx->transaction, &runtime_error);
        if (control != 0) return mod_msconnector_fail_request(r, p->runtime, ctx,
            control == 1 ? MSCONNECTOR_ERROR_TIMEOUT :
            control == 2 ? MSCONNECTOR_ERROR_HOST_API_FAILURE : runtime_error.code);
    }
'''
        self.assertEqual(observed.count(terminal), 1)
        stripped = observed.replace(terminal, "", 1).replace('#include "diagnostic_terminal_control.h"\n', "", 1)
        response = '''    {
        handler_t result = mod_msconnector_apply_decision(r, p, ctx, &decision);
        i12_diagnostic_host(r, ctx, "response_decision_returned");
        return result;
    }'''
        self.assertEqual(stripped.count(response), 1)
        stripped = stripped.replace(response, "    return mod_msconnector_apply_decision(r, p, ctx, &decision);", 1)
        stripped = stripped.replace('\n#include "diagnostic_native_observer.h"', "", 1)
        for seam in ("request_decision_returned", "request_reset_entered", "technical_error_response_selected"):
            line = ('        ' if seam == "request_decision_returned" else '    ') + f'i12_diagnostic_host(r, ctx, "{seam}");\n'
            self.assertEqual(stripped.count(line), 1)
            stripped = stripped.replace(line, "", 1)
        prefix = '#ifndef _GNU_SOURCE\n#define _GNU_SOURCE\n#endif\n#include "lighttpd-host-observer.h"\n'
        self.assertTrue(stripped.startswith(prefix))
        self.assertEqual(stripped[len(prefix):], original)
        identity = json.loads((output / "observation-strip-identity.json").read_text())
        self.assertEqual(identity["additive_seams"], 5)
        self.assertIs(identity["current_product_byte_identity_after_stripping_observation"], True)
        self.assertEqual(identity["stripped_product_sha256"], digest(ROOT / MODULE))
        faults = json.loads((output / "extended-fault-overlay.json").read_text())
        self.assertIs(faults["stripped_input_identity"], True)
        self.assertIs(faults["native_sdk_return_mutated"], False)
        self.assertEqual(faults["fault_runtime_sha256"], digest(source / RUNTIME))
        for key, filename in (("sink_header_sha256", "patched_faults.h"),
                              ("budget_observer_sha256", "diagnostic_budget_observer.h"),
                              ("finish_observer_sha256", "diagnostic_finish_observer.h")):
            self.assertEqual(faults[key], digest(source / filename))
        runtime = (source / RUNTIME).read_text()
        self.assertIn('i12_diagnostic_boundary_result("request_headers", msc_process_request_headers(', runtime)
        self.assertIn('i12_diagnostic_boundary_result("logging", msc_process_logging(', runtime)
        self.assertIn("static int i12_diagnostic_finish_implementation(", runtime)
        terminal_receipt = json.loads((output / "terminal-control-overlay.json").read_text())
        self.assertEqual(terminal_receipt["module_after_sha256"], digest(source / MODULE))
        self.assertEqual(terminal_receipt["header_sha256"], digest(source / "diagnostic_terminal_control.h"))
        wrapper = output / "native-build/observed-cc.py"
        wrapper_source = wrapper.read_text()
        ast.parse(wrapper_source)
        for name in ("observer", "host", "bootstrap", "sdk"):
            self.assertIn(str(output / "build" / (name + ".o")), wrapper_source)
        for symbol in self.symbols:
            self.assertIn("-Wl,--wrap=" + symbol, wrapper_source)
        self.assertIn("if '-c' not in sys.argv", wrapper_source)
        self.assertEqual(wrapper.stat().st_mode & 0o777, 0o500)
        self.assertEqual(len(self.commands), 1)
        argv, directory, label, environment = self.commands[0]
        self.assertEqual(argv, ["sh", source / "connectors/lighttpd/build/build_module.sh"])
        self.assertEqual((directory, label), (output / "native-build", "native-build"))
        self.assertEqual(environment["CC"], str(wrapper))
        self.assertEqual(environment["LIGHTTPD_MSCONNECTOR_CORE_MODE"], "stock")
        preparation = json.loads((output / "preparation.json").read_text())
        self.assertEqual(preparation["current_product_module_sha256"], digest(ROOT / MODULE))
        self.assertEqual(preparation["pre_observation_materialized_module_sha256"], digest(ROOT / MODULE))
        self.assertEqual(preparation["source_variant_receipt_sha256"], digest(source / "i12-source-application-receipt.json"))
        self.assertEqual(preparation["stock_module_after_diagnostic_overlay_sha256"], digest(source / MODULE))
        self.assertEqual(preparation["runtime_after_fault_overlay_sha256"], digest(source / RUNTIME))
        self.assertEqual(preparation["diagnostic_overlay_sha256"], digest(source / "diagnostic_native_observer.h"))
        self.assertEqual(preparation["fault_overlay_sha256"], digest(source / "diagnostic_faults.h"))
        self.assertEqual(preparation["host_module_sha256"], digest(output / "artifacts/modules/mod_msconnector.so"))
        self.assertEqual(preparation["host_sha256"], digest(self.args.host))
        self.assertEqual(preparation["sdk_sha256"], digest(self.sdk / "lib/libmodsecurity.so"))
        self.assertEqual(preparation["fixture_source_sha256"], digest(source_path(NATIVE, root=ROOT)))
        self.assertEqual(preparation["numeric_loopback_client_sha256"], digest(output / "fixtures/curl-raw-client.py"))
        self.assertIs(preparation["observation_overlay_changes_decisions"], False)
        self.assertIs(preparation["historical_full_module_used_as_product"], False)
        for helper, expected in preparation["path_boundary_dependencies_sha256"].items():
            self.assertEqual(expected, digest(self.repository / "ci/lib" / helper))
        bindings = json.loads((output / "fixtures/backend-inputs.json").read_text())
        self.assertEqual(set(bindings), self.native.PREPARED_BACKEND_FILES)
        self.assertEqual(bindings, {name: digest(output / "fixtures" / name) for name in bindings})
        self.assertEqual(preparation["prepared_backend_inputs_sha256"], digest(output / "fixtures/backend-inputs.json"))
        self.assertEqual((output / "current-product-mod_msconnector.c").read_bytes(), (ROOT / MODULE).read_bytes())
        self.assertEqual((output / "artifacts/bin/lighttpd").read_bytes(), self.args.host.read_bytes())
        self.assertEqual((output / "artifacts/modules/mod_proxy.so").read_bytes(), self.args.proxy_module.read_bytes())
        self.assertNotIn("urlsplit", (output / "fixtures/curl-raw-client.py").read_text())

    def test_exported_module_hash_mismatch_emits_no_preparation_receipt(self):
        self.export_mismatch = True
        with self.assertRaisesRegex(ValueError, "Current source inventory module changed"):
            self.prepare()
        self.assertEqual(self.commands, [])
        self.assertFalse((self.args.output / "preparation.json").exists())

    def test_missing_request_anchor_emits_no_preparation_receipt(self):
        module = self.repository / MODULE
        module.write_text(module.read_text().replace(REQUEST_ANCHOR, "        /* missing request seam */", 1))
        with self.assertRaisesRegex(ValueError, "Stock request-decision observation seam changed"):
            self.prepare()
        self.assertEqual(self.commands, [])
        self.assertFalse((self.args.output / "preparation.json").exists())

    def test_ambiguous_request_anchor_emits_no_preparation_receipt(self):
        module = self.repository / MODULE
        module.write_text(module.read_text().replace(REQUEST_ANCHOR, REQUEST_ANCHOR + "\n" + REQUEST_ANCHOR, 1))
        with self.assertRaisesRegex(ValueError, "Stock request-decision observation seam changed"):
            self.prepare()
        self.assertEqual(self.commands, [])
        self.assertFalse((self.args.output / "preparation.json").exists())

    def test_compiler_boundary_failure_emits_no_preparation_receipt(self):
        self.compiler_failure = True
        with self.assertRaisesRegex(RuntimeError, "synthetic compiler boundary failure"):
            self.prepare()
        self.assertEqual(len(self.commands), 1)
        self.assertFalse((self.args.output / "preparation.json").exists())
        self.assertFalse((self.args.output / "artifacts").exists())


if os.environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)


if __name__ == "__main__":
    unittest.main()
