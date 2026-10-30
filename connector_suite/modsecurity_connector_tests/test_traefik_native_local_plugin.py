from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import concurrent.futures
import errno
import fcntl
import importlib.util
import json
import os
import re
import socket
import stat
import struct
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest import mock


ROOT = connector_root()
PLUGIN = source_path('connectors/traefik/native_middleware', root=ROOT)
RUNNER_PATH = source_path('connectors/traefik/scripts/runtime_native_smoke.py', root=ROOT)


def load_runner():
    module = load_source(RUNNER_PATH)
    return module


runner = load_runner()


def engine_socket_parent(path: Path) -> object:
    return runner.EngineSocketParent(
        path=path,
        identity=runner.private_directory_identity(path, "test parent"),
    )


def short_socket_temporary_directory() -> tempfile.TemporaryDirectory:
    """Allocate test state under a writable, short existing temp boundary."""

    default_root = Path(tempfile.gettempdir())
    for candidate in (default_root.parent, default_root):
        if candidate == Path(candidate.anchor) or not candidate.is_dir():
            continue
        if not os.access(candidate, os.W_OK | os.X_OK):
            continue
        longest_socket = (
            candidate
            / ("q" + "f" * 8)
            / (
                runner.ENGINE_SOCKET_DIRECTORY_PREFIX
                + "f" * runner.ENGINE_SOCKET_DIRECTORY_RANDOM_HEX_LENGTH
            )
            / runner.ENGINE_SOCKET_FILENAME
        )
        if len(os.fsencode(str(longest_socket))) <= 100:
            return tempfile.TemporaryDirectory(prefix="q", dir=candidate)
    raise RuntimeError("no writable short temporary directory is available for AF_UNIX tests")


class TraefikNativeLocalPluginTest(unittest.TestCase):
    def test_normal_client_waits_for_server_eof_after_declared_body(self) -> None:
        body_sent = threading.Event()
        finish_handler = threading.Event()
        requests = []
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(3)

            def serve() -> None:
                peer, _ = listener.accept()
                with peer:
                    peer.settimeout(3)
                    request = b""
                    while b"\r\n\r\n" not in request:
                        request += peer.recv(4096)
                    requests.append(request)
                    peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc")
                    body_sent.set()
                    if not finish_handler.wait(3):
                        raise RuntimeError("test handler completion barrier timed out")

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                server = pool.submit(serve)
                client = pool.submit(
                    runner.request_through_traefik,
                    listener.getsockname()[1], b"", "completion-control", 200,
                )
                try:
                    self.assertTrue(body_sent.wait(3))
                    self.assertFalse(client.done())
                finally:
                    finish_handler.set()
                self.assertEqual(client.result(timeout=3), (200, 3))
                server.result(timeout=3)
            self.assertIn(b"Connection: close", requests[0])

    def test_physical_eof_timeout_and_extra_tail_are_failures(self) -> None:
        for payload in (None, b"unexpected-tail"):
            with self.subTest(payload=payload):
                left, right = socket.socketpair()
                with left, right:
                    left.settimeout(0.02)
                    if payload is not None:
                        right.sendall(payload)
                    with self.assertRaises(RuntimeError):
                        runner.require_response_socket_eof(left)

    def test_completion_duplicate_closes_when_response_setup_fails(self) -> None:
        owned = []
        original_dup = socket.socket.dup

        def tracked_dup(sock):
            duplicate = original_dup(sock)
            owned.append(duplicate)
            return duplicate

        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(3)
            port = listener.getsockname()[1]
            with mock.patch.object(socket.socket, "dup", tracked_dup), mock.patch.object(
                runner.CompletionHTTPResponse, "begin", side_effect=RuntimeError("setup failed")
            ):
                with self.assertRaisesRegex(RuntimeError, "setup failed"):
                    runner.request_through_traefik(port, b"", "failure", 200)
            peer, _ = listener.accept()
            peer.close()
        self.assertEqual(len(owned), 1)
        self.assertEqual(owned[0].fileno(), -1)

    def test_unbuffered_chunked_response_handles_actual_short_reads(self) -> None:
        left, right = socket.socketpair()
        first_body_read = threading.Event()
        with left, right:
            left.settimeout(3)
            right.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\na")
            response = runner.CompletionHTTPResponse(left)
            response.begin()
            original_read = response.fp.read

            def observe_read(amount):
                result = original_read(amount)
                if result == b"a":
                    first_body_read.set()
                return result

            response.fp.read = observe_read
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                body = pool.submit(runner.read_response_body, response)
                try:
                    self.assertTrue(first_body_read.wait(3))
                finally:
                    right.sendall(b"bc\r\n0\r\n\r\n")
                    right.shutdown(socket.SHUT_WR)
                self.assertEqual(body.result(timeout=3), (200, 3))
            response.close()

    def test_unbuffered_content_length_handles_actual_short_reads(self) -> None:
        left, right = socket.socketpair()
        first_body_read = threading.Event()
        with left, right:
            left.settimeout(3)
            right.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\na")
            response = runner.CompletionHTTPResponse(left)
            response.begin()
            original_read = response.fp.read

            def observe_read(amount):
                result = original_read(amount)
                if result == b"a":
                    first_body_read.set()
                return result

            response.fp.read = observe_read
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                body = pool.submit(runner.read_response_body, response)
                try:
                    self.assertTrue(first_body_read.wait(3))
                finally:
                    right.sendall(b"bc")
                    right.shutdown(socket.SHUT_WR)
                self.assertEqual(body.result(timeout=3), (200, 3))
            response.close()

    def test_physical_tcp_reset_is_not_normal_eof(self) -> None:
        with socket.socket() as listener, socket.socket() as client:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            client.settimeout(3)
            client.connect(listener.getsockname())
            peer, _ = listener.accept()
            peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            peer.close()
            with self.assertRaisesRegex(RuntimeError, "physical socket EOF"):
                runner.require_response_socket_eof(client)

    def test_sized_body_read_rejects_truncation_and_inflight_timeout(self) -> None:
        for close_peer in (True, False):
            with self.subTest(close_peer=close_peer):
                left, right = socket.socketpair()
                with left, right:
                    left.settimeout(0.02)
                    right.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")
                    if close_peer:
                        right.shutdown(socket.SHUT_WR)
                    response = runner.CompletionHTTPResponse(left)
                    try:
                        response.begin()
                        with self.assertRaisesRegex(RuntimeError, "incomplete body|did not complete"):
                            runner.read_response_body(response)
                        if close_peer:
                            self.assertEqual(response.length, 7)
                    finally:
                        response.close()

    def test_request_truncation_and_body_timeout_close_owned_sockets(self) -> None:
        original_connection = runner.http.client.HTTPConnection
        original_dup = socket.socket.dup
        original_response_init = runner.CompletionHTTPResponse.__init__
        for close_peer in (True, False):
            owned = []
            retained_responses = []
            retained_errors = []

            def track_response(response, *args, **kwargs):
                original_response_init(response, *args, **kwargs)
                retained_responses.append((response, response.fp, response.fp.fileno()))

            def tracked_dup(sock):
                duplicate = original_dup(sock)
                owned.append(duplicate)
                return duplicate

            def bounded_connection(host, port, timeout):
                return original_connection(host, port, timeout=0.05)

            with self.subTest(close_peer=close_peer), socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                listener.settimeout(3)
                port = listener.getsockname()[1]

                def serve():
                    peer, _ = listener.accept()
                    with peer:
                        peer.settimeout(3)
                        request = b""
                        while b"\r\n\r\n" not in request:
                            request += peer.recv(4096)
                        peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nabc")
                        if close_peer:
                            peer.shutdown(socket.SHUT_WR)
                        self.assertEqual(peer.recv(1), b"")

                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    server = pool.submit(serve)
                    with mock.patch.object(socket.socket, "dup", tracked_dup), mock.patch.object(
                        runner.http.client, "HTTPConnection", bounded_connection
                    ), mock.patch.object(
                        runner.CompletionHTTPResponse, "__init__", track_response
                    ):
                        client = pool.submit(runner.request_through_traefik, port, b"", "truncated", 200)
                        retained_error = client.exception(timeout=3)
                        self.assertIsInstance(retained_error, RuntimeError)
                        self.assertIsNotNone(retained_error.__traceback__)
                        retained_errors.append(retained_error)
                    server.result(timeout=3)
                self.assertEqual(len(owned), 1)
                self.assertEqual(owned[0].fileno(), -1)
                self.assertEqual(len(retained_errors), 1)
                self.assertRegex(str(retained_errors[0]), "incomplete body|did not complete")
                if not close_peer:
                    self.assertIsInstance(retained_errors[0].__cause__, TimeoutError)
                self.assertEqual(len(retained_responses), 1)
                response, response_file, response_fd = retained_responses[0]
                self.assertTrue(response_file.closed)
                self.assertIsNone(response.fp)
                with self.assertRaises(OSError) as closed:
                    fcntl.fcntl(response_fd, fcntl.F_GETFD)
                self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_response_cleanup_closes_all_resources_and_preserves_original_error(self) -> None:
        original = RuntimeError("original body failure")
        response = mock.Mock()
        response.close.side_effect = OSError("response close failed")
        connection = mock.Mock()
        connection.close.side_effect = OSError("connection close failed")
        completion = mock.Mock()
        with self.assertRaises(RuntimeError) as raised:
            try:
                raise original
            finally:
                runner.close_response_resources(response, connection, completion)
        self.assertIs(raised.exception, original)
        self.assertIn("cleanup failures", original.__notes__[0])
        response.close.assert_called_once()
        connection.close.assert_called_once()
        completion.close.assert_called_once()

        with self.assertRaises(OSError):
            runner.close_response_resources(response, connection, completion)
        self.assertEqual(completion.close.call_count, 2)

    def test_unbuffered_http_parser_does_not_hide_extra_tail(self) -> None:
        left, right = socket.socketpair()
        with left, right:
            left.settimeout(3)
            right.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcEXTRA")
            right.shutdown(socket.SHUT_WR)
            response = runner.CompletionHTTPResponse(left)
            response.begin()
            self.assertEqual(response.read(), b"abc")
            with self.assertRaisesRegex(RuntimeError, "beyond its declared body"):
                runner.require_response_socket_eof(left)
            response.close()

    def test_uds_is_the_only_engine_mode_and_reference_default(self) -> None:
        source = (PLUGIN / "middleware.go").read_text(encoding="utf-8")
        reference = (
            source_path('examples/traefik/configuration-reference.md', root=ROOT)
        ).read_text(encoding="utf-8")
        reference_de = (
            source_path('examples/traefik/configuration-reference.de.md', root=ROOT)
        ).read_text(encoding="utf-8")
        self.assertIn('EngineMode:                   "uds",', source)
        self.assertIn('if value.EngineMode != "uds" {', source)
        self.assertIn("unsupported engineMode", source)
        self.assertNotIn("| passthrough \\| uds |", reference)
        self.assertNotIn("| passthrough \\| uds |", reference_de)
        self.assertIn("Legacy source-only passthrough is rejected", reference)
        self.assertIn("Legacy-source-only-passthrough wird", reference_de)

    def test_uds_only_contract_is_consistent_in_manifest_manual_docs_and_inventory(self) -> None:
        manifest = (PLUGIN / ".traefik.yml").read_text(encoding="utf-8")
        readme = (source_path('examples/traefik/README.md', root=ROOT)).read_text(
            encoding="utf-8"
        )
        readme_de = (
            source_path('examples/traefik/README.de.md', root=ROOT)
        ).read_text(encoding="utf-8")
        generator = (
            source_path('ci/checks/documentation/connector_config_reference.py', root=ROOT)
        ).read_text(encoding="utf-8")
        inventory = json.loads(
            (source_path('reports/connector-configuration-inventory.json', root=ROOT)).read_text(
                encoding="utf-8"
            )
        )

        self.assertIn("engineMode: uds", manifest)
        self.assertIn("engineSocketPath: /run/traefik-msconnector/engine.sock", manifest)
        self.assertNotIn("engineMode: passthrough", manifest)
        self.assertIn("legacy `passthrough` configuration is", readme)
        self.assertIn("Legacy-`passthrough`-Konfiguration", readme_de)
        self.assertIn('ALLOWED_VALUES_TRAEFIK_ENGINE_MODE = "uds"', generator)
        engine_modes = [
            option
            for option in inventory["options"]
            if option["connector"] == "traefik" and option["name"].endswith("engineMode")
        ]
        self.assertTrue(engine_modes)
        self.assertTrue(
            all(
                option["allowed_values"] == "uds" and option["default"] == "uds"
                for option in engine_modes
            )
        )

    def test_native_config_fields_have_bilingual_inventory_parity(self) -> None:
        source = (PLUGIN / "middleware.go").read_text(encoding="utf-8")
        reference = (source_path('examples/traefik/configuration-reference.md', root=ROOT)).read_text(
            encoding="utf-8"
        )
        reference_de = (
            source_path('examples/traefik/configuration-reference.de.md', root=ROOT)
        ).read_text(encoding="utf-8")
        selected_example = (
            source_path('examples/traefik/safe/traefik-dynamic.yaml', root=ROOT)
        ).read_text(encoding="utf-8")
        inventory = json.loads(
            (source_path('reports/connector-configuration-inventory.json', root=ROOT)).read_text(
                encoding="utf-8"
            )
        )
        config_block = re.search(
            r"(?ms)^type Config struct \{(?P<body>.*?)^\}", source
        )
        self.assertIsNotNone(config_block)
        fields = [
            tag.split(",", 1)[0]
            for tag in re.findall(r'`json:"([^"]+)', config_block.group("body"))
        ]
        # Two decoder tombstones reject removed inspection limits; they are
        # not configurable host controls and must stay out of the inventory.
        removed_fields = {"maxRequestBodyBytes", "maxResponseBodyBytes"}
        self.assertEqual(len(fields), 10)
        self.assertTrue(removed_fields.issubset(fields))
        active_fields = set(fields) - removed_fields
        native_options = {
            option["name"]
            for option in inventory["options"]
            if option.get("connector") == "traefik"
            and option["name"].startswith(
                "http.middlewares.modsecurity-native-streaming.plugin.modsecurityNative."
            )
        }
        prefix = "http.middlewares.modsecurity-native-streaming.plugin.modsecurityNative."
        self.assertEqual(native_options, {prefix + field for field in active_fields})
        for field in removed_fields:
            with self.subTest(removed_field=field):
                self.assertNotIn(prefix + field, reference)
                self.assertNotIn(prefix + field, reference_de)
                self.assertNotIn(f"{field}:", selected_example)
        for field in active_fields:
            path = (
                "http.middlewares.modsecurity-native-streaming.plugin.modsecurityNative."
                + field
            )
            with self.subTest(field=field):
                self.assertIn(path, reference)
                self.assertIn(path, reference_de)
                self.assertIn(path, native_options)
                self.assertIn(f"{field}:", selected_example)
        self.assertIn("uds maximum 32768", reference)
        self.assertIn("maximum 60000 milliseconds", reference)
        self.assertIn("UDS-Maximum 32768", reference_de)
        self.assertIn(
            '"default": "32768"',
            (source_path('reports/connector-configuration-inventory.json', root=ROOT)).read_text(
                encoding="utf-8"
            ),
        )

    def test_local_plugin_package_matches_module_suffix(self) -> None:
        module = re.search(
            r"(?m)^module\s+([^\s]+)\s*$",
            (PLUGIN / "go.mod").read_text(encoding="utf-8"),
        )
        package = re.search(
            r"(?m)^package\s+([A-Za-z_][A-Za-z0-9_]*)\s*$",
            (PLUGIN / "middleware.go").read_text(encoding="utf-8"),
        )
        self.assertIsNotNone(module)
        self.assertIsNotNone(package)
        assert module is not None
        assert package is not None
        self.assertEqual(module.group(1).rsplit("/", 1)[-1], package.group(1))

    def test_native_host_runner_stages_plugin_and_refuses_promotion(self) -> None:
        source = (
            source_path('connectors/traefik/scripts/runtime_native_smoke.py', root=ROOT)
        ).read_text(encoding="utf-8")
        self.assertIn('"plugins-local/src"', source)
        self.assertIn('"rule_evaluation": "host_runtime_observed_not_promoted"', source)
        self.assertNotIn('"rule_evaluation": "not_wired"', source)
        self.assertIn('"capability_promotion": "not_permitted"', source)
        self.assertIn('"integration_mode": "native-traefik-middleware"', source)
        self.assertIn('rule: "PathPrefix(`/`)"', source)

    def test_native_host_runner_uses_a_short_private_uds_root(self) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn("tempfile.mkdtemp", source)
        self.assertIn("TRAEFIK_ENGINE_SOCKET_PARENT", source)
        self.assertIn("resolve_engine_socket_parent", source)
        self.assertNotIn('dir="/var/tmp"', source)
        self.assertNotIn("ENGINE_SOCKET_FALLBACK_ALLOCATION_ROOT", source)
        self.assertNotIn("TMPDIR", source)
        self.assertIn("ENGINE_SOCKET_PATH_MAX_BYTES", source)
        self.assertIn("def start_native_runtime_setup(", source)
        self.assertIn("create_private_engine_socket_dir(inputs.engine_socket_parent)", source)
        self.assertIn('"host_runtime_cleanup_incomplete"', source)
        self.assertIn("DirectoryIdentity", source)

    def test_engine_socket_parent_resolution_requires_explicit_private_input(self) -> None:
        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-test-") as temporary:
            root = Path(temporary)
            explicit = root / "explicit"
            explicit.mkdir(mode=0o700)
            with mock.patch.dict(
                os.environ,
                {runner.ENGINE_SOCKET_PARENT_ENV: str(explicit)},
                clear=False,
            ):
                selected = runner.resolve_engine_socket_parent()
                self.assertEqual(selected.path, explicit)
            with mock.patch.dict(
                os.environ,
                {
                    runner.ENGINE_SOCKET_PARENT_ENV: "",
                    "TMPDIR": str(explicit),
                },
                clear=False,
            ):
                with self.assertRaisesRegex(runner.MissingDependency, "TRAEFIK_ENGINE_SOCKET_PARENT"):
                    runner.resolve_engine_socket_parent()

    def test_engine_socket_parent_rejects_unsafe_explicit_values(self) -> None:
        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-test-") as temporary:
            root = Path(temporary)
            private = root / "private"
            private.mkdir(mode=0o700)
            nonprivate = root / "nonprivate"
            nonprivate.mkdir(mode=0o700)
            symlink = root / "symlink"
            symlink.symlink_to(private, target_is_directory=True)
            regular = root / "regular"
            regular.write_text("not a directory", encoding="utf-8")
            for candidate, reason in (
                (Path("relative"), "absolute"),
                (Path(os.sep), "too broad"),
                (ROOT, "outside checkout"),
                (symlink, "symlink"),
                (regular, "directory"),
            ):
                with self.subTest(candidate=candidate):
                    with self.assertRaisesRegex(runner.MissingDependency, reason):
                        runner.assert_private_engine_socket_parent(candidate, "test parent")
            with mock.patch.object(
                runner.stat,
                "S_IMODE",
                return_value=stat.S_IRUSR | stat.S_IXUSR,
            ):
                with self.assertRaisesRegex(runner.MissingDependency, "private"):
                    runner.assert_private_engine_socket_parent(nonprivate, "test parent")

    def test_native_runtime_root_requires_an_owner_controlled_ancestor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-test-") as temporary:
            root = Path(temporary)
            safe_parent = root / "safe"
            safe_parent.mkdir(mode=0o700)
            safe_parent.chmod(0o700)
            selected = safe_parent / "nested" / "runtime"
            self.assertEqual(runner.assert_runtime_root(selected), selected)

            replaceable_parent = root / "replaceable"
            replaceable_parent.mkdir(mode=0o777)
            replaceable_parent.chmod(0o777)
            with self.assertRaisesRegex(runner.MissingDependency, "must not be group or world writable"):
                runner.assert_runtime_root(replaceable_parent / "runtime")

            root_alias = root / "safe-alias"
            root_alias.symlink_to(safe_parent, target_is_directory=True)
            with self.assertRaisesRegex(runner.MissingDependency, "symlink"):
                runner.assert_runtime_root(root_alias / "runtime")

    def test_native_runtime_root_rejects_shared_temporary_directories_through_permissions(self) -> None:
        for shared_root in (Path("/tmp"), Path("/var/tmp")):
            with self.subTest(shared_root=shared_root):
                with self.assertRaisesRegex(
                    runner.MissingDependency, "must not be group or world writable"
                ):
                    runner.assert_runtime_root(shared_root)

    def make_staged_runtime_workspace(
        self, temporary_root: Path
    ) -> tuple[object, object, dict[str, Path]]:
        """Create the owned temporary inputs plus retained runtime evidence."""

        runtime_root = temporary_root / "runtime-root"
        runtime_root.mkdir(mode=0o700)
        socket_parent = temporary_root / "socket-parent"
        socket_parent.mkdir(mode=0o700)
        workspaces: dict[str, Path] = {}
        for name in ("plugins-local", "effective-config", "engine-build"):
            workspace = runtime_root / name
            workspace.mkdir(mode=0o700)
            (workspace / "owned-marker").write_text(name, encoding="utf-8")
            workspaces[name] = workspace

        logs_dir = runtime_root / "logs"
        logs_dir.mkdir(mode=0o700)
        event_path = logs_dir / "events.jsonl"
        event_path.write_text('{"event":"host-runtime"}\n', encoding="utf-8")
        result_path = runtime_root / "result.json"
        result_path.write_text('{"status":"PASS"}\n', encoding="utf-8")
        observations_path = runtime_root / "transport-observations.diagnostic.json"
        observations_path.write_text('{"cleanup":"pending"}\n', encoding="utf-8")
        retained = runtime_root / "retained-unrelated"
        retained.mkdir(mode=0o700)
        (retained / "marker").write_text("retain", encoding="utf-8")
        nested = runtime_root / "nested"
        nested.mkdir(mode=0o700)
        nested_workspace = nested / "plugins-local"
        nested_workspace.mkdir(mode=0o700)
        (nested_workspace / "marker").write_text("not a direct child", encoding="utf-8")

        effective_config = workspaces["effective-config"]
        static_config = effective_config / "traefik-static.yaml"
        dynamic_config = effective_config / "traefik-dynamic.yaml"
        engine_config = effective_config / "engine.conf"
        for config in (static_config, dynamic_config, engine_config):
            config.write_text("generated\n", encoding="utf-8")
        rules_file = temporary_root / "rules.conf"
        rules_file.write_text("SecRuleEngine On\n", encoding="utf-8")
        inputs = runner.NativeRuntimeInputs(
            runtime_root=runtime_root,
            engine_socket_parent=engine_socket_parent(socket_parent),
            run_id=None,
            first_byte_output=None,
            binary=Path("/bin/true"),
            include_dir=temporary_root,
            library_dir=temporary_root,
            rules_file=rules_file,
            rule_ids={},
            rules_profile="test",
            module_name="test-plugin",
        )
        artifacts = runner.NativeRuntimeArtifacts(
            logs_dir=logs_dir,
            result_path=result_path,
            transport_observations_path=observations_path,
            static_config=static_config,
            dynamic_config=dynamic_config,
            engine_config=engine_config,
            event_path=event_path,
        )
        return inputs, artifacts, {
            **workspaces,
            "event_path": event_path,
            "nested_workspace": nested_workspace,
            "observations_path": observations_path,
            "result_path": result_path,
            "retained": retained,
        }

    def test_readonly_plugin_source_stages_private_copy_and_cleans_it_safely(self) -> None:
        with tempfile.TemporaryDirectory(prefix="traefik-readonly-stage-") as temporary:
            root = Path(temporary)
            source = root / "sealed-plugin"
            source.mkdir(mode=0o700)
            (source / "nested").mkdir(mode=0o700)
            files = {
                "go.mod": "module example.test/native_middleware\n",
                "middleware.go": "package native_middleware\n",
                "engine_uds.go": "package native_middleware\n",
                ".traefik.yml": "import: example.test/native_middleware\n",
                "nested/marker": "sealed source remains unchanged\n",
            }
            for relative, content in files.items():
                (source / relative).write_text(content, encoding="utf-8")
                (source / relative).chmod(0o444)
            (source / "nested").chmod(0o555)
            source.chmod(0o555)
            inputs = SimpleNamespace(
                runtime_root=root / "runtime",
                module_name=runner.read_plugin_module(source),
            )
            try:
                with mock.patch.object(runner, "PLUGIN_SOURCE", source):
                    artifacts = runner.stage_native_runtime(inputs)
                workspace = inputs.runtime_root / "plugins-local"
                for candidate in (workspace, *workspace.rglob("*")):
                    expected = 0o700 if candidate.is_dir() else 0o600
                    self.assertEqual(stat.S_IMODE(candidate.stat().st_mode), expected)
                artifacts.event_path.write_text("host evidence\n", encoding="utf-8")
                self.assertTrue(runner.cleanup_staged_runtime_workspaces(inputs, artifacts))
                self.assertFalse(workspace.exists())
                self.assertEqual(artifacts.event_path.read_text(), "host evidence\n")
                self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o555)
                self.assertEqual(stat.S_IMODE((source / "nested").stat().st_mode), 0o555)
                for relative, content in files.items():
                    self.assertEqual((source / relative).read_text(), content)
                    self.assertEqual(stat.S_IMODE((source / relative).stat().st_mode), 0o444)
            finally:
                # Restore only this test's owned copies for temporary cleanup,
                # including the intentionally failing pre-fix execution.
                for candidate in (root, *root.rglob("*")):
                    candidate.chmod(0o700 if candidate.is_dir() else 0o600)

    def test_staged_workspace_cleanup_removes_only_owned_directories_and_keeps_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-cleanup-") as temporary:
            inputs, artifacts, paths = self.make_staged_runtime_workspace(Path(temporary))

            self.assertTrue(runner.cleanup_staged_runtime_workspaces(inputs, artifacts))

            for name in ("plugins-local", "effective-config", "engine-build"):
                self.assertFalse(paths[name].exists(), name)
            self.assertEqual(paths["event_path"].read_text(encoding="utf-8"), '{"event":"host-runtime"}\n')
            self.assertEqual(paths["result_path"].read_text(encoding="utf-8"), '{"status":"PASS"}\n')
            self.assertEqual(
                paths["observations_path"].read_text(encoding="utf-8"),
                '{"cleanup":"pending"}\n',
            )
            self.assertTrue(paths["retained"].is_dir())
            self.assertTrue(paths["nested_workspace"].is_dir())

    def test_staged_workspace_cleanup_refuses_symlinked_owned_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-cleanup-") as temporary:
            root = Path(temporary)
            inputs, artifacts, paths = self.make_staged_runtime_workspace(root)
            plugin_workspace = paths["plugins-local"]
            (plugin_workspace / "owned-marker").unlink()
            plugin_workspace.rmdir()
            foreign = root / "foreign-workspace"
            foreign.mkdir(mode=0o700)
            sentinel = foreign / "must-not-delete"
            sentinel.write_text("foreign", encoding="utf-8")
            plugin_workspace.symlink_to(foreign, target_is_directory=True)

            self.assertFalse(runner.cleanup_staged_runtime_workspaces(inputs, artifacts))

            self.assertTrue(plugin_workspace.is_symlink())
            self.assertTrue(sentinel.is_file())
            self.assertTrue(paths["effective-config"].is_dir())
            self.assertTrue(paths["engine-build"].is_dir())

    def test_staged_workspace_cleanup_refuses_runtime_root_replaced_by_outside_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-cleanup-") as temporary:
            root = Path(temporary)
            inputs, artifacts, paths = self.make_staged_runtime_workspace(root)
            original_runtime_root = root / "original-runtime-root"
            inputs.runtime_root.rename(original_runtime_root)
            outside = root / "outside-runtime-root"
            outside.mkdir(mode=0o700)
            outside_workspace = outside / "plugins-local"
            outside_workspace.mkdir(mode=0o700)
            sentinel = outside_workspace / "must-not-delete"
            sentinel.write_text("foreign", encoding="utf-8")
            inputs.runtime_root.symlink_to(outside, target_is_directory=True)

            self.assertFalse(runner.cleanup_staged_runtime_workspaces(inputs, artifacts))

            self.assertTrue(sentinel.is_file())
            self.assertTrue((original_runtime_root / "plugins-local").is_dir())
            self.assertTrue((original_runtime_root / "logs" / "events.jsonl").is_file())

    def test_staged_workspace_cleanup_refuses_nonprivate_runtime_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-cleanup-") as temporary:
            inputs, artifacts, paths = self.make_staged_runtime_workspace(Path(temporary))
            inputs.runtime_root.chmod(0o755)

            self.assertFalse(runner.cleanup_staged_runtime_workspaces(inputs, artifacts))

            self.assertTrue(paths["plugins-local"].is_dir())
            self.assertTrue(paths["effective-config"].is_dir())
            self.assertTrue(paths["engine-build"].is_dir())

    def test_write_json_refuses_result_symlink_without_touching_external_sentinel(self) -> None:
        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-json-") as temporary:
            root = Path(temporary)
            output_parent = root / "runtime"
            output_parent.mkdir(mode=0o700)
            sentinel = root / "external-sentinel.json"
            sentinel.write_text('{"must":"remain"}\n', encoding="utf-8")
            result_path = output_parent / "result.json"
            result_path.symlink_to(sentinel)

            with self.assertRaisesRegex(runner.MissingDependency, "artifact path is unsafe"):
                runner.write_json(result_path, {"status": "PASS"})

            self.assertTrue(result_path.is_symlink())
            self.assertEqual(sentinel.read_text(encoding="utf-8"), '{"must":"remain"}\n')

    def test_write_json_atomically_replaces_regular_result_with_private_valid_json(self) -> None:
        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-json-") as temporary:
            root = Path(temporary)
            output_parent = root / "runtime"
            output_parent.mkdir(mode=0o700)
            result_path = output_parent / "result.json"
            result_path.write_text('{"old":true}\n', encoding="utf-8")
            result_path.chmod(0o644)
            previous_inode = result_path.lstat().st_ino
            payload = {"status": "PASS", "transaction": "traefik-json-unit"}

            runner.write_json(result_path, payload)

            result_stat = result_path.lstat()
            self.assertTrue(stat.S_ISREG(result_stat.st_mode))
            self.assertFalse(result_path.is_symlink())
            self.assertNotEqual(result_stat.st_ino, previous_inode)
            self.assertEqual(stat.S_IMODE(result_stat.st_mode), 0o600)
            self.assertEqual(json.loads(result_path.read_text(encoding="utf-8")), payload)
            self.assertEqual([entry.name for entry in output_parent.iterdir()], ["result.json"])

    def test_write_json_refuses_symlinked_parent_without_touching_external_result(self) -> None:
        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-json-") as temporary:
            root = Path(temporary)
            external_parent = root / "external-runtime"
            external_parent.mkdir(mode=0o700)
            sentinel = external_parent / "result.json"
            sentinel.write_text('{"must":"remain"}\n', encoding="utf-8")
            output_parent = root / "runtime-alias"
            output_parent.symlink_to(external_parent, target_is_directory=True)

            with self.assertRaisesRegex(runner.MissingDependency, "contains a symlink"):
                runner.write_json(output_parent / "result.json", {"status": "PASS"})

            self.assertTrue(output_parent.is_symlink())
            self.assertEqual(sentinel.read_text(encoding="utf-8"), '{"must":"remain"}\n')

    def collect_full_lifecycle_inputs(
        self,
        temporary_root: Path,
        evidence_root: Path | None,
        evidence_output: Path | None,
    ) -> object:
        """Collect inputs while leaving first-byte path validation unmocked."""

        runtime_root = temporary_root / "traefik-runtime"
        socket_parent = temporary_root / "socket-parent"
        socket_parent.mkdir(mode=0o700)
        environment = {
            "MSCONNECTOR_CRS_RUNTIME": "0",
            "NO_CRS_ARTIFACT_PROFILE": "full_lifecycle",
            "TRAEFIK_BIN": "/bin/true",
            "TRAEFIK_NATIVE_RUNTIME_ROOT": str(runtime_root),
        }
        if evidence_root is not None:
            environment["TRAEFIK_FIRST_BYTE_EVIDENCE_ROOT"] = str(evidence_root)
        if evidence_output is not None:
            environment["FULL_LIFECYCLE_EVIDENCE_OUTPUT"] = str(evidence_output)
        with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(
            runner, "resolve_engine_socket_parent", return_value=engine_socket_parent(socket_parent)
        ), mock.patch.object(
            runner, "require_local_executable", return_value=Path("/bin/true")
        ), mock.patch.object(
            runner, "require_modsecurity_environment", return_value=(temporary_root, temporary_root)
        ), mock.patch.object(
            runner, "select_engine_rules", return_value=(temporary_root / "rules.conf", {}, "test")
        ), mock.patch.object(runner, "require_engine_inputs"), mock.patch.object(
            runner, "read_plugin_module", return_value="test-plugin"
        ):
            return runner.collect_native_runtime_inputs()

    def test_full_lifecycle_first_byte_output_requires_a_declared_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-first-byte-") as temporary:
            root = Path(temporary)
            output = root / "first-byte-evidence.json"

            with self.assertRaisesRegex(runner.MissingDependency, "TRAEFIK_FIRST_BYTE_EVIDENCE_ROOT"):
                self.collect_full_lifecycle_inputs(root, None, output)

    def test_full_lifecycle_first_byte_output_rejects_regular_file_outside_declared_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-first-byte-") as temporary:
            root = Path(temporary)
            evidence_root = root / "evidence-root"
            evidence_root.mkdir(mode=0o700)
            outside = root / "outside"
            outside.mkdir(mode=0o700)
            output = outside / "first-byte-evidence.json"
            output.write_text('{"must":"remain"}\n', encoding="utf-8")

            with self.assertRaises(runner.MissingDependency):
                self.collect_full_lifecycle_inputs(root, evidence_root, output)

            self.assertEqual(output.read_text(encoding="utf-8"), '{"must":"remain"}\n')

    def test_full_lifecycle_first_byte_output_rejects_noncanonical_name(self) -> None:
        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-first-byte-") as temporary:
            root = Path(temporary)
            evidence_root = root / "evidence-root"
            evidence_root.mkdir(mode=0o700)
            output = evidence_root / "unexpected-evidence.json"
            output.write_text('{"must":"remain"}\n', encoding="utf-8")

            with self.assertRaises(runner.MissingDependency):
                self.collect_full_lifecycle_inputs(root, evidence_root, output)

            self.assertEqual(output.read_text(encoding="utf-8"), '{"must":"remain"}\n')

    def test_full_lifecycle_first_byte_output_rejects_nested_fixed_name(self) -> None:
        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-first-byte-") as temporary:
            root = Path(temporary)
            evidence_root = root / "evidence-root"
            evidence_root.mkdir(mode=0o700)
            nested = evidence_root / "nested"
            nested.mkdir(mode=0o700)

            with self.assertRaises(runner.MissingDependency):
                self.collect_full_lifecycle_inputs(
                    root, evidence_root, nested / "first-byte-evidence.json"
                )

    def test_full_lifecycle_first_byte_output_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-first-byte-") as temporary:
            root = Path(temporary)
            evidence_root = root / "evidence-root"
            evidence_root.mkdir(mode=0o700)
            sentinel = root / "external-sentinel.json"
            sentinel.write_text('{"must":"remain"}\n', encoding="utf-8")
            output = evidence_root / "first-byte-evidence.json"
            output.symlink_to(sentinel)

            with self.assertRaises(runner.MissingDependency):
                self.collect_full_lifecycle_inputs(root, evidence_root, output)

            self.assertTrue(output.is_symlink())
            self.assertEqual(sentinel.read_text(encoding="utf-8"), '{"must":"remain"}\n')

    def test_full_lifecycle_first_byte_output_accepts_only_fixed_direct_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-first-byte-") as temporary:
            root = Path(temporary)
            evidence_root = root / "evidence-root"
            evidence_root.mkdir(mode=0o700)
            output = evidence_root / "first-byte-evidence.json"

            inputs = self.collect_full_lifecycle_inputs(root, evidence_root, output)

            self.assertEqual(inputs.first_byte_output, output)

    def test_engine_socket_parent_ancestor_requires_no_cross_user_replacement(self) -> None:
        owned_child = SimpleNamespace(
            st_mode=stat.S_IFDIR | stat.S_IRWXU,
            st_uid=os.geteuid(),
        )
        mutable_ancestor = SimpleNamespace(
            st_mode=stat.S_IFDIR | stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO,
            st_uid=os.geteuid(),
        )
        sticky_ancestor = SimpleNamespace(
            st_mode=mutable_ancestor.st_mode | stat.S_ISVTX,
            st_uid=os.geteuid(),
        )
        self.assertFalse(
            runner.directory_entry_is_protected_from_cross_user_replacement(
                mutable_ancestor, owned_child
            )
        )
        self.assertTrue(
            runner.directory_entry_is_protected_from_cross_user_replacement(
                sticky_ancestor, owned_child
            )
        )

    def test_engine_socket_parent_rejects_control_characters_and_yaml_quotes_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-test-") as temporary:
            root = Path(temporary)
            control_parent = root / "private\ninjection"
            control_parent.mkdir(mode=0o700)
            with mock.patch.dict(
                os.environ,
                {runner.ENGINE_SOCKET_PARENT_ENV: str(control_parent)},
                clear=False,
            ):
                with self.assertRaisesRegex(runner.MissingDependency, "control characters"):
                    runner.resolve_engine_socket_parent()

            dynamic_config = root / "dynamic.yaml"
            unusual_socket = root / "socket: # value" / "engine.sock"
            runner.write_dynamic_config(dynamic_config, 18080, unusual_socket)
            self.assertIn(
                f"engineSocketPath: {json.dumps(str(unusual_socket))}",
                dynamic_config.read_text(encoding="utf-8"),
            )

    @mock.patch.object(runner, "ENGINE_SOCKET_PATH_MAX_BYTES", 1000)
    def test_engine_socket_child_is_private_short_and_cleanup_keeps_parent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-test-") as temporary:
            parent = Path(temporary)
            selected_parent = engine_socket_parent(parent)
            child = runner.create_private_engine_socket_dir(selected_parent)
            self.assertEqual(child.path.parent, parent)
            self.assertTrue(child.path.name.startswith(runner.ENGINE_SOCKET_DIRECTORY_PREFIX))
            self.assertEqual(child.path.stat().st_mode & 0o777, 0o700)
            self.assertLessEqual(
                len(os.fsencode(str(child.path / "engine.sock"))), runner.ENGINE_SOCKET_PATH_MAX_BYTES
            )
            self.assertTrue(runner.remove_private_engine_socket_dir(child, selected_parent))
            self.assertFalse(child.path.exists())
            self.assertTrue(parent.is_dir())

    @mock.patch.object(runner, "ENGINE_SOCKET_PATH_MAX_BYTES", 1000)
    def test_engine_socket_children_allocate_without_collision_for_parallel_runs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-test-") as temporary:
            parent = Path(temporary)
            selected_parent = engine_socket_parent(parent)
            barrier = threading.Barrier(2)

            def allocate_child() -> object:
                barrier.wait(timeout=5)
                return runner.create_private_engine_socket_dir(selected_parent)

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                first_future = executor.submit(allocate_child)
                second_future = executor.submit(allocate_child)
                first = first_future.result(timeout=5)
                second = second_future.result(timeout=5)
            try:
                self.assertNotEqual(first.path, second.path)
                self.assertTrue(first.path.is_dir())
                self.assertTrue(second.path.is_dir())
                self.assertEqual(first.path.parent, parent)
                self.assertEqual(second.path.parent, parent)
            finally:
                self.assertTrue(runner.remove_private_engine_socket_dir(first, selected_parent))
                self.assertTrue(runner.remove_private_engine_socket_dir(second, selected_parent))

    @mock.patch.object(runner, "ENGINE_SOCKET_PATH_MAX_BYTES", 1000)
    def test_engine_socket_child_preserves_an_existing_foreign_socket(self) -> None:
        with short_socket_temporary_directory() as temporary:
            parent = Path(temporary)
            selected_parent = engine_socket_parent(parent)
            foreign_child = runner.create_private_engine_socket_dir(selected_parent)
            foreign_socket = foreign_child.path / "engine.sock"
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                server.bind(os.fspath(foreign_socket))
                next_child = runner.create_private_engine_socket_dir(selected_parent)
                try:
                    self.assertNotEqual(next_child, foreign_child)
                    self.assertTrue(foreign_socket.exists())
                    self.assertFalse((next_child.path / "engine.sock").exists())
                finally:
                    self.assertTrue(
                        runner.remove_private_engine_socket_dir(
                            next_child, selected_parent
                        )
                    )
            finally:
                server.close()
                self.assertFalse(
                    runner.remove_private_engine_socket_dir(foreign_child, selected_parent)
                )
                self.assertTrue(foreign_socket.exists())
                foreign_socket.unlink()
                self.assertTrue(
                    runner.remove_private_engine_socket_dir(foreign_child, selected_parent)
                )

    @mock.patch.object(runner, "ENGINE_SOCKET_PATH_MAX_BYTES", 1000)
    def test_engine_socket_cleanup_refuses_replaced_child(self) -> None:
        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-test-") as temporary:
            root = Path(temporary)
            selected_parent = engine_socket_parent(root)
            child = runner.create_private_engine_socket_dir(selected_parent)
            child.path.rmdir()
            child.path.mkdir(mode=0o700)
            self.assertFalse(runner.remove_private_engine_socket_dir(child, selected_parent))
            self.assertTrue(child.path.exists())
            child.path.rmdir()

    def test_engine_socket_setup_failure_removes_the_allocated_child(self) -> None:
        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-test-") as temporary:
            root = Path(temporary)
            runtime_root = root / "runtime"
            parent_path = root / "socket-parent"
            parent_path.mkdir(mode=0o700)
            selected_parent = engine_socket_parent(parent_path)
            with mock.patch.dict(
                os.environ,
                {"TRAEFIK_NATIVE_RUNTIME_ROOT": str(runtime_root), "TRAEFIK_BIN": "/bin/true"},
                clear=False,
            ), mock.patch.object(runner, "assert_runtime_root", return_value=runtime_root), mock.patch.object(
                runner, "require_local_executable", return_value=Path("/bin/true")
            ), mock.patch.object(
                runner, "require_modsecurity_environment", return_value=(root, root)
            ), mock.patch.object(
                runner, "select_engine_rules", return_value=(root / "rules", {}, "test")
            ), mock.patch.object(
                runner, "require_engine_inputs"
            ), mock.patch.object(
                runner, "read_plugin_module", return_value="test-plugin"
            ), mock.patch.object(
                runner, "resolve_engine_socket_parent", return_value=selected_parent
            ), mock.patch.object(
                runner, "free_port", side_effect=RuntimeError("injected setup failure")
            ), mock.patch.object(
                runner, "ENGINE_SOCKET_PATH_MAX_BYTES", 1000
            ):
                with self.assertRaisesRegex(RuntimeError, "injected setup failure"):
                    runner.run()
            self.assertEqual(list(parent_path.iterdir()), [])
            for name in ("plugins-local", "effective-config", "engine-build"):
                self.assertFalse((runtime_root / name).exists(), name)

    def test_missing_engine_socket_parent_fails_before_runtime_root_setup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-test-") as temporary:
            temporary_root = Path(temporary)
            runtime_root = temporary_root / "runtime"
            inherited_tmpdir = temporary_root / "valid-inherited-tmpdir"
            inherited_tmpdir.mkdir(mode=0o700)
            with mock.patch.dict(
                os.environ,
                {
                    "TRAEFIK_NATIVE_RUNTIME_ROOT": str(runtime_root),
                    runner.ENGINE_SOCKET_PARENT_ENV: "",
                    "TMPDIR": str(inherited_tmpdir),
                },
                clear=False,
            ):
                with self.assertRaisesRegex(
                    runner.MissingDependency, "TRAEFIK_ENGINE_SOCKET_PARENT"
                ):
                    runner.run()
            self.assertFalse(runtime_root.exists())

    def test_engine_socket_parent_length_is_checked_before_child_allocation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-test-") as temporary:
            parent = Path(temporary) / ("x" * 90)
            parent.mkdir(mode=0o700)
            with self.assertRaisesRegex(runner.MissingDependency, "too long"):
                runner.assert_engine_socket_path_length(parent)

    def test_engine_service_runtime_test_uses_a_short_private_uds_root(self) -> None:
        source = (
            source_path('connectors/traefik/build/test-engine-service-runtime.sh', root=ROOT)
        ).read_text(encoding="utf-8")
        self.assertIn('SOCKET_PARENT="${TRAEFIK_ENGINE_SOCKET_TEST_PARENT:-}"', source)
        self.assertIn('must name an existing private 0700 directory', source)
        self.assertIn('protected from cross-user ancestor replacement', source)
        self.assertIn('os.path.realpath(candidate)', source)
        self.assertIn('stat.S_ISVTX', source)
        self.assertIn('mktemp -d "$SOCKET_PARENT"/msconnector-traefik-engine-test.XXXXXX', source)
        self.assertIn('SOCKET_PATH="$SOCKET_DIR/engine.sock"', source)
        self.assertIn('[ "${#SOCKET_PATH}" -le 100 ]', source)
        self.assertIn('rmdir "$SOCKET_DIR"', source)
        self.assertIn("replacement-sentinel", source)
        self.assertNotIn('rm -f "$SOCKET_PATH"', source)

    def test_engine_service_binds_cleanup_to_the_created_socket_identity(self) -> None:
        source = (
            source_path('connectors/traefik/src/traefik_engine_service.c', root=ROOT)
        ).read_text(encoding="utf-8")
        self.assertIn("traefik_engine_socket_identity", source)
        self.assertIn("traefik_engine_capture_bound_socket_identity", source)
        self.assertIn("traefik_engine_remove_owned_socket", source)
        self.assertIn("traefik_engine_listener_accepts_self_probe", source)
        self.assertIn("SO_PEERCRED", source)
        self.assertIn("traefik_engine_listener_post_bind_hook", source)
        self.assertIn("traefik_engine_listener_post_probe_hook", source)
        self.assertIn("traefik_engine_private_directory_is_safe", source)
        self.assertIn("traefik_engine_socket_parent_is_safe", source)
        self.assertNotIn("umask(", source)
        listener_source = source[
            source.index("static int traefik_engine_create_listener") : source.index(
                "static void traefik_engine_shutdown_active_workers_locked"
            )
        ]
        serve_source = source[
            source.index("static int traefik_engine_serve") : source.index(
                "static int traefik_engine_self_test_append_u16"
            )
        ]
        self.assertNotIn("(void)unlink(socket_path);", listener_source)
        self.assertNotIn("(void)unlink(socket_path);", serve_source)

    def test_engine_service_bounds_active_admission_without_lifetime_shutdown(self) -> None:
        source = (
            source_path('connectors/traefik/src/traefik_engine_service.c', root=ROOT)
        ).read_text(encoding="utf-8")
        self.assertIn("TRAEFIK_ENGINE_DEFAULT_MAX_WORKERS 64U", source)
        self.assertIn("TRAEFIK_ENGINE_HARD_MAX_WORKERS 256U", source)
        self.assertIn("service->worker_count >= service->max_workers", source)
        self.assertIn("TRAEFIK_ENGINE_WORKER_CAPACITY", source)
        self.assertIn(
            "worker_result == TRAEFIK_ENGINE_WORKER_CAPACITY", source
        )
        self.assertIn("if (max_connections != 0U &&", source)
        self.assertIn("if (max_connections != 0U) {\n            ++*accepted_connections;", source)
        self.assertNotIn("TRAEFIK_ENGINE_DEFAULT_MAX_CONNECTIONS", source)
        self.assertNotIn("max_connections = TRAEFIK_ENGINE_DEFAULT_MAX_CONNECTIONS", source)

    def test_crs_requests_send_the_canonical_framework_run_id(self) -> None:
        """The normalizer may only report a run ID that the host received."""

        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-crs-") as temporary:
            root = Path(temporary)
            logs = root / "logs"
            logs.mkdir()
            inputs = SimpleNamespace(
                rules_profile="framework-crs-v4.29.0",
                runtime_root=root,
                include_dir=root,
                library_dir=root,
                binary=root / "traefik",
                run_id="traefik-crs-run-42",
            )
            artifacts = SimpleNamespace(
                logs_dir=logs,
                engine_config=root / "engine.conf",
                event_path=logs / "events.jsonl",
                static_config=root / "traefik.yaml",
            )
            setup = SimpleNamespace(engine_socket=root / "engine.sock", traefik_port=18443)
            processes = runner.NativeProcesses()
            live_process = SimpleNamespace(poll=lambda: None, returncode=None)
            observed_headers: dict[str, dict[str, str] | None] = {}

            def request(
                _port: int,
                _body: bytes,
                request_id: str,
                expected_status: int,
                extra_headers: dict[str, str] | None = None,
                **_kwargs: object,
            ) -> tuple[int, int]:
                observed_headers[request_id] = extra_headers
                return expected_status, 1

            with mock.patch.object(runner, "build_engine_service", return_value=root / "engine"), mock.patch.object(
                runner, "wait_for_socket"
            ), mock.patch.object(runner, "wait_for_port"), mock.patch.object(
                runner.subprocess, "Popen", side_effect=(live_process, live_process)
            ), mock.patch.object(runner, "request_through_traefik", side_effect=request):
                results = runner.run_crs_requests(inputs, artifacts, setup, processes)

            self.assertEqual(results.allow_status, 200)
            self.assertEqual(results.block_status, 403)
            self.assertEqual(results.bypass_status, 403)
            for request_id in (
                results.request_ids.allow,
                results.request_ids.block,
                results.request_ids.bypass,
            ):
                self.assertEqual(observed_headers[request_id]["X-Framework-Run-ID"], inputs.run_id)

    def test_running_traefik_host_preserves_owned_processes_and_diagnostics(self) -> None:
        """Both runtime profiles share startup without changing process ownership."""

        with tempfile.TemporaryDirectory(prefix="msconnector-traefik-host-") as temporary:
            root = Path(temporary)
            logs = root / "logs"
            logs.mkdir()
            inputs = SimpleNamespace(
                runtime_root=root,
                include_dir=root,
                library_dir=root,
                binary=root / "traefik",
            )
            artifacts = SimpleNamespace(
                logs_dir=logs,
                engine_config=root / "engine.conf",
                static_config=root / "traefik.yaml",
            )
            setup = SimpleNamespace(engine_socket=root / "engine.sock", traefik_port=18443)
            processes = runner.NativeProcesses()
            engine_process = object()
            traefik_process = object()

            with mock.patch.object(
                runner, "build_engine_service", return_value=root / "engine"
            ), mock.patch.object(runner, "wait_for_socket") as wait_for_socket, mock.patch.object(
                runner, "wait_for_port"
            ) as wait_for_port, mock.patch.object(
                runner.subprocess, "Popen", side_effect=(engine_process, traefik_process)
            ) as popen:
                with runner.running_traefik_host(
                    inputs,
                    artifacts,
                    setup,
                    processes,
                    engine_description="persistent test engine",
                    host_description="test Traefik host",
                ):
                    self.assertIs(processes.engine, engine_process)
                    self.assertIs(processes.traefik, traefik_process)

            wait_for_socket.assert_called_once_with(
                setup.engine_socket, engine_process, "persistent test engine"
            )
            wait_for_port.assert_called_once_with(setup.traefik_port, traefik_process, "test Traefik host")
            self.assertEqual(popen.call_count, 2)
            self.assertEqual(popen.call_args_list[0].kwargs["cwd"], root)
            self.assertEqual(
                popen.call_args_list[1].args[0], [str(inputs.binary), f"--configFile={artifacts.static_config}"]
            )

    def test_crs_transaction_ids_are_not_reused_across_run_ids(self) -> None:
        first = runner.crs_request_ids("traefik-crs-run-one")
        second = runner.crs_request_ids("traefik-crs-run-two")

        self.assertEqual(len({first.allow, first.block, first.bypass}), 3)
        self.assertEqual(len({second.allow, second.block, second.bypass}), 3)
        self.assertFalse({first.allow, first.block, first.bypass} & {second.allow, second.block, second.bypass})
        self.assertIn("traefik-crs-run-one", first.allow)
        self.assertIn("traefik-crs-run-two", second.allow)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
