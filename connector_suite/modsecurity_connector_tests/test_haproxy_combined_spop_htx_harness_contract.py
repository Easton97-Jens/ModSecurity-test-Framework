"""Static safety and wiring contracts for the local HAProxy combined harness."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

from pathlib import Path
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = connector_root()
HARNESS = source_path('connectors/haproxy/harness/combined_spop_htx', root=ROOT)
RUNNER = HARNESS / "run_combined_spop_htx.sh"
BACKEND = HARNESS / "backend.py"
P3_RULES = HARNESS / "rules-p3-deny.conf"
P4_RULES = HARNESS / "rules-p4-safe.conf"
MRC1_HEADER = source_path('common/runtime/response_companion_transport.h', root=ROOT)
MRC1_CLIENT = source_path('common/runtime/response_companion_client.c', root=ROOT)
HTX_FILTER = source_path('connectors/haproxy/htx-overlay/haproxy_modsecurity_htx_filter.c', root=ROOT)
PREPARED_PATH = HARNESS / "prepared_artifacts.py"
PREPARED = load_source(PREPARED_PATH)


class PreparedArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        root_patch = mock.patch.object(PREPARED, "SOURCE_ROOT", self.root)
        root_patch.start()
        self.addCleanup(root_patch.stop)
        self.inputs = []
        for relative in ("connectors/profile_registry.c", "connectors/profile_registry.h",
                         "connectors/haproxy/htx-overlay/haproxy_modsecurity_htx_filter.c"):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"production fixture\n")
            self.inputs.append(path)
        self.haproxy = self.root / "haproxy"
        self.spoa = self.root / "spoa"
        self.library = self.root / "library.so"
        for path in (self.haproxy, self.spoa):
            path.write_bytes(b"#!/bin/sh\nexit 0\n")
            path.chmod(0o700)
        self.library.write_bytes(b"library fixture")
        self.manifest = self.root / "provenance.json"
        self.proof = self.root / "equivalence.json"
        self.manifest.write_text(json.dumps({"source_sha": "a" * 40,
            "artifacts": {"haproxy_htx": {"sha256": PREPARED.digest(self.haproxy)},
                          "haproxy_spop": {"sha256": PREPARED.digest(self.spoa)}},
            "library": {"sha256": PREPARED.digest(self.library)}}))
        self.records = {}
        for path in self.inputs:
            data = path.read_bytes()
            self.records[str(path.relative_to(self.root))] = {"type": "blob", "git_object":
                hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data, usedforsecurity=False).hexdigest()}
        self.write_proof()

    def write_proof(self, revision="b" * 40) -> None:
        self.proof.write_text(json.dumps({"artifact_build_sha": "a" * 40,
            "runtime_parent_sha": revision, "production_runtime_inputs_equal": True,
            "file_objects": self.records}))

    def validate(self):
        with mock.patch.object(PREPARED.subprocess, "run", side_effect=[
                subprocess.CompletedProcess([], 0, stdout="b" * 40 + "\n", stderr=""),
                subprocess.CompletedProcess([], 0, stdout="HAProxy version 3.2.25\n", stderr="")]) as run:
            self.process_calls = run
            return PREPARED.validate(self.root, str(self.haproxy), str(self.spoa),
                str(self.manifest), str(self.proof), str(self.library), "3.2.25")

    def test_matching_pair_and_complete_production_proof_is_accepted(self):
        self.assertEqual(self.validate()["verified_production_inputs"], 3)
        self.assertEqual(self.process_calls.call_args_list[0], mock.call(
            ["git", "rev-parse", "HEAD"], cwd=self.root, check=True,
            capture_output=True, text=True, timeout=PREPARED.PROBE_TIMEOUT_SECONDS))
        self.assertEqual(self.process_calls.call_args_list[1].kwargs["timeout"],
                         PREPARED.PROBE_TIMEOUT_SECONDS)

    def test_untrusted_source_roots_fail_before_files_or_processes(self):
        foreign = self.root / "foreign"
        foreign.mkdir()
        alias = self.root / "alias-root"
        alias.symlink_to(self.root, target_is_directory=True)
        inputs = (".", "--help", str(foreign), str(alias),
                  str(alias / "foreign"), str(self.root) + "/./",
                  str(self.root) + "/foreign/..", str(self.root) + "/")
        for root in inputs:
            with self.subTest(root=root), mock.patch.object(PREPARED.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    PREPARED.validate(root, "missing-haproxy", "missing-spoa",
                                      "missing-manifest", "missing-proof", "missing-library", "3.2.25")
                run.assert_not_called()

    def test_source_root_canonical_file_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "own checkout"):
            PREPARED.canonical_source_root(self.library)

    def test_cli_preserves_noncanonical_root_for_rejection(self):
        result = subprocess.run([sys.executable, str(PREPARED_PATH),
            str(ROOT) + "/./", "missing-haproxy", "missing-spoa", "missing-manifest",
            "missing-proof", "missing-library", "3.2.25"], capture_output=True,
            text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("source root must be canonical", result.stderr)

    def test_timed_out_probe_cannot_publish_prepared_artifacts(self):
        timeout = subprocess.TimeoutExpired("prepared probe", PREPARED.PROBE_TIMEOUT_SECONDS)
        revision = subprocess.CompletedProcess([], 0, stdout="b" * 40 + "\n", stderr="")
        for outcomes in ([timeout], [revision, timeout]):
            with self.subTest(probe=len(outcomes)), \
                    mock.patch.object(PREPARED.subprocess, "run", side_effect=outcomes):
                with self.assertRaises(subprocess.TimeoutExpired):
                    PREPARED.validate(self.root, str(self.haproxy), str(self.spoa),
                        str(self.manifest), str(self.proof), str(self.library), "3.2.25")

    def test_modified_artifact_is_rejected(self):
        self.spoa.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "artifact hash"):
            self.validate()

    def test_changed_or_missing_production_input_is_rejected(self):
        self.inputs[0].write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "production input differs"):
            self.validate()
        del self.records[str(self.inputs[0].relative_to(self.root))]
        self.write_proof()
        with self.assertRaisesRegex(ValueError, "omits production inputs"):
            self.validate()

    def test_wrong_runtime_revision_is_rejected(self):
        self.write_proof("c" * 40)
        with self.assertRaisesRegex(ValueError, "revision binding"):
            self.validate()

    def test_changed_library_is_rejected(self):
        self.library.write_bytes(b"changed library")
        with self.assertRaisesRegex(ValueError, "library differs"):
            self.validate()

    def test_missing_source_proof_is_rejected(self):
        with mock.patch.object(PREPARED.subprocess, "run", return_value=
                subprocess.CompletedProcess([], 0, stdout="b" * 40 + "\n", stderr="")), \
                self.assertRaisesRegex(ValueError, "require a production-source"):
            PREPARED.validate(self.root, str(self.haproxy), str(self.spoa),
                str(self.manifest), "", str(self.library), "3.2.25")

    def test_symlink_parent_relative_and_nonexecutable_paths_are_rejected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.haproxy)
        parent_alias = self.root / "parent-alias"
        parent_alias.symlink_to(self.root, target_is_directory=True)
        for path in (str(alias), str(parent_alias / "haproxy"), "haproxy", str(self.library)):
            with self.subTest(path=path), self.assertRaises((ValueError, FileNotFoundError)):
                PREPARED.canonical_file(path, executable=True)

    def test_partial_opt_in_fails_before_runtime_creation(self):
        env = os.environ.copy()
        for key in tuple(env):
            if key.startswith("COMBINED_SPOP_HTX_"):
                del env[key]
        env["COMBINED_SPOP_HTX_PREPARED_HAPROXY_BIN"] = str(self.haproxy)
        result = subprocess.run(["sh", str(RUNNER)], env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 77)
        self.assertIn("COMBINED_SPOP_HTX_PREPARED_SPOA_BIN must be explicitly set", result.stderr)


class HaproxyCombinedSpopHtxHarnessContractTests(unittest.TestCase):
    def run_normal_error_check(self, htx_log: str, spop_log: str):
        runner = RUNNER.read_text(encoding="utf-8")
        body = runner.split("assert_no_unexpected_technical_events() {", 1)[1].split("\n}\n", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "haproxy.stderr.log").write_text(htx_log)
            (root / "decision.jsonl").write_text(spop_log)
            script = 'die() { printf "%s\\n" "$*" >&2; exit 1; }\n'
            script += "assert_no_unexpected_technical_events() {" + body + '\n}\nassert_no_unexpected_technical_events "$1"\n'
            return subprocess.run(["sh", "-s", "--", str(root)], input=script,
                                  text=True, capture_output=True)

    def test_normal_native_rule_decision_is_accepted(self):
        result = self.run_normal_error_check('requested=deny host_action=log_only\n',
                                            '{"event":"rule_intervention"}\n')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_normal_host_or_spop_technical_error_cannot_publish_pass(self):
        for htx, spop in (
                ('[WARNING] {"event":"connector_error"}\n', '{"decision":"pass"}\n'),
                ('host_action=log_only\n', '{ "event" : "protocol_error" }\n')):
            with self.subTest(htx=htx, spop=spop):
                result = self.run_normal_error_check(htx, spop)
                self.assertEqual(result.returncode, 1)
                self.assertIn("unexpected physical connector/protocol error", result.stderr)

    def test_runner_is_shell_syntax_valid(self) -> None:
        result = subprocess.run(
            ["sh", "-n", str(RUNNER)], check=False, capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_current_sources_must_select_mrc1_v2_without_v1_fallback(self) -> None:
        header = MRC1_HEADER.read_text(encoding="utf-8")
        client = MRC1_CLIENT.read_text(encoding="utf-8")
        filter_source = HTX_FILTER.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn(
            "#define MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_PROTOCOL_VERSION 2U",
            header,
        )
        self.assertIn("There is deliberately no v1", header)
        self.assertIn(
            "msconnector_response_companion_client_cancel_with_cause", client
        )
        self.assertIn(
            "msconnector_response_companion_client_cancel_with_cause", filter_source
        )
        self.assertIn("assert_mrc1_v2", runner)
        self.assertIn("MRC1 protocol version 2", runner)

    def test_requires_explicit_external_paths_and_distinct_loopback_ports(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        for name in (
            "COMBINED_SPOP_HTX_RUNTIME_ROOT",
            "COMBINED_SPOP_HTX_ALLOWED_ROOT",
            "COMBINED_SPOP_HTX_HAPROXY_SOURCE_DIR",
            "COMBINED_SPOP_HTX_MODSECURITY_INCLUDE_DIR",
            "COMBINED_SPOP_HTX_MODSECURITY_LIB_DIR",
            "COMBINED_SPOP_HTX_MODSECURITY_LIBRARY",
            "COMBINED_SPOP_HTX_HAPROXY_PORT",
            "COMBINED_SPOP_HTX_SPOA_PORT",
            "COMBINED_SPOP_HTX_BACKEND_PORT",
        ):
            self.assertIn(name, runner)
        self.assertIn("fresh direct child", runner)
        self.assertIn("selected ports must be distinct", runner)
        self.assertIn("bind 127.0.0.1:$HAPROXY_PORT", runner)
        self.assertIn("server app 127.0.0.1:$BACKEND_PORT", runner)
        self.assertIn("server agent 127.0.0.1:$SPOA_PORT", runner)

    def test_private_uds_and_cleanup_are_owned_and_bounded(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn('PRIVATE_ROOT="$RUN_ROOT/private"', runner)
        self.assertIn('chmod 700 "$PRIVATE_ROOT"', runner)
        self.assertIn('SOCKET_PATH="$PRIVATE_ROOT/mrc1-v2.sock"', runner)
        self.assertIn('trap cleanup EXIT', runner)
        self.assertIn('stop_process_group', runner)
        self.assertIn('rm -f -- "$SOCKET_PATH"', runner)
        self.assertNotIn("rm -rf", runner)
        self.assertIn("refusing pre-existing MRC1 socket path", runner)
        self.assertIn("SPOP did not remove the MRC1 socket it owned", runner)

    def test_wires_spoe_request_ack_to_native_htx_mrc1_response_path(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("filter spoe engine modsecurity config", runner)
        self.assertIn("filter modsecurity-htx response-companion-socket", runner)
        self.assertIn("response-companion=native-htx", runner)
        self.assertIn("register-var-names blocked action status redirect_url rule_id phase error response_handle", runner)
        self.assertIn("http-request send-spoe-group modsecurity request-check", runner)
        self.assertIn("phase4-mode safe", runner)
        self.assertNotIn("http-response send-spoe-group", runner)
        self.assertIn("assert_p2_evidence", runner)
        self.assertIn("run_case p3-deny", runner)
        self.assertIn("run_case p4-safe", runner)

    def test_covers_cancel_ttl_missing_correlation_and_connection_reuse(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("run_cancel_case", runner)
        self.assertIn("--max-time 1", runner)
        self.assertIn("cancel_status" , runner)
        self.assertIn("run_ttl_case", runner)
        self.assertIn("write_agent_config \"$case_name\" \"$P4_RULES\" 100", runner)
        self.assertIn("ttl_curl_status", runner)
        self.assertIn("TTL expiry expected curl status 18", runner)
        self.assertIn("fail-closed postcommit response-companion body", runner)
        self.assertIn("missing-correlation", runner)
        self.assertIn("run_connection_reuse_case", runner)
        self.assertIn("same_tcp_connection", runner)
        self.assertIn("Connection: keep-alive", runner)

    def test_backend_never_logs_body_payloads_and_fixture_rules_are_phase_specific(self) -> None:
        backend = BACKEND.read_text(encoding="utf-8")
        p3 = P3_RULES.read_text(encoding="utf-8")
        p4 = P4_RULES.read_text(encoding="utf-8")
        compile(backend, str(BACKEND), "exec")
        self.assertIn("self.rfile.read(content_length)", backend)
        self.assertIn('json.dump({"route": path, "slow": bool(delay_seconds)}, log)', backend)
        self.assertNotIn("request_body", backend)
        self.assertIn("ThreadingHTTPSServer", backend)
        self.assertIn("certfile=args.cert_file, keyfile=args.key_file", backend)
        self.assertNotIn("wrap_socket", backend)
        self.assertIn('server app 127.0.0.1:$BACKEND_PORT ssl verify none', RUNNER.read_text(encoding="utf-8"))
        self.assertIn("phase:3,deny,status:403", p3)
        self.assertIn("RESPONSE_HEADERS:X-Combined-Decision", p3)
        self.assertIn("phase:4,deny,status:403", p4)
        self.assertIn("RESPONSE_BODY", p4)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
