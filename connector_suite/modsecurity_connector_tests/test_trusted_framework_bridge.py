"""Targeted source-trust regressions for the protected Parent integration bridge.

These specialist tests require an explicit Connector checkout. They do not run
the privileged hosted broker or mutate its installed gate.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import zlib
import contextlib
import io
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from modsecurity_test_framework.connector_context import connector_root, test_root
from modsecurity_connector_ci.runtime.broker import nginx_exact_head_root_launcher as LAUNCHER


ROOT = connector_root()
BRIDGE_PATH = ROOT / "ci/run-trusted-framework.py"
BRIDGE = argparse.Namespace(**runpy.run_path(str(BRIDGE_PATH), run_name="_bridge_contract"))
REVISION = "a" * 40
FRAMEWORK_REVISION = "b" * 40
RELATIVE = BRIDGE.TOOLS["exact-dispatcher"]


class TrustedFrameworkBridgeTests(unittest.TestCase):
    def projector_bootstrap(self):
        import yaml

        action = test_root() / ".github/actions/connector-ci/test-connectors-with-crs-no-mrts/connector-mode/action.yml"
        document = yaml.safe_load(action.read_text())
        step = next(item for item in document["runs"]["steps"]
                    if item.get("id") == "prepare-haproxy-runtime-evidence")
        return step["run"].split("<<'AUTHENTICATED_PROJECTOR'\n", 1)[1].split("\nAUTHENTICATED_PROJECTOR", 1)[0]

    def execute_projector_bootstrap(self, root, revision, framework_revision, operation):
        captured = io.BytesIO()
        output = io.TextIOWrapper(captured, encoding="utf-8")
        # As in the raw object fixture below, repository plumbing runs under
        # the fixture's invoking identity. The separate production command
        # test verifies that an actual root caller cannot avoid UID demotion.
        identity = mock.patch.object(os, "geteuid", return_value=1001) if os.geteuid() == 0 else contextlib.nullcontext()
        try:
            with identity, mock.patch.object(sys, "argv", ["projector-bootstrap", str(root), revision, framework_revision, operation]):
                with contextlib.redirect_stdout(output):
                    exec(compile(self.projector_bootstrap(), "actual-action-projector-bootstrap", "exec"),
                         {"__name__": "_projector_bootstrap_fixture"})
            output.flush()
            return captured.getvalue()
        finally:
            output.detach()

    def test_action_projector_rehashes_commit_tree_and_blob_before_root_capsule(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "parent"
            framework = root / BRIDGE.GITLINK
            framework.mkdir(parents=True)
            (root / "ci").mkdir()
            (root / "ci/run-trusted-framework.py").write_bytes(BRIDGE_PATH.read_bytes())
            environment = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
                           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}

            def git(repository, *arguments, data=None):
                return subprocess.check_output(
                    ["/usr/bin/git", "-c", f"safe.directory={repository}", "-C", str(repository), *arguments],
                    input=data, env=environment, stderr=subprocess.DEVNULL)

            def store(repository, kind, body):
                return git(repository, "hash-object", "-w", "-t", kind, "--stdin", data=body).decode().strip()

            def commit(repository, tree):
                return store(repository, "commit", (f"tree {tree}\nauthor Fixture <f@example.invalid> 1 +0000\n"
                                                   "committer Fixture <f@example.invalid> 1 +0000\n\nfixture\n").encode())

            for repository in (root, framework):
                git(repository, "init", "--quiet")
            relative = "connector_suite/modsecurity_connector_ci/runtime/lifecycle/project-haproxy-runtime-evidence.py"
            source = framework / relative
            source.parent.mkdir(parents=True)
            safe = b"print('authenticated projector')\n"
            source.write_bytes(safe)
            blob = store(framework, "blob", safe)
            tree = store(framework, "tree", b"100644 " + source.name.encode() + b"\0" + bytes.fromhex(blob))
            for component in reversed(relative.split("/")[:-1]):
                tree = store(framework, "tree", b"40000 " + component.encode() + b"\0" + bytes.fromhex(tree))
            framework_revision = commit(framework, tree)
            git(framework, "update-ref", "HEAD", framework_revision)
            modules = store(root, "tree", b"160000 ModSecurity-test-Framework\0" + bytes.fromhex(framework_revision))
            parent_tree = store(root, "tree", b"40000 modules\0" + bytes.fromhex(modules))
            revision = commit(root, parent_tree)
            git(root, "update-ref", "HEAD", revision)
            self.assertEqual(self.execute_projector_bootstrap(root, revision, framework_revision, "oid"),
                             (blob + "\n").encode())
            self.assertEqual(self.execute_projector_bootstrap(root, revision, framework_revision, "source"), safe)
            malicious = b"raise RuntimeError('candidate projector')\n"
            malicious_blob = store(framework, "blob", malicious)
            malicious_tree_body = b"100644 " + source.name.encode() + b"\0" + bytes.fromhex(malicious_blob)
            malicious_tree = store(framework, "tree", malicious_tree_body)
            for component in reversed(relative.split("/")[:-1]):
                malicious_tree_body = b"40000 " + component.encode() + b"\0" + bytes.fromhex(malicious_tree)
                malicious_tree = store(framework, "tree", malicious_tree_body)
            for kind, oid in (("commit", framework_revision), ("tree", tree), ("blob", blob)):
                with self.subTest(corrupt_object=kind):
                    path = framework / ".git/objects" / oid[:2] / oid[2:]
                    original = path.read_bytes()
                    path.chmod(0o600)
                    body = zlib.decompress(original).partition(b"\0")[2]
                    if kind == "commit":
                        body = body.replace(b"tree " + tree.encode() + b"\n",
                                            b"tree " + malicious_tree.encode() + b"\n", 1)
                    elif kind == "tree":
                        body = malicious_tree_body
                    else:
                        body = malicious
                    path.write_bytes(zlib.compress(kind.encode() + b" " + str(len(body)).encode() + b"\0" + body))
                    source.write_bytes(malicious)
                    try:
                        if kind in {"commit", "tree"}:
                            # The old rev-parse→blob-hash capsule accepted this
                            # attacker-selected, internally consistent blob.
                            selected = git(framework, "rev-parse", f"{framework_revision}:{relative}").decode().strip()
                            self.assertEqual(selected, malicious_blob)
                            self.assertEqual(git(framework, "cat-file", "blob", selected), malicious)
                        with self.assertRaises((ValueError, subprocess.SubprocessError)):
                            self.execute_projector_bootstrap(root, revision, framework_revision, "source")
                    finally:
                        path.write_bytes(original)
                        source.write_bytes(safe)

    def test_action_projector_rejects_modified_bootstrap_before_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "ci").mkdir()
            marker = root / "candidate-executed"
            (root / "ci/run-trusted-framework.py").write_text(f"open({str(marker)!r}, 'w').write('bad')\n")
            with self.assertRaisesRegex(ValueError, "immutable source digest"):
                self.execute_projector_bootstrap(root, "a" * 40, "b" * 40, "source")
            self.assertFalse(marker.exists())

    def fixture(self, directory: str, relative: str = RELATIVE, gitlink_mode="160000"):
        global REVISION, FRAMEWORK_REVISION
        root = Path(directory) / "parent"
        framework = root / BRIDGE.GITLINK
        source = framework / relative
        source.parent.mkdir(parents=True)
        source.write_text("print('trusted implementation')\n")
        objects = {}

        def store(kind, data):
            oid = hashlib.sha1(kind.encode() + b" " + str(len(data)).encode() + b"\0" + data).hexdigest()
            objects[kind, oid] = data
            return oid

        blob = store("blob", source.read_bytes())
        self.blob_oid = blob
        parts = relative.split("/")
        tree = store("tree", b"100644 " + parts[-1].encode() + b"\0" + bytes.fromhex(blob))
        for component in reversed(parts[:-1]):
            tree = store("tree", b"40000 " + component.encode() + b"\0" + bytes.fromhex(tree))
        FRAMEWORK_REVISION = store("commit", b"tree " + tree.encode() + b"\n\nfixture Framework\n")
        modules = store("tree", gitlink_mode.encode() + b" ModSecurity-test-Framework\0" + bytes.fromhex(FRAMEWORK_REVISION))
        parent_tree = store("tree", b"40000 modules\0" + bytes.fromhex(modules))
        REVISION = store("commit", b"tree " + parent_tree.encode() + b"\n\nfixture Parent\n")
        calls = []

        def git(repository, *arguments, forwarded, data=None):
            calls.append((repository, arguments))
            if arguments == ("rev-parse", "--show-toplevel", "HEAD"):
                revision = REVISION if repository == root else FRAMEWORK_REVISION
                return f"{repository}\n{revision}\n".encode()
            if len(arguments) == 3 and arguments[0] == "cat-file":
                return objects[arguments[1], arguments[2]]
            if arguments[:3] == ("hash-object", "--no-filters", "-t") and arguments[-1:] == ("--stdin",):
                kind = arguments[3]
                return (hashlib.sha1(kind.encode() + b" " + str(len(data)).encode() + b"\0" + data).hexdigest() + "\n").encode()
            self.fail(f"unexpected source acquisition: {arguments}")

        return root, framework, source, git, calls

    def test_only_the_protected_parent_gitlink_selects_framework_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, framework, source, git, calls = self.fixture(temporary)
            with mock.patch.dict(BRIDGE.authenticated_source.__globals__, _git=git):
                path, data = BRIDGE.authenticated_source(root, REVISION, RELATIVE, [])
            self.assertEqual(path, source)
            self.assertEqual(data, source.read_bytes())
            self.assertIn((root, ("cat-file", "commit", REVISION)), calls)
            self.assertIn((framework, ("cat-file", "blob", self.blob_oid)), calls)

    def test_candidate_selected_framework_head_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, framework, _source, git, _calls = self.fixture(temporary)

            def wrong(repository, *arguments, forwarded, data=None):
                if repository == framework and arguments[0] == "rev-parse":
                    return f"{framework}\n{'c' * 40}\n".encode()
                return git(repository, *arguments, forwarded=forwarded, data=data)

            with mock.patch.dict(BRIDGE.authenticated_source.__globals__, _git=wrong):
                with self.assertRaisesRegex(BRIDGE.TrustError, "trusted Parent gitlink"):
                    BRIDGE.authenticated_source(root, REVISION, RELATIVE, [])

    def test_missing_or_non_gitlink_framework_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, _framework, _source, git, _calls = self.fixture(temporary, gitlink_mode="40000")
            with mock.patch.dict(BRIDGE.authenticated_source.__globals__, _git=git):
                with self.assertRaisesRegex(BRIDGE.TrustError, "wrong object mode"):
                    BRIDGE.authenticated_source(root, REVISION, RELATIVE, [])

    def test_modified_checkout_cannot_replace_the_trusted_framework_blob(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, _framework, source, git, _calls = self.fixture(temporary)
            source.write_text("raise RuntimeError('candidate replacement')\n")
            with mock.patch.dict(BRIDGE.authenticated_source.__globals__, _git=git):
                with self.assertRaisesRegex(BRIDGE.TrustError, "exact trusted Git blob"):
                    BRIDGE.authenticated_source(root, REVISION, RELATIVE, [])

    def test_source_and_ancestor_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            actual = root / "actual"
            actual.mkdir()
            (actual / "source.py").write_text("pass\n")
            (root / "alias").symlink_to(actual, target_is_directory=True)
            (actual / "alias.py").symlink_to(actual / "source.py")
            for base, name in ((root / "alias", "source.py"), (actual, "alias.py")):
                with self.subTest(name=name), self.assertRaises(OSError):
                    BRIDGE.read_source(base, name)

    def test_non_regular_and_oversized_sources_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.mkfifo(root / "pipe.py")
            with self.assertRaises(BRIDGE.TrustError):
                BRIDGE.read_source(root, "pipe.py")
            with (root / "large.py").open("wb") as stream:
                stream.truncate(BRIDGE.MAX_SOURCE_BYTES + 1)
            with self.assertRaises(BRIDGE.TrustError):
                BRIDGE.read_source(root, "large.py")

    def test_traversal_and_partial_revisions_are_rejected(self):
        for value in ("relative", "/some/../other"):
            with self.subTest(root=value), self.assertRaises(BRIDGE.TrustError):
                BRIDGE._absolute(value)
        for value in ("master", REVISION[:8], REVISION.upper()):
            with self.subTest(revision=value), self.assertRaises(BRIDGE.TrustError):
                BRIDGE._sha(value)
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(BRIDGE.TrustError):
                BRIDGE.read_source(Path(temporary), "../outside.py")

    def test_root_git_checks_drop_to_the_explicit_runner_identity(self):
        arguments = ["--runner-uid", "1001", "--runner-gid", "1002"]
        completed = subprocess.CompletedProcess([], 0)

        def write_result(*_arguments, **options):
            os.write(options["stdout"], b"ok")
            return completed
        globals_ = BRIDGE._git.__globals__
        with mock.patch.object(globals_["os"], "geteuid", return_value=0):
            with mock.patch.object(globals_["subprocess"], "run", side_effect=write_result) as run:
                self.assertEqual(BRIDGE._git(ROOT, "rev-parse", "HEAD", forwarded=arguments), b"ok")
            invocation = run.call_args
            command = invocation.args[0]
            self.assertEqual(command[0], "/usr/bin/setpriv")
            for flag in ("--reuid=1001", "--regid=1002", "--clear-groups", "--no-new-privs",
                         "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all"):
                self.assertIn(flag, command)
            self.assertEqual(command[command.index("--") + 1], "/usr/bin/git")
            self.assertEqual(invocation.kwargs["env"]["GIT_CONFIG_GLOBAL"], "/dev/null")
            self.assertEqual(invocation.kwargs["env"]["GIT_CONFIG_NOSYSTEM"], "1")

    def test_root_source_checks_reject_missing_or_root_runner_identity(self):
        globals_ = BRIDGE._git.__globals__
        with mock.patch.object(globals_["os"], "geteuid", return_value=0):
            for arguments in ([], ["--runner-uid", "0", "--runner-gid", "0"]):
                with self.subTest(arguments=arguments), self.assertRaises(BRIDGE.TrustError):
                    BRIDGE._git(ROOT, "rev-parse", "HEAD", forwarded=arguments)

    def test_fixed_tool_registry_rejects_candidate_paths(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                BRIDGE.main(["--tool", "../../candidate.py", "--connector-root", str(ROOT),
                             "--connector-revision", REVISION])
        self.assertEqual(error.exception.code, 2)

    def test_isolated_sealed_execution_preserves_main_module_and_exit_status(self):
        source = b"from __future__ import annotations\nfrom dataclasses import dataclass\n@dataclass\nclass Result:\n    value: int\nassert Result(23).value == 23\nassert __name__ == '__main__'\nraise SystemExit(23)\n"
        with mock.patch.dict(BRIDGE.main.__globals__, authenticated_source=lambda *args: (Path("/trusted/source.py"), source)):
            status = BRIDGE.main(["--tool", "exact-dispatcher", "--connector-root", str(ROOT),
                                  "--connector-revision", REVISION])
        self.assertEqual(status, 23)

    def test_sealed_invocation_round_trips_payload_arguments(self):
        original_run = subprocess.run
        required = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
        variants = {
            "option-like": ["-c", "--help", "--source-reader-uid", "--"],
            "spaces": ["two words", "trailing "],
            "unicode": ["München", "東京"],
            "newlines": ["first\nsecond", "\r"],
            "empty": ["", "--empty="],
            "surrogateescaped": [os.fsdecode(b"argument-\xff")],
        }
        for case, payload in variants.items():
            with self.subTest(case=case):
                code = (f"import sys\nassert sys.argv[1:] == {payload!r}\n"
                        "assert __file__ == '/trusted/source.py'\n").encode()

                def launch(command, **options):
                    self.assertEqual(command[:4], [sys.executable, "-I", "-c", BRIDGE.INVOCATION_LAUNCHER])
                    self.assertEqual(len(command), 6)
                    for value in command[4:]:
                        descriptor = int(value)
                        self.assertIn(descriptor, options["pass_fds"])
                        self.assertEqual(fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & required, required)
                    return original_run(command, **options)

                with mock.patch.dict(BRIDGE.main.__globals__, authenticated_source=lambda *args: (Path("/trusted/source.py"), code)):
                    with mock.patch.object(subprocess, "run", side_effect=launch):
                        status = BRIDGE.main(["--tool", "exact-dispatcher", "--connector-root", str(ROOT),
                                              "--connector-revision", REVISION, "--", *payload])
                self.assertEqual(status, 0)

    def test_invocation_envelope_rejects_untrusted_descriptors(self):
        required = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE

        def descriptor(data, sealed=True):
            result = os.memfd_create("invocation-fixture", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            self.assertEqual(os.write(result, data), len(data))
            os.lseek(result, 0, os.SEEK_SET)
            if sealed:
                fcntl.fcntl(result, fcntl.F_ADD_SEALS, required)
            return result

        cases = ("unsealed-source", "unsealed-envelope", "foreign-owner-metadata", "extra-key",
                 "non-string-argument", "non-string-source", "directory-envelope", "oversized-envelope")
        with tempfile.TemporaryDirectory() as temporary:
            for case in cases:
                with self.subTest(case=case):
                    marker = Path(temporary) / case
                    source = f"open({str(marker)!r}, 'w').write('executed')\n".encode()
                    invocation = {"source_name": "/trusted/source.py", "argv": []}
                    if case == "extra-key":
                        invocation["unexpected"] = True
                    elif case == "non-string-argument":
                        invocation["argv"] = [1]
                    elif case == "non-string-source":
                        invocation["source_name"] = 1
                    source_fd = descriptor(source, case != "unsealed-source")
                    if case == "directory-envelope":
                        invocation_fd = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
                    else:
                        data = b"x" * (BRIDGE.MAX_SOURCE_BYTES + 1) if case == "oversized-envelope" else json.dumps(invocation).encode()
                        invocation_fd = descriptor(data, case != "unsealed-envelope")
                    launcher = BRIDGE.INVOCATION_LAUNCHER
                    if case == "foreign-owner-metadata":
                        launcher = ("import os,sys\n_original_fstat = os.fstat\n"
                                    "def foreign(fd):\n"
                                    "    metadata = _original_fstat(fd)\n"
                                    "    if fd == int(sys.argv[2]):\n"
                                    "        fields = list(metadata); fields[4] += 1\n"
                                    "        return os.stat_result(fields)\n"
                                    "    return metadata\n"
                                    "os.fstat = foreign\n" + launcher)
                    try:
                        result = subprocess.run(
                            [sys.executable, "-I", "-c", launcher, str(source_fd), str(invocation_fd)],
                            pass_fds=(source_fd, invocation_fd), stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, check=False,
                        )
                        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                        expected = ("invocation envelope must contain" if case in
                                    {"extra-key", "non-string-argument", "non-string-source"}
                                    else "invocation requires a bounded owned sealed regular descriptor")
                        self.assertIn(expected, result.stderr)
                        self.assertFalse(marker.exists())
                    finally:
                        os.close(source_fd)
                        os.close(invocation_fd)

    def test_gate_shims_reject_modified_bridge_before_any_candidate_code(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "ci").mkdir()
            marker = root / "executed"
            (root / "ci/run-trusted-framework.py").write_text(f"open({str(marker)!r}, 'w').write('bad')\n")
            for filename in ("nginx_exact_head_root_launcher.py", "nginx_exact_head_result_collector.py"):
                completed = subprocess.run(
                    [sys.executable, "-I", str(ROOT / "ci/runtime/broker" / filename),
                     "--base-repo-root", str(root), "--trusted-dispatcher-base-sha", REVISION],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(completed.returncode, 77)
                self.assertIn("trusted Parent source digest", completed.stderr)
            self.assertFalse(marker.exists())

    def test_collector_binding_arguments_are_separate_from_payload(self):
        collector = argparse.Namespace(**runpy.run_path(
            str(ROOT / "ci/runtime/broker/nginx_exact_head_result_collector.py"),
            run_name="_collector_arguments_contract"))
        bindings = ["--base-repo-root", str(ROOT), "--trusted-dispatcher-base-sha", REVISION]
        payload = ["--opaque", "München"]
        variants = {
            "metadata-first": bindings + payload,
            "metadata-between": payload[:1] + bindings + payload[1:],
            "metadata-last": payload + bindings,
            "duplicate-base": bindings + ["--base-repo-root", str(ROOT)],
            "missing-revision": bindings[:2] + payload,
        }
        for case, arguments in variants.items():
            with self.subTest(case=case), mock.patch.object(sys, "argv", ["collector", *arguments]):
                if case in {"duplicate-base", "missing-revision"}:
                    with self.assertRaisesRegex(ValueError, "exactly one"):
                        collector.collector_arguments()
                else:
                    self.assertEqual(collector.collector_arguments(), (ROOT, REVISION, payload))

    def test_separate_source_reader_identity_does_not_enter_the_root_tool_api(self):
        source = b"import sys\nassert sys.argv[1:] == ['--verify']\n"
        acquire = mock.Mock(return_value=(Path("/trusted/source.py"), source))
        with mock.patch.dict(BRIDGE.main.__globals__, authenticated_source=acquire):
            status = BRIDGE.main(["--tool", "readonly-prepare", "--connector-root", str(ROOT),
                                  "--connector-revision", REVISION, "--source-reader-uid", "1001",
                                  "--source-reader-gid", "1002", "--", "--verify"])
        self.assertEqual(status, 0)
        self.assertEqual(acquire.call_args.args[-1],
                         ["--verify", "--runner-uid", "1001", "--runner-gid", "1002"])

    def test_readonly_object_acquisition_never_reads_candidate_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            relative = BRIDGE.TOOLS["readonly-prepare"]
            root, framework, source, git, _calls = self.fixture(temporary, relative)
            source.write_text("raise RuntimeError('untrusted candidate helper')\n")

            def candidate(repository, *arguments, forwarded, data=None):
                if repository == framework and arguments[0] == "rev-parse":
                    return f"{framework}\n{'c' * 40}\n".encode()
                return git(repository, *arguments, forwarded=forwarded, data=data)

            with mock.patch.dict(BRIDGE.authenticated_source.__globals__, _git=candidate,
                                 read_source=mock.Mock(side_effect=AssertionError("candidate read"))):
                path, data = BRIDGE.authenticated_source(root, REVISION, relative, [], object_only=True)
            self.assertEqual(data, b"print('trusted implementation')\n")
            self.assertEqual(str(path), f"git:{FRAMEWORK_REVISION}:{relative}")

    def test_object_acquisition_rejects_wrong_repository_and_missing_trusted_object(self):
        with tempfile.TemporaryDirectory() as temporary:
            relative = BRIDGE.TOOLS["readonly-prepare"]
            root, framework, _source, git, _calls = self.fixture(temporary, relative)

            def wrong_root(repository, *arguments, forwarded, data=None):
                if repository == framework and arguments[0] == "rev-parse":
                    return f"/candidate/other-framework\n{FRAMEWORK_REVISION}\n".encode()
                return git(repository, *arguments, forwarded=forwarded, data=data)

            with mock.patch.dict(BRIDGE.authenticated_source.__globals__, _git=wrong_root):
                with self.assertRaisesRegex(BRIDGE.TrustError, "trusted Parent gitlink"):
                    BRIDGE.authenticated_source(root, REVISION, relative, [], object_only=True)

            def missing(repository, *arguments, forwarded, data=None):
                if arguments[:2] == ("cat-file", "blob"):
                    raise subprocess.CalledProcessError(128, ["git", "cat-file"])
                return git(repository, *arguments, forwarded=forwarded, data=data)

            with mock.patch.dict(BRIDGE.authenticated_source.__globals__, _git=missing):
                with self.assertRaises(subprocess.CalledProcessError):
                    BRIDGE.authenticated_source(root, REVISION, relative, [], object_only=True)

    def test_brokers_cannot_select_immutable_object_mode(self):
        for tool in ("exact-launcher", "exact-collector", "exact-dispatcher", "root-broker"):
            with self.subTest(tool=tool), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    BRIDGE.main(["--tool", tool, "--connector-root", str(ROOT),
                                 "--connector-revision", REVISION, "--trusted-framework-object"])
                self.assertEqual(error.exception.code, 2)

    def test_replacement_refs_and_corrupt_object_store_cannot_change_trusted_source(self):
        parent = os.environ.get("TMP_ROOT") or os.environ.get("TMPDIR")
        with tempfile.TemporaryDirectory(prefix="trusted-object-", dir=parent) as temporary:
            temporary_root = Path(temporary)
            root, framework = temporary_root / "parent", temporary_root / "parent" / BRIDGE.GITLINK
            root.mkdir()
            framework.mkdir(parents=True)
            environment = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
                           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}

            def git(repo, *arguments, data=None):
                return subprocess.check_output(
                    ["/usr/bin/git", "-c", f"safe.directory={repo}", "-C", str(repo), *arguments],
                    input=data, env=environment, stderr=subprocess.DEVNULL,
                )

            for repo in (root, framework):
                git(repo, "init", "--quiet")

            def store(repo, kind, data):
                return git(repo, "hash-object", "-w", "-t", kind, "--stdin", data=data).decode().strip()

            def commit(repo, tree):
                return store(repo, "commit", (f"tree {tree}\nauthor Fixture <f@example.invalid> 1 +0000\n"
                                               "committer Fixture <f@example.invalid> 1 +0000\n\nfixture\n").encode())

            relative = BRIDGE.TOOLS["readonly-prepare"]
            source, safe, malicious = framework / relative, b"print('trusted')\n", b"print('candidate')\n"
            source.parent.mkdir(parents=True)
            source.write_bytes(safe)
            blob = store(framework, "blob", safe)
            tree = store(framework, "tree", b"100644 " + source.name.encode() + b"\0" + bytes.fromhex(blob))
            for component in reversed(relative.split("/")[:-1]):
                tree = store(framework, "tree", b"40000 " + component.encode() + b"\0" + bytes.fromhex(tree))
            framework_commit = commit(framework, tree)
            git(framework, "update-ref", "HEAD", framework_commit)
            modules = store(root, "tree", b"160000 ModSecurity-test-Framework\0" + bytes.fromhex(framework_commit))
            parent_tree = store(root, "tree", b"40000 modules\0" + bytes.fromhex(modules))
            parent_commit = commit(root, parent_tree)
            git(root, "update-ref", "HEAD", parent_commit)
            malicious_blob = store(framework, "blob", malicious)
            malicious_tree = store(framework, "tree", b"100644 " + source.name.encode() + b"\0" + bytes.fromhex(malicious_blob))
            for component in reversed(relative.split("/")[:-1]):
                malicious_tree = store(framework, "tree", b"40000 " + component.encode() + b"\0" + bytes.fromhex(malicious_tree))
            malicious_commit = commit(framework, malicious_tree)
            # Some managed sandboxes map only UID0, so no nonroot identity can
            # own a fixture repository there. This real Git-object proof uses
            # the invoking identity; the separate command test verifies the
            # production setpriv/no-new-privs/capability boundary exactly.
            identity = mock.patch.object(os, "geteuid", return_value=1001) if os.geteuid() == 0 else contextlib.nullcontext()
            forwarded = []
            with identity:
                _name, data = BRIDGE.authenticated_source(root, parent_commit, relative, forwarded, object_only=True)
                self.assertEqual(data, safe)
                with self.subTest(attack="replacement-ref"):
                    git(framework, "replace", framework_commit, malicious_commit)
                    source.write_bytes(malicious)
                    _name, data = BRIDGE.authenticated_source(root, parent_commit, relative, forwarded, object_only=True)
                    self.assertEqual(data, safe)
                    with self.assertRaisesRegex(BRIDGE.TrustError, "exact trusted Git blob"):
                        BRIDGE.authenticated_source(root, parent_commit, relative, forwarded)
                    git(framework, "replace", "-d", framework_commit)
                for kind, oid in (("commit", framework_commit), ("tree", tree), ("blob", blob)):
                    with self.subTest(attack="corrupt-object", kind=kind):
                        path = framework / ".git/objects" / oid[:2] / oid[2:]
                        original = path.read_bytes()
                        path.chmod(0o600)
                        raw = zlib.decompress(original)
                        header, _, body = raw.partition(b"\0")
                        changed = body + b"\n# malicious replacement"
                        path.write_bytes(zlib.compress(kind.encode() + b" " + str(len(changed)).encode() + b"\0" + changed))
                        try:
                            with self.assertRaises((BRIDGE.TrustError, subprocess.SubprocessError)):
                                BRIDGE.authenticated_source(root, parent_commit, relative, forwarded, object_only=True)
                        finally:
                            path.write_bytes(original)

    def test_cells_driver_is_bound_to_the_trusted_parent_framework_gitlink(self):
        code = b"import os,sys,fcntl\ni=sys.argv.index('--trusted-cells-source-fd');fd=int(sys.argv[i+1])\nassert fcntl.fcntl(fd,fcntl.F_GET_SEALS)&fcntl.F_SEAL_WRITE\nassert os.fdopen(fd,'rb').read()==b'fixed trusted cells'\n"
        acquire = mock.Mock(side_effect=[(Path("/trusted/launcher.py"), code),
                                         (Path("/trusted/cells.sh"), b"fixed trusted cells")])
        with mock.patch.dict(BRIDGE.main.__globals__, authenticated_source=acquire):
            self.assertEqual(BRIDGE.main(["--tool", "exact-launcher", "--connector-root", str(ROOT),
                                          "--connector-revision", REVISION]), 0)
        self.assertEqual(acquire.call_args_list[1].args[2], BRIDGE.CELLS_SOURCE)

    def test_cells_driver_rejects_unsealed_or_foreign_source_fds(self):
        unsealed = os.memfd_create("unsealed-fixture", os.MFD_ALLOW_SEALING)
        try:
            os.write(unsealed, b"untrusted cells")
            with self.assertRaises(LAUNCHER.LauncherError):
                LAUNCHER.admit_trusted_cells_source(unsealed)
        finally:
            os.close(unsealed)
        sealed = BRIDGE.sealed_source(b"trusted bytes with wrong owner")
        details = os.fstat(sealed)
        fields = list(details)
        fields[4] = 1001
        try:
            with mock.patch.object(LAUNCHER.os, "fstat", return_value=os.stat_result(fields)):
                with self.assertRaises(LAUNCHER.LauncherError):
                    LAUNCHER.admit_trusted_cells_source(sealed)
        finally:
            os.close(sealed)

    def context_cli(self):
        path = test_root() / BRIDGE.TOOLS["connector-context"]
        return argparse.Namespace(**runpy.run_path(str(path), run_name="_context_contract"))

    def test_connector_context_exports_exact_roots_and_private_environment(self):
        cli = self.context_cli()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "parent"
            framework = root / BRIDGE.GITLINK
            (framework / "modsecurity_test_framework").mkdir(parents=True)
            (framework / "modsecurity_test_framework/connector.py").write_text("pass\n")
            def git(repository, *arguments):
                if arguments == ("rev-parse", "--show-toplevel", "HEAD"):
                    revision = REVISION if repository == root else FRAMEWORK_REVISION
                    return f"{repository}\n{revision}"
                return FRAMEWORK_REVISION
            with mock.patch.dict(cli.context.__globals__, git=git), mock.patch.dict(os.environ, RUNNER_TEMP=temporary):
                actual = cli.context(root, REVISION, FRAMEWORK_REVISION)
            self.assertEqual(actual, {
                "CONNECTOR_ROOT": str(root), "CONNECTOR_REVISION": REVISION,
                "TEST_ROOT": str(framework), "FRAMEWORK_ROOT": str(framework),
                "FRAMEWORK_REVISION": FRAMEWORK_REVISION, "CONNECTOR_TEST_PROFILE": "h1",
                "CONNECTOR_TEST_OUTPUT_ROOT": str(Path(temporary) / "ModSecurity-conector-tests"),
                "PYTHONPATH": f"{framework}:{framework}/connector_suite",
                "PYTHONSAFEPATH": "1", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
            })
            self.assertEqual((Path(temporary) / "ModSecurity-conector-tests").stat().st_mode & 0o777, 0o700)

    def test_connector_context_rejects_malformed_revisions_and_checkout_mismatches(self):
        cli = self.context_cli()
        root = Path("/fixture/parent")
        for case in ("malformed-parent", "malformed-framework", "parent-head", "gitlink", "framework-head"):
            with self.subTest(case=case):
                def git(repository, *arguments):
                    if arguments == ("rev-parse", "--show-toplevel", "HEAD"):
                        revision = REVISION if repository == root else FRAMEWORK_REVISION
                        if case == ("parent-head" if repository == root else "framework-head"):
                            revision = "c" * 40
                        return f"{repository}\n{revision}"
                    return "c" * 40 if case == "gitlink" else FRAMEWORK_REVISION
                with mock.patch.dict(cli.context.__globals__, git=git), self.assertRaises(ValueError):
                    cli.context(root, "master" if case == "malformed-parent" else REVISION,
                                "bad" if case == "malformed-framework" else FRAMEWORK_REVISION)

    def test_connector_context_rejects_unsafe_output_paths(self):
        cli = self.context_cli()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            for case in ("relative", "traversal", "newline", "symlink-parent", "symlink-output", "writable-output"):
                with self.subTest(case=case):
                    leaf = base / case
                    leaf.mkdir()
                    argument = str(leaf)
                    if case == "relative":
                        argument = "relative"
                    elif case == "traversal":
                        argument += "/../other"
                    elif case == "newline":
                        argument += "\nOTHER=value"
                    elif case == "symlink-parent":
                        alias = base / "alias"
                        alias.symlink_to(leaf, target_is_directory=True)
                        argument = str(alias)
                    elif case == "symlink-output":
                        (leaf / "ModSecurity-conector-tests").symlink_to(base, target_is_directory=True)
                    else:
                        output = leaf / "ModSecurity-conector-tests"
                        output.mkdir()
                        output.chmod(0o777)
                    with self.assertRaises((ValueError, OSError)):
                        cli.private_output(argument)

    def test_connector_context_source_is_authenticated_before_execution(self):
        relative = BRIDGE.TOOLS["connector-context"]
        for case in ("modified", "symlink", "candidate-head"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root, framework, source, git, _calls = self.fixture(temporary, relative)
                if case == "modified":
                    source.write_text("raise RuntimeError('candidate context')\n")
                elif case == "symlink":
                    safe = source.with_suffix(".safe")
                    source.rename(safe)
                    source.symlink_to(safe)
                original_git = git
                def acquire(repository, *arguments, forwarded, data=None):
                    if case == "candidate-head" and repository == framework and arguments[0] == "rev-parse":
                        return f"{framework}\n{'c' * 40}\n".encode()
                    return original_git(repository, *arguments, forwarded=forwarded, data=data)
                with mock.patch.dict(BRIDGE.authenticated_source.__globals__, _git=acquire):
                    with self.assertRaises((BRIDGE.TrustError, OSError)):
                        BRIDGE.authenticated_source(root, REVISION, relative, [])

    def test_cells_source_fd_cannot_be_supplied_by_the_caller(self):
        for token in ("--trusted-cells-source-fd", "--trusted-cells-source-fd=10"):
            with self.subTest(token=token), contextlib.redirect_stderr(io.StringIO()):
                acquire = mock.Mock()
                with mock.patch.dict(BRIDGE.main.__globals__, authenticated_source=acquire):
                    with self.assertRaises(SystemExit) as error:
                        BRIDGE.main(["--tool", "exact-launcher", "--connector-root", str(ROOT),
                                     "--connector-revision", REVISION, "--", token, "10"])
                self.assertEqual(error.exception.code, 2)
                acquire.assert_not_called()


if __name__ == "__main__":
    unittest.main()
