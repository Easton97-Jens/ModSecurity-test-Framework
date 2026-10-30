"""Current capture preparation must fail before a changed/ambiguous port."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SOURCE = connector_root() / "connectors/haproxy/harness/i12_current_capture.py"
CAPTURE = load_source(SOURCE)


class CurrentCaptureTests(unittest.TestCase):
    def test_exact_capture_delta_survives_unrelated_current_prefix(self):
        before = b"one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\n"
        after = before.replace(b"four\n", b"actual-observation\nfour\n")
        current = b"new-product-prefix\n" + before
        self.assertEqual(CAPTURE.relocate_delta(before, after, current), b"new-product-prefix\n" + after)

    def test_changed_or_ambiguous_context_cannot_be_fuzzed(self):
        before, after = b"first\nanchor\nlast\n", b"first\nobservation\nanchor\nlast\n"
        for current in (before.replace(b"anchor", b"changed"), before + before):
            with self.subTest(current=current), self.assertRaisesRegex(ValueError, "changed or is ambiguous"):
                CAPTURE.relocate_delta(before, after, current)

    def test_unchanged_historical_capture_file_keeps_current_bytes(self):
        old, current = b"old SDK interface\n", b"current SDK-compatible interface\n"
        self.assertEqual(CAPTURE.relocate_delta(old, old, current), current)

    @staticmethod
    def allocation_sources():
        public = "int haproxy_modsecurity_transaction_begin_request_with_profile(\nvoid) { return 23; }\n"
        following = "int haproxy_modsecurity_transaction_begin_request(\nvoid) { return 29; }\n"
        helper = "void haproxy_lifecycle_host_observe(\nvoid) {}\n"
        historical = public + following
        observed = public.replace("int haproxy_modsecurity_transaction_begin_request_with_profile(",
                                  "static int observed_real_begin_request_with_profile(")
        observed += public + helper + following
        private = ("static int begin_request_with_scope(\n"
                   "        haproxy_modsecurity_engine *engine,\n"
                   "        const haproxy_modsecurity_request *request,\n"
                   "        const char *profile_id,\n"
                   "        int request_authorization_only,\n"
                   "        haproxy_modsecurity_decision *decision,\n"
                   "        haproxy_modsecurity_transaction **transaction) {\n"
                   "    return request_authorization_only ? 31 : 37;\n}\n")
        return historical.encode(), observed.encode(), (private + historical).encode()

    def test_allocation_port_keeps_private_scope_body_and_forwards_scope(self):
        before, after, current = self.allocation_sources()
        result = CAPTURE.port_binding(before, after, current).decode()
        self.assertIn("return request_authorization_only ? 31 : 37;", result)
        self.assertEqual(result.count("static int observed_real_begin_request_with_scope("), 1)
        self.assertEqual(result.count("static int begin_request_with_scope("), 1)
        self.assertIn("observed_real_begin_request_with_scope(engine, request, profile_id,\n"
                      "        request_authorization_only, decision, transaction)", result)
        self.assertIn("actual == NULL ? NULL : &actual->contract", result)
        self.assertIn("actual == NULL ? NULL : actual->transaction", result)
        self.assertIn("errno = saved;\n    return result;", result)
        self.assertNotIn("observed_real_begin_request_with_profile", result)

    def test_allocation_port_rejects_changed_private_scope_signature(self):
        before, after, current = self.allocation_sources()
        changed = current.replace(b"int request_authorization_only,", b"int changed_scope,")
        with self.assertRaisesRegex(ValueError, "anchor changed or is ambiguous"):
            CAPTURE.port_binding(before, after, changed)

    def test_spop_port_brackets_current_authorization_and_companion_branches(self):
        call = ("    modsec_rc = state->config.response_phases_enabled ?\n"
                "        haproxy_modsecurity_transaction_begin(\n"
                "            state->engine, &modsec_request, decision, &transaction) :\n"
                "        haproxy_modsecurity_transaction_begin_request_authorization(\n"
                "            state->engine, &modsec_request, decision, &transaction);\n")
        old = "before_native_call();\n"
        observed = ""
        for handle, label in (("NULL", "spop_complete_request_sample_accepted"),
                              ("transaction", "spop_atomic_request_evaluated")):
            observed += (f'    haproxy_lifecycle_spop_observe({handle}, "{label}",\n'
                         '        (unsigned int)request->body_len, (int)request->http_metadata.advertised_body_len,\n'
                         '        request->has_body_len_arg, request->has_body);\n')
            if handle == "NULL":
                observed += old
        result = CAPTURE.port_spop(old.encode(), observed.encode(), call.encode()).decode()
        self.assertEqual(result.count(call), 1)
        self.assertLess(result.index('"spop_complete_request_sample_accepted"'), result.index(call))
        self.assertGreater(result.index('"spop_atomic_request_evaluated"'), result.index(call))
        before_bytes, observed_bytes = old.encode(), observed.encode()
        changed_call = call.replace("response_phases_enabled", "changed").encode()
        with self.assertRaisesRegex(ValueError, "anchor changed or is ambiguous"):
            CAPTURE.port_spop(before_bytes, observed_bytes, changed_call)

    @staticmethod
    def release_archive_bytes(payload):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as out:
            for name, content in (("VERSION", b"3.2.25\n"), ("payload.txt", payload)):
                member = tarfile.TarInfo("haproxy-3.2.25/" + name)
                member.size = len(content)
                out.addfile(member, io.BytesIO(content))
        return buffer.getvalue()

    def test_archive_replacement_after_hash_never_changes_parsed_bytes(self):
        with tempfile.TemporaryDirectory(dir=CAPTURE.STORAGE) as directory:
            root = Path(directory)
            archive = root / "release.tar"
            original = self.release_archive_bytes(b"verified source")
            replacement = self.release_archive_bytes(b"unverified replacement")
            archive.write_bytes(original)
            contract = {"version": "3.2.25", "sha256": hashlib.sha256(original).hexdigest()}
            original_sha = CAPTURE.sha
            changed = False

            def replace_after_hash(data):
                nonlocal changed
                if data == original and not changed:
                    changed = True
                    archive.write_bytes(replacement)
                return original_sha(data)

            with patch.object(CAPTURE, "sha", side_effect=replace_after_hash):
                receipt = CAPTURE.unpack_upstream(archive, root / "source", contract)
            self.assertTrue(changed)
            self.assertEqual((root / "source/payload.txt").read_bytes(), b"verified source")
            self.assertEqual(receipt["archive_sha256"], contract["sha256"])

    def test_archive_and_output_symlink_paths_are_rejected(self):
        with tempfile.TemporaryDirectory(dir=CAPTURE.STORAGE) as directory:
            root = Path(directory)
            data = self.release_archive_bytes(b"verified")
            archive = root / "release.tar"
            archive.write_bytes(data)
            contract = {"version": "3.2.25", "sha256": hashlib.sha256(data).hexdigest()}
            alias = root / "alias.tar"
            alias.symlink_to(archive)
            with self.assertRaises(OSError):
                CAPTURE.unpack_upstream(alias, root / "source", contract)
            parent = root / "linked-parent"
            parent.symlink_to(root, target_is_directory=True)
            output = parent / "source"
            with self.assertRaises(OSError):
                CAPTURE.unpack_upstream(archive, output, contract)
            self.assertFalse((root / "source").exists())

    def test_materialization_parent_swap_cannot_redirect_file(self):
        with tempfile.TemporaryDirectory(dir=CAPTURE.STORAGE) as directory:
            root = Path(directory)
            outside, source = root / "outside", root / "source"
            outside.mkdir()
            data = self.release_archive_bytes(b"verified")
            archive = root / "release.tar"
            archive.write_bytes(data)
            contract = {"version": "3.2.25", "sha256": hashlib.sha256(data).hexdigest()}
            original_write = CAPTURE.write_upstream_member
            changed = False

            def replace_source(descriptor, parts, content, mode):
                nonlocal changed
                if not changed:
                    changed = True
                    source.rename(root / "held-source")
                    source.symlink_to(outside, target_is_directory=True)
                return original_write(descriptor, parts, content, mode)

            with patch.object(CAPTURE, "write_upstream_member", side_effect=replace_source):
                with self.assertRaisesRegex(ValueError, "directory changed"):
                    CAPTURE.unpack_upstream(archive, source, contract)
            self.assertEqual(list(outside.iterdir()), [])
            self.assertEqual((root / "held-source/payload.txt").read_bytes(), b"verified")

    def test_storage_anchor_must_be_private(self):
        with tempfile.TemporaryDirectory(dir=CAPTURE.STORAGE) as directory:
            root = Path(directory)
            archive = root / "release.tar"
            archive.write_bytes(self.release_archive_bytes(b"verified"))
            root.chmod(0o777)
            try:
                with patch.object(CAPTURE, "STORAGE", root):
                    with self.assertRaisesRegex(ValueError, "privately owned"):
                        with CAPTURE.storage_parent(archive):
                            pass
            finally:
                root.chmod(0o700)

    def test_current_runtime_owned_feature_macro_is_not_redefined(self):
        CAPTURE.STORAGE.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=CAPTURE.STORAGE) as directory:
            source = Path(directory) / "runtime.c"
            source.write_text("#define _GNU_SOURCE\n#include <unistd.h>\n")
            self.assertEqual(CAPTURE.agent_feature_flags(source), [])
            source.write_text("#include <unistd.h>\n")
            self.assertEqual(CAPTURE.agent_feature_flags(source), ["-D_GNU_SOURCE"])

    def test_upstream_hash_mismatch_writes_no_source(self):
        with tempfile.TemporaryDirectory(dir=CAPTURE.STORAGE) as directory:
            root = Path(directory)
            archive = root / "release.tar"
            archive.write_bytes(b"unverified archive")
            with self.assertRaisesRegex(ValueError, "archive hash differs"):
                CAPTURE.unpack_upstream(archive, root / "source", {"version": "3.2.25", "sha256": "0" * 64})
            self.assertFalse((root / "source").exists())

    def test_upstream_duplicate_members_are_rejected_before_writes(self):
        with tempfile.TemporaryDirectory(dir=CAPTURE.STORAGE) as directory:
            root = Path(directory)
            archive = root / "release.tar"
            with tarfile.open(archive, "w") as out:
                for content in (b"original", b"replacement"):
                    member = tarfile.TarInfo("haproxy-3.2.25/duplicate")
                    member.size = len(content)
                    out.addfile(member, io.BytesIO(content))
            contract = {"version": "3.2.25", "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
            with self.assertRaisesRegex(ValueError, "duplicate upstream"):
                CAPTURE.unpack_upstream(archive, root / "source", contract)
            self.assertFalse((root / "source").exists())

    def test_archive_links_materialize_only_regular_pinned_members(self):
        with tempfile.TemporaryDirectory(dir=CAPTURE.STORAGE) as directory:
            root = Path(directory)
            archive = root / "release.tar"
            with tarfile.open(archive, "w") as out:
                for name, content in (("VERSION", b"3.2.25\n"), ("ssl/original", b"pinned fixture")):
                    member = tarfile.TarInfo("haproxy-3.2.25/" + name)
                    member.size = len(content)
                    out.addfile(member, io.BytesIO(content))
                member = tarfile.TarInfo("haproxy-3.2.25/checks/copy")
                member.type, member.linkname = tarfile.SYMTYPE, "../ssl/original"
                out.addfile(member)
            contract = {"version": "3.2.25", "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
            output = root / "source"
            receipt = CAPTURE.unpack_upstream(archive, output, contract)
            self.assertFalse((output / "checks/copy").is_symlink())
            self.assertEqual((output / "checks/copy").read_bytes(), b"pinned fixture")
            self.assertEqual(receipt["normalizations"][0]["resolved_regular_member"], "haproxy-3.2.25/ssl/original")
            self.assertEqual(receipt["normalizations"][0]["content_sha256"], hashlib.sha256(b"pinned fixture").hexdigest())

    def test_archive_links_reject_escape_missing_chain_and_hardlink(self):
        with tempfile.TemporaryDirectory(dir=CAPTURE.STORAGE) as directory:
            root = Path(directory)
            for index, (kind, target) in enumerate(((tarfile.SYMTYPE, "../../outside"),
                                                  (tarfile.SYMTYPE, "missing"),
                                                  (tarfile.SYMTYPE, "chain"),
                                                  (tarfile.LNKTYPE, "chain"))):
                with self.subTest(target=target, kind=kind):
                    archive = root / (str(index) + ".tar")
                    with tarfile.open(archive, "w") as out:
                        member = tarfile.TarInfo("haproxy-3.2.25/link")
                        member.type, member.linkname = kind, target
                        out.addfile(member)
                        chain = tarfile.TarInfo("haproxy-3.2.25/chain")
                        chain.type, chain.linkname = tarfile.SYMTYPE, "link"
                        out.addfile(chain)
                    contract = {"version": "3.2.25", "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
                    with self.assertRaises(ValueError):
                        CAPTURE.unpack_upstream(archive, root / ("source" + str(index)), contract)

    def test_upstream_archive_cannot_escape_or_follow_links(self):
        CAPTURE.STORAGE.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=CAPTURE.STORAGE) as directory:
            root = Path(directory)
            for index, name in enumerate(("haproxy-3.2.25/../../escape", "haproxy-3.2.25/link")):
                archive = root / (str(index) + ".tar")
                with tarfile.open(archive, "w") as out:
                    member = tarfile.TarInfo(name)
                    if index:
                        member.type, member.linkname = tarfile.SYMTYPE, "/etc/passwd"
                        out.addfile(member)
                    else:
                        member.size = 3
                        out.addfile(member, io.BytesIO(b"bad"))
                contract = {"version": "3.2.25", "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
                output = root / ("output-" + str(index))
                with self.assertRaises(ValueError):
                    CAPTURE.unpack_upstream(archive, output, contract)
                self.assertFalse((root / "escape").exists())



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
