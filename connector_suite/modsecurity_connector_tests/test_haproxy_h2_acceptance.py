"""Fail-closed contracts for the opt-in native HTX H2 observer and reader."""
import io
import copy
from pathlib import Path
import tarfile
import tempfile
import unittest

from modsecurity_test_framework.connector_context import connector_root, test_root, load_source

BUILDER = load_source(test_root() / "ci/provisioning/prepare-haproxy-h2-test-build.py")
from connector_suite.adapters.haproxy.harness import haproxy_h2_acceptance as reader


class ObserverContractTests(unittest.TestCase):
    def test_observer_preserves_cleanup_and_scopes_claim_to_success(self):
        source = (connector_root() / "connectors/haproxy/htx-overlay/haproxy_modsecurity_htx_filter.c").read_text()
        observed = BUILDER.observe_filter(source)
        self.assertEqual(observed.count("haproxy_modsecurity_htx_abort_context(ctx);"),
                         source.count("haproxy_modsecurity_htx_abort_context(ctx);"))
        self.assertEqual(observed.count("modsecurity-htx-test: claim transaction_id="), 1)
        start = observed.index("static int haproxy_modsecurity_htx_companion_open_and_claim(")
        end = observed.index("\nstatic int haproxy_modsecurity_htx_companion_commit(", start)
        self.assertIn("modsecurity-htx-test: claim transaction_id=", observed[start:end])
        self.assertIn("context_detached host_stream_id=%u handle_present=%d", observed)
        self.assertLess(observed.index("haproxy_modsecurity_htx_abort_context(ctx);\n    ha_warning"),
                        observed.index("context_detached host_stream_id="))

    def test_changed_anchor_rejected(self):
        source = (connector_root() / "connectors/haproxy/htx-overlay/haproxy_modsecurity_htx_filter.c").read_text()
        changed = source.replace('"haproxy-htx-%u", s->uniq_id);', '"changed", s->uniq_id);')
        with self.assertRaises(ValueError):
            BUILDER.observe_filter(changed)

    def test_closed_inputs_include_build_and_registry(self):
        hashes = BUILDER.parent_source_hashes(connector_root())
        for name in ("connectors/haproxy/Makefile", "connectors/profile_registry.c",
                     "connectors/haproxy/htx-overlay/haproxy_modsecurity_htx_filter.c"):
            self.assertIn(name, hashes)


class ArchiveAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "a.c").write_bytes(b"actual source\n")
        (self.source / ".haproxy-source-provenance").write_text("fixture")

    def archive(self, names=("upstream/a.c",), link=None):
        path = self.root / "archive.tar.gz"
        with tarfile.open(path, "w:gz") as bundle:
            for name in names:
                member = tarfile.TarInfo(name)
                payload = b"actual source\n"
                member.size = len(payload)
                bundle.addfile(member, io.BytesIO(payload))
            if link:
                member = tarfile.TarInfo("upstream/link")
                member.type = tarfile.SYMTYPE
                member.linkname = link
                bundle.addfile(member)
        return path

    def test_exact_bytes_and_safe_symlink(self):
        (self.source / "link").symlink_to("a.c")
        self.assertEqual(set(BUILDER.verify_source_archive(self.archive(link="a.c"), self.source)), {"a.c", "link"})

    def test_changed_byte(self):
        archive = self.archive()
        (self.source / "a.c").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            BUILDER.verify_source_archive(archive, self.source)

    def test_extra_file(self):
        (self.source / "foreign").write_bytes(b"x")
        archive = self.archive()
        with self.assertRaises(ValueError):
            BUILDER.verify_source_archive(archive, self.source)

    def test_duplicate_archive_member(self):
        archive = self.archive(("upstream/a.c", "upstream/a.c"))
        with self.assertRaises(ValueError):
            BUILDER.verify_source_archive(archive, self.source)

    def test_traversal_archive_member(self):
        archive = self.archive(("upstream/../outside",))
        with self.assertRaises(ValueError):
            BUILDER.verify_source_archive(archive, self.source)

    def test_escaping_symlink(self):
        (self.root / "outside").write_bytes(b"x")
        (self.source / "link").symlink_to("../outside")
        archive = self.archive(link="../outside")
        with self.assertRaises(ValueError):
            BUILDER.verify_source_archive(archive, self.source)


class ReaderContractTests(unittest.TestCase):
    def fixture(self):
        access = [{"uri": "/acceptance/unit-allow/" + role, "alpn": "h2", "http_major": 2,
                   "transaction_id": "haproxy-htx-" + str(index), "client_port": 12345, "status": 200}
                  for index, role in enumerate(("peer", "target", "followup"))]
        native = "".join("modsecurity-htx-test: admitted transaction_id=" + row["transaction_id"] + "\n"
                         + "modsecurity-htx-test: cleanup transaction_id=" + row["transaction_id"]
                         + " native_released=1 companion_closed=1\n" for row in access)
        witness = "modsecurity-htx-test: cleanup transaction_id=haproxy-htx-1 native_released=1 companion_closed=1"
        upstream = {"driver_error": None, "peer_held_until_target_observed": True,
                    "first_byte_before_eos": True,
                    "target_cleanup_while_peer_held": {"transaction_id": "haproxy-htx-1", "witness": witness,
                                                       "peer_terminal": False, "peer_eos_sent": False},
                    "paths": {row["uri"]: {"arrivals": 1, "eos_sent": True, "response_finished": True}
                              for row in access}}
        wire = {"alpn": "h2", "tls_verified": True,
                "body_bytes": {str(n): 26 for n in (1, 3, 5)},
                "requests": [{"stream_id": stream, "method": "GET", "path": row["uri"]}
                             for stream, row in zip((1, 3, 5), access)],
                "status": {str(n): 200 for n in (1, 3, 5)},
                "terminal": {str(n): {"type": 0} for n in (1, 3, 5)}}
        return ["allow", wire, access, native, [], upstream, {"verified": True, "tls_removed": True}, "unit"]

    def test_complete_contract(self):
        self.assertEqual(reader.validate_case(*self.fixture())["status"], "PASS")

    def test_independent_missing_or_crossed_witnesses_reject(self):
        mutations = {
            "wire_protocol": lambda x: x[1].update(alpn="http/1.1"),
            "wire_status": lambda x: x[1]["status"].update({"3": 403}),
            "target_payload_missing": lambda x: x[1]["body_bytes"].update({"3": 0}),
            "peer_payload_missing": lambda x: x[1]["body_bytes"].update({"1": 0}),
            "crossed_stream": lambda x: x[1]["requests"][1].update(path=x[2][0]["uri"]),
            "cleanup_after_close": lambda x: x[5]["target_cleanup_while_peer_held"].update(peer_terminal=True),
            "writer_error": lambda x: x[5]["paths"][x[2][0]["uri"]].update(write_error="actual failure"),
            "upstream_duplicate": lambda x: x[5]["paths"][x[2][0]["uri"]].update(arrivals=2),
            "upstream_missing": lambda x: x[5]["paths"].pop(x[2][0]["uri"]),
            "cleanup_failed": lambda x: x[6].update(verified=False),
            "missing_native": lambda x: x.__setitem__(3, ""),
            "foreign_native": lambda x: x.__setitem__(3, x[3] + "modsecurity-htx-test: admitted transaction_id=haproxy-htx-99\n"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                fixture = self.fixture()
                mutate(fixture)
                with self.assertRaises(ValueError):
                    reader.validate_case(*fixture)

    def test_duplicate_json_rejected(self):
        with self.assertRaises(ValueError):
            reader.load_json('{"status":200,"status":403}')


class ArtifactAdmissionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.binary = self.root / "overlay/worktree/haproxy"
        self.binary.parent.mkdir(parents=True)
        self.binary.write_bytes(b"unit artifact; never executed")
        library = self.root / "libmodsecurity.so"
        library.write_bytes(b"unit library; never loaded")
        product = connector_root() / "connectors/haproxy/htx-overlay/haproxy_modsecurity_htx_filter.c"
        observed = self.binary.parent / "src/haproxy_modsecurity_htx_filter.c"
        observed.parent.mkdir()
        observed.write_text(BUILDER.observe_filter(product.read_text()))
        self.manifest = {"schema_version": 1, "test_only_observer": True,
                         "parent_source_sha256": BUILDER.parent_source_hashes(connector_root()),
                         "observer_source_sha256": BUILDER.digest(test_root() / "ci/provisioning/prepare-haproxy-h2-test-build.py"),
                         "binary": str(self.binary), "binary_sha256": BUILDER.digest(self.binary),
                         "modsecurity_library": str(library), "modsecurity_library_sha256": BUILDER.digest(library),
                         "production_filter_sha256": BUILDER.digest(product),
                         "observed_filter_sha256": BUILDER.digest(observed)}

    def admit(self, manifest):
        return reader.admit_manifest(manifest, connector_root(), test_root(), self.root / "h2-test-build.json")

    def test_exact_artifact_identity(self):
        self.assertEqual(self.admit(self.manifest), self.binary)

    def test_wrong_hashes_source_and_location_fail(self):
        for key, value in (("parent_source_sha256", {}), ("binary", "/usr/bin/false"),
                           ("binary_sha256", "0" * 64), ("modsecurity_library_sha256", "0" * 64),
                           ("observer_source_sha256", "0" * 64), ("observed_filter_sha256", "0" * 64)):
            with self.subTest(key=key):
                manifest = copy.deepcopy(self.manifest)
                manifest[key] = value
                with self.assertRaises(ValueError):
                    self.admit(manifest)

    def test_symlink_binary_fails_even_with_matching_bytes(self):
        real = self.binary.with_name("real")
        self.binary.rename(real)
        self.binary.symlink_to(real.name)
        with self.assertRaises(ValueError):
            self.admit(self.manifest)


if __name__ == "__main__":
    unittest.main()
