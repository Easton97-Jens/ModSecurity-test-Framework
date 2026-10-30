"""Zero-process producer-receipt controls; real Go/FIPS builds are separate."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import os
from pathlib import Path
import struct
import tempfile
import unittest


ROOT = connector_root()
PROVENANCE = load_source(source_path('ci/checks/analysis/sonar-native-security/go_provenance.py', root=ROOT))


class GoNativeProducerChainTest(unittest.TestCase):
    def setUp(self):
        storage = Path(os.environ.get("CODEX_TEMP_ROOT", "/var/tmp/codex/ModSecurity-conector"))
        self.temporary = tempfile.TemporaryDirectory(prefix="sonar-go-chain-unit-", dir=storage)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.checkout = self.root / "checkout"
        self.checkout.mkdir()
        (self.checkout / ".go-version").write_text("1.27.3\n")
        goroot = self.root / "unit-goroot"
        go = goroot / "bin/go"
        go.parent.mkdir(parents=True)
        go.write_bytes(b"unit-only approved Go identity fixture")
        tool = goroot / "pkg/tool/unit-platform/link"
        tool.parent.mkdir(parents=True)
        tool.write_bytes(b"unit-only approved linker identity fixture")
        sources = {}
        for name in ("src/cmd/link/internal/ld/fips140.go", "src/cmd/go/internal/work/buildid.go",
                     "src/cmd/buildid/buildid.go", "src/cmd/internal/buildid/rewrite.go"):
            path = goroot / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("// unit-only producer source identity fixture\n")
            sources[str(path)] = PROVENANCE.digest(path)
        work = self.root / "go-work"
        work.mkdir()
        self.raw = work / "a.out"
        raw = bytearray(1024)
        raw[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<Q", raw, 40, 512)
        struct.pack_into("<HHH", raw, 58, 64, 3, 1)
        names = b"\0.shstrtab\0.go.fipsinfo\0"
        raw[128:128 + len(names)] = names
        struct.pack_into("<IIQQQQIIQQ", raw, 576, 1, 3, 0, 0, 128, len(names), 0, 0, 1, 0)
        struct.pack_into("<IIQQQQIIQQ", raw, 640, 11, 1, 0, 0, 256, 120, 0, 0, 8, 0)
        raw[256:272] = b"\xff Go fipsinfo \xff\0"
        self.raw.write_bytes(raw)
        # Arbitrary unit bytes model the bounded producer slot. They are NOT a
        # computed checksum or a claim of a compiled/executable FIPS artifact.
        raw[272:304] = b"f" * 32
        self.postlink = self.root / "postlink"
        self.postlink.write_bytes(raw)
        self.product = self.root / "unit-product"
        self.product.write_bytes(raw)
        replay = self.root / "unit-replay"
        replay.write_bytes(raw)
        go_link = {"schema": 1, "kind": "go-tool-link", "arguments": [str(tool), "-o", str(self.raw)],
                   "tool_sha256": PROVENANCE.digest(tool), "output": str(self.raw),
                   "output_sha256": PROVENANCE.digest(self.postlink), "retained_output": str(self.postlink)}
        self.raw_record = {"kind": "link", "output": str(self.raw),
                           "output_sha256": PROVENANCE.digest(self.raw), "inputs": {},
                           "retained_files": {str(self.raw): str(self.raw)}}
        self.records = [self.raw_record, go_link]
        self.chain = {"go_version": "go1.27.3", "goroot": str(goroot), "go_executable": str(go),
                      "go_sha256": PROVENANCE.digest(go), "go_sources": sources, "go_link": go_link,
                      "raw_link_output": str(self.raw), "raw_link_sha256": PROVENANCE.digest(self.raw),
                      "retained_raw_link": str(self.raw),
                      "fips_transition": PROVENANCE.verify_fips_transition(self.raw, self.postlink),
                      "buildid_replay_arguments": [str(go), "tool", "buildid", "-w", str(replay)],
                      "buildid_replay": str(replay), "buildid_replay_sha256": PROVENANCE.digest(replay),
                      "published_artifact": str(self.product), "published_sha256": PROVENANCE.digest(self.product),
                      "go_work_root": str(work), "external_go_inputs": {}, "object_aliases": {},
                      "external_context_compilations": []}

    def test_approved_producer_chain_receipt(self):
        result = PROVENANCE.verify_chain(self.chain, self.checkout, self.product, self.records)
        self.assertEqual(result, self.raw_record)

    def test_unexpected_postlink_mutation_rejected(self):
        data = bytearray(self.postlink.read_bytes())
        data[100] = 1
        self.postlink.write_bytes(data)
        self.chain["go_link"]["output_sha256"] = PROVENANCE.digest(self.postlink)
        with self.assertRaisesRegex(ValueError, "unexpected bytes changed outside Go FIPS checksum slot"):
            PROVENANCE.verify_chain(self.chain, self.checkout, self.product, self.records)


if os.environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)


if __name__ == "__main__":
    unittest.main()
