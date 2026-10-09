"""Exact projection identity controls; no native runtime claim."""
import hashlib
from pathlib import Path
import unittest
from tests.no_crs.test_nginx_native_operation_bundle import bundle


class NativeProjectionCaseIdentityTest(unittest.TestCase):
    def fixture(self, case, run):
        name = "phase4-" + hashlib.sha256((run + ":" + case).encode()).hexdigest()[:24]
        root = "/external/projections/" + name
        receipt = {"docroot_projection_parent": "/external/projections", "docroot_projection_root": root}
        config = ('load_module "/private/nginx-module.so";\nuser nobody nogroup;\nworker_processes 1;\n'
                  'daemon off;\nmodsecurity on;\nroot "' + root + '";\n').encode()
        return receipt, {"nginx.conf": config}, {"parent_root": Path("/source/parent"), "framework_root": Path("/source/framework")}

    def test_all_shared_routes_accept_exact_case_and_actual_run_hash(self):
        for case in sorted(bundle.PHASE4_CASES | bundle.MIME_CASES | bundle.EVENT_CASES):
            runs = ("run-at255", "run-over256", "run-long-query") if case in bundle.EVENT_CASES else ("run",)
            for run in runs:
                with self.subTest(case=case, run=run):
                    receipt, raw, sources = self.fixture(case, run)
                    bundle.projection_and_config(receipt, raw, case, run, sources)

    def test_old_run_name_and_wrong_case_run_parent_config_are_rejected(self):
        case, run = "phase4_body_at_limit", "run"
        receipt, raw, sources = self.fixture(case, run)
        mutations = [(case, "other-run", receipt, raw), ("phase4_body_over_limit", run, receipt, raw)]
        for root in ("/external/projections/run", receipt["docroot_projection_root"] + "-wrong", "/external/projections/nested/" + receipt["docroot_projection_root"].split("/")[-1]):
            changed = dict(receipt, docroot_projection_root=root)
            changed_raw = {"nginx.conf": raw["nginx.conf"].replace(receipt["docroot_projection_root"].encode(), root.encode())}
            mutations.append((case, run, changed, changed_raw))
        mutations.append((case, run, dict(receipt, docroot_projection_parent="/other"), raw))
        mutations.append((case, run, receipt, {"nginx.conf": raw["nginx.conf"].replace(b"root \"/external", b"root \"/wrong")}))
        for mutated_case, mutated_run, changed, changed_raw in mutations:
            with self.subTest(case=mutated_case, run=mutated_run, receipt=changed):
                with self.assertRaises(ValueError):
                    bundle.projection_and_config(changed, changed_raw, mutated_case, mutated_run, sources)
