"""Contract tests for the isolated With-CRS/no-MRTS profile boundary."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = connector_root()


def load(name: str, path: Path):
    module = load_source(path)
    return module


PROFILE = load("with_crs_no_mrts_profile_tested", source_path('ci/runtime/lifecycle/with-crs-no-mrts-profile.py', root=ROOT))
RUNTIME_FIXTURES = load("with_crs_no_mrts_runtime_fixtures", source_path('tests/test_with_crs_no_mrts_runtime.py', root=ROOT))
AGGREGATE = load(
    "aggregate_with_crs_no_mrts_tested",
    source_path('ci/runtime/lifecycle/aggregate-five-connector-with-crs-no-mrts.py', root=ROOT),
)

HEAD = "a" * 40
BASE = "b" * 40
FRAMEWORK = "c" * 40
MRTS = "d" * 40
CRS = "e" * 40
RULE_SHA = "f" * 64
RUN = "with-crs-no-mrts-123-1"


class ValidationPass(dict):
    @property
    def status(self):
        return "PASS"


def private_json(path: Path, value: object) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = PROFILE.canonical_json(value)
    path.write_bytes(data)
    path.chmod(0o600)
    return data


def private_file(path: Path, value: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, str):
        path.write_text(value, encoding="utf-8")
    else:
        path.write_bytes(value)
    path.chmod(0o600)


def source_files_digest(source_files: object) -> str:
    return hashlib.sha256(PROFILE.canonical_json(source_files)).hexdigest()


def facts(connector: str, source_files: list[dict[str, str]]) -> dict[str, object]:
    generic = connector in PROFILE.GENERIC_CONNECTORS
    return {
        "schema_version": 1,
        "record_type": PROFILE.FACTS_RECORD,
        "profile": PROFILE.PROFILE,
        "connector": connector,
        "case_id": PROFILE.CASE_ID,
        "source_kind": PROFILE.SOURCE_KINDS[connector],
        "integration_mode": PROFILE.INTEGRATION_MODES[connector],
        "functional_result": "PASS",
        "allow_control": {"status": "observed", "http_status": 200} if generic else {"status": "not_observed"},
        "block": {"http_status": 403, "action": "deny", "rule_id": PROFILE.RULE_ID},
        "cleanup_status": "complete",
        "source_files_sha256": source_files_digest(source_files),
        "no_mrts": (
            {"status": "runtime_observed", "flags": {name: False for name in (
                "mrts_artifact_used", "mrts_inventory_loaded", "mrts_listener_created",
                "mrts_process_started", "mrts_runner_invoked")}}
            if generic else (
                {"status": "workflow_declared", "workflow_value": "no-mrts"}
                if connector == "apache"
                else {"status": "source_declared", "source_value": "no-mrts"}
            )
        ),
    }


def cell_directory(root: Path, connector: str, github_run: str = "123", attempt: str = "1") -> Path:
    return root / f"with-crs-no-mrts-{connector}-{github_run}-{attempt}"


def cell(root: Path, connector: str, *, head: str = HEAD, base: str = BASE,
         profile_run: str = RUN, github_run: str = "123", attempt: str = "1") -> Path:
    directory = cell_directory(root, connector, github_run, attempt)
    directory.mkdir(mode=0o700)
    source = [{"path": "source/result.json", "sha256": hashlib.sha256(b"source").hexdigest()}]
    fact_value = facts(connector, source)
    fact_data = private_json(directory / "functional-facts.json", fact_value)
    receipt = {
        "schema_version": 1, "record_type": PROFILE.PROFILE_RECORD, "profile": PROFILE.PROFILE,
        "connector": connector, "cell_identity": f"{connector}:with-crs:no-mrts", "case_id": PROFILE.CASE_ID,
        "source_kind": PROFILE.SOURCE_KINDS[connector], "integration_mode": PROFILE.INTEGRATION_MODES[connector],
        "profile_run_id": profile_run, "cell_run_id": f"crs-{github_run}-{attempt}-{connector}",
        "cell_run_id_kind": "workflow_cell", "github_run_id": github_run, "github_run_attempt": attempt,
        "artifact_name": f"with-crs-no-mrts-{connector}-{github_run}-{attempt}", "parent_sha": head,
        "base_sha": base, "framework_sha": FRAMEWORK, "mrts_sha": MRTS, "crs_commit": CRS,
        "executed_test": PROFILE.CASE_ID,
        "crs_rule_file": "rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf", "crs_rule_sha256": RULE_SHA,
        "functional_facts_sha256": hashlib.sha256(fact_data).hexdigest(), "source_files": source,
        "technical_validation": "PASS", "functional_result": "PASS", "cleanup_status": "complete",
        "no_mrts": fact_value["no_mrts"],
    }
    receipt_data = private_json(directory / "profile-cell-receipt.json", receipt)
    refresh_cell_manifest(directory, facts_raw=fact_data, receipt_raw=receipt_data)
    return directory


def refresh_cell_manifest(
    directory: Path, *, facts_raw: bytes | None = None, receipt_raw: bytes | None = None
) -> None:
    if facts_raw is None:
        facts_raw = (directory / "functional-facts.json").read_bytes()
    if receipt_raw is None:
        receipt_raw = (directory / "profile-cell-receipt.json").read_bytes()
    private_json(directory / "manifest.json", {
        "schema_version": 1, "record_type": PROFILE.MANIFEST_RECORD,
        "files": [
            {"name": "functional-facts.json", "sha256": hashlib.sha256(facts_raw).hexdigest(), "size_bytes": len(facts_raw)},
            {"name": "profile-cell-receipt.json", "sha256": hashlib.sha256(receipt_raw).hexdigest(), "size_bytes": len(receipt_raw)},
        ],
    })


def repack_cell(directory: Path, *, facts_mutator=None, receipt_mutator=None) -> None:
    """Repack a fixture after a deliberate semantic mutation.

    This models a downloaded artifact that has a recomputed local manifest, so
    aggregate rejection proves a semantic contract rather than a stale hash.
    It deliberately does not update the facts' source-list binding after a
    receipt-only source-list mutation.
    """
    facts_value = json.loads((directory / "functional-facts.json").read_text(encoding="utf-8"))
    receipt_value = json.loads((directory / "profile-cell-receipt.json").read_text(encoding="utf-8"))
    if facts_mutator is not None:
        facts_mutator(facts_value)
    facts_raw = private_json(directory / "functional-facts.json", facts_value)
    receipt_value["functional_facts_sha256"] = hashlib.sha256(facts_raw).hexdigest()
    if receipt_mutator is not None:
        receipt_mutator(receipt_value)
    receipt_raw = private_json(directory / "profile-cell-receipt.json", receipt_value)
    refresh_cell_manifest(directory, facts_raw=facts_raw, receipt_raw=receipt_raw)


def aggregate_args(root: Path, output: Path, **changes: str) -> SimpleNamespace:
    values = dict(artifact_root=root, output_dir=output, parent_sha=HEAD, base_sha=BASE,
                  profile_run_id=RUN, github_run_id="123", github_run_attempt="1",
                  framework_sha=FRAMEWORK, mrts_sha=MRTS, crs_commit=CRS, crs_rule_sha256=RULE_SHA)
    values.update(changes)
    return SimpleNamespace(**values)


def aggregate_with_args(root: Path, output: Path, **changes: str) -> dict[str, object]:
    """Run the strict aggregate using a separately prepared argument object."""
    return AGGREGATE.aggregate(aggregate_args(root, output, **changes))


def producer_args(root: Path, connector: str, source: Path) -> SimpleNamespace:
    verified_root = root / "verified" / connector
    verified_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    source_root = verified_root if connector == "apache" else source
    return SimpleNamespace(
        connector=connector, profile_run_id=RUN, cell_run_id=f"crs-123-1-{connector}",
        parent_sha=HEAD, base_sha=BASE, github_run_id="123", github_run_attempt="1",
        framework_sha=FRAMEWORK, mrts_sha=MRTS, crs_commit=CRS, crs_rule_sha256=RULE_SHA,
        haproxy_evidence_sha256=hashlib.sha256((source / "haproxy-runtime-evidence.json").read_bytes()).hexdigest()
        if connector == "haproxy" else "0" * 64,
        haproxy_manifest_sha256=hashlib.sha256((source / "manifest.json").read_bytes()).hexdigest()
        if connector == "haproxy" else "0" * 64,
        haproxy_evidence_uid=65534 if connector == "haproxy" else 65534,
        haproxy_evidence_gid=65534 if connector == "haproxy" else 65534,
        crs_source_root=root / "crs", verified_root=verified_root,
        source_root=source_root, output_dir=verified_root / "profile-cell",
    )


def make_crs_checkout(root: Path) -> tuple[str, str]:
    checkout = root / "crs"
    checkout.mkdir(mode=0o700)
    rule = b"SecRule ARGS \"@rx select\" \" id: 942270,deny\"\n"
    private_json(checkout / "rules" / "REQUEST-942-APPLICATION-ATTACK-SQLI.conf", {})
    (checkout / "rules" / "REQUEST-942-APPLICATION-ATTACK-SQLI.conf").write_bytes(rule)
    (checkout / "rules" / "REQUEST-942-APPLICATION-ATTACK-SQLI.conf").chmod(0o600)
    subprocess.run(["git", "init", "-q", str(checkout)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(checkout), "add", "rules"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(checkout), "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-q", "-m", "fixture"], check=True, capture_output=True)
    commit = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
    return commit, hashlib.sha256(rule).hexdigest()


def apache_audit(
    *,
    rule_id: int = PROFILE.RULE_ID,
    request: str = PROFILE.APACHE_AUDIT_REQUEST_LINE,
    transaction: str = "apacheprofile",
) -> str:
    return "\n".join(
        (
            f"---{transaction}---A--",
            f'[unique_id "{transaction}"] [id "{transaction}"]',
            f"---{transaction}---B--",
            request,
            "Host: profile.invalid",
            "",
            f"---{transaction}---F--",
            "HTTP/1.1 403 Forbidden",
            "Content-Type: text/plain",
            "",
            f"---{transaction}---H--",
            "Message: Warning. [file \"/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf\"] "
            f'[id "{rule_id}"] [msg "profile fixture"]',
            f"---{transaction}---Z--",
            "",
        )
    )


def apache_cleanup_receipt(
    *,
    cleanup_status: str = "PASS",
    residual: int = 0,
    cell_run_id: str = "crs-123-1-apache",
    github_run_id: str = "123",
    github_run_attempt: str = "1",
) -> dict[str, object]:
    return {
        "schema_version": PROFILE.SCHEMA_VERSION,
        "record_type": PROFILE.APACHE_CLEANUP_RECORD,
        "profile": PROFILE.PROFILE,
        "connector": "apache",
        "case_id": PROFILE.CASE_ID,
        "cell_run_id": cell_run_id,
        "github_run_id": github_run_id,
        "github_run_attempt": github_run_attempt,
        "listener_port": 18080,
        "tracked_host_processes_remaining": residual,
        "tracked_helper_processes_remaining": 0,
        "selected_listeners_remaining": 0,
        "pid_files_remaining": 0,
        "cleanup_status": cleanup_status,
    }


def make_apache_source(root: Path) -> Path:
    source = root / "verified" / "apache"
    source.mkdir(mode=0o700, parents=True, exist_ok=True)
    case = {"name": PROFILE.CASE_ID, "executed_connector": "apache", "live_executed": True,
            "status": "pass", "expected_status": 403, "actual_status": 403, "observed_status": 403,
            "observed_transport_result": "http_status", "expected_intervention": "deny",
            "requires_crs": True, "variant": "with-crs"}
    private_json(
        source / PROFILE.APACHE_SUMMARY_RELATIVE_PATH,
        {"apache": {"cases": {PROFILE.CASE_ID: case}}},
    )
    private_file(
        source / PROFILE.APACHE_RESULTS_RELATIVE_PATH,
        json.dumps(case, sort_keys=True) + "\n",
    )
    private_file(source / PROFILE.APACHE_AUDIT_RELATIVE_PATH, apache_audit())
    private_json(source / PROFILE.APACHE_CLEANUP_RECEIPT_NAME, apache_cleanup_receipt())
    return source


def make_haproxy_source(root: Path) -> Path:
    source = root / "haproxy-source"
    evidence = {"schema_version": 1, "record_type": "haproxy_runtime_evidence", "case_id": PROFILE.CASE_ID,
                "cell_run_id": "crs-123-1-haproxy", "cell_run_id_kind": "workflow_cell",
                "connector": "haproxy", "connector_profile": "haproxy_spoe_spop_htx",
                "integration_mode": PROFILE.INTEGRATION_MODES["haproxy"], "crs_mode": "with-crs", "mrts_mode": "no-mrts",
                "parent_sha": HEAD, "framework_sha": FRAMEWORK, "mrts_sha": MRTS, "expected_status": 403,
                "host_status": 403, "transport_result": "http_status", "requested_action": "deny",
                "host_action": "enforced_reply", "rule_id": PROFILE.RULE_ID, "runtime_result": "success",
                "cleanup_result": "complete", "engine_decision": "block", "observed_phases": ["P2"],
                "phase_counts": {"P1": 0, "P2": 1, "P3": 0, "P4": 0}}
    raw = private_json(source / "haproxy-runtime-evidence.json", evidence)
    private_json(source / "manifest.json", {"schema_version": 1, "record_type": "haproxy_runtime_evidence_manifest",
        "files": [{"name": "haproxy-runtime-evidence.json", "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}]})
    return source


def make_generic_source(root: Path, connector: str, run: str, *, crs_commit: str, crs_rule_sha: str,
                        parent_sha: str = "b" * 40) -> Path:
    """Build a wholly local synthetic source through the normalizer fixture helpers.

    This intentionally does not read retained CI artifacts.  The existing test
    helpers create complete host-shaped inputs, and the normalizer plus the
    strict common validator are exercised as part of this producer test.
    """
    fixture = RUNTIME_FIXTURES.WithCrsNoMrtsRuntimeContractTest()
    runtime = root / f"{connector}-runtime"
    fixture.make_observation(runtime, connector=connector)
    if connector == "lighttpd":
        fixture.make_lighttpd_host_evidence(runtime, run_id=run)
    else:
        fixture.populate_host_evidence(connector, runtime)
    if connector == "envoy":
        summary = runtime / "runtime-summary.txt"
        private_file(
            summary,
            summary.read_text(encoding="utf-8").replace("run_id=envoy-run", f"run_id={run}"),
        )
    elif connector == "traefik":
        result_path = runtime / "result.json"
        result = json.loads(result_path.read_text(encoding="utf-8"))
        result["run_id"] = run
        private_json(result_path, result)
    fixture.normalize(connector, root, runtime, run_id=run)

    observation_path = root / "evidence" / "normalized" / connector / run / "runtime-observation.json"
    observation = json.loads(observation_path.read_text(encoding="utf-8"))
    observation["identity"]["parent_commit"] = parent_sha
    private_json(observation_path, observation)
    event_path = root / "evidence" / "normalized" / connector / run / "event.json"
    event = json.loads(event_path.read_text(encoding="utf-8"))
    event["connector_commit"] = parent_sha
    event["crs_commit"] = crs_commit
    event["crs_rule_file_sha256"] = crs_rule_sha
    private_json(event_path, event)
    runtime_path = root / "evidence" / "runtime" / connector / run / "runtime.json"
    runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    runtime["canonical_observation"]["evidence_sha256"] = hashlib.sha256(
        observation_path.read_bytes()
    ).hexdigest()
    private_json(runtime_path, runtime)
    return root


class WithCrsNoMrtsProfileContractTest(unittest.TestCase):
    def test_crs_rule_identity_accepts_pinned_json_syntax_only(self):
        self.assertIsNotNone(PROFILE.APACHE_CRS_RULE_ID.search(b'"id":942270,'))
        self.assertIsNotNone(PROFILE.APACHE_CRS_RULE_ID.search(b"id: 942270,deny"))
        for near_miss in (b'"id":942271,', b'"id":9422700,', b'"rule_id":942270,'):
            with self.subTest(near_miss=near_miss):
                self.assertIsNone(PROFILE.APACHE_CRS_RULE_ID.search(near_miss))

    def test_produce_accepts_apache_and_haproxy_source_contracts(self):
        with tempfile.TemporaryDirectory(prefix="profile-producer-") as temporary:
            root = Path(temporary)
            commit, digest = make_crs_checkout(root)
            for connector, source_factory in (("apache", make_apache_source), ("haproxy", make_haproxy_source)):
                args = producer_args(root, connector, source_factory(root))
                args.crs_commit, args.crs_rule_sha256 = commit, digest
                if connector == "haproxy":
                    trusted_digests = {
                        "haproxy-runtime-evidence.json": args.haproxy_evidence_sha256,
                        "manifest.json": args.haproxy_manifest_sha256,
                    }
                    verifier_context = mock.patch.object(
                        PROFILE.HAPROXY_PROJECTOR,
                        "verify_staged_package",
                        return_value=trusted_digests,
                    )
                else:
                    verifier_context = nullcontext()
                with verifier_context as verifier:
                    receipt = PROFILE.produce(args)
                    if connector == "haproxy":
                        verifier.assert_called_once()
                        trusted = verifier.call_args.kwargs["trusted"]
                        self.assertEqual(trusted.parent_sha, args.parent_sha)
                        self.assertEqual(trusted.framework_sha, args.framework_sha)
                        self.assertEqual(trusted.mrts_sha, args.mrts_sha)
                        self.assertEqual(trusted.cell_run_id, args.cell_run_id)
                        self.assertEqual(verifier.call_args.kwargs["evidence_uid"], args.haproxy_evidence_uid)
                        self.assertEqual(verifier.call_args.kwargs["evidence_gid"], args.haproxy_evidence_gid)
                self.assertEqual(receipt["connector"], connector)
                self.assertEqual(receipt["cell_run_id"], f"crs-123-1-{connector}")
                self.assertEqual(set((args.output_dir).iterdir()), {
                    args.output_dir / "functional-facts.json", args.output_dir / "profile-cell-receipt.json",
                    args.output_dir / "manifest.json"})
            mismatch_source = make_haproxy_source(root / "mismatch")
            mismatch = producer_args(root / "mismatch", "haproxy", mismatch_source)
            mismatch.crs_source_root = root / "crs"
            mismatch.crs_commit, mismatch.crs_rule_sha256 = commit, digest
            actual_digests = {
                "haproxy-runtime-evidence.json": mismatch.haproxy_evidence_sha256,
                "manifest.json": mismatch.haproxy_manifest_sha256,
            }
            mismatch.haproxy_evidence_sha256 = "0" * 64
            with mock.patch.object(
                PROFILE.HAPROXY_PROJECTOR, "verify_staged_package", return_value=actual_digests
            ):
                with self.assertRaisesRegex(ValueError, "source digests"):
                    PROFILE.produce(mismatch)
            incomplete = producer_args(root / "incomplete", "haproxy", make_haproxy_source(root / "incomplete"))
            incomplete.crs_source_root = root / "crs"
            incomplete.crs_commit, incomplete.crs_rule_sha256 = commit, digest
            incomplete.haproxy_evidence_uid = 0
            with self.assertRaisesRegex(ValueError, "evidence UID"):
                PROFILE.produce(incomplete)

    def test_produce_rejects_bad_cell_binding_and_hardlinked_source(self):
        with tempfile.TemporaryDirectory(prefix="profile-producer-reject-") as temporary:
            root = Path(temporary)
            commit, digest = make_crs_checkout(root)
            source = make_apache_source(root)
            args = producer_args(root, "apache", source)
            args.crs_commit, args.crs_rule_sha256 = commit, digest
            args.cell_run_id = "crs-123-1-wrong"
            with self.assertRaises(ValueError):
                PROFILE.produce(args)
            args.cell_run_id = "crs-123-1-apache"
            summary = source / PROFILE.APACHE_SUMMARY_RELATIVE_PATH
            os.link(summary, source / "hardlink.json")
            with self.assertRaises(ValueError):
                PROFILE.produce(args)

    def test_apache_and_haproxy_reject_missing_parent_workflow_run_binding(self):
        with tempfile.TemporaryDirectory(prefix="profile-parent-run-binding-") as temporary:
            root = Path(temporary)
            commit, digest = make_crs_checkout(root)
            for connector, source_factory in (("apache", make_apache_source), ("haproxy", make_haproxy_source)):
                with self.subTest(connector=connector):
                    source = source_factory(root)
                    args = producer_args(root, connector, source)
                    args.crs_commit, args.crs_rule_sha256 = commit, digest
                    args.cell_run_id = "crs-123-1-unbound"
                    with self.assertRaises(ValueError):
                        PROFILE.produce(args)

    def test_apache_profile_rejects_unbound_rule_and_unproven_cleanup(self):
        cases = (
            (
                "wrong_rule",
                lambda source: private_file(
                    source / PROFILE.APACHE_AUDIT_RELATIVE_PATH,
                    apache_audit(rule_id=942271),
                ),
            ),
            (
                "unbound_rule",
                lambda source: private_file(
                    source / PROFILE.APACHE_AUDIT_RELATIVE_PATH,
                    apache_audit(rule_id=942271)
                    + apache_audit(
                        request="GET /unrelated HTTP/1.1",
                        transaction="unrelatedprofile",
                    ),
                ),
            ),
            (
                "missing_cleanup",
                lambda source: (source / PROFILE.APACHE_CLEANUP_RECEIPT_NAME).unlink(),
            ),
            (
                "failed_cleanup",
                lambda source: private_json(
                    source / PROFILE.APACHE_CLEANUP_RECEIPT_NAME,
                    apache_cleanup_receipt(cleanup_status="FAIL"),
                ),
            ),
            (
                "residual_tracked_process",
                lambda source: private_json(
                    source / PROFILE.APACHE_CLEANUP_RECEIPT_NAME,
                    apache_cleanup_receipt(residual=1),
                ),
            ),
            (
                "wrong_cleanup_cell_run",
                lambda source: private_json(
                    source / PROFILE.APACHE_CLEANUP_RECEIPT_NAME,
                    apache_cleanup_receipt(cell_run_id="crs-123-1-other"),
                ),
            ),
            (
                "wrong_cleanup_github_run",
                lambda source: private_json(
                    source / PROFILE.APACHE_CLEANUP_RECEIPT_NAME,
                    apache_cleanup_receipt(github_run_id="124"),
                ),
            ),
            (
                "wrong_cleanup_github_attempt",
                lambda source: private_json(
                    source / PROFILE.APACHE_CLEANUP_RECEIPT_NAME,
                    apache_cleanup_receipt(github_run_attempt="2"),
                ),
            ),
        )
        for name, mutate in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix="profile-apache-reject-") as temporary:
                root = Path(temporary)
                commit, digest = make_crs_checkout(root)
                source = make_apache_source(root)
                args = producer_args(root, "apache", source)
                args.crs_commit, args.crs_rule_sha256 = commit, digest
                mutate(source)
                with self.assertRaises((ValueError, OSError)):
                    PROFILE.produce(args)

    def test_apache_native_audit_boundary_is_required_without_a_preamble(self):
        native = apache_audit()
        PROFILE._apache_audit_block_observation(native.encode("utf-8"))

        non_native = native.replace("---apacheprofile---", "--apacheprofile-")
        non_native_bytes = non_native.encode("utf-8")
        with self.assertRaisesRegex(ValueError, "outside a transaction"):
            PROFILE._apache_audit_block_observation(non_native_bytes)

        preamble_bytes = ("untrusted preamble\n" + native).encode("utf-8")
        with self.assertRaisesRegex(ValueError, "outside a transaction"):
            PROFILE._apache_audit_block_observation(preamble_bytes)

    def test_apache_profile_rejects_primitive_type_confusion_at_source_boundary(self):
        def mutate_summary(source: Path, name: str, value: object) -> None:
            path = source / PROFILE.APACHE_SUMMARY_RELATIVE_PATH
            summary = json.loads(path.read_text(encoding="utf-8"))
            summary["apache"]["cases"][PROFILE.CASE_ID][name] = value
            private_json(path, summary)

        def mutate_results(source: Path, name: str, value: object) -> None:
            path = source / PROFILE.APACHE_RESULTS_RELATIVE_PATH
            result = json.loads(path.read_text(encoding="utf-8"))
            result[name] = value
            private_file(path, json.dumps(result, sort_keys=True) + "\n")

        def mutate_cleanup(source: Path, name: str, value: object) -> None:
            path = source / PROFILE.APACHE_CLEANUP_RECEIPT_NAME
            cleanup = json.loads(path.read_text(encoding="utf-8"))
            cleanup[name] = value
            private_json(path, cleanup)

        cases = (
            ("summary_live_executed_integer", lambda source: mutate_summary(source, "live_executed", 1)),
            ("summary_expected_status_float", lambda source: mutate_summary(source, "expected_status", 403.0)),
            ("jsonl_requires_crs_integer", lambda source: mutate_results(source, "requires_crs", 1)),
            ("jsonl_actual_status_float", lambda source: mutate_results(source, "actual_status", 403.0)),
            ("cleanup_schema_boolean", lambda source: mutate_cleanup(source, "schema_version", True)),
            ("cleanup_schema_float", lambda source: mutate_cleanup(source, "schema_version", 1.0)),
        )
        for name, mutate in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix="profile-apache-types-") as temporary:
                root = Path(temporary)
                commit, digest = make_crs_checkout(root)
                source = make_apache_source(root)
                args = producer_args(root, "apache", source)
                args.crs_commit, args.crs_rule_sha256 = commit, digest
                mutate(source)
                with self.assertRaises(ValueError):
                    PROFILE.produce(args)

    def test_apache_profile_rejects_source_root_mismatch_and_cleanup_receipt_is_one_shot(self):
        with tempfile.TemporaryDirectory(prefix="profile-apache-binding-") as temporary:
            root = Path(temporary)
            commit, digest = make_crs_checkout(root)
            source = make_apache_source(root)
            args = producer_args(root, "apache", source)
            args.crs_commit, args.crs_rule_sha256 = commit, digest
            other = root / "other"
            other.mkdir(mode=0o700)
            args.source_root = other
            with self.assertRaises(ValueError):
                PROFILE.produce(args)

            receipt_parent = root / "cleanup-receipt"
            receipt_parent.mkdir(mode=0o700)
            output = receipt_parent / PROFILE.APACHE_CLEANUP_RECEIPT_NAME
            writer_args = SimpleNamespace(
                output=output,
                cell_run_id="crs-123-1-apache",
                github_run_id="123",
                github_run_attempt="1",
                listener_port=18080,
            )
            PROFILE._write_apache_cleanup_receipt(writer_args)
            receipt = PROFILE.parse_json_object(
                output.read_bytes(), "Apache cleanup receipt", canonical=True
            )
            self.assertEqual(receipt["github_run_id"], "123")
            self.assertEqual(receipt["github_run_attempt"], "1")
            self.assertEqual(receipt["tracked_host_processes_remaining"], 0)
            self.assertEqual(receipt["selected_listeners_remaining"], 0)
            with self.assertRaises(ValueError):
                PROFILE._write_apache_cleanup_receipt(writer_args)

    def test_apache_selected_results_write_stays_anchored_after_path_replacement(self):
        with tempfile.TemporaryDirectory(prefix="apache-selected-results-fd-") as temporary:
            root = Path(temporary)
            results = root / "results"
            outside = root / "outside"
            results.mkdir(mode=0o700)
            outside.mkdir(mode=0o700)
            canary = outside / "canary"
            canary.write_text("unchanged\n", encoding="utf-8")

            descriptor = PROFILE._open_absolute_directory(results, "selected Apache results directory")
            try:
                moved = root / "moved-results"
                results.rename(moved)
                results.symlink_to(outside, target_is_directory=True)
                PROFILE._write_new_named_file(
                    descriptor,
                    PROFILE.APACHE_SELECTED_RESULTS_NAME,
                    b'{"case":"anchored"}\n',
                    "selected Apache case JSONL",
                    PROFILE.APACHE_SELECTED_OUTPUT_NAMES,
                )
            finally:
                os.close(descriptor)

            self.assertEqual(
                (moved / PROFILE.APACHE_SELECTED_RESULTS_NAME).read_bytes(),
                b'{"case":"anchored"}\n',
            )
            self.assertFalse((outside / PROFILE.APACHE_SELECTED_RESULTS_NAME).exists())
            self.assertEqual(canary.read_text(encoding="utf-8"), "unchanged\n")

    def test_apache_selected_results_rejects_replacement_between_stat_and_open(self):
        with tempfile.TemporaryDirectory(prefix="apache-selected-results-race-") as temporary:
            root = Path(temporary)
            results = root / "results"
            results.mkdir(mode=0o700)
            moved = root / "moved-results"
            original_open = PROFILE.os.open
            replaced = False

            def replace_before_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal replaced
                if path == "results" and dir_fd is not None and not replaced:
                    replaced = True
                    results.rename(moved)
                    results.mkdir(mode=0o700)
                return original_open(path, flags, mode, dir_fd=dir_fd)

            root_fd = PROFILE._open_absolute_directory(root, "Apache runtime root")
            try:
                with mock.patch.object(PROFILE.os, "open", side_effect=replace_before_open):
                    with self.assertRaises(ValueError):
                        PROFILE._open_runtime_child(
                            root_fd, ("results",), "selected Apache results directory"
                        )
            finally:
                os.close(root_fd)
            self.assertTrue(replaced)
            self.assertTrue(moved.is_dir())
            self.assertTrue(results.is_dir())

    def test_create_runtime_child_preserves_existing_private_mode(self):
        with tempfile.TemporaryDirectory(prefix="apache-selected-results-mode-") as temporary:
            root = Path(temporary)
            existing = root / "existing"
            existing.mkdir(mode=0o750)
            os.chmod(existing, 0o750)
            root_fd = PROFILE._open_absolute_directory(root, "Apache runtime root")
            try:
                descriptor = PROFILE._create_runtime_child(
                    root_fd, ("existing",), "selected Apache results directory"
                )
                try:
                    self.assertEqual(stat.S_IMODE(os.fstat(descriptor).st_mode), 0o750)
                finally:
                    os.close(descriptor)
            finally:
                os.close(root_fd)

    def test_produce_accepts_full_generic_shape_but_rejects_minimal_observation(self):
        with tempfile.TemporaryDirectory(prefix="profile-generic-") as temporary:
            root = Path(temporary)
            commit, digest = make_crs_checkout(root)
            run = "crs-123-1-envoy"
            source = make_generic_source(root, "envoy", run, crs_commit=commit, crs_rule_sha=digest)
            args = producer_args(root, "envoy", source)
            # The normalizer fixture deliberately emits its own synthetic
            # parent/framework/MRTS identities; bind the producer to those
            # exact values instead of replacing them with test constants.
            args.parent_sha, args.base_sha = "b" * 40, "a" * 40
            args.crs_commit, args.crs_rule_sha256 = commit, digest
            receipt = PROFILE.produce(args)
            self.assertEqual(receipt["connector"], "envoy")
            observation_path = source / "evidence" / "normalized" / "envoy" / run / "runtime-observation.json"
            observation_path.write_bytes(PROFILE.canonical_json({"schema_version": 1, "status": "PASS"}))
            args.verified_root = root / "verified-minimal" / "envoy"
            args.output_dir = args.verified_root / "profile-cell"
            args.verified_root.mkdir(mode=0o700, parents=True)
            with self.assertRaises(ValueError):
                PROFILE.produce(args)
    def test_exact_five_cells_aggregate_and_matrix_disposition(self):
        with tempfile.TemporaryDirectory(prefix="profile-aggregate-") as temporary:
            root = Path(temporary)
            for connector in PROFILE.CONNECTORS:
                cell(root, connector)
            result = AGGREGATE.aggregate(aggregate_args(root, root / "aggregate"))
            self.assertTrue(result["summary"]["technical_validity"]["exact_five"])
            self.assertEqual(result["matrix"]["counts"], {"passed": 5, "failed": 0, "blocked": 6, "not_run": 13, "not_applicable": 0})
            rows = result["matrix"]["rows"]
            self.assertEqual(len(rows), 24)
            self.assertEqual(
                {(row["connector"], row["profile"]) for row in rows},
                {
                    (connector, profile_name)
                    for connector in AGGREGATE.MATRIX_CONNECTORS
                    for profile_name, _crs, _mrts in AGGREGATE.MATRIX_VARIANTS
                },
            )
            passed = {(row["connector"], row["profile"]) for row in rows if row["status"] == "passed"}
            blocked = {(row["connector"], row["profile"]) for row in rows if row["status"] == "blocked"}
            not_run = {(row["connector"], row["profile"]) for row in rows if row["status"] == "not_run"}
            self.assertEqual(passed, {(connector, "with_crs_no_mrts") for connector in PROFILE.CONNECTORS})
            self.assertEqual(
                blocked,
                {
                    (connector, profile_name)
                    for connector in ("envoy", "traefik", "lighttpd")
                    for profile_name in ("no_crs_with_mrts", "with_crs_with_mrts")
                },
            )
            self.assertEqual(len(not_run), 13)
            self.assertFalse(any(row["status"] in {"failed", "not_applicable"} for row in rows))
            self.assertTrue(all(row["candidate_head"] == HEAD and row["base_sha"] == BASE for row in rows))

    def test_exact_five_cells_are_produced_by_the_profile_boundary(self):
        """Exercise every connector producer before the strict aggregate."""
        with tempfile.TemporaryDirectory(prefix="profile-five-producers-") as temporary:
            root = Path(temporary)
            commit, digest = make_crs_checkout(root)
            sources = {
                "apache": make_apache_source(root),
                "haproxy": make_haproxy_source(root),
            }
            for connector in ("envoy", "lighttpd", "traefik"):
                sources[connector] = make_generic_source(
                    root, connector, f"crs-123-1-{connector}",
                    crs_commit=commit, crs_rule_sha=digest, parent_sha=HEAD,
                )
            artifact_root = root / "downloaded-cells"
            artifact_root.mkdir(mode=0o700)
            for connector in PROFILE.CONNECTORS:
                args = producer_args(root, connector, sources[connector])
                args.crs_commit, args.crs_rule_sha256 = commit, digest
                if connector == "haproxy":
                    verifier_context = mock.patch.object(
                        PROFILE.HAPROXY_PROJECTOR,
                        "verify_staged_package",
                        return_value={
                            "haproxy-runtime-evidence.json": args.haproxy_evidence_sha256,
                            "manifest.json": args.haproxy_manifest_sha256,
                        },
                    )
                else:
                    verifier_context = nullcontext()
                with verifier_context:
                    receipt = PROFILE.produce(args)
                self.assertEqual(receipt["technical_validation"], "PASS")
                shutil.copytree(args.output_dir, cell_directory(artifact_root, connector))
            result = AGGREGATE.aggregate(aggregate_args(
                root=artifact_root, output=root / "aggregate", crs_commit=commit,
                crs_rule_sha256=digest,
            ))
            self.assertTrue(result["summary"]["technical_validity"]["exact_five"])
            self.assertEqual(result["summary"]["functional_success"]["connector_count"], 5)

    def test_aggregate_rejects_missing_duplicate_and_foreign_cells(self):
        with tempfile.TemporaryDirectory(prefix="profile-shape-") as temporary:
            root = Path(temporary)
            for connector in PROFILE.CONNECTORS[:-1]:
                cell(root, connector)
            with self.assertRaises(ValueError):
                aggregate_with_args(root, root / "aggregate")
            shutil.copytree(cell_directory(root, "apache"), root / "extra")
            with self.assertRaises(ValueError):
                aggregate_with_args(root, root / "aggregate")

    def test_aggregate_rejects_renamed_foreign_evidence_directory(self):
        with tempfile.TemporaryDirectory(prefix="profile-foreign-directory-") as temporary:
            root = Path(temporary)
            for connector in PROFILE.CONNECTORS:
                cell(root, connector)
            cell_directory(root, "apache").rename(root / "foreign-evidence")
            with self.assertRaises(ValueError):
                aggregate_with_args(root, root / "aggregate")

    def test_aggregate_rejects_identity_and_binding_tampering(self):
        for field, value in (("parent_sha", "9" * 40), ("base_sha", "8" * 40),
                             ("profile_run_id", "with-crs-no-mrts-124-1"),
                             ("github_run_id", "124"), ("github_run_attempt", "2")):
            with self.subTest(field=field), tempfile.TemporaryDirectory(prefix="profile-identity-") as temporary:
                root = Path(temporary)
                for connector in PROFILE.CONNECTORS:
                    cell(root, connector)
                with self.assertRaises(ValueError):
                    aggregate_with_args(root, root / "aggregate", **{field: value})

    def test_aggregate_rejects_one_repacked_cell_with_conflicting_identity_or_provenance(self):
        mutations = (
            ("record_type", "unexpected_profile_receipt"),
            ("profile", "no-crs"),
            ("connector", "foreign"),
            ("parent_sha", "1" * 40),
            ("base_sha", "2" * 40),
            ("profile_run_id", "with-crs-no-mrts-124-1"),
            ("github_run_id", "124"),
            ("github_run_attempt", "2"),
            ("cell_run_id", "crs-123-1-foreign"),
            ("crs_commit", "3" * 40),
            ("crs_rule_sha256", "4" * 64),
        )
        for field, value in mutations:
            with self.subTest(field=field), tempfile.TemporaryDirectory(prefix="profile-mixed-cell-") as temporary:
                root = Path(temporary)
                for connector in PROFILE.CONNECTORS:
                    cell(root, connector)
                repack_cell(
                    cell_directory(root, "envoy"),
                    receipt_mutator=lambda receipt, field=field, value=value: receipt.__setitem__(field, value),
                )
                with self.assertRaises(ValueError):
                    aggregate_with_args(root, root / "aggregate")

    def test_aggregate_rejects_manifest_hash_source_path_and_link_attacks(self):
        with tempfile.TemporaryDirectory(prefix="profile-integrity-") as temporary:
            root = Path(temporary)
            for connector in PROFILE.CONNECTORS:
                cell(root, connector)
            manifest = cell_directory(root, "apache") / "manifest.json"
            value = json.loads(manifest.read_text())
            value["files"][0]["size_bytes"] += 1
            private_json(manifest, value)
            with self.assertRaises(ValueError):
                aggregate_with_args(root, root / "aggregate")
        with tempfile.TemporaryDirectory(prefix="profile-link-") as temporary:
            root = Path(temporary)
            for connector in PROFILE.CONNECTORS:
                cell(root, connector)
            target = root / "target"
            target.mkdir(mode=0o700)
            (root / "alias").symlink_to(target, target_is_directory=True)
            with self.assertRaises(ValueError):
                aggregate_with_args(root, root / "aggregate")

    def test_aggregate_rejects_repacked_source_bindings_and_noncanonical_receipts(self):
        receipt_mutations = (
            ("unsafe_source_path", lambda receipt: receipt["source_files"][0].__setitem__("path", "../source/result.json")),
            ("invalid_source_hash", lambda receipt: receipt["source_files"][0].__setitem__("sha256", "g" * 64)),
            ("wrong_source_hash", lambda receipt: receipt["source_files"][0].__setitem__("sha256", "0" * 64)),
            ("missing_source_binding", lambda receipt: receipt.__setitem__("source_files", [])),
        )
        for name, mutate in receipt_mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix="profile-source-binding-") as temporary:
                root = Path(temporary)
                for connector in PROFILE.CONNECTORS:
                    cell(root, connector)
                repack_cell(cell_directory(root, "apache"), receipt_mutator=mutate)
                with self.assertRaises(ValueError):
                    aggregate_with_args(root, root / "aggregate")
        for name, mutate in (
            (
                "duplicate_key",
                lambda raw: b'{"schema_version":1,' + raw[1:],
            ),
            (
                "noncanonical_whitespace",
                lambda raw: raw[:-1] + b" \n",
            ),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix="profile-noncanonical-") as temporary:
                root = Path(temporary)
                for connector in PROFILE.CONNECTORS:
                    cell(root, connector)
                receipt_path = cell_directory(root, "apache") / "profile-cell-receipt.json"
                receipt_path.write_bytes(mutate(receipt_path.read_bytes()))
                refresh_cell_manifest(cell_directory(root, "apache"))
                with self.assertRaises(ValueError):
                    aggregate_with_args(root, root / "aggregate")

    def test_aggregate_rejects_repacked_primitive_type_confusion(self):
        mutations = (
            (
                "receipt_schema_boolean",
                "apache",
                None,
                lambda receipt: receipt.__setitem__("schema_version", True),
                None,
            ),
            (
                "receipt_schema_float",
                "apache",
                None,
                lambda receipt: receipt.__setitem__("schema_version", 1.0),
                None,
            ),
            (
                "facts_schema_float",
                "apache",
                lambda facts: facts.__setitem__("schema_version", 1.0),
                None,
                None,
            ),
            (
                "facts_schema_boolean",
                "apache",
                lambda facts: facts.__setitem__("schema_version", True),
                None,
                None,
            ),
            (
                "manifest_schema_float",
                "apache",
                None,
                None,
                lambda manifest: manifest.__setitem__("schema_version", 1.0),
            ),
            (
                "manifest_size_float",
                "apache",
                None,
                None,
                lambda manifest: manifest["files"][0].__setitem__("size_bytes", float(manifest["files"][0]["size_bytes"])),
            ),
            (
                "block_status_float",
                "apache",
                lambda facts: facts["block"].__setitem__("http_status", 403.0),
                None,
                None,
            ),
            (
                "block_rule_float",
                "apache",
                lambda facts: facts["block"].__setitem__("rule_id", float(PROFILE.RULE_ID)),
                None,
                None,
            ),
            (
                "allow_status_float",
                "envoy",
                lambda facts: facts["allow_control"].__setitem__("http_status", 200.0),
                None,
                None,
            ),
            (
                "no_mrts_false_as_float_zero",
                "envoy",
                lambda facts: facts["no_mrts"]["flags"].__setitem__("mrts_runner_invoked", 0.0),
                None,
                None,
            ),
            (
                "receipt_no_mrts_false_as_float_zero",
                "envoy",
                None,
                lambda receipt: receipt["no_mrts"]["flags"].__setitem__("mrts_runner_invoked", 0.0),
                None,
            ),
            (
                "no_mrts_false_as_zero",
                "envoy",
                lambda facts: facts["no_mrts"]["flags"].__setitem__("mrts_runner_invoked", 0),
                None,
                None,
            ),
        )
        for name, connector, facts_mutator, receipt_mutator, manifest_mutator in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix="profile-type-confusion-") as temporary:
                root = Path(temporary)
                for expected_connector in PROFILE.CONNECTORS:
                    cell(root, expected_connector)
                directory = cell_directory(root, connector)
                repack_cell(
                    directory,
                    facts_mutator=facts_mutator,
                    receipt_mutator=receipt_mutator,
                )
                if manifest_mutator is not None:
                    manifest_path = directory / "manifest.json"
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    manifest_mutator(manifest)
                    private_json(manifest_path, manifest)
                with self.assertRaises(ValueError):
                    aggregate_with_args(root, root / "aggregate")

    def test_profile_rejects_minimal_generic_observation_and_preexisting_output(self):
        with tempfile.TemporaryDirectory(prefix="profile-produce-") as temporary:
            root = Path(temporary)
            source = root / "source"
            observation = source / "evidence" / "normalized" / "envoy" / "crs-123-1-envoy" / "runtime-observation.json"
            private_json(observation, {"schema_version": 1, "status": "PASS"})
            args = SimpleNamespace(connector="envoy", profile_run_id=RUN, cell_run_id="crs-123-1-envoy",
                                   parent_sha=HEAD, base_sha=BASE, github_run_id="123", github_run_attempt="1",
                                   framework_sha=FRAMEWORK, mrts_sha=MRTS, crs_commit=CRS, crs_rule_sha256=RULE_SHA,
                                   crs_source_root=root / "crs", verified_root=root / "verified", source_root=source,
                                   output_dir=root / "verified" / "profile-cell")
            with self.assertRaises((ValueError, OSError)):
                PROFILE.produce(args)
            args.source_root.mkdir(mode=0o700, exist_ok=True)
            args.verified_root.mkdir(mode=0o700)
            (args.verified_root / "profile-cell").mkdir(mode=0o700)
            with self.assertRaises(ValueError):
                PROFILE._create_output_directory(args.verified_root, args.output_dir)

    def test_no_crs_aggregator_remains_profile_specific_and_is_rejected_as_a_with_crs_cell(self):
        no_crs = load("no_crs_aggregate_static", source_path('ci/runtime/lifecycle/aggregate-five-connector-no-crs.py', root=ROOT))
        self.assertNotEqual(getattr(no_crs, "PROFILE", None), PROFILE.PROFILE)
        self.assertIn("no-crs", Path(source_path('ci/runtime/lifecycle/aggregate-five-connector-no-crs.py', root=ROOT)).read_text())
        no_crs_profile = load("no_crs_profile_fixture", source_path('ci/runtime/lifecycle/five-connector-no-crs-profile.py', root=ROOT))
        with tempfile.TemporaryDirectory(prefix="profile-no-crs-artifact-") as temporary:
            root = Path(temporary)
            for connector in PROFILE.CONNECTORS:
                if connector != "apache":
                    cell(root, connector)
            artifact = cell_directory(root, "apache")
            artifact.mkdir(mode=0o700)
            private_json(
                artifact / "profile-receipt.json",
                no_crs_profile.receipt_payload(
                    connector="apache",
                    run_id="no-crs-123",
                    connector_commit=HEAD,
                    framework_commit=FRAMEWORK,
                    cleanup_status="passed",
                ),
            )
            private_json(artifact / "result.json", {"profile": no_crs_profile.PROFILE, "status": "PASS"})
            private_json(artifact / "manifest.json", {"profile": no_crs_profile.PROFILE, "artifacts": {}})
            with self.assertRaises(ValueError):
                aggregate_with_args(root, root / "aggregate")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
