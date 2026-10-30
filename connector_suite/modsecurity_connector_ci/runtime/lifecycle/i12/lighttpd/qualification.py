"""Adapt reviewed lighttpd proposals to the existing I12 qualification contracts.

This module does not create measurements or infer expectations. Worker proposals
remain unreviewed until a separate exact-file Root review authorizes evaluation.
Inherited exports are read-only; current results are written to a new directory.
"""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import copy
import importlib.util
import json
import os
from pathlib import Path
import stat


UNCONFIGURED_EXTERNAL_ROOT = Path("/__i12_external_root_requires_I12_TEST_ROOT__")


def configured_external_root():
    """Resolve the declared test root without touching it during module import."""
    declared = os.environ.get("I12_TEST_ROOT")
    if declared:
        return Path(declared).absolute()
    return UNCONFIGURED_EXTERNAL_ROOT


def storage_root(root=None):
    """Validate the configured private evidence root when it is actually used."""
    root = Path(root or globals().get("EXTERNAL_ROOT", configured_external_root())).absolute()
    if root == UNCONFIGURED_EXTERNAL_ROOT:
        raise ValueError("Set I12_TEST_ROOT to an existing private evidence directory")
    for parent in (root.parent, root):
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o022):
            raise ValueError(
                "Evidence storage must be an existing current-user-owned directory without shared write access")
    return root


REPOSITORY = connector_root()
BASELINE = REPOSITORY / "reports/testing/lighttpd-i12-20261015"
ROUTES = ("lighttpd-stock-sidecar", "lighttpd-patched-native", "lighttpd-stock-native-control")
EXTERNAL_ROOT = configured_external_root()
LEDGER = load_source(REPOSITORY / 'ci/evidence/reports/generate-pr382-i12-lifecycle-ledger.py')
ORACLES = LEDGER.ORACLES
SOURCES = load_source(Path(__file__).with_name('ledger.py'))
LOADED_SOURCES = {
    str(Path(module.__file__).absolute()): SOURCES.snapshot(Path(module.__file__))
    for module in (LEDGER, ORACLES, SOURCES)
}
LOADED_SOURCES[str(Path(__file__).absolute())] = SOURCES.snapshot(Path(__file__))


def reference(path, role=None, **metadata):
    path = Path(path).absolute()
    readable = (EXTERNAL_ROOT, REPOSITORY, test_root(), Path("/usr"))
    if (".." in path.parts or any(part in (".git", ".aws", ".ssh") for part in path.parts)
            or not any(path.is_relative_to(root) for root in readable)):
        raise ValueError("Evidence must belong to the approved repository, external run or installed image roots")
    if path.is_relative_to(EXTERNAL_ROOT):
        storage_root(EXTERNAL_ROOT)
    result = SOURCES.reference(path)
    if role is not None:
        result["role"] = role
    result.update(metadata)
    return result


def original_row(case_id, baseline_dir=BASELINE):
    parts = case_id.split("::")
    if len(parts) != 3 or parts[0] != "I12" or parts[1] not in ROUTES:
        raise ValueError("Expected an exact original lighttpd ID")
    source = Path(baseline_dir) / (parts[1] + "-cases.json")
    rows = json.loads(source.read_text())["rows"]
    matches = [row for row in rows if row["run_scoped_case_id"] == case_id]
    if len(matches) != 1:
        raise ValueError("Original ID is absent or ambiguous")
    return matches[0]


def packet_template(case_id, identity):
    row = original_row(case_id)
    return {
        "run_scoped_case_id": case_id,
        "leg_id": row["leg_id"],
        "reviewed_by": "worker",
        "execution_kind": "host_http",
        "execution_observed": False,
        **identity,
        "observations": {
            field: {"value": None, "reason": "No physical measurement supplied for " + field}
            for field in LEDGER.ROLES
        },
        "oracle_evaluated": False,
        "outcome": None,
        "full_lifecycle_qualified": False,
    }


def _read_physical(path):
    ref = reference(path)
    raw, actual = SOURCES.snapshot(Path(ref["path"]))
    if actual != ref:
        raise ValueError("Evidence changed while loading its JSON snapshot")
    return json.loads(raw), ref


def _exclusive_json(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def frozen_qualifier_sources(destination):
    """Keep exact validator bytes even when the shared branch advances later."""
    directory = destination / "qualifier-sources"
    directory.mkdir(mode=0o700)
    result = []
    for original, (raw, loaded_ref) in LOADED_SOURCES.items():
        if SOURCES.snapshot(Path(original)) != (raw, loaded_ref):
            raise ValueError("Loaded qualification source changed during this evaluation")
        target = directory / (loaded_ref["sha256"] + ".py")
        if not target.exists():
            with target.open("xb") as stream:
                stream.write(raw)
            target.chmod(0o444)
        result.append({**reference(target, "qualification_source"), "original_source_path": original})
    return result


def loaded_source_digests():
    return {path: ref["sha256"] for path, (_, ref) in LOADED_SOURCES.items()}


def verify_qualifier_sources(result, root_review):
    """Bind retained validator bytes to the exact separate Root source approval."""
    approved = root_review.get("qualifier_source_sha256", {})
    refs = result.get("qualifier_sources", [])
    if (set(approved) != set(LOADED_SOURCES) or len(refs) != len(approved)
            or {ref.get("original_source_path") for ref in refs} != set(approved)):
        raise ValueError("Qualification sources need exact separately Root-approved identities")
    for ref in refs:
        actual = ORACLES.verify_reference(ref)
        if (ref.get("role") != "qualification_source"
                or actual["sha256"] != approved[ref["original_source_path"]]):
            raise ValueError("Executed qualification source differs from Root source approval")


def reviewed_proposal(proposal, review):
    """Apply only separately hash-bound Root decisions to a worker proposal."""
    packet = copy.deepcopy(proposal)
    packet["reviewed_by"] = "root"
    if packet.get("execution_kind") == "host_pre_native_rejection":
        approval_ref = review.get("pre_native_source_approval")
        if approval_ref is None or review.get("pre_native_outcome") != "PASS":
            raise ValueError("Pre-native qualification needs exact separate Root source and outcome review")
        approval, actual = _read_physical(approval_ref["path"])
        if actual["sha256"] != approval_ref.get("sha256") or approval != packet.get("source_approval"):
            raise ValueError("Pre-native source approval changed after Root review")
        packet["source_approval"]["reviewed_by"] = "root"
        packet["outcome"] = "PASS"
    return packet


def packet_validator(packet):
    validators = {"host_http": LEDGER.reviewed_packet,
                  "configuration_parser": LEDGER.reviewed_configuration_packet,
                  "host_pre_native_rejection": LEDGER.reviewed_pre_native_packet}
    try:
        return validators[packet.get("execution_kind")]
    except KeyError as exc:
        raise ValueError("No selected lighttpd execution-kind validator") from exc


def qualification_destination(output_dir):
    destination = Path(output_dir)
    external = destination.absolute().is_relative_to(EXTERNAL_ROOT)
    if (".." in destination.parts or not (external
            or destination.absolute().is_relative_to(REPOSITORY / "reports/testing"))):
        raise ValueError("Qualification output must belong to the external run or testing report root")
    if external:
        storage_root(EXTERNAL_ROOT)
    if destination.exists() or destination.is_symlink():
        raise ValueError("Current qualification output must be a fresh physical directory")
    for parent in destination.absolute().parents:
        if parent.is_symlink():
            raise ValueError("Symlink qualification output parent")
    destination.mkdir(parents=True, mode=0o700)
    return destination


def qualify(packet_proposal_path, oracle_record_path, root_review_path, output_dir):
    """Require a separate Root review, then call the unchanged shared validators."""
    packet, packet_ref = _read_physical(packet_proposal_path)
    record, record_ref = _read_physical(oracle_record_path)
    review, review_ref = _read_physical(root_review_path)
    case_id = packet["run_scoped_case_id"]
    row = original_row(case_id)
    if record.get("run_scoped_case_id") != case_id:
        raise ValueError("Oracle proposal cannot transfer between original IDs")
    if (review.get("reviewed_by") != "root" or review.get("run_scoped_case_id") != case_id
            or review.get("packet_sha256") != packet_ref["sha256"]
            or review.get("oracle_record_sha256") != record_ref["sha256"]
            or not review.get("independent_oracle_review")
            or not review.get("physical_transaction_review")
            or review.get("qualifier_source_sha256") != loaded_source_digests()):
        raise ValueError("Separate Root review must bind both exact proposals and their evidence")
    record = copy.deepcopy(record)
    record["reviewed_by"] = "root"
    if record.get("approved_correction") is not None:
        record["approved_correction"]["reviewed_by"] = "root"
    oracle_review = ORACLES.review_record(record, row)
    if not oracle_review["resolved"] or oracle_review["category"] == "UNSUPPORTED_CAPABILITY":
        raise ValueError("A qualified host verdict requires a resolved applicable oracle")
    packet = reviewed_proposal(packet, review)
    destination = qualification_destination(output_dir)
    packet_path = destination / "reviewed-packet.json"
    _exclusive_json(packet_path, packet)
    validator = packet_validator(packet)
    result = validator(reference(packet_path), row, oracle_review["effective_oracle"])
    _exclusive_json(destination / "oracle-review.json", oracle_review)
    _exclusive_json(destination / "root-reviewed-record.json", record)
    verdict = {
        "run_scoped_case_id": case_id,
        "leg_id": row["leg_id"],
        "original_row_sha256": row["original_row_sha256"],
        "root_review": review_ref,
        "proposal": packet_ref,
        "oracle_proposal": record_ref,
        "oracle_review": oracle_review,
        "qualifier_sources": frozen_qualifier_sources(destination),
        "qualifier": result,
        "status": result["outcome"] if result.get("full_case_qualified", result["full_lifecycle_qualified"]) else "PARTIAL_HOST_MEASUREMENTS",
        "new_evidence_refs": [reference(packet_path), review_ref, packet_ref, record_ref],
    }
    _exclusive_json(destination / "qualification.json", verdict)
    return verdict
