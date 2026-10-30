"""Validate NGINX contract acceptance independently of lifecycle qualification.

The caller supplies the immutable original selection and protected raw-evidence
root. This module verifies bindings and acceptance prerequisites; it does not
infer observations from filenames, manufacture measurements, or resolve oracles.
Lifecycle qualification remains an input from its own independent reviewer;
its hash-bound outcome independently determines whether the contract passed.
"""
from modsecurity_test_framework.connector_context import load_source

import copy
from collections import namedtuple
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat


SHA256 = re.compile(r"[0-9a-f]{64}")
CATALOG = load_source(Path(__file__).with_name('contract_catalog.py'))
SCOPES = {
    "configuration": "configuration_only",
    "preconnector_http_reject": "preconnector_http_reject_only",
    "lifecycle": "full_host_lifecycle",
    "derived": "derived_evidence_only",
    "source_not_applicable": "source_no_operation",
    "cycle_cleanup": "cycle_cleanup_only",
    "special": "special_contract_only",
}
REQUIRED = {
    "configuration_test": {"configuration_result": "configuration"},
    "config_open": {"configuration_result": "configuration", "sink_open_result": "sink_open"},
    "http400_before_allocation": {
        "client_status": "client", "allocation_count": "allocation_observer",
        "backend_request_count": "backend", "neighbor_result": "neighbor",
    },
    "lifecycle": {"native_lifecycle": "lifecycle_packet"},
    "derived_requirement": {"derivation_result": "derived_source"},
    "source_no_operation": {"source_operation_absent": "source"},
    "descriptor_cycle_cleanup": {
        "descriptor_close_result": "descriptor_observer", "cycle_cleanup_result": "cycle_cleanup",
    },
    "process_clean_shutdown": {
        "process_exit_result": "process_observer", "cycle_cleanup_result": "cycle_cleanup",
    },
    "allocation_begin_failure": {
        "allocation_failure_result": "allocation_observer", "client_result": "client",
        "cleanup_result": "cleanup", "neighbor_result": "neighbor",
    },
    "interrupted_missing_eos": {
        "eos_absent_result": "native_observer", "transport_result": "client",
        "cleanup_result": "cleanup", "neighbor_result": "neighbor",
    },
    "client_cancel": {
        "cancel_result": "client", "cleanup_result": "cleanup",
        "native_cancel_result": "native_observer", "neighbor_result": "neighbor",
    },
    "current_h1_campaign": {
        "campaign_result": "campaign", "current_revision_result": "host_identity",
        "framing_result": "client", "cleanup_result": "cleanup", "neighbor_result": "neighbor",
    },
}
NATIVE_OBSERVATIONS = frozenset({
    "native_lifecycle", "native_transaction_id", "native_eos", "native_finish",
    "native_free", "native_phases",
})
NATIVE_NA = frozenset({"native_transaction_id", "native_eos", "native_finish", "native_free"})
NONREQUEST_KINDS = frozenset({"configuration", "derived", "source_not_applicable", "cycle_cleanup"})


def canonical_digest(value):
    """Hash JSON without depending on key order or presentation whitespace."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def nonempty_text(value, label):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} requires nonempty text")
    return value


def verify_reference_ancestry(path, root):
    for component in (path, *path.parents):
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid not in (0, os.geteuid()):
            raise ValueError("evidence requires operator ownership without symlinks")
        transit = (component != path and not component.is_relative_to(root) and
                   info.st_uid == 0 and stat.S_ISDIR(info.st_mode) and
                   info.st_mode & stat.S_ISVTX)
        if info.st_mode & 0o022 and not transit:
            raise ValueError("evidence has writable ancestry")
        if component != path and not stat.S_ISDIR(info.st_mode):
            raise ValueError("evidence ancestry must be directories")


def verified_reference(reference, root):
    """Hash a regular, protected file without admitting symlink ancestry."""
    if not isinstance(reference, dict):
        raise ValueError("evidence reference must be an object")
    path = Path(nonempty_text(reference.get("path"), "evidence path"))
    digest = reference.get("sha256")
    if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
        raise ValueError("evidence requires a lowercase SHA256")
    nonempty_text(reference.get("role"), "evidence role")
    if (not path.is_absolute() or ".." in path.parts or str(path) != reference["path"] or
            path == root or not path.is_relative_to(root)):
        raise ValueError("evidence must be canonical and inside the protected root")
    verify_reference_ancestry(path, root)
    # O_NOFOLLOW and fstat also protect the final component during the read.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("evidence must be a regular file")
        hasher = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
        if hasher.hexdigest() != digest:
            raise ValueError("evidence SHA256 mismatch")
    return copy.deepcopy(reference)


def projected_requirements(rows):
    requirements = []
    full_requirements = []
    for row in rows:
        requirement = row.get("selected_requirement")
        if not isinstance(requirement, dict):
            raise ValueError("original selected requirement must be an object")
        public = copy.deepcopy(requirement)
        if not {"original_source_hashes_count", "original_source_hashes_set_sha256"} <= requirement.keys():
            hashes = public.pop("original_source_hashes", {})
            public["original_source_hashes_count"] = len(hashes)
            public["original_source_hashes_set_sha256"] = canonical_digest(hashes)
            full_requirements.append(requirement)
        requirements.append(public)
    return requirements, full_requirements


def verify_original_rows(rows, requirements):
    for row, public in zip(rows, requirements):
        case_id = row["run_scoped_case_id"]
        contract = CATALOG.CONTRACTS[case_id]
        requirement = row["selected_requirement"]
        if (requirement["run_scoped_case_id"] != case_id or
                canonical_digest(public) != contract["public_requirement_sha256"] or
                requirement["execution_kind"] != contract["original_execution_kind"]):
            raise ValueError("immutable original execution kind or requirement changed")
        if ("selected_requirement_sha256" in row and
                row["selected_requirement_sha256"] != contract["selected_requirement_sha256"]):
            raise ValueError("immutable original selected requirement SHA256 changed")


def original_selection(rows):
    """Check the actual original order, contracts, and execution classification."""
    if not isinstance(rows, list) or len(rows) != 140:
        raise ValueError("exactly 140 original NGINX selected rows required")
    ids = [row.get("run_scoped_case_id") for row in rows]
    requirements, full_requirements = projected_requirements(rows)
    if (canonical_digest(ids) != CATALOG.ORIGINAL_ORDERED_ID_SHA256 or
            canonical_digest(requirements) != CATALOG.PUBLIC_SELECTED_CONTRACT_SHA256):
        raise ValueError("immutable original ordered IDs or selected contracts changed")
    if full_requirements and (len(full_requirements) != 140 or
                             canonical_digest(full_requirements) != CATALOG.ORIGINAL_SELECTED_CONTRACT_SHA256):
        raise ValueError("immutable full original selected contracts changed")
    verify_original_rows(rows, requirements)
    return dict(zip(ids, rows))


def observations(record, roles):
    values = record.get("observations")
    na = record.get("not_applicable_observations")
    if not isinstance(values, dict) or not isinstance(na, dict):
        raise ValueError("observations and explicit N/A observations must be objects")
    if values.keys() & na.keys():
        raise ValueError("an observation cannot be measured and N/A")
    for name, reason in na.items():
        nonempty_text(name, "N/A observation")
        nonempty_text(reason, "N/A reason")
    for name, observation in values.items():
        nonempty_text(name, "observation")
        if not isinstance(observation, dict) or "value" not in observation:
            raise ValueError("observation requires an explicit value")
        refs = observation.get("evidence_roles")
        if (not isinstance(refs, list) or not refs or
                any(not isinstance(role, str) or role not in roles for role in refs)):
            raise ValueError("observation requires verified evidence roles")
    return values, na


def reviewed_lifecycle_packet(case_id, supplied, qualified, root):
    packet = supplied.get("lifecycle_packet")
    loaded = None
    outcome = None
    if qualified and not isinstance(packet, dict):
        raise ValueError("true lifecycle qualification requires an independent lifecycle packet")
    if packet is not None:
        if not isinstance(packet, dict):
            raise ValueError("independent lifecycle packet must be a reference")
        packet = verified_reference({**packet, "role": "lifecycle_packet"}, root)
        loaded = json.loads(Path(packet["path"]).read_text())
        if (not isinstance(loaded, dict) or loaded.get("run_scoped_case_id") != case_id or
                loaded.get("leg_id") != "nginx-native" or
                loaded.get("full_lifecycle_qualified") is not qualified):
            raise ValueError("independent lifecycle packet identity or qualification mismatch")
        outcome = loaded.get("outcome")
        if outcome not in ("PASS", "FAIL"):
            raise ValueError("independent lifecycle packet requires an explicit PASS/FAIL outcome")
    return packet, loaded, outcome


def verify_identity_fields(identity, qualified):
    nonempty_text(identity.get("run_id"), "independent run_id")
    for field in ("connection_id", "request_id", "transaction_id"):
        if field in identity:
            nonempty_text(identity[field], "independent " + field)
    if qualified:
        nonempty_text(identity.get("transaction_id"), "independent lifecycle transaction_id")


def verify_reviewed_identity(supplied, qualified, loaded, root):
    identity = supplied.get("physical_identity")
    if identity is not None:
        if not isinstance(identity, dict):
            raise ValueError("independent physical identity must be an object")
        verify_identity_fields(identity, qualified)
        request = identity.get("physical_request")
        if not isinstance(request, dict):
            raise ValueError("independent selected request reference required")
        verified_reference({**request, "role": "selected_request"}, root)
        if loaded is not None and loaded.get("run_id") != identity["run_id"]:
            raise ValueError("independent packet run differs from reviewed physical identity")
    if qualified and identity is None:
        raise ValueError("independent lifecycle requires reviewed physical identity")


def reviewed_binding(case_id, supplied, root):
    """Admit reviewer output through a separate, explicit trust boundary.

    The caller must construct this map from independent packet/client review,
    never from the acceptance record. Raw acceptance booleans and identity text
    cannot create qualification or another physical request.
    """
    if supplied is None:
        return {"full_lifecycle_qualified": False, "physical_identity": None,
                "lifecycle_packet": None, "lifecycle_outcome": None}
    if not isinstance(supplied, dict) or supplied.get("run_scoped_case_id") != case_id:
        raise ValueError("independent binding must identify the same original ID")
    if supplied.get("selected_requirement_sha256") != CATALOG.CONTRACTS[case_id][
            "selected_requirement_sha256"]:
        raise ValueError("independent binding original contract hash mismatch")
    qualified = supplied.get("full_lifecycle_qualified")
    if not isinstance(qualified, bool):
        raise ValueError("independent lifecycle qualification must be boolean")
    result = copy.deepcopy(supplied)
    packet, loaded, outcome = reviewed_lifecycle_packet(case_id, supplied, qualified, root)
    if packet is not None:
        result["lifecycle_packet"] = packet
    if "lifecycle_outcome" in supplied and supplied["lifecycle_outcome"] != outcome:
        raise ValueError("independent lifecycle outcome differs from hash-bound packet")
    result["lifecycle_outcome"] = outcome
    verify_reviewed_identity(supplied, qualified, loaded, root)
    result.setdefault("physical_identity", None)
    result.setdefault("lifecycle_packet", None)
    return result


def reviewed_external_parents(references, catalog):
    """Bind every nonselected parent to its own hash-verified review receipt.

    A generic source role or a caller-provided PASS label cannot replace the
    actual receipt's exact source identity, reviewed outcome, and oracle review.
    References have already passed the protected-path and SHA256 checks.
    """
    expected = {case_id for case_id in catalog["source_case_ids"]
                if case_id not in CATALOG.CONTRACTS}
    reviewed = set()
    for reference in references:
        if reference["role"] != "external_derived_source":
            continue
        parent = reference.get("source_case_id")
        if not isinstance(parent, str) or parent not in expected or parent in reviewed:
            raise ValueError("external derived evidence must bind each exact catalog parent once")
        try:
            receipt = json.loads(Path(reference["path"]).read_text())
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("external derived source requires a reviewed JSON receipt") from error
        if (not isinstance(receipt, dict) or receipt.get("run_scoped_case_id") != parent or
                receipt.get("outcome") != "PASS" or receipt.get("oracle_evaluated") is not True):
            raise ValueError("external derived receipt must bind the exact parent and reviewed PASS")
        nonempty_text(receipt.get("reviewed_by"), "external derived reviewer")
        reviewed.add(parent)
    if reviewed != expected:
        raise ValueError("each external derived parent requires its own hash-bound reviewed PASS")


def verify_record_identity(record, identity):
    for field in ("run_id", "connection_id", "request_id", "transaction_id"):
        if field in record and (identity is None or record[field] != identity.get(field)):
            raise ValueError("record identity differs from independent physical review")


def record_classification(record, catalog, binding):
    kind, subtype = catalog["contract_kind"], catalog["contract_subtype"]
    for field, expected in (("contract_kind", kind), ("contract_subtype", subtype),
                            ("original_execution_kind", catalog["original_execution_kind"])):
        if field in record and record[field] != expected:
            raise ValueError("record cannot relabel catalog " + field)
    if record.get("acceptance_scope") != SCOPES[kind]:
        raise ValueError("acceptance scope differs from catalog contract kind")
    status = record.get("status")
    if status not in ("PASS", "FAIL", "INCOMPLETE"):
        raise ValueError("unsupported contract acceptance status")
    qualified = binding["full_lifecycle_qualified"]
    outcome = binding["lifecycle_outcome"]
    if "full_lifecycle_qualified" in record and (
            not isinstance(record["full_lifecycle_qualified"], bool) or
            record["full_lifecycle_qualified"] != qualified):
        raise ValueError("record lifecycle boolean differs from independent review")
    if "lifecycle_outcome" in record and record["lifecycle_outcome"] != outcome:
        raise ValueError("record lifecycle outcome differs from independent review")
    if kind in ("configuration", "preconnector_http_reject", "source_not_applicable", "cycle_cleanup") and qualified:
        raise ValueError("non-native catalog contract cannot claim native lifecycle")
    identity = binding["physical_identity"]
    verify_record_identity(record, identity)
    return status, qualified, outcome, identity


RecordEvidence = namedtuple("RecordEvidence", "gaps references roles sources values na")


def record_evidence(record, root):
    gaps = record.get("remaining_contract_gaps")
    if not isinstance(gaps, list) or any(not isinstance(gap, str) or not gap.strip() for gap in gaps):
        raise ValueError("remaining contract gaps must be explicit text entries")
    if not isinstance(record.get("oracle_resolved"), bool):
        raise ValueError("explicit oracle resolution required")
    references = record.get("evidence_refs")
    if not isinstance(references, list):
        raise ValueError("evidence refs must be a list")
    references = [verified_reference(reference, root) for reference in references]
    roles = {reference["role"] for reference in references}
    sources = record.get("source_hashes")
    source_refs = {reference["path"]: reference["sha256"] for reference in references
                   if reference["role"] == "source"}
    if not isinstance(sources, dict) or sources != source_refs:
        raise ValueError("source hashes must exactly match verified source evidence")
    values, na = observations(record, roles)
    return RecordEvidence(gaps, references, roles, sources, values, na)


def verify_nonrequest_contract(kind, identity, roles, values, na):
    if kind in ("configuration", "preconnector_http_reject", "source_not_applicable", "cycle_cleanup"):
        if NATIVE_OBSERVATIONS & values.keys() or not NATIVE_NA.issubset(na):
            raise ValueError("non-native contract requires explicit native N/A")
    if kind in NONREQUEST_KINDS and "selected_request" in roles:
        raise ValueError("nonrequest contract cannot count a selected physical request")
    if kind in ("configuration", "source_not_applicable") and roles & {"client", "cleanup", "lifecycle_packet"}:
        raise ValueError("configuration/source-N/A cannot claim client or native cleanup evidence")
    if kind in ("configuration", "cycle_cleanup") and identity is not None:
        raise ValueError("configuration/cycle contract cannot claim a physical request identity")
    if kind == "source_not_applicable":
        if identity is not None or not {"selected_request", "client_result", "cleanup_result"}.issubset(na):
            raise ValueError("source-N/A requires request/client/cleanup N/A without physical identity")


def verify_request_binding(binding, identity, roles, references):
    if "lifecycle_packet" in roles:
        packet = binding.get("lifecycle_packet")
        if packet is None or any((ref["path"], ref["sha256"]) != (packet["path"], packet["sha256"])
                                for ref in references if ref["role"] == "lifecycle_packet"):
            raise ValueError("lifecycle evidence must equal the independently reviewed packet")
    requests = [ref for ref in references if ref["role"] == "selected_request"]
    if requests:
        physical = identity["physical_request"] if identity else None
        if physical is None or len(requests) != 1 or any(
                (ref["path"], ref["sha256"]) != (physical["path"], physical["sha256"]) for ref in requests):
            raise ValueError("selected request must equal independent physical request binding")
    return requests


def verify_derived_binding(record, kind, catalog, case_id, identity):
    if kind == "derived":
        expected = list(catalog["source_case_ids"])
        if "derived_from" in record and record["derived_from"] != expected:
            raise ValueError("derived parents must equal immutable original source IDs")
        if case_id in expected:
            if case_id not in CATALOG.SELF_ANCHORED_DERIVED_ROOTS or identity is None:
                raise ValueError("self-anchored derived root requires reviewed parent physical binding")
        elif identity is not None:
            raise ValueError("non-root derived row cannot manufacture a physical binding")


def verify_pass_measurements(subtype, values):
    for name, role in REQUIRED[subtype].items():
        if name not in values or role not in values[name]["evidence_roles"]:
            raise ValueError(f"PASS requires measured {name} with {role} evidence")
        expected_value = True if name in ("native_lifecycle", "source_operation_absent") else "PASS"
        if name not in ("client_status", "allocation_count", "backend_request_count") and (
                values[name]["value"] != expected_value or
                (expected_value is True and values[name]["value"] is not True)):
            raise ValueError("PASS requires successful " + name)


def verify_preconnector_pass(kind, subtype, references, values):
    if kind == "preconnector_http_reject":
        independent = []
        for role in REQUIRED[subtype].values():
            paths = {(Path(ref["path"]).stat().st_dev, Path(ref["path"]).stat().st_ino)
                     for ref in references if ref["role"] == role}
            if any(paths & previous for previous in independent):
                raise ValueError("preconnector observers require independent raw evidence files")
            independent.append(paths)
        for name, expected_value in (("client_status", 400), ("allocation_count", 0),
                                     ("backend_request_count", 0)):
            if type(values[name]["value"]) is not int or values[name]["value"] != expected_value:
                raise ValueError("preconnector PASS requires HTTP400 and zero allocation/backend")


def verify_derived_pass(case_id, kind, binding, references, catalog):
    qualified, outcome = binding["full_lifecycle_qualified"], binding["lifecycle_outcome"]
    if kind == "derived":
        reviewed_external_parents(references, catalog)
        if case_id in CATALOG.SELF_ANCHORED_DERIVED_ROOTS and (
                not qualified or outcome != "PASS" or binding["lifecycle_packet"] is None):
            raise ValueError("self-anchored derived PASS requires an independently "
                             "qualified parent packet outcome PASS")


def verify_pass_contract(record, original, binding, catalog, evidence, requests):
    if record["status"] != "PASS":
        return
    case_id = original["run_scoped_case_id"]
    kind, subtype = catalog["contract_kind"], catalog["contract_subtype"]
    qualified, outcome = binding["full_lifecycle_qualified"], binding["lifecycle_outcome"]
    gaps, references, roles, sources, values, _ = evidence
    if gaps or record["oracle_resolved"] is not True:
        raise ValueError("PASS forbidden with gaps or unresolved oracle")
    if not references or not sources:
        raise ValueError("PASS requires raw evidence and hash-bound sources")
    verify_derived_pass(case_id, kind, binding, references, catalog)
    if (original["selected_requirement"]["expected_oracle"].get(
            "unresolved_expected_value_reason") and "oracle_resolution" not in roles):
        raise ValueError("original unresolved oracle requires hash-bound resolution evidence")
    verify_pass_measurements(subtype, values)
    if kind == "lifecycle" and not qualified:
        raise ValueError("lifecycle PASS requires independent full lifecycle qualification")
    if kind == "lifecycle" and outcome != "PASS":
        raise ValueError("lifecycle contract PASS requires independent packet outcome PASS")
    verify_preconnector_pass(kind, subtype, references, values)
    if kind in ("preconnector_http_reject", "lifecycle", "special") and not requests:
        raise ValueError("host PASS requires independently bound selected request evidence")


def acceptance_record(record, original, binding, root):
    """Validate acceptance using catalog classification and reviewer bindings."""
    case_id = original["run_scoped_case_id"]
    catalog = CATALOG.CONTRACTS[case_id]
    if record.get("selected_requirement_sha256") != catalog["selected_requirement_sha256"]:
        raise ValueError("immutable selected requirement SHA256 mismatch")
    kind, subtype = catalog["contract_kind"], catalog["contract_subtype"]
    status, qualified, outcome, identity = record_classification(record, catalog, binding)
    evidence = record_evidence(record, root)
    _, references, roles, _, values, na = evidence
    verify_nonrequest_contract(kind, identity, roles, values, na)
    requests = verify_request_binding(binding, identity, roles, references)
    verify_derived_binding(record, kind, catalog, case_id, identity)
    verify_pass_contract(record, original, binding, catalog, evidence, requests)
    normalized = copy.deepcopy(record)
    normalized.update(contract_kind=kind, contract_subtype=subtype,
                      original_execution_kind=catalog["original_execution_kind"],
                      full_lifecycle_qualified=qualified, lifecycle_outcome=outcome)
    if kind == "derived":
        normalized["derived_from"] = list(catalog["source_case_ids"])
    return {"run_scoped_case_id": case_id, "contract_kind": kind, "contract_subtype": subtype,
            "contract_acceptance": status, "acceptance_scope": SCOPES[kind],
            "full_lifecycle_qualified": qualified, "lifecycle_outcome": outcome,
            "independently_reviewed": copy.deepcopy(binding),
            "record": normalized}


def protected_evidence_root(evidence_root):
    root = Path(evidence_root)
    if not root.is_absolute() or not root.is_dir() or root.resolve(strict=True) != root:
        raise ValueError("canonical existing protected evidence root required")
    info = root.lstat()
    if info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
        raise ValueError("evidence root must be operator-owned and protected")
    return root


def admit_physical_request(result, identity, physical_requests, native_transactions):
    if result["contract_acceptance"] == "PASS" and result["contract_kind"] not in NONREQUEST_KINDS:
        physical = identity["physical_request"]
        key = (identity["run_id"], physical["path"], physical["sha256"])
        if key in physical_requests:
            raise ValueError("independent physical request cannot accept multiple original IDs")
        transaction = identity.get("transaction_id")
        if transaction is not None:
            native_key = (identity["run_id"], transaction)
            if native_key in native_transactions:
                raise ValueError("independent native transaction cannot accept multiple original IDs")
            native_transactions.add(native_key)
        physical_requests.add(key)


def collect_acceptance(records, selected, bindings, root):
    accepted, physical_requests, native_transactions = {}, set(), set()
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("acceptance record must be an object")
        case_id = record.get("run_scoped_case_id")
        if case_id not in selected or case_id in accepted:
            raise ValueError("unknown or duplicate original acceptance ID")
        result = acceptance_record(record, selected[case_id], bindings[case_id], root)
        identity = bindings[case_id]["physical_identity"]
        admit_physical_request(result, identity, physical_requests, native_transactions)
        accepted[case_id] = result
    return accepted, physical_requests


def review_derivation(case_id, visiting, accepted, selected, reviewed_derivations):
    if case_id in reviewed_derivations:
        return
    result = accepted.get(case_id)
    if result is None or result["contract_acceptance"] != "PASS":
        raise ValueError("derived PASS requires accepted original parent contracts")
    if case_id in visiting:
        raise ValueError("derived PASS cannot have circular parent contracts")
    if result["contract_kind"] == "derived":
        for parent in result["record"]["derived_from"]:
            if parent == case_id and case_id in CATALOG.SELF_ANCHORED_DERIVED_ROOTS:
                continue
            if parent in selected:
                review_derivation(parent, visiting | {case_id}, accepted, selected, reviewed_derivations)
            # Nonselected parents were independently bound to exact
            # reviewed receipts while accepting this derived record.
    reviewed_derivations.add(case_id)


def verify_derivations(accepted, selected):
    reviewed_derivations = set()

    for case_id, result in accepted.items():
        if result["contract_kind"] == "derived" and result["contract_acceptance"] == "PASS":
            review_derivation(case_id, set(), accepted, selected, reviewed_derivations)


def build_acceptance(selected_rows, records, *, evidence_root, independently_reviewed):
    """Validate actual original contracts without manufacturing physical requests."""
    selected = original_selection(selected_rows)
    root = protected_evidence_root(evidence_root)
    if not isinstance(independently_reviewed, dict) or any(
            case_id not in selected for case_id in independently_reviewed):
        raise ValueError("independent review must map only original selected IDs")
    bindings = {case_id: reviewed_binding(case_id, independently_reviewed.get(case_id), root)
                for case_id in selected}
    accepted, physical_requests = collect_acceptance(records, selected, bindings, root)
    verify_derivations(accepted, selected)
    rows = [accepted.get(case_id, {
        "run_scoped_case_id": case_id, "contract_kind": CATALOG.CONTRACTS[case_id]["contract_kind"],
        "contract_subtype": CATALOG.CONTRACTS[case_id]["contract_subtype"],
        "contract_acceptance": "INCOMPLETE", "full_lifecycle_qualified": bindings[case_id]["full_lifecycle_qualified"],
        "lifecycle_outcome": bindings[case_id]["lifecycle_outcome"],
        "remaining_contract_gaps": ["no contract acceptance record"],
    }) for case_id in selected]
    return {"schema_version": 1, "profile": "nginx-native",
            "original_ordered_id_sha256": CATALOG.ORIGINAL_ORDERED_ID_SHA256,
            "original_selected_contract_sha256": CATALOG.ORIGINAL_SELECTED_CONTRACT_SHA256,
            "summary": {"original_ids": 140, "contract_pass": sum(
                row["contract_acceptance"] == "PASS" for row in rows),
                "selected_physical_requests": len(physical_requests)}, "rows": rows}
