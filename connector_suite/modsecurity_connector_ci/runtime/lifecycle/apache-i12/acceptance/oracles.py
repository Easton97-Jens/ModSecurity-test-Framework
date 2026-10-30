#!/usr/bin/env python3
"""Independent source review for the original Apache54; never qualify execution.

This module produces unsigned proposals, retaining every original contract.
Root must review an explicit proposal and its sources before the unchanged
shared reconciliation validator can accept it. Runtime observations are absent.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import argparse
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

APACHE_IDS_SHA256 = "4c660ea9f259f43f13b5b3c7e1e09815a65d537dd5dcddfce446ee0183468c73"
APACHE_CONTRACTS_SHA256 = "2a470a552e424d149b601b11040694e79ff8f03d9421838c37dae51d823e2c33"
ORIGINAL54_SHA256 = "0eaa47211bc4d6b622af0d78988700b132298d895c955111668ccfabf3e2c1f4"
SDK_SHA256 = "328ffa3b4517f0242450293a916aba4f512b4defc3bd1fcc7465e0778adc725c"
FORMER_HISTORY_OBJECTS_SHA256 = "776ac0cc86d780b2a6a1f77434ae098ca1ae4edfacbb19295e12383c5a95e342"
FORMER_HISTORY_CONTRACT_SHA256 = "a55494356b983ab1829e2c1ea863d81b3eba2660b48bc25044d7a030baca8cb9"
REQUEST_ALLOW = frozenset((
    "NEED-request-empty", "NEED-request-single-chunk", "NEED-request-file",
    "NEED-request-content-type-present", "NEED-request-content-type-missing",
    "NEED-request-charset-present", "NEED-request-charset-missing",
    "NEED-request-csv", "NEED-request-eos-once"))
RESPONSE_ALLOW = frozenset(("NEED-response-file", "NEED-response-csv"))
REQUEST_DENY = frozenset(("NEED-request-streaming", "NEED-request-marker-at-payload-end"))
RESPONSE_DENY = frozenset(("NEED-response-streaming", "NEED-response-marker-at-payload-end"))
ABNORMAL = frozenset(("NEED-missing-eos", "NEED-cancel", "NEED-client-exit-signal",
                      "NEED-incomplete-framing", "NEED-abort-reset-observation"))
UNDEFINED = frozenset(("NEED-request-mime-scope-in", "NEED-request-mime-scope-out",
                       "NEED-request-above-former-connector-limit",
                       "NEED-response-above-former-connector-limit"))
SINK_CASES = {
    "E2E-APACHE-INVALID-EVENT-PATH": ("badpath", "Common_POSIX_parent_open", 2),
    "E2E-APACHE-UNSAFE-DEVFULL": ("devfull", "Common_regular_file_validation", 22),
    "E2E-APACHE-UNWRITABLE-EVENT-SINK": ("unwritable", "Common_POSIX_leaf_open", 13),
    "E2E-APACHE-SINK-CLOSED-DESCRIPTOR": ("closed-descriptor", "apr_file_write_full", 9),
    "E2E-APACHE-SINK-PHYSICAL-ENOSPC": ("physical-enospc", "apr_file_write_full", 28),
}
LIMIT_CASES = frozenset(("phase2_truncated", "phase4_body_at_limit",
    "phase4_body_over_limit", "phase4_body_process_partial", "phase4_body_reject"))
HISTORICAL = {
    "E2E-APACHE-ALLOW": ("allow", 200, 1, 120001, 1),
    "E2E-APACHE-EMPTY-EOS": ("allow", 200, 2, None, 1),
    "E2E-APACHE-ONE-EOS": ("allow", 200, 2, None, 1),
    "E2E-APACHE-MULTI-EOS": ("allow", 200, 4, None, 1),
    "E2E-APACHE-P1-DENY": ("deny", 403, 1, 120011, 0),
    "E2E-APACHE-P2-DENY": ("deny", 403, 2, 120012, 0),
    "E2E-APACHE-P3-DENY": ("deny", 403, 3, 120013, 1),
    "E2E-APACHE-P3-REDIRECT": ("redirect", 302, 3, 120014, 1),
    "E2E-APACHE-P4-SAFE-LATE": ("deny", 200, 4, 120015, 1),
    "E2E-APACHE-P4-STRICT-LATE": ("deny", 200, 4, 120015, 1),
    "E2E-APACHE-MIME-SCOPEOUT": ("allow", 200, 4, None, 1),
    "E2E-APACHE-MISSING-CHARSET": ("allow", 200, 4, None, 1),
    "E2E-APACHE-MISSING-CONTENT-TYPE": ("allow", 200, 4, None, 1),
    "E2E-APACHE-WITH-CHARSET": ("allow", 200, 4, None, 1),
    "E2E-APACHE-TECHNICAL-PRECOMMIT": ("technical_error", 500, 1, None, 0),
    "E2E-APACHE-TECHNICAL-POSTCOMMIT": ("technical_error", 200, 4, None, 1),
}


def digest(value):
    content = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(content.encode()).hexdigest()


def reference(path, kind, revision, **extra):
    supplied = Path(path).absolute()
    if supplied.resolve(strict=True) != supplied or not supplied.is_file():
        raise ValueError("Source must be a physical regular nonsymlink file")
    content = supplied.read_bytes()
    return {"path": str(supplied), "sha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content), "kind": kind, "revision": revision, **extra}


def independent_sdk(path):
    result = reference(path, "native_engine_contract", "ModSecurity v3.0.14",
        upstream="https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3.0.14/src/transaction.cc")
    if result["sha256"] != SDK_SHA256:
        raise ValueError("Native oracle source is not the reviewed exact SDK3.0.14 source")
    return result


def load_shared():
    source = source_path('ci') / "evidence/reports/generate-pr382-i12-oracle-reconciliation.py"
    module = load_source(source)
    return module


def intervention_status(result):
    return {"deny": 403, "redirect": 302}.get(result)


def proposed_oracle(result, status, phase, rule=None, backend=None):
    return {"native_result": result, "visible_status": status, "rule_id": rule,
            "phase": phase, "native_intervention_status": intervention_status(result), "event_fields": [], "physical_evidence_not_projection": True,
            "unresolved_expected_value_reason": None, "backend_requests": backend}


def basic_proposal(case_id):
    if case_id in REQUEST_ALLOW:
        return proposed_oracle("allow", 200, 2, backend=1)
    if case_id in RESPONSE_ALLOW:
        return proposed_oracle("allow", 200, 4, backend=1)
    if case_id in REQUEST_DENY:
        return proposed_oracle("deny", 403, 2, 1100101, 0)
    if case_id in RESPONSE_DENY:
        return proposed_oracle("deny", 200, 4, 1100301, 1)
    if case_id == "NEED-neighbor-connection-stream":
        return proposed_oracle("allow", 200, 4, backend=1)
    if case_id in HISTORICAL:
        return proposed_oracle(*HISTORICAL[case_id])
    return None


def declared_body(value):
    """Validate declared fixture bytes without consulting any observed result."""
    try:
        content = base64.b64decode(value["data"], validate=True)
        if len(content) != value["bytes"] or hashlib.sha256(content).hexdigest() != value["sha256"]:
            raise ValueError("Declared fixture byte identity mismatch")
    except (KeyError, TypeError) as error:
        raise ValueError("Declared fixture body is incomplete") from error
    return content


def validate_former_history(proof):
    receipt = proof["source_history_receipt"]
    physical = reference(receipt["path"], "source_history", "retained independently reviewed history")
    if any(physical[key] != receipt.get(key) for key in ("sha256", "bytes")):
        raise ValueError("Former-limit history receipt identity mismatch")
    history = json.loads(Path(physical["path"]).read_text()).get("former_limit_history", {})
    objects = history.get("source_objects", [])
    object_identity = sorted(tuple(item.get(key) for key in
        ("revision", "repository_path", "git_blob_oid", "sha256")) for item in objects)
    if (history.get("default_bytes") != 1048576 or history.get("max_config_bytes") != 10485760
            or len(objects) != 9 or len({item.get("git_blob_oid") for item in objects}) != 9
            or {item.get("direction") for item in objects} != {"request", "response"}
            or digest(object_identity) != FORMER_HISTORY_OBJECTS_SHA256
            or digest(history) != FORMER_HISTORY_CONTRACT_SHA256
            or any(not item.get("selected_lines") for item in objects)):
        raise ValueError("Former-limit history lacks the nine exact source objects")


def former_limit_proposal(case_id, plan):
    direction = "request" if "request" in case_id else "response"
    target = plan.get("request" if direction == "request" else "backend", {})
    proof = plan.get("former_limit_proof", {})
    facts = ["former_limit_history", "sdk_raw_append", "sdk_response_limit", "exact_fixture_rules"]
    if not target.get("body") or not proof.get("source_history_receipt"):
        return None, facts, ["Bind the nine retained historical Git objects,10MiB+1 payload and explicit16MiB SDK allowance; old2MiB+1 exceeds only the former default."]
    validate_former_history(proof)
    content = declared_body(target["body"])
    marker = b"no-crs-" + direction.encode() + b"-body-marker"
    if len(content) != 10485761 or not content.endswith(marker):
        return None, facts, ["Former-maximum variant requires exactly10MiB+1 with the unchanged marker at its payload end."]
    rules = plan.get("rules", "").splitlines()
    if "Sec%sBodyLimit 16777216" % direction.capitalize() not in rules:
        return None, facts, ["Explicit16MiB native allowance is not independently bound in the declared rules."]
    if direction == "request" and "SecRequestBodyNoFilesLimit 16777216" not in rules:
        return None, facts, ["The independent non-file request limit must also allow the full10MiB+1 body."]
    if direction == "response" and plan.get("apache", {}).get("phase4_mode") not in ("safe", "strict"):
        return None, facts, ["Historical response ceiling applied to Safe/Strict; Off used SIZE_MAX and cannot prove removal of that ceiling."]
    proposal = proposed_oracle("deny", 403 if direction == "request" else 200,
                               2 if direction == "request" else 4,
                               1100101 if direction == "request" else 1100301,
                               0 if direction == "request" else 1)
    proposal["former_limit_contract"] = {
        "old_default_bytes": 1048576, "old_max_config_bytes": 10485760,
        "declared_payload_bytes": len(content), "native_limit_bytes": 16777216,
        "history_source_receipt": copy.deepcopy(proof["source_history_receipt"]),
        "history_objects_require_independent_review": 9,
        "tail_marker_is_rule_source_not_runtime_match": True}
    return proposal, facts, []


def request_mime_proposal(case_id, plan):
    request = plan.get("request", {})
    mime = "text/plain" if case_id.endswith("-in") else "image/png"
    facts = ["sdk_request_processor", "sdk_request_unknown_format", "sdk_request_bytes", "exact_fixture_rules"]
    headers = [(name.lower(), value) for name, value in request.get("headers", [])]
    if ("content-type", mime) not in headers or not request.get("body"):
        return None, facts, ["Bind the actual request MIME and raw bytes; no request MIME allowlist may be inferred from response configuration."]
    body = declared_body(request["body"])
    if body != b"Apache-I12-request-payload":
        return None, facts, ["Request MIME proposal is limited to the declared marker-free raw payload; changed bytes require independent rule review."]
    proposal = proposed_oracle("allow", 200, 2, backend=1)
    proposal["request_processor_contract"] = {
        "content_type": mime, "selected_body_type": "UnknownFormat",
        "raw_body_available_to_phase2": True, "request_mime_allowlist": None,
        "interpretation": "Both types append raw bytes and reach RequestBodyPhase; neither selects MULTIPART/URLENCODED. This does not prove a request allowlist in/out behavior."}
    return proposal, facts, ["Original scope-in/out terminology requires explicit Root interpretation as SDK processor/raw-ingest behavior, retaining the original obligation."]


def historical_sink_proposal(case_id, plan):
    mode, stage, code = SINK_CASES[case_id]
    facts = ["apache_sink_stages", "private_file_admission", "common_private_file_errno",
             "apache_nonmandatory_rule_match", "apache_mandatory_sink_500", "exact_fixture_rules"]
    rules = plan.get("rules", "")
    if (plan.get("request", {}).get("path") != "/sink-disruptive"
            or plan.get("fault", {}).get("kind") != mode
            or "id:120001,phase:1,pass,log" not in rules
            or "id:120016,phase:1,deny,status:403,log" not in rules):
        return None, facts, ["Bind unchanged native120001 pass/log before120016 deny403 and the exact physical sink fault; configured rule alone is insufficient."]
    if rules.index("id:120001,") > rules.index("id:120016,"):
        return None, facts, ["Reordered120016-before120001 cannot reconcile the original fixture."]
    proposal = proposed_oracle("deny", 500, 1, 120016, 0)
    proposal["host_result"] = "technical_error"
    proposal["sink_first_cause"] = {"operation": stage, "errno_or_apr_status": code,
        "error_domain": "Common_POSIX" if mode in ("badpath", "devfull", "unwritable") else "APR",
        "rule120001_is_separate_nonmandatory_match": True,
        "native120016_status": 403, "mandatory_event_failed": True,
        "renderer_status": 500, "requires_real_operation_not_mock_return": True}
    proposal["conditional_on"] = predicates(case_id) + [
        "native120001 remains before120016; the nonmandatory pass/log failure latches sink state without inventing a disruptive native decision",
        "actual matched120016 deny403 and mandatory sink failure precede uncommitted Apache renderer500",
        "unwritable means the selected effective UID genuinely lacks directory write permission; privileged bypass cannot qualify",
        "ENOSPC variant is the real write to a /dev/full-rebound descriptor, not a claim of filesystem exhaustion"]
    return proposal, facts, ["Require actual native120016 audit separately from120001 and the first physical Common/POSIX or APR failure. The source candidate does not activate the fault or erase the historical failure."]


def prepared_proposal(case_id, plan):
    if case_id in SINK_CASES:
        return historical_sink_proposal(case_id, plan)
    if case_id in UNDEFINED:
        if "mime-scope" in case_id:
            return request_mime_proposal(case_id, plan)
        return former_limit_proposal(case_id, plan)
    return None, [], []


def predicates(case_id):
    """Each extra contract remains a separately measured obligation."""
    result = ["exact current source/build/SDK/config/rules/UID/run identity",
              "unique principal transaction with independent client/native/backend joins",
              "physical native audit and JSONL, actual host commit/EOS and once cleanup",
              "controls obey their own unchanged configuration; waited process/listener cleanup"]
    if "stream" in case_id:
        result += ["causal prefix barrier and actual native append boundaries; send chunks alone are insufficient"]
    if case_id.endswith("file"):
        result += ["MULTIPART/native upload collection and upload cleanup" if "request" in case_id
                   else "actual Apache static file/APR_FILE bucket; local client file alone is insufficient"]
    if case_id.endswith("csv"):
        result += ["raw byte digest only; no CSV parser claim; response text/csv explicitly in SDK MIME set"]
    if "eos" in case_id.lower():
        result += ["actual APR EOS and native finalization separately; client EOF is not native EOS"]
    if case_id in RESPONSE_DENY or "P4-" in case_id:
        result += ["a successful prefix handoff before P4; actual commit and Safe/log_only or Strict/abort"]
    if case_id in HISTORICAL:
        result += ["the original direct fixture/rules and request generation are bound separately"]
    return result


def sink_analysis(case_id):
    facts, gaps = [], []
    if "sink" not in case_id.lower() and case_id not in ("E2E-APACHE-INVALID-EVENT-PATH", "E2E-APACHE-UNSAFE-DEVFULL"):
        return facts, gaps
    facts += ["apache_sink_stages", "apr_write_full", "private_file_admission"]
    gaps += ["Prove actual rule120016, separate120001, and first sink operation before selecting host outcome.",
             "Pre-APR Common/POSIX rejection is not APR-open failure; descriptor rebinding is not filesystem exhaustion."]
    if case_id.endswith("flush"):
        gaps += ["Production Apache sink is unbuffered and has no flush call; standalone APRflush cannot qualify this host obligation."]
    if case_id.endswith("short-write"):
        gaps += ["APRwrite_full retries partial writes; capture the actual lower-level short operation and retry/error."]
    return facts, gaps


def source_analysis(case_id, plan):
    """Conditional source inference; never copy the plan's candidate expected status."""
    proposal, facts, gaps = prepared_proposal(case_id, plan)
    if proposal is None and case_id not in UNDEFINED and case_id not in SINK_CASES:
        proposal = basic_proposal(case_id)
    if (case_id == "NEED-response-file" and proposal is not None
            and plan.get("backend", {}).get("file", {}).get("serving") == "apache_static_file"):
        proposal["backend_requests"] = 0
        proposal["response_file_contract"] = "Direct Apache DocumentRoot source; actual static handler and APR_FILE bucket remain separate runtime predicates."
    if proposal is not None:
        facts += ["sdk_request_bytes", "sdk_response_mime", "apache_eos_and_prefix", "exact_fixture_rules"]
    if case_id in ABNORMAL:
        facts += ["apache_read_error_before_eos", "http_incomplete_message"]
        gaps += ["No fixed final HTTP status follows from peer shutdown, RST or process signal timing.",
                 "Normal P2/P4/EOS calls cannot be invented; capture the actual abnormal cleanup.",
                 "A typed absent-status branch requires exact independent negative-observation witnesses and Root review; null is never an approval or a normal-success fallback."]
    sink_facts, sink_gaps = sink_analysis(case_id)
    facts += sink_facts
    gaps += sink_gaps
    if case_id in ("NEED-invalid-native-return", "NEED-invalid-metadata", "NEED-timeout"):
        facts += ["native_return_contract", "apache_fail_closed"]
        gaps += ["Bind and observe the exact invalid result/metadata or authoritative elapsed-budget seam; source policy alone does not activate a fault."]
    if case_id == "NEED-timeout":
        gaps += ["Current request fixture has no authoritative elapsed-budget owner, start/deadline clock or exact crossing operation. A sleep or configured timeout alone cannot establish native timeout semantics."]
    if "TECHNICAL-" in case_id:
        gaps += ["The old pre/postcommit shim must be independently bound to a real technical boundary; no rule120015 attribution from configured status."]
    if case_id == "E2E-APACHE-MULTI-EOS":
        gaps += ["The historical name describes multiple chunks, not multiple terminal EOS; prove one terminal EOS and actual multiple native appends."]
    if not facts:
        raise ValueError("No independent source treatment for " + case_id)
    if proposal is not None:
        proposal.setdefault("conditional_on", predicates(case_id))
    return proposal, sorted(set(facts)), gaps


def limit_source_proposal(case_id, plan):
    """Supplemental original-rule absence inference, separate from the original54."""
    phase = 2 if case_id.startswith("phase2") else 4
    target = plan.get("request" if phase == 2 else "backend", {})
    if not target.get("body"):
        return None
    body = declared_body(target["body"])
    partial = case_id in ("phase2_truncated", "phase4_body_process_partial")
    at_limit = case_id == "phase4_body_at_limit"
    if body != b"a" * (16 if at_limit else 17):
        return None
    prefix = "Request" if phase == 2 else "Response"
    action = "ProcessPartial" if partial else "Reject"
    rules = plan.get("rules", "").splitlines()
    if not {"Sec%sBodyLimit 16" % prefix, "Sec%sBodyLimitAction %s" % (prefix, action)}.issubset(rules):
        return None
    reject = not partial and not at_limit
    result = proposed_oracle("deny" if reject else "allow", 403 if reject else 200,
                             phase, backend=0 if phase == 2 and reject else 1)
    result["limit_contract"] = {"native_limit_bytes": 16, "wire_body_bytes": len(body),
        "action": action, "native_buffer_bytes": 16,
        "original_marker_rule_id": 1100101 if phase == 2 else 1100301,
        "marker_present_in_native_buffer": False, "native_limit_has_intrinsic_rule_id": False,
        "transport_incomplete": False,
        "response_reject_403_requires_no_prior_commit": phase == 4 and reject}
    result["conditional_on"] = predicates(case_id) + [
        "actual limit metadata and append return0/1 must match the native branch",
        "rule absence requires native audit/observer negative witnesses, not merely no JSONL",
        "response rejection maps403 only before actual commit; otherwise retain actual transport/commit branch"]
    return result


def supplemental_proposals(plan):
    result = []
    for prepared in plan["rows"]:
        case_id = prepared.get("case_id")
        if case_id not in LIMIT_CASES:
            continue
        proposal = limit_source_proposal(case_id, prepared)
        original = prepared["original_contract"]["expected_oracle"]
        if proposal is not None:
            proposal["event_fields"] = copy.deepcopy(original.get("event_fields", []))
        result.append({"original_id": prepared["original_id"], "case_id": case_id,
            "original_oracle": copy.deepcopy(original), "candidate_effective_oracle": proposal,
            "category_candidate": "ORACLE_DEFECT_CONFIRMED" if original.get("rule_id") else "SOURCE_CONFIRMED_EXPECTATION",
            "source_fact_keys": ["sdk_raw_append", "sdk_response_limit", "native_return_contract", "exact_fixture_rules"],
            "reviewed_by": None, "approved_correction": None, "outcome": None,
            "full_lifecycle_qualified": False})
    return result


def abnormal_status_draft(case_id, prepared):
    if case_id not in ABNORMAL:
        return None
    return {"source_inference_only": True, "reviewed_by": None,
        "branch": "conditional_terminal_transport_without_final_HTTP_response",
        "visible_status": None, "native_terminal_phase": None,
        "client_operation": prepared.get("request", {}).get("peer_action"),
        "required_independent_witnesses": [
            "exact principal native allocation/append progress before owned peer action",
            "actual socket SHUT_WR/RST or waited owned-client SIGINT/SIGTERM",
            "bounded complete client capture showing no final HTTP status, with read/wait termination",
            "host native/process/backend receipts bound to the same run/UID/request",
            "actual abnormal cleanup; no invented normal P2/P4/native EOS"],
        "final_HTTP_status_if_observed": "reject this absent-status branch; independently review the observed-status branch",
        "shared_schema_binding": None, "outcome": None, "full_lifecycle_qualified": False}


def minimal_mapping_gap(plan):
    for row in plan["rows"]:
        if row.get("case_id") == "phase4_deny_after_commit_log_only_minimal":
            return {"original_id": row["original_id"], "candidate_effective_oracle": None,
                "source_fact_keys": ["apache_phase4_mode_parser", "apache_late_mode_branches"],
                "source_gap": "Common parser and Apache directive accept only off/safe/strict. Off takes the native intervention path; Safe uses the committed log_only policy. No source defines a minimal-to-Safe alias. Preserve the original minimal obligation pending explicit source-based Root interpretation.",
                "configured_candidate_mode": row.get("apache", {}).get("phase4_mode"),
                "approved_mapping": None, "outcome": None, "full_lifecycle_qualified": False}
    return None


def validate_inventory(rows):
    ids = [row["original_id"] for row in rows]
    if len(ids) != 155 or len(set(ids)) != 155:
        raise ValueError("Original155 unique inventory required")
    if sum(row["contract_kind"] == "configuration" for row in rows) != 10:
        raise ValueError("Ten configuration and145 host contracts must remain separate")
    if hashlib.sha256(("\n".join(ids) + "\n").encode()).hexdigest() != APACHE_IDS_SHA256:
        raise ValueError("Immutable original155 ID order changed")
    if digest([row["original_contract"] for row in rows]) != APACHE_CONTRACTS_SHA256:
        raise ValueError("Immutable original155 contracts changed")
    return ids


def validate_original54(rows, historical):
    old = {row["run_scoped_case_id"]: row for row in historical["oracle_matrix"]
           if row["leg_id"] == "apache-native"}
    selected = [row for row in rows if row["baseline"]["original54member"]]
    ids = [row["original_id"] for row in selected]
    if len(ids) != 54 or set(old) != set(ids):
        raise ValueError("Exact original54 membership changed")
    if hashlib.sha256(("\n".join(ids) + "\n").encode()).hexdigest() != ORIGINAL54_SHA256:
        raise ValueError("Original54 immutable membership/order changed")
    for row in selected:
        if old[row["original_id"]]["original_selected_requirement"] != row["original_contract"]:
            raise ValueError("Historical original oracle/contract changed")
    return selected, old


def validate_inputs(inventory, plan, old_reconciliation):
    rows = inventory["rows"]
    ids = validate_inventory(rows)
    plans = {row["original_id"]: row for row in plan["rows"]}
    if len(plan["rows"]) != 155 or set(plans) != set(ids):
        raise ValueError("Plan must retain exactly the155 original contracts")
    for row in rows:
        if plans[row["original_id"]]["original_contract"] != row["original_contract"]:
            raise ValueError("Plan changes or omits an original contract")
    selected, old = validate_original54(rows, old_reconciliation)
    return selected, plans, old


def build_review(inventory, plan, old_reconciliation, sources):
    selected, plans, old = validate_inputs(inventory, plan, old_reconciliation)
    result = []
    for row in selected:
        identity = row["original_id"]
        prepared = plans[identity]
        proposal, facts, gaps = source_analysis(row["case_id"], prepared)
        record = old[identity]
        if proposal is not None:
            proposal["event_fields"] = copy.deepcopy(record["original_oracle"].get("event_fields", []))
        result.append({"original_id": identity, "case_id": row["case_id"],
            "original_contract": copy.deepcopy(row["original_contract"]),
            "original_oracle": copy.deepcopy(record["original_oracle"]),
            "original_source_revision": copy.deepcopy(record["original_source_revision"]),
            "original_source_hashes": copy.deepcopy(record["original_source_hashes"]),
            "historical_disposition": {key: copy.deepcopy(record.get(key)) for key in
                ("category", "resolved", "retest", "approved_correction", "outcome")},
            "prepared_contract_sha256": digest(prepared),
            "historical_fixture": copy.deepcopy(prepared.get("historical_fixture")),
            "original_fixture_refs": copy.deepcopy(row["source_bindings"]),
            "previous_revision_oracle_resolved": row["baseline"]["original_oracle_resolved"],
            "independent_sources": copy.deepcopy(sources["independent"]),
            "implementation_sources": copy.deepcopy(sources["implementation"]),
            "source_fact_keys": facts, "candidate_effective_oracle": proposal,
            "typed_status_absence_draft": abnormal_status_draft(row["case_id"], prepared),
            "scope_gaps": gaps, "required_runtime_predicates": predicates(row["case_id"]),
            "category": "UNRESOLVED_ORACLE", "resolved": False, "reviewed_by": None,
            "execution_observed": None, "actual_observations": None,
            "outcome": None, "full_lifecycle_qualified": False})
    return {"schema_version": 1, "scope": "apache-native", "source_review_only": True,
            "original155": 155, "configuration_contracts": 10, "host_contracts": 145,
            "original54": len(result), "new_revision_resolved": 0,
            "candidates_with_source_based_outcome": sum(r["candidate_effective_oracle"] is not None for r in result),
            "fact_registry": copy.deepcopy(sources.get("facts", {})), "rows": result,
            "supplemental_existing_oracle_conflicts": supplemental_proposals(plan),
            "minimal_mapping_review": minimal_mapping_gap(plan)}


def unresolved_record(review):
    """Draft shape for the unchanged shared validator, with no approval forged."""
    return {"run_scoped_case_id": review["original_id"], "leg_id": "apache-native",
            "reviewed_by": None, "category": "UNRESOLVED_ORACLE",
            "interpretation": "Independent source proposal only; Root review and current-host evidence remain separate.",
            "scope": "Exact selected Apache contract; original expectations and revision remain unchanged.",
            "independent_sources": copy.deepcopy(review["independent_sources"]),
            "implementation_sources": copy.deepcopy(review["implementation_sources"])}


def read_input(path):
    helper = source_path('ci/runtime/lifecycle/apache-i12') / "paths.py"
    module = load_source(helper)
    return json.loads(module.input_path(path).read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("inventory", "plan", "historical-reconciliation", "sources", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    result = build_review(*[read_input(path) for path in
        (args.inventory, args.plan, args.historical_reconciliation, args.sources)])
    helper = source_path('ci/runtime/lifecycle/apache-i12') / "paths.py"
    module = load_source(helper)
    with module.new_output(args.output).open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
