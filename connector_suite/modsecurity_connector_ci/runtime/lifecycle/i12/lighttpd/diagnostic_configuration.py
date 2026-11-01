#!/usr/bin/env python3
"""Propose original diagnostic parser qualifications from waited processes.

The shared configuration validator and a separate Root review decide the result.
This producer never assigns host lifecycle observations to parser invocations.
"""
from modsecurity_test_framework.connector_context import load_source
import argparse
import importlib.util
import json
from pathlib import Path

# Load the maintained Parent filesystem boundary from this checkout.
import sys as _i12_sys

import modsecurity_connector_ci.lib.i12_path_safety as i12_paths


def adapter():
    module = load_source(Path(__file__).with_name('qualification.py'))
    return module


def attempted_rules_path(process, args):
    path = Path(process["rules_path"])
    for inside, outside in ((Path("/mnt/fixtures"), args.source_manifest.parent),
                            (Path("/task"), args.attempt / "data")):
        if path.is_relative_to(inside):
            return outside / path.relative_to(inside)
    raise ValueError("Attempted rules are outside the admitted fixture/task bindings")


def measurement_refs(q, case, process, args, expectation):
    refs = [q.reference(case / "parser-process.json", "parser_process"),
            q.reference(args.source_manifest, "source_manifest"),
            q.reference(case / "lighttpd.conf", "effective_configuration"),
            q.reference(args.preparation / "artifacts/bin/lighttpd", "invoked_image"),
            q.reference(args.preparation / "artifacts/modules/mod_msconnector.so", "native_module"),
            q.reference(case / "parser-cleanup.json", "cleanup_observer"),
            q.reference(args.attempt / "controller-result.json", "isolation_receipt"),
            q.reference(case / "config.stdout", "parser_stdout"),
            q.reference(case / "config.stderr", "parser_stderr"), expectation]
    refs.append(q.reference(case / "rules-absence.json", "rules_absence") if process.get("rules_absence_sha256")
                else q.reference(attempted_rules_path(process, args), "rules_file"))
    return refs


def prepare_expectations(q, args, corrections):
    """Declare source-derived diagnostics before launching the parser controls."""
    runtime = args.preparation / "source/common/runtime/msconnector_runtime.c"
    product_revision = json.loads((args.preparation / "preparation.json").read_text())["checkout_head"]
    source = runtime.read_text()
    causes = {
        "missing_rules_file": "libmodsecurity rejected rules file",
        "invalid_rule_syntax": "libmodsecurity rejected rules file",
        "unknown_config_key": "unknown configuration key: invented_unknown_key",
        "invalid_boolean": "invalid enabled value",
        "invalid_status": "invalid default_error_status value",
        "invalid_size": "invalid max_header_count value",
        "unsafe_event_path": "cannot open event_path /task/configcontrols/missing-parent/events.jsonl: No such file or directory",
    }
    for name, cause in causes.items():
        anchor = {"unknown_config_key": "unknown configuration key: %s",
                  "unsafe_event_path": "cannot open event_path %s: %s"}.get(name, cause)
        if anchor not in source:
            raise ValueError("Expected diagnostic is absent from the captured Runtime source")
        original = q.original_row("I12::lighttpd-stock-native-control::" + name)
        expected = corrections[name]["expected_oracle"]
        proposal = {"reviewed_by": "worker", "run_scoped_case_id": original["run_scoped_case_id"],
            "purpose": "Pre-execution source expectation proposal; separate Root review required",
            "expected_parser_rejection": {
                "original_contract_sha256": q.ORACLES.canonical_digest(original["selected_requirement"]),
                "oracle_sha256": q.ORACLES.canonical_digest(expected),
                "diagnostic_stream": "stderr", "diagnostic_contains": cause, "first_cause": cause},
            "source_proof": [q.reference(runtime, kind="implementation_contract", revision=product_revision,
                                           literal_anchor=anchor),
                q.reference(args.host_source / "src/server.c", kind="official_host_contract", revision=args.host_revision),
                q.reference(args.framework / "tests/cases/no-crs-baseline/catalog.json",
                            kind="native_engine_contract", revision=args.framework_sha)],
            "input_contract": {"output_root": "/task/configcontrols",
                "invalid_rule_literal": "NotAValidModSecurityDirective",
                "missing_rules_path": "/task/configcontrols/absent-rules.conf",
                "unsafe_event_path_errno_contract": "Fresh missing-parent directory is absent; open reports ENOENT."}}
        with (args.output / (name + "-expectation-proposal.json")).open("x") as stream:
            json.dump(proposal, stream, indent=2)
            stream.write("\n")


def proposal(q, probe, receipt, args, correction=None):
    case = args.attempt / "data/configcontrols" / probe["case_id"]
    process = json.loads((case / "parser-process.json").read_text())
    case_id = process["run_scoped_case_id"]
    original = q.original_row(case_id)
    if original["selected_requirement"]["execution_kind"] != "actual_configtest":
        raise ValueError("Parser proposal requires original actual_configtest selection")
    expected = correction["expected_oracle"] if correction else original["selected_requirement"]["expected_oracle"]
    controller = json.loads((args.attempt / "controller-result.json").read_text())
    checks = {"no_signal": process["waited_signal"] is None,
              "exact_expected_exit": process["waited_exit"] == expected["visible_status"],
              "supervisor_reaped": controller["supervisor_reaped"],
              "no_namespace_survivors": not controller["surviving_namespace_pids"],
              "no_mount_leaks": not controller["outside_mount_leaks"]}
    host_contract = q.reference(args.host_source / "src/server.c", "expectation_source",
                                kind="official_host_contract", revision=args.host_revision)
    expectation = (q.reference(args.expectations / (probe["case_id"] + "-expectation-proposal.json"),
                    "expectation_source", kind="official_host_contract", revision=args.host_revision)
                   if expected["native_result"] == "config_rejected" else host_contract)
    if expected["native_result"] == "config_rejected":
        declared = json.loads(Path(expectation["path"]).read_text())["expected_parser_rejection"]
        checks.update(first_cause=process["first_cause"] == declared["first_cause"],
                      diagnostic=declared["diagnostic_contains"] in process[declared["diagnostic_stream"]])
    identity_keys = ("run_scoped_case_id", "leg_id", "run_id", "parent_sha", "execution_kind",
                     "execution_observed", "effective_config_sha256", "rules_sha256")
    packet = {key: process[key] for key in identity_keys}
    if process.get("rules_absence_sha256"):
        packet["rules_absence_sha256"] = process["rules_absence_sha256"]
    binding = {"parent_sha": process["parent_sha"], "effective_config_sha256": process["effective_config_sha256"],
               "rules_sha256": process["rules_sha256"], "runtime_config": q.reference(case / "runtime.conf"),
               "original_selected_requirement": original["selected_requirement"],
               "executed_input_hashes": controller["executed_input_hashes_before"]}
    if process.get("rules_absence_sha256"):
        binding["rules_absence_sha256"] = process["rules_absence_sha256"]
    packet.update(reviewed_by="worker", oracle_evaluated=True, oracle_sha256=q.ORACLES.canonical_digest(expected),
        measurement_evidence=measurement_refs(q, case, process, args, expectation),
        independent_evaluation_checks=checks, outcome="PASS" if all(checks.values()) else "FAIL",
        full_lifecycle_qualified=False, actual_observations={
            "parser_process": {key: process[key] for key in
                ("argv", "cwd", "waited_exit", "waited_signal", "stdout", "stderr", "executable_sha256", "first_cause")},
            "invocation_identity": {"host_binary_sha256": receipt["host_sha256"], "module_sha256": receipt["module_sha256"],
                                    "uid": receipt["uid"], "gid": receipt["gid"]},
            "source_config_binding": binding, "cleanup": json.loads((case / "parser-cleanup.json").read_text())})
    oracle = {"run_scoped_case_id": case_id, "leg_id": original["leg_id"], "reviewed_by": "worker",
              "category": "SOURCE_CONFIRMED_EXPECTATION", "scope": "Original configuration parser acceptance/rejection only",
              "interpretation": "The original selected parser contract and official host setup/return semantics prescribe the exact process exit independently of the target parser observation.",
              "independent_sources": [host_contract,
                  {**q.reference(args.framework / "tests/cases/no-crs-baseline/catalog.json"),
                   "kind": "native_engine_contract", "revision": args.framework_sha}],
              "implementation_sources": [q.reference(args.preparation / "source/connectors/lighttpd/module/mod_msconnector.c")]}
    if correction:
        oracle.update(category="ORACLE_DEFECT_CONFIRMED", approved_correction=correction,
                      interpretation=correction["reason"])
        oracle["independent_sources"].extend(correction["proof"])
        oracle["separate_correction_approval"] = q.reference(args.corrections)
        packet["separate_correction_approval"] = q.reference(args.corrections)
    return packet, oracle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("attempt", "preparation", "framework", "output", "source-manifest", "host-source"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--framework-sha", required=True)
    parser.add_argument("--host-revision", required=True)
    parser.add_argument("--corrections", type=Path)
    parser.add_argument("--expectations", type=Path)
    parser.add_argument("--prepare-expectations", action="store_true")
    args = parser.parse_args()
    q = adapter()
    if args.output.resolve() != args.output.absolute() or args.output.exists():
        raise ValueError("Output must be a fresh physical directory")
    args.output = i12_paths.new_directory(args.output)
    corrections = json.loads(args.corrections.read_text()) if args.corrections else {}
    corrections = corrections.get("corrections", corrections)
    if args.prepare_expectations:
        prepare_expectations(q, args, corrections)
        return
    if not args.expectations:
        raise ValueError("Source-bound parser expectation proposals must precede the retake")
    q.reference(args.attempt / "data/configcontrols/receipt.json")
    receipt = json.loads((args.attempt / "data/configcontrols/receipt.json").read_text())
    for probe in receipt["configuration_probes"]:
        packet, oracle = proposal(q, probe, receipt, args, corrections.get(probe["case_id"]))
        for suffix, value in (("packet-proposal", packet), ("oracle-proposal", oracle)):
            with (args.output / (probe["case_id"] + "-" + suffix + ".json")).open("x") as output:
                json.dump(value, output, indent=2)
                output.write("\n")


if __name__ == "__main__":
    main()
