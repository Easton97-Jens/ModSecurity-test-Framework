#!/usr/bin/env python3
"""Seal fresh original-ID Envoy captures from independently reviewed fixture inputs.

Preparation does not execute a host, resolve the canonical ledger, or qualify PASS.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, load_source
import argparse
import copy
import hashlib
import json
import importlib.util
from pathlib import Path
import re
import shutil

if __package__:
    from . import host_scenarios as host, evidence_io, reconcile as baseline_producer, source_inventory
else:
    import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.host_scenarios as host
    import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.evidence_io as evidence_io
    import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.reconcile as baseline_producer
    import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.source_inventory as source_inventory

HERE = Path(__file__).resolve().parent
ROOT = connector_root()
STORAGE = host.STORAGE
SOURCE_TARGET = "/mnt/src"
FIXTURE_TARGET = "/mnt/fixtures"
LIMITS = {"memory_bytes": 3221225472, "processes": 384, "output_bytes": 2147483648}


def physical(path, directory=False):
    path = Path(path).absolute()
    if path.resolve(strict=True) != path or not (path.is_dir() if directory else path.is_file()):
        raise ValueError("Nonphysical input path: " + str(path))
    return path


def evidence_roots():
    """Use independently configured roots, never a reference-selected parent."""
    return (ROOT, test_root()) + ((Path(evidence_io.ARCHIVES),) if evidence_io.ARCHIVES else ()) + ((STORAGE,) if STORAGE is not None else ())


def reference(path):
    return evidence_io.reference(Path(path).absolute(), roots=evidence_roots())


def checked_reference_bytes(ref):
    path = Path(ref["path"])
    path = path if path.is_absolute() else ROOT / path
    content = evidence_io.read_bytes(path, roots=evidence_roots())
    if (hashlib.sha256(content).hexdigest() != ref["sha256"]
            or ("bytes" in ref and len(content) != ref["bytes"])):
        raise ValueError("Reviewed source or fixture hash changed: " + str(path))
    return path, content


def check_reference(ref):
    return checked_reference_bytes(ref)[0]


def validate_baseline(path):
    baseline = evidence_io.read_json(Path(path).absolute(), roots=evidence_roots())
    refs = baseline["input_evidence"]
    ledger = json.loads(checked_reference_bytes(refs["ledger"])[1])
    oracles = json.loads(checked_reference_bytes(refs["oracles"])[1])
    expected = baseline_producer.reconcile(ledger, oracles)
    actual = {key: value for key, value in baseline.items() if key != "input_evidence"}
    if actual != expected:
        raise ValueError("Baseline differs from independently revalidated original ledger")
    return baseline


def validate_review_identity(row, binding, originals, seen):
    identity, route = row.get("run_scoped_case_id"), row.get("route")
    if identity not in originals or identity in seen:
        raise ValueError("Unknown or duplicate original case identity")
    seen.add(identity)
    original = originals[identity]
    if (route != original["leg_id"] or identity.split("::")[1] != route
            or row.get("original_oracle") != original["original_oracle"]):
        raise ValueError("Original route or oracle was substituted")
    bound_id = binding.get("run_scoped_case_id", binding.get("original_id"))
    if bound_id != identity or binding.get("route", route) != route:
        raise ValueError("Fixture binding lacks the exact original identity")
    if row.get("lifecycle_qualified") is not False:
        raise ValueError("A source proposal cannot qualify a lifecycle PASS")


def selected_review_shapes(row, originals, seen):
    binding = row.get("fixture_binding") or {}
    if row.get("category") != "SOURCE_SEMANTICS_CONFIRMED" or binding.get("origin") != "new_task_fixture_binding":
        return None
    validate_review_identity(row, binding, originals, seen)
    refs = binding.get("physical_inputs", binding.get("files", []))
    if not row.get("source_refs"):
        raise ValueError("Independent source review references are required")
    for ref in row.get("source_refs", []) + refs:
        check_reference(ref)
    shapes = [check_reference(ref) for ref in refs if Path(ref["path"]).name == "shape.json"]
    if not shapes or len(shapes) != len(set(shapes)):
        raise ValueError("An exact distinct physical shape is required")
    return shapes


def select_document_rows(document, originals, seen, review_ref, selected, skipped):
    for row in document.get("rows", document.get("records", [])):
        shapes = selected_review_shapes(row, originals, seen)
        if shapes is None:
            continue
        if not isinstance(row.get("effective_oracle"), dict):
            skipped.append({"run_scoped_case_id": row["run_scoped_case_id"], "reason": "effective_oracle_unknown"})
            continue
        selected.append((row, shapes, review_ref))


def selected_reviews(documents, baseline, baseline_ref):
    originals = {row["run_scoped_case_id"]: row for row in baseline["rows"]}
    seen, selected, skipped = set(), [], []
    for path in documents:
        review_ref = reference(path)
        document = evidence_io.read_json(review_ref["path"], roots=evidence_roots())
        input_ref = document.get("input_evidence")
        if input_ref is not None and (input_ref.get("sha256") != baseline_ref["sha256"]
                                     or check_reference(input_ref) != Path(baseline_ref["path"])):
            raise ValueError("Oracle review refers to a different baseline")
        select_document_rows(document, originals, seen, review_ref, selected, skipped)
    if not selected:
        raise ValueError("No fixture-bound original oracle proposals selected")
    return selected, skipped


def verify_binding(binding):
    source, ledger = physical(binding["source"], True), physical(binding["ledger"])
    if STORAGE not in source.parents or STORAGE not in ledger.parents:
        raise ValueError("Reuse requires registered external storage scope")
    if host.sha(ledger) != binding["ledger_sha256"] or ledger.stat().st_mode & 0o222:
        raise ValueError("Sealed binding ledger changed or is writable")
    files = json.loads(ledger.read_text())["files"]
    actual = source_inventory.tree_inventory(source)
    if actual != files:
        raise ValueError("Sealed binding complete inventory mismatch")
    for path in [source, *source.rglob("*")]:
        if path.stat().st_mode & 0o222:
            raise ValueError("Reused input is not sealed read-only")
    return source


def admission_bindings(spec):
    if (set(spec) != {"mode", "timeout_seconds", "setup_timeout_seconds", "resource_limits", "argv", "bindings", "environment"}
            or spec["mode"] != "nonroot" or spec["timeout_seconds"] != 120
            or spec["setup_timeout_seconds"] != 120 or spec["resource_limits"] != LIMITS
            or spec["argv"] != ["/usr/local/bin/python3", "-P", "/mnt/fixtures/driver.py"]
            or spec["environment"] != {"CONNECTOR_ROOT": SOURCE_TARGET}):
        raise ValueError("Original admission or privilege boundary differs")
    bindings = {item["target"]: item for item in spec["bindings"]}
    if len(spec["bindings"]) != 3 or set(bindings) != {SOURCE_TARGET, "/mnt/artifacts", FIXTURE_TARGET}:
        raise ValueError("Exactly three approved private bindings are required")
    return bindings


def verify_native_build_inputs(proof, source, artifacts, parent_sha):
    if proof.get("build_ready") is not True or proof.get("actual_source_commit") != parent_sha:
        raise ValueError("Actual native build does not match the selected Parent")
    # The source is a sealed copy; proof.source_copy keeps the original build
    # location so its retained Git archive and exact overlays remain checkable.
    source_inventory.verify(source, proof)
    for relative, expected in proof["binaries"].items():
        if host.sha(artifacts / Path(relative).name) != expected:
            raise ValueError("Actual binary differs from native build")
    if host.sha(artifacts / "envoy") != host.HOST_SHA:
        raise ValueError("Actual Envoy image identity changed")
    for filename, expected in proof["module_inputs"].items():
        if host.sha(source / "connectors/envoy/ext_proc" / filename) != expected:
            raise ValueError("Patched Go module inputs changed")


def verified_admission(shape_path, parent_sha, cache):
    fixture = physical(shape_path.parent, True)
    spec_path = physical(fixture.parent / (fixture.name + "-admission.json"))
    spec = json.loads(spec_path.read_text())
    bindings = admission_bindings(spec)
    for item in bindings.values():
        key = (item["source"], item["ledger"], item["ledger_sha256"])
        if key not in cache:
            cache[key] = verify_binding(item)
    if Path(bindings[FIXTURE_TARGET]["source"]) != fixture:
        raise ValueError("Admission fixture was substituted")
    proof = json.loads((fixture / "actual-build-provenance-v1.json").read_text())
    source, artifacts = Path(bindings[SOURCE_TARGET]["source"]), Path(bindings["/mnt/artifacts"]["source"])
    build_key = (str(source), str(artifacts), host.sha(fixture / "actual-build-provenance-v1.json"), parent_sha)
    if build_key not in cache:
        verify_native_build_inputs(proof, source, artifacts, parent_sha)
        cache[build_key] = True
    shape = json.loads(shape_path.read_text())
    if shape.get("parent_sha") != parent_sha or not re.fullmatch("[a-f0-9]{40}", parent_sha):
        raise ValueError("Shape lacks the exact Parent revision")
    return spec, shape, reference(spec_path)


def fixture_oracle(row, shape):
    oracle = copy.deepcopy(row["effective_oracle"])
    suffix = shape["case_id"].split("::")[-1]
    comparison = None
    if suffix.endswith("host-reject"):
        comparison = oracle.get("host_reject_comparison")
    elif suffix.endswith("request-partial"):
        comparison = oracle.get("process_partial_comparison", oracle.get("native_partial_comparison"))
    return copy.deepcopy(comparison) if comparison is not None else oracle


def require_storage():
    if STORAGE is None:
        raise ValueError("CODEX_PROJECT_STATE configuration required for original-ID preparation")
    return STORAGE


def registered_run(run_root):
    require_storage()
    run = physical(run_root, True)
    budget_path = run / ".codex-storage-budget.json"
    if STORAGE not in run.parents or not budget_path.is_file():
        raise ValueError("Registered external task run required")
    budget = json.loads(physical(budget_path).read_text())
    if budget.get("status") != "registered" or budget.get("run_root") != str(run):
        raise ValueError("Run registration identity differs")
    if {path.name for path in run.iterdir()} != {".codex-storage-budget.json"}:
        raise ValueError("Fresh registered output root required")
    return run


def prepare_inputs(selected):
    prepared, cache, parents = [], {}, set()
    # Validate every input before producing any fixture output.
    for row, shapes, review_ref in selected:
        for shape_path in shapes:
            original_shape = json.loads(shape_path.read_text())
            parent_sha = original_shape.get("parent_sha", "")
            spec, shape, admission_ref = verified_admission(shape_path, parent_sha, cache)
            if shape.get("leg") != row["route"]:
                raise ValueError("Selected shape belongs to a sibling route")
            parents.add(parent_sha)
            oracle = fixture_oracle(row, shape)
            prepared.append((row, shape_path, shape, spec, oracle, review_ref, admission_ref))
    if len(parents) != 1:
        raise ValueError("One exact Parent revision is required for the matrix")
    return prepared, next(iter(parents))


def copy_binding(binding, run, copied_bindings):
    key = (binding["target"], binding["ledger_sha256"])
    if key not in copied_bindings:
        label = "source" if binding["target"] == SOURCE_TARGET else "artifacts"
        destination = run / "reused-inputs" / (label + "-" + binding["ledger_sha256"])
        destination.parent.mkdir(mode=0o700, exist_ok=True)
        shutil.copytree(Path(binding["source"]), destination, copy_function=shutil.copy2)
        copied_bindings[key] = host.seal_tree(destination) | {"target": binding["target"]}
        if copied_bindings[key]["ledger_sha256"] != binding["ledger_sha256"]:
            raise ValueError("Copied source or artifact bytes changed")
    return copied_bindings[key]



def bound_shape(shape, identity, label, oracle, review_ref):
    shape = copy.deepcopy(shape)
    shape.update(case_id="I12-ENVOY-HOST::" + label, original_case_ids=[identity],
                 review_sha256=review_ref["sha256"], oracle_review_sha256=review_ref["sha256"],
                 approved_source_oracle=oracle)
    for stale in ("expected_source_oracle_proposal_only", "host_request_buffer_max_bytes"):
        shape.pop(stale, None)
    status = oracle.get("visible_status")
    if type(status) is int and 100 <= status <= 599:
        shape["expected_status"] = status
    else:
        # Unknown expectations cannot be replaced with a measured HTTP result.
        # Existing client behavior is preserved but explicitly remains unqualified.
        shape["expected_status_source"] = "inherited_client_check_not_oracle"
    return shape, status


def materialize_case(run, index, prepared_row, copied_bindings, controller_module):
    row, shape_path, shape, spec, oracle, review_ref, admission_ref = prepared_row
    identity = row["run_scoped_case_id"]
    suffix = re.sub("[^a-z0-9]+", "-", identity.split("::")[-1].lower()).strip("-")
    label = "original-" + row["route"] + "-" + suffix + "-" + str(index)
    destination = run / "host-fixtures" / label
    shutil.copytree(shape_path.parent, destination, copy_function=shutil.copy2)
    for path in [destination, *destination.rglob("*")]:
        path.chmod(0o700 if path.is_dir() or path.stat().st_mode & 0o111 else 0o600)
    shape, status = bound_shape(shape, identity, label, oracle, review_ref)
    host.write(destination / "shape.json", shape)
    fixture_binding = host.seal_tree(destination) | {"target": FIXTURE_TARGET}
    updated = copy.deepcopy(spec)
    updated["bindings"] = [fixture_binding if item["target"] == FIXTURE_TARGET else copy_binding(item, run, copied_bindings)
                           for item in spec["bindings"]]
    spec_path = destination.parent / (label + "-admission.json")
    host.write(spec_path, updated)
    spec_path.chmod(0o444)
    controller_module.read_spec(spec_path)
    return {"label": label, "route": row["route"], "spec": str(spec_path),
                   "original_case_ids": [identity], "expected_http_status": status,
                   "expected_target_backend": shape.get("target_backend", True),
                   "qualification": "unreviewed_capture_input", "source_review": review_ref,
                   "oracle_review_sha256": review_ref["sha256"],
                   "approved_source_oracle": oracle, "original_shape": reference(shape_path),
                   "original_admission": admission_ref}


def prepare(args):
    run = registered_run(args.run_root)
    old = physical(args.historical, True)
    controller, admission = old / "isolation/private-runtime-v5.py", old / "isolation/candidate-admission-v5.py"
    if host.sha(physical(controller)) != host.OLD_CONTROLLER_SHA or host.sha(physical(admission)) != host.ADMISSION_SHA:
        raise ValueError("Original controller/admission hash changed")
    baseline = validate_baseline(args.baseline)
    selected, skipped = selected_reviews(args.oracle_review, baseline, reference(args.baseline))
    prepared, parent_sha = prepare_inputs(selected)
    isolated = run / "isolation"
    isolated.mkdir(mode=0o700)
    new_controller = isolated / controller.name
    new_controller.write_text(host.controller_source(controller.read_text(), old, run))
    shutil.copyfile(admission, isolated / admission.name)
    for path in isolated.iterdir():
        path.chmod(0o444)
    controller_module = load_source(new_controller)
    matrix = []
    copied_bindings = {}

    for index, prepared_row in enumerate(prepared):
        matrix.append(materialize_case(run, index, prepared_row, copied_bindings, controller_module))
    result = {"parent_sha": parent_sha, "controller": str(new_controller),
              "controller_sha256": host.sha(new_controller), "controller_original_sha256": host.OLD_CONTROLLER_SHA,
              "admission_sha256": host.ADMISSION_SHA, "baseline": reference(args.baseline),
              "qualification": "unreviewed_original_id_capture_inputs", "host_launched": False,
              "new_lifecycle_pass": 0, "scenarios": matrix, "skipped": skipped}
    host.write(run / "host-scenarios.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("run-root", "historical", "baseline"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--oracle-review", type=Path, action="append", required=True)
    args = parser.parse_args()
    result = prepare(args)
    print(json.dumps({"scenarios": len(result["scenarios"]), "host_launched": False,
                      "matrix": str(args.run_root / "host-scenarios.json")}))


if __name__ == "__main__":
    main()
