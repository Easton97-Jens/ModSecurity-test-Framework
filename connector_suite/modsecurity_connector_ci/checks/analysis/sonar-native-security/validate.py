#!/usr/bin/env python3
"""Export one captured link target only after its declared source closure checks.

The producer-owned JSON contract declares target, revision, artifact, sources
(checkout-relative exact paths) and external_inputs (absolute path -> SHA-256).
Unknown archives, missing objects, mixed variants and copied product sources
are rejected. This is build provenance, not a server-side taint success proof.
"""
from modsecurity_test_framework.connector_context import load_source

import argparse
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile


GO_PROVENANCE = load_source(Path(__file__).with_name('go_provenance.py'))
SOURCE_MAPPING = load_source(Path(__file__).with_name('source_mapping.py'))


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def checked_hashes(values):
    for name, expected in values.items():
        if not Path(name).is_absolute() or digest(name) != expected:
            raise ValueError(f"captured input changed or is not absolute: {name}")


def verify_lto_limit(record, contract, checkout, capture_root):
    transients = record.get("compiler_internal_transients", {})
    if not transients:
        return
    producer = checkout / "connectors/apache/build/apxs-wrapper.in"
    if (not contract.get("allow_gcc_internal_lto_context_limit")
            or contract["producer"]["script"] != "connectors/apache/build/apxs-wrapper.in"
            or contract["producer"]["script_sha256"] != digest(producer)
            or not re.search(r"(?:^|-)gcc(?:-\d+)?$", Path(record["arguments"][0]).name)
            or not any(argument.startswith("-flto") for argument in record["arguments"])):
        raise ValueError("unadmitted GCC internal LTO context limit")
    context = record["lto_context"]
    temporary = Path(context["compiler_tmpdir"])
    if (context["mode"] != "apache-gcc-native-driver"
            or temporary != capture_root.resolve().parent / "compiler-tmp" or not temporary.is_dir()
            or temporary.is_relative_to(checkout)):
        raise ValueError("GCC internal LTO context escapes its invocation-owned compiler TMPDIR")
    checked_hashes({context["source_map"]: context["source_map_sha256"]})
    mapping = json.loads(Path(context["source_map"]).read_text())
    SOURCE_MAPPING.verify_manifest(mapping)
    if (mapping["checkout"] != str(checkout) or mapping["producer"] != context["producer"]
            or context["producer"] != {"path": str(producer), "sha256": digest(producer)}):
        raise ValueError("GCC internal LTO limit is not bound to the actual Apache native producer")
    original_operands = {str(SOURCE_MAPPING.absolute(argument, Path(record["directory"])))
                         for argument in record["expanded_arguments"][1:] if not argument.startswith("-")}
    for name, reason in transients.items():
        path = Path(name)
        admitted = ((reason == "gcc-lto-intermediate-not-retained"
                     and re.fullmatch(r"[^/]+\.ltrans(?a:\d+)\.ltrans\.o", path.name) is not None)
                    or (reason == "gcc-lto-debug-auxiliary-not-retained"
                        and re.fullmatch(r"cc[A-Za-z0-9]+\.debug\.temp\.o", path.name) is not None))
        if (not admitted or not path.is_relative_to(temporary)
                or path.is_relative_to(checkout) or path.resolve() != path
                or name in record["inputs"] or name in original_operands):
            raise ValueError("missing original/Parent object cannot use the compiler-internal LTO limit")


def external_admission(contract, checkout):
    """Admit generated host glue only with a durable pinned producer receipt."""
    sources = contract.get("external_sources", {})
    if not sources:
        return {}
    context = contract["external_context"]
    if context["host"] == "haproxy":
        return haproxy_external_admission(sources, context, checkout)
    if context["host"] != "nginx":
        raise ValueError("external source host has no admitted native producer")
    pin_contract = checkout / "ci/provisioning/components/prepare-runtime-components.py"
    if context["pin_contract"] != str(pin_contract) or digest(pin_contract) != context["pin_contract_sha256"]:
        raise ValueError("external source pin contract changed")
    tree = ast.parse(pin_contract.read_text())
    names = {"NGINX_PINNED_RELEASE_ASSET_NAME", "NGINX_PINNED_RELEASE_ASSET_SHA256"}
    pins = {target.id: ast.literal_eval(node.value)
            for node in tree.body if isinstance(node, ast.Assign)
            for target in node.targets if isinstance(target, ast.Name) and target.id in names}
    archive = Path(context["archive"])
    if (archive.name != pins["NGINX_PINNED_RELEASE_ASSET_NAME"]
            or context["archive_sha256"] != pins["NGINX_PINNED_RELEASE_ASSET_SHA256"]):
        raise ValueError("external source archive does not match current Parent pin")
    checked_hashes({str(archive): context["archive_sha256"],
                    context["configure_receipt"]: context["configure_receipt_sha256"]})
    source_root = Path(context["source_root"])
    if (not source_root.is_absolute() or source_root.resolve(strict=True) != source_root
            or not source_root.is_dir() or source_root.is_relative_to(checkout)
            or checkout.is_relative_to(source_root)):
        raise ValueError("external source root must be durable and disjoint from checkout")
    receipt = json.loads(Path(context["configure_receipt"]).read_text())
    if (receipt["host"] != context["host"] or receipt["source_root"] != str(source_root)
            or receipt["configure_directory"] != str(source_root)
            or "--add-dynamic-module=" + str(checkout / "connectors/nginx") not in receipt["configure_arguments"]):
        raise ValueError("external source configure receipt disagrees with native producer")
    checked_hashes(receipt["generated_files"])
    checked_hashes(sources)
    _verify_nginx_sources(sources, source_root, receipt)
    return sources


def haproxy_external_admission(sources, context, checkout):
    pin_contract = checkout / "connectors/haproxy/htx-overlay/version-contract.json"
    if context["pin_contract"] != str(pin_contract) or digest(pin_contract) != context["pin_contract_sha256"]:
        raise ValueError("HAProxy external source pin contract changed")
    pin = json.loads(pin_contract.read_text())
    archive = Path(context["archive"])
    if archive.name != "haproxy-" + pin["version"] + ".tar.gz" or context["archive_sha256"] != pin["sha256"]:
        raise ValueError("HAProxy external source archive disagrees with current native pin")
    checked_hashes({str(archive): context["archive_sha256"],
                    context["configure_receipt"]: context["configure_receipt_sha256"]})
    source_root = Path(context["source_root"])
    if (not source_root.is_absolute() or source_root.resolve(strict=True) != source_root
            or not source_root.is_dir() or source_root.is_relative_to(checkout)
            or checkout.is_relative_to(source_root)):
        raise ValueError("HAProxy external source root is not a durable disjoint native tree")
    receipt = json.loads(Path(context["configure_receipt"]).read_text())
    producer = checkout / "connectors/haproxy/htx-overlay/build-overlay.sh"
    if (receipt["host"] != "haproxy" or receipt["source_root"] != str(source_root)
            or receipt["native_build_arguments"] != ["sh", str(producer)]
            or receipt["producer_sha256"] != digest(producer)):
        raise ValueError("HAProxy external source receipt disagrees with its actual native producer")
    checked_hashes(receipt["generated_files"])
    checked_hashes(sources)
    _verify_haproxy_sources(archive, sources, source_root, receipt, pin)
    return sources


def _verify_nginx_sources(sources, source_root, receipt):
    for name, expected in sources.items():
        path = Path(name)
        if (path.resolve(strict=True) != path or not path.is_relative_to(source_root)
                or receipt["generated_files"].get(name) != expected):
            raise ValueError("unadmitted external source in target contract")


def _verify_haproxy_sources(archive, sources, source_root, receipt, pin):
    with tarfile.open(archive) as bundle:
        for name, expected in sources.items():
            path = Path(name)
            if path.resolve(strict=True) != path or not path.is_relative_to(source_root):
                raise ValueError("unadmitted HAProxy external source path")
            member = "haproxy-" + pin["version"] + "/" + str(path.relative_to(source_root))
            if receipt["archive_sources"].get(name) != {"archive_member": member, "sha256": expected}:
                raise ValueError("unadmitted HAProxy external source receipt")
            stream = bundle.extractfile(member)
            if stream is None or hashlib.sha256(stream.read()).hexdigest() != expected:
                raise ValueError("HAProxy external source differs from actual pinned archive member")


def _verify_compile_mapping(record):
    mapping = record.get("source_mapping")
    if mapping:
        checked_hashes({mapping["manifest"]: mapping["manifest_sha256"]})
        manifest = json.loads(Path(mapping["manifest"]).read_text())
        copied = [Path(name) for name in mapping["ordered_copied_dependencies"]]
        original = [Path(name) for name in mapping["ordered_original_dependencies"]]
        SOURCE_MAPPING.verify_dependency_context(copied, original, manifest)
        if (record["dependencies"] != mapping["original_dependencies"]
                or any(name in manifest["files"] for name in record["dependencies"])
                or mapping["original_source"] != next(iter(record["sources"]))):
            raise ValueError("mapped compiler does not actually read all original Parent source/header inputs")
        _verify_mapped_arguments(record, mapping, manifest)


def _verify_mapped_arguments(record, mapping, manifest):
    producer_args = mapping["original_producer_arguments"]
    indices = [index for index, argument in enumerate(producer_args[1:])
               if not argument.startswith("-") and str(SOURCE_MAPPING.absolute(
                   argument, Path(record["directory"]))) == mapping["copied_source"]]
    if len(indices) != 1:
        raise ValueError("mapped native producer source operand is ambiguous")
    mapped_args = SOURCE_MAPPING.mapped_arguments(
        producer_args[1:], indices[0], Path(mapping["original_source"]),
        Path(mapping["copied_source"]), manifest)
    if record["expanded_arguments"] != [producer_args[0], *mapped_args]:
        raise ValueError("mapped compiler arguments disagree with the pre-execution receipt")


class _CapturedGraph:
    def __init__(self, external, object_aliases, producers, contract, checkout, root):
        self.external = external
        self.object_aliases = object_aliases
        self.producers = producers
        self.graph_records = []
        self.selected = []
        self.contract = contract
        self.checkout = checkout
        self.root = root
        self.visiting = set()

    def walk(self, name, expected_hash):
        key = (name, expected_hash)
        if key in self.visiting:
            raise ValueError("cyclic captured link graph")
        checked_hashes({name: expected_hash})
        if name in self.external:
            if expected_hash != self.external[name]:
                raise ValueError("external input identity mismatch")
            return
        if name in self.object_aliases:
            alias = self.object_aliases[name]
            if expected_hash != alias["sha256"]:
                raise ValueError("Go numbered object alias changed")
            self.walk(alias["producer"], expected_hash)
            return
        variants = self.producers.get(key, [])
        if len(variants) != 1:
            raise ValueError(f"missing or ambiguous captured producer: {name}")
        record = variants[0]
        if record["kind"] not in {"compile", "link", "archive"}:
            raise ValueError("compile-and-link must use separately captured translation units")
        for field in ("sources", "dependencies", "response_files", "inputs", "linker_inputs", "link_map"):
            checked_hashes(record[field])
        if digest(record["arguments"][0]) != record["compiler_sha256"]:
            raise ValueError("captured compiler identity changed")
        if not Path(record["directory"]).is_dir():
            raise ValueError("captured working directory was removed")
        self.graph_records.append(record)
        self.visiting.add(key)
        if record["kind"] == "compile":
            self._compile(record)
        elif record["kind"] == "archive":
            self._archive(record)
        else:
            self._link(record)
        self.visiting.remove(key)


    def _compile(self, record):
        if len(record["sources"]) != 1 or not record["dependencies"]:
            raise ValueError("translation unit has no complete dependency context")
        if "-std=c++20" in record["expanded_arguments"] or "-fmodules-ts" in record["expanded_arguments"]:
            raise ValueError("C++20/modules target needs an explicitly supported analysis contract")
        _verify_compile_mapping(record)
        self.selected.append(record)

    def _archive(self, record):
        if (not record["members"] or set(record["members"].values()) != set(record["inputs"])
                or any(Path(path).name != member for member, path in record["members"].items())):
            raise ValueError("archive member closure disagrees with real native producer")
        for child, child_hash in record["inputs"].items():
            self.walk(child, child_hash)

    def _link(self, record):
        verify_lto_limit(record, self.contract, self.checkout, self.root)
        if not record["inputs"]:
            raise ValueError("link target has no captured object inputs")
        if not record["link_map"] or not record["linker_inputs"]:
            raise ValueError("link target has no retained real linker input inventory")
        if not set(record["inputs"]).issubset(record["linker_inputs"]):
            raise ValueError("declared object inputs disagree with real linker map")
        if not set(self.external).issubset(record["linker_inputs"]):
            raise ValueError("declared external SDK input was not loaded by the real linker")
        for linked in record["linker_inputs"]:
            if (Path(linked).is_relative_to(self.checkout)
                    and linked not in record["inputs"] and linked not in self.external):
                raise ValueError("undeclared checkout input in real linker map")
        for child, child_hash in record["inputs"].items():
            self.walk(child, child_hash)


def _declared_sources(contract, checkout):
    expected = set()
    for name in contract["sources"]:
        path = checkout / name
        if (Path(name).is_absolute() or ".." in Path(name).parts or not path.is_file()
                or any(character in name for character in ",\r\n\0")):
            raise ValueError("declared target source is not a checkout file")
        if path.resolve() != path.absolute():
            raise ValueError("declared target source traverses a symlink")
        expected.add(str(path))
    if not expected or len(expected) != len(contract["sources"]):
        raise ValueError("target source closure is empty or duplicated")
    return expected


def _captured_producers(records):
    producers = {}
    for record in records:
        if record.get("schema") != 1:
            raise ValueError("unsupported capture schema")
        key = (record["output"], record["output_sha256"])
        producers.setdefault(key, []).append(record)
    return producers


def _verify_source_closure(selected, full_source_closure):
    actual = [name for record in selected for name in record["sources"]]
    if len(actual) != len(set(actual)):
        raise ValueError("multiple compilation variants of the same source in one target")
    # External host objects are not silently discarded. The contract must name
    # every source in the selected target; copied checkout code cannot pass.
    if set(actual) != full_source_closure:
        raise ValueError("captured target source closure disagrees with producer contract: "
                         + json.dumps({"missing": sorted(full_source_closure - set(actual)),
                                       "unexpected": sorted(set(actual) - full_source_closure)}))


def _indexed_parent_inputs(selected, checkout, expected):
    parent_dependencies = {name for record in selected for name in record["dependencies"]
                           if Path(name).is_relative_to(checkout)}
    parent_headers = parent_dependencies - expected
    indexed_inputs = expected | parent_dependencies
    if any(Path(name).resolve(strict=True) != Path(name) or any(character in name for character in ",\r\n\0")
           for name in indexed_inputs):
        raise ValueError("Parent indexed dependency path is noncanonical or ambiguous")
    indexed_relative = sorted(str(Path(name).relative_to(checkout)) for name in indexed_inputs)
    return parent_headers, indexed_inputs, indexed_relative


def _verify_context_compilations(context_compilations):
    for record in context_compilations:
        for field in ("sources", "dependencies", "response_files"):
            checked_hashes(record[field])
        if digest(record["arguments"][0]) != record["compiler_sha256"]:
            raise ValueError("external Go context compiler identity changed")


def _record_limitations(evidence, graph_records, go_chain):
    unretained = {name: reason for record in graph_records
                  for name, reason in record.get("compiler_internal_transients", {}).items()}
    if unretained:
        evidence["unretained_compiler_internal_inputs"] = unretained
        evidence["limitations"].append(
            "GCC internal LTO temporary bytes are not retained; real original-object target membership "
            "and source/headers are verified for SAST, not a complete final ELF/internal-LTO byte DAG.")
    if go_chain:
        evidence["limitations"].extend([
            "The native target includes actual producer-compiled static archive members; dead-code reachability is not asserted.",
            "Go IR, Go/C cross-language taint and external standard-library code are outside this C/C++ target claim."])


def export(root, contract, checkout, output, *, allow_dirty_development=False):
    checkout = checkout.resolve(strict=True)
    if (not output.is_absolute() or output.resolve() != output
            or output == checkout or output.is_relative_to(checkout) or checkout.is_relative_to(output)
            or output.exists() or output.is_symlink()):
        raise ValueError("export output must be fresh, canonical and external/disjoint from checkout")
    ancestor = output.parent
    while not ancestor.exists():
        ancestor = ancestor.parent
    SOURCE_MAPPING.verify_trusted_directory(ancestor)
    revision = subprocess.check_output(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
    if revision != contract["revision"]:
        raise ValueError("target contract disagrees with checkout revision")
    dirty = bool(subprocess.check_output(["git", "-C", str(checkout), "status", "--porcelain",
                                         "--untracked-files=all"]))
    if dirty and not allow_dirty_development:
        raise ValueError("native scan requires a clean exact-revision checkout")
    expected = _declared_sources(contract, checkout)
    external_sources = external_admission(contract, checkout)
    full_source_closure = expected | set(external_sources)
    external = contract.get("external_inputs", {})
    checked_hashes(external)
    records = [json.loads(path.read_text()) for path in sorted(root.glob("*.json"))]
    artifact = str(Path(contract["artifact"]).resolve(strict=True))
    artifact_hash = digest(artifact)
    go_chain = contract.get("go_producer_chain")
    object_aliases = {}
    context_compilations = []
    if go_chain:
        raw_link = GO_PROVENANCE.verify_chain(go_chain, checkout, Path(artifact), records)
        object_aliases = go_chain["object_aliases"]
        context_compilations = go_chain["external_context_compilations"]
        if any(external.get(name) != value for name, value in go_chain["external_go_inputs"].items()):
            raise ValueError("Go external input contract disagrees with actual producer chain")
    producers = _captured_producers(records)
    graph = _CapturedGraph(external, object_aliases, producers, contract, checkout, root)
    selected = graph.selected
    graph_records = graph.graph_records
    if go_chain:
        graph.walk(raw_link["output"], raw_link["output_sha256"])
    else:
        graph.walk(artifact, artifact_hash)
    _verify_source_closure(selected, full_source_closure)
    parent_headers, indexed_inputs, indexed_relative = _indexed_parent_inputs(selected, checkout, expected)
    _verify_context_compilations(context_compilations)
    context_by_output = {(record["output"], record["output_sha256"]): record for record in context_compilations}
    rows = [{"directory": record["directory"], "file": next(iter(record["sources"])),
             "arguments": record["arguments"], "output": record["output"]}
            for record in sorted([*selected, *context_by_output.values()], key=lambda item: next(iter(item["sources"])))]
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    database = output / "compile_commands.json"
    database.write_text(json.dumps(rows, indent=2) + "\n")
    evidence = {"schema": 1, "target": contract["target"], "revision": revision,
                "import_eligible": not dirty and not allow_dirty_development,
                "development_only": allow_dirty_development,
                "artifact": artifact, "artifact_sha256": artifact_hash,
                "compile_commands_sha256": digest(database), "translation_units": len(rows),
                "parent_product_sources": sorted(expected),
                "parent_product_headers": sorted(parent_headers),
                "external_build_context_sources": sorted(set(external_sources) | {
                    source for record in context_compilations for source in record["sources"]}),
                "scanner_expected_parent_translation_units": len(expected),
                "scanner_expected_parent_headers": len(parent_headers),
                "scanner_expected_parent_indexed_inputs": len(indexed_inputs),
                "scanner_expected_parent_input_paths": sorted(indexed_inputs),
                "scanner_scope": {"sonar.projectBaseDir": str(checkout),
                                  "sonar.sources": ",".join(indexed_relative),
                                  "sonar.cfamily.compile-commands": str(database),
                                  "sonar.coverage.exclusions": "**", "sonar.scm.revision": revision},
                "contract": contract, "captures": selected,
                "link_graph_records": graph_records,
                "limitations": ["No scanner or server-side taint/parse-quality result is asserted.",
                                 "External generated/upstream translation units are retained build context; "
                                 "only Parent-owned translation units are requested for indexing/taint analysis."]}
    _record_limitations(evidence, graph_records, go_chain)
    (output / "manifest.json").write_text(json.dumps(evidence, indent=2) + "\n")
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-root", required=True, type=Path)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--checkout", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--allow-dirty-development", action="store_true",
                        help="development proof only; output is NOT import eligible")
    args = parser.parse_args()
    try:
        evidence = export(args.capture_root, json.loads(args.contract.read_text()), args.checkout, args.output,
                          allow_dirty_development=args.allow_dirty_development)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"native target validation failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"target": evidence["target"], "translation_units": evidence["translation_units"],
                      "import_eligible": evidence["import_eligible"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
