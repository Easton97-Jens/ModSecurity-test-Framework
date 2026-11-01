#!/usr/bin/env python3
"""Link Apache-only test observers from one pinned, already captured fresh build.

The JSON spec names hash-bound build_identity, capture_receipt, make_stdout,
fault_receipt, fault_header, sdk_library and helper_objects (common/fault/bucket).
All instrumentation is written to a new output directory. No input is rebuilt
in place, and this receipt never qualifies runtime behavior.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import time

SOURCE_FILES = ("connectors/apache/src/mod_security3.c", "connectors/apache/src/msc_filters.c")
OBSERVERS = ("apache-host-observer.c", "apache-observer-fd-bootstrap.c",
             "native-lifecycle-observer.c", "native-lifecycle-sdk.cpp")
STRICT = {"-std=c17", "-Wall", "-Wextra", "-Werror", "-fno-lto", "-fPIC",
          "-fstack-protector-strong", "-Wformat", "-Werror=format-security"}
MAX_HASHED_INPUT_BYTES = 512 * 1024 * 1024
MAX_JSON_INPUT_BYTES = 64 * 1024 * 1024
SYSTEM_LIBRARY_ROOTS = (Path("/usr/lib"), Path("/usr/local/lib"))
SYSTEM_INCLUDE_ROOTS = (Path("/usr/include"), Path("/usr/local/include"))

# The shared native test matrix covers Common-runtime entry points that Apache
# neither links nor calls.  The captured apache-current observer defines the
# first 26 wrappers below; the remaining shared symbols have separate runtime
# and response-companion observers.  Keep this split explicit so a changing
# shared tuple requires review instead of silently intersecting ELF symbols.
APACHE_NATIVE_WRAPPED_SYMBOLS = (
    "msconnector_transaction_contract_init", "msconnector_transaction_contract_finish",
    "msconnector_transaction_contract_cleanup", "msconnector_transaction_contract_complete_phase",
    "msconnector_transaction_contract_set_response_committed",
    "msconnector_transaction_contract_record_response_metadata", "msc_new_transaction",
    "msc_new_transaction_with_id", "msc_transaction_cleanup", "msc_process_request_body",
    "msc_process_response_body", "msc_process_logging", "msc_append_request_body",
    "msc_append_response_body", "msc_process_request_headers", "msc_process_response_headers",
    "msc_intervention", "msconnector_runtime_transaction_begin",
    "msconnector_runtime_transaction_begin_request_stream",
    "msconnector_runtime_transaction_append_request_body_chunk",
    "msconnector_runtime_transaction_finish_request_body",
    "msconnector_runtime_transaction_process_response_headers",
    "msconnector_runtime_transaction_append_response_body_chunk",
    "msconnector_runtime_transaction_finish_response_body",
    "msconnector_runtime_transaction_finish", "msconnector_runtime_transaction_destroy",
)
SHARED_NON_APACHE_WRAPPED_SYMBOLS = (
    "msconnector_runtime_transaction_finalize_and_snapshot",
    "msconnector_runtime_response_companion_handoff_with_handle",
    "msconnector_runtime_response_companion_claim_handle",
    "msconnector_runtime_response_companion_revoke_handle",
    "msconnector_runtime_response_companion_session_process_response_headers",
    "msconnector_runtime_response_companion_session_append_response_body_chunk",
    "msconnector_runtime_response_companion_session_finish_response_body",
    "msconnector_runtime_response_companion_session_set_response_commit_state",
    "msconnector_runtime_response_companion_session_record_host_action",
    "msconnector_runtime_response_companion_session_fail",
    "msconnector_runtime_response_companion_session_cancel",
    "msconnector_runtime_response_companion_session_release",
)
APACHE_HOST_WRAPPED_SYMBOLS = ("msconnector_open_private_event_file", "apache_lifecycle_observe")


def file_identity(details):
    return (details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns,
            details.st_ctime_ns, details.st_uid, details.st_gid, details.st_mode,
            details.st_nlink)


def sha(path):
    """Hash one already selected regular file without following its final link."""
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_size < 0
                or before.st_size > MAX_HASHED_INPUT_BYTES):
            raise ValueError("Expected bounded regular input file")
        digest = hashlib.sha256()
        size = 0
        while True:
            block = os.read(descriptor, min(1024 * 1024, MAX_HASHED_INPUT_BYTES + 1 - size))
            if not block:
                break
            size += len(block)
            if size > MAX_HASHED_INPUT_BYTES:
                raise ValueError("Input exceeds the hash bound")
            digest.update(block)
        after = os.fstat(descriptor)
        if size != before.st_size or file_identity(before) != file_identity(after):
            raise ValueError("Input changed while hashing")
        return digest.hexdigest()
    except OSError as error:
        raise ValueError("Unable to read admitted regular input") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def read_regular_bytes(path, maximum=MAX_JSON_INPUT_BYTES):
    """Read bounded bytes once from one no-follow descriptor."""
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_size < 0
                or before.st_size > maximum):
            raise ValueError("Expected bounded regular input file")
        content = bytearray()
        while len(content) <= maximum:
            block = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(content)))
            if not block:
                break
            content.extend(block)
        after = os.fstat(descriptor)
        if (len(content) > maximum or len(content) != before.st_size
                or file_identity(before) != file_identity(after)):
            raise ValueError("Input changed while reading")
        return bytes(content)
    except OSError as error:
        raise ValueError("Unable to read admitted regular input") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def configured_storage_root():
    """Return the explicit task storage root, rejecting aliases and unsafe ancestry."""
    value = os.environ.get("CODEX_TEMP_ROOT")
    if not value or not isinstance(value, str):
        raise ValueError("CODEX_TEMP_ROOT must select the authorized evidence root")
    root = Path(value)
    if (not root.is_absolute() or ".." in root.parts or str(root) != value
            or root.resolve(strict=True) != root or not root.is_dir()):
        raise ValueError("Configured evidence root must be canonical")
    for ancestor in (root, *root.parents):
        details = ancestor.stat()
        sticky_shared = details.st_uid == 0 and details.st_mode & stat.S_ISVTX
        if (not stat.S_ISDIR(details.st_mode) or details.st_uid not in {0, os.geteuid()}
                or details.st_mode & 0o022 and not sticky_shared):
            raise ValueError("Configured evidence ancestry permits replacement")
    return root


def validate_private_ancestry(ancestor, anchor):
    """Require every directory through the admitted anchor to resist replacement."""
    while True:
        details = ancestor.stat()
        if (not stat.S_ISDIR(details.st_mode) or details.st_uid not in {0, os.geteuid()}
                or details.st_mode & 0o022):
            raise ValueError("Admitted input ancestry permits replacement")
        if ancestor == anchor:
            return
        ancestor = ancestor.parent


def admitted_path(value, roots, *, directory=False):
    """Admit a canonical absolute path below an explicit root before filesystem use."""
    if not isinstance(value, str) or not value or len(value) > 4096 or any(ord(char) < 32 for char in value):
        raise ValueError("Canonical admitted path required")
    supplied = Path(value)
    if (not supplied.is_absolute() or ".." in supplied.parts or str(supplied) != value
            or not any(supplied.is_relative_to(root) for root in roots)):
        raise ValueError("Input escapes authorized evidence roots")
    try:
        resolved = supplied.resolve(strict=True)
    except OSError as error:
        raise ValueError("Unable to resolve admitted input") from error
    if resolved != supplied or not any(resolved.is_relative_to(root) for root in roots):
        raise ValueError("Admitted input follows a link or escapes its root")
    details = resolved.stat()
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (not expected_type(details.st_mode) or details.st_uid not in {0, os.geteuid()}
            or details.st_mode & 0o022):
        raise ValueError("Admitted input has an unexpected object type")
    anchor = max((root for root in roots if resolved.is_relative_to(root)), key=lambda root: len(root.parts))
    validate_private_ancestry(resolved if directory else resolved.parent, anchor)
    return resolved


def new_output_path(value, storage):
    """Admit one fresh output below the configured storage root."""
    if not isinstance(value, str) or not value or len(value) > 4096 or any(ord(char) < 32 for char in value):
        raise ValueError("Canonical output path required")
    output = Path(value)
    if (not output.is_absolute() or ".." in output.parts or str(output) != value
            or output == storage or not output.is_relative_to(storage)):
        raise ValueError("Output escapes configured evidence storage")
    parent = output.parent.resolve(strict=True)
    if parent != output.parent or output.resolve(strict=False) != output or output.exists():
        raise ValueError("Output must be fresh and cannot follow links")
    ancestor = parent
    while True:
        details = ancestor.stat()
        if (not stat.S_ISDIR(details.st_mode) or details.st_uid not in {0, os.geteuid()}
                or details.st_mode & 0o022):
            raise ValueError("Output ancestry permits replacement")
        if ancestor == storage:
            break
        ancestor = ancestor.parent
    return output


def source_member(root, name):
    """Resolve an inventory member without accepting absolute or parent paths."""
    if not isinstance(name, str):
        raise ValueError("Source inventory name must be text")
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts or str(relative) != name:
        raise ValueError("Source inventory member escapes the source root")
    return admitted_path(str(root / relative), (root,))


def bound(item, roots):
    if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
        raise ValueError("Exact path and hash binding required")
    path = admitted_path(item["path"], roots)
    if sha(path) != item["sha256"]:
        raise ValueError("Input hash mismatch: " + str(path))
    return path


def bound_json(item, roots):
    if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
        raise ValueError("Exact path and hash binding required")
    path = admitted_path(item["path"], roots)
    content = read_regular_bytes(path)
    if hashlib.sha256(content).hexdigest() != item["sha256"]:
        raise ValueError("Input hash mismatch: " + str(path))
    return json.loads(content)


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError("Source anchor must occur exactly once: " + before)
    return text.replace(before, after, 1)


def instrument(texts, anchors):
    """Apply separately receipted fault seams and actual pre-read bucket hooks."""
    result = dict(texts)
    if len(anchors) != 4:
        raise ValueError("Expected all four versioned fault anchors")
    for anchor in anchors:
        name = anchor["file"]
        if name not in SOURCE_FILES or anchor["occurrences_required"] != 1:
            raise ValueError("Unexpected fault anchor scope")
        result[name] = replace_once(result[name], anchor["original"], anchor["replacement"])
    name = SOURCE_FILES[0]
    result[name] = replace_once(result[name],
        "    return msconnector_transaction_contract_record_request_metadata(&msr->contract,",
        "    if (!i12_apache_fault_request_metadata(r)) return 0;\n"
        "    return msconnector_transaction_contract_record_request_metadata(&msr->contract,")
    name = SOURCE_FILES[1]
    result[name] = replace_once(result[name],
        "    ret = apr_bucket_read(bucket, &data, &len, block);",
        '    apache_lifecycle_observe("actual_request_apr_bucket_before_read", msr, r, bucket);\n'
        "    ret = apr_bucket_read(bucket, &data, &len, block);")
    result[name] = replace_once(result[name],
        "    rc = apr_bucket_read(bucket, &data, &len, APR_BLOCK_READ);",
        '    apache_lifecycle_observe("actual_response_apr_bucket_before_read", msr, msr->r, bucket);\n'
        "    rc = apr_bucket_read(bucket, &data, &len, APR_BLOCK_READ);")
    result[name] = replace_once(result[name],
        "    ret = apr_bucket_read(bucket, &data, &len, block);\n"
        "    if (ret != APR_SUCCESS)\n        return ret;",
        "    ret = apr_bucket_read(bucket, &data, &len, block);\n"
        "    if (ret != APR_SUCCESS)\n        return ret;\n"
        "    (void)i12_apache_fault_after_bucket_read(r, &data, len, ret);")
    return result


def compiler_argv(log, relative):
    matches = []
    for line in log.splitlines():
        if not line.startswith("libtool: compile:"):
            continue
        argv = shlex.split(line.split("libtool: compile:", 1)[1])
        if "-c" in argv and argv[argv.index("-c") + 1] == relative:
            matches.append(argv)
    if len(matches) != 1:
        raise ValueError("Canonical compiler command is missing or ambiguous: " + relative)
    argv = matches[0]
    if not STRICT.issubset(argv) or argv.count("-c") != 1 or argv.count("-o") != 1:
        raise ValueError("Canonical compiler command lost strict flags")
    if "-include" in argv or any(a.startswith("@") for a in argv):
        raise ValueError("Unexpected pre-existing injection in compile command")
    reject_dependency_outputs(argv)
    return argv


def reject_dependency_outputs(argv):
    """Reject optional compiler outputs rather than writing into the build tree."""
    dependency_flags = ("-M", "-MM", "-MD", "-MMD", "-MF", "-MT", "-MQ", "-MP", "-MG", "-MJ")
    for flag in argv:
        if (any(flag == item or flag.startswith(item) for item in dependency_flags)
                or flag.startswith(("-Wp,-M", "--dependencies", "--write-dependencies",
                                    "--user-dependencies", "--dependency-file", "--dependency-target",
                                    "-save-temps", "-dumpdir", "-dumpbase", "-fprofile-", "-ftest-coverage"))
                or flag == "-Xpreprocessor"):
            raise ValueError("Canonical compiler auxiliary/dependency output is not allowed: " + flag)


def validate_wrapper_definitions(symbol_table, symbols):
    defined = set()
    for line in symbol_table.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[0].rstrip(":").isdigit() and fields[6] != "UND":
            defined.add(fields[7].split("@", 1)[0])
    if any("__wrap_" + name not in defined for name in symbols):
        raise ValueError("ELF defined wrapper implementation missing")


def validate_sdk_resolution(ldd_output, sdk):
    """Check only the selected SDK; Apache-host imports are resolved by httpd."""
    resolutions = []
    for line in ldd_output.splitlines():
        fields = line.split()
        if not fields or not Path(fields[0]).name.startswith("libmodsecurity.so"):
            continue
        if len(fields) >= 3 and fields[1] == "=>" and fields[2] != "not":
            path = Path(fields[2])
        elif fields[0].startswith("/"):
            path = Path(fields[0])
        else:
            raise ValueError("Selected SDK is unresolved in ldd output")
        if not path.is_absolute() or path.resolve() != Path(sdk).resolve():
            raise ValueError("ldd resolved a different SDK library")
        resolutions.append(str(path.resolve()))
    if len(resolutions) != 1:
        raise ValueError("Expected exactly one selected SDK resolution")
    return resolutions[0]


def validate_source_snapshot(root, snapshot, written):
    for name, record in snapshot["files"].items():
        file = source_member(root, name)
        if sha(file) != written.get(name, record["sha256"]):
            raise ValueError("Source snapshot changed: " + name)
    for name, expected in written.items():
        file = source_member(root, name)
        if sha(file) != expected:
            raise ValueError("Capture output changed: " + name)


def native_symbols(path):
    assignments = [node for node in ast.parse(path.read_text()).body
                   if isinstance(node, ast.Assign) and any(
                       isinstance(target, ast.Name) and target.id == "SYMBOLS"
                       for target in node.targets)]
    if len(assignments) != 1:
        raise ValueError("Native wrapper list missing or ambiguous")
    symbols = ast.literal_eval(assignments[0].value)
    if not isinstance(symbols, tuple) or not symbols or len(symbols) != len(set(symbols)):
        raise ValueError("Invalid native wrapper list")
    return list(symbols)


def apache_wrapped_symbols(path):
    """Return the exact wrappers implemented by the Apache observer set."""
    shared = native_symbols(path)
    expected_shared = list(APACHE_NATIVE_WRAPPED_SYMBOLS + SHARED_NON_APACHE_WRAPPED_SYMBOLS)
    if shared != expected_shared:
        raise ValueError("Shared native wrapper contract changed; review Apache observer scope")
    return list(APACHE_NATIVE_WRAPPED_SYMBOLS + APACHE_HOST_WRAPPED_SYMBOLS)


def validate_capture_identity(root, marker, capture, identity):
    """Reconcile the source, capture manifest and complete inventory bindings."""
    if capture.get("profile") != "apache-current" or capture.get("source_copy") != str(root):
        raise ValueError("Complete apache-current capture required")
    if identity.get("source_revision") != marker["source_revision"] or capture.get("source_revision") != marker["source_revision"]:
        raise ValueError("Source revisions disagree")
    if identity.get("git_tree") != capture.get("source_git_tree") or not identity.get("git_tree"):
        raise ValueError("Source trees disagree")
    manifest = source_member(root, "ci/runtime/lifecycle/i12/manifest.json")
    if sha(manifest) != capture.get("capture_manifest_sha256"):
        raise ValueError("Capture manifest changed")
    inventory = source_member(root, marker["snapshot_manifest"])
    inventory_content = read_regular_bytes(inventory)
    inventory_sha256 = hashlib.sha256(inventory_content).hexdigest()
    if (inventory_sha256 != marker["snapshot_manifest_sha256"]
            or inventory_sha256 != identity["source_inventory_sha256"]
            or inventory_sha256 != capture["snapshot_manifest_sha256"]):
        raise ValueError("Full source inventory binding mismatch")
    snapshot = json.loads(inventory_content)
    written = capture["exact_written_sha256"]
    if not written or not all(name in written for name in SOURCE_FILES):
        raise ValueError("Incomplete capture receipt")
    validate_source_snapshot(root, snapshot, written)


def validate_product_build(spec, storage, identity):
    """Admit all fresh objects and the transcript from their canonical build."""
    objects = identity["objects"]
    if len(objects) != 33 or identity.get("fresh_product_translation_units") != 33 or identity.get("historical_objects_reused") is not False:
        raise ValueError("All 33 fresh Product objects required")
    for path, expected in objects.items():
        bound({"path": path, "sha256": expected}, (storage,))
    if any(record.get("exit") != 0 for record in identity["commands"]):
        raise ValueError("Failed canonical build cannot be reused")
    make_record = [r for r in identity["commands"] if r["label"] == "make"]
    make_path = bound(spec["make_stdout"], (storage,))
    if len(make_record) != 1 or make_record[0]["stdout_sha256"] != sha(make_path):
        raise ValueError("Compiler transcript does not belong to this build")
    return make_path


def validate_sdk_inputs(spec, storage, identity):
    """Bind the selected SDK library and its complete header inventory."""
    sdk = bound(spec["sdk_library"], (storage, *SYSTEM_LIBRARY_ROOTS))
    if str(sdk) != identity["sdk"]["path"] or sha(sdk) != identity["sdk"]["sha256"]:
        raise ValueError("Selected SDK differs from canonical build")
    include = admitted_path(spec["sdk_include"], (storage, *SYSTEM_INCLUDE_ROOTS), directory=True)
    if not (include / "modsecurity/transaction.h").is_file():
        raise ValueError("Explicit selected SDK include root required")
    for path, expected in identity["sdk_headers"].items():
        if not Path(path).is_relative_to(include):
            raise ValueError("SDK header inventory differs from selected include root")
        bound({"path": path, "sha256": expected}, (include,))
    return sdk, include


def validate_helper_inputs(spec, storage, capture):
    """Bind helpers and ensure fault anchors target the captured Product source."""
    if set(spec["helper_objects"]) != {"common", "fault", "bucket"}:
        raise ValueError("Exact Common, fault and bucket helpers required")
    helpers = {name: bound(item, (storage,)) for name, item in spec["helper_objects"].items()}
    fault = bound_json(spec["fault_receipt"], (storage,))
    if fault.get("exit") != 0 or fault.get("helper_revision") != 2 or fault.get("object_sha256") != sha(helpers["fault"]):
        raise ValueError("Fault helper identity mismatch")
    header = bound(spec["fault_header"], (storage,))
    for anchor in fault["external_source_anchors"]:
        if capture["actual_before_sha256"].get(anchor["file"]) != anchor["source_sha256"]:
            raise ValueError("Fault anchors target a different Product revision")
    return helpers, fault, header


def validate_inputs(spec):
    storage = configured_storage_root()
    root = admitted_path(spec["source_root"], (storage,), directory=True)
    output = new_output_path(spec["output"], storage)
    if output.is_relative_to(root) or root.is_relative_to(output):
        raise ValueError("Output must be fresh and disjoint from input source")
    if (root / ".git").exists():
        raise ValueError("Only a disposable source export may be instrumented")
    marker = json.loads(read_regular_bytes(source_member(root, ".i12-disposable-source-copy.json")))
    if marker.get("format") != "i12-disposable-source-copy-v2" or marker.get("disposable") is not True or marker.get("path") != str(root):
        raise ValueError("Disposable v2 identity required")
    capture = bound_json(spec["capture_receipt"], (storage,))
    identity = bound_json(spec["build_identity"], (storage,))
    validate_capture_identity(root, marker, capture, identity)
    make_path = validate_product_build(spec, storage, identity)
    sdk, include = validate_sdk_inputs(spec, storage, identity)
    helpers, fault, header = validate_helper_inputs(spec, storage, capture)
    symbols = apache_wrapped_symbols(root / "tests/test_native_lifecycle_observer.py")
    if spec["wrapped_symbols"] != symbols:
        raise ValueError("Wrapper list must exactly preserve the Apache-defined observer scope")
    return root, output, identity, capture, helpers, fault, header, sdk, include, make_path, symbols


def compile_observers(root, output, include, receipt, run):
    compiled = []
    includes = ["-I", str(root), "-I", str(root / "common/include"), "-I", str(root / "ci/runtime/lifecycle"),
                "-I", str(root / "connectors/apache/src"), "-I", "/usr/include/apache2", "-I", "/usr/include/apr-1.0",
                *([] if include == Path("/usr/include") else ["-isystem", str(include)])]
    receipt["observer_objects"] = {}
    for filename in OBSERVERS:
        cpp = filename.endswith(".cpp")
        source = root / ("connectors/apache/src" if filename.startswith("apache-") else "ci/runtime/lifecycle") / filename
        obj = output / (source.stem + ".o")
        argv = ["g++" if cpp else "cc", "-std=c++17" if cpp else "-std=c17", "-Wall", "-Wextra", "-Werror",
                "-pthread", "-fPIC", "-fno-lto", *(["-D_GNU_SOURCE"] if filename == "apache-host-observer.c" else []),
                *includes, "-c", str(source), "-o", str(obj)]
        run("compile-" + source.stem, argv, root)
        compiled.append(obj)
        receipt["observer_objects"][str(obj)] = {"sha256": sha(obj), "source_sha256": sha(source)}
    return compiled


def validate_elf_hardening(dynamic, program, link_argv):
    if "BIND_NOW" not in dynamic or "-Wl,-Bsymbolic-functions" not in link_argv:
        raise ValueError("ELF immediate binding or symbolic-function linkage missing")
    if "GNU_RELRO" not in program:
        raise ValueError("ELF RELRO missing")
    stack = [line for line in program.splitlines() if "GNU_STACK" in line]
    if len(stack) != 1 or "RWE" in stack[0]:
        raise ValueError("ELF non-executable stack missing")


def validate_unchanged_build_inputs(root, identity, capture, texts, storage):
    # Rebind the complete inventory/capture outputs after all compiler/linker
    # commands. Checking only the two copied TUs would miss another source file
    # changed by a tool while these immutable inputs were in use.
    marker = json.loads(read_regular_bytes(source_member(root, ".i12-disposable-source-copy.json")))
    inventory = source_member(root, marker["snapshot_manifest"])
    inventory_content = read_regular_bytes(inventory)
    if hashlib.sha256(inventory_content).hexdigest() != identity["source_inventory_sha256"]:
        raise ValueError("Source inventory changed during build")
    validate_source_snapshot(root, json.loads(inventory_content), capture["exact_written_sha256"])
    for name, text in texts.items():
        if (root / name).read_text() != text:
            raise ValueError("Input source mutated during build")
    for path, expected in identity["objects"].items():
        if sha(admitted_path(path, (storage,))) != expected:
            raise ValueError("Original Product object mutated during build")


def build(spec_path):
    storage = configured_storage_root()
    spec_path = admitted_path(str(spec_path), (storage,))
    spec = json.loads(spec_path.read_text())
    root, output, identity, capture, helpers, fault, header, sdk, include, make_path, symbols = validate_inputs(spec)
    texts = {name: (root / name).read_text() for name in SOURCE_FILES}
    changed = instrument(texts, fault["external_source_anchors"])
    canonical = {name: compiler_argv(make_path.read_text(), "src/" + Path(name).name) for name in SOURCE_FILES}
    output.mkdir(mode=0o700, parents=True)
    commands = []
    receipt = {"schema": "apache-i12-observed-module-build-v1", "spec_sha256": sha(spec_path),
               "builder_sha256": sha(__file__), "source_root": str(root),
               "source_revision": identity["source_revision"], "git_tree": identity["git_tree"],
               "historical_objects_reused": False,
               "input_bindings": spec, "commands": commands, "runtime_qualification": None,
               "source_input_mutated": False, "retained_product_objects": {},
               "instrumented_sources": {}, "wrapped_symbols": symbols,
               "shared_non_apache_wrapped_symbols": list(SHARED_NON_APACHE_WRAPPED_SYMBOLS)}

    def save():
        (output / "build-identity.json").write_text(json.dumps(receipt, indent=2) + "\n")

    def run(label, argv, cwd):
        started = time.time_ns()
        # GCC can emit dependencies through inherited environment variables even
        # when no dependency flag appears in its captured canonical argv.
        env = {key: value for key, value in os.environ.items()
               if key not in {"DEPENDENCIES_OUTPUT", "SUNPRO_DEPENDENCIES"}}
        result = subprocess.run(["rtk", "proxy", *map(str, argv)], cwd=cwd, env=env,
                                capture_output=True, timeout=180)
        out, err = output / (label + ".stdout"), output / (label + ".stderr")
        out.write_bytes(result.stdout)
        err.write_bytes(result.stderr)
        record = {"label": label, "argv": ["rtk", "proxy", *map(str, argv)], "cwd": str(cwd),
                  "exit": result.returncode, "started_ns": started, "ended_ns": time.time_ns(),
                  "stdout_sha256": sha(out), "stderr_sha256": sha(err)}
        commands.append(record)
        save()
        if result.returncode:
            raise RuntimeError("Build command failed; retained receipt: " + label)
        return result.stdout.decode(errors="replace")

    replacement_objects = {}
    for name in SOURCE_FILES:
        original = root / name
        target = output / "source-overlay" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(changed[name])
        obj = output / (original.stem + ".o")
        argv = list(canonical[name])
        old_obj = (root / "connectors/apache" / argv[argv.index("-o") + 1]).resolve()
        if str(old_obj) not in identity["objects"]:
            raise ValueError("Canonical object not present in fresh build receipt")
        argv[argv.index("-c") + 1] = str(target)
        argv[argv.index("-o") + 1] = str(obj)
        argv += ["-iquote", str(original.parent), "-include", str(header),
                 "-ffile-prefix-map=" + str(output) + "=/i12/observer-overlay"]
        run("recompile-" + original.stem, argv, root / "connectors/apache")
        replacement_objects[str(old_obj)] = obj
        receipt["instrumented_sources"][name] = {"before_sha256": sha(original),
            "after_sha256": sha(target), "path": str(target), "canonical_argv": canonical[name],
            "original_object_sha256": identity["objects"][str(old_obj)], "object_sha256": sha(obj)}

    product = []
    for path, expected in identity["objects"].items():
        selected = replacement_objects.get(path, Path(path))
        product.append(selected)
        if path not in replacement_objects:
            receipt["retained_product_objects"][path] = expected
    if len(receipt["retained_product_objects"]) != 31:
        raise ValueError("Expected exactly 31 unchanged fresh Product objects")
    compiled = compile_observers(root, output, include, receipt, run)
    module = output / "mod_security3.so"
    link_argv = ["g++", "-shared", "-fPIC", "-fno-lto", "-pthread", "-Wl,--as-needed",
        "-Wl,-Bsymbolic-functions", "-Wl,-z,relro", "-Wl,-z,now", *product, *compiled,
        *helpers.values(), *["-Wl,--wrap=" + name for name in symbols], str(sdk),
        "-Wl,-rpath," + str(sdk.parent), "-o", str(module)]
    run("link-observed", link_argv, root)
    dynamic = run("elf-dynamic", ["readelf", "-d", str(module)], root)
    program = run("elf-program", ["readelf", "-W", "-l", str(module)], root)
    symbol_table = run("elf-symbols", ["readelf", "-W", "-s", str(module)], root)
    libraries = run("linked-libraries", ["ldd", str(module)], root)
    receipt["resolved_sdk"] = validate_sdk_resolution(libraries, sdk)
    validate_elf_hardening(dynamic, program, link_argv)
    validate_wrapper_definitions(symbol_table, symbols)
    validate_unchanged_build_inputs(root, identity, capture, texts, storage)
    receipt.update({"module": str(module), "module_sha256": sha(module),
                    "product_translation_units": 33, "recompiled_product_translation_units": 2,
                    "historical_objects_reused": False, "sdk_sha256": sha(sdk)})
    save()
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    args = parser.parse_args()
    result = build(args.spec)
    print(json.dumps({"module": result["module"], "module_sha256": result["module_sha256"],
                      "runtime_qualification": None}, sort_keys=True))


if __name__ == "__main__":
    main()
