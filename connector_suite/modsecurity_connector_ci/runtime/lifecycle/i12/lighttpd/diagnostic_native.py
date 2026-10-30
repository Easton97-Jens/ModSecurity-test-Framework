#!/usr/bin/env python3
"""Bind original stock-native diagnostics to real isolated instrumented hosts.

Preparation reuses the manifest's lighttpd capture variant. Execution uses its
separate waited raw client and observed backend, not in-process projections.
Root alone reviews oracle and lifecycle proposals with the existing qualifier.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, load_source
import argparse
import hashlib
import importlib.util
import json
import re
import os
from pathlib import Path
import shutil
import signal
import socket
from socketserver import TCPServer
import stat
import subprocess
import sys
import time


ROUTE = "lighttpd-stock-native-control"
PROC = Path("/proc")
TEXT_PLAIN = "text/plain"
HEALTHY_NEIGHBOR = "/diagnostic/healthy-neighbor"
HOST_BINARY = "/mnt/artifacts/bin/lighttpd"
BACKEND_LOG = "backend.jsonl"
EXTERNAL_ROOT = Path(os.environ.get("I12_TEST_ROOT", "/__i12_external_root_requires_I12_TEST_ROOT__")).absolute()
RUN_ROOT = EXTERNAL_ROOT / "runs"
TASK_ROOT = Path("/task")
READ_ROOTS = (TASK_ROOT, Path("/mnt"), EXTERNAL_ROOT, connector_root(), test_root(), Path("/usr"))


def sha(path):
    path = Path(path).resolve(strict=True)
    if not any(path.is_relative_to(root) for root in READ_ROOTS):
        raise ValueError("Hash input is outside approved source, image or task roots")
    if any(part in (".git", ".ssh", ".aws") for part in path.parts):
        raise ValueError("Sensitive directories are not diagnostic inputs")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_external_storage():
    for directory in (EXTERNAL_ROOT.parent, EXTERNAL_ROOT):
        details = directory.lstat()
        if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.geteuid() or details.st_mode & 0o022:
            raise ValueError("External diagnostic storage must be private and current-user-owned")


def physical_output(path, *, existing=False):
    path = path.absolute()
    if path.is_relative_to(EXTERNAL_ROOT):
        validate_external_storage()
    if (path.resolve() != path or not any(path.is_relative_to(root) for root in
            (TASK_ROOT, RUN_ROOT))):
        raise ValueError("Diagnostic output must be a physical task-owned absolute path")
    if path.exists() != existing:
        raise ValueError("Diagnostic output existence does not match its invocation scope")
    return path


def declared_cases(path):
    path = path.absolute()
    if path.resolve(strict=True) != path or not path.is_file() or path.stat().st_nlink != 1:
        raise ValueError("Case source must be a physical single-link file")
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("Case source exceeds 4 MiB")
    cases = json.loads(path.read_text())["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= 100:
        raise ValueError("Diagnostic case count outside bounded scope")
    names = [case["case_id"] for case in cases]
    if len(set(names)) != len(names) or any(not re.fullmatch(r"[A-Za-z0-9_-]+", name) for name in names):
        raise ValueError("Case IDs must be unique physical-directory-safe original names")
    return cases


def json_output_parts(path):
    path = Path(path).absolute()
    if path.is_relative_to(EXTERNAL_ROOT):
        validate_external_storage()
    roots = [root for root in (TASK_ROOT, RUN_ROOT) if path.is_relative_to(root)]
    if path.resolve() != path or not roots:
        raise ValueError("JSON output must be a physical task-owned path")
    root = roots[0]
    parts = path.relative_to(root).parts
    if not parts:
        raise ValueError("JSON output must name a file below its approved root")
    for part in parts:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", part) or part in (".", ".."):
            raise ValueError("JSON output components must be bounded literal names")
    return root, parts


def write(path, value):
    root, parts = json_output_parts(path)
    parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = child
        descriptor = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                             0o600, dir_fd=parent)
        with os.fdopen(descriptor, "w") as stream:
            details = os.fstat(stream.fileno())
            if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1 or details.st_uid != os.geteuid():
                raise ValueError("JSON output must be an owned single-link regular file")
            if details.st_mode & 0o077:
                raise ValueError("JSON output must have private file permissions")
            stream.truncate(0)
            stream.write(json.dumps(value, indent=2) + "\n")
    finally:
        os.close(parent)


def command(argv, directory, label, env=None):
    actual = ["rtk", "proxy", *map(str, argv)]
    result = subprocess.run(actual, capture_output=True, env=env, timeout=180)
    (directory / f"{label}.stdout").write_bytes(result.stdout)
    (directory / f"{label}.stderr").write_bytes(result.stderr)
    write(directory / f"{label}.command.json", {"argv": actual, "exitcode": result.returncode})
    if result.returncode:
        raise RuntimeError(f"{label} failed: {result.returncode}")
    return result


def copied_product_inputs(source, repository, stock):
    inputs = {}
    for path in source.rglob("*"):
        if not path.is_file():
            continue
        original = repository / path.relative_to(source)
        if sha(path) != sha(stock.regular(original)):
            raise ValueError("Copied product bytes differ from current checkout")
        mode = 493 if original.stat().st_mode & 0o111 else 420
        path.chmod(mode)
        inputs[str(path.relative_to(source))] = {"mode": mode, "sha256": sha(path)}
    return inputs


def materialize_current(args, stock):
    """Validate current product inventory, then add hash-verified capture tools.

    Historical source_targets for complete product files are deliberately never
    applied. The shared immutable store and its strict historical apply remain
    unchanged; this variant materializes only existing observation primitives.
    """
    source = args.output / "source"
    source.mkdir(mode=0o700)
    for relative in ("common", "connectors/lighttpd"):
        stock.copy_tree(args.repository / relative, source / relative)
    for relative in ("connectors/profile_registry.c", "connectors/profile_registry.h"):
        shutil.copyfile(stock.regular(args.repository / relative), source / relative)
    store = load_source(args.repository / 'ci/runtime/lifecycle/i12/capture_sources.py')
    registry = store.Registry()
    verified = registry.verify()
    head = command(["git", "-C", args.repository, "rev-parse", "HEAD"], args.output, "actual-head").stdout.decode().strip()
    if head != args.checkout_head:
        raise ValueError("Current checkout differs from explicitly selected product revision")
    tree = command(["git", "-C", args.repository, "rev-parse", "HEAD^{tree}"], args.output, "actual-tree").stdout.decode().strip()
    inputs = copied_product_inputs(source, args.repository, stock)
    snapshot = {"format": "i12-source-export-manifest-v1", "source_revision": head,
                "git_tree": tree, "files": inputs, "gitlinks": {}}
    write(source / store.SNAPSHOT, snapshot)
    write(source / store.MARKER, {"format": "i12-disposable-source-copy-v2", "path": str(source),
        "disposable": True, "source_revision": head, "snapshot_manifest": store.SNAPSHOT,
        "snapshot_manifest_sha256": sha(source / store.SNAPSHOT)})
    identity = store.disposable(source, registry.manifest["delivery_product_baseline"],
        Path(registry.manifest["authorized_storage_root"]))
    write(args.output / "current-export-validation.json", {"identity": identity, "immutable_store_verification": verified})
    profile = registry.manifest["profiles"]["lighttpd"]
    observations = {name: value for name, value in profile["source_targets"].items()
                    if name.startswith(("lighttpd-", "ci/runtime/lifecycle/native-lifecycle-"))}
    written = {}
    for prefix, entries in ((source, observations), (source / ".i12-capture/lighttpd", profile["capture_files"])):
        for name, value in entries.items():
            path = prefix / store.relative(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(registry.content(value["sha256"]))
            path.chmod(value.get("mode", 420))
            written[str(path.relative_to(source))] = sha(path)
    write(source / store.RECEIPT, {**identity, "profile": "lighttpd", "capture_variant": "current-product-stock-diagnostic",
        "historical_product_source_targets_applied": False, "exact_written_sha256": written,
        "source_copy_only": True, "runtime_qualified": False})
    build = args.output / "build"
    build.mkdir()
    strict = ["-Wall", "-Wextra", "-Werror", "-fPIC", "-fno-lto", "-pthread"]
    includes = ["-I", source, "-I", source / "common/include", "-I", source / "common/runtime",
                "-I", source / "ci/runtime/lifecycle", "-isystem", args.sdk / "include"]
    for name, relative in (("observer", "ci/runtime/lifecycle/native-lifecycle-observer.c"),
            ("host", "lighttpd-host-observer.c"), ("bootstrap", "lighttpd-observer-fd-bootstrap.c"),
            ("sdk", "ci/runtime/lifecycle/native-lifecycle-sdk.cpp")):
        compiler, standard = ("g++", "-std=c++17") if name == "sdk" else ("cc", "-std=c17")
        command([compiler, standard, *strict, *includes, "-c", source / relative, "-o", build / (name + ".o")],
                args.output, "compile-" + name)
    symbols = command(["nm", "-g", build / "observer.o"], args.output, "wrapped-symbols").stdout.decode()
    wrapped = sorted({line.split()[-1][7:] for line in symbols.splitlines()
                      if line.split() and line.split()[-1].startswith("__wrap_")})
    write(args.output / "build-binding.json", {"wrapped_symbols": wrapped, "current_product_inputs": inputs,
        "source_export_identity": identity, "capture_application_receipt_sha256": sha(source / store.RECEIPT)})


def numeric_loopback_client(original):
    """Retain the raw observer with explicit port/path inputs, without URL parsing.

    The host fixture is plaintext HTTP on isolated numeric loopback. Its client
    needs no scheme, DNS lookup, authority, redirect, or remote URL capability.
    """
    start = original.index("    if argument.startswith(")
    body_limit = re.search(r"^if len\(body\)>\d+", original[start:], re.MULTILINE)
    if body_limit is None:
        raise ValueError("Numeric diagnostic client body-limit anchor changed")
    end = start + body_limit.start()
    replacement = '''    if argument in ('--i12-port', '--i12-path'):
        if index+1>=len(arguments):raise SystemExit('incomplete numeric loopback argument')
        value=arguments[index+1];index+=2
        if argument=='--i12-port':
            if not value.isascii() or not value.isdecimal():raise SystemExit('port must be numeric')
            port=int(value)
        else:path=value
        continue
    raise SystemExit('unsupported fixture curl argument: '+argument)
if port is None or not 1<=port<=65535 or path is None or not path.startswith('/') or path.startswith('//'):
    raise SystemExit('fixture requires a numeric loopback port and origin-form path')
if any(character in path for character in '\\r\\n'):
    raise SystemExit('invalid origin-form path')
if header_file is None or body_file is None or writeout!='%{http_code}':
    raise SystemExit('incomplete exact fixture curl contract')
'''
    text = original[:start] + replacement + original[end:]
    text = text.replace("from urllib.parse import urlsplit\n", "", 1)
    text = text.replace("url=None", "port=None;path=None", 1)
    text = text.replace("path=parsed.path+('?' +parsed.query if parsed.query else '')\n", "", 1)
    text = text.replace("parsed.port", "port")
    if "parsed" in text or "urlsplit" in text:
        raise ValueError("Numeric diagnostic client anchors changed")
    compile(text, "diagnostic-numeric-raw-client.py", "exec")
    return text


def prepare(args):
    """Reuse existing variant preparation, then add stock-specific read-only hooks."""
    args.output.mkdir(mode=0o700)
    stock_path = args.repository / "ci/runtime/lifecycle/i12/lighttpd/stock_capture.py"
    stock = load_source(stock_path)
    materialize_current(args, stock)
    source = args.output / "source"
    module = source / "connectors/lighttpd/module/mod_msconnector.c"
    exported_module_hash = sha(module)
    current_module = args.repository / "connectors/lighttpd/module/mod_msconnector.c"
    before = sha(current_module)
    if exported_module_hash != before:
        raise ValueError("Current source inventory module changed before observation")
    shutil.copyfile(current_module, args.output / "current-product-mod_msconnector.c")
    prefix = "#ifndef _GNU_SOURCE\n#define _GNU_SOURCE\n#endif\n#include \"lighttpd-host-observer.h\"\n"
    current_text = current_module.read_text()
    text, deltas = prefix + current_text, []
    original, added = "} handler_ctx;", '} handler_ctx;\n#include "diagnostic_native_observer.h"'
    text = text.replace(original, added, 1)
    deltas.append((original, added))
    needle = "        const handler_t rc = mod_msconnector_apply_decision(r, p, ctx, &decision);"
    if text.count(needle) != 1:
        raise ValueError("Stock request-decision observation seam changed")
    added = needle + '\n        i12_diagnostic_host(r, ctx, "request_decision_returned");'
    text = text.replace(needle, added, 1)
    deltas.append((needle, added))
    needle = "    return mod_msconnector_apply_decision(r, p, ctx, &decision);"
    offset = text.rindex("REQUEST_FUNC(mod_msconnector_handle_response_start)")
    response = text[offset:]
    if response.count(needle) != 1:
        raise ValueError("Stock response-decision observation seam changed")
    added = ('    {\n        handler_t result = mod_msconnector_apply_decision(r, p, ctx, &decision);\n'
        '        i12_diagnostic_host(r, ctx, "response_decision_returned");\n        return result;\n    }')
    response = response.replace(needle, added, 1)
    deltas.append((needle, added))
    text = text[:offset] + response
    needle = "    int defer_transaction_finish = 0;"
    added = needle + '\n    i12_diagnostic_host(r, ctx, "request_reset_entered");'
    text = text.replace(needle, added, 1)
    deltas.append((needle, added))
    needle = "    result = mod_msconnector_error_response(r, runtime, code);"
    added = needle + '\n    i12_diagnostic_host(r, ctx, "technical_error_response_selected");'
    text = text.replace(needle, added, 1)
    deltas.append((needle, added))
    restored = text
    for original, added in reversed(deltas):
        if restored.count(added) != 1:
            raise ValueError("Diagnostic observation cannot be stripped unambiguously")
        restored = restored.replace(added, original, 1)
    if restored != prefix + current_text:
        raise ValueError("Diagnostic observation changed current product behavior")
    write(args.output / "observation-strip-identity.json", {"current_product_module_sha256": before,
        "stripped_product_sha256": hashlib.sha256(restored[len(prefix):].encode()).hexdigest(),
        "current_product_byte_identity_after_stripping_observation": True, "additive_seams": len(deltas),
        "historical_full_module_used_as_product": False})
    module.write_text(text)
    observer = args.repository / "ci/runtime/lifecycle/i12/lighttpd/diagnostic_native_observer.h"
    shutil.copyfile(observer, source / observer.name)
    fault_source = args.repository / "ci/runtime/lifecycle/i12/lighttpd/diagnostic_faults.h"
    shutil.copyfile(fault_source, source / fault_source.name)
    runtime_source = source / "common/runtime/msconnector_runtime.c"
    runtime_text = "#ifndef _GNU_SOURCE\n#define _GNU_SOURCE\n#endif\n#include \"diagnostic_faults.h\"\n" + runtime_source.read_text()
    for suffix, boundary in (("request_headers", "request_headers"), ("logging", "logging")):
        needle = f"msc_process_{suffix}(native->transaction) != 1"
        if runtime_text.count(needle) != 1:
            raise ValueError("Native diagnostic fault boundary changed")
        runtime_text = runtime_text.replace(needle,
            f'i12_diagnostic_boundary_result("{boundary}", msc_process_{suffix}(native->transaction)) != 1', 1)
    runtime_source.write_text(runtime_text)
    extension = load_source(args.repository / 'ci/runtime/lifecycle/i12/lighttpd/diagnostic_fault_capture.py')
    write(args.output / "extended-fault-overlay.json", extension.extend(source,
        args.repository / "ci/runtime/lifecycle/i12/lighttpd/patched_faults.h"))
    control_header = args.repository / "ci/runtime/lifecycle/i12/lighttpd/diagnostic_terminal_control.h"
    shutil.copyfile(control_header, source / control_header.name)
    terminal_before = sha(module)
    terminal_anchor = "    {\n        const handler_t rc = mod_msconnector_apply_decision(r, p, ctx, &decision);"
    terminal_seam = '''    {
        const int control = i12_diagnostic_terminal_control(ctx->transaction, &runtime_error);
        if (control != 0) return mod_msconnector_fail_request(r, p->runtime, ctx,
            control == 1 ? MSCONNECTOR_ERROR_TIMEOUT :
            control == 2 ? MSCONNECTOR_ERROR_HOST_API_FAILURE : runtime_error.code);
    }
'''
    terminal_text = module.read_text()
    if terminal_text.count(terminal_anchor) != 1:
        raise ValueError("Explicit diagnostic caller anchor changed")
    terminal_text = terminal_text.replace('#include "diagnostic_native_observer.h"',
        '#include "diagnostic_native_observer.h"\n#include "diagnostic_terminal_control.h"', 1)
    terminal_text = terminal_text.replace(terminal_anchor, terminal_seam + terminal_anchor, 1)
    module.write_text(terminal_text)
    write(args.output / "terminal-control-overlay.json", {"module_before_sha256": terminal_before,
        "module_after_sha256": sha(module), "header_sha256": sha(control_header),
        "scope": "Only explicitly selected diagnostic public timeout/cancel caller; no automatic SDK timer or native body-hook claim."})
    build = args.output / "native-build"
    build.mkdir()
    objects = [args.output / "build" / f"{name}.o" for name in ("observer", "host", "bootstrap", "sdk")]
    symbols = json.loads((args.output / "build-binding.json").read_text())["wrapped_symbols"]
    includes = ["-I", str(source), "-I", str(source / "ci/runtime/lifecycle")]
    wrapper = build / "observed-cc.py"
    wrapper.write_text(f"#!{sys.executable}\nimport subprocess,sys\nextra={includes!r}\n"
        f"if '-c' not in sys.argv: extra += {[str(x) for x in objects]!r} + "
        f"{['-Wl,--wrap=' + name for name in symbols]!r} + ['-lstdc++']\n"
        "raise SystemExit(subprocess.run(['rtk','proxy','cc',*sys.argv[1:],*extra]).returncode)\n")
    wrapper.chmod(0o500)
    environment = {**os.environ, "CC": str(wrapper), "BUILD_ROOT": str(build),
        "LIGHTTPD_SOURCE_DIR": str(args.core), "LIGHTTPD_BUILD_DIR": str(args.core_build),
        "MODSECURITY_INCLUDE_DIR": str(args.sdk / "include"),
        "MODSECURITY_LIB_DIR": str(args.sdk / "lib"), "LIGHTTPD_MSCONNECTOR_CORE_MODE": "stock"}
    command(["sh", source / "connectors/lighttpd/build/build_module.sh"], build, "native-build", environment)
    artifacts = args.output / "artifacts"
    (artifacts / "modules").mkdir(parents=True)
    (artifacts / "bin").mkdir()
    shutil.copyfile(args.host, artifacts / "bin/lighttpd")
    (artifacts / "bin/lighttpd").chmod(0o555)
    for original, name in [(build / "lighttpd-connector/modules/mod_msconnector.so", "mod_msconnector.so"),
                           (args.proxy_module, "mod_proxy.so")]:
        shutil.copyfile(original, artifacts / "modules" / name)
    fixtures = args.output / "fixtures"
    fixtures.mkdir()
    captured = source / ".i12-capture/lighttpd/stock-empty-drivers"
    for filename in ("curl-raw-client.py", "observed-backend.py"):
        shutil.copyfile(captured / filename, fixtures / filename)
    raw_client = fixtures / "curl-raw-client.py"
    raw_client.write_text(numeric_loopback_client(raw_client.read_text()))
    shutil.copyfile(args.repository / "ci/runtime/common/response_fixture_omission.py", fixtures / "response_fixture_omission.py")
    shutil.copyfile(Path(__file__), fixtures / "diagnostic_native.py")
    shutil.copyfile(args.repository / "ci/runtime/lifecycle/i12/lighttpd/diagnostic_transport.py", fixtures / "diagnostic_transport.py")
    for helper in ("i12_path_safety.py", "runtime_path_utils.py"):
        shutil.copyfile(args.repository / "ci/lib" / helper, fixtures / helper)
    write(args.output / "preparation.json", {"capture_contract_store_delivery_baseline": "8cc32dceb06121f589150a9794f28878c5e4ba2a",
        "checkout_head": args.checkout_head, "source_variant_receipt_sha256": sha(source / "i12-source-application-receipt.json"),
        "stock_module_before_diagnostic_overlay_sha256": before,
        "pre_observation_materialized_module_sha256": exported_module_hash,
        "historical_full_module_used_as_product": False,
        "current_product_module_sha256": before,
        "current_product_module_snapshot": str(args.output / "current-product-mod_msconnector.c"),
        "stock_module_after_diagnostic_overlay_sha256": sha(module), "diagnostic_overlay_sha256": sha(observer),
        "runtime_after_fault_overlay_sha256": sha(runtime_source), "fault_overlay_sha256": sha(fault_source),
        "host_sha256": sha(args.host), "host_module_sha256": sha(artifacts / "modules/mod_msconnector.so"),
        "sdk_sha256": sha(args.sdk / "lib/libmodsecurity.so"), "fixture_source_sha256": sha(Path(__file__)),
        "path_boundary_dependencies_sha256": {
            helper: sha(fixtures / helper)
            for helper in ("i12_path_safety.py", "runtime_path_utils.py")},
        "numeric_loopback_client_sha256": sha(raw_client),
        "observation_overlay_changes_decisions": False,
        "fault_overlay": "Only explicit declared modes alter caller pointers/stdio or Runtime boundary return, or invoke actual public timeout/cancel APIs; real native SDK returns stay separately recorded."})


def free_port():
    with socket.socket() as stream:
        stream.bind(("127.0.0.1", 0))
        return stream.getsockname()[1]


def start(directory, label, argv, environment):
    stdout = (directory / f"{label}.stdout").open("xb")
    stderr = (directory / f"{label}.stderr").open("xb")
    try:
        process = subprocess.Popen(["rtk", "proxy", *map(str, argv)], stdout=stdout,
                                   stderr=stderr, env=environment, start_new_session=True)
    except BaseException:
        stdout.close()
        stderr.close()
        raise
    return process, stdout, stderr


def stop(actor, actual_host=()):
    process, stdout, stderr = actor
    signalled, forced = [], False
    if process.poll() is None:
        for record in actual_host:
            proc = PROC / str(record["pid"])
            try:
                token = (proc / "stat").read_text().rsplit(")", 1)[1].split()[19]
                if token == record["starttime"]:
                    os.kill(record["pid"], signal.SIGTERM)
                    signalled.append(record["pid"])
            except (FileNotFoundError, ProcessLookupError):
                pass
        if not signalled:
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            forced = True
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
    stdout.close()
    stderr.close()
    return {"wrapper_pid": process.pid, "waited_exit": process.returncode, "reaped": process.poll() is not None,
            "actual_host_pids_signalled_after_starttime_verification": signalled, "forced_kill": forced}


def ready(port, process):
    for _ in range(200):
        if process.poll() is not None:
            raise RuntimeError("Actor exited before listening")
        rows = Path("/proc/net/tcp").read_text().splitlines()[1:]
        if any(line.split()[3] == "0A" and line.split()[1].endswith(f":{port:04X}") for line in rows):
            return
        time.sleep(0.02)
    raise TimeoutError("Actor did not listen")


def snapshot(directory, label, executable):
    records = []
    for proc in PROC.iterdir():
        if not proc.name.isdigit():
            continue
        try:
            if os.readlink(proc / "exe") != str(executable):
                continue
            token = (proc / "stat").read_text().rsplit(")", 1)[1].split()[19]
            (directory / f"{label}-{proc.name}.maps").write_bytes((proc / "maps").read_bytes())
            (directory / f"{label}-{proc.name}.status").write_bytes((proc / "status").read_bytes())
            fds, fd_metadata = {}, {}
            for descriptor in (proc / "fd").iterdir():
                try:
                    fds[descriptor.name] = os.readlink(descriptor)
                    details = descriptor.stat()
                    fd_metadata[descriptor.name] = {"device": details.st_dev, "inode": details.st_ino,
                        "mode": details.st_mode & 0o777, "owner_uid": details.st_uid, "nlink": details.st_nlink}
                except FileNotFoundError:
                    fds[descriptor.name] = {"closed_during_actual_snapshot": True}
            records.append({"pid": int(proc.name), "starttime": token, "exe_sha256": sha(proc / "exe"),
                "fds": fds, "fd_metadata": fd_metadata})
        except (FileNotFoundError, ProcessLookupError):
            continue
    write(directory / f"{label}-identity.json", records)
    return records


def stop_backend(*_):
    raise SystemExit(0)


class NumericLoopbackFixtureServer(TCPServer):
    """Private plaintext wire fixture; no DNS, wildcard bind or remote peers."""

    allow_reuse_address = True

    def __init__(self, port, handler):
        if type(port) is not int or not 0 <= port <= 65535:
            raise ValueError("Backend fixture requires an integer loopback TCP port")
        super().__init__(("127.0.0.1", port), handler)

    def verify_request(self, request, client_address):
        try:
            bound_address = self.socket.getsockname()[0]
            peer_address = request.getpeername()[0]
        except OSError:
            return False
        return (bound_address == "127.0.0.1"
                and client_address[0] == "127.0.0.1"
                and peer_address == "127.0.0.1")


def backend_handler(module, directory, case):
    module.Handler.body_bytes = b"diagnostic-native-response"
    headers = [("Content-Type", TEXT_PLAIN)]
    if case.get("backend_marker"):
        headers.append(("X-Modsec-Upstream", case["backend_marker"]))
    module.Handler.fixture = module.ResponseFixture(200, tuple(headers))
    class DiagnosticBackend(module.Handler):
        def _send_fixture(self, *, include_body):
            selected = self.fixture
            if self.path == HEALTHY_NEIGHBOR:
                self.fixture = module.ResponseFixture(200, (("Content-Type", TEXT_PLAIN),))
            try:
                delay = case.get("backend_chunk_delay_seconds", 0)
                if delay and self.path != HEALTHY_NEIGHBOR:
                    self._send_delayed(include_body, delay)
                    return
                if case.get("backend_short_length") and self.path != HEALTHY_NEIGHBOR:
                    self._send_short(include_body)
                    return
                super()._send_fixture(include_body=include_body)
            finally:
                self.fixture = selected

        def _send_delayed(self, include_body, delay):
            if not 0 < delay <= 2:
                raise ValueError("Declared backend chunk delay exceeds bounded fixture scope")
            self.send_response(200)
            self.send_header("Content-Type", TEXT_PLAIN)
            self.send_header("Content-Length", str(len(self.body_bytes)))
            self.end_headers()
            for payload in (self.body_bytes[:1], self.body_bytes[1:]):
                try:
                    written = self.wfile.write(payload) if include_body else 0
                    self.wfile.flush()
                    event = {"actual_body_write_return": written, "actual_flush_returned": True}
                except (BrokenPipeError, ConnectionResetError) as error:
                    event = {"actual_transport_exception": type(error).__name__}
                with (directory / "backend-transport.jsonl").open("a") as stream:
                    stream.write(json.dumps({"pid": os.getpid(), "monotonic_ns": time.monotonic_ns(),
                        "path": self.path, **event}) + "\n")
                time.sleep(delay)

        def _send_short(self, include_body):
            self.send_response(200)
            self.send_header("Content-Type", TEXT_PLAIN)
            self.send_header("Content-Length", str(len(self.body_bytes) + 9))
            self.end_headers()
            written = 0
            if include_body:
                written = self.wfile.write(self.body_bytes)
            self.wfile.flush()
            with (directory / "backend-transport.jsonl").open("a") as stream:
                stream.write(json.dumps({"pid": os.getpid(), "monotonic_ns": time.monotonic_ns(),
                    "actual_body_write_return": written, "declared_content_length": len(self.body_bytes) + 9,
                    "actual_flush_returned": True, "path": self.path}) + "\n")
            time.sleep(0.05)
            self.close_connection = True

    return DiagnosticBackend


def serve_numeric_loopback(server):
    server.timeout = 0.05
    while True:
        server.handle_request()


def backend(port, directory):
    sys.path.insert(0, "/mnt/fixtures")
    module = load_source('/mnt/fixtures/observed-backend.py')
    case = json.loads((directory / "case.json").read_text())
    server = NumericLoopbackFixtureServer(port, backend_handler(module, directory, case))
    signal.signal(signal.SIGTERM, stop_backend)
    try:
        serve_numeric_loopback(server)
    finally:
        server.server_close()


def wire_client(directory, label, port, request):
    source = directory / (label + ".wire-request.json")
    output = directory / (label + ".process.json")
    write(source, request)
    argv = ["rtk", "proxy", sys.executable, "/mnt/fixtures/diagnostic_transport.py",
            "--port", str(port), "--request", str(source), "--output", str(output)]
    started_unix_ns = time.time_ns()
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = process.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise
    ended_unix_ns = time.time_ns()
    (directory / (label + ".stdout")).write_bytes(stdout)
    (directory / (label + ".stderr")).write_bytes(stderr)
    receipt = json.loads(output.read_text())
    write(directory / (label + ".client.json"), receipt)
    command_receipt = {"argv": argv, "cwd": str(Path.cwd()), "wrapper_pid": process.pid,
        "waited_exit": process.returncode, "waited_signal": -process.returncode if process.returncode < 0 else None,
        "started_unix_ns": started_unix_ns, "ended_unix_ns": ended_unix_ns}
    write(directory / (label + ".command.json"), command_receipt)
    waited = {"waited_exit": process.returncode, "waited_signal": -process.returncode if process.returncode < 0 else None,
              "actual_argv": argv}
    receipt.update(waited)
    for earlier in receipt["prefix_receipts"]:
        earlier.update(waited)
    write(output, receipt)
    return receipt


def file_window_point(path):
    """Read actual file identity and offset at the synchronous driver boundary."""
    if path.resolve() != path:
        raise ValueError("Physical window observer refuses aliased files")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        details = os.fstat(stream.fileno())
        if not stat.S_ISREG(details.st_mode) or details.st_uid != os.geteuid() or details.st_nlink != 1:
            raise ValueError("Physical window observer requires own single-link regular file")
        return {"monotonic_ns": time.monotonic_ns(), "unix_ns": time.time_ns(),
            "pid": os.getpid(), "uid": os.geteuid(), "path": str(path),
            "device": details.st_dev, "inode": details.st_ino, "size": details.st_size,
            "mode": details.st_mode & 0o777, "owner_uid": details.st_uid, "nlink": details.st_nlink}


def loopback_target(port, request_path):
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("Diagnostic loopback port must be an integer TCP port")
    if (not isinstance(request_path, str) or not request_path.startswith("/") or request_path.startswith("//")
            or any(c in request_path for c in "\r\n")):
        raise ValueError("Diagnostic request target must be an absolute HTTP path")
    return ["--i12-port", str(port), "--i12-path", request_path]


def client(directory, label, port, request):
    if "raw_requests" in request:
        return wire_client(directory, label, port, request)
    environment = {**os.environ, "I12_APACHE_CLIENT_TOKEN": label}
    argv = [sys.executable, "/mnt/fixtures/curl-raw-client.py", "--http1.1", "-sS", "-D", str(directory / f"{label}.headers"),
            "-o", str(directory / f"{label}.body"), "-w", "%{http_code}", "-X", request.get("method", "GET")]
    for name, value in request.get("headers", []):
        argv += ["-H", f"{name}:{value}"]
    if "body_hex" in request:
        body = bytes.fromhex(request["body_hex"])
        if len(body) > 65536:
            raise ValueError("Diagnostic client entity exceeds 64 KiB")
        body_path = directory / (label + ".request-body")
        body_path.write_bytes(body)
        argv += ["--data-binary", "@" + str(body_path)]
    argv += loopback_target(port, request["path"])
    actual = ["rtk", "proxy", *argv]
    completed = subprocess.run(actual, env=environment, capture_output=True, timeout=30)
    (directory / f"{label}.stdout").write_bytes(completed.stdout)
    (directory / f"{label}.stderr").write_bytes(completed.stderr)
    receipt = json.loads((Path("/task/client") / f"{label}.receipt.json").read_text())
    receipt.update({"waited_exit": completed.returncode, "waited_signal": -completed.returncode if completed.returncode < 0 else None,
                    "actual_argv": actual})
    write(directory / f"{label}.process.json", receipt)
    return receipt


def unsupported_body_configuration_probes(directory, runtime, config):
    """Observe actual stock parser rejection, never emulate a body callback."""
    records = []
    for name in ("request", "response"):
        variant_runtime = directory / (name + "-streaming-runtime.conf")
        variant_config = directory / (name + "-streaming-lighttpd.conf")
        variant_runtime.write_text(runtime.read_text().replace(name + "_body_mode=none", name + "_body_mode=streaming", 1))
        variant_config.write_text(config.read_text().replace(str(runtime), str(variant_runtime), 1))
        argv = ["rtk", "proxy", HOST_BINARY, "-m", "/mnt/artifacts/modules", "-tt", "-f", str(variant_config)]
        result = subprocess.run(argv, capture_output=True, timeout=15)
        stdout = directory / (name + "-streaming.stdout")
        stderr = directory / (name + "-streaming.stderr")
        stdout.write_bytes(result.stdout)
        stderr.write_bytes(result.stderr)
        records.append({"mode": name, "argv": argv, "cwd": str(Path.cwd()), "waited_exit": result.returncode,
            "waited_signal": -result.returncode if result.returncode < 0 else None,
            "runtime_sha256": sha(variant_runtime), "host_config_sha256": sha(variant_config),
            "stdout_sha256": sha(stdout), "stderr_sha256": sha(stderr)})
    write(directory / "unsupported-body-configuration-probes.json", records)
    return records


def append_host_cleanup(receipt):
    for record in receipt.get("actual_host", []):
        proc = PROC / str(record["pid"])
        try:
            gone = (proc / "stat").read_text().rsplit(")", 1)[1].split()[19] != record["starttime"]
        except FileNotFoundError:
            gone = True
        receipt["actual_host_cleanup"].append({"pid": record["pid"], "starttime": record["starttime"], "same_process_gone": gone})


def run_case(output, case):
    directory = output / case["case_id"]
    directory.mkdir(mode=0o700)
    write(directory / "case.json", case)
    port, backend_port = free_port(), free_port()
    rules = directory / "rules.conf"
    audit = directory / "audit.log"
    text = case["rules"].replace("@@AUDIT_LOG@@", str(audit)).replace("@@AUDIT_LOG_DIR@@", str(directory))
    text += f'\nSecDebugLog "{directory}/debug.log"\nSecDebugLogLevel 5\n'
    rules.write_text(text)
    runtime = directory / "runtime.conf"
    runtime.write_text(f"enabled=on\nrules_file={rules}\nrequest_body_mode=none\nresponse_body_mode=none\n"
                       f"default_error_status=500\nevent_path={directory}/events.jsonl\n")
    with runtime.open("a") as extra:
        for key, value in case.get("runtime_settings", {}).items():
            extra.write(f"{key}={value}\n")
    config = directory / "lighttpd.conf"
    config.write_text('server.compat-module-load = "disable"\nserver.modules = ( "mod_proxy", "mod_msconnector" )\n'
        f'server.document-root = "{directory}"\nserver.bind = "127.0.0.1"\nserver.port = {port}\n'
        f'server.errorlog = "{directory}/host-error.log"\nmsconnector.enabled = "enable"\n'
        f'msconnector.config-file = "{runtime}"\n'
        f'proxy.server = ( "" => ( ( "host" => "127.0.0.1", "port" => {backend_port} ) ) )\n')
    if case.get("pre_native_control"):
        with config.open("a") as stream:
            stream.write('debug.log-request-header-on-error = "enable"\n'
                'server.feature-flags += ( "server.errorlog-high-precision" => "enable" )\n')
    actual_run_id = "i12d-" + hashlib.sha256(case["case_id"].encode()).hexdigest()[:12] + "-" + str(time.time_ns())
    environment = {**os.environ, "MSCONNECTOR_LIGHTTPD_NATIVE_OBSERVER": str(directory / "native.jsonl"),
        "MSCONNECTOR_LIGHTTPD_DIAGNOSTIC_HOST": str(directory / "host.jsonl"),
        "MSCONNECTOR_LIGHTTPD_DIAGNOSTIC_FAULT": case.get("fault", "off"),
        "MSCONNECTOR_LIGHTTPD_POINTER_FAULT": case.get("pointer_fault", "off"),
        "MSCONNECTOR_LIGHTTPD_SINK_FAULT": case.get("sink_fault", "off"),
        "MSCONNECTOR_LIGHTTPD_DIAGNOSTIC_BUDGET_LOG": str(directory / "budget.jsonl"),
        "MSCONNECTOR_LIGHTTPD_DIAGNOSTIC_FINISH_LOG": str(directory / "finish.jsonl"),
        "MSCONNECTOR_LIGHTTPD_DIAGNOSTIC_CONTROL": case.get("terminal_control", "off"),
        "MSCONNECTOR_LIGHTTPD_DIAGNOSTIC_CONTROL_LOG": str(directory / "control.jsonl"),
        "MSCONNECTOR_LIGHTTPD_DIAGNOSTIC_FAULT_LOG": str(directory / "fault.jsonl"),
        "MSCONNECTOR_LIFECYCLE_RUN": actual_run_id, "MSCONNECTOR_LIFECYCLE_PROFILE": ROUTE,
        "MSCONNECTOR_LIFECYCLE_CASE": case["case_id"], "MSCONNECTOR_APACHE_BACKEND_CAPTURE": str(directory / BACKEND_LOG)}
    actors, receipt = [], {"case_id": case["case_id"], "run_scoped_case_id": f'I12::{ROUTE}::{case["case_id"]}',
        "leg_id": ROUTE, "actual_run_id": actual_run_id, "uid": os.getuid(), "gid": os.getgid(), "execution_observed": False,
        "effective_config_sha256": sha(config), "rules_sha256": sha(rules), "case_contract": case}
    if case.get("prove_unsupported_body_modes"):
        receipt["unsupported_body_configuration_probes"] = unsupported_body_configuration_probes(directory, runtime, config)
    try:
        upstream = start(directory, "backend", [sys.executable, "/mnt/fixtures/diagnostic_native.py", "backend",
                         "--port", backend_port, "--output", directory], environment)
        actors.append(("backend", upstream))
        ready(backend_port, upstream[0])
        host = start(directory, "host", [HOST_BINARY, "-D", "-m", "/mnt/artifacts/modules", "-f", config], environment)
        actors.append(("host", host))
        if case.get("expected_startup_failure") is True:
            receipt["actual_startup_failure"] = {"host_process_waited_exit": host[0].wait(timeout=10),
                "http_request_executed": False,
                "reason": "Declared startup-boundary control waits for actual host termination; no readiness connection or HTTP request is sent."}
            return receipt
        ready(port, host[0])
        receipt["actual_host"] = snapshot(directory, "host", Path(HOST_BINARY))
        prefix = () if case.get("sequence_from_wire") else case.get("sequence_prefix", ())
        receipt["sequence_prefix"] = [client(directory, case["case_id"] + f"-prefix-{index}", port, request)
                                      for index, request in enumerate(prefix)]
        if case.get("pre_native_control"):
            receipt["main_window_before"] = {"event_sink": file_window_point(directory / "events.jsonl"),
                "core_diagnostic": file_window_point(directory / "host-error.log")}
        receipt["main"] = client(directory, case["case_id"], port, case["request"])
        if case.get("pre_native_control"):
            receipt["main_window_after"] = {"event_sink": file_window_point(directory / "events.jsonl"),
                "core_diagnostic": file_window_point(directory / "host-error.log")}
        receipt["sequence_prefix"].extend(receipt["main"].get("prefix_receipts", []))
        receipt["execution_observed"] = True
        time.sleep(0.05)
        backend_rows = (directory / BACKEND_LOG).read_text().splitlines() if (directory / BACKEND_LOG).exists() else []
        receipt["backend_main_rows"] = [line for line in backend_rows if
            receipt["main"]["started_ns"] <= json.loads(line)["monotonic_ns"] <= receipt["main"]["completed_ns"]]
        neighbor_request = case.get("neighbor_request", {"path": HEALTHY_NEIGHBOR})
        receipt["neighbor"] = client(directory, case["case_id"] + "-neighbor", port, neighbor_request)
        receipt["sequence_suffix"] = [client(directory, case["case_id"] + f"-suffix-{index}", port, request)
                                      for index, request in enumerate(case.get("sequence_suffix", ()))]
        receipt["after_main_host"] = snapshot(directory, "host-after", Path(HOST_BINARY))
    except RuntimeError as error:
        if case.get("expected_startup_failure") is not True:
            raise
        receipt["actual_startup_failure"] = {"error": str(error),
            "host_process_polled_exit": host[0].poll(),
            "http_request_executed": False}
    finally:
        receipt["actors_cleanup"] = {label: stop(actor, receipt.get("actual_host", ()) if label == "host" else ())
                                     for label, actor in reversed(actors)}
        receipt["actual_host_cleanup"] = []
        append_host_cleanup(receipt)
        listeners = Path("/proc/net/tcp").read_text().splitlines()[1:]
        receipt["listeners_after_cleanup"] = [line for line in listeners if line.split()[3] == "0A" and
            any(line.split()[1].endswith(f":{target:04X}") for target in (port, backend_port))]
        receipt["evidence"] = {p.name: {"sha256": sha(p), "bytes": p.stat().st_size} for p in directory.iterdir() if p.is_file()}
        write(directory / "capture.json", receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "run", "backend"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--port", type=int)
    for name in ("repository", "core", "core-build", "sdk", "host", "proxy-module", "cases"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--checkout-head", default="3af897f5c68da870da764da8f95fcb370d2f6e7d")
    args = parser.parse_args()
    os.umask(0o077)
    args.output = physical_output(args.output, existing=args.mode == "backend")
    if args.mode == "prepare":
        prepare(args)
    elif args.mode == "backend":
        backend(args.port, args.output)
    else:
        args.output.mkdir(mode=0o700)
        rows = [run_case(args.output, case) for case in declared_cases(args.cases)]
        write(args.output / "captures.json", rows)


if __name__ == "__main__":
    main()
