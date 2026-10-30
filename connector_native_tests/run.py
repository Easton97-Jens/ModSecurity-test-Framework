#!/usr/bin/env python3
"""Compile and run preserved native self-tests against an explicit product revision."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile


_COMMON_RUNTIME_PATH = 'common/runtime'


SIMPLE_TARGETS = {
    "envoy-bridge": ("envoy", "envoy_bridge", "msconnector_envoy_bridge_self_test()"),
    "lighttpd-bridge": ("lighttpd", "lighttpd_bridge", "msconnector_lighttpd_bridge_self_test() != MSCONNECTOR_STATUS_OK"),
    "traefik-decision-service": ("traefik", "traefik_decision_service", "msconnector_traefik_decision_service_self_test()"),
    "haproxy-spoa-starter": ("haproxy", "haproxy_spoa_agent_starter", "haproxy_spoa_agent_starter_self_test()"),
}
COMPLEX_TARGETS = {"traefik-engine", "haproxy-spop-runtime", "haproxy-modsecurity-binding"}
TARGETS = tuple(sorted(set(SIMPLE_TARGETS) | COMPLEX_TARGETS))


def checked_directory(value: str, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or any(c in value for c in '\\"\n\r'):
        raise ValueError(f"{label} must be an absolute canonical directory")
    for ancestor in (*reversed(path.parents), path):
        details = ancestor.lstat()
        if not stat.S_ISDIR(details.st_mode):
            raise ValueError(f"{label} must not contain symlinks or non-directories")
    return path.resolve(strict=True)


def checked_output(value: str, connector: Path, test_root: Path) -> Path:
    output = checked_directory(value, "output root")
    if output == Path("/") or any(output == root or root in output.parents for root in (connector, test_root.parent)):
        raise ValueError("native test output must be external to both source checkouts")
    for ancestor in (*reversed(output.parents), output):
        details = ancestor.stat()
        sticky_root = ancestor != output and details.st_uid == 0 and details.st_mode & stat.S_ISVTX
        if details.st_uid not in {0, os.geteuid()} or (details.st_mode & 0o022 and not sticky_root):
            raise ValueError("native test output must have trusted non-writable ancestry")
    if output.stat().st_uid != os.geteuid():
        raise ValueError("native test output root must belong to this invocation's user")
    return output


def process(command: list[str], *, timeout: int, log: Path, cwd: Path) -> int:
    """Keep all compiler/test descendants inside one bounded process group."""
    with log.open("xb") as stream:
        child = subprocess.Popen(command, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        try:
            result = child.wait(timeout=timeout)
            if result:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            return result
        except BaseException:
            try:
                os.killpg(child.pid, signal.SIGTERM)
                child.wait(timeout=2)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass
            finally:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()
            raise


def translation_unit(target: str, connector: Path, tests: Path) -> str:
    if target in SIMPLE_TARGETS:
        family, stem, invocation = SIMPLE_TARGETS[target]
        source = f"connectors/{family}/src/{stem}.c"
        return (f'#include "{connector / source}"\n'
                f'#include "{tests / source.replace(".c", ".inc")}"\n'
                f"int main(void) {{ return {invocation}; }}\n")
    if target == "traefik-engine":
        source = "connectors/traefik/src/traefik_engine_service.c"
        invocation = ("if (argc != 2) return 2; "
                      "return traefik_engine_protocol_self_test() == 0 && "
                      "traefik_engine_socket_ownership_self_test(argv[1]) == 0 ? 0 : 1;")
    elif target == "haproxy-spop-runtime":
        source = "connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c"
        invocation = "return run_runtime_self_test_command(argc, argv);"
    else:
        source = "connectors/haproxy/src/haproxy_modsecurity_binding.c"
        driver = tests.parent / "connector_suite/adapters/haproxy/src/haproxy_modsecurity_binding_self_test.c"
        if not driver.is_file():
            raise ValueError("Framework-owned HAProxy binding test driver is missing")
        return (f'#include "{connector / source}"\n'
                f'#include "{tests / source.replace(".c", ".inc")}"\n'
                f'#include "{driver}"\n')
    prelude = (f'#include "{tests / "connectors/traefik/src/traefik_engine_test_hooks.h"}"\n'
               if target == "traefik-engine" else "")
    return (prelude + "#define main msconnector_product_main\n"
            f'#include "{connector / source}"\n'
            "#undef main\n"
            f'#include "{tests / source.replace(".c", ".inc")}"\n'
            f"int main(int argc, char **argv) {{ {invocation} }}\n")


def run(args: argparse.Namespace) -> int:
    if os.environ.get("ON_DEMAND_TESTS") != "1" and not os.environ.get("ACTIVE_TEST_EXECUTION"):
        raise ValueError("native specialist tests require explicit ON_DEMAND_TESTS=1 or an admitted execution")
    connector = checked_directory(args.connector_root, "Connector root")
    tests = checked_directory(args.test_root, "test root")
    revision = subprocess.check_output(["git", "-C", str(connector), "rev-parse", "HEAD"], text=True).strip()
    if re.fullmatch(r"[a-f0-9]{40}", args.connector_revision) is None or revision != args.connector_revision:
        raise ValueError("Connector revision must exactly identify the explicit checkout HEAD")
    if not (connector / "common/include/msconnector/request.h").is_file():
        raise ValueError("Connector root lacks the product Common contract")
    if args.argument and (args.target != "haproxy-modsecurity-binding" or
                          len(args.argument) != 2 or args.argument[0] not in {"--self-test", "--self-test-crs"}):
        raise ValueError("only the binding target accepts its explicit self-test mode and rules file")
    output = checked_output(args.output_root, connector, tests)
    directory = Path(tempfile.mkdtemp(prefix=args.target + "-", dir=output))
    os.chmod(directory, 0o700)
    source = directory / "test.c"
    source.write_text(translation_unit(args.target, connector, tests), encoding="utf-8")
    flags = ["-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread"]
    for include in (connector, connector / "common/include", connector / _COMMON_RUNTIME_PATH,
                    connector / "connectors/traefik", connector / "connectors/traefik/src",
                    connector / "connectors/haproxy/src", connector / "connectors/envoy/src"):
        flags.extend(("-I", str(include)))
    if args.modsecurity_include:
        flags.extend(("-I", str(checked_directory(args.modsecurity_include, "ModSecurity include"))))
    sources = [source]
    if args.target in SIMPLE_TARGETS:
        sources += [connector / f"common/src/{name}.c"
                    for name in ("origin", "capabilities", "intervention", "block_statuses", "http_status", "status", "transaction")]
    else:
        sources += sorted((connector / "common/src").glob("*.c"))
        sources += sorted((connector / _COMMON_RUNTIME_PATH).glob("*.c"))
        sources.append(connector / "connectors/profile_registry.c")
        if args.target.startswith("haproxy-"):
            sources.append(connector / "connectors/haproxy/src/haproxy_modsecurity_mapper.c")
        if args.target == "haproxy-spop-runtime":
            sources += [connector / f"connectors/haproxy/src/{name}.c"
                        for name in ("haproxy_modsecurity_binding", "haproxy_spop_response_companion_backend")]
    compiler = os.environ.get("CC", "cc")
    linker = os.environ.get("CXX", "c++")
    # HEAD identifies the checkout; content digests identify the actual inputs,
    # including a deliberately dirty migration worktree. Never label a dirty
    # build as proof of the immutable HEAD's source bytes.
    bound = set(sources)
    bound.update((connector / "common/include").rglob("*.h"))
    bound.update((connector / _COMMON_RUNTIME_PATH).glob("*.h"))
    if args.target in SIMPLE_TARGETS:
        family, stem, _ = SIMPLE_TARGETS[args.target]
        product_source = connector / f"connectors/{family}/src/{stem}.c"
    elif args.target == "traefik-engine":
        family = "traefik"
        product_source = connector / "connectors/traefik/src/traefik_engine_service.c"
    else:
        family = "haproxy"
        stem = "haproxy_spop_diagnostic_runtime" if args.target == "haproxy-spop-runtime" else "haproxy_modsecurity_binding"
        product_source = connector / f"connectors/haproxy/src/{stem}.c"
    bound.add(product_source)
    bound.update((connector / f"connectors/{family}/src").glob("*.h"))
    bound.add(tests / product_source.relative_to(connector).with_suffix(".inc"))
    if args.target == "traefik-engine":
        bound.add(tests / "connectors/traefik/src/traefik_engine_test_hooks.h")
        bound.add(tests / "connectors/traefik/src/traefik_engine_protocol_helpers.inc")
    if args.target == "haproxy-modsecurity-binding":
        bound.add(tests.parent / "connector_suite/adapters/haproxy/src/haproxy_modsecurity_binding_self_test.c")
        if not args.argument:
            raise ValueError("binding test requires its explicit mode and rules file")
        rules = Path(args.argument[1])
        if not rules.is_absolute() or not rules.is_file() or rules.is_symlink():
            raise ValueError("binding test rules must be an explicit regular non-symlink file")
        bound.add(rules)

    def bindings() -> dict[str, str]:
        return {str(item): hashlib.sha256(item.read_bytes()).hexdigest() for item in sorted(bound)}

    source_bindings = bindings()
    bindings_file = directory / "input-bindings.json"
    bindings_file.write_text(json.dumps(source_bindings, indent=2) + "\n", encoding="utf-8")
    binding_digest = hashlib.sha256(bindings_file.read_bytes()).hexdigest()

    def compile_source(pair: tuple[int, Path]) -> Path:
        index, item = pair
        object_file = directory / f"source-{index}.o"
        code = process([compiler, *flags, "-c", str(item), "-o", str(object_file)],
                       timeout=120, log=directory / f"compile-{index}.log", cwd=connector)
        if code:
            raise RuntimeError(f"native compilation failed ({code}): {item}; log={directory / f'compile-{index}.log'}")
        return object_file

    with ThreadPoolExecutor(max_workers=os.cpu_count() or 1) as pool:
        objects = list(pool.map(compile_source, enumerate(sources)))
    binary = directory / "native-test"
    command = [linker, *(str(item) for item in objects), "-pthread"]
    if args.target in COMPLEX_TARGETS:
        if args.modsecurity_lib:
            library_root = checked_directory(args.modsecurity_lib, "ModSecurity library")
            command += ["-L", str(library_root), f"-Wl,-rpath,{library_root}"]
        command.append("-lmodsecurity")
    command += ["-o", str(binary)]
    if process(command, timeout=120, log=directory / "link.log", cwd=connector):
        raise RuntimeError(f"native link failed; log={directory / 'link.log'}")
    if args.build_only:
        code = 0
    else:
        invocation = [str(binary)]
        if args.target == "traefik-engine":
            if not args.socket_parent:
                raise ValueError("Traefik engine self-test requires an explicit short external --socket-parent")
            socket_parent = checked_output(args.socket_parent, connector, tests)
            private_sockets = Path(tempfile.mkdtemp(prefix="native-", dir=socket_parent))
            os.chmod(private_sockets, 0o700)
            invocation.append(str(private_sockets))
        elif args.target == "haproxy-spop-runtime":
            temporary = directory / "tmp"
            logs = directory / "logs"
            temporary.mkdir(mode=0o700)
            logs.mkdir(mode=0o700)
            invocation += ["--runtime-self-test", "--tmp-root", str(temporary), "--log-root", str(logs)]
        invocation += args.argument
        try:
            code = process(invocation, timeout=300, log=directory / "execution.log", cwd=connector)
        finally:
            if args.target == "traefik-engine":
                # The fixture owns/removes its inner socket directory. Retain
                # unexpected files rather than deleting outside that contract.
                try:
                    private_sockets.rmdir()
                except OSError:
                    pass
    receipt = {"schema_version": 1, "run_id": directory.name, "execution_id": args.target,
               "target": args.target, "profile": args.profile,
               "counting_scope": "specialist execution; no expanded unique-case count is derived",
               "connector_root": str(connector), "connector_revision": revision,
               "connector_worktree_dirty": bool(subprocess.check_output(
                   ["git", "-C", str(connector), "status", "--porcelain", "--untracked-files=no"], text=True)),
               "framework_revision": subprocess.check_output(
                   ["git", "-C", str(tests), "rev-parse", "HEAD"], text=True).strip(),
               "framework_worktree_dirty": bool(subprocess.check_output(
                   ["git", "-C", str(tests), "status", "--porcelain", "--untracked-files=no"], text=True)),
               "test_root": str(tests), "test_translation_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
               "input_bindings_sha256": binding_digest, "input_bindings_file": str(bindings_file),
               "binary": str(binary), "build_only": args.build_only,
               "status": "passed" if code == 0 else "failed", "exit_code": code}
    if bindings() != source_bindings:
        receipt.update(status="failed", exit_code=2, error="native test inputs changed during execution")
        code = 2
    (directory / "result.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2))
    return code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connector-root", required=True)
    parser.add_argument("--connector-revision", required=True)
    parser.add_argument("--test-root", required=True)
    parser.add_argument("--target", required=True, choices=TARGETS)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--profile", choices=("native-selftest",), default="native-selftest")
    parser.add_argument("--argument", action="append", default=[])
    parser.add_argument("--socket-parent")
    parser.add_argument("--modsecurity-include", default=os.environ.get("MODSECURITY_INCLUDE_DIR"))
    parser.add_argument("--modsecurity-lib", default=os.environ.get("MODSECURITY_LIB_DIR"))
    parser.add_argument("--build-only", action="store_true")
    try:
        return run(parser.parse_args())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"NATIVE_TEST_REJECTED: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
