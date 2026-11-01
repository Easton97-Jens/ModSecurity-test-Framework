#!/usr/bin/env python3
"""Build the existing Envoy I12 capture in a fresh, Git-free source copy.

This producer never launches a host. Its receipts qualify source/build and
native controls only; route qualification requires separate host evidence.
"""
from modsecurity_test_framework.connector_context import load_source
import argparse
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import time
if __package__:
    from . import source_inventory, evidence_io
else:
    import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.source_inventory as source_inventory
    import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.evidence_io as evidence_io

MODULE_PATH = 'connectors/envoy/ext_proc'
GO_MOD = 'go.mod'
GO_SUM = 'go.sum'
OBSERVER_TEST = 'tests/test_native_lifecycle_observer.py'
OBSERVER_ARCHIVE = 'libi12_envoy_observer.a'
ALL_PACKAGES = './...'
SYSTEM_INCLUDE = '/usr/include'


# These installed image roots are policy, independent of CLI/receipt paths.
# Evidence roots keep their descriptor/no-follow policy; only public installed
# images may use the SDK/Go symlinks supplied by the operating system.
PUBLIC_INSTALL_ROOTS = tuple(map(Path, (
    "/usr/include", "/usr/lib", "/usr/local/lib", "/usr/bin", "/usr/local/go")))


def sha(path):
    evidence_roots = evidence_io.DEFAULT_ROOTS
    path, root = evidence_io.approved_path(path, (*evidence_roots, *PUBLIC_INSTALL_ROOTS))
    roots = evidence_roots
    if root in PUBLIC_INSTALL_ROOTS:
        # Approve the lexical input before resolve can inspect any filesystem
        # object, then approve the resolved image under installed roots again.
        path = path.resolve(strict=True)
        evidence_io.approved_path(path, PUBLIC_INSTALL_ROOTS)
        roots = PUBLIC_INSTALL_ROOTS
    return evidence_io.reference(path, roots)["sha256"]


def load(path, _name):
    module = load_source(path)
    return module


def validate(source, out, env, run, go, sdk_include, sdk_library, controls_only=False):
    module = source / MODULE_PATH
    before = {name: sha(module / name) for name in (GO_MOD, GO_SUM)}
    symbols = load(source / OBSERVER_TEST, "observer_validation").SYMBOLS
    observer_flags = " ".join([str(out / OBSERVER_ARCHIVE),
        "-Wl,--undefined=msconnector_lifecycle_sdk_transaction_id",
        *("-Wl,--wrap=" + name for name in symbols)])
    env.update(CGO_ENABLED="1", CGO_CFLAGS=" ".join(["-D_DEFAULT_SOURCE -std=c17",
        *('-I' + str(path) for path in (source, source / "common/include",
          source / "common/runtime", sdk_include))]),
        CGO_LDFLAGS=" ".join([str(out / "build/envoy-ext-proc/libmsconnector_envoy_ext_proc_common.a"),
            observer_flags, str(sdk_library), "-Wl,-rpath," + str(sdk_library.parent), "-lstdc++ -pthread"]))
    if not controls_only:
        run("go-native", [go, "test", "-tags", "libmodsecurity", "-count=1", ALL_PACKAGES], module)
        run("go-race", [go, "test", "-race", "-tags", "libmodsecurity", "-count=1", ALL_PACKAGES], module)
        run("go-vet", [go, "vet", "-tags", "libmodsecurity", ALL_PACKAGES], module)
    control_output = out / "observer-controls"
    suffix = 1
    while control_output.exists():
        suffix += 1
        control_output = out / ("observer-controls-" + str(suffix))
    env["NATIVE_OBSERVER_TEST_OUT"] = str(control_output)
    if sdk_include == Path(SYSTEM_INCLUDE):
        # Shared controls hardcode -isystem. Use byte-identical physical headers
        # outside GCC's canonical include_next directory, without editing tests.
        private_include = out / "control-sdk-include"
        if not private_include.exists():
            shutil.copytree(sdk_include / "modsecurity", private_include / "modsecurity")
        headers = {str(path.relative_to(sdk_include)): sha(path)
                   for path in (sdk_include / "modsecurity").rglob("*") if path.is_file()}
        copied = {str(path.relative_to(private_include)): sha(path)
                  for path in private_include.rglob("*") if path.is_file()}
        if headers != copied:
            raise ValueError("private control SDK header bytes differ")
        (out / "control-sdk-headers.json").write_text(json.dumps({
            "source": str(sdk_include), "copy": str(private_include),
            "headers_sha256": headers, "byte_identical": True}, indent=2) + "\n")
        env["MODSECURITY_INCLUDE_DIR"] = str(private_include)
    run("native-observer-controls", ["python3", source / OBSERVER_TEST], source)
    if before != {name: sha(module / name) for name in before}:
        raise ValueError("Go module input mutated")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--revision", help="Exact full lowercase commit SHA to archive; required for a fresh build")
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--module-cache", type=Path, required=True,
                        help="Existing offline module cache; copied before use")
    parser.add_argument("--go", type=Path, default=Path("/usr/local/go/bin/go"))
    parser.add_argument("--sdk-include", type=Path, default=Path(SYSTEM_INCLUDE))
    parser.add_argument("--sdk-library", type=Path,
                        default=Path("/usr/lib/x86_64-linux-gnu/libmodsecurity.so"))
    parser.add_argument("--tmp-root", type=Path,
                        help="Private physical short directory for Unix-socket test paths")
    parser.add_argument("--validate-existing", action="store_true",
                        help="Validate this producer's hash-bound existing build without rebuilding")
    parser.add_argument("--controls-only", action="store_true",
                        help="With --validate-existing, retry native controls after successful Go checks")
    args = parser.parse_args()
    if args.controls_only and not args.validate_existing:
        parser.error("--controls-only requires --validate-existing")
    if not args.validate_existing or args.revision is not None:
        try:
            source_inventory.full_revision(args.revision)
        except ValueError as exc:
            parser.error(str(exc))
    return args


def existing_receipt(args, source, out, parser):
    receipt = json.loads((out / "receipt.json").read_text())
    if not receipt.get("build_ready") or receipt["source_copy"] != str(source):
        parser.error("existing build receipt is not ready or names a different source")
    if args.revision is not None and args.revision != receipt['actual_source_commit']:
        parser.error("existing build revision differs")
    if args.controls_only:
        for label in ("go-native", "go-race", "go-vet"):
            if not any(check["exit_code"] == 0 and
                       (check["label"] == label or check["label"].startswith(label + "-retry-"))
                       for check in receipt["checks"]):
                parser.error("--controls-only requires successful existing " + label)
    return receipt


def prepare_temporary(args, storage, parser):
    temp = args.tmp_root.absolute()
    if storage not in temp.parents or temp.resolve() != temp:
        parser.error("temporary directory must be physical under external project storage")
    temp.mkdir(mode=0o700, parents=True, exist_ok=True)
    if temp.is_symlink() or temp.stat().st_uid != os.getuid() or temp.stat().st_mode & 0o077:
        parser.error("temporary directory must be private and owned by the current user")


def prepare_paths(args):
    storage = evidence_io.configured_storage(required=True)
    checkout = args.checkout.resolve(strict=True)
    root = args.run_root.absolute()
    if storage not in root.parents or root.resolve() != root:
        raise ValueError("run root must be a physical external project-storage path")
    root.mkdir(parents=True, exist_ok=True)
    source, out = root / "source", root / "native-build"
    if not args.validate_existing and (source.exists() or out.exists()):
        raise ValueError("fresh source and native-build destinations required")
    out.mkdir(exist_ok=args.validate_existing)
    env = os.environ.copy()
    env.update(PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1",
               PIP_REQUIRE_VIRTUALENV="true", PIP_DISABLE_PIP_VERSION_CHECK="1")
    receipt = {"schema": "i12.envoy.native-build.v1", "host_launched": False,
               "source_copy": str(source), "checks": [], "status": "in_progress"}
    parser = argparse.ArgumentParser(description=__doc__)
    if args.validate_existing:
        receipt = existing_receipt(args, source, out, parser)
    if args.tmp_root:
        prepare_temporary(args, storage, parser)
    return checkout, root, source, out, env, receipt


class CommandRunner:
    def __init__(self, checkout, out, env, receipt):
        self.checkout, self.out, self.env, self.receipt = checkout, out, env, receipt

    def save(self):
        out, receipt = self.out, self.receipt
        (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")


    def __call__(self, label, command, cwd=None, timeout=1800):
        out, env, receipt = self.out, self.env, self.receipt
        if cwd is None:
            cwd = self.checkout
        previous = sum(check["label"] == label or check["label"].startswith(label + "-retry-")
                       for check in receipt["checks"])
        if previous:
            label += "-retry-" + str(previous)
        argv = ["rtk", "proxy", *map(str, command)]
        started = time.time_ns()
        try:
            proc = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=timeout)
            stdout, stderr, code = proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired as exc:
            stdout, stderr, code = exc.stdout or b"", exc.stderr or b"", 124
        for name, data in (("stdout", stdout), ("stderr", stderr)):
            (out / (label + "." + name)).write_bytes(data)
        receipt["checks"].append({"label": label, "argv": argv, "cwd": str(cwd),
            "start_ns": started, "finish_ns": time.time_ns(), "exit_code": code,
            "environment": {key: env[key] for key in (
                "CGO_ENABLED", "CGO_CFLAGS", "CGO_LDFLAGS", "TMPDIR",
                "MODSECURITY_INCLUDE_DIR", "NATIVE_OBSERVER_TEST_OUT",
                "GOROOT", "GOOS", "GOARCH", "GOTOOLCHAIN") if key in env},
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest()})
        self.save()
        print(json.dumps({"label": label, "exit_code": code}), flush=True)
        if code:
            raise RuntimeError(label + " failed; inspect " + str(out))
        return stdout



def validate_existing(args, source, out, receipt, env, run):
    source_inventory.verify(source, receipt)
    module = source / MODULE_PATH
    if receipt["module_inputs"] != {name: sha(module / name) for name in (GO_MOD, GO_SUM)}:
        raise ValueError("existing build Go module input hash mismatch")
    for relative, expected in receipt["binaries"].items():
        if sha(out / relative) != expected:
            raise ValueError("existing build binary hash mismatch: " + relative)
    application = json.loads((source / "i12-source-application-receipt.json").read_text())
    for relative, expected in application["exact_written_sha256"].items():
        if sha(source / relative) != expected:
            raise ValueError("existing source overlay hash mismatch: " + relative)
    if receipt["sdk_library"]["sha256"] != sha(args.sdk_library):
        raise ValueError("existing build SDK hash mismatch")
    env.update(receipt["environment"])
    env.update(MODSECURITY_LIB_DIR=str(args.sdk_library.parent),
               PATH=str(args.go.parent) + os.pathsep + env["PATH"])
    if args.tmp_root:
        env["TMPDIR"] = str(args.tmp_root.absolute())
    receipt["validation_environment"] = {"TMPDIR": env["TMPDIR"]}
    if 'go_provenance' in receipt:
        previous = receipt['go_provenance']
        if sha(args.go.resolve(strict=True)) != previous['executable_sha256']:
            raise ValueError('existing build Go executable hash mismatch')
        if 'tools' in previous:
            verify_go_toolchain_hashes(previous)
        isolate_go_environment(args.go, env)
        profile = json.loads((source / source_inventory.MANIFEST).read_text())['profiles']['envoy']
        record_go_provenance(args.go, env, receipt, run, profile)
    validate(source, out, env, run, args.go, args.sdk_include, args.sdk_library, args.controls_only)
    receipt["status"] = "pass"
    receipt.pop("failure", None)
    run.save()


def extract_source_archive(source, archive):
    with tarfile.open(fileobj=io.BytesIO(archive)) as stream:
        for member in stream.getmembers():
            target = source / member.name
            if (not target.is_relative_to(source) or ".." in Path(member.name).parts
                    or not (member.isfile() or member.isdir())):
                raise ValueError("source archive contains unsupported entry: " + member.name)
        stream.extractall(source, filter="data")


def apply_capture(capture, registry, source, receipt):
    # Verify the entire original registry before constructing a private adapter.
    # Neither the archived nor the checked-in manifest is rewritten.
    registry, metadata = source_inventory.verified_registry(
        capture, registry, receipt['actual_source_commit'], receipt['manifest_sha256'])
    if metadata is not None:
        receipt['envoy_registry_adapter'] = metadata
    profile = registry.manifest['profiles']['envoy']
    source_inventory.observer_contract(profile)
    before = receipt['source_before_overlay']
    historical = all(before.get(name) == old
                     for name, (old, _current) in source_inventory.OBSERVER_HASHES.items())
    if not historical:
        metadata = source_inventory.adapter_metadata(
            registry.manifest, before, receipt['actual_source_commit'], receipt['manifest_sha256'])
        registry = copy.copy(registry)
        registry.manifest = copy.deepcopy(registry.manifest)
        for name in metadata['preserved_targets']:
            del registry.manifest['profiles']['envoy']['source_targets'][name]
        receipt['envoy_capture_adapter'] = metadata
    return capture.apply(registry, 'envoy', source)


def prepare_source(source, receipt, run, revision):
    revision = source_inventory.full_revision(revision)
    head = run("source-head", ["git", "rev-parse", "--verify", revision + '^{commit}']).decode().strip()
    if head != revision:
        raise ValueError('resolved source revision differs from requested commit')
    archive = run("source-archive", ["git", "archive", "--format=tar", head])
    source.mkdir()
    extract_source_archive(source, archive)
    capture = load(source / "ci/runtime/lifecycle/i12/capture_sources.py", "envoy_capture")
    registry = capture.Registry(root=source / "ci/runtime/lifecycle/i12", repository=source)
    (source / capture.MARKER).write_text(json.dumps({
        "format": "i12-disposable-source-copy-v1", "path": str(source),
        "disposable": True, "parent_sha": registry.manifest["delivery_product_baseline"]}))
    receipt["actual_source_commit"] = head
    receipt['source_revision_selection'] = {'requested': revision, 'resolved': head}
    receipt["capture_marker_parent_is_historical_contract"] = True
    receipt["manifest_sha256"] = sha(source / "ci/runtime/lifecycle/i12/manifest.json")
    profile = registry.manifest["profiles"]["envoy"]
    receipt["source_before_overlay"] = {
        name: sha(source / name) for name in profile["source_targets"]}
    run.save()
    # The shared materializer verifies all original bytes before any overlay.
    receipt["capture_application"] = apply_capture(capture, registry, source, receipt)
    for name in profile["capture_files"]:
        if name.startswith("source-copy-tests/"):
            relative = name.removeprefix("source-copy-tests/")
            target = source / relative
            if target.exists():
                raise ValueError("source-copy test already present: " + relative)
            target.write_bytes((source / ".i12-capture/envoy" / name).read_bytes())
    # The capture stores text modes; the native builder requires its helper executable.
    for name in ("build_ext_proc.sh", "build_composite.sh"):
        (source / "connectors/envoy/build" / name).chmod(0o755)
    receipt["source_copy_executable_modes"] = ["build_ext_proc.sh", "build_composite.sh"]
    receipt["complete_source_inventory"] = source_inventory.verify(source, receipt)
    module = source / MODULE_PATH
    dependency_hashes = {name: sha(module / name) for name in (GO_MOD, GO_SUM)}
    receipt["module_inputs"] = dependency_hashes
    return profile, dependency_hashes


def configure_native_environment(args, root, out, receipt, env):
    shutil.copytree(args.module_cache.resolve(strict=True), root / "offline-mod")
    (root / "tmp").mkdir()
    env.update(GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off", GOWORK="off",
               GOFLAGS="-mod=readonly -p=" + str(os.cpu_count() or 1),
               GOMAXPROCS=str(os.cpu_count() or 1), GOCACHE=str(root / "go-cache"),
               GOMODCACHE=str(root / "offline-mod"), TMPDIR=str(args.tmp_root.absolute() if args.tmp_root else root / "tmp"),
               BUILD_ROOT=str(out / "build"), MODSECURITY_INCLUDE_DIR=str(args.sdk_include),
               MODSECURITY_LIB_DIR=str(args.sdk_library.parent),
               MODSECURITY_LIB_FILE=str(args.sdk_library),
               PATH=str(args.go.parent) + os.pathsep + env["PATH"])
    isolate_go_environment(args.go, env)
    receipt["environment"] = {key: env[key] for key in (
        "GOROOT", "GOOS", "GOARCH", "GOTOOLCHAIN", "GOPROXY", "GOSUMDB", "GOWORK", "GOFLAGS", "GOMAXPROCS",
        "GOCACHE", "GOMODCACHE", "TMPDIR", "BUILD_ROOT", "MODSECURITY_INCLUDE_DIR",
        "MODSECURITY_LIB_FILE")}
    receipt["sdk_library"] = {"path": str(args.sdk_library), "sha256": sha(args.sdk_library)}


def go_root(go):
    executable = go.resolve(strict=True)
    if not go.is_absolute() or go.name != 'go' or executable.name != 'go' or executable.parent.name != 'bin':
        raise ValueError('selected Go must resolve to its physical GOROOT/bin/go')
    return executable.parent.parent


def isolate_go_environment(go, env):
    root = go_root(go)
    env.update(GOROOT=str(root), GOOS='linux', GOARCH='amd64', GOTOOLCHAIN='local',
               PATH=str(root / 'bin') + os.pathsep + env.get('PATH', ''))


def verify_go_toolchain_hashes(identity):
    paths = {'driver': {'path': identity['executable_path'], 'sha256': identity['executable_sha256']},
             **identity['tools']}
    for name, item in paths.items():
        path = Path(item['path'])
        if path.resolve(strict=True) != path or not path.is_file() or sha(path) != item['sha256']:
            raise ValueError('Go toolchain executable changed: ' + name)


def record_go_provenance(go, env, receipt, run, profile):
    version = profile['provenance']['go_version']
    if not isinstance(version, str) or re.fullmatch(r'\d+\.\d+\.\d+', version, flags=re.ASCII) is None:
        raise ValueError('exact capture Go version required')
    executable = go.resolve(strict=True)
    root = go_root(go)
    selected = shutil.which('go', path=env.get('PATH', ''))
    if (not go.is_absolute() or go.name != 'go' or not executable.is_file()
            or selected is None or Path(selected).resolve(strict=True) != executable
            or env.get('GOTOOLCHAIN') != 'local'
            or env.get('GOROOT') != str(root)
            or env.get('GOOS') != 'linux' or env.get('GOARCH') != 'amd64'):
        raise ValueError('native build must use the selected local Go executable for linux/amd64')
    identity = {'required_version': version, 'required_identity': 'go version go' + version + ' linux/amd64',
                'actual_identity': None, 'configured_path': str(go), 'executable_path': str(executable),
                'executable_sha256': sha(executable), 'verified': False}
    receipt['go_provenance'] = identity
    output = run('go-version', [go, 'version'])
    identity['actual_identity'] = output.decode('utf-8', errors='replace').removesuffix('\n')
    if sha(executable) != identity['executable_sha256']:
        run.save()
        raise ValueError('Go executable changed during provenance capture')
    if output != (identity['required_identity'] + '\n').encode():
        run.save()
        raise ValueError('Go version differs from exact capture provenance')
    required = {'GOROOT': str(root), 'GOOS': 'linux', 'GOARCH': 'amd64', 'GOVERSION': 'go' + version,
                'GOTOOLDIR': str(root / 'pkg/tool/linux_amd64')}
    identity['required_environment'] = required
    output = run('go-environment', [go, 'env', *required])
    identity['environment_output'] = output.decode('utf-8', errors='replace')
    identity['actual_environment'] = None
    if output != ''.join(value + '\n' for value in required.values()).encode():
        run.save()
        raise ValueError('Go environment differs from isolated capture toolchain')
    identity['actual_environment'] = dict(zip(required, output.decode().splitlines()))
    identity['tools'] = {}
    for name in ('compile', 'link'):
        path = root / 'pkg/tool/linux_amd64' / name
        if path.resolve(strict=True) != path or not path.is_file():
            raise ValueError('Go tool must be physical inside selected GOROOT: ' + name)
        item = {'path': str(path), 'sha256': sha(path), 'required_identity': name + ' version go' + version}
        identity['tools'][name] = item
        output = run('go-' + name + '-version', [path, '-V'])
        item['actual_identity'] = output.decode('utf-8', errors='replace').removesuffix('\n')
        if output != (item['required_identity'] + '\n').encode():
            run.save()
            raise ValueError('Go tool version differs from exact capture provenance: ' + name)
    verify_go_toolchain_hashes(identity)
    identity['verified'] = True
    run.save()


def compile_native(args, source, out, env, receipt, run, profile):
    if sha(args.sdk_library) != profile["provenance"]["sdk_image_sha256"]:
        raise ValueError("SDK library differs from the selected capture contract")
    record_go_provenance(args.go, env, receipt, run, profile)
    controls = load(source / OBSERVER_TEST, "envoy_observer_controls")
    symbols = controls.SYMBOLS
    if len(symbols) != 38 or len(set(symbols)) != 38:
        raise ValueError("expected exact shared 38-symbol observer contract")
    receipt["wrap_symbols"] = list(symbols)
    flags = ["-Wall", "-Wextra", "-Werror"]
    run("observer", ["gcc", "-std=c17", *flags, "-pthread", "-I", source / "common/include",
        "-I", args.sdk_include, "-c", source / "ci/runtime/lifecycle/native-lifecycle-observer.c",
        "-o", out / "observer.o"])
    # Re-adding /usr/include as -isystem changes include_next ordering in GCC.
    sdk_cpp_flags = [] if args.sdk_include == Path(SYSTEM_INCLUDE) else ["-isystem", args.sdk_include]
    run("accessor", ["g++", "-std=c++17", *flags, *sdk_cpp_flags, "-c",
        source / "ci/runtime/lifecycle/native-lifecycle-sdk.cpp", "-o", out / "accessor.o"])
    run("observer-archive", ["ar", "rcs", out / OBSERVER_ARCHIVE,
        out / "observer.o", out / "accessor.o"])
    env["I12_ENVOY_OBSERVER_LDFLAGS"] = " ".join([str(out / OBSERVER_ARCHIVE),
        "-Wl,--undefined=msconnector_lifecycle_sdk_transaction_id",
        *("-Wl,--wrap=" + name for name in symbols)])
    run("sdk-identity-build", ["gcc", "-std=c17", *flags, "-I", args.sdk_include,
        source / ".i12-capture/envoy/sdk-who.c", args.sdk_library, "-o", out / "sdk-who"])
    run("sdk-identity", [out / "sdk-who"])
    run("composite-build", ["sh", source / "connectors/envoy/build/build_composite.sh"], source)
    verify_go_toolchain_hashes(receipt['go_provenance'])
    receipt["build_ready"] = True
    receipt["binaries"] = {str(path.relative_to(out)): sha(path) for path in (
        out / "build/envoy-ext-proc/msconnector_envoy_ext_proc",
        out / "build/envoy-composite/msconnector_composite")}
    ready = source.parent / "host-ready-bin"
    ready.mkdir()
    for relative in receipt["binaries"]:
        shutil.copy2(out / relative, ready / Path(relative).name)
    receipt["host_ready_binaries"] = str(ready)
    run.save()


def main():
    args = parse_args()
    checkout, root, source, out, env, receipt = prepare_paths(args)
    run = CommandRunner(checkout, out, env, receipt)
    try:
        if args.validate_existing:
            validate_existing(args, source, out, receipt, env, run)
            return
        profile, dependency_hashes = prepare_source(source, receipt, run, args.revision)
        configure_native_environment(args, root, out, receipt, env)
        compile_native(args, source, out, env, receipt, run, profile)
        validate(source, out, env, run, args.go, args.sdk_include, args.sdk_library)
        module = source / MODULE_PATH
        if dependency_hashes != {name: sha(module / name) for name in dependency_hashes}:
            raise ValueError("Go module input mutated")
        receipt["status"] = "pass"
        run.save()
    except Exception as exc:
        receipt["status"], receipt["failure"] = "failed", str(exc)
        run.save()
        raise


if __name__ == "__main__":
    main()
