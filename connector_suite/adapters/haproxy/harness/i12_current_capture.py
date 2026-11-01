#!/usr/bin/env python3
"""Port the existing HAProxy I12 capture onto an exact current source export.

Historical objects remain unchanged. This consumer retains complete v2 export
inventories and current before/after deltas; compilation never qualifies a host.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import argparse
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import difflib
import hashlib
import importlib.util
import io
import json
import os
import posixpath
from pathlib import Path
import re
import shutil
import subprocess
import stat
import tarfile
import threading

STORAGE = Path("/var") / "tmp" / "codex" / "ModSecurity-conector"
VARIANTS = ("haproxy-direct", "haproxy-spop-agent", "haproxy-companion-host")
BINDING = "connectors/haproxy/src/haproxy_modsecurity_binding.c"
SPOP = "connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c"
MARKER = ".i12-disposable-source-copy.json"
SNAPSHOT = ".i12-source-export-manifest.json"
MANIFEST = "manifest.json"
COMMON_RUNTIME = "common/runtime"
LIFECYCLE = "ci/runtime/lifecycle"
HAPROXY_SRC = "connectors/haproxy/src"
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def sha(data):
    return hashlib.sha256(data).hexdigest()


def physical(path):
    if not path.is_absolute() or ".." in path.parts or any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError("absolute physical path required")
    return path


def fresh(path):
    physical(path).relative_to(STORAGE)
    if path == STORAGE:
        raise ValueError("a fresh child of storage is required")
    path.mkdir(mode=0o700, parents=False, exist_ok=False)
    return path


def load_tool(path):
    module = load_source(physical(path))
    if not hasattr(module, "SNAPSHOT"):
        raise ValueError("the existing capture tool v2 inventory contract is required")
    return module


class Commands:
    def __init__(self, output):
        self.output = output
        self.rows = []
        self.lock = threading.Lock()

    def run(self, argv, label, cwd=None, env=None):
        actual = ["rtk", "proxy", *map(str, argv)]
        stdout, stderr = self.output / (label + ".stdout"), self.output / (label + ".stderr")
        with stdout.open("xb") as out, stderr.open("xb") as err:
            result = subprocess.run(actual, cwd=cwd, env=env, stdout=out, stderr=err)
        row = {"argv": actual, "cwd": str(cwd) if cwd else None, "exit": result.returncode,
               "stdout": str(stdout), "stderr": str(stderr), "stdout_sha256": sha(stdout.read_bytes()), "stderr_sha256": sha(stderr.read_bytes())}
        with self.lock:
            self.rows.append(row)
            (self.output / "commands.json").write_text(json.dumps(self.rows, indent=2) + "\n")
        if result.returncode:
            raise RuntimeError(label + " failed")
        return stdout


def extract_git_archive(archive, target):
    with tarfile.open(archive) as source:
        for member in source:
            relative = Path(member.name)
            if relative.is_absolute() or ".." in relative.parts or ".git" in relative.parts:
                raise ValueError("unsafe Git export member")
            path = target / relative
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("xb") as output, source.extractfile(member) as data:
                    shutil.copyfileobj(data, output)
                path.chmod(member.mode & 0o777)
            else:
                raise ValueError("Git export must contain only physical regular files/directories")


def export_archive(repo, revision, target, commands, label):
    if re.fullmatch("[0-9a-f]{40}", revision) is None:
        raise ValueError("complete source revision required")
    archive = commands.run(["git", "archive", "--format=tar", revision], label + "-archive", repo)
    tree = commands.run(["git", "rev-parse", revision + "^{tree}"], label + "-tree", repo).read_text().strip()
    listing = commands.run(["git", "ls-tree", "-r", "-z", revision], label + "-files", repo).read_bytes()
    target.mkdir(mode=0o700, exist_ok=False)
    files, gitlinks = {}, {}
    extract_git_archive(archive, target)
    for entry in listing.split(b"\0"):
        if not entry:
            continue
        attributes, name_bytes = entry.split(b"\t", 1)
        mode, kind, identity = attributes.decode().split()
        name = name_bytes.decode()
        if kind == "commit" and mode == "160000":
            gitlinks[name] = identity
            (target / name).mkdir(parents=True, exist_ok=True)
        elif kind == "blob" and mode in ("100644", "100755"):
            (target / name).chmod(int(mode, 8) & 0o777)
            files[name] = {"mode": int(mode, 8) & 0o777, "sha256": sha((target / name).read_bytes())}
        else:
            raise ValueError("unsupported source Git object")
    snapshot = {"format": "i12-source-export-manifest-v1", "source_revision": revision, "git_tree": tree, "files": files, "gitlinks": gitlinks}
    data = (json.dumps(snapshot, indent=2, sort_keys=True) + "\n").encode()
    (target / SNAPSHOT).write_bytes(data)
    marker = {"format": "i12-disposable-source-copy-v2", "path": str(target), "disposable": True,
              "source_revision": revision, "snapshot_manifest": SNAPSHOT, "snapshot_manifest_sha256": sha(data)}
    (target / MARKER).write_text(json.dumps(marker, indent=2) + "\n")
    return snapshot


def relocate_delta(before, after, current):
    """Move only uniquely matching complete historical context, without fuzz."""
    old, new = before.decode().splitlines(keepends=True), after.decode().splitlines(keepends=True)
    current_text = current.decode()
    changes = []
    for group in difflib.SequenceMatcher(a=old, b=new, autojunk=False).get_grouped_opcodes(3):
        original = "".join(old[group[0][1]:group[-1][2]])
        replacement = "".join(new[group[0][3]:group[-1][4]])
        if not original or current_text.count(original) != 1:
            raise ValueError("historical instrumentation context changed or is ambiguous")
        start = current_text.index(original)
        changes.append((start, start + len(original), replacement))
    for first, second in zip(sorted(changes), sorted(changes)[1:]):
        if first[1] > second[0]:
            raise ValueError("overlapping instrumentation anchors")
    for start, end, replacement in sorted(changes, reverse=True):
        current_text = current_text[:start] + replacement + current_text[end:]
    return current_text.encode()


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError("reviewed current product anchor changed or is ambiguous")
    return text.replace(before, after)


def port_binding(before, after, current):
    """Reviewed d004 scope refactor: observe the common private allocation seam."""
    old, observed = before.decode(), after.decode()
    text = current.decode()
    spop_helper = ""
    helper_marker = "\n/* Values have operation-specific meanings; no ordinary HTX finished field is reused. */"
    if helper_marker in observed:
        helper_offset = observed.index(helper_marker)
        spop_helper, observed = observed[helper_offset:], observed[:helper_offset]
    old_name = "int haproxy_modsecurity_transaction_begin_request_with_profile("
    observed_name = "static int observed_real_begin_request_with_profile("
    # Remove only the historical public allocation wrapper, then relocate all
    # remaining original logging/retire deltas with their exact context.
    wrapper_start = observed.index("int haproxy_modsecurity_transaction_begin_request_with_profile(\n")
    helper_start = observed.index("void haproxy_lifecycle_host_observe(", wrapper_start)
    wrapper_end = observed.index("int haproxy_modsecurity_transaction_begin_request(\n", helper_start)
    host_helper = observed[helper_start:wrapper_end]
    reduced = observed[:wrapper_start] + observed[wrapper_end:]
    reduced = replace_once(reduced, observed_name, old_name)
    text = relocate_delta(old.encode(), reduced.encode(), text.encode()).decode()
    anchor = "static int begin_request_with_scope(\n        haproxy_modsecurity_engine *engine,\n        const haproxy_modsecurity_request *request,\n        const char *profile_id,\n        int request_authorization_only,\n        haproxy_modsecurity_decision *decision,\n        haproxy_modsecurity_transaction **transaction) {"
    text = replace_once(text, anchor, anchor.replace("begin_request_with_scope", "observed_real_begin_request_with_scope"))
    end = text.index("int haproxy_modsecurity_transaction_begin_request_with_profile(")
    wrapper = '''static int begin_request_with_scope(
        haproxy_modsecurity_engine *engine,
        const haproxy_modsecurity_request *request,
        const char *profile_id, int request_authorization_only,
        haproxy_modsecurity_decision *decision,
        haproxy_modsecurity_transaction **transaction) {
    uint64_t call = msconnector_lifecycle_host_begin();
    int result = observed_real_begin_request_with_scope(engine, request, profile_id,
        request_authorization_only, decision, transaction);
    int saved = errno;
    haproxy_modsecurity_transaction *actual = transaction == NULL ? NULL : *transaction;
    (void)msconnector_lifecycle_host_end(call, actual,
        actual == NULL ? NULL : &actual->contract,
        actual == NULL ? NULL : actual->transaction, result == 0 && actual != NULL);
    errno = saved;
    return result;
}

'''
    return (text[:end] + wrapper + host_helper + text[end:] + spop_helper).encode()


def port_spop(before, after, current):
    observed = after.decode()
    blocks = []
    for handle, label in (("NULL", "spop_complete_request_sample_accepted"), ("transaction", "spop_atomic_request_evaluated")):
        block = f'    haproxy_lifecycle_spop_observe({handle}, "{label}",\n        (unsigned int)request->body_len, (int)request->http_metadata.advertised_body_len,\n        request->has_body_len_arg, request->has_body);\n'
        blocks.append(block)
        observed = replace_once(observed, block, "")
    text = relocate_delta(before, observed.encode(), current).decode()
    call = '''    modsec_rc = state->config.response_phases_enabled ?
        haproxy_modsecurity_transaction_begin(
            state->engine, &modsec_request, decision, &transaction) :
        haproxy_modsecurity_transaction_begin_request_authorization(
            state->engine, &modsec_request, decision, &transaction);
'''
    return replace_once(text, call, blocks[0] + call + blocks[1]).encode()


def copy_current(source, target):
    shutil.copytree(source, target, symlinks=False)
    marker = json.loads((target / MARKER).read_text())
    marker["path"] = str(target)
    (target / MARKER).write_text(json.dumps(marker, indent=2) + "\n")


def port_target(name, before, after, current):
    if before is None:
        if current is not None:
            raise ValueError("capture addition collides with current product")
        return after
    if name == BINDING:
        return port_binding(before, after, current)
    if name == SPOP:
        return port_spop(before, after, current)
    return relocate_delta(before, after, current)


def port_profile(tool, registry, source, target, profile, output):
    copy_current(source, target)
    identity = tool.disposable(target, registry.manifest["delivery_product_baseline"], STORAGE)
    records = []
    for name, entry in registry.manifest["profiles"][profile]["source_targets"].items():
        path = target / tool.relative(name)
        current = tool.plain(path) if path.exists() else None
        before = registry.content(entry["before_sha256"]) if entry["before_sha256"] else None
        after = registry.content(entry["sha256"])
        result = port_target(name, before, after, current)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(result)
        path.chmod(entry.get("mode", 420))
        delta = "".join(difflib.unified_diff((current or b"").decode().splitlines(keepends=True), result.decode().splitlines(keepends=True), fromfile="a/" + name, tofile="b/" + name))
        delta_path = output / (profile + "-" + path.name + ".patch")
        delta_path.write_text(delta)
        records.append({"path": name, "current_before_sha256": sha(current) if current is not None else None,
                        "current_after_sha256": sha(result), "historical_before_sha256": entry["before_sha256"],
                        "historical_after_sha256": entry["sha256"], "delta": str(delta_path), "delta_sha256": sha(delta.encode()),
                        "reviewed_scope_port": name in (BINDING, SPOP)})
    receipt = {"profile": profile, "current_export": identity, "source_copy": str(target), "source_targets": records,
               "historical_registry_manifest_sha256": sha((registry.root / MANIFEST).read_bytes()),
               "historical_objects_modified": False, "runtime_qualified": False}
    (target / "i12-current-source-application-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


def registry_repository(tool, output):
    """Resolve immutable repository objects from their exact archived bytes."""
    repository = output / "registry-repository"
    repository.mkdir(exist_ok=False)
    manifest = json.loads((tool.HERE / MANIFEST).read_text())
    provenance = []
    for identity, item in manifest["objects"].items():
        if item["kind"] != "repository":
            continue
        relative = tool.relative(item["path"])
        candidates = [output / root / relative for root in ("current-base", "historical-base")]
        selected = next((path for path in candidates if path.is_file() and sha(tool.plain(path)) == identity), None)
        if selected is None:
            raise ValueError("no exact archived source for repository capture object: " + identity)
        destination = repository / relative
        if destination.exists() and sha(destination.read_bytes()) != identity:
            raise ValueError("multiple incompatible repository objects share a path")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            shutil.copy2(selected, destination)
        provenance.append({"object_sha256": identity, "path": str(relative), "archived_source": str(selected)})
    (output / "repository-object-resolution.json").write_text(json.dumps({"purpose": "historical Registry content reconstruction only; never a current product source tree", "objects": provenance}, indent=2) + "\n")
    return repository


def prepare(repo, revision, tool_path, output):
    output = fresh(output)
    commands = Commands(output)
    tool = load_tool(tool_path)
    baseline = json.loads((tool.HERE / MANIFEST).read_text())["delivery_product_baseline"]
    export_archive(repo, baseline, output / "historical-base", commands, "historical")
    export_archive(repo, revision, output / "current-base", commands, "current")
    registry = tool.Registry(repository=registry_repository(tool, output))
    registry.verify()
    receipts = [port_profile(tool, registry, output / "current-base", output / profile, profile, output) for profile in VARIANTS]
    (output / "preparation.json").write_text(json.dumps({"source_revision": revision, "profiles": receipts, "host_runs": 0, "runtime_qualified": False}, indent=2) + "\n")
    return receipts


def sdk_inventory(sdk):
    sdk = physical(sdk)
    images = sorted((sdk / "lib").glob("libmodsecurity.so.*"))
    images = [path for path in images if path.is_file() and not path.is_symlink()]
    if len(images) != 1:
        raise ValueError("one physical versioned SDK image required")
    headers = {str(path.relative_to(sdk)): sha(path.read_bytes()) for path in sorted((sdk / "include").rglob("*")) if path.is_file()}
    return {"root": str(sdk), "image": str(images[0]), "image_sha256": sha(images[0].read_bytes()), "headers": headers}


def upstream_members(package, prefix):
    members = {}
    for member in package.getmembers():
        path = Path(member.name)
        if not path.parts or path.parts[0] != prefix or ".." in path.parts or path.is_absolute():
            raise ValueError("unexpected upstream archive path")
        if len(path.parts) == 1 and not member.isdir():
            raise ValueError("upstream release root must be a directory")
        if member.name in members:
            raise ValueError("duplicate upstream archive member")
        if not (member.isdir() or member.isfile() or member.issym()):
            raise ValueError("upstream archive special files are not admitted")
        members[member.name] = member
    return members


def upstream_regular_target(member, members, prefix):
    if not member.issym():
        return member
    if posixpath.isabs(member.linkname):
        raise ValueError("absolute upstream archive link")
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(member.name), member.linkname))
    if not resolved.startswith(prefix + "/"):
        raise ValueError("upstream archive link escapes release")
    target = members.get(resolved)
    if target is None or not target.isfile():
        raise ValueError("upstream archive link target must be a regular member")
    return target


def storage_parts(path):
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("absolute storage child required")
    parts = path.relative_to(STORAGE).parts
    if not parts or any(part in ("", ".", "..") or "/" in part for part in parts):
        raise ValueError("storage child required")
    return parts


def descend_directory(parent, parts, create=False):
    descriptor = os.dup(parent)
    try:
        for part in parts:
            if create:
                try:
                    os.mkdir(part, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(part, DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


@contextmanager
def storage_parent(path):
    parts = storage_parts(path)
    root = os.open("/", DIRECTORY_FLAGS)
    try:
        anchor = descend_directory(root, STORAGE.parts[1:])
    finally:
        os.close(root)
    try:
        status = os.fstat(anchor)
        if status.st_uid != os.getuid() or status.st_mode & 0o022:
            raise ValueError("storage anchor must be privately owned")
        parent = descend_directory(anchor, parts[:-1])
        try:
            yield parent, parts[-1]
        finally:
            os.close(parent)
    finally:
        os.close(anchor)


def regular_bytes(parent, name):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("physical regular input required")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            return source.read()
    finally:
        os.close(descriptor)


@contextmanager
def upstream_directory(source):
    with storage_parent(source) as (parent, name):
        os.mkdir(name, mode=0o700, dir_fd=parent)
        directory = os.open(name, DIRECTORY_FLAGS, dir_fd=parent)
        try:
            yield directory
            held, visible = os.fstat(directory), os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (held.st_dev, held.st_ino) != (visible.st_dev, visible.st_ino):
                raise ValueError("upstream source directory changed during materialization")
        finally:
            os.close(directory)


def write_upstream_member(directory, parts, content, mode):
    parent = descend_directory(directory, parts[:-1], create=True)
    try:
        descriptor = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             mode, dir_fd=parent)
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            os.fchmod(output.fileno(), mode)
    finally:
        os.close(parent)


def materialize_upstream(package, members, regular, directory):
    normalizations = []
    for name, member in members.items():
        parts = Path(name).parts[1:]
        if member.isdir():
            os.close(descend_directory(directory, parts, create=True))
            continue
        original = regular[name]
        with package.extractfile(original) as data:
            content = data.read()
        mode = original.mode & 0o777
        write_upstream_member(directory, parts, content, mode)
        if member.issym():
            normalizations.append({"archive_member": name, "original_linkname": member.linkname,
                                   "resolved_regular_member": original.name, "content_sha256": sha(content),
                                   "mode": oct(mode), "materialized_as": "physical_regular_file"})
    return normalizations


def unpack_upstream(archive, source, contract):
    with storage_parent(archive) as (parent, name):
        archive_bytes = regular_bytes(parent, name)
    if sha(archive_bytes) != contract["sha256"]:
        raise ValueError("HAProxy release archive hash differs")
    prefix = "haproxy-" + contract["version"]
    # Parse the exact admitted bytes whose digest was checked; never reopen the
    # pathname after authentication. All output accesses stay below a held FD.
    with tarfile.open(fileobj=io.BytesIO(archive_bytes)) as package:
        members = upstream_members(package, prefix)
        regular = {name: upstream_regular_target(member, members, prefix)
                   for name, member in members.items() if not member.isdir()}
        with upstream_directory(source) as directory:
            normalizations = materialize_upstream(package, members, regular, directory)
            if regular_bytes(directory, "VERSION").decode().strip() != contract["version"]:
                raise ValueError("upstream HAProxy version differs")
    return {"archive_sha256": contract["sha256"], "version": contract["version"],
            "filesystem_symlinks_created": 0, "normalizations": normalizations}


def install_scope_observer(source):
    wrapper = Path(__file__).with_name("i12_request_scope_observer.c")
    target = source / "connectors/haproxy/harness" / wrapper.name
    if target.exists() and target.read_bytes() != wrapper.read_bytes():
        raise ValueError("archived request observer differs from selected consumer")
    target.write_bytes(wrapper.read_bytes())
    return {"path": str(target), "consumer_path": str(wrapper), "sha256": sha(wrapper.read_bytes())}


def stage_host(source, upstream, build, sdk, commands, label):
    script = source / "connectors/haproxy/htx-overlay/build-overlay.sh"
    text = script.read_text()
    boundary = "modsecurity_library=\n"
    if text.count(boundary) != 1:
        raise ValueError("repository-native overlay staging boundary changed")
    staging = script.with_name("i12-stage-current-overlay.sh")
    staging.write_text(text.split(boundary)[0])
    env = dict(os.environ, CONNECTOR_ROOT=str(source), HAPROXY_HTX_SOURCE_DIR=str(upstream),
               HAPROXY_HTX_BUILD_DIR=str(build), MODSECURITY_INCLUDE_DIR=str(sdk / "include"),
               MODSECURITY_LIB_DIR=str(sdk / "lib"))
    commands.run(["sh", staging], label + "-stage", env=env)
    return build / "worktree"


def compile_observers(source, host, sdk, output, commands, label):
    output.mkdir(exist_ok=False)
    include = ["-I" + str(source / "common/include"), "-I" + str(source / COMMON_RUNTIME), "-I" + str(host / "src")]
    sources = {"request-scope-observer": source / "connectors/haproxy/harness/i12_request_scope_observer.c"}
    sources.update({name: source / LIFECYCLE / (name + ".c") for name in ("companion-observer", "tls-write-observer")})
    objects = {}
    for name, path in sources.items():
        obj = output / (name + ".o")
        commands.run(["cc", "-std=c17", "-Wall", "-Wextra", "-Werror", *include, "-I" + str(sdk / "include"), "-c", path, "-o", obj], label + "-" + name)
        objects[name] = obj
    obj = output / "native-lifecycle-sdk.o"
    commands.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-isystem", sdk / "include", *include,
                  "-c", source / "ci/runtime/lifecycle/native-lifecycle-sdk.cpp", "-o", obj], label + "-sdk")
    objects["native-lifecycle-sdk"] = obj
    return objects


def product_input_binding(source, host):
    pairs = [(source / HAPROXY_SRC / name, host / "src" / name)
             for name in ("haproxy_modsecurity_binding.c", "haproxy_modsecurity_binding.h", "haproxy_modsecurity_mapper.c", "haproxy_modsecurity_mapper.h")]
    pairs.append((source / "connectors/haproxy/htx-overlay/haproxy_modsecurity_htx_filter.c", host / "src/haproxy_modsecurity_htx_filter.c"))
    pairs.extend((path, host / "include/msconnector" / path.relative_to(source / "common/include/msconnector"))
                 for path in (source / "common/include/msconnector").rglob("*") if path.is_file())
    pairs.extend((source / "common/src" / path.name.removeprefix("msconnector_"), path)
                 for path in (host / "src").glob("msconnector_*.c") if path.name not in ("msconnector_profile_registry.c", "msconnector_response_companion_client.c"))
    pairs.extend(((source / "connectors/profile_registry.c", host / "src/msconnector_profile_registry.c"),
                  (source / "connectors/profile_registry.h", host / "src/connectors/profile_registry.h")))
    result = []
    for original, actual in pairs:
        before, after = sha(original.read_bytes()), sha(actual.read_bytes())
        if before != after:
            raise ValueError("current product input copy differs")
        result.append({"source": str(original), "build_input": str(actual), "sha256": before})
    return result


def build_host(source, upstream, sdk, build, symbols, commands, label, jobs):
    host = stage_host(source, upstream, build, sdk, commands, label)
    binding = product_input_binding(source, host)
    if list(host.rglob("*.o")) or (host / "haproxy").exists():
        raise ValueError("upstream source unexpectedly contains compiled output")
    objects = compile_observers(source, host, sdk, build / "observers", commands, label)
    image = sdk_inventory(sdk)["image"]
    wraps = ["-Wl,--wrap=" + symbol for symbol in [*symbols, "msconnector_transaction_contract_finish_request_authorization", "SSL_write"]]
    libraries = [*map(str, objects.values()), image, "-Wl,-rpath,'$$ORIGIN'", "-Wl,-rpath," + str(sdk / "lib"), "-lstdc++", "-pthread", "-lcrypto", *wraps]
    commands.run(["make", "-C", host, "TARGET=linux-glibc", "-j" + str(jobs), "USE_OPENSSL=1",
                  "CFLAGS=-I" + str(host / "src/connectors") + " -I" + str(sdk / "include") + " -I" + str(source / LIFECYCLE), "ADDLIB=" + " ".join(libraries), "haproxy"], label + "-build")
    return {"binary": str(host / "haproxy"), "sha256": sha((host / "haproxy").read_bytes()), "current_product_inputs": binding,
            "all_host_objects_fresh": True, "observer_objects": {name: str(path) for name, path in objects.items()}}


def agent_sources(source):
    makefile = (source / "connectors/haproxy/Makefile").read_text()
    line = next(row for row in makefile.splitlines() if row.startswith("COMMON_SDK_SRCS :="))
    paths = [Path(value.replace("$(COMMON_SRC)", str(source / "common/src"))) for value in line.split(":=", 1)[1].split()]
    paths += [source / COMMON_RUNTIME / name for name in ("msconnector_runtime.c", "response_companion_transport.c", "response_companion_client.c")]
    paths += [source / "connectors/profile_registry.c"]
    paths += [source / HAPROXY_SRC / name for name in ("haproxy_spop_diagnostic_runtime.c", "haproxy_modsecurity_binding.c", "haproxy_modsecurity_mapper.c", "haproxy_spop_response_companion_backend.c")]
    return paths


def agent_feature_flags(path):
    # Current runtime TUs own this feature macro; command-line '=1' would
    # conflict with their empty definition under the unchanged -Werror.
    owns_macro = re.search(r"(?m)^#\s*define\s+_GNU_SOURCE(?:\s|$)", path.read_text())
    return [] if owns_macro else ["-D_GNU_SOURCE"]


def build_agent(source, sdk, build, observers, symbols, commands, jobs):
    build.mkdir(exist_ok=False)
    inputs = agent_sources(source)
    objects = [build / (str(index) + "-" + path.stem + ".o") for index, path in enumerate(inputs)]
    include = ["-I" + str(source), "-I" + str(source / "common/include"), "-I" + str(source / COMMON_RUNTIME),
               "-I" + str(source / HAPROXY_SRC), "-I" + str(source / LIFECYCLE), "-I" + str(sdk / "include")]
    def compile_one(item):
        index, path = item
        commands.run(["cc", "-std=c17", *agent_feature_flags(path), "-Wall", "-Wextra", "-Werror", *include, "-c", path, "-o", objects[index]], "agent-" + str(index))
    with ThreadPoolExecutor(max_workers=jobs) as executor:
        list(executor.map(compile_one, enumerate(inputs)))
    wraps = ["-Wl,--wrap=" + symbol for symbol in [*symbols, "msconnector_transaction_contract_finish_request_authorization"]]
    observed = [path for name, path in observers.items() if name != "tls-write-observer"]
    image = sdk_inventory(sdk)["image"]
    binary = build / "haproxy-spop"
    commands.run(["c++", *objects, *observed, image, "-Wl,-rpath,$ORIGIN", "-Wl,-rpath," + str(sdk / "lib"), "-pthread", "-lcrypto", *wraps, "-o", binary], "agent-link")
    return {"binary": str(binary), "sha256": sha(binary.read_bytes()), "all_agent_objects_fresh": True,
            "source_inputs": [{"path": str(path), "sha256": sha(path.read_bytes())} for path in inputs]}


def build_all(output, sdk, archive, tool_path, jobs):
    commands = Commands(output / "build-commands")
    commands.output.mkdir(exist_ok=False)
    tool = load_tool(tool_path)
    registry = tool.Registry(repository=output / "registry-repository")
    sdk_proof = sdk_inventory(sdk)
    contract = json.loads((output / "current-base/connectors/haproxy/htx-overlay/version-contract.json").read_text())
    upstream = output / "upstream-" / contract["version"]
    upstream.parent.mkdir(exist_ok=False)
    normalization = unpack_upstream(archive, upstream, contract)
    (output / "upstream-normalizations.json").write_text(json.dumps(normalization, indent=2) + "\n")
    wrapper_sources = {profile: install_scope_observer(output / profile) for profile in VARIANTS}
    host_build = output / "companion-build"
    symbols = registry.manifest["profiles"]["haproxy-companion-host"]["provenance"]["GNU_wrapped_symbols"]
    companion = build_host(output / "haproxy-companion-host", upstream, sdk, host_build, symbols, commands, "companion", jobs)
    # Compile the SPOP owner against its own variant's current full product copy.
    agent_observers = compile_observers(output / "haproxy-spop-agent", Path(companion["binary"]).parent, sdk,
                                        output / "agent-observers", commands, "agent-observers")
    agent = build_agent(output / "haproxy-spop-agent", sdk, output / "agent-build", agent_observers, symbols, commands, jobs)
    early = {"companion": companion, "agent": agent, "sdk": sdk_proof, "wrapper_sources": wrapper_sources,
             "host_runs": 0, "runtime_qualified": False}
    (output / "first-regression-builds.json").write_text(json.dumps(early, indent=2) + "\n")
    direct = build_host(output / "haproxy-direct", upstream, sdk, output / "direct-build", symbols, commands, "direct", jobs)
    result = {**early, "direct": direct, "upstream_archive": str(archive), "upstream_archive_sha256": normalization["archive_sha256"]}
    (output / "current-builds.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--capture-tool", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--sdk", type=Path)
    parser.add_argument("--upstream-archive", type=Path)
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()
    result = prepare(physical(args.repository), args.revision, args.capture_tool, args.output)
    if args.build:
        if args.sdk is None or args.upstream_archive is None or args.jobs < 1:
            parser.error("build needs SDK, pinned upstream archive and positive jobs")
        build_all(args.output, physical(args.sdk), physical(args.upstream_archive), args.capture_tool, args.jobs)
    print(json.dumps({"profiles": len(result), "runtime_qualified": False}))


if __name__ == "__main__":
    main()
