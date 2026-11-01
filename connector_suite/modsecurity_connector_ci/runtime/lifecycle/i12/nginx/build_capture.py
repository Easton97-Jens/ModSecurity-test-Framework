"""Fresh ordinary or source-observed NGX module; no hosts or old-output writes."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import argparse, ast, hashlib, json, re, shlex, subprocess, shutil, os, stat, threading
import importlib.util
import io
import tarfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


REPOSITORY_ROOT = connector_root()
RECEIPT_NAME = "receipt.json"
NGINX_SOURCE = "connectors/nginx/src"
COMMON_INCLUDE = "common/include"
LIFECYCLE_SOURCE = "ci/runtime/lifecycle"
MODULE_NAME = "ngx_http_modsecurity_module.so"
NGINX_BINARY = "sbin/nginx"
PREFIX_MODULE = "modules/ngx_http_modsecurity_module.so"

SAFE_ABSOLUTE_PATH = re.compile(r"/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")


def lexical_absolute_path(value):
    """Return only an absolute path assembled from a conservative alphabet."""
    match = SAFE_ABSOLUTE_PATH.fullmatch(str(value))
    if match is None or any(part in ("", ".", "..") for part in match.group(0).split("/")[1:]):
        raise ValueError("canonical absolute artifact path required")
    return Path(match.group(0))


def validate_path_component(component, path, approved):
    info = component.lstat()
    if info.st_uid not in (0, os.geteuid()) or stat.S_ISLNK(info.st_mode):
        raise ValueError("artifact path requires root/operator ownership without symlinks")
    inside = any(component == root or component.is_relative_to(root) for root in approved)
    shared_transit = (not inside and info.st_uid == 0 and stat.S_ISDIR(info.st_mode)
                      and info.st_mode & stat.S_ISVTX)
    if info.st_mode & 0o022 and not shared_transit:
        raise ValueError("artifact path has a group/world-writable component")
    if component != path and not stat.S_ISDIR(info.st_mode):
        raise ValueError("artifact path ancestor must be a directory")


def trusted_path(value, roots, *, regular=False, directory=False):
    """Confine a canonical path to protected project-owned roots."""
    path = lexical_absolute_path(value)
    approved = []
    for value_root in roots:
        root = lexical_absolute_path(value_root)
        if root.resolve(strict=True) != root or not root.is_dir():
            raise ValueError("canonical existing artifact root required")
        approved.append(root)
    if not any(path.is_relative_to(root) for root in approved):
        raise ValueError("artifact path is outside approved roots")
    if path.resolve(strict=True) != path:
        raise ValueError("artifact path must not traverse links")
    for component in reversed((path, *path.parents)):
        validate_path_component(component, path, approved)
    info = path.lstat()
    if regular and not stat.S_ISREG(info.st_mode):
        raise ValueError("artifact input must be a regular file")
    if directory and not stat.S_ISDIR(info.st_mode):
        raise ValueError("artifact input must be a directory")
    return path


def sha(path):
    """Hash one protected project file without following links or special files."""
    path = trusted_path(path, (storage_root(), REPOSITORY_ROOT), regular=True)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    descriptor = os.open(path, flags)
    try:
        before = path.lstat()
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or
                (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)):
            raise ValueError("artifact input changed before hashing")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def storage_root():
    """Use the project-admitted storage anchor, never a public-temp default."""
    value = os.environ.get("CODEX_TEMP_ROOT", "")
    root = Path(value)
    if (not value or not root.is_absolute() or str(root) != value or
            ".." in root.parts or root == Path("/")):
        raise ValueError("canonical project CODEX_TEMP_ROOT required")
    return root


def command_path(value, root, *, regular=False, directory=False):
    """Produce a validated argv path below one private output root."""
    return str(trusted_path(value, (root,), regular=regular, directory=directory))


OBSERVER_COMPATIBILITY = {
    "ci/runtime/lifecycle/native-lifecycle-observer.c": (
        "0d903fc5e6432769a136931b7ebea16a6f87db941d28d23583ccccf4c75e6537",
        "ad8e5e36a17e746cf202c685dbb529fc09717f5c25441b713fa369420aa55ac6",
        "52aba91c92a8d1a3b1f2b4acf50db6acb103d6d0cd63c45a0e75bcf5fa8553e6"),
    "ci/runtime/lifecycle/native-lifecycle-observer.h": (
        "5b7d8fa7c327017cafb05b1e932f70eefe8641797751a0dc19df0337f4893b1b",
        "f9f63b62ba8efc555dc20e673cc02251d5ab6c2ab17d8f5efa760d0d97146dcd",
        "5a34307b4d52927f36573fcf1caf4f63e3e0ce7adffc522e462128148bec7060"),
}


def identity(value):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise ValueError("complete lowercase Git identity required")
    return value


def source_name(value):
    if (not value or value.startswith("/") or "\\" in value or
            any(part in ("", ".", "..", ".git") for part in value.split("/"))):
        raise ValueError("unsafe Git export path")
    return value


def inventory_row(row, files, gitlinks):
    header, name = row.split(b"\t", 1)
    mode, kind, oid = header.decode("ascii").split(" ")
    name = source_name(name.decode("utf-8"))
    identity(oid)
    if name in files or name in gitlinks:
        raise ValueError("duplicate Git inventory path")
    if (mode, kind) == ("160000", "commit"):
        gitlinks[name] = oid
    elif kind == "blob" and mode in ("100644", "100755"):
        files[name] = {"mode": int(mode[-3:], 8), "git_blob": oid}
    else:
        raise ValueError("only regular Git files and gitlinks permitted")


def tree_inventory(raw):
    files, gitlinks = {}, {}
    for row in raw.split(b"\0"):
        if row:
            inventory_row(row, files, gitlinks)
    if not files:
        raise ValueError("empty Git export")
    for name in (*files, *gitlinks):
        if any(str(parent) in files or str(parent) in gitlinks
               for parent in Path(name).parents if str(parent) != "."):
            raise ValueError("Git inventory path collision")
    return files, gitlinks


def export_regular_member(archive, member, name, target, files, seen, inventory):
    if not member.isfile() or name not in files or name in seen:
        raise ValueError("unexpected archive object/path/duplicate")
    expected = files[name]
    if member.mode != expected["mode"]:
        raise ValueError("archive Git mode differs")
    stream = archive.extractfile(member)
    if stream is None:
        raise ValueError("archive regular-file payload absent")
    payload = stream.read()
    # Git's object name is a compatibility identifier; the independent
    # snapshot/integrity binding below always uses SHA-256.
    blob = hashlib.sha1(b"blob " + str(len(payload)).encode() + b"\0" + payload,
                        usedforsecurity=False).hexdigest()
    if len(payload) != member.size or blob != expected["git_blob"]:
        raise ValueError("archive blob differs from Git tree")
    destination = target / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as output:
        output.write(payload)
    destination.chmod(expected["mode"])
    inventory[name] = {"mode": expected["mode"], "sha256": hashlib.sha256(payload).hexdigest()}
    seen.add(name)


def export_archive(data, target, files, gitlinks):
    """Extract only exact ls-tree blobs; tar extraction never selects paths."""
    directories = set(gitlinks)
    for name in (*files, *gitlinks):
        directories.update(str(p) for p in Path(name).parents if str(p) != ".")
    seen, seen_directories, inventory = set(), set(), {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for member in archive:
            name = source_name(member.name.rstrip("/") if member.isdir() else member.name)
            if member.isdir():
                if name not in directories or name in seen_directories or member.mode != 0o755:
                    raise ValueError("unexpected archive directory/mode/duplicate")
                seen_directories.add(name)
                (target / name).mkdir(parents=True, exist_ok=True)
                continue
            export_regular_member(archive, member, name, target, files, seen, inventory)
    if seen != set(files):
        raise ValueError("missing archive files")
    for name in gitlinks:
        (target / name).mkdir(parents=True, exist_ok=True)
    return inventory


def export_current(git, target, revision, capture):
    identity(revision)
    tree = identity(git("rev-parse", revision + "^{tree}").decode().strip())
    files, gitlinks = tree_inventory(git("ls-tree", "-rz", "--full-tree", revision))
    inventory = export_archive(git("-c", "tar.umask=0022", "archive", "--format=tar", revision),
                               target, files, gitlinks)
    snapshot = {"format": "i12-source-export-manifest-v1", "source_revision": revision,
                "git_tree": tree, "files": inventory, "gitlinks": gitlinks}
    data = (json.dumps(snapshot, sort_keys=True, indent=2) + "\n").encode()
    (target / capture.SNAPSHOT).write_bytes(data)
    marker = {"format": "i12-disposable-source-copy-v2", "path": str(target), "disposable": True,
              "source_revision": revision, "snapshot_manifest": capture.SNAPSHOT,
              "snapshot_manifest_sha256": hashlib.sha256(data).hexdigest()}
    (target / capture.MARKER).write_text(json.dumps(marker) + "\n")
    return capture.disposable(target, "unused-v2", storage_root())


def permitted_transition(name, current, entry):
    before, after = entry["before_sha256"], entry["sha256"]
    if current == before or (current is None and before is None):
        return "exact-profile-before"
    if OBSERVER_COMPATIBILITY.get(name) == (current, before, after):
        return "explicit-historical-observer-compatibility"
    raise ValueError("unapproved capture transition: " + name)


def historical_object_candidate(git, revision, name, expected):
    identity(revision)
    row = git("ls-tree", "-z", revision, "--", name)
    if not row:
        return None
    files, links = tree_inventory(row)
    if links or set(files) != {name}:
        raise ValueError("non-regular historical repository object: " + name)
    blob = files[name]["git_blob"]
    size = int(git("cat-file", "-s", blob).decode().strip())
    if size > 2 * 1024 * 1024:
        return None
    payload = git("cat-file", "blob", blob)
    if hashlib.sha256(payload).hexdigest() != expected:
        return None
    if len(payload) != size or b"\0" in payload:
        raise ValueError("invalid exact historical text object")
    payload.decode("utf-8")
    return revision, blob, payload, files[name]["mode"]


def find_historical_object(git, revision, name, expected):
    history = git("log", "-n", "513", "--format=%H", revision, "--", name).decode().splitlines()
    candidates = dict.fromkeys([revision, *history[:512]])
    found = None
    for revision in candidates:
        found = historical_object_candidate(git, revision, name, expected)
        if found is not None:
            break
    if found is None:
        raise ValueError("exact repository object absent from bounded 512-commit path history: " + name)
    return found


def registry_control_names(manifest, capture):
    names = {"capture_sources.py", "manifest.json"}
    for entry in manifest["objects"].values():
        for field in ("file", "patch"):
            if field in entry:
                names.add(str(capture.relative(entry[field])))
    return names


def frozen_registry(checkout, output, capture, source_identity, git):
    """Reconstruct exact manifest repository objects without changing shared data."""
    replica = output / "historical-capture-control-plane"
    root = replica / "ci/runtime/lifecycle/i12"
    root.mkdir(parents=True, mode=0o700)
    manifest_bytes = capture.plain(checkout / "ci/runtime/lifecycle/i12/manifest.json")
    manifest = json.loads(manifest_bytes)
    frozen = {}
    names = registry_control_names(manifest, capture)
    for name in sorted(names):
        payload = capture.plain(checkout / "ci/runtime/lifecycle/i12" / name)
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as destination:
            destination.write(payload)
        target.chmod(0o644)
        frozen[name] = hashlib.sha256(payload).hexdigest()
    resolutions, demanded = {}, {}
    for expected, entry in manifest["objects"].items():
        if entry["kind"] != "repository":
            continue
        name = str(capture.relative(entry["path"]))
        if name in demanded:
            if demanded[name] != expected:
                raise ValueError("conflicting repository object identities: " + name)
            continue
        demanded[name] = expected
        found = find_historical_object(git, source_identity["source_revision"], name, expected)
        revision, blob, payload, mode = found
        target = replica / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as destination:
            destination.write(payload)
        target.chmod(mode)
        resolutions[name] = {"expected_sha256": expected, "source_commit": revision,
                             "source_git_blob": blob, "mode": mode,
                             "history_search_limit": 512, "current_revision": source_identity["source_revision"]}
    replica_registry = capture.Registry(root=root, repository=replica)
    replica_registry.verify()
    helper = root / "capture_sources.py"
    verified = subprocess.run(["rtk", "proxy", "python3", str(helper), "verify"], capture_output=True)
    (output / "historical-registry-verify.stdout").write_bytes(verified.stdout)
    (output / "historical-registry-verify.stderr").write_bytes(verified.stderr)
    if verified.returncode:
        raise RuntimeError("unchanged frozen shared Registry verify failed")
    receipt = {"format": "nginx-i12-frozen-shared-registry-v1", "replica": str(replica),
               "exact_control_plane_sha256": frozen, "repository_resolution": resolutions,
               "shared_verify_stdout_sha256": hashlib.sha256(verified.stdout).hexdigest(),
               "shared_verify_stderr_sha256": hashlib.sha256(verified.stderr).hexdigest(),
               "shared_verify_exit": verified.returncode,
               "scope": "Historical exact object reconstruction; not a current product checkout or runtime qualification"}
    path = output / "historical-registry-reconstruction-receipt.json"
    path.write_text(json.dumps(receipt, indent=2) + "\n")
    return replica_registry, helper, receipt, sha(path)


def apply_historical_adapter(checkout, output, snapshot, capture, source_identity, git):
    registry, helper, reconstruction, reconstruction_sha = frozen_registry(
        checkout, output, capture, source_identity, git)
    profile = registry.manifest["profiles"]["nginx"]
    stage = output / "historical-nginx-profile-stage"
    stage.mkdir(mode=0o700)
    transitions = {}
    for name, entry in profile["source_targets"].items():
        target = snapshot / capture.relative(name)
        current = sha(target) if target.exists() else None
        reason = permitted_transition(name, current, entry)
        transitions[name] = {"current_before_sha256": current, "historical_before_sha256": entry["before_sha256"],
                             "profile_after_sha256": entry["sha256"], "transition": reason}
        if entry["before_sha256"] is not None:
            historical = stage / name
            historical.parent.mkdir(parents=True, exist_ok=True)
            historical.write_bytes(registry.content(entry["before_sha256"]))
            historical.chmod(entry.get("mode", 420))
    marker = {"format": "i12-disposable-source-copy-v1", "path": str(stage), "disposable": True,
              "parent_sha": registry.manifest["delivery_product_baseline"]}
    (stage / capture.MARKER).write_text(json.dumps(marker) + "\n")
    helper_argument = command_path(helper, output, regular=True)
    stage_argument = command_path(stage, output, directory=True)
    command = ["rtk", "proxy", "python3", helper_argument,
               "apply", "--profile", "nginx", "--source-copy", stage_argument]
    applied = subprocess.run(command, capture_output=True, shell=False)
    (output / "source-application.stdout").write_bytes(applied.stdout)
    (output / "source-application.stderr").write_bytes(applied.stderr)
    if applied.returncode:
        raise RuntimeError("historical compatibility capture failed; retained logs")
    receipt = json.loads(capture.plain(stage / capture.RECEIPT))
    expected = {name: entry["sha256"] for name, entry in profile["source_targets"].items()}
    expected.update({".i12-capture/nginx/" + name: entry["sha256"]
                     for name, entry in profile["capture_files"].items()})
    if receipt["exact_written_sha256"] != expected or receipt["source_revision"] != marker["parent_sha"]:
        raise ValueError("historical shared receipt differs")
    for name, digest in expected.items():
        source = stage / capture.relative(name)
        payload = capture.plain(source)
        if hashlib.sha256(payload).hexdigest() != digest:
            raise ValueError("historical profile output differs")
        target = snapshot / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        target.chmod(stat.S_IMODE(source.stat().st_mode))
    adapter = {"format": "nginx-i12-current-source-adapter-v1", **source_identity,
               "historical_stage": str(stage), "historical_stage_identity": marker,
               "historical_shared_receipt_sha256": sha(stage / capture.RECEIPT),
               "historical_registry_reconstruction_receipt_sha256": reconstruction_sha,
               "historical_registry_reconstruction": reconstruction,
               "shared_apply_stdout_sha256": hashlib.sha256(applied.stdout).hexdigest(),
               "shared_apply_stderr_sha256": hashlib.sha256(applied.stderr).hexdigest(),
               "shared_apply_exit": applied.returncode,
               "historical_shared_receipt": receipt, "transitions": transitions,
               "exact_written_sha256": expected, "runtime_qualified": False,
               "scope": "Current v2 export with explicitly historical nginx profile outputs; stage is not current source"}
    (snapshot / capture.RECEIPT).write_text(json.dumps(adapter, indent=2) + "\n")
    (output / "nginx-current-source-adapter-receipt.json").write_text(json.dumps(adapter, indent=2) + "\n")


def open_output_component(component, descriptor, current, output, storage, flags):
    # The fixed anchor must already exist. Missing descendants can only
    # be created through a previously verified non-writable directory.
    if current == output:
        os.mkdir(component, mode=0o700, dir_fd=descriptor)
    elif storage in current.parents:
        try:
            os.mkdir(component, mode=0o700, dir_fd=descriptor)
        except FileExistsError:
            pass
    child = os.open(component, flags, dir_fd=descriptor)
    try:
        metadata = os.fstat(child)
        shared_transit = (current in storage.parents and metadata.st_uid == 0
                          and metadata.st_mode & stat.S_ISVTX)
        if metadata.st_uid not in (0, os.geteuid()) or (
            metadata.st_mode & 0o022 and not shared_transit
        ):
            raise ValueError("untrusted output ancestor: " + str(current))
    except BaseException:
        os.close(child)
        raise
    return child


def create_private_output(output):
    """Create a fresh output below trusted storage without following symlinks.

    Root-owned sticky directories are only transit ancestors. All storage and
    output ancestors must be owned by root/the operator and deny other writers.
    Existing directories are inspected through descriptors, never chmodded.
    """
    storage = storage_root()
    output = lexical_absolute_path(output)
    if not output.is_absolute() or ".." in output.parts or storage not in output.parents:
        raise ValueError("fresh absolute external output below trusted storage required")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    current = Path("/")
    try:
        root_stat = os.fstat(descriptor)
        if root_stat.st_uid != 0 or root_stat.st_mode & 0o022:
            raise ValueError("untrusted filesystem root")
        for component in output.parts[1:]:
            current = current / component
            child = open_output_component(component, descriptor, current, output, storage, flags)
            os.close(descriptor)
            descriptor = child
    finally:
        os.close(descriptor)
    return output


def freeze_headers(w, base, build, own, observer):
    frozen_headers={}
    for directory in [w/COMMON_INCLUDE,w/NGINX_SOURCE,w/LIFECYCLE_SOURCE,base/"sdk/include",build/"src",build/"objs",own]:
        for header in directory.rglob("*.h"):
            if header.is_file() and not header.is_symlink(): frozen_headers[str(header.resolve())]=sha(header)
    for header in observer.glob("*.h"): frozen_headers[str(header.resolve())]=sha(header)
    return frozen_headers


def prepare_compilation(objects, context):
    w, base, build, out = context.source, context.base, context.nginx, context.output
    own, observer, cflags, inc = context.own, context.observer, context.cflags, context.includes
    text = context.recipe_text
    inputs, fresh, rows = {}, {}, []
    compilation_jobs=[]
    for i,obj in enumerate(objects):
        # Parse the actual generated native compile recipe, retaining full diagnostics.
        block=re.search(r"^"+re.escape(obj)+r":.*?\n\t\$\(CC\) (.*?)(?:\n\n|\Z)",text,re.M|re.S)
        if not block: raise ValueError("object native compiler recipe absent: "+obj)
        args=shlex.split(block.group(1).replace("\\\n"," "))
        src=args[-1]
        if src.startswith(str(base/"connector-src")):
            current=w/"connectors/nginx"/Path(src).relative_to(base/"connector-src")
        elif src.startswith(str(base/"source-inputs")):
            current=w/Path(src).relative_to(base/"source-inputs")
        else: current=(build/src).resolve()
        inputs[str(current)]=sha(current)
        chosen=current
        target=out/(f"{i:02d}-"+Path(obj).name)
        command=["cc","-c","-fPIC",*cflags,*inc,"-I"+str(w/NGINX_SOURCE),"-I"+str(own),"-I"+str(observer),"-MMD","-MF",str(target)+".d","-o",target,chosen]
        compilation_jobs.append((f"compile-{i:02d}",command))
        fresh[obj]=str(target); rows.append({"source":str(current),"source_sha256":inputs[str(current)],"compiled_source":str(chosen),"compiled_source_sha256":sha(chosen),"object":str(target)})
    return compilation_jobs, fresh, rows, inputs


def execute_compilation(compilation_jobs, jobs, run, build):
    with ThreadPoolExecutor(max_workers=jobs) as executor:
        futures=[executor.submit(run,label,command,build) for label,command in compilation_jobs]
        failures=[]
        for future in futures:
            try: future.result()
            except Exception as error: failures.append(str(error))
    if failures: raise RuntimeError("; ".join(failures))


def dependency_hashes(out, build):
    dependencies={}
    for dep in out.glob("*.o.d"):
        tokens=shlex.split(dep.read_text().replace("\\\n"," ").split(":",1)[1])
        for token in tokens:
            path=Path(token); path=path if path.is_absolute() else build/path
            dependencies[str(path.resolve())]=sha(path)
    return dependencies


def add_observers(context, inputs, run, link, receipt):
    w, observer, base, out = context.source, context.observer, context.base, context.output
    symboltree=ast.parse((w/"tests/test_native_lifecycle_observer.py").read_text())
    symbols=next(ast.literal_eval(n.value) for n in symboltree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="SYMBOLS" for t in n.targets))
    # The exact capture observer predates finalize_and_snapshot (current shared tests:38).
    symbols=tuple(symbol for symbol in symbols if symbol != "msconnector_runtime_transaction_finalize_and_snapshot")
    if len(symbols)!=37 or len(set(symbols))!=37: raise ValueError("reviewed current37 wrapper surface changed")
    receipt["wrapped_symbols"]=symbols
    for src,name,compiler,standard in [(observer/"native-lifecycle-observer.c","observer","cc","c17"),(observer/"native-lifecycle-sdk.cpp","sdk-observer","c++","c++17")]:
        inputs[str(src)]=sha(src)
        run(name+"-compile",[compiler,"-std="+standard,"-Wall","-Wextra","-Werror","-fPIC","-pthread","-I"+str(w/COMMON_INCLUDE),"-isystem",base/"sdk/include","-c",src,"-o",out/(name+".o")])
        link.append(str(out/(name+".o")))
    link.extend(["-lstdc++","-pthread",*("-Wl,--wrap="+s for s in symbols)])
    return symbols


def verify_native_coverage(dynamic, symbols, relocations, disassembly, receipt):
    if not all(re.search(r"\bT __wrap_"+re.escape(symbol)+r"$",dynamic,re.M) for symbol in symbols): raise ValueError("wrapper export absent")
    mandatory={"ngx_http_modsecurity_module.c":["msconnector_transaction_contract_init","msc_new_transaction_with_id","msconnector_transaction_contract_cleanup","msc_transaction_cleanup"],
        "ngx_http_modsecurity_access.c":["msc_process_request_headers","msc_append_request_body","msc_process_request_body"],
        "ngx_http_modsecurity_header_filter.c":["msc_process_response_headers"],
        "ngx_http_modsecurity_body_filter.c":["msc_append_response_body","msc_process_response_body"],
        "ngx_http_modsecurity_log.c":["msconnector_transaction_contract_finish","msc_process_logging"]}
    coverage=[]
    for name,required in mandatory.items():
        sources=[path for path in relocations if Path(path).name==name]
        if len(sources)!=1: raise ValueError("exact caller TU absent")
        for symbol in required:
            pre=[line.strip() for line in relocations[sources[0]].splitlines() if re.search(r"\b"+re.escape(symbol)+r"(?:[-+]|\s|$)",line)]
            calls=[line.strip() for line in disassembly.splitlines() if re.search(r"\bcall\b.*<__wrap_"+re.escape(symbol)+r"(?:@plt)?>",line)]
            if not pre or not calls: raise ValueError("genuine native caller/wrapped relocation absent: "+symbol)
            coverage.append({"caller_source":sources[0],"symbol":symbol,"genuine_object_relocations":pre,"linked_wrapped_calls":calls})
    receipt["mandatory_native_call_coverage"]=coverage
    receipt["coverage_limit"]="Static source/object/caller wiring only; actual per-case calls/returns require independent host raws. Same-object Common internal calls can remain unwrapped and cannot become synthetic API counts."


def native_recipe(w, base, receipt):
    build=base/"nginx-src"; makefile=build/"objs/Makefile"; text=makefile.read_text()
    receipt["makefile_sha256"]=sha(makefile)
    receipt["sdk_library_sha256"]=sha(base/"sdk/lib/libmodsecurity.so.3.0.14")
    if receipt["sdk_library_sha256"]!="32257230b8f378987ba1204049dcc1e23927fd44c8778e09d41805ad705c3407": raise ValueError("reviewed SDK3.0.14 library pin differs")
    receipt["sdk_version"]="3.0.14"
    receipt["nginx_binary_sha256"]=sha(base/"prefix"/NGINX_BINARY)
    if receipt["nginx_binary_sha256"]!="0d2287b344a1af4c6cc986dd915c09c60f3c942ec8ae76f8bdc5456506939746": raise ValueError("reviewed native NGX1.31.6 host pin differs")
    receipt["old_baseline_module_sha256"]=sha(base/"prefix"/PREFIX_MODULE)
    cflags=shlex.split(re.search(r"^CFLAGS = (.*)$",text,re.M).group(1))
    if "-Werror" not in cflags or "-std=c17" not in cflags: raise ValueError("native warning/C17 contract absent")
    inc=shlex.split(re.search(r"^ALL_INCS = (.*?)\n\n",text,re.M|re.S).group(1).replace("\\\n"," "))
    inc=[str(w/Path(item).relative_to(base/"source-inputs")) if item.startswith(str(base/"source-inputs")) else item for item in inc]
    match=re.search(r"\t\$\(LINK\) -o objs/ngx_http_modsecurity_module\.so ([\s\S]*?)\n\n",text)
    if not match: raise ValueError("native link recipe absent")
    original=shlex.split("cc -o objs/ngx_http_modsecurity_module.so "+match.group(1).replace("\\\n"," "))
    objects=[item for item in original if item.endswith(".o")]
    if len(objects)!=34: raise ValueError("expected exact33 Parent TUs plus one generated NGX registration TU")
    return build, text, cflags, inc, original, objects


def build(a):
    w=Path(a.source); base=Path(a.base); out=Path(a.output)
    out.mkdir(mode=0o700); steps=[]; receipt_lock=threading.Lock()
    receipt={"scope":"fresh current Parent33TU module, no host/runtime qualification", "source_snapshot": str(w), "build_recipe_sha256": sha(Path(__file__).resolve()), "parent_sha":a.parent_sha,"instrumented":a.instrumented,"steps":steps}
    def run(label,argv,cwd=out):
        cmd=["rtk","proxy",*map(str,argv)]; r=subprocess.run(cmd,cwd=cwd,capture_output=True)
        (out/(label+".stdout")).write_bytes(r.stdout);(out/(label+".stderr")).write_bytes(r.stderr)
        with receipt_lock:
            steps.append({"argv":cmd,"cwd":str(cwd),"exit":r.returncode})
            (out/RECEIPT_NAME).write_text(json.dumps(receipt,indent=2)+"\n")
        if r.returncode: raise RuntimeError(label+" failed; retained logs")
        return r.stdout.decode()
    if run("head",["git","rev-parse","HEAD"],Path(a.checkout)).strip()!=a.parent_sha: raise ValueError("fresh merged head differs")
    build, text, cflags, inc, original, objects = native_recipe(w, base, receipt)
    own=w/".i12-capture/nginx"
    observer=w/LIFECYCLE_SOURCE
    if a.instrumented:
        receipt["source_application_receipt"] = json.loads((w/"i12-source-application-receipt.json").read_text())
    frozen_headers = freeze_headers(w, base, build, own, observer)
    receipt["frozen_headers_sha256"]=frozen_headers
    receipt["observer_source"]=str(observer)

    context = argparse.Namespace(source=w, base=base, nginx=build, output=out,
                                 own=own, observer=observer, cflags=cflags, includes=inc, recipe_text=text)
    compilation_jobs, fresh, rows, inputs = prepare_compilation(objects, context)
    receipt["compile_jobs"]=min(len(compilation_jobs),a.jobs)
    execute_compilation(compilation_jobs, receipt["compile_jobs"], run, build)
    for row in rows: row["object_sha256"]=sha(row["object"])
    generated=[row for row in rows if row["source"].endswith("ngx_http_modsecurity_module_modules.c")]
    parent=[row for row in rows if row not in generated]
    if len(parent)!=33 or len(generated)!=1: raise ValueError("Parent/generated translation-unit scope mismatch")
    receipt["compiled_parent_units"]=parent
    receipt["compiled_nginx_generated_units"]=generated
    # Retain each actual preprocessor dependency hash; includes are not inferred from a build label.
    dependencies = dependency_hashes(out, build)
    receipt["dependencies_sha256"]=dependencies
    link=[fresh.get(x,x) for x in original]; link[2]=str(out/MODULE_NAME)
    if a.instrumented:
        symbols = add_observers(context, inputs, run, link, receipt)
    run("module-link",link,build)
    dynamic=run("dynamic-symbols",["nm","-D",out/MODULE_NAME])
    run("relocations",["readelf","-Wr",out/MODULE_NAME])
    disassembly=run("disassembly",["objdump","-dr",out/MODULE_NAME])
    run("dynamic-section",["readelf","-d",out/MODULE_NAME])
    relocations={}
    for i,row in enumerate(rows): relocations[row["source"]]=run(f"object-{i:02d}-relocations",["objdump","-r",row["object"]])
    if a.instrumented:
        verify_native_coverage(dynamic, symbols, relocations, disassembly, receipt)
    if any(sha(path)!=value for path,value in {**frozen_headers,**inputs,**dependencies}.items()): raise ValueError("build input changed during compilation")
    if sha(base/"prefix"/PREFIX_MODULE)!=receipt["old_baseline_module_sha256"]: raise ValueError("old module modified")
    if run("head-after",["git","rev-parse","HEAD"],Path(a.checkout)).strip()!=a.parent_sha: raise ValueError("merged head changed during build")
    receipt["module_sha256"]=sha(out/MODULE_NAME)
    prefix=out/"prefix"
    (prefix/"sbin").mkdir(parents=True,mode=0o700);(prefix/"modules").mkdir(mode=0o700)
    shutil.copyfile(base/"prefix"/NGINX_BINARY,prefix/NGINX_BINARY);(prefix/NGINX_BINARY).chmod(0o500)
    shutil.copyfile(out/MODULE_NAME,prefix/PREFIX_MODULE);(prefix/PREFIX_MODULE).chmod(0o400)
    if sha(prefix/NGINX_BINARY)!=receipt["nginx_binary_sha256"] or sha(prefix/PREFIX_MODULE)!=receipt["module_sha256"]: raise ValueError("fresh prefix sealing differs")
    receipt["fresh_prefix"]=str(prefix)
    receipt["library_binding"]="Use separately pinned SDK3.0.14 read-only library directory; no old module/source relabeling."
    receipt["status"]="BUILD_PASS_RUNTIME_NOT_EXECUTED"
    receipt["full_lifecycle_qualified"]=False
    (out/RECEIPT_NAME).write_text(json.dumps(receipt,indent=2)+"\n")
    print(json.dumps({"status":receipt["status"],"module_sha256":receipt["module_sha256"]}))



def capture_extra_state(checkout, output, snapshot):
    # Additional NGINX-only state capture is separate from shared capture.
    extra = {"shared_capture_receipt_sha256": sha(snapshot / "i12-source-application-receipt.json"),
             "header_sha256": sha(checkout / "ci/runtime/lifecycle/i12/nginx/host_state.h"), "files": {}}
    shutil.copyfile(checkout / "ci/runtime/lifecycle/i12/nginx/host_state.h",
                    snapshot / "connectors/nginx/src/i12-nginx-host-state.h")
    patches = {
        "ngx_http_modsecurity_access.c": [
            ("    ret = msc_process_request_body(ctx->modsec_transaction);",
             '    ngxi12_body_state(ctx, "request_before_native_finalize", NULL);\n    ret = msc_process_request_body(ctx->modsec_transaction);'),
            ("    if (r->request_body != NULL && r->request_body->temp_file != NULL) {",
             '    ngxi12_body_state(ctx, "request_body_path", NULL);\n    if (r->request_body != NULL && r->request_body->temp_file != NULL) {')],
        "ngx_http_modsecurity_body_filter.c": [
            ("    return ngx_http_modsecurity_append_response_body_buffer(r, ctx, mcf,",
             '    ngxi12_body_state(ctx, "response_buffer", chain->buf);\n    return ngx_http_modsecurity_append_response_body_buffer(r, ctx, mcf,')]
    }
    for filename, changes in patches.items():
        target = snapshot / NGINX_SOURCE / filename
        before = sha(target)
        text = target.read_text()
        text = '#include "ngx_http_modsecurity_common.h"\n#include "i12-nginx-host-state.h"\n' + text
        for old, new in changes:
            if text.count(old) != 1:
                raise ValueError("exact NGINX state capture site differs: " + filename)
            text = text.replace(old, new)
        target.write_text(text)
        extra["files"][filename] = {"before_sha256": before, "after_sha256": sha(target)}
    (output / "nginx-extra-capture-receipt.json").write_text(json.dumps(extra, indent=2) + "\n")


def compile_fixtures(output):
    working_directory = command_path(output, storage_root(), directory=True)
    fixtures = output / "fixtures"
    fixtures.mkdir()
    fixture_receipt = {}
    for name in ("nginx_worker_self_maps", "nginx_common_input_fault",
                 "nginx_engine_budget_fault", "nginx_transaction_fault"):
        source = output / "source-ordinary" / "tests/fixtures" / (name + ".c")
        target = fixtures / (name + ".so")
        command = ["rtk", "proxy", "cc", "-std=c17", "-D_DEFAULT_SOURCE", "-Wall", "-Wextra", "-Werror",
                   "-shared", "-fPIC", "-I./source-ordinary/common/include",
                   "./source-ordinary/tests/fixtures/" + name + ".c", "-ldl", "-o", "./fixtures/" + name + ".so"]
        result = subprocess.run(command, cwd=working_directory,
                                capture_output=True, shell=False)
        (fixtures / (name + ".stdout")).write_bytes(result.stdout)
        (fixtures / (name + ".stderr")).write_bytes(result.stderr)
        fixture_receipt[name] = {"argv": command, "cwd": working_directory,
                                 "exit": result.returncode, "source_sha256": sha(source)}
        if result.returncode:
            raise RuntimeError("fixture build failed: " + name)
        fixture_receipt[name]["library_sha256"] = sha(target)
    (fixtures / RECEIPT_NAME).write_text(json.dumps(fixture_receipt, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "base", "output", "parent-sha"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()
    configured_storage = storage_root()
    checkout = trusted_path(args.source, (configured_storage, REPOSITORY_ROOT), directory=True)
    base = trusted_path(args.base, (configured_storage,), directory=True)
    if not 1 <= args.jobs <= 8:
        parser.error("fresh external output and 1..8 jobs required")
    output = create_private_output(args.output)
    def git(*argv):
        result = subprocess.run(["rtk", "proxy", "git", *argv], cwd=checkout,
                                check=True, capture_output=True)
        return result.stdout
    identity(args.parent_sha)
    if git("rev-parse", "HEAD").decode().strip() != args.parent_sha:
        raise ValueError("checkout HEAD differs from required exact head")
    scope = ["common", "connectors/nginx", "connectors/profile_registry.h", "connectors/profile_registry.c",
             LIFECYCLE_SOURCE, "tests/test_native_lifecycle_observer.py", "tests/fixtures/nginx_worker_self_maps.c",
             "tests/fixtures/nginx_common_input_fault.c", "tests/fixtures/nginx_engine_budget_fault.c",
             "tests/fixtures/nginx_transaction_fault.c"]
    # Evidence records the real checkout state; source scopes must remain clean.
    diff = git("diff", "HEAD", "--", *scope)
    (output / "checkout-source.diff").write_bytes(diff)
    (output / "checkout-status.txt").write_bytes(git("status", "--porcelain=v1"))
    # NGINX-owned untracked harnesses are allowed, never copied as product input.
    if diff:
        raise ValueError("tracked build inputs differ from exact checkout HEAD")
    manifest = checkout / "ci/runtime/lifecycle/i12/manifest.json"
    baseline = json.loads(manifest.read_text())["delivery_product_baseline"]
    capture = load_source(checkout / 'ci/runtime/lifecycle/i12/capture_sources.py')
    snapshots = {}
    export_identities = {}
    for variant in ("ordinary", "observed"):
        snapshot = output / ("source-" + variant)
        snapshot.mkdir(mode=0o700)
        export_identities[variant] = export_current(git, snapshot, args.parent_sha, capture)
        if variant == "observed":
            apply_historical_adapter(checkout, output, snapshot, capture, export_identities[variant], git)
            capture_extra_state(checkout, output, snapshot)
        snapshots[variant] = str(snapshot)
    provenance = {"checkout_sha": args.parent_sha, "manifest_sha256": sha(manifest),
                  "capture_helper_sha256": sha(checkout / "ci/runtime/lifecycle/i12/capture_sources.py"),
                  "capture_product_baseline": baseline, "source_snapshots": snapshots,
                  "validated_current_exports": export_identities,
                  "checkout_source_diff_sha256": sha(output / "checkout-source.diff")}
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    compile_fixtures(output)
    for variant in ("ordinary", "observed"):
        build(argparse.Namespace(source=snapshots[variant], checkout=str(checkout),
                                 base=str(base), output=str(output / variant),
                                 parent_sha=args.parent_sha, instrumented=variant == "observed",
                                 observer_source=None, jobs=args.jobs))
    if git("diff", "HEAD", "--", *scope) != diff:
        raise ValueError("checkout build inputs changed during build")
    print(json.dumps(provenance))


if __name__ == "__main__":
    main()
