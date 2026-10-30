#!/usr/bin/env python3
"""Prepare real, pinned host headers for full-scope CFamily AutoConfig.

This produces configure-time context, not a complete compilation database or a
claim that independent executable targets and their variants share an ABI.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import ast
import configparser
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from urllib.parse import urlsplit


ROOT = connector_root()

from modsecurity_connector_ci.lib.runtime_path_utils import is_safe_runtime_root
from modsecurity_test_framework.product_sources.ci.lib.framework_revision_pins import (
    FRAMEWORK_PATH, load_framework_revision_pins,
)

GIT_PREFIX = ("git", "--no-replace-objects")


def git_output(repository: Path, *arguments: str, data: bytes | None = None) -> bytes:
    return subprocess.check_output(
        [*GIT_PREFIX, "-C", str(repository), *arguments],
        stderr=subprocess.PIPE, timeout=120, input=data,
    )


def pinned_git_repository(destination: Path, url: str, revision: str, logs: Path, label: str,
                          *, bare: bool) -> list[dict[str, object]]:
    """Fetch one exact commit and materialize only explicitly requested blobs."""
    commands = [["git", "init", *(["--bare"] if bare else []), str(destination)]]
    prefix = [*GIT_PREFIX, "-C", str(destination)]
    commands.extend([
        prefix + ["remote", "add", "origin", url],
        prefix + ["config", "remote.origin.promisor", "true"],
        prefix + ["config", "remote.origin.partialCloneFilter", "blob:none"],
        prefix + ["-c", "fetch.fsckObjects=true", "fetch", "--depth=1", "--no-tags",
                  "--filter=blob:none", "origin", revision],
    ])
    records = [run(command, destination.parent, logs / f"{label}-git-{index}.log", timeout=120)
               for index, command in enumerate(commands)]
    if git_output(destination, "rev-parse", "FETCH_HEAD").decode().strip() != revision:
        raise ValueError("native source Git fetch returned a different commit")
    return records


def modsecurity_literal(value: str) -> object:
    """Decode one declaration without evaluating Framework source as code."""
    try:
        return ast.literal_eval(value)
    except (ValueError, SyntaxError):
        raise ValueError("Framework ModSecurity identity must contain literal values") from None


def modsecurity_contract(common: bytes) -> dict[str, str]:
    """Read the Framework's three immutable V3 declarations as passive data."""
    fields = {"MODSECURITY_V3_APPROVED_REPO_URL", "MODSECURITY_V3_APPROVED_COMMIT",
              "MODSECURITY_V3_RELEASE_TAG"}
    values = {}
    for line in common.decode("utf-8").splitlines():
        name, separator, value = line.partition("=")
        if separator and name in fields:
            if name in values:
                raise ValueError("Framework declares a duplicate ModSecurity identity")
            values[name] = modsecurity_literal(value)
    if set(values) != fields:
        raise ValueError("Framework ModSecurity identity is incomplete")
    origin = values["MODSECURITY_V3_APPROVED_REPO_URL"]
    revision = values["MODSECURITY_V3_APPROVED_COMMIT"]
    tag = values["MODSECURITY_V3_RELEASE_TAG"]
    if origin != "https://github.com/owasp-modsecurity/ModSecurity.git":
        raise ValueError("Framework ModSecurity identity must use the approved official origin")
    if not isinstance(revision, str) or re.fullmatch(r"[a-f0-9]{40}", revision, re.ASCII) is None:
        raise ValueError("Framework ModSecurity identity requires an exact commit")
    if not isinstance(tag, str) or re.fullmatch(r"v3\.\d+\.\d+", tag, re.ASCII) is None:
        raise ValueError("Framework ModSecurity identity requires a stable v3 release tag")
    return {"source_url": origin, "commit": revision, "release_tag": tag, "version": tag[1:]}


def framework_modsecurity_contract(output: Path, logs: Path) -> dict[str, object]:
    pins = load_framework_revision_pins(ROOT)
    revision = str(pins["framework_sha"])
    entry = git_output(ROOT, "ls-tree", "HEAD", "--", FRAMEWORK_PATH)
    if entry != f"160000 commit {revision}\t{FRAMEWORK_PATH}\n".encode("ascii"):
        raise ValueError("Framework revision lock disagrees with the Parent gitlink")
    modules = configparser.ConfigParser(interpolation=None)
    modules.read_string(git_output(ROOT, "show", "HEAD:.gitmodules").decode("utf-8"))
    origin = modules[f'submodule "{FRAMEWORK_PATH}"']["url"]
    parsed = urlsplit(origin)
    if (parsed.scheme != "https" or parsed.hostname != "github.com"
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or not parsed.path.endswith(".git")):
        raise ValueError("Framework identity requires a credential-free GitHub HTTPS origin")
    repository = output / "framework-contract.git"
    commands = pinned_git_repository(repository, origin, revision, logs, "framework", bare=True)
    specifier = revision + ":ci/lib/common.sh"
    size = int(git_output(repository, "cat-file", "-s", specifier))
    if not 0 < size <= 512 * 1024:
        raise ValueError("Framework source contract exceeds the input size bound")
    common = git_output(repository, "cat-file", "blob", specifier)
    blob = git_output(repository, "rev-parse", specifier).decode("ascii").strip()
    if git_output(repository, "hash-object", "--stdin", data=common).decode().strip() != blob:
        raise ValueError("Framework source contract disagrees with its Git blob")
    return {**modsecurity_contract(common), "framework_revision": revision,
            "framework_source_url": origin, "framework_common_blob": blob,
            "framework_common_sha256": hashlib.sha256(common).hexdigest(),
            "framework_commands": commands}


def modsecurity_headers(output: Path, logs: Path) -> tuple[Path, dict[str, object]]:
    identity = framework_modsecurity_contract(output, logs)
    source = output / "sources/modsecurity"
    commands = pinned_git_repository(source, str(identity["source_url"]), str(identity["commit"]),
                                     logs, "modsecurity", bare=False)
    commands.append(run(
        [*GIT_PREFIX, "-C", str(source), "sparse-checkout", "set",
         "--no-cone", "/headers/"], output, logs / "modsecurity-sparse.log"))
    commands.append(run(
        [*GIT_PREFIX, "-C", str(source), "checkout", "--detach", str(identity["commit"])],
        output, logs / "modsecurity-checkout.log"))
    if git_output(source, "rev-parse", "HEAD").decode().strip() != identity["commit"]:
        raise ValueError("ModSecurity header checkout disagrees with its approved identity")
    if git_output(source, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("ModSecurity header checkout is dirty")
    headers = source / "headers"
    identity.update({"source": str(source), "headers": str(headers), "commands": commands,
                     "headers_tree": git_output(source, "rev-parse", "HEAD:headers").decode().strip()})
    identity["public_headers"] = required_files([
        headers / "modsecurity/modsecurity.h", headers / "modsecurity/rules_set.h",
        headers / "modsecurity/transaction.h"])
    identity["cleanup_api_probe"] = run(
        ["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-isystem", str(headers),
         "-fsyntax-only", str(source_path('common/scripts/modsecurity_targeted_eval.cc', root=ROOT))],
        ROOT, logs / "modsecurity-cleanup-api-probe.log")
    return headers, identity


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def contracts() -> dict[str, dict[str, str]]:
    """Read existing Parent pins as data, without executing contract content."""
    module = ast.parse((source_path('ci/provisioning/components/prepare-runtime-components.py', root=ROOT)).read_text())
    values = {
        target.id: ast.literal_eval(node.value)
        for node in module.body if isinstance(node, ast.Assign)
        for target in node.targets if isinstance(target, ast.Name)
        and target.id.startswith("NGINX_PINNED_")
    }
    haproxy = json.loads((source_path('connectors/haproxy/htx-overlay/version-contract.json', root=ROOT)).read_text())
    lighttpd = {
        key: value for line in
        (source_path('connectors/lighttpd/lighttpd-version.contract', root=ROOT)).read_text().splitlines()
        if line and not line.startswith("#")
        for key, value in [line.split("=", 1)]
    }
    nginx_version = values["NGINX_PINNED_VERSION_READBACK"].split("/", 1)[1]
    result = {
        "nginx": {"version": nginx_version, "directory": f"nginx-{nginx_version}",
                  "url": values["NGINX_PINNED_SOURCE_REPOSITORY"] + "/releases/download/"
                  + values["NGINX_PINNED_RELEASE_TAG"] + "/" + values["NGINX_PINNED_RELEASE_ASSET_NAME"],
                  "sha256": values["NGINX_PINNED_RELEASE_ASSET_SHA256"]},
        "haproxy": {"version": haproxy["version"], "directory": "haproxy-" + haproxy["version"],
                    "url": haproxy["source_url"], "sha256": haproxy["sha256"]},
        "lighttpd": {"version": lighttpd["LIGHTTPD_VERSION"],
                     "directory": "lighttpd-" + lighttpd["LIGHTTPD_VERSION"],
                     "url": lighttpd["LIGHTTPD_DOWNLOAD_URL"], "sha256": lighttpd["LIGHTTPD_SHA256"],
                     "patch": lighttpd["LIGHTTPD_PATCH_FILENAME"]},
    }
    for item in result.values():
        parsed = urlsplit(item["url"])
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.query or parsed.fragment):
            raise ValueError("native source contracts require credential-free pinned HTTPS URLs")
        if not re.fullmatch(r"[a-f0-9]{64}", item["sha256"]):
            raise ValueError("native source contract requires an exact SHA-256")
        if not re.fullmatch(r"[a-z]+-\d+(?:\.\d+)+", item["directory"], re.ASCII):
            raise ValueError("native source contract directory is invalid")
    if Path(result["lighttpd"]["patch"]).name != result["lighttpd"]["patch"]:
        raise ValueError("lighttpd patch must be a versioned leaf filename")
    return result


def fresh_root(value: str) -> Path:
    path = Path(value)
    if (not path.is_absolute() or ".." in path.parts or any(c in value for c in "\r\n,\0")
            or not is_safe_runtime_root(path) or path.is_relative_to(ROOT)
            or ROOT.is_relative_to(path)):
        raise ValueError("native context root must be a safe absolute external path")
    if path.exists() or path.is_symlink():
        raise ValueError("native context root must be fresh")
    path.mkdir(parents=True, mode=0o700)
    return path


def verified_archive(item: dict[str, str], downloads: Path, archives_root: Path | None) -> Path:
    name = Path(urlsplit(item["url"]).path).name
    cached = archives_root / name if archives_root is not None else None
    if cached is not None and (cached.exists() or cached.is_symlink()):
        if cached.is_symlink() or not cached.is_file():
            raise ValueError("cached native archive must be a regular file")
        archive = cached
    else:
        archive = downloads / name
        request = urllib.request.Request(item["url"], headers={"User-Agent": "Parent-Sonar-native-context"})
        with urllib.request.urlopen(request, timeout=60) as response, archive.open("xb") as output:
            if urlsplit(response.geturl()).scheme != "https":
                raise ValueError("native source download redirected away from HTTPS")
            shutil.copyfileobj(response, output)
    if sha256(archive) != item["sha256"]:
        raise ValueError(f"native archive SHA-256 mismatch: {name}")
    return archive


def unpack(archive: Path, sources: Path, expected: str) -> Path:
    destination = sources / expected
    if destination.exists() or destination.is_symlink():
        raise ValueError("native extraction destination must be fresh")
    with tarfile.open(archive, "r:*") as bundle:
        members = bundle.getmembers()
        if not members or any(not Path(m.name).parts or Path(m.name).is_absolute()
                              or ".." in Path(m.name).parts
                              or Path(m.name).parts[0] != expected for m in members):
            raise ValueError("native archive has an unexpected top-level directory")
        bundle.extractall(sources, members=members, filter="data")
    if not destination.is_dir() or destination.is_symlink():
        raise ValueError("native archive did not produce the expected source directory")
    return destination


def run(command: list[str], cwd: Path, log: Path, *,
        environment: dict[str, str] | None = None, timeout: int = 300) -> dict[str, object]:
    selected_environment = environment or {}
    with log.open("x", encoding="utf-8") as output:
        subprocess.run(command, cwd=cwd, stdout=output, stderr=subprocess.STDOUT, check=True,
                       env=dict(os.environ, TMPDIR=str(log.parent), **selected_environment), timeout=timeout)
    return {"arguments": command, "directory": str(cwd), "log": str(log), "timeout_seconds": timeout,
            "environment": selected_environment}


def required_files(paths: list[Path]) -> dict[str, str]:
    for path in paths:
        if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
            raise ValueError(f"required native context file is missing or invalid: {path}")
    return {str(path): sha256(path) for path in paths}


def nginx_includes(source: Path) -> list[Path]:
    """Use the real configure-generated include search list, not guessed flags."""
    makefile = (source / "objs/Makefile").read_text().replace("\\\n", " ")
    for line in makefile.splitlines():
        name, separator, value = line.partition("=")
        if separator and name.strip() == "ALL_INCS":
            arguments = shlex.split(value)
            break
    else:
        raise ValueError("NGINX configure did not publish ALL_INCS")
    result = []
    for index, argument in enumerate(arguments):
        if argument == "-I":
            directory = (source / arguments[index + 1]).resolve()
        elif argument.startswith("-I"):
            directory = (source / argument[2:]).resolve()
        else:
            continue
        if directory.is_relative_to(source) and directory not in result:
            result.append(directory)
    if not result:
        raise ValueError("NGINX configure did not publish host include directories")
    return result


def include_value(paths: list[Path]) -> str:
    if not paths or any(not p.is_dir() or any(c in str(p) for c in "\r\n,\0") for p in paths):
        raise ValueError("native include directories must exist and have unambiguous paths")
    return ",".join(str(path) for path in paths)


def checkout_state() -> tuple[str, str]:
    def git(*arguments: str) -> str:
        return subprocess.check_output(["git", "-C", str(ROOT), *arguments], text=True).strip()
    return git("rev-parse", "HEAD"), git("status", "--porcelain", "--untracked-files=all")


def prepare(output: Path, pins: dict[str, dict[str, str]], archives_root: Path | None) -> dict[str, object]:
    revision, initial_status = checkout_state()
    sources, downloads, logs = (output / name for name in ("sources", "downloads", "logs"))
    for path in (sources, downloads, logs):
        path.mkdir()
    hosts = {}
    for name, item in pins.items():
        archive = verified_archive(item, downloads, archives_root)
        source = unpack(archive, sources, item["directory"])
        hosts[name] = {"version": item["version"], "archive_url": item["url"],
                       "archive_sha256": item["sha256"], "source": str(source)}
    nginx = Path(hosts["nginx"]["source"])
    hosts["nginx"]["configure"] = run(
        ["sh", "./configure", "--with-compat", "--add-dynamic-module=" + str(source_path('connectors/nginx', root=ROOT))],
        nginx, logs / "nginx-configure.log")
    generated = required_files([nginx / "objs/ngx_auto_config.h", nginx / "objs/ngx_auto_headers.h",
                                nginx / "objs/Makefile"])
    stock = Path(hosts["lighttpd"]["source"])
    patched = sources / ("lighttpd-patched-" + pins["lighttpd"]["version"])
    patch = source_path('connectors/lighttpd/patches', root=ROOT) / pins["lighttpd"]["patch"]
    hosts["lighttpd"]["patch_sha256"] = sha256(patch)
    hosts["lighttpd"]["patch_command"] = run(
        ["sh", str(source_path('connectors/lighttpd/build/apply_core_patch.sh', root=ROOT)), "--apply"],
        ROOT, logs / "lighttpd-patch.log", environment={
            "BUILD_ROOT": str(output), "LIGHTTPD_SOURCE_DIR": str(stock),
            "LIGHTTPD_PATCHED_SOURCE_DIR": str(patched)})
    stamp = patched / ".msconnector-lighttpd-patch.sha256"
    generated.update(required_files([stamp]))
    if stamp.read_text().strip() != hosts["lighttpd"]["patch_sha256"]:
        raise ValueError("patched lighttpd source stamp disagrees with the current patch")
    hosts["lighttpd"]["patch_stamp"] = str(stamp)
    plugin = (patched / "src/plugin.h").read_text()
    if not re.search(r"^#define\s+LIGHTTPD_MSCONNECTOR_STREAM_HOOK_ABI_VERSION\s+2\s*$", plugin, re.MULTILINE):
        raise ValueError("patched lighttpd header does not declare stream hook ABI 2")
    build, stage = output / "lighttpd-build", output / "lighttpd-stage"
    build.mkdir()
    configure = patched / "configure"
    if not configure.is_file():
        autogen = patched / "autogen.sh"
        hosts["lighttpd"]["autogen_sha256"] = required_files([autogen])[str(autogen)]
        # The unchanged upstream script installs an ERR trap despite its sh
        # shebang. Bash supports that trap and runs its actual autoreconf flow.
        hosts["lighttpd"]["bootstrap"] = run(
            ["bash", str(autogen)], patched, logs / "lighttpd-autogen.log")
    generated.update(required_files([configure]))
    hosts["lighttpd"]["configure"] = run(
        [str(configure), "--prefix=" + str(stage), "--bindir=" + str(stage / "bin"),
         "--sbindir=" + str(stage / "bin"), "--libdir=" + str(stage / "lib")],
        build, logs / "lighttpd-configure.log")
    generated.update(required_files([build / "config.h", patched / "src/plugin.h"]))
    modsecurity_include, hosts["modsecurity"] = modsecurity_headers(output, logs)
    generated.update(hosts["modsecurity"]["public_headers"])
    haproxy = Path(hosts["haproxy"]["source"])
    required_files([haproxy / "include/haproxy/api.h", haproxy / "VERSION", patched / "src/base.h"])
    if (haproxy / "VERSION").read_text().strip() != pins["haproxy"]["version"]:
        raise ValueError("HAProxy source VERSION disagrees with the contract")
    # AutoConfig follows the connector's conditional HTTP/2 branches even
    # though this real host configure is the H1 variant. Supply the actual
    # pinned dependency header without defining or enabling NGX_HTTP_V2.
    http2 = nginx / "src/http/v2"
    generated.update(required_files([http2 / "ngx_http_v2.h"]))
    hosts["nginx"]["conditional_http2_include"] = str(http2)
    includes = [modsecurity_include] + nginx_includes(nginx) + [
        http2, haproxy / "include", build, patched / "src"]
    if checkout_state() != (revision, initial_status):
        raise ValueError("checkout changed while native context was being prepared")
    manifest = {"revision": revision, "uncommitted_changes": bool(initial_status),
                "hosts": hosts, "generated_files": generated,
                "includes": [str(path) for path in includes], "include_value": include_value(includes),
                "limitations": ["Header/configure context only; no complete compilation database.",
                                "HAProxy make-derived feature defines are not globally injected.",
                                "lighttpd headers select patched-native; stock and patched ABIs are not interchangeable.",
                                "Per-file HAVE_CONFIG_H/MSCONNECTOR_LIGHTTPD_HOST_API and other variants are not proven by include directories.",
                                "AutoConfig C/C++ taint and independent executable-target assumptions remain unchanged."]}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--archives-root", type=Path)
    args = parser.parse_args()
    try:
        pins = contracts()
        manifest = prepare(fresh_root(args.output_root), pins, args.archives_root)
    except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError, configparser.Error) as error:
        print(f"Sonar native context failed: {error}", file=sys.stderr)
        return 1
    print(manifest["include_value"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
