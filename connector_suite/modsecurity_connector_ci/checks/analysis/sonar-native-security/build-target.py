#!/usr/bin/env python3
"""Capture one product target through a verified native producer seam.

Original-source builds, the bounded lighttpd split producer and genuine Go
postlink receipts are separate contracts. No functional tests or scanner run.
Each selected binary/module owns its database; broad Parent analysis is separate.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import ast
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

verify_fips_transition = load_tool('ci/checks/analysis/sonar-native-security/go_provenance.py').verify_fips_transition
verify_trusted_directory = load_tool('ci/checks/analysis/sonar-native-security/source_mapping.py').verify_trusted_directory


PROFILE_REGISTRY_SOURCE = 'connectors/profile_registry.c'
COMMON_SOURCE_DIRECTORY = 'common/src'
COMMON_INCLUDE_DIRECTORY = 'common/include'
PROFILE_REGISTRY_HEADER = 'connectors/profile_registry.h'
SHELL_FORWARD_ARGUMENTS = ' "$@"\n'
SHELL_EXEC_PREFIX = '#!/bin/sh\nexec '
COMMON_SOURCE_PATTERN = 'common/src/*.c'


TARGETS = {
    "common-targeted-evaluator": {
        "script": "ci/checks/analysis/check-targeted-evaluator-cpp17.sh",
        "producer_sha256": "0a39b7bc288eea8ee39764694e7fe5b21335761675590ca093e3d73585f1a6d3",
        "evaluator": True,
    },
    "apache-native-module": {"script": "connectors/apache/build/apxs-wrapper.in", "apache": True},
    "haproxy-htx": {"script": "connectors/haproxy/htx-overlay/build-overlay.sh", "haproxy_htx": True},
    "envoy-ext-proc": {
        "script": "connectors/envoy/build/build_ext_proc.sh",
        "artifact": "envoy-ext-proc/msconnector_envoy_ext_proc",
        "cgo": True,
        "sources": [PROFILE_REGISTRY_SOURCE,
                    "connectors/envoy/ext_proc/internal/processor/common_runtime_bridge.c"],
    },
    "envoy-composite": {
        "script": "connectors/envoy/build/build_composite.sh",
        "artifact": "envoy-composite/msconnector_composite",
        "cgo": True,
        "sources": [PROFILE_REGISTRY_SOURCE,
                    "connectors/envoy/ext_proc/internal/processor/common_runtime_bridge.c"],
    },
    "lighttpd-patched-module": {
        "script": "connectors/lighttpd/build/build_module.sh",
        "lighttpd_patched": True,
    },
    "nginx-dynamic-module": {
        "script": "connectors/nginx/config",
        "nginx": True,
    },
    "lighttpd-stock-sidecar": {
        "script": "connectors/lighttpd/build/build_stock_sidecar.sh",
        "producer_sha256": "8fccab4cdffa2f31172eebdcb88a839e967ccb31855abdd8de94bee21e7db8c0",
        "artifact": "lighttpd-stock-sidecar/lighttpd-stock-sidecar",
        "split": True,
    },
    "envoy-ext-authz": {
        "script": "connectors/envoy/build/build_connector.sh",
        "artifact": "envoy-connector/msconnector_envoy_ext_authz",
        "sources": [PROFILE_REGISTRY_SOURCE, "connectors/envoy/metadata.c",
                    "connectors/envoy/src/envoy_modsecurity_mapper.c",
                    "connectors/envoy/src/envoy_ext_authz_response_companion.c",
                    "connectors/envoy/src/envoy_ext_authz_service_main.c"],
    },
    "haproxy-spoa-runtime": {
        "script": "connectors/haproxy/Makefile",
        "artifact": "haproxy-spoa-runtime/haproxy-modsecurity-spoa",
        "make_target": "build-spoa-runtime",
    },
    "traefik-engine-service": {
        "script": "connectors/traefik/build/build-engine-service.sh",
        "artifact": "traefik-engine-service/traefik-engine-service",
        "sources": [PROFILE_REGISTRY_SOURCE,
                    "connectors/traefik/src/traefik_engine_service.c"],
    },
    "traefik-forwardauth": {
        "script": "connectors/traefik/build/build-connector.sh",
        "artifact": "traefik-connector/traefik-forwardauth",
        "sources": [PROFILE_REGISTRY_SOURCE, "connectors/traefik/metadata.c",
                    "connectors/traefik/src/traefik_modsecurity_mapper.c",
                    "connectors/traefik/src/traefik_forwardauth_response_companion.c",
                    "connectors/traefik/src/traefik_provenance.c",
                    "connectors/traefik/src/traefik_forwardauth_service_main.c"],
    },
}


def haproxy_sources(checkout):
    """Read the native recipe's explicit source lists without evaluating Make."""
    text = (checkout / "connectors/haproxy/Makefile").read_text()
    result = ["connectors/haproxy/src/haproxy_modsecurity_binding.c",
              "connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c",
              "connectors/haproxy/src/haproxy_modsecurity_mapper.c"]
    replacements = {"$(COMMON_SRC)": COMMON_SOURCE_DIRECTORY, "$(REPO_ROOT)/": "",
                    "$(PROFILE_REGISTRY_SOURCE)": PROFILE_REGISTRY_SOURCE}
    for variable in ("COMMON_SDK_SRCS", "RESPONSE_COMPANION_SRCS"):
        matches = re.findall(r"^" + variable + r" := (.+)$", text, re.MULTILINE)
        if len(matches) != 1:
            raise ValueError("native HAProxy source contract changed")
        for name in matches[0].split():
            for token, replacement in replacements.items():
                name = name.replace(token, replacement)
            if "$" in name:
                raise ValueError("unsupported dynamic HAProxy source contract")
            if name.startswith("src/"):
                name = "connectors/haproxy/" + name
            result.append(name)
    if len(result) != len(set(result)):
        raise ValueError("duplicate HAProxy target source")
    return result


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_build_output_ancestry(root):
    """Check every existing output ancestor before creating any task files."""
    ancestor = root.parent
    while not ancestor.exists():
        ancestor = ancestor.parent
    verify_trusted_directory(ancestor)


def mapping_manifest(checkout, root, producer, pairs, context):
    files = {str(copied): {"original": str(original), "sha256": digest(original)}
             for copied, original in pairs}
    manifest = {"schema": 1, "checkout": str(checkout), "copy_root": str(root),
                "producer": {"path": str(producer), "sha256": digest(producer)},
                "context_files": {str(path): digest(path) for path in context}, "files": files,
                "original_include_directories": [str(checkout / COMMON_INCLUDE_DIRECTORY), str(checkout)],
                "original_quote_directories": sorted({str(checkout)} | {str(original.parent) for _, original in pairs
                                                       if original.suffix in {".h", ".hpp", ".hxx"}
                                                       and not original.is_relative_to(checkout / COMMON_INCLUDE_DIRECTORY)})}
    path = root / "source-map.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    return path


def build_apache(checkout, root, sdk, environment, log):
    apxs_name = shutil.which("apxs")
    apache_name = shutil.which("apache2") or shutil.which("httpd")
    if apxs_name is None or apache_name is None:
        raise ValueError("Apache local feasibility requires existing installed apxs and matching host headers")
    apxs = Path(apxs_name).resolve(strict=True)
    version = subprocess.check_output([apache_name, "-v"], env=environment, text=True)
    stage = root / "apache-context"
    shutil.copytree(checkout / "connectors/apache", stage)
    producer = checkout / "connectors/apache/build/apxs-wrapper.in"
    text = producer.read_text()
    matches = re.findall(r'MSCONNECTOR_COMMON_SOURCES="([^\"]+)"', text)
    if len(matches) != 1:
        raise ValueError("Apache native Common source contract changed")
    common = []
    for item in matches[0].split():
        if not item.startswith("$MSCONNECTOR_COMMON_SRC/") or not item.endswith(".c"):
            raise ValueError("Apache native Common source list is not explicit")
        common.append(item.removeprefix("$MSCONNECTOR_COMMON_SRC/"))
    source_names = ["mod_security3.c", "msc_config.c", "msc_filters.c", "msc_utils.c", "msc_apache_mapper.c"]
    pairs = [(stage / "src" / path.name, path) for path in (checkout / "connectors/apache/src").iterdir()
             if path.is_file() and path.suffix in {".c", ".h"}]
    common_root = root / "common-src"
    registry = root / "profile-registry"
    pairs += [(common_root / name, checkout / COMMON_SOURCE_DIRECTORY / name) for name in [*common, "header_validation_internal.h"]]
    pairs += [(registry / PROFILE_REGISTRY_SOURCE, checkout / PROFILE_REGISTRY_SOURCE),
              (registry / PROFILE_REGISTRY_HEADER, checkout / PROFILE_REGISTRY_HEADER)]
    context = [apxs, checkout / "connectors/apache/configure.ac", checkout / "connectors/apache/Makefile.am"]
    manifest = mapping_manifest(checkout, root, producer, pairs, context)
    proxy = root / "apxs"
    proxy.write_text("#!/bin/sh\nfor arg do\n if [ \"$arg\" = -c ]; then\n  exec "
                     + shlex.join([str(apxs), "-S", "CC=" + environment["CC"],
                                   "-Wc,-std=c17", "-Wc,-Wall", "-Wc,-Wextra", "-Wc,-Werror"])
                     + ' "$@"\n fi\ndone\nexec ' + shlex.quote(str(apxs)) + SHELL_FORWARD_ARGUMENTS)
    proxy.chmod(0o700)
    environment = dict(environment, SONAR_NATIVE_SOURCE_MAP=str(manifest),
                       SONAR_NATIVE_LTO_CONTEXT="apache-gcc-native-driver",
                       MSCONNECTOR_COMMON_INC=str(checkout / COMMON_INCLUDE_DIRECTORY),
                       MSCONNECTOR_COMMON_SRC=str(checkout / COMMON_SOURCE_DIRECTORY),
                       MSCONNECTOR_COMMON_BUILD_SRC=str(common_root),
                       MSCONNECTOR_PROFILE_REGISTRY_BUILD_ROOT=str(registry))
    native_cc = subprocess.check_output([str(apxs), "-q", "CC"], env=environment, text=True).strip()
    if len(shlex.split(native_cc)) != 1 or "/" in native_cc:
        raise ValueError("installed APXS/libtool compiler requires a reviewed direct executable seam")
    real_native_cc = shutil.which(native_cc)
    if real_native_cc is None:
        raise ValueError("installed APXS compiler is unavailable")
    binary_dir = root / "bin"
    binary_dir.mkdir(mode=0o700)
    compiler_proxy = binary_dir / native_cc
    compiler_proxy.write_text(SHELL_EXEC_PREFIX + shlex.join([
        sys.executable, str(Path(__file__).with_name("capture.py").resolve()), "--compiler",
        str(Path(real_native_cc).resolve()), "--"]) + SHELL_FORWARD_ARGUMENTS)
    compiler_proxy.chmod(0o700)
    environment["PATH"] = str(binary_dir) + os.pathsep + environment["PATH"]
    subprocess.run(["sh", "./autogen.sh"], cwd=stage, env=environment,
                   stdout=log, stderr=subprocess.STDOUT, check=True)
    configure = ["./configure", "--with-apxs=" + str(proxy), "--with-libmodsecurity=" + str(sdk)]
    subprocess.run(configure, cwd=stage, env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
    subprocess.run(["make"], cwd=stage, env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
    artifact = stage / "src/.libs/mod_security3.so"
    query = {}
    for name in ("CC", "CFLAGS", "CPPFLAGS", "EXTRA_CPPFLAGS", "EXTRA_CFLAGS", "INCLUDEDIR", "LIBTOOL"):
        query[name] = subprocess.check_output([str(apxs), "-q", name], env=environment, text=True).strip()
    receipt = {"context_kind": "installed-context-local-feasibility", "runtime_qualification": False,
               "apache_version": version.strip(), "apxs": str(apxs), "apxs_sha256": digest(apxs),
               "apxs_queries": query, "configure_arguments": configure,
               "configure_directory": str(stage), "source_map": str(manifest),
               "source_map_sha256": digest(manifest),
               "limitation": "Installed Apache/APR context is recorded; no pinned runtime or hosted evidence is asserted."}
    (root / "apache-installed-context.json").write_text(json.dumps(receipt, indent=2) + "\n")
    sources = ["connectors/apache/src/" + name for name in source_names]
    sources += ["common/src/" + name for name in common] + [PROFILE_REGISTRY_SOURCE]
    return sources, artifact, receipt


def extract_haproxy_archive(archive, host, dirname):
    """Validate the pinned archive layout before extracting any member."""
    with tarfile.open(archive) as bundle:
        members = bundle.getmembers()
        if not members or any(Path(member.name).is_absolute() or ".." in Path(member.name).parts
                              or not Path(member.name).parts or Path(member.name).parts[0] != dirname
                              for member in members):
            raise ValueError("HAProxy archive has an unexpected source root")
        bundle.extractall(host, members=members, filter="data")


def record_haproxy_foreign_sources(producer, checkout, worktree, source, dirname, foreign):
    """Bind upstream compile sources to their unchanged pinned archive members."""
    for path in producer["sources"]:
        if not Path(path).is_relative_to(checkout):
            relative = Path(path).relative_to(worktree)
            if digest(source / relative) != digest(Path(path)):
                raise ValueError("upstream HTX source differs from its pinned archive member")
            foreign[path] = {"archive_member": dirname + "/" + str(relative), "sha256": digest(Path(path))}


def haproxy_foreign_sources(link, records, checkout, worktree, source, dirname):
    """Require one actual compile producer per linked native object."""
    foreign = {}
    for name, expected in link["inputs"].items():
        if Path(name).suffix != ".o":
            # Shared SDK inputs are separately hash-bound in the target
            # contract; they are not translation-unit object producers.
            continue
        producers = [record for record in records if record["kind"] == "compile"
                     and record["output"] == name and record["output_sha256"] == expected]
        if len(producers) != 1:
            raise ValueError("native HTX link input lacks its unique actual compile")
        record_haproxy_foreign_sources(producers[0], checkout, worktree, source, dirname, foreign)
    return foreign


def build_haproxy_htx(checkout, root, environment, archive, log):
    contract_path = checkout / "connectors/haproxy/htx-overlay/version-contract.json"
    pin = json.loads(contract_path.read_text())
    if archive is None or digest(archive) != pin["sha256"]:
        raise ValueError("HAProxy HTX requires the current native contract's verified source archive")
    archive = archive.resolve(strict=True)
    dirname = "haproxy-" + pin["version"]
    host = root / "host"
    host.mkdir()
    extract_haproxy_archive(archive, host, dirname)
    source = host / dirname
    overlay = root / "haproxy-overlay"
    worktree = overlay / "worktree"
    producer = checkout / TARGETS["haproxy-htx"]["script"]
    text = producer.read_text()
    matches = re.findall(r"^COMMON_SOURCES='([^']+)'$", text, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError("HAProxy HTX native Common source contract changed")
    pairs = [(worktree / "src/haproxy_modsecurity_htx_filter.c",
              checkout / "connectors/haproxy/htx-overlay/haproxy_modsecurity_htx_filter.c")]
    for name in ("haproxy_modsecurity_binding.c", "haproxy_modsecurity_binding.h",
                 "haproxy_modsecurity_mapper.c", "haproxy_modsecurity_mapper.h"):
        pairs.append((worktree / "src" / name, checkout / "connectors/haproxy/src" / name))
    pairs += [(worktree / "src/msconnector_profile_registry.c", checkout / PROFILE_REGISTRY_SOURCE),
              (worktree / "src/connectors/profile_registry.h", checkout / PROFILE_REGISTRY_HEADER),
              (worktree / "src/header_validation_internal.h", checkout / "common/src/header_validation_internal.h"),
              (worktree / "src/msconnector_response_companion_client.c", checkout / "common/runtime/response_companion_client.c")]
    for name in ("response_companion_client.h", "response_companion_protocol.h",
                 "response_companion_transport.h", "msconnector_runtime.h"):
        pairs.append((worktree / "src" / name, checkout / "common/runtime" / name))
    for path in (checkout / "common/include/msconnector").rglob("*"):
        if path.is_file():
            pairs.append((worktree / "include/msconnector" / path.relative_to(checkout / "common/include/msconnector"), path))
    for name in matches[0].split():
        pairs.append((worktree / "src" / ("msconnector_" + name), checkout / COMMON_SOURCE_DIRECTORY / name))
    context = [archive, contract_path, checkout / "connectors/haproxy/htx-overlay" / pin["makefile_patch"],
               source / "Makefile"]
    manifest = mapping_manifest(checkout, root, producer, pairs, context)
    binary_dir = root / "bin"
    binary_dir.mkdir(mode=0o700)
    make = shutil.which("make")
    if make is None:
        raise ValueError("native HTX producer requires an existing Make")
    # Upstream assigns CC unconditionally. This producer-owned proxy supplies
    # the capture compiler as a real Make command-line variable and adds C17
    # with the GNU extensions required by upstream typeof expressions; no
    # warnings are removed from the native recipe's existing include flags.
    make_proxy = binary_dir / "make"
    make_proxy.write_text("#!/usr/bin/env python3\nimport os,sys\na=sys.argv[1:]\n"
                          "a=[v+' -std=gnu17' if v.startswith('CFLAGS=') else v for v in a]\n"
                          + "os.execv(" + repr(make) + ",[" + repr(make) + ","
                          + repr("CC=" + environment["CC"]) + ",*a])\n")
    make_proxy.chmod(0o700)
    environment = dict(environment, HAPROXY_HTX_SOURCE_DIR=str(source), HAPROXY_HTX_BUILD_DIR=str(overlay),
                       CONNECTOR_ROOT=str(checkout), MAKE_JOBS=str(os.cpu_count() or 1),
                       SONAR_NATIVE_SOURCE_MAP=str(manifest), PATH=str(binary_dir) + os.pathsep + environment["PATH"])
    command = ["sh", str(producer)]
    subprocess.run(command, cwd=checkout, env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
    records = [json.loads(path.read_text()) for path in (root / "captures").glob("*.json")]
    artifact = worktree / "haproxy"
    links = [record for record in records if record["kind"] == "link" and record["output"] == str(artifact)]
    if len(links) != 1:
        raise ValueError("native HTX binary has no unique actual compiler link")
    foreign = haproxy_foreign_sources(links[0], records, checkout, worktree, source, dirname)
    receipt = root / "haproxy-build-receipt.json"
    receipt.write_text(json.dumps({"host": "haproxy", "source_root": str(worktree),
                                  "native_build_arguments": command, "producer_sha256": digest(producer),
                                  "archive_sources": foreign,
                                  "generated_files": {str(worktree / "Makefile"): digest(worktree / "Makefile")}}, indent=2) + "\n")
    external_context = {"host": "haproxy", "source_root": str(worktree), "archive": str(archive),
                        "archive_sha256": digest(archive), "pin_contract": str(contract_path),
                        "pin_contract_sha256": digest(contract_path), "configure_receipt": str(receipt),
                        "configure_receipt_sha256": digest(receipt)}
    sources = [str(original.relative_to(checkout)) for _, original in pairs if original.suffix == ".c"]
    return sources, artifact, {name: value["sha256"] for name, value in foreign.items()}, external_context


def replay_go_link_candidates(records, root, go, artifact, environment, log):
    """Replay the actual buildid step and require one matching final artifact."""
    candidates = []
    replay_root = root / "go-buildid-replay"
    replay_root.mkdir(mode=0o700)
    for index, record in enumerate(row for row in records if row["kind"] == "go-tool-link"):
        postlink = Path(record["retained_output"])
        if digest(postlink) != record["output_sha256"] or digest(Path(record["arguments"][0])) != record["tool_sha256"]:
            raise ValueError("actual Go linker/tool output identity changed")
        replay = replay_root / str(index)
        shutil.copyfile(postlink, replay)
        command = [str(go), "tool", "buildid", "-w", str(replay)]
        subprocess.run(command, env=dict(environment, GOFLAGS=""), stdout=log, stderr=subprocess.STDOUT, check=True)
        if digest(replay) == digest(artifact):
            candidates.append((record, replay, command))
    if len(candidates) != 1:
        raise ValueError("no unique actual Go linker/buildid chain produces the final artifact")
    go_link, replay, replay_command = candidates[0]
    return go_link, replay, replay_command


def restore_go_native_context(raw, work_root):
    """Verify retained bytes before restoring missing task-owned link context."""
    for name, retained in raw["retained_files"].items():
        path = Path(name)
        expected = raw["output_sha256"] if name == raw["output"] else raw["inputs"][name]
        if digest(Path(retained)) != expected:
            raise ValueError("retained real native linker input/output changed")
        if path.is_file():
            if digest(path) != expected:
                raise ValueError("native linker input/output was unexpectedly replaced")
        elif path.is_relative_to(work_root):
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(retained, path)
        else:
            raise ValueError("missing native linker context outside task-owned Go work root")


def go_object_provenance(raw, records, checkout):
    """Separate unique Parent object producers from external Go context."""
    aliases, external, context_compiles = {}, {}, []
    for name, expected in raw["inputs"].items():
        if Path(name).suffix != ".o":
            continue
        matches = [record for record in records if record["kind"] == "compile"
                   and record["output_sha256"] == expected]
        parent_matches = [record for record in matches
                          if any(Path(source).is_relative_to(checkout) for source in record["sources"])]
        if len(parent_matches) > 1:
            raise ValueError("ambiguous Parent compilation identity for Go linker object")
        if parent_matches:
            aliases[name] = {"producer": parent_matches[0]["output"], "sha256": expected}
        else:
            external[name] = expected
            context_compiles.extend(matches)
    return aliases, external, context_compiles


def finish_go_capture(checkout, root, artifact, environment, log):
    """Bind real C/AR/link inputs to the Go final artifact without source rewrites."""
    records = [json.loads(path.read_text()) for path in (root / "captures").glob("*.json")]
    go = Path(shutil.which("go")).resolve(strict=True)
    version = subprocess.check_output([str(go), "env", "GOVERSION"], env=environment, text=True).strip()
    approved_version = "go" + (checkout / ".go-version").read_text().strip()
    if version != approved_version:
        raise ValueError("actual Go toolchain differs from current Parent .go-version")
    goroot = Path(subprocess.check_output([str(go), "env", "GOROOT"], env=environment, text=True).strip())
    go_link, replay, replay_command = replay_go_link_candidates(records, root, go, artifact, environment, log)
    raw_candidates = [record for record in records if record["kind"] == "link"
                      and record["output"] == go_link["output"]]
    if len(raw_candidates) != 1:
        raise ValueError("Go final artifact lacks a unique raw native compiler link")
    raw = raw_candidates[0]
    retained_raw = Path(raw["retained_files"][raw["output"]])
    transition = verify_fips_transition(retained_raw, go_link["retained_output"])
    work_root = root / "go-work"
    restore_go_native_context(raw, work_root)
    aliases, external, context_compiles = go_object_provenance(raw, records, checkout)
    source_paths = [goroot / name for name in (
        "src/cmd/link/internal/ld/fips140.go", "src/cmd/go/internal/work/buildid.go",
        "src/cmd/buildid/buildid.go", "src/cmd/internal/buildid/rewrite.go")]
    sources = {str(path): digest(path) for path in source_paths}
    chain = {"go_version": version, "go_executable": str(go), "go_sha256": digest(go),
             "goroot": str(goroot), "go_sources": sources,
             "go_work_root": str(work_root), "go_link": go_link, "raw_link_output": raw["output"],
             "raw_link_sha256": raw["output_sha256"], "retained_raw_link": str(retained_raw),
             "fips_transition": transition, "buildid_replay_arguments": replay_command,
             "buildid_replay": str(replay), "buildid_replay_sha256": digest(replay),
             "published_artifact": str(artifact), "published_sha256": digest(artifact),
             "object_aliases": aliases, "external_go_inputs": external,
             "external_context_compilations": context_compiles}
    (root / "go-producer-chain.json").write_text(json.dumps(chain, indent=2) + "\n")
    return chain


def build_nginx(checkout, root, sdk, environment, archive, log):
    """Build only the pinned native dynamic module, keeping configure context."""
    pin_source = checkout / "ci/provisioning/components/prepare-runtime-components.py"
    tree = ast.parse(pin_source.read_text())
    pins = {target.id: ast.literal_eval(node.value)
            for node in tree.body if isinstance(node, ast.Assign)
            for target in node.targets if isinstance(target, ast.Name)
            and target.id in {"NGINX_PINNED_RELEASE_ASSET_NAME", "NGINX_PINNED_RELEASE_ASSET_SHA256"}}
    if archive is None or archive.name != pins["NGINX_PINNED_RELEASE_ASSET_NAME"]:
        raise ValueError("NGINX requires its declared pinned host archive")
    archive = archive.resolve(strict=True)
    if digest(archive) != pins["NGINX_PINNED_RELEASE_ASSET_SHA256"]:
        raise ValueError("NGINX host archive SHA256 disagrees with current Parent pin")
    host = root / "host"
    host.mkdir()
    dirname = archive.name.removesuffix(".tar.gz")
    with tarfile.open(archive) as bundle:
        members = bundle.getmembers()
        if not members or any(Path(member.name).is_absolute() or ".." in Path(member.name).parts
                              or not Path(member.name).parts or Path(member.name).parts[0] != dirname
                              for member in members):
            raise ValueError("NGINX archive has an unexpected source root")
        bundle.extractall(host, members=members, filter="data")
    source = host / dirname
    environment = dict(environment, MODSECURITY_INC=str(sdk / "include"), MODSECURITY_LIB=str(sdk / "lib"),
                       MSCONNECTOR_COMMON_INC=str(checkout / COMMON_INCLUDE_DIRECTORY),
                       MSCONNECTOR_COMMON_SRC=str(checkout / COMMON_SOURCE_DIRECTORY),
                       MSCONNECTOR_PROFILE_REGISTRY_ROOT=str(checkout))
    configure = ["sh", "./configure", "--with-compat", "--with-cc=" + environment["CC"],
                 "--with-cc-opt=-std=c17 -Wall -Wextra -Werror",
                 "--add-dynamic-module=" + str(checkout / "connectors/nginx")]
    subprocess.run(configure, cwd=source, env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
    subprocess.run(["make", "-j", str(os.cpu_count() or 1), "modules"], cwd=source,
                   env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
    module_contract = (checkout / "connectors/nginx/config").read_text()
    matches = re.findall(r'ngx_module_srcs="([^\"]+)"', module_contract)
    if len(matches) != 1:
        raise ValueError("NGINX native source contract changed")
    sources = []
    for item in matches[0].replace("\\\n", " ").split():
        for variable, value in (("$ngx_addon_dir", "connectors/nginx"),
                                ("$MSCONNECTOR_COMMON_SRC", COMMON_SOURCE_DIRECTORY),
                                ("$MSCONNECTOR_PROFILE_REGISTRY_ROOT/", "")):
            item = item.replace(variable, value)
        if "$" in item or Path(item).is_absolute() or ".." in Path(item).parts:
            raise ValueError("unsupported dynamic NGINX source contract")
        sources.append(item)
    glue = source / "objs/ngx_http_modsecurity_module_modules.c"
    generated = {str(path): digest(path) for path in (glue, source / "objs/Makefile",
                 source / "objs/ngx_auto_config.h", source / "objs/ngx_auto_headers.h")}
    receipt = root / "nginx-configure-receipt.json"
    receipt.write_text(json.dumps({"host": "nginx", "source_root": str(source),
                                  "configure_arguments": configure, "configure_directory": str(source),
                                  "generated_files": generated}, indent=2) + "\n")
    context = {"host": "nginx", "source_root": str(source),
               "archive": str(archive), "archive_sha256": digest(archive),
               "pin_contract": str(pin_source), "pin_contract_sha256": digest(pin_source),
               "configure_receipt": str(receipt), "configure_receipt_sha256": digest(receipt)}
    return sources, source / "objs/ngx_http_modsecurity_module.so", {str(glue): digest(glue)}, context


def build_lighttpd_patched(checkout, root, environment, archive, log):
    contract_path = checkout / "connectors/lighttpd/lighttpd-version.contract"
    pin = {key: value for line in contract_path.read_text().splitlines()
           if line and not line.startswith("#") for key, value in [line.split("=", 1)]}
    dirname = "lighttpd-" + pin["LIGHTTPD_VERSION"]
    if archive is None:
        url = pin["LIGHTTPD_DOWNLOAD_URL"]
        if url != "https://download.lighttpd.net/lighttpd/releases-1.4.x/" + dirname + ".tar.xz":
            raise ValueError("lighttpd download requires its declared official HTTPS origin")
        archive = root / (dirname + ".tar.xz")
        with urllib.request.urlopen(url, timeout=60) as response, archive.open("xb") as stream:
            if not response.geturl().startswith("https://"):
                raise ValueError("lighttpd host archive redirected away from HTTPS")
            shutil.copyfileobj(response, stream)
    archive = archive.resolve(strict=True)
    if digest(archive) != pin["LIGHTTPD_SHA256"]:
        raise ValueError("lighttpd host archive disagrees with current native version contract")
    host = root / "host"
    host.mkdir()
    with tarfile.open(archive) as bundle:
        members = bundle.getmembers()
        if not members or any(Path(member.name).is_absolute() or ".." in Path(member.name).parts
                              or not Path(member.name).parts or Path(member.name).parts[0] != dirname
                              for member in members):
            raise ValueError("lighttpd archive has an unexpected source root")
        bundle.extractall(host, members=members, filter="data")
    original = host / dirname
    patched = host / (dirname + "-patched")
    environment = dict(environment, LIGHTTPD_SOURCE_DIR=str(original), LIGHTTPD_PATCHED_SOURCE_DIR=str(patched))
    patch_script = checkout / "connectors/lighttpd/build/apply_core_patch.sh"
    subprocess.run(["sh", str(patch_script), "--apply"], cwd=checkout, env=environment,
                   stdout=log, stderr=subprocess.STDOUT, check=True)
    config = root / "lighttpd-config"
    config.mkdir()
    if not (patched / "configure").is_file():
        if any(shutil.which(tool) is None for tool in ("autoreconf", "autoconf", "automake")):
            raise ValueError("pinned lighttpd source requires existing Autotools; no tool installation is authorized")
        # The canonical script installs an ERR trap; execute that actual
        # producer with Bash, as the existing native-context producer does.
        subprocess.run(["bash", str(patched / "autogen.sh")], cwd=patched, env=environment,
                       stdout=log, stderr=subprocess.STDOUT, check=True)
    configure = [str(patched / "configure"), "--prefix=" + str(root / "lighttpd-stage")]
    subprocess.run(configure, cwd=config, env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
    environment.update({"LIGHTTPD_SOURCE_DIR": str(patched), "LIGHTTPD_CONFIG_DIR": str(config),
                        "LIGHTTPD_MSCONNECTOR_CORE_MODE": "patched", "MSCONNECTOR_C_STD": "c17"})
    for name in ("LIGHTTPD_CONNECTOR_OUT_DIR", "LIGHTTPD_MODULE_DIR"):
        environment.pop(name, None)
    subprocess.run(["sh", str(checkout / TARGETS["lighttpd-patched-module"]["script"])],
                   cwd=checkout, env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
    sources = sorted(str(path.relative_to(checkout)) for path in checkout.glob(COMMON_SOURCE_PATTERN))
    sources += ["common/runtime/msconnector_runtime.c", PROFILE_REGISTRY_SOURCE,
                "connectors/lighttpd/src/lighttpd_modsecurity_mapper.c", "connectors/lighttpd/module/mod_msconnector.c"]
    patchfile = checkout / "connectors/lighttpd/patches" / pin["LIGHTTPD_PATCH_FILENAME"]
    context = {"host": "lighttpd", "archive": str(archive), "archive_sha256": digest(archive),
               "version_contract": str(contract_path), "version_contract_sha256": digest(contract_path),
               "patch": str(patchfile), "patch_sha256": digest(patchfile),
               "configure_arguments": configure, "configure_directory": str(config),
               "generated_files": {str(path): digest(path) for path in
                   (config / "config.h", patched / "src/plugin.h", patched / ".msconnector-lighttpd-patch.sha256")}}
    return sources, root / "build/lighttpd-connector/modules/mod_msconnector.so", context


def build_lighttpd_split(checkout, root, sdk, environment, log):
    """Explicit mirrored native command: fail closed on any producer change.

    The native producer combines compilation and linking. This adapter executes
    original sources separately with identical flags, then compares its product
    bytes with a real canonical native-script build. The independent smoke
    executable produced by that comparison is never executed or exported.
    """
    sources = ["connectors/lighttpd/stock_sidecar/stock_sidecar.c",
               "common/runtime/msconnector_runtime.c", PROFILE_REGISTRY_SOURCE]
    sources += sorted(str(path.relative_to(checkout)) for path in checkout.glob(COMMON_SOURCE_PATTERN))
    flags = ["-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread",
             "-DMSCONNECTOR_STOCK_SIDECAR_MAIN"]
    for directory in (checkout, checkout / COMMON_INCLUDE_DIRECTORY, checkout / "common/runtime",
                      checkout / "connectors/lighttpd/stock_sidecar", sdk / "include"):
        flags += ["-I", str(directory)]
    output = root / "build/lighttpd-stock-sidecar"
    output.mkdir(parents=True)
    objects = []
    for index, source in enumerate(sources):
        obj = output / f"{index}.o"
        command = [environment["CC"], *flags, "-c", str(checkout / source), "-o", str(obj)]
        subprocess.run(command, cwd=checkout, env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
        objects.append(str(obj))
    command = [environment["CC"], *flags, *objects, "-L", str(sdk / "lib"),
               "-Wl,-rpath," + str(sdk / "lib"), "-lmodsecurity", "-lcrypto", "-lyajl",
               "-o", str(output / "lighttpd-stock-sidecar")]
    subprocess.run(command, cwd=checkout, env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
    baseline_environment = dict(environment, BUILD_ROOT=str(root / "canonical-build"), MSCONNECTOR_C_STD="c17")
    baseline_environment.pop("LIGHTTPD_STOCK_SIDECAR_OUT_DIR", None)
    subprocess.run(["sh", str(checkout / TARGETS["lighttpd-stock-sidecar"]["script"])],
                   cwd=checkout, env=baseline_environment, stdout=log, stderr=subprocess.STDOUT, check=True)
    canonical = root / "canonical-build/lighttpd-stock-sidecar/lighttpd-stock-sidecar"
    if digest(canonical) != digest(output / "lighttpd-stock-sidecar"):
        raise ValueError("split lighttpd artifact differs from canonical native producer; parity unverified")
    return sources, digest(canonical)


def build_targeted_evaluator(checkout, root, sdk, environment, cxx, log):
    """Mirror the SHA-bound C++17 producer with durable selected-SDK context.

    Only compilation and linking run. The canonical producer's temporary
    include overlay is unsuitable for a retained compilation database, so this
    target owns an equivalent namespace-only overlay for the entire scan.
    """
    source = "common/scripts/modsecurity_targeted_eval.cc"
    overlay = root / "sdk-includes"
    overlay.mkdir(mode=0o700)
    (overlay / "modsecurity").symlink_to(sdk / "include/modsecurity", target_is_directory=True)
    flags = ["-std=c++17", "-Wall", "-Wextra", "-Werror", "-isystem", str(overlay)]
    obj = root / "modsecurity_targeted_eval.o"
    artifact = root / "modsecurity_targeted_eval"
    subprocess.run([environment["CXX"], *flags, "-c", str(checkout / source), "-o", str(obj)],
                   cwd=checkout, env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
    subprocess.run([environment["CXX"], *flags, str(obj), "-L", str(sdk / "lib"),
                    "-Wl,-rpath," + str(sdk / "lib"), "-lmodsecurity", "-o", str(artifact)],
                   cwd=checkout, env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
    # Run the genuine combined native producer with the same actual compiler;
    # it never executes the evaluator. Its temporary context is not exported.
    compiler = Path(shutil.which(cxx)).resolve(strict=True)
    baseline_environment = dict(environment, CXX=str(compiler), CPP_BUILD_ROOT=str(root / "canonical-build"))
    subprocess.run(["sh", str(checkout / TARGETS["common-targeted-evaluator"]["script"])],
                   cwd=checkout, env=baseline_environment, stdout=log, stderr=subprocess.STDOUT, check=True)
    canonical = root / "canonical-build/modsecurity_targeted_eval"
    if digest(canonical) != digest(artifact):
        raise ValueError("split C++17 evaluator differs from canonical producer; artifact parity unverified")
    receipt = {"canonical_artifact_sha256": digest(canonical), "split_command_mirror": True,
               "durable_sdk_namespace_overlay": str(overlay), "language_standard": "c++17",
               "canonical_compiler": str(compiler), "canonical_compiler_sha256": digest(compiler),
               "runtime_executed": False}
    (root / "evaluator-build-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return [source], artifact, receipt


def verify_native_output_root(checkout, root, sdk, allowed_output_parent):
    """Validate external ownership and ancestry before creating build files."""
    allowed_parent = (Path("/var/tmp/codex/ModSecurity-conector") if allowed_output_parent is None
                      else allowed_output_parent).resolve(strict=True)
    verify_trusted_directory(allowed_parent)
    if (len(allowed_parent.parts) < 3 or not allowed_parent.is_dir()
            or allowed_parent.is_relative_to(checkout)
            or allowed_parent.stat().st_uid != os.getuid()):
        raise ValueError("authorized output parent must be an owned external directory disjoint from checkout")
    if any(re.fullmatch(r"[-A-Za-z0-9_./]+", str(path)) is None for path in (checkout, root, sdk)):
        raise ValueError("native shell producers require unambiguous path operands")
    if root.exists() or root.is_symlink() or ".." in root.parts:
        raise ValueError("build run root must be fresh and absolute")
    if (root == allowed_parent or not root.is_relative_to(allowed_parent)
            or root.resolve() != root):
        raise ValueError("build run root must be a fresh private child of the caller-authorized external parent")
    if root.is_relative_to(checkout) or checkout.is_relative_to(root):
        raise ValueError("build run root must be disjoint from checkout")
    verify_build_output_ancestry(root)


def verify_native_build_inputs(checkout, sdk, target):
    """Bind the selected native producer and immutable SDK before build setup."""
    spec = TARGETS[target]
    if "producer_sha256" in spec and digest(checkout / spec["script"]) != spec["producer_sha256"]:
        raise ValueError("split adapter canonical producer changed; explicit parity review required")
    library = sdk / "lib/libmodsecurity.so"
    if not library.is_file() or not (sdk / "include/modsecurity/modsecurity.h").is_file():
        raise ValueError("SDK must supply the immutable ModSecurity development prefix")
    return spec, library


def native_build_environment(checkout, root, sdk, captures, shims):
    """Sanitize inherited compiler paths and retain explicit native defaults."""
    environment = dict(os.environ)
    implicit_environment = {
        "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH", "INCLUDE",
        "COMPILER_PATH", "GCC_EXEC_PREFIX", "LIBRARY_PATH", "GCC_SPECS", "SDKROOT",
        "MACOSX_DEPLOYMENT_TARGET", "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "LD_RUN_PATH",
        "DEPENDENCIES_OUTPUT", "SUNPRO_DEPENDENCIES", "SOURCE_DATE_EPOCH",
        "CCC_OVERRIDE_OPTIONS",
        "CFLAGS", "CPPFLAGS", "LDFLAGS", "LDLIBS", "MODSECURITY_LIB_FILE", "MODSECURITY_PREFIX",
    }
    for name in tuple(environment):
        if name in implicit_environment or name.startswith(("DYLD_", "HAPROXY_", "SONAR_NATIVE_")):
            environment.pop(name)
    environment["LC_ALL"] = "C"
    compiler_tmp = root / "compiler-tmp"
    compiler_tmp.mkdir(mode=0o700)
    # These native build flags are optional caller extensions. A dedicated
    # capture run starts from the production defaults rather than inheriting
    # unrelated diagnostic/coverage/link overrides.
    for name in ("TRAEFIK_ENGINE_SERVICE_CFLAGS", "TRAEFIK_ENGINE_SERVICE_LDFLAGS",
                 "TRAEFIK_CONNECTOR_CFLAGS", "TRAEFIK_CONNECTOR_LDFLAGS",
                 "TRAEFIK_ENGINE_SERVICE_BUILD_DIR", "TRAEFIK_ENGINE_SERVICE_BIN",
                 "TRAEFIK_CONNECTOR_BUILD_DIR", "TRAEFIK_CONNECTOR_BIN"):
        environment.pop(name, None)
    environment.update({"BUILD_ROOT": str(root / "build"), "CC": shims["cc"], "CXX": shims["cxx"],
                        "CONNECTOR_ROOT": str(checkout), "PROJECT_ROOT": str(checkout),
                        "MAKEFLAGS": "", "MFLAGS": "", "MAKEOVERRIDES": "",
                        "TMPDIR": str(compiler_tmp),
                        "SONAR_NATIVE_CAPTURE_ROOT": str(captures),
                        "MODSECURITY_INCLUDE_DIR": str(sdk / "include"),
                        "MODSECURITY_LIB_DIR": str(sdk / "lib")})
    return environment


def configure_go_capture_environment(checkout, root, target, spec, environment, go_module_cache):
    """Install capture seams and configure the isolated offline Go work root."""
    if spec.get("cgo"):
        archiver = shutil.which("ar")
        if archiver is None:
            raise ValueError("native CGo archive requires an existing archiver")
        shim = root / "ar"
        shim.write_text(SHELL_EXEC_PREFIX + shlex.join([
            sys.executable, str(Path(__file__).with_name("archive-capture.py").resolve()),
            "--archiver", str(Path(archiver).resolve()), "--"]) + SHELL_FORWARD_ARGUMENTS)
        shim.chmod(0o700)
        environment["AR"] = str(shim)
        environment["ENVOY_EXT_PROC_COMMON_TEST"] = "0"
        go_shim = root / "go-tool"
        go_shim.write_text(SHELL_EXEC_PREFIX + shlex.join([
            sys.executable, str(Path(__file__).with_name("go-tool-capture.py").resolve())]) + SHELL_FORWARD_ARGUMENTS)
        go_shim.chmod(0o700)
    if target.startswith("envoy-"):
        module_cache = root / "go-module-cache" if go_module_cache is None else go_module_cache.resolve(strict=True)
        if (not module_cache.is_absolute() or module_cache.is_relative_to(checkout)
                or checkout.is_relative_to(module_cache)
                or re.fullmatch(r"[-A-Za-z0-9_./]+", str(module_cache)) is None):
            raise ValueError("explicit Go module cache must be a canonical external directory disjoint from checkout")
        work = root / "go-work"
        work.mkdir(mode=0o700)
        environment.update({"GOTOOLCHAIN": "local", "GOPROXY": "off",
                            "GOFLAGS": ("-mod=readonly -work -toolexec=" + str(go_shim)) if spec.get("cgo") else "-mod=readonly",
                            "GOCACHE": str(root / "go-cache"),
                            "GOMODCACHE": str(module_cache), "TMPDIR": str(work)})
        # The native producer also builds the independent Go response observer.
        # Its native subprocesses cannot enter the ext_authz selected graph.


def native_target_command(checkout, spec):
    """Prepare the selected native command before opening its build log."""
    command, sources = None, None
    if "make_target" in spec:
        command = ["make", "-C", str(checkout / "connectors/haproxy"),
                   "REPO_ROOT=" + str(checkout), "CFLAGS=-std=c17 -Wall -Wextra -Werror",
                   spec["make_target"]]
        sources = haproxy_sources(checkout)
    elif not any(spec.get(name) for name in ("split", "nginx", "lighttpd_patched", "haproxy_htx", "apache", "evaluator")):
        command = ["sh", str(checkout / spec["script"]), "build"]
        sources = sorted(str(path.relative_to(checkout))
                         for pattern in (COMMON_SOURCE_PATTERN, "common/runtime/*.c")
                         for path in checkout.glob(pattern)) + spec["sources"]
    return command, sources


def execute_native_target(checkout, root, sdk, spec, environment, cxx, host_archive, command, sources, log):
    """Run the selected producer and return its target-specific receipt data."""
    details = {}
    artifact = None
    if spec.get("evaluator"):
        sources, artifact, details["evaluator_receipt"] = build_targeted_evaluator(
            checkout, root, sdk, environment, cxx, log)
    elif spec.get("nginx"):
        sources, artifact, details["external_sources"], details["external_context"] = build_nginx(
            checkout, root, sdk, environment, host_archive, log)
    elif spec.get("lighttpd_patched"):
        sources, artifact, details["header_context"] = build_lighttpd_patched(
            checkout, root, environment, host_archive, log)
    elif spec.get("haproxy_htx"):
        sources, artifact, details["external_sources"], details["external_context"] = build_haproxy_htx(
            checkout, root, environment, host_archive, log)
    elif spec.get("apache"):
        sources, artifact, details["installed_context"] = build_apache(checkout, root, sdk, environment, log)
    elif spec.get("split"):
        sources, details["canonical_hash"] = build_lighttpd_split(checkout, root, sdk, environment, log)
    else:
        subprocess.run(command, cwd=checkout,
                       env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
    return sources, artifact, details


def add_native_target_context(contract, spec, details):
    """Attach native receipt data in the established contract field order."""
    if spec.get("evaluator"):
        contract["producer"].update(details["evaluator_receipt"])
    if spec.get("split"):
        contract["producer"]["canonical_artifact_sha256"] = details["canonical_hash"]
        contract["producer"]["split_command_mirror"] = True
    if spec.get("nginx") or spec.get("haproxy_htx"):
        contract["external_sources"] = details["external_sources"]
        contract["external_context"] = details["external_context"]
    if spec.get("lighttpd_patched"):
        contract["header_context"] = details["header_context"]
    if spec.get("apache"):
        contract["installed_context"] = details["installed_context"]
        contract["allow_gcc_internal_lto_context_limit"] = True


def build(checkout, root, sdk, target, cc, cxx, host_archive=None, go_module_cache=None,
          allowed_output_parent=None):
    checkout = checkout.resolve(strict=True)
    revision_before = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
    product_diff_before = subprocess.check_output(
        ["git", "-C", str(checkout), "diff", "HEAD", "--", "common", "connectors"])
    root = root.absolute()
    sdk = sdk.resolve(strict=True)
    verify_native_output_root(checkout, root, sdk, allowed_output_parent)
    spec, library = verify_native_build_inputs(checkout, sdk, target)
    root.mkdir(parents=True, mode=0o700)
    captures = root / "captures"
    captures.mkdir(mode=0o700)
    launcher = Path(__file__).with_name("capture.py").resolve()
    shims = {}
    for name, compiler in (("cc", cc), ("cxx", cxx)):
        executable = shutil.which(compiler)
        if executable is None:
            raise ValueError("required compiler is unavailable")
        shim = root / name
        command = [sys.executable, str(launcher), "--compiler", str(Path(executable).resolve()), "--"]
        shim.write_text(SHELL_EXEC_PREFIX + shlex.join(command) + SHELL_FORWARD_ARGUMENTS)
        shim.chmod(0o700)
        shims[name] = str(shim)
    environment = native_build_environment(checkout, root, sdk, captures, shims)
    configure_go_capture_environment(checkout, root, target, spec, environment, go_module_cache)
    command, sources = native_target_command(checkout, spec)
    with (root / "build.log").open("x") as log:
        sources, artifact, details = execute_native_target(
            checkout, root, sdk, spec, environment, cxx, host_archive, command, sources, log)
    if not any(spec.get(name) for name in ("nginx", "lighttpd_patched", "haproxy_htx", "apache", "evaluator")):
        artifact = root / "build" / spec["artifact"]
    if not artifact.is_file():
        raise ValueError("native script did not produce its declared target artifact")
    revision = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
    product_diff_after = subprocess.check_output(
        ["git", "-C", str(checkout), "diff", "HEAD", "--", "common", "connectors"])
    if revision != revision_before or product_diff_after != product_diff_before:
        raise ValueError("checkout revision or tracked product sources changed during native build")
    contract = {"target": target, "revision": revision, "artifact": str(artifact),
                "sources": sources, "external_inputs": {str(library.resolve()): digest(library)},
                "producer": {"script": spec["script"], "script_sha256": digest(checkout / spec["script"])},
                "compiler_environment": "implicit compiler/loader paths sanitized; source flags explicit in argv",
                "limitations": ["Dynamic library resolution is declared by SDK path; scanner readback is separate."]}
    add_native_target_context(contract, spec, details)
    if spec.get("cgo"):
        with (root / "build.log").open("a") as log:
            chain = finish_go_capture(checkout, root, artifact, environment, log)
        contract["go_producer_chain"] = chain
        contract["external_inputs"].update(chain["external_go_inputs"])
    (root / "contract.json").write_text(json.dumps(contract, indent=2) + "\n")
    return contract


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--sdk-prefix", required=True, type=Path)
    parser.add_argument("--target", required=True, choices=TARGETS)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--cxx", default="c++")
    parser.add_argument("--host-archive", type=Path)
    parser.add_argument("--go-module-cache", type=Path)
    parser.add_argument("--allowed-output-parent", type=Path,
                        help="caller-authorized external parent, e.g. GitHub runner.temp; defaults to local project storage")
    args = parser.parse_args()
    try:
        result = build(args.checkout, args.output_root, args.sdk_prefix, args.target, args.cc, args.cxx,
                       args.host_archive, args.go_module_cache, args.allowed_output_parent)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"native target build failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"target": result["target"], "artifact": result["artifact"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
