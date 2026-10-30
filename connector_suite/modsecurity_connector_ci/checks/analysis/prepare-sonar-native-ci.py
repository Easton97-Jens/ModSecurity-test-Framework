#!/usr/bin/env python3
"""Orchestrate canonical SDK transfer and separate Hosted native Sonar analyses.

This entry point builds and captures code. It never runs product tests, starts
connector runtimes, invokes a scanner, or accesses provider credentials.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, source_path, load_tool, load_source

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request


from modsecurity_test_framework.product_sources.ci.lib.framework_revision_pins import (
    FRAMEWORK_PATH, load_framework_revision_pins,
)


ROOT = connector_root()


verify_trusted_directory = load_tool('ci/checks/analysis/sonar-native-security/source_mapping.py').verify_trusted_directory

TARGETS = (
    "traefik-engine-service", "haproxy-spoa-runtime",
    "apache-native-module", "haproxy-htx", "envoy-ext-proc", "envoy-composite",
    "lighttpd-patched-module", "nginx-dynamic-module", "lighttpd-stock-sidecar",
    "envoy-ext-authz", "traefik-forwardauth",
    "common-targeted-evaluator",
)
NATIVE_STORAGE_ROOT = Path("/var/tmp/codex/ModSecurity-conector")
PROJECT_PREFIX = "Easton97-Jens_ModSecurity-conector_native_"
PROJECT_BASE_DIR = "sonar.projectBaseDir"
HEX40 = re.compile(r"[0-9a-f]{40}")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def run(arguments: list[str], **kwargs) -> None:
    subprocess.run(arguments, cwd=ROOT, check=True, **kwargs)


def check_revision(revision: str) -> None:
    if HEX40.fullmatch(revision) is None:
        raise ValueError("expected an exact hexadecimal SCM revision")
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if actual != revision or subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT
    ):
        raise ValueError("native CI requires a clean checkout at the exact analyzed revision")


def external_root(root: Path) -> Path:
    approved = NATIVE_STORAGE_ROOT
    if (not root.is_absolute() or root.resolve() != root or root == approved
            or not root.is_relative_to(approved) or root.is_relative_to(ROOT)
            or ROOT.is_relative_to(root)):
        raise ValueError("native CI root must be a canonical private external project child")
    ancestor = root
    while not ancestor.exists():
        ancestor = ancestor.parent
    verify_trusted_directory(ancestor)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    verify_trusted_directory(root)
    if root.stat().st_uid != os.getuid():
        raise ValueError("native CI output must be owned by the current user")
    root.chmod(0o700)
    return root


def framework_contract() -> dict[str, str]:
    """Initialize only the exact direct Framework, never its MRTS submodule."""
    pins = load_framework_revision_pins(ROOT)
    expected = str(pins["framework_sha"])
    recorded = subprocess.check_output(["git", "ls-tree", "HEAD", "--", FRAMEWORK_PATH], cwd=ROOT)
    if recorded != f"160000 commit {expected}\t{FRAMEWORK_PATH}\n".encode():
        raise ValueError("Framework gitlink differs from the canonical revision lock")
    run(["git", "-c", "protocol.file.allow=never", "submodule", "update", "--init", "--", FRAMEWORK_PATH])
    framework = ROOT / FRAMEWORK_PATH
    actual = subprocess.check_output(["git", "-C", str(framework), "rev-parse", "HEAD"], text=True).strip()
    if actual != expected:
        raise ValueError("Framework checkout differs from its exact recorded commit")
    module = load_source(source_path('ci/checks/analysis/prepare-sonar-native-context.py', root=ROOT))
    return {**module.modsecurity_contract((framework / "ci/lib/common.sh").read_bytes()),
            "framework_sha": expected}


def sdk_environment(root: Path) -> dict[str, str]:
    base = root / "sdk"
    return dict(os.environ, VERIFIED_RUN_ROOT=str(base), BUILD_ROOT=str(base / "build"),
                SOURCE_ROOT=str(base / "src"), TMP_ROOT=str(base / "tmp"),
                LOG_ROOT=str(base / "logs"), CACHE_ROOT=str(base / "cache-v2"),
                CONNECTOR_COMPONENT_CACHE=str(base / "cache-v2/shared"),
                RUNTIME_REPORT_OUTPUT_ROOT=str(base / "reports"),
                RUNTIME_COMPONENT_TARGET="shared", ALLOW_RUNTIME_DOWNLOADS="1",
                ALLOW_RUNTIME_BUILDS="1", PYTHON=sys.executable,
                PYTHONDONTWRITEBYTECODE="1", TMPDIR=str(base / "tmp"))


def prepare_sdk(root: Path, transfer: Path, revision: str) -> None:
    check_revision(revision)
    root = external_root(root)
    framework_contract()
    run([sys.executable, "ci/tools/install-ci-dependencies.py", "--ci-toolcache",
         "--framework-lock", FRAMEWORK_PATH + "/requirements-ci.lock"])
    environment = sdk_environment(root)
    Path(environment["TMP_ROOT"]).mkdir(parents=True, mode=0o700)
    run(["sh", "ci/provisioning/cache/with-runtime-components.sh", sys.executable,
         str(Path(__file__).resolve()), "pack-sdk", "--root", str(root),
         "--transfer", str(transfer), "--revision", revision], env=environment)


def pack_sdk(root: Path, transfer: Path, revision: str) -> None:
    check_revision(revision)
    contract = framework_contract()
    if (os.environ.get("MODSECURITY_SOURCE_SHA") != contract["commit"]
            or os.environ.get("MODSECURITY_SOURCE_URL") != contract["source_url"]):
        raise ValueError("prepared SDK does not match the canonical Framework source identity")
    prefix = Path(os.environ["MODSECURITY_PREFIX"]).resolve(strict=True)
    prefixes = root / "sdk/cache-v2/shared/prefix"
    if not prefix.is_relative_to(prefixes / "modsecurity"):
        raise ValueError("prepared SDK prefix escapes the canonical shared cache")
    library = prefix / "lib/libmodsecurity.so"
    if not library.is_file() or not (prefix / "include/modsecurity/modsecurity.h").is_file():
        raise ValueError("prepared SDK is missing its real development inputs")
    provenance_path = root / "sdk/cache-v2/shared/builds/modsecurity" / prefix.name / "manifest.json"
    provenance = json.loads(provenance_path.read_text())
    if (provenance["status"] != "complete"
            or provenance["actual_sha"] != contract["commit"]
            or provenance["build_id"] != prefix.name or provenance["prefix"] != str(prefix)):
        raise ValueError("canonical SDK build provenance disagrees with its actual prefix/source")
    # Prefix siblings include the canonical Expat dependency. Preserve their
    # relative symlinks and absolute prefix locations across same-run jobs.
    transfer.mkdir(parents=True, exist_ok=False, mode=0o700)
    bundle = transfer / "sdk.tar.gz"
    with tarfile.open(bundle, "w:gz", dereference=False) as archive:
        archive.add(prefixes, arcname=str(prefixes.relative_to(root)))
    metadata = {"schema": 1, "revision": revision, "source": contract,
                "prefix": str(prefix), "bundle_sha256": digest(bundle),
                "library_sha256": digest(library), "provenance": {
                    name: provenance[name] for name in (
                        "actual_sha", "build_id", "dependency_hash", "patchset_sha256",
                        "compiler", "target_architecture", "cache_identity", "provenance_verification")}}
    (transfer / "sdk-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")


def sdk_prefix_filter(root: Path, expected: Path, member: tarfile.TarInfo, destination: str):
    path = Path(member.name)
    if (path.is_absolute() or ".." in path.parts
            or not (root / path).resolve().is_relative_to(expected)):
        raise ValueError("SDK transfer member escapes its fixed prefix subtree")
    if member.issym() or member.islnk():
        linked = ((root / path).parent / member.linkname if member.issym()
                  else root / member.linkname).resolve()
        if not linked.is_relative_to(expected):
            raise ValueError("SDK transfer link escapes its fixed prefix subtree")
    return tarfile.data_filter(member, destination)


def restore_sdk(root: Path, transfer: Path, revision: str) -> Path:
    metadata = json.loads((transfer / "sdk-metadata.json").read_text())
    if (set(metadata) != {"schema", "revision", "source", "prefix", "bundle_sha256", "library_sha256", "provenance"}
            or metadata["schema"] != 1 or metadata["revision"] != revision
            or metadata["source"] != framework_contract()):
        raise ValueError("SDK transfer does not belong to this exact revision/source contract")
    bundle = transfer / "sdk.tar.gz"
    if digest(bundle) != metadata["bundle_sha256"]:
        raise ValueError("SDK transfer archive digest mismatch")
    prefix = Path(metadata["prefix"])
    expected = root / "sdk/cache-v2/shared/prefix"
    if prefix.resolve() != prefix or not prefix.is_relative_to(expected / "modsecurity") or expected.exists():
        raise ValueError("SDK transfer requires a fresh matching external prefix destination")
    if (metadata["provenance"]["actual_sha"] != metadata["source"]["commit"]
            or metadata["provenance"]["build_id"] != prefix.name):
        raise ValueError("SDK transfer build provenance disagrees with its source/prefix")
    with tarfile.open(bundle) as archive:
        archive.extractall(root, filter=lambda member, destination:
                           sdk_prefix_filter(root, expected, member, destination))
    library = prefix / "lib/libmodsecurity.so"
    if digest(library) != metadata["library_sha256"]:
        raise ValueError("restored SDK library digest mismatch")
    return prefix


def host_archive(target: str, destination: Path) -> Path | None:
    if target == "nginx-dynamic-module":
        source = source_path('ci/provisioning/components/prepare-runtime-components.py', root=ROOT)
        names = {"NGINX_PINNED_RELEASE_ASSET_NAME", "NGINX_PINNED_RELEASE_ASSET_SHA256",
                 "NGINX_PINNED_SOURCE_REPOSITORY", "NGINX_PINNED_RELEASE_TAG"}
        values = {node.targets[0].id: ast.literal_eval(node.value)
                  for node in ast.parse(source.read_text()).body
                  if isinstance(node, ast.Assign) and len(node.targets) == 1
                  and isinstance(node.targets[0], ast.Name) and node.targets[0].id in names}
        name = values["NGINX_PINNED_RELEASE_ASSET_NAME"]
        url = (values["NGINX_PINNED_SOURCE_REPOSITORY"] + "/releases/download/"
               + values["NGINX_PINNED_RELEASE_TAG"] + "/" + name)
        expected = values["NGINX_PINNED_RELEASE_ASSET_SHA256"]
    elif target == "haproxy-htx":
        pin = json.loads((source_path('connectors/haproxy/htx-overlay/version-contract.json', root=ROOT)).read_text())
        name, url, expected = "haproxy-" + pin["version"] + ".tar.gz", pin["source_url"], pin["sha256"]
    elif target == "lighttpd-patched-module":
        pin = {key: value
               for line in (source_path('connectors/lighttpd/lighttpd-version.contract', root=ROOT)).read_text().splitlines()
               if line and not line.startswith("#") for key, value in [line.split("=", 1)]}
        name = "lighttpd-" + pin["LIGHTTPD_VERSION"] + ".tar.xz"
        url, expected = pin["LIGHTTPD_DOWNLOAD_URL"], pin["LIGHTTPD_SHA256"]
    else:
        return None
    if (not url.startswith("https://") or Path(name).name != name
            or re.fullmatch(r"[0-9a-f]{64}", expected) is None):
        raise ValueError("native host archive requires its canonical HTTPS identity and digest")
    destination.mkdir(mode=0o700)
    archive = destination / name
    with urllib.request.urlopen(url, timeout=120) as response, archive.open("xb") as stream:
        if not response.geturl().startswith("https://"):
            raise ValueError("native host archive redirected away from HTTPS")
        shutil.copyfileobj(response, stream)
    if digest(archive) != expected:
        raise ValueError("native host archive digest differs from its current canonical contract")
    return archive


def prepare_go(root: Path) -> Path:
    cache = root / "go-modules"
    cache.mkdir(mode=0o700)
    env = dict(os.environ, GOTOOLCHAIN="local", GOWORK="off", GOFLAGS="-mod=readonly",
               GOMODCACHE=str(cache), GOCACHE=str(root / "go-download-cache"),
               GOPROXY="https://proxy.golang.org", GOSUMDB="sum.golang.org")
    for module in ("connectors/envoy/ext_proc",):
        directory = ROOT / module
        if not directory.is_dir():
            raise ValueError("native producer Go module is missing")
        before = {name: digest(directory / name) for name in ("go.mod", "go.sum")}
        subprocess.run(["go", "mod", "download"], cwd=directory, env=env, check=True)
        subprocess.run(["go", "mod", "verify"], cwd=directory, env=env, check=True)
        if before != {name: digest(directory / name) for name in before}:
            raise ValueError("Go module download changed its pinned source manifests")
    return cache


def ctu_limits(units: int, disk_bytes: int, memory_kib: int, cpus: int) -> tuple[int, int]:
    if type(units) is not int or units <= 0:
        raise ValueError("CTU resources require a positive compiled translation-unit count")
    quota = max(1024, units * 40)
    if disk_bytes < (quota + 2048) * 1024 * 1024:
        raise ValueError("insufficient free space for full CTU context")
    if memory_kib < 6 * 1024 * 1024:
        raise ValueError("native CTU analysis requires at least 6 GiB of host memory")
    threads = min(cpus or 1, max(1, (memory_kib // (1024 * 1024) - 2) // 4), 2)
    return threads, quota


def write_settings(manifest: dict, root: Path, target: str, revision: str) -> None:
    scope = manifest["scanner_scope"]
    if (set(scope) != {PROJECT_BASE_DIR, "sonar.sources", "sonar.cfamily.compile-commands",
                       "sonar.coverage.exclusions", "sonar.scm.revision"}
            or scope["sonar.coverage.exclusions"] != "**" or target not in TARGETS
            or manifest["target"] != target or manifest["revision"] != revision
            or manifest["import_eligible"] is not True or manifest["development_only"] is not False
            or scope["sonar.scm.revision"] != revision or scope[PROJECT_BASE_DIR] != str(ROOT)
            or set(scope["sonar.sources"].split(",")) != {
                str(Path(path).relative_to(ROOT)) for path in manifest["scanner_expected_parent_input_paths"]}):
        raise ValueError("scanner scope is not the exact eligible Parent target closure")
    memory_kib = int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines()
                          if line.startswith("MemTotal:")))
    threads, quota = ctu_limits(manifest["translation_units"], shutil.disk_usage(root).free,
                               memory_kib, os.cpu_count() or 1)
    # project.settings and sonar.projectBaseDir are incompatible CLI options.
    # The fixed scanner step runs at the verified checkout root; retain only
    # its validated relative source list and absolute compiler-context path.
    settings = {**{name: value for name, value in scope.items() if name != PROJECT_BASE_DIR},
                "sonar.projectKey": PROJECT_PREFIX + target.replace("-", "_"),
                "sonar.organization": "easton97-jens", "sonar.host.url": "https://sonarcloud.io",
                "sonar.sourceEncoding": "UTF-8", "sonar.scm.exclusions.disabled": "true",
                "sonar.scanner.autoconfig.enabled": "false", "sonar.qualitygate.wait": "true",
                "sonar.qualitygate.timeout": "600", "sonar.cfamily.taintAnalysis": "true",
                "sonar.cfamily.taintAnalysis.timeout": "0",
                "sonar.cfamily.ctuAnalysis.branchSubstring": "all branches",
                "sonar.cfamily.ctuAnalysis.diskQuotaMb": str(quota),
                "sonar.cfamily.analysisCache.mode": "fs",
                "sonar.cfamily.analysisCache.path": str(root / "ctu-cache"),
                "sonar.cfamily.threads": str(threads), "sonar.cfamily.memoryPressureBoundPct": "95",
                "sonar.working.directory": str(root / "scanner-work")}
    if os.environ.get("GITHUB_EVENT_NAME") == "pull_request":
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        pr = event["pull_request"]
        repository = "Easton97-Jens/ModSecurity-conector"
        if (pr["head"]["sha"] != revision or pr["head"]["repo"]["full_name"] != repository
                or pr["base"]["repo"]["full_name"] != repository
                or type(event["number"]) is not int or event["number"] <= 0):
            raise ValueError("PR analysis context does not match the exact same-repository revision")
        settings.update({"sonar.pullrequest.key": str(event["number"]),
                         "sonar.pullrequest.branch": pr["head"]["ref"],
                         "sonar.pullrequest.base": pr["base"]["ref"]})
    if any(any(character in str(value) for character in "\n\r\0") for value in settings.values()):
        raise ValueError("scanner settings contain an ambiguous property value")
    (root / "native.properties").write_text("".join(f"{name}={value}\n" for name, value in settings.items()))


def analyze(root: Path, transfer: Path, revision: str, target: str) -> None:
    check_revision(revision)
    root = external_root(root)
    sdk = restore_sdk(root, transfer, revision)
    archive = host_archive(target, root / "host-archives")
    go_cache = prepare_go(root) if target.startswith("envoy-") else None
    producer = source_path('ci/checks/analysis/sonar-native-security', root=ROOT)
    command = [sys.executable, str(producer / "build-target.py"), "--checkout", str(ROOT),
               "--output-root", str(root / "capture"), "--sdk-prefix", str(sdk), "--target", target]
    if archive:
        command += ["--host-archive", str(archive)]
    if go_cache:
        command += ["--go-module-cache", str(go_cache)]
    run(command)
    run([sys.executable, str(producer / "validate.py"), "--checkout", str(ROOT),
         "--capture-root", str(root / "capture/captures"), "--contract", str(root / "capture/contract.json"),
         "--output", str(root / "validated")])
    manifest = json.loads((root / "validated/manifest.json").read_text())
    write_settings(manifest, root, target, revision)
    check_revision(revision)


def report(root: Path, revision: str, target: str) -> None:
    lines = [f"Native security target: {target}", f"Revision: {revision}",
             f"Project: {PROJECT_PREFIX + target.replace('-', '_')}"]
    path = root / "scanner-work/report-task.txt"
    if path.is_file() and not path.is_symlink():
        lines += [line for line in path.read_text().splitlines()
                  if line.startswith(("ceTaskId=", "dashboardUrl=", "projectKey="))]
    else:
        lines.append("No server task published; no completed analysis or Quality Gate is asserted.")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a") as stream:
            stream.write("\n".join(lines) + "\n")
    print("\n".join(lines))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("sdk", "pack-sdk", "analyze", "report"))
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--transfer", type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--target", choices=TARGETS)
    args = parser.parse_args()
    if args.mode in {"sdk", "pack-sdk", "analyze"} and args.transfer is None:
        parser.error("--transfer is required")
    if args.mode in {"analyze", "report"} and args.target is None:
        parser.error("--target is required")
    try:
        if args.mode == "sdk":
            prepare_sdk(args.root, args.transfer, args.revision)
        elif args.mode == "pack-sdk":
            pack_sdk(args.root, args.transfer, args.revision)
        elif args.mode == "analyze":
            analyze(args.root, args.transfer, args.revision, args.target)
        else:
            report(args.root, args.revision, args.target)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"native CI preparation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
