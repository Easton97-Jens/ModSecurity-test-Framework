#!/usr/bin/env python3
"""Produce genuine, revision-bound Parent coverage in a fresh external directory.

This is an explicitly on-demand Sonar assessment, not a hosted-runtime qualification or a
claim that every existing test executes. Test ownership and coverage are separate.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import ast
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import stat
import sys
import tempfile
import xml.etree.ElementTree as ET


ROOT = connector_root()
RCFILE = source_path('ci/sonar-coverage.ini', root=ROOT)
ACTIVE_INVENTORY_SOURCE = "ci/lib/active_test_inventory.py"
GO_PACKAGE_PATTERN = "./..."
# Explicit requirements: analysis scope, revision provenance, private artifacts,
# report input classification, and engine inventory. No discovery of unrelated
# runtime/I12 suites. Subprocess patching also measures invoked Parent writers.
PYTHON_TESTS = (
    "modsecurity_connector_tests.test_sonar_scope",
    "modsecurity_connector_tests.test_sonar_coverage",
    "modsecurity_connector_tests.test_sonar_native_context",
    "modsecurity_connector_tests.test_sonar_evidence_boundaries",
    "modsecurity_connector_tests.test_evidence_input_security",
    "modsecurity_connector_tests.test_framework_revision_pins.RevisionLockTests.test_offline_loader_requires_no_git_repository",
    "modsecurity_connector_tests.test_framework_revision_pins.RevisionLockTests.test_invalid_schema_and_revision_values_are_rejected",
    "modsecurity_connector_tests.test_runtime_artifact_utils.RuntimeArtifactUtilsTest.test_descriptor_backed_private_root_requires_existing_exact_root",
    "modsecurity_connector_tests.test_runtime_artifact_utils.RuntimeArtifactUtilsTest.test_descriptor_backed_private_root_rejects_links_hardlinks_and_unsafe_names",
    "modsecurity_connector_tests.test_runtime_artifact_utils.RuntimeArtifactUtilsTest.test_runtime_or_source_artifact_path_accepts_only_project_sources_or_private_files",
    "modsecurity_connector_tests.test_nginx_mrts_http500_cluster_analysis",
    "modsecurity_connector_tests.test_engine_lifecycle_artifacts.EngineLifecycleArtifactsTest.test_writes_payload_free_current_host_inventory",
    "modsecurity_connector_tests.test_engine_lifecycle_artifacts.EngineLifecycleArtifactsTest.test_rejects_payload_bearing_event_input",
)
# Named lifecycle and negative-boundary scenarios, across each module's relevant
# packages; -coverpkg=./... retains zeroes in unexecuted default-build packages.
GO_TESTS = {
    "envoy": ("connectors/envoy/ext_proc", (
        "TestClientFramesBoundedOrderedOperations",
        "TestProcessStreamsChunksAndCleansUpAtResponseEOS",
        "TestProcessRejectsExcessActiveStreamBeforeTransactionOpenAndReleasesSlot",
        "TestCheckForwards33ByteBodyWithoutConnectorPolicy",
        "TestCheckPreservesValidatedRedirect",
        "TestProcessMissingMetadataFailsClosed503",
        "TestJSONLObserverRejectsFinalSymlink",
        "TestPrivateEventLogRetainsValidatedParentDescriptor",
        "TestPrivateUDSAcceptsExpectedPeerCredentials",
        "TestOwnedListenerDoesNotRemoveReplacedSocket",
        "TestSourceOnlyBuildRefusesServingEngine",
        "TestCompositeObserverWritesOnlyBoundedLifecycleMetadata",
        "TestCheckConfigAdmissionRejectsUnprovenStrictPolicy",
    )),
    "traefik-native": ("connectors/traefik/native_middleware", (
        "TestMiddlewareForwardsRequestAuthorityAsHostHeader",
        "TestMiddlewareRejectsConflictingHostHeaderBeforeEngine",
        "TestMiddlewareStreamsRequestAndResponseInBoundedChunks",
        "TestMiddlewareFailsClosedAndClosesIdleRequestBody",
        "TestLateResponseDecisionDoesNotReplaceCommittedResponse",
        "TestUDSEngineUsesOneSessionForFullLifecycle",
        "TestUDSEngineCancellationClosesBlockedConnection",
        "TestUDSEngineAcknowledgesP1AndP2HostDenies",
    )),
    "traefik-composite": ("connectors/traefik/composite_middleware", (
        "TestStripInternalHeadersRemovesTrailerForms",
        "TestMiddlewareReplacesClientLeaseAndCompletesPrivateLifecycle",
        "TestReservationPayloadBindsActualRequestTransportMetadata",
        "TestResponseWriterRecordsDownstreamWriteFailures",
        "TestResponseWriterSuppressesRejectedResponseChunk",
        "TestResponseWriterForwardsAllowedResponseChunkAtSameBoundary",
        "TestMiddlewareReplacesPreCommitUDSFailureWith503",
        "TestNewRejectsUnsafeSocketPath",
    )),
    "traefik-observer": ("connectors/traefik/response_observer", (
        "TestResponseHeaderEncodingUsesLengthThenBytesOrder",
        "TestReadResultAcceptsCanonicalStatuslessSuccess",
        "TestMiddlewareStreamsHeaderOnlyResponseAndStripsHandle",
        "TestMiddlewareFailsClosedForRejectedReplay",
        "TestMiddlewareAppliesPrecommitBlockAndCancel",
        "TestMiddlewareSendsBoundedResponseBodyChunks",
        "TestConcurrentRequestsUseIndependentSessions",
        "TestReleaseFailureTriggersDeterministicCleanup",
    )),
}


def run(arguments: list[str], *, cwd: Path = ROOT, env: dict[str, str]) -> str:
    result = subprocess.run(arguments, cwd=cwd, env=env, check=True, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, end="", flush=True)
    return result.stdout


def validate_python_report(path: Path) -> int:
    """Require real repository-relative production paths and actual execution."""
    report = ET.parse(path)
    classes = report.findall(".//class")
    if not classes or not any(int(line.get("hits", "0")) > 0 for line in report.findall(".//line")):
        raise ValueError("Python coverage has no measured execution")
    for entry in classes:
        filename = Path(entry.attrib["filename"])
        if filename.is_absolute() or ".." in filename.parts or not (ROOT / filename).is_file():
            raise ValueError(f"Python coverage path is not a repository file: {filename}")
    return len(classes)


def publish_python_report(output: Path, env: dict[str, str]) -> dict[str, object]:
    """Merge real parallel runs, retaining the earlier selected-test data."""
    env["COVERAGE_FILE"] = str(output / "python.data")
    coverage = [sys.executable, "-m", "coverage"]
    run([*coverage, "combine", "--append", "--keep", f"--rcfile={RCFILE}"], env=env)
    report = output / "python.xml"
    run([*coverage, "xml", "--keep-combined", f"--rcfile={RCFILE}", "-o", str(report)], env=env)
    source_files = validate_python_report(report)
    # subprocess collection can add an empty Cobertura source element. Every
    # filename above was checked against the project root, so one explicit '.'
    # makes resolution unambiguous without changing any measured counters.
    tree = ET.parse(report)
    sources = tree.getroot().find("sources")
    if sources is None:
        raise ValueError("Python coverage has no source-root declaration")
    sources.clear()
    ET.SubElement(sources, "source").text = "."
    tree.write(report, encoding="utf-8", xml_declaration=True)
    return {"report": str(report), "source_files": source_files,
            "selectors": list(PYTHON_TESTS)}


def admitted_offline_inventory():
    """Use the existing Parent admission API; never discover extra tests."""
    name = "sonar_coverage_inventory"
    specification = importlib.util.spec_from_file_location(name, ROOT / ACTIVE_INVENTORY_SOURCE)
    if specification is None or specification.loader is None:
        raise ValueError("cannot load the authoritative Parent inventory admission")
    module = importlib.util.module_from_spec(specification)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        specification.loader.exec_module(module)
        inventory = module.load_inventory(ROOT)
        if not inventory.offline_case_ids:
            raise ValueError("coverage requires explicitly admitted offline Python cases")
        selected = module.select_executions(inventory, case_ids=inventory.offline_case_ids, on_demand=True)
        return inventory, selected
    finally:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous


def offline_partitions(selected: tuple[dict, ...]) -> tuple[tuple[dict, ...], tuple[dict, ...]]:
    """Retain timing assertions while measuring only the normal offline units."""
    measured, timing = [], []
    for execution in selected:
        if execution["selector"]["kind"] != "python" or "offline-unit" not in execution["groups"]:
            raise ValueError("coverage offline selection must contain admitted Python units only")
        destination = timing if "offline-timing" in execution["groups"] else measured
        destination.append(execution)
    return tuple(measured), tuple(timing)


def offline_command(selected: tuple[dict, ...], output: Path, env: dict[str, str],
                    *, measured: bool) -> tuple[list[str], dict[str, str]]:
    """Use the same exact inventory runner with isolated coverage startup."""
    if not selected:
        raise ValueError("offline coverage selection must not be empty")
    child_env = dict(env)
    child_env.pop("ON_DEMAND_TESTS", None)
    # coverage7.17's installed startup hook consults exactly these two values.
    # Measured CLI starts fresh from RCFILE; timing Python has neither startup.
    child_env.pop("COVERAGE_PROCESS_START", None)
    child_env.pop("COVERAGE_PROCESS_CONFIG", None)
    command = [sys.executable]
    if measured:
        command.extend(["-m", "coverage", "run", f"--rcfile={RCFILE}", "--parallel-mode"])
    else:
        child_env.pop("COVERAGE_FILE", None)
    command.extend(["ci/tools/run-active-tests.py", "--on-demand", "--strict-skips", "--output-root", str(output)])
    for execution in selected:
        command.extend(["--execution", execution["id"]])
    return command, child_env


def parallel_python_files(output: Path) -> set[Path]:
    return set(output.glob("python.data.*"))


def python_child_witness_line() -> int:
    """Locate an actual body statement that only the guarded child executes."""
    tree = ast.parse((ROOT / ACTIVE_INVENTORY_SOURCE).read_bytes())
    child = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name == "python_child")
    return next(node.lineno for node in child.body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == "summary" for target in node.targets))


def read_python_coverage_data(path: Path):
    from coverage import CoverageData

    data = CoverageData(basename=str(path))
    data.read()
    return data


def child_file_has_witness(path: Path, witness: int) -> bool:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Python coverage input must be a regular parallel data file")
    data = read_python_coverage_data(path)
    if not data.has_arcs():
        raise ValueError("offline subprocess coverage must retain branch observations")
    for filename in data.measured_files():
        source = Path(filename)
        if source.is_absolute():
            source = source.relative_to(ROOT)
        if source.as_posix() == ACTIVE_INVENTORY_SOURCE:
            return witness in (data.lines(filename) or [])
    return False


def child_coverage_witnesses(files: set[Path], expected: int) -> list[str]:
    """Require actual branch data in distinct child files, not parent imports."""
    witness = python_child_witness_line()
    children = [path.name for path in sorted(files) if child_file_has_witness(path, witness)]
    if len(children) != expected:
        raise ValueError(f"offline subprocess coverage has {len(children)} measured children; expected {expected}")
    return children



def retain_child_coverage(output: Path, names: list[str]) -> list[dict[str, object]]:
    """Keep exact verified raw bytes outside coverage's automatic combine glob."""
    retained = output / "child-witness"
    retained.mkdir(mode=0o700)
    records = []
    for name in names:
        if re.fullmatch(r"python\.data\.[A-Za-z0-9_.-]+", name, flags=re.ASCII) is None:
            raise ValueError("invalid child coverage data basename")
        records.append(retain_child_file(output / name, retained / name))
    return records


def retain_child_file(source: Path, destination: Path) -> dict[str, object]:
    """Read a non-link owned file and create an exclusive private byte copy."""
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as incoming:
        before = os.fstat(incoming.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.geteuid():
            raise ValueError("child coverage data must be an owned single-link regular file")
        digest = hashlib.sha256()
        size = 0
        target = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(target, "wb") as outgoing:
            while chunk := incoming.read(1024 * 1024):
                outgoing.write(chunk)
                digest.update(chunk)
                size += len(chunk)
            outgoing.flush()
            os.fsync(outgoing.fileno())
        after = os.fstat(incoming.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns) or size != before.st_size:
            destination.unlink()
            raise ValueError("child coverage data changed during retention")
    return {"path": f"child-witness/{destination.name}", "sha256": digest.hexdigest(), "size_bytes": size}


def run_offline_partition(inventory, selected: tuple[dict, ...], output: Path,
                          env: dict[str, str], *, measured: bool) -> dict:
    """Run admitted IDs and verify their real terminal inventory summary."""
    output.mkdir(mode=0o700)
    command, child_env = offline_command(selected, output, env, measured=measured)
    run(command, env=child_env)
    summaries = list(output.glob("active-tests-*/summary.json"))
    if len(summaries) != 1:
        raise ValueError("offline assessment requires one actual runner summary")
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    expected_ids = [item["id"] for item in selected]
    expected_cases = [case["id"] for item in selected for case in item["cases"]]
    if (summary.get("inventory_sha256") != inventory.digest
            or summary.get("selected_execution_ids") != expected_ids
            or summary.get("selected_case_ids") != expected_cases
            or summary.get("selected_core_case_ids")):
        raise ValueError("offline assessment summary differs from the admitted Python exceptions")
    results = summary.get("results", [])
    if [item.get("execution_id") for item in results] != expected_ids:
        raise ValueError("offline assessment lost an admitted execution result")
    if any(item.get("status") != "passed" for item in results):
        raise ValueError("offline assessment contains a blocked or failed case")
    return {"summary": str(summaries[0]), "execution_ids": expected_ids, "case_ids": expected_cases}


def offline_python_coverage(output: Path, env: dict[str, str]) -> dict:
    """Run the retained specialist assessment with its admitted on-demand IDs."""
    inventory, selected = admitted_offline_inventory()
    measured, timing = offline_partitions(selected)
    result = {"inventory_sha256": inventory.digest, "measured": None, "unmeasured_timing": None}
    if measured:
        before = parallel_python_files(output)
        result["measured"] = run_offline_partition(
            inventory, measured, output / "offline-measured", env, measured=True)
        files = parallel_python_files(output) - before
        names = child_coverage_witnesses(files, len(measured))
        artifacts = retain_child_coverage(output, names)
        retained_files = {output / item["path"] for item in artifacts}
        child_coverage_witnesses(retained_files, len(measured))
        result["child_data_files"] = [item["path"] for item in artifacts]
        result["child_data_artifacts"] = artifacts
        result["new_parallel_data_files"] = len(files)
    if timing:
        before = parallel_python_files(output)
        result["unmeasured_timing"] = run_offline_partition(
            inventory, timing, output / "offline-timing", env, measured=False)
        if parallel_python_files(output) != before:
            raise ValueError("offline timing cases unexpectedly produced coverage data")
    return result


def python_coverage(output: Path, env: dict[str, str]) -> dict[str, object]:
    env["COVERAGE_FILE"] = str(output / "python.data")
    coverage = [sys.executable, "-m", "coverage"]
    run([*coverage, "run", f"--rcfile={RCFILE}", "--parallel-mode",
         "ci/checks/analysis/check-sonar-scope.py"], env=env)
    # The caller explicitly opted into this specialist assessment. Scope its
    # module-discovery opt-in to this unittest child only;
    # the scope CLI, report writers and other producers retain the original env.
    test_env = dict(env, ON_DEMAND_TESTS="1")
    run([*coverage, "run", f"--rcfile={RCFILE}", "--parallel-mode", "-m",
         "unittest", "-v", *PYTHON_TESTS], env=test_env)
    offline = offline_python_coverage(output, env)
    result = publish_python_report(output, env)
    result["offline_python"] = offline
    return result


def finalize_python(output_root: Path, env: dict[str, str], revision: str,
                    *, allow_dirty: bool = False) -> dict[str, object]:
    """Only combine CLI-integration coverage from the same completed revision."""
    offline = None
    for language in ("python", "go", "native"):
        manifest = json.loads((output_root / language / "manifest.json").read_text(encoding="utf-8"))
        if manifest.get("revision") != revision:
            raise ValueError(f"{language} coverage revision does not match the checkout")
        if manifest.get("uncommitted_changes") and not allow_dirty:
            raise ValueError(f"{language} coverage was produced from uncommitted changes")
        if language == "python":
            offline = manifest.get("coverage", {}).get("offline_python")
    result = publish_python_report(output_root / "python", env)
    if offline is not None:
        result["offline_python"] = offline
    return result


def go_coverage(output: Path, env: dict[str, str]) -> dict[str, object]:
    env.update(GOTOOLCHAIN="local", GOWORK="off", GOCACHE=str(output / "build-cache"),
               GOMODCACHE=str(output / "module-cache"))
    reports = {}
    for name, (relative, names) in GO_TESTS.items():
        module = ROOT / relative
        pattern = "^(" + "|".join(re.escape(name) for name in names) + ")$"
        listing = run(["go", "test", "-mod=readonly", "-list", pattern, GO_PACKAGE_PATTERN], cwd=module, env=env)
        missing = set(names) - set(listing.splitlines())
        if missing:
            raise ValueError(f"selected Go tests are missing in {relative}: {sorted(missing)}")
        report = output / f"{name}.out"
        run(["go", "test", "-mod=readonly", "-count=1", "-timeout=120s", "-run", pattern,
             f"-coverpkg={GO_PACKAGE_PATTERN}", f"-coverprofile={report}", GO_PACKAGE_PATTERN], cwd=module, env=env)
        if len(report.read_text(encoding="utf-8").splitlines()) < 2:
            raise ValueError(f"Go coverage is empty: {relative}")
        run(["go", "tool", "cover", f"-func={report}"], cwd=module, env=env)
        reports[name] = {"report": str(report), "selectors": list(names), "packages": GO_PACKAGE_PATTERN}
    return reports


def native_coverage(output: Path, env: dict[str, str]) -> dict[str, object]:
    build = output / "build"
    env.update(BUILD_ROOT=str(build), VERIFIED_RUN_ROOT=str(output / "runtime"),
               MSCONNECTOR_CFLAGS="-std=c17 -Wall -Wextra -Werror --coverage -O0")
    run(["sh", "ci/checks/common/check-common-helpers.sh"], env=env)
    gcov = output / "gcov"
    gcov.mkdir()
    objects = sorted((build / "common-helper-smoke").glob("*.gcda"))
    if not objects:
        raise ValueError("native tests produced no execution counters (.gcda)")
    sources = set()
    reports = 0
    for index, counters in enumerate(objects):
        work = output / "gcov-work" / str(index)
        work.mkdir(parents=True)
        run(["gcov", "--hash-filenames", "--preserve-paths", "--branch-probabilities",
             "--branch-counts", str(counters)], cwd=work, env=env)
        for report in work.glob("*.gcov"):
            first = report.read_text(encoding="utf-8").splitlines()[0]
            source = Path(first.split("Source:", 1)[1])
            if not source.is_absolute():
                source = ROOT / source
            source = source.resolve(strict=True)
            if source.is_relative_to(ROOT):
                if not source.is_file():
                    raise ValueError(f"native coverage source is missing: {source}")
                sources.add(source.relative_to(ROOT).as_posix())
                # Unique object prefix preserves every binary's real report,
                # including overlapping source coverage; no output overwrite.
                report.rename(gcov / f"{index}-{report.name}")
                reports += 1
    expected = {path.relative_to(ROOT).as_posix() for path in (source_path('common/src', root=ROOT)).glob("*.c")}
    if not expected.issubset(sources):
        raise ValueError(f"native coverage lost Common sources: {sorted(expected - sources)}")
    return {"reports_path": str(gcov), "reports": reports, "source_paths": sorted(sources),
            "limitation": "Common helper/constructor/intervention tests; no connector-host coverage"}


def measure_coverage(language: str, output_root: Path, output: Path,
                     env: dict[str, str], revision: str, *,
                     allow_dirty: bool) -> tuple[dict[str, object], Path]:
    if language == "finalize-python":
        return finalize_python(output_root, env, revision, allow_dirty=allow_dirty), output_root / "python"
    producer = {"python": python_coverage, "go": go_coverage, "native": native_coverage}[language]
    return producer(output, env), output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", choices=("python", "go", "native", "finalize-python"), required=True)
    parser.add_argument("--output-root", type=Path, required=True,
                        help="external task-owned root; each language subdirectory must be fresh")
    parser.add_argument("--temp-root", type=Path, required=True,
                        help="external temporary parent with a short path for Unix sockets")
    parser.add_argument("--allow-dirty", action="store_true",
                        help="local development only; mark reports as uncommitted evidence")
    parser.add_argument("--on-demand", action="store_true",
                        help="explicitly run this specialist coverage assessment outside the default suite")
    args = parser.parse_args()
    try:
        if not args.on_demand:
            raise ValueError("specialist coverage requires explicit --on-demand; automatic CI uses the default inventory")
        if not args.output_root.is_absolute():
            raise ValueError("output root must be absolute")
        output_root = args.output_root.resolve()
        if output_root == ROOT or output_root.is_relative_to(ROOT):
            raise ValueError("coverage output must be outside the checkout")
        output = output_root / args.language
        if args.language != "finalize-python":
            output.mkdir(parents=True, exist_ok=False)
        temp_root = args.temp_root.resolve()
        if not args.temp_root.is_absolute() or temp_root == ROOT or temp_root.is_relative_to(ROOT):
            raise ValueError("temporary root must be absolute and outside the checkout")
        temp_root.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ)
        env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1")
        revision = run(["git", "rev-parse", "HEAD"], env=env).strip()
        status = run(["git", "status", "--porcelain", "--untracked-files=normal"], env=env)
        if status and not args.allow_dirty:
            raise ValueError("clean checkout required for revision-bound reports; use --allow-dirty only for local development")
        result = {"revision": revision, "uncommitted_changes": bool(status), "language": args.language,
                  "evidence_layer": "selected real test coverage; runtime and analyzer import not implied"}
        with tempfile.TemporaryDirectory(prefix="scov-", dir=temp_root) as temporary:
            env["TMPDIR"] = temporary
            result["coverage"], output = measure_coverage(
                args.language, output_root, output, env, revision, allow_dirty=args.allow_dirty)
        if run(["git", "rev-parse", "HEAD"], env=env).strip() != revision:
            raise ValueError("checkout revision changed while tests ran")
        if run(["git", "status", "--porcelain", "--untracked-files=normal"], env=env) != status:
            raise ValueError("checkout files changed while tests ran")
        (output / "manifest.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError, ET.ParseError, subprocess.CalledProcessError) as exc:
        if isinstance(exc, subprocess.CalledProcessError):
            print(exc.stdout or "", file=sys.stderr, end="")
        print(f"Sonar coverage failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
