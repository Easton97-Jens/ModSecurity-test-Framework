#!/bin/sh
set -eu

: "${TEST_ROOT:?TEST_ROOT must identify the pinned Framework checkout}"
. "$TEST_ROOT/ci/lib/path-bootstrap.sh"

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)

# Bridge only this native two-request run to the existing legacy evidence writer.
# Build/provisioning and the actual built connector host path remain separate.
exec "${PYTHON:-python3}" -P - "$SCRIPT_DIR" "$@" <<'PY_LEGACY_ENVOY'
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time

SCRIPT_DIR = Path(sys.argv[1])
from modsecurity_test_framework.connector_context import connector_root, source_path, load_tool
ROOT = connector_root()
writer = load_tool("common/scripts/write_smoke_result.py")
from modsecurity_connector_ci.lib.runtime_path_utils import runtime_artifact_path, verified_runtime_artifact_root, verified_runtime_paths

MAX_BYTES = 131072
EXPECTED_RULE = "1000001"


def private_bytes(root, path, since=0):
    path = runtime_artifact_path(root, path, "native legacy evidence")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_BYTES
                or (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) != (os.geteuid(), os.getegid(), 0o600)
                or before.st_mtime_ns < since):
            raise ValueError("native legacy evidence is not a current private bounded regular file")
        body = stream.read(MAX_BYTES + 1)
        after = os.fstat(stream.fileno())
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(body) > MAX_BYTES or any(getattr(before, key) != getattr(after, key) for key in fields):
            raise ValueError("native legacy evidence changed during reading")
    return body


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("native legacy evidence has duplicate keys")
        result[key] = value
    return result


def native_summary(runtime, since):
    pairs = []
    for line in private_bytes(runtime, runtime / "runtime-summary.txt", since).decode().splitlines():
        key, separator, value = line.partition("=")
        if not separator:
            raise ValueError("native summary has an invalid line")
        pairs.append((key, value))
    summary = unique_keys(pairs)
    expected = {"status": "PASS", "integration_mode": "ext_authz", "allowed_request_status": "200",
                "blocked_request_status": "403", "rule_id": EXPECTED_RULE, "event_log": str(runtime / "events.jsonl"),
                "processes_stopped": "yes", "response_body_verified": "false", "production_ready": "false",
                "response_phase_smoke": "0", "terminal_authz_marker_stripped": "yes", "response_observer_started": "yes"}
    if any(summary.get(key) != value for key, value in expected.items()):
        raise ValueError("native summary does not prove the closed two-request legacy run")


def client_observation(runtime, filename, expected_status, since):
    probe = json.loads(private_bytes(runtime, runtime / filename, since), object_pairs_hook=unique_keys)
    fields = {"schema_version", "evidence_type", "http_status", "response_bytes", "body_payload_persisted",
              "redirect_location_verified", "composite_lease_header_present"}
    if not isinstance(probe, dict) or set(probe) != fields:
        raise ValueError("native client observation has an unexpected schema")
    if (type(probe["schema_version"]) is not int or probe["schema_version"] != 1
            or probe["evidence_type"] != "envoy_http_client_probe" or type(probe["http_status"]) is not int
            or probe["http_status"] != expected_status
            or type(probe["response_bytes"]) is not int or probe["response_bytes"] < 0
            or probe["body_payload_persisted"] is not False or probe["redirect_location_verified"] is not False
            or probe["composite_lease_header_present"] is not False):
        raise ValueError("native client observation does not prove the expected payload-free response")


def native_block_event(runtime, since):
    rows = [json.loads(line, object_pairs_hook=unique_keys)
            for line in private_bytes(runtime, runtime / "events.jsonl", since).splitlines() if line.strip()]
    if not rows or any(not isinstance(row, dict) for row in rows):
        raise ValueError("native event log has no valid records")
    expected = {"connector": "envoy", "integration_mode": "ext_authz", "transaction_id": "envoy-block-1",
                "rule_id": EXPECTED_RULE, "phase": "request_headers", "status": "blocked", "action": "deny",
                "requested_action": "deny", "actual_action": "deny", "http_status": 403}
    matching = [row for row in rows if type(row.get("http_status")) is int
                and all(row.get(key) == value for key, value in expected.items())]
    if len(matching) != 1:
        raise ValueError("native event log lacks one exact matching rule/transaction/deny event")


def clear_current_outputs(evidence, results, log_dir):
    outputs = [evidence / name for name in ("result.json", "runtime-result.json", "targeted-result.json",
                                           "results.jsonl", "summary.json", "summary.txt")]
    outputs.extend(results / ("envoy-" + suffix) for suffix in ("results.jsonl", "summary.json", "summary.txt"))
    outputs.append(log_dir / "status.log")
    for path in outputs:
        runtime_artifact_path(evidence if path.parent == evidence else path.parent, path, "current legacy output")
        if path.exists():
            private_bytes(path.parent, path)
            path.unlink()


def write_legacy_record(paths, evidence, results, log_dir, runtime, rules):
    arguments = ["--connector", "envoy", "--integration-mode", "ext_authz", "--status", "PASS", "--exit-code", "0",
                 "--runtime-verified", "true", "--allowed-request-status", "200", "--blocked-request-status", "403",
                 "--decision-backend", "libmodsecurity", "--modsecurity-ruleset", "targeted",
                 "--modsecurity-smoke-case", "legacy-native-two-request", "--modsecurity-backend-verified", "true",
                 "--modsecurity-rule-loaded", "true", "--modsecurity-rule-id", EXPECTED_RULE,
                 "--modsecurity-rule-file", str(rules), "--decision-log-path", str(runtime / "events.jsonl"),
                 "--evidence-root", str(evidence), "--results-dir", str(results), "--connector-root", str(ROOT),
                 "--harness-path", str(SCRIPT_DIR / "run_envoy_smoke.sh"), "--skipped-reason", "",
                 "--log-dir", str(log_dir), "--resolved-runtime-binary", os.environ.get("ENVOY_BIN", ""),
                 "--runtime-binary-env-var", "ENVOY_BIN", "--runtime-binary-name", "envoy",
                 "--note", "One native two-request legacy smoke: actual allow/deny probes, matching rule 1000001 event, stopped processes. runtime-result.json aliases the same targeted record; no catalog coverage."]
    for option, key in (("source-root", "SOURCE_ROOT"), ("build-root", "BUILD_ROOT"),
                        ("tmp-root", "TMP_ROOT"), ("log-root", "LOG_ROOT")):
        arguments.extend(["--" + option, paths[key]])
    for claim in (*writer.DEFAULT_CLAIMS_NOT_ALLOWED, "catalog_coverage=true", "mrts_complete=true"):
        arguments.extend(["--claim-not-allowed", claim])
    writer.main(arguments)
    body = private_bytes(evidence, evidence / "result.json")
    descriptor = os.open(evidence / "runtime-result.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(body)


def main():
    os.umask(0o077)
    paths = verified_runtime_paths(os.environ)
    root = verified_runtime_artifact_root(paths["VERIFIED_RUN_ROOT"])
    evidence = verified_runtime_artifact_root(root / "envoy-smoke")
    results = verified_runtime_artifact_root(runtime_artifact_path(root, Path(os.environ.get("RESULTS_DIR", paths["BUILD_ROOT"] + "/results")), "legacy results directory"))
    log_dir = verified_runtime_artifact_root(root / "logs/envoy-legacy")
    clear_current_outputs(evidence, results, log_dir)
    rules = source_path("common/rules/modsecurity_targeted_smoke.conf")
    if (os.environ.get("RUN_ONE_CASE", "0") == "1" or os.environ.get("MSCONNECTOR_NO_CRS_BASELINE", "0") != "0"
            or os.environ.get("TEST_CASE", "")
            or os.environ.get("SMOKE_CASES", "") or os.environ.get("MODSECURITY_SMOKE_CASE", "") not in ("", "targeted")
            or os.environ.get("CRS_SMOKE_CASE", "")
            or os.environ.get("MODSECURITY_RULESET", "targeted") not in ("", "targeted")
            or os.environ.get("MODSECURITY_TEST_VARIANT", "no-crs") not in ("", "no-crs")
            or os.environ.get("MSCONNECTOR_RESPONSE_PHASE_SMOKE", "0") != "0"
            or os.environ.get("RULES_FILE", str(rules)) != str(rules)
            or os.environ.get("MSCONNECTOR_EXPECTED_RULE_ID", EXPECTED_RULE) != EXPECTED_RULE):
        raise ValueError("legacy Envoy evidence supports only its native targeted two-request contract")
    runtime = Path(tempfile.mkdtemp(prefix="n.", dir=evidence))
    environment = dict(os.environ, RUNTIME_ROOT=str(runtime), EVENT_LOG_PATH=str(runtime / "events.jsonl"))
    started = time.time_ns()
    result = subprocess.run(["/bin/sh", str(SCRIPT_DIR / "run_envoy_connector_runtime.sh"), *sys.argv[2:]],
                            env=environment, stdin=subprocess.DEVNULL, check=False)
    if result.returncode != 0:
        return result.returncode if result.returncode > 0 else 128 - result.returncode
    native_summary(runtime, started)
    client_observation(runtime, "allow-client.json", 200, started)
    client_observation(runtime, "deny-client.json", 403, started)
    native_block_event(runtime, started)
    write_legacy_record(paths, evidence, results, log_dir, runtime, rules)
    return 0


try:
    exit_code = main()
except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
    print(f"envoy legacy evidence blocked: {error}", file=sys.stderr)
    exit_code = 1
raise SystemExit(exit_code)
PY_LEGACY_ENVOY
