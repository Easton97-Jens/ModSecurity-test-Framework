#!/usr/bin/env python3
"""Bounded sequential use of existing HAProxy capture drivers; never a qualifier."""
import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import time

SCHEMA = "i12-haproxy-batch-v1"
LIMIT = 6
LEGS = {"native": "haproxy-native-htx", "spop": "haproxy-spop-request",
        "companion": "haproxy-spop-htx-response-companion"}
PYTHON = "/usr/local/bin/python3"
FIXTURES = Path("/mnt/fixtures")
TASK = Path("/task")
STORAGE = Path("/var") / "tmp" / "codex" / "ModSecurity-conector"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def physical(path):
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("absolute physical path required")
    if not any(path.is_relative_to(boundary) for boundary in (STORAGE, FIXTURES, TASK)):
        raise ValueError("path outside admitted capture storage")
    for part in (path, *path.parents):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid not in (0, os.geteuid()):
            raise ValueError("foreign or symlink path")
    return path


def read_bound(path, expected):
    physical(path)
    if not path.is_file() or path.stat().st_mode & 0o222:
        raise ValueError("sealed regular file required")
    data = path.read_bytes()
    if digest(data) != expected:
        raise ValueError("input identity mismatch")
    return data


def inventory(root):
    physical(root)
    result = {}
    for path in root.rglob("*"):
        physical(path)
        if path.is_file():
            result[str(path.relative_to(root))] = digest(path.read_bytes())
        elif not path.is_dir():
            raise ValueError("special input forbidden")
    return result


def relocate(data, route, member):
    """Only known driver runtime paths and whole port literals may change."""
    text = data.decode()
    replacements = {str(FIXTURES): str(FIXTURES / member), "/task": f"/task/{member}"}
    if route == "native":
        replacements.update({str(port): str(21000 + int(member[1:]) * 10 + offset)
                             for offset, port in enumerate((18490, 18491))})
    elif route == "spop":
        replacements.update({str(port): str(22000 + int(member[1:]) * 10 + offset)
                             for offset, port in enumerate(range(18540, 18545))})
    else:
        raise ValueError("companion uses existing explicit root and dynamic ports")
    counts = {}
    # A single substitution prevents replacement output being interpreted again.
    pattern = re.compile(r"/mnt/fixtures(?![A-Za-z0-9_-])|/task(?![A-Za-z0-9_-])|(?<![0-9])(?:" +
                         "|".join(key for key in replacements if key.isdecimal()) + r")(?![0-9])")
    def substitute(match):
        key = match.group()
        counts[key] = counts.get(key, 0) + 1
        return replacements[key]
    updated = pattern.sub(substitute, text)
    compile(updated, "relocated-driver.py", "exec")
    return updated.encode(), {key: {"to": replacements[key], "count": count} for key, count in counts.items()}


def driver_argv(route, member, fixture=None):
    base = FIXTURES / member
    work = TASK / member
    script = "launch.py" if route == "native" else "i12_" + route + "_host.py"
    argv = ["rtk", "proxy", PYTHON, "-B", str(base / script)]
    if route == "companion":
        argv += ["--root", str(work / "host"), "--allowed-root", str(TASK),
                 "--host", "/mnt/artifacts/haproxy", "--agent", "/mnt/artifacts/haproxy-spop",
                 "--openssl-config", str(base / "openssl.cnf"), "--neighbor", "--case", "safe",
                 "--case-id", fixture["case_id"], "--fixture", str(base / fixture["path"])]
    return argv


def source_case(case):
    source = physical(Path(case["source"]))
    if inventory(source) != case["files"]:
        raise ValueError("source fixture inventory mismatch")
    for name, expected in case["files"].items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("escaping fixture member")
        read_bound(source / name, expected)
    return source


def prepare_member(case, destination, member):
    route = case["route"]
    source = source_case(case)
    target = destination / member
    target.mkdir(mode=0o700)
    changes = []
    modified = {"native": {"launch.py", "client.py", "backend.py"},
                "spop": {"i12_spop_host.py"}, "companion": set()}[route]
    for name, expected in case["files"].items():
        data = read_bound(source / name, expected)
        original = data
        substitutions = {}
        if name in modified:
            data, substitutions = relocate(data, route, member)
        out = target / name
        out.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        out.write_bytes(data)
        out.chmod(0o444)
        if original != data:
            changes.append({"file": name, "before_sha256": digest(original), "after_sha256": digest(data),
                            "substitutions": substitutions,
                            "diff": "".join(difflib.unified_diff(original.decode().splitlines(True),
                                        data.decode().splitlines(True), fromfile=name, tofile=member + "/" + name))})
    identity_file = {"native": "case-contract.json", "spop": "selected.json",
                     "companion": case.get("fixture", "")}[route]
    if identity_file not in case["files"]:
        raise ValueError("identity file is not a bound fixture member")
    identity = json.loads((target / identity_file).read_text())
    actual_id = identity.get("original_id", identity.get("case_id"))
    if actual_id != case["original_id"]:
        raise ValueError("original identity differs from physical fixture")
    fixture = {"case_id": actual_id, "path": identity_file}
    entry = {"member": member, "route": route, "original_id": actual_id,
             "workspace": str(TASK / member),
             "data_root": str(TASK / member / "host") if route == "companion" else str(TASK / member),
             "argv": driver_argv(route, member, fixture), "timeout_seconds": 180,
             "source": str(source), "source_files": case["files"], "relocations": changes,
             "fixture": fixture, "full_lifecycle_pass": None}
    return entry


def prepare(plan, output):
    cases = plan["cases"]
    if not 1 <= len(cases) <= LIMIT or len({case["route"] for case in cases}) != 1:
        raise ValueError("one route and one to six cases required")
    identities = [case["original_id"] for case in cases]
    if len(set(identities)) != len(cases):
        raise ValueError("duplicate original identity")
    for case in cases:
        if not case["original_id"].startswith("I12::" + LEGS[case["route"]] + "::"):
            raise ValueError("route and original identity differ")
    entries = [prepare_member(case, output, f"c{index:02d}") for index, case in enumerate(cases)]
    coordinator = output / "i12_batch.py"
    coordinator.write_bytes(Path(__file__).read_bytes())
    coordinator.chmod(0o444)
    queue = {"schema": SCHEMA, "cases": entries, "files": inventory(output),
             "artifact_binding_required_from_root": True, "host_runs": 0, "full_lifecycle_pass": None,
             "limits": {"cases": LIMIT, "runtime_seconds": 1200, "output_bytes": 536870912,
                        "memory_bytes": 2147483648, "processes": 128}}
    queue_path = output / "queue.json"
    queue_path.write_text(json.dumps(queue, indent=2) + "\n")
    queue_path.chmod(0o444)
    ledger = output.with_name(output.name + "-ledger.json")
    ledger.write_text(json.dumps({"files": inventory(output), "symlinks": {}}, indent=2) + "\n")
    ledger.chmod(0o444)
    return {"queue_sha256": digest(queue_path.read_bytes()), "ledger": str(ledger),
            "ledger_sha256": digest(ledger.read_bytes()), "prepared_unsealed_no_execution": True}


def seal(root, expected):
    ledger = root.with_name(root.name + "-ledger.json")
    files = json.loads(read_bound(ledger, expected))["files"]
    if inventory(root) != files:
        raise ValueError("candidate changed before seal")
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        path.chmod(0o555 if path.is_dir() else 0o444)
    root.chmod(0o555)


def load_queue(path, expected):
    queue = json.loads(read_bound(path, expected))
    root = path.parent
    if queue.get("schema") != SCHEMA or not 1 <= len(queue["cases"]) <= LIMIT:
        raise ValueError("invalid batch queue")
    actual = inventory(root)
    actual.pop(path.name, None)
    if actual != queue["files"]:
        raise ValueError("batch input inventory differs")
    for index, entry in enumerate(queue["cases"]):
        validate_entry(entry, index)
        validate_fixture_identity(entry, root)
    for item in (root, *root.rglob("*")):
        if item.stat().st_mode & 0o222:
            raise ValueError("batch inputs must be sealed")
    return queue


def validate_entry(entry, index):
    if entry["member"] != f"c{index:02d}":
        raise ValueError("member order or uniqueness differs")
    if not re.fullmatch(r"c0[0-5]", entry["member"]):
        raise ValueError("invalid workspace member")
    if entry["workspace"] != str(TASK / entry["member"]):
        raise ValueError("workspace differs")
    data_root = str(TASK / entry["member"] / "host") if entry["route"] == "companion" else entry["workspace"]
    if entry["data_root"] != data_root:
        raise ValueError("data root differs")
    if entry["argv"] != driver_argv(entry["route"], entry["member"], entry["fixture"]):
        raise ValueError("unapproved driver argv")
    if not 1 <= entry["timeout_seconds"] <= 180:
        raise ValueError("invalid member timeout")


def validate_fixture_identity(entry, root):
    relative = Path(entry["fixture"]["path"])
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("escaping identity fixture")
    identity_path = physical(root / entry["member"] / relative)
    identity = json.loads(identity_path.read_text())
    actual = identity.get("original_id", identity.get("case_id"))
    if actual != entry["original_id"] or actual != entry["fixture"]["case_id"]:
        raise ValueError("queue original identity differs from physical fixture")
    if not actual.startswith("I12::" + LEGS[entry["route"]] + "::"):
        raise ValueError("queue route differs from physical original identity")


def process_record(pid):
    proc = Path("/proc") / str(pid)
    fields = (proc / "stat").read_text().rsplit(")", 1)[1].split()
    return {"pid": int(pid), "state": fields[0], "ppid": int(fields[1]),
            "starttime": fields[19], "exe": os.readlink(proc / "exe") if (proc / "exe").exists() else None}


def processes():
    result = {}
    for proc in Path("/proc").iterdir():
        if proc.name.isdecimal():
            try:
                row = process_record(proc.name)
                result[str(row["pid"]) + ":" + row["starttime"]] = row
            except (FileNotFoundError, ProcessLookupError):
                continue
    return result


def descriptors():
    result = {}
    for name in os.listdir("/proc/self/fd"):
        try:
            result[name] = os.readlink("/proc/self/fd/" + name)
        except FileNotFoundError:
            continue
    return result


def socket_tables():
    result = {"live": {}, "tcp_time_wait": {}}
    for protocol in ("tcp", "tcp6", "udp", "udp6", "unix"):
        for line in Path("/proc/net", protocol).read_text().splitlines()[1:]:
            fields = line.split()
            if protocol == "unix":
                key = protocol + ":" + fields[6]
            else:
                key = protocol + ":" + fields[9] + ":" + fields[1] + ":" + fields[2]
            time_wait = protocol.startswith("tcp") and fields[3] == "06"
            group = "tcp_time_wait" if time_wait else "live"
            result[group][key] = {"protocol": protocol, "raw": line}
    return result


def sockets():
    return socket_tables()["live"]


def state():
    captured_sockets = socket_tables()
    return {"wall_ns": time.time_ns(), "processes": processes(),
            "descriptors": descriptors(), "sockets": captured_sockets["live"],
            "tcp_time_wait": captured_sockets["tcp_time_wait"]}


def cleanup_difference(before, after):
    errors = []
    for key in ("processes", "sockets"):
        extra = sorted(set(after[key]) - set(before[key]))
        if extra:
            errors.append({"kind": key + "_leak", "actual_new_keys": extra})
    if after["descriptors"] != before["descriptors"]:
        errors.append({"kind": "coordinator_descriptor_change", "before": before["descriptors"],
                       "after": after["descriptors"]})
    return errors


def native_cleanup(root):
    value = json.loads((root / "execution.json").read_text())
    waits = [row for row in value["commands"] if row.get("label", "").endswith("-wait")]
    return {"source": str(root / "execution.json"), "observed": waits,
            "clean": bool(waits) and all(row.get("reaped") is True for row in waits)}


def spop_cleanup(root):
    rows = [json.loads(line) for line in (root / "cleanup.jsonl").read_text().splitlines()]
    taps = [json.loads(line) for line in (root / "observer-cleanup.jsonl").read_text().splitlines()]
    return {"source": str(root / "cleanup.jsonl"), "observed": rows + taps,
            "clean": bool(rows and taps) and all(row.get("backend_joined") is True for row in rows)
                     and all(row.get("listener_joined") is True and row.get("workers_joined") is True for row in taps)}


def companion_cleanup(root):
    receipt = json.loads((root / "receipt.json").read_text())
    observations = json.loads((root / "observations.json").read_text())
    clean = [row for row in observations if row.get("kind") == "capture_cleanup"]
    failures = [row for row in observations if row.get("kind") == "capture_cleanup_error"]
    return {"source": str(root / "receipt.json"), "observed": receipt["commands"],
            "clean": bool(clean) and not failures and
                     all(row.get("reaped") is True for row in receipt["commands"] if row.get("label", "").endswith("-wait"))}


def cleanup_receipt(entry):
    readers = {"native": native_cleanup, "spop": spop_cleanup, "companion": companion_cleanup}
    return readers[entry["route"]](Path(entry["data_root"]))


def signal_group(child, signum):
    try:
        os.killpg(child.pid, signum)
    except ProcessLookupError:
        pass  # The owned child is still waited even if its group just exited.


def run_member(entry, workspace):
    """Run exactly one admitted driver and wait; no outcome translation."""
    before = state()
    timed_out = False
    environment = dict(os.environ)
    for key, suffix in (("TMPDIR", "tmp"),
                        ("XDG_DATA_HOME", "rtk-data"), ("XDG_CACHE_HOME", "cache")):
        directory = workspace / suffix
        directory.mkdir(mode=0o700)
        environment[key] = str(directory)
    with (workspace / "driver.stdout").open("xb") as out, (workspace / "driver.stderr").open("xb") as err:
        child = subprocess.Popen(entry["argv"], cwd=workspace, stdout=out, stderr=err,
                                 start_new_session=True, close_fds=True, env=environment)
        try:
            launched = process_record(child.pid)
        except (OSError, ValueError) as error:
            launched = {"pid": child.pid, "starttime": None,
                        "proc_observation_error": type(error).__name__ + ": " + str(error)}
        try:
            code = child.wait(timeout=entry["timeout_seconds"])
        except subprocess.TimeoutExpired:
            timed_out = True
            signal_group(child, signal.SIGTERM)
            try:
                code = child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                signal_group(child, signal.SIGKILL)
                code = child.wait(timeout=3)
    after = state()
    errors = cleanup_difference(before, after)
    if launched.get("starttime") is None:
        errors.append({"kind": "driver_process_identity_unknown"})
    if timed_out:
        errors.append({"kind": "member_timeout"})
    try:
        receipt = cleanup_receipt(entry)
        if not receipt["clean"]:
            errors.append({"kind": "existing_driver_cleanup_failed"})
    except (OSError, ValueError, KeyError) as error:
        receipt = {"clean": None, "reason": type(error).__name__ + ": " + str(error)}
        errors.append({"kind": "existing_driver_cleanup_unknown"})
    return {"original_id": entry["original_id"], "argv": entry["argv"], "cwd": str(workspace),
            "launched_process": launched, "waited_exit": code, "signal": -code if code < 0 else None,
            "timeout": timed_out, "before": before, "after": after, "cleanup_receipt": receipt,
            "errors": errors, "full_lifecycle_pass": None}


def bounds_after_member(queue, task, started):
    limits = queue.get("limits", {})
    output_bytes = sum(path.lstat().st_size for path in task.rglob("*")
                       if stat.S_ISREG(path.lstat().st_mode))
    elapsed = time.monotonic() - started
    errors = []
    if output_bytes > limits.get("output_bytes", float("inf")):
        errors.append({"kind": "batch_output_limit", "actual_bytes": output_bytes})
    if elapsed > limits.get("runtime_seconds", float("inf")):
        errors.append({"kind": "batch_runtime_limit", "actual_seconds": elapsed})
    return errors


def execute_queue(queue, expected, task=TASK):
    """Internal sequential runner; CLI separately enforces original admission."""
    results = []
    started = time.monotonic()
    for entry in queue["cases"]:
        workspace = task / entry["member"]
        workspace.mkdir(mode=0o700, exist_ok=False)
        row = run_member(entry, workspace)
        row["errors"].extend(bounds_after_member(queue, task, started))
        results.append(row)
        (workspace / "batch-member.json").write_text(json.dumps(row, indent=2) + "\n")
        if row["errors"]:
            break
    failed = len(results) != len(queue["cases"]) or any(row["errors"] for row in results)
    summary = {"schema": SCHEMA, "queue_sha256": expected, "members": results,
               "batch_capture_complete": not failed, "full_lifecycle_pass": None,
               "controller_zero_is_not_case_PASS": True,
               "cases_started": len(results), "cases_not_started": len(queue["cases"]) - len(results)}
    (task / "batch-result.json").write_text(json.dumps(summary, indent=2) + "\n")
    return 77 if failed else 0


NAMESPACE_KEYS = {"user", "mnt", "net", "pid", "ipc", "uts"}
CAPABILITY_FIELDS = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")


def check_private_status(status, identity):
    if (identity["uid"], identity["gid"]) != (65534, 65534) or identity["groups"]:
        raise ValueError("actual nonroot identity differs")
    if status.get("NoNewPrivs") != "1":
        raise ValueError("actual no-new-privileges is missing")
    if any(int(status[key], 16) != 0 for key in CAPABILITY_FIELDS):
        raise ValueError("actual capability mask is nonzero")


def private_namespaces(config):
    """Reject incomplete controller keys before reading fixed namespace paths."""
    outside = config.get("outside_namespaces")
    if not isinstance(outside, dict) or set(outside) != NAMESPACE_KEYS:
        raise ValueError("complete actual namespace set required")
    return {key: os.readlink("/proc/self/ns/" + key) for key in sorted(NAMESPACE_KEYS)}


def check_admission(admission, config, status, namespaces, identity):
    """Reuse the actual original receipt and immutable controller config."""
    check_private_status(status, identity)
    if admission.get("mode") != "nonroot" or config.get("mode") != "nonroot":
        raise ValueError("original controller mode differs")
    if (admission.get("uid"), admission.get("gid")) != (identity["uid"], identity["gid"]):
        raise ValueError("original admission identity differs")
    if namespaces != admission["namespaces"]:
        raise ValueError("actual namespace differs from original admission")
    if set(namespaces) != NAMESPACE_KEYS or set(config["outside_namespaces"]) != NAMESPACE_KEYS:
        raise ValueError("complete actual namespace set required")
    if any(namespaces[key] == value for key, value in config["outside_namespaces"].items()):
        raise ValueError("actual namespace is shared with outside")
    if not {str(FIXTURES), "/mnt/artifacts"}.issubset(config["readonly"]):
        raise ValueError("original immutable bindings differ")


def run_batch(queue_path, expected):
    queue = load_queue(queue_path, expected)
    if Path.cwd() != TASK or os.geteuid() != 65534 or os.getegid() != 65534:
        raise ValueError("batch requires admitted nonroot /task controller execution")
    admission = json.loads((TASK / "isolation-admission.json").read_text())
    config = json.loads(Path("/opt/controller/admission.json").read_text())
    status = {key: value for line in Path("/proc/self/status").read_text().splitlines() if ":" in line
              for key, value in [line.split(":", 1)]}
    status = {key: value.strip() for key, value in status.items()}
    namespaces = private_namespaces(config)
    identity = {"uid": os.geteuid(), "gid": os.getegid(), "groups": os.getgroups()}
    check_admission(admission, config, status, namespaces, identity)
    return execute_queue(queue, expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--plan", type=Path, required=True)
    prepare_parser.add_argument("--sha256", required=True)
    prepare_parser.add_argument("--output", type=Path, required=True)
    seal_parser = sub.add_parser("seal")
    seal_parser.add_argument("--output", type=Path, required=True)
    seal_parser.add_argument("--sha256", required=True)
    run_parser = sub.add_parser("run")
    run_parser.add_argument("--queue", type=Path, required=True)
    run_parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        from connector_suite.adapters.haproxy.harness.i12_native_cases import fresh_output
        plan = json.loads(read_bound(args.plan, args.sha256))
        output = fresh_output(args.output)
        print(json.dumps(prepare(plan, output)))
        return 0
    if args.command == "seal":
        seal(args.output, args.sha256)
        return 0
    return run_batch(args.queue, args.sha256)


if __name__ == "__main__":
    raise SystemExit(main())
