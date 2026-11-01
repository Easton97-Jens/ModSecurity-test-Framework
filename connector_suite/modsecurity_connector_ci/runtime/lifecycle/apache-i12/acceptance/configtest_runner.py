#!/usr/bin/env python3
"""Observe the actual Apache config parser below the existing RTK wrapper.

Runtime source contract: copy this stdlib-only file beside batch.py, include its
SHA256 in the sealed fixture binding, and launch it solely through the existing
private batch admission. This helper neither admits an environment nor reviews
an outcome. Its exclusive receipts describe its own direct child, not RTK.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    with Path(path).open("x", encoding="utf-8") as output:
        os.chmod(path, 0o600)
        json.dump(value, output, indent=2)
        output.write("\n")


def canonical(value):
    supplied = Path(value)
    if not supplied.is_absolute() or ".." in supplied.parts or supplied.resolve(strict=True) != supplied:
        raise ValueError("config parser input must be canonical and nonsymlink")
    return supplied


def inputs(owned, config, root):
    root, owned, config = (canonical(value) for value in (root, owned, config))
    if not root.is_dir() or root.stat().st_uid != os.geteuid():
        raise ValueError("config parser root must be an owned directory")
    if owned != root.parent / "native-bin/apache2" or config != root / "httpd.conf":
        raise ValueError("config parser paths differ from the owned Apache layout")
    for path in (owned, config):
        if not path.is_file() or path.stat().st_uid != os.geteuid():
            raise ValueError("config parser input must be an owned regular file")
    return owned, config, root


def cleanup_observation(process):
    receipt = {"pid": process.pid, "reaped": True, "scope": "parser_pid_only",
               "descendants_observed": None,
               "observed_monotonic_ns": time.monotonic_ns(),
               "proc_pid_absent": None, "proc_lstat_errno": None}
    try:
        (Path("/proc") / str(process.pid)).lstat()
        receipt["proc_pid_absent"] = False
    except FileNotFoundError:
        receipt.update(proc_pid_absent=True, proc_lstat_errno=errno.ENOENT)
    return receipt


def capture(owned, config, root, wait_timeout=10):
    owned, config, root = inputs(owned, config, root)
    argv = [str(owned), "-t", "-f", str(config)]
    receipt = {"argv": argv, "cwd": str(root), "supervisor_pid": os.getpid(),
               "supervisor_parent_pid": os.getppid(), "started_unix_ns": time.time_ns(),
               "executable_sha256": sha(owned), "config_sha256": sha(config),
               "helper_sha256": sha(Path(__file__).resolve()), "timeout": False}
    # Deliberately direct: the caller already supplies the outer RTK proxy.
    # Inserting another RTK here would lose the actual child's signal status.
    with (root / "configtest.stdout").open("xb") as stdout, \
            (root / "configtest.stderr").open("xb") as stderr:
        os.chmod(stdout.name, 0o600)
        os.chmod(stderr.name, 0o600)
        process = subprocess.Popen(argv, cwd=root, stdout=stdout, stderr=stderr)
        receipt.update(pid=process.pid, parser_pid=process.pid)
        try:
            process.wait(timeout=wait_timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
            receipt["timeout"] = True
        cleanup = cleanup_observation(process)
        save(root / "configtest-cleanup.json", cleanup)
    receipt.update(ended_unix_ns=time.time_ns(), raw_returncode=process.returncode,
                   waited_exit=process.returncode,
                   waited_signal=-process.returncode if process.returncode < 0 else None,
                   cleanup=cleanup, cleanup_sha256=sha(root / "configtest-cleanup.json"))
    receipt["input_identity_unchanged"] = (sha(owned) == receipt["executable_sha256"]
                                           and sha(config) == receipt["config_sha256"])
    receipt["stream_decoding_errors"] = {}
    for stream in ("stdout", "stderr"):
        content = (root / ("configtest." + stream)).read_bytes()
        receipt[stream + "_bytes"] = len(content)
        receipt[stream + "_sha256"] = hashlib.sha256(content).hexdigest()
        receipt[stream] = None
        try:
            receipt[stream] = content.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            receipt["stream_decoding_errors"][stream] = {"start": error.start, "end": error.end,
                                                         "reason": error.reason}
    diagnostic = next((line for stream in ("stderr", "stdout") if receipt[stream] is not None
                       for line in receipt[stream].splitlines() if line.strip()), None)
    if diagnostic is not None:
        receipt["first_cause"] = diagnostic
    save(root / "configtest-process.json", receipt)
    save(root / "configtest.command.json", receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owned", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()
    receipt = capture(args.owned, args.config, args.root)
    # This is the helper's transport status, never the Apache outcome.
    return helper_exit(receipt)


def helper_exit(receipt):
    """A timed-out capture cannot produce successful helper transport."""
    return 0 if (receipt["input_identity_unchanged"] and not receipt["stream_decoding_errors"]
                 and receipt["timeout"] is False) else 1


if __name__ == "__main__":
    raise SystemExit(main())
