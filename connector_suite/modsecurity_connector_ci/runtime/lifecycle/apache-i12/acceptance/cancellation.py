"""Native-append gates and real owned-client termination for Apache fixtures.

Observer rows are evidence inputs, never synthesized by this module. A failed
gate may require process cleanup, but cannot become a successful cancellation.
Actual TCP reset receipt remains separate from a requested SO_LINGER close.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import time

MAX_CAPTURE_BYTES = 4 * 1024 * 1024
ACTIONS = {
    "cancel_client_process_after_first_native_append": signal.SIGINT,
    "SIGTERM_client_process_after_first_native_append": signal.SIGTERM,
}


class GateError(RuntimeError):
    """No physical, uniquely associated native append witness was established."""


def checked_path(value):
    path = Path(value).absolute()
    parent = path.parent
    if path.resolve() != path or parent.resolve(strict=True) != parent:
        raise GateError("Capture path follows a symlink or noncanonical component")
    metadata = parent.stat()
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
        raise GateError("Capture parent is not an owned nonshared directory")
    return path


def write_receipt(path, value):
    path = checked_path(path)
    content = (json.dumps(value, indent=2) + "\n").encode()
    if len(content) > MAX_CAPTURE_BYTES:
        raise GateError("Receipt exceeds the bounded capture size")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content)


def read_capture(path):
    path = checked_path(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise GateError("Capture is not an owned regular file")
        content = stream.read(MAX_CAPTURE_BYTES + 1)
    if len(content) > MAX_CAPTURE_BYTES:
        raise GateError("Observer capture exceeds the bounded gate size")
    return content


def validate_identity(identity):
    for field in ("run", "case", "transaction_id"):
        value = identity.get(field)
        if not isinstance(value, str) or not value or len(value) > 256:
            raise GateError("Gate requires an explicit bounded principal " + field)
    if "host_pid" in identity and (type(identity["host_pid"]) is not int or identity["host_pid"] <= 0):
        raise GateError("Invalid selected host PID")


def belongs(row, identity, after_ns):
    if (row.get("schema") != "native-lifecycle-v1" or row.get("profile") != "apache-native"
            or row.get("run") != identity["run"] or row.get("case") != identity["case"]
            or row.get("uid") != os.geteuid() or row.get("invalid") is not False):
        return False
    if type(row.get("monotonic_ns")) is not int or row["monotonic_ns"] < after_ns:
        return False
    return "host_pid" not in identity or row.get("pid") == identity["host_pid"]


def same_allocation(left, right):
    return (left.get("pid") == right.get("pid")
            and left.get("allocation_scope_kind") == right.get("allocation_scope_kind") == "host"
            and type(left.get("allocation_scope_call")) is int
            and left["allocation_scope_call"] == right.get("allocation_scope_call"))


def allocation_witness(rows, identity):
    native = [row for row in rows if row.get("function") in ("native_new", "native_new_with_id")
              and row.get("edge") == "return" and row.get("result") == 1
              and row.get("transaction_id") == identity["transaction_id"]]
    if len(native) != 1:
        return None
    joined = [row for row in rows if row.get("function") == "host_allocation"
              and row.get("edge") == "return" and row.get("result") == 1
              and row.get("allocation_join_verified") is True and same_allocation(row, native[0])]
    if len(joined) != 1 or native[0]['monotonic_ns'] > joined[0]['monotonic_ns']:
        return None
    return native[0], joined[0]


def find_native_append(rows, identity, after_ns):
    """Require actual return plus positive allocation join for this exact native ID."""
    validate_identity(identity)
    principal = [row for row in rows if belongs(row, identity, after_ns)]
    allocation = allocation_witness(principal, identity)
    if allocation is None:
        return None
    native, joined = allocation
    candidates = [row for row in principal if row.get("function") == "native_append_request_body"
                  and row.get("edge") == "return" and type(row.get("result")) is int
                  and row["result"] in (0, 1) and type(row.get("input_size")) is int
                  and row["input_size"] > 0 and row.get("transaction_id") == identity["transaction_id"]
                  and same_allocation(row, native)]
    for result in sorted(candidates, key=lambda row: row["monotonic_ns"]):
        entered = [row for row in principal if row.get("function") == "native_append_request_body"
                   and row.get("edge") == "enter" and row.get("call") == result.get("call")
                   and same_allocation(row, result) and row.get("transaction_id") == identity["transaction_id"]
                   and joined['monotonic_ns'] <= row["monotonic_ns"] <= result["monotonic_ns"]]
        if len(entered) == 1:
            return {"native_allocation": native, "host_allocation": joined,
                    "append_enter": entered[0], "append_return": result}
    return None


def decode_rows(content):
    rows = []
    for line in content.splitlines(keepends=True):
        if not line.endswith(b"\n"):
            continue
        try:
            row = json.loads(line)
        except ValueError as error:
            raise GateError("Malformed complete observer record") from error
        if not isinstance(row, dict):
            raise GateError("Observer record is not an object")
        rows.append(row)
    return rows


def append_snapshot(path, identity, after_ns):
    content = read_capture(path)
    if content is None:
        return None
    witness = find_native_append(decode_rows(content), identity, after_ns)
    if witness is None:
        return None
    return {"path": str(Path(path).absolute()), "prefix_bytes": len(content),
            "prefix_sha256": hashlib.sha256(content).hexdigest(), "witness": witness,
            "gate_observed_ns": time.monotonic_ns(), "is_host_qualification": False}


def wait_for_append(native_log, identity, after_ns, timeout=5):
    """Wait only for physical append evidence; a timeout yields no cancellation."""
    if not 0 < timeout <= 20:
        raise ValueError("Gate timeout must be bounded to 20 seconds")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = append_snapshot(native_log, identity, after_ns)
        if result is not None:
            return result
        time.sleep(0.01)
    raise GateError("Principal native append was not observed before the gate deadline")


def publish_send_ready(path, progress):
    """Wire child calls this after actual sendall, before waiting/receiving."""
    if (type(progress.get("started_ns")) is not int or progress['started_ns'] <= 0
            or type(progress.get("request_send_completed_ns")) is not int
            or progress['request_send_completed_ns'] < progress['started_ns']):
        raise GateError("A completed real request send must precede the checkpoint")
    if not any(item.get("bytes", 0) > 0 for item in progress.get("request_send_operations", [])):
        raise GateError("Cancellation requires a real nonempty body send")
    write_receipt(path, {"pid": os.getpid(), "uid": os.geteuid(),
        "checkpoint_ns": time.monotonic_ns(), "progress": copy.deepcopy(progress)})


def pause_for_parent():
    """Only the owned parent's validated gate releases a signalled wire child."""
    while True:
        signal.pause()


def process_identity(pid):
    text = Path('/proc').joinpath(str(pid), 'stat').read_text()
    fields = text.rsplit(')', 1)[1].split()
    status = Path('/proc').joinpath(str(pid), 'status').read_text().splitlines()
    uid_line = next(line for line in status if line.startswith('Uid:'))
    return {"pid": pid, "ppid": int(fields[1]), "starttime": fields[19],
            "effective_uid": int(uid_line.split()[2])}


def waited_status(pid, status):
    return {"pid": pid, "raw_wait_status": status, "waited_monotonic_ns": time.monotonic_ns(),
            "exited": os.WIFEXITED(status), "signalled": os.WIFSIGNALED(status),
            "exit_code": os.WEXITSTATUS(status) if os.WIFEXITED(status) else None,
            "actual_signal": os.WTERMSIG(status) if os.WIFSIGNALED(status) else None}


class OwnedWireChild:
    """No process-group or external-PID signalling; reap this one direct fork."""
    def __init__(self, wire_client):
        self.pid = os.fork()
        self.waited = None
        if self.pid == 0:
            self.execute(wire_client)
        try:
            self.identity = process_identity(self.pid)
            if self.identity["ppid"] != os.getpid() or self.identity["effective_uid"] != os.geteuid():
                raise GateError("Forked wire client ownership could not be established")
        except (OSError, ValueError, GateError):
            # An unreaped direct fork cannot have its PID reused. Clean up even
            # when /proc prevented the stronger starttime ownership receipt.
            if self.poll() is None:
                os.kill(self.pid, signal.SIGKILL)
                pid, status = os.waitpid(self.pid, 0)
                self.waited = waited_status(pid, status)
            raise

    @staticmethod
    def execute(wire_client):
        for selected in (signal.SIGINT, signal.SIGTERM):
            signal.signal(selected, signal.SIG_DFL)
        code = 78
        try:
            candidate = wire_client()
            if type(candidate) is int and 0 <= candidate <= 255:
                code = candidate
        finally:
            # This terminal child boundary deliberately handles the active
            # exception by retaining the default error code: even a custom
            # BaseException must never unwind into the parent's controller.
            # Real SIGINT/SIGTERM retain SIG_DFL and therefore still produce
            # physical signal wait status.
            os._exit(code)

    def poll(self):
        if self.waited is None:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid == self.pid:
                self.waited = waited_status(pid, status)
        return self.waited

    def send_signal(self, selected):
        if self.poll() is not None:
            return None
        current = process_identity(self.pid)
        if current != self.identity or current["ppid"] != os.getpid():
            raise GateError("Wire child PID/starttime/UID no longer matches its fork receipt")
        os.kill(self.pid, selected)
        return {"signal": int(selected), "operation_completed_ns": time.monotonic_ns(),
                "target_identity": current}

    def reap(self, timeout=2):
        deadline = time.monotonic() + timeout
        while self.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        if self.waited is None:
            operation = self.send_signal(signal.SIGKILL)
            if self.waited is None:
                pid, status = os.waitpid(self.pid, 0)
                self.waited = waited_status(pid, status)
            if operation is not None:
                self.waited["cleanup_escalated_to_SIGKILL"] = True
        return self.waited


def ready_checkpoint(path, child):
    content = read_capture(path)
    if content is None or not content.endswith(b'\n'):
        return None
    record = json.loads(content)
    if record.get("pid") != child.pid or record.get("uid") != os.geteuid():
        raise GateError("Send checkpoint does not belong to the actual forked client")
    return record


def await_child_gate(child, native_log, identity, ready_path, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise GateError("Wire child exited before a cancellation could be performed")
        ready = ready_checkpoint(ready_path, child)
        if ready is not None:
            witness = append_snapshot(native_log, identity, ready['progress']['started_ns'])
            if witness is not None:
                return ready, witness
        time.sleep(0.01)
    raise GateError("Principal send/append gate deadline expired")


def supervise_client(wire_client, native_log, identity, ready_path, termination_path, action, timeout=5):
    """Fork a real wire client, gate a real signal, and retain its direct wait status."""
    validate_identity(identity)
    if action not in ACTIONS or not 0 < timeout <= 20:
        raise ValueError("Unsupported or unbounded cancellation operation")
    result = {"action": action, "requested_action_performed": False,
              "native_append_gate": None, "send_checkpoint": None,
              "requested_signal_operation": None, "cleanup_signal_operation": None,
              "actual_termination": None, "failure": None, "wrapper_exit": 1}
    child = OwnedWireChild(wire_client)
    try:
        ready, witness = await_child_gate(child, native_log, identity, ready_path, timeout)
        result.update(send_checkpoint=ready, native_append_gate=witness)
        result["requested_signal_operation"] = child.send_signal(ACTIONS[action])
        result["requested_action_performed"] = result["requested_signal_operation"] is not None
    except (GateError, OSError, ValueError) as error:
        result["failure"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        if not result["requested_action_performed"]:
            result["cleanup_signal_operation"] = child.send_signal(signal.SIGTERM)
        result["actual_termination"] = child.reap()
        terminated = result["actual_termination"]
        if (result["requested_action_performed"] and terminated["actual_signal"] == ACTIONS[action]
                and not terminated.get("cleanup_escalated_to_SIGKILL")):
            result["wrapper_exit"] = 0
        write_receipt(termination_path, result)
    return result


def wait_then_reset(connection, native_log, identity, after_ns, timeout=5):
    """Request a real TCP reset after native append; do not assert receipt on wire."""
    witness = wait_for_append(native_log, identity, after_ns, timeout)
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
    option = struct.unpack('ii', connection.getsockopt(socket.SOL_SOCKET, socket.SO_LINGER, 8))
    configured = time.monotonic_ns()
    connection.close()
    return {"native_append_gate": witness, "actual_linger_option": list(option),
            "setsockopt_completed_ns": configured, "close_completed_ns": time.monotonic_ns(),
            "actual_socket_fileno_after_close": connection.fileno(), "rst_on_wire_observed": None,
            "server_reset_observed": None, "is_host_qualification": False}
