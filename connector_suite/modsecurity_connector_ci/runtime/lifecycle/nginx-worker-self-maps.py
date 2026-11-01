"""Optional private own-worker capture; absence retains strict direct maps read."""
import json
import os
from pathlib import Path
import stat
import time

MAXIMUM = 64 * 1024
LEDGER = "worker-self-maps.raw"
LIBRARY = "worker-self-maps.so"

class Capture:
    def __init__(self, args, output, environment, hashes, startup):
        self.output, self.startup, self.descriptor = output, startup, None
        library = getattr(args, "worker_self_map_library", None)
        if library is None:
            return
        origin = startup.BASE.absolute_path(library)
        hashes["worker_self_map_library_sha256"] = startup.BASE.snapshot_artifact(origin, output / LIBRARY, executable=False)
        self.descriptor = os.open(output / LEDGER, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(self.descriptor, 0o600)
            environment["LD_PRELOAD"] = str(output / LIBRARY) + (":" + environment["LD_PRELOAD"] if environment.get("LD_PRELOAD") else "")
            environment["MSCONNECTOR_OWNED_SELF_MAP_FD"] = str(self.descriptor)
            environment["MSCONNECTOR_OWNED_SELF_MAP_UID"] = "65534"
            self.required = environment["LD_PRELOAD"].split(":") + [str(output / "nginx-module.so")]
        except BaseException:
            os.close(self.descriptor)
            self.descriptor = None
            raise

    def descriptors(self, existing=None):
        return tuple(fd for fd in (existing, self.descriptor) if fd is not None)

    def close(self):
        if self.descriptor is not None:
            descriptor = self.descriptor
            self.descriptor = None
            try:
                os.fsync(descriptor)
            except BaseException as sync_error:
                try:
                    os.close(descriptor)
                except OSError as close_error:
                    raise sync_error from close_error
                raise
            os.close(descriptor)

    def capture(self, roles):
        if self.descriptor is None:
            raw = self.startup.bounded_capture(Path("/proc") / str(roles["worker_pid"]) / "maps")
        else:
            raw = self.read_worker(roles)
        with (self.output / "worker-maps.log").open("xb") as capture:
            capture.write(raw)

    def read_worker(self, roles):
        deadline = time.monotonic() + 2
        while os.fstat(self.descriptor).st_size == 0 and time.monotonic() < deadline:
            time.sleep(0.02)
        info = os.fstat(self.descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= MAXIMUM):
            raise ValueError("bounded private worker self-map capture missing or invalid")
        raw = os.pread(self.descriptor, MAXIMUM + 1, 0)
        return validate(raw, roles, self.startup.process_info(roles["worker_pid"]), self.required)

def validate(raw, roles, actual, required):
    header, separator, maps = raw.partition(b"\n")
    if not separator or len(header) > 1024 or len(raw) > MAXIMUM:
        raise ValueError("invalid bounded worker self-map framing")
    record = json.loads(header)
    if (not isinstance(record, dict) or set(record) != {"version", "pid", "ppid", "uid", "gid", "starttime", "bytes"}
            or any(type(value) is not int for value in record.values())):
        raise ValueError("worker self-map identity must use exact numeric fields")
    expected = {"version":1, "pid":roles["worker_pid"], "ppid":roles["master_pid"], "uid":65534, "gid":65534, "bytes":len(maps)}
    if any(record[key] != value for key,value in expected.items()) or not maps.endswith(b"\n"):
        raise ValueError("worker self-map identity or complete bytes mismatch")
    if actual is None or actual[:2] != (65534, roles["master_pid"]) or str(record["starttime"]) != actual[3]:
        raise ValueError("worker self-map PID generation no longer matches actual own worker")
    paths = {line.split(None,5)[5] for line in maps.decode("utf-8").splitlines() if len(line.split(None,5)) == 6}
    if any(path not in paths for path in required):
        raise ValueError("actual worker maps omit required module or fixture library")
    return maps
