#!/usr/bin/env python3
"""Run one connector stage with short, invocation-owned Unix socket paths."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import time


from modsecurity_connector_ci.lib.runtime_path_utils import ensure_safe_runtime_directory, is_safe_runtime_parent


def live_group_members(group: int) -> list[int]:
    """Inspect Linux process states; unreaped zombies cannot use the socket."""
    members = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            record = (entry / "stat").read_text()
            fields = record[record.rfind(")") + 2:].split()
            if int(fields[2]) == group and fields[0] not in {"Z", "X"}:
                members.append(int(entry.name))
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    return members


def stop_group(group: int) -> bool:
    remaining = bool(live_group_members(group))
    for signum in (signal.SIGTERM, signal.SIGKILL):
        if not live_group_members(group):
            return remaining
        try:
            os.killpg(group, signum)
        except ProcessLookupError:
            return remaining
        deadline = time.monotonic() + 2
        while live_group_members(group) and time.monotonic() < deadline:
            time.sleep(0.02)
    if live_group_members(group):
        raise RuntimeError("connector stage process group did not terminate; socket root retained")
    return remaining


def private_socket_root(parent: Path) -> Path:
    if not parent.is_absolute() or not parent.is_dir() or not is_safe_runtime_parent(parent):
        raise ValueError("socket parent must be an existing safe absolute directory")
    ensure_safe_runtime_directory(parent)
    if len(os.fsencode(parent / "mcs.12345678" / "traefik-forwardauth-companion.sock")) >= 108:
        raise ValueError("configured socket parent is too long for Unix sockets")
    return ensure_safe_runtime_directory(tempfile.mkdtemp(prefix="mcs.", dir=parent))


class StageProcessGroup:
    """Keep socket ownership until every live stage process has stopped."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.child: subprocess.Popen[bytes] | None = None
        self.pending_signals: list[int] = []
        self.previous_handlers = {}
        self.safe_to_remove = True
        self.lingering = False

    def forward(self, signum: int, _frame: object) -> None:
        if self.child is None:
            self.pending_signals.append(signum)
            return
        try:
            os.killpg(self.child.pid, signum)
        except ProcessLookupError:
            pass

    def __enter__(self) -> StageProcessGroup:
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            self.previous_handlers[signum] = signal.signal(signum, self.forward)
        return self

    def execute(self, command: list[str]) -> int:
        environment = dict(os.environ, MSCONNECTOR_PRIVATE_SOCKET_ROOT=str(self.root))
        self.child = subprocess.Popen(command, env=environment, start_new_session=True)
        for signum in self.pending_signals:
            self.forward(signum, None)
        return self.child.wait()

    def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
        try:
            if self.child is not None:
                self.safe_to_remove = False
                self.lingering = stop_group(self.child.pid)
                self.child.wait()
                self.safe_to_remove = True
        except (OSError, ValueError, RuntimeError):
            print(f"retained private socket root: {self.root}", file=sys.stderr)
            raise
        finally:
            for signum, handler in self.previous_handlers.items():
                signal.signal(signum, handler)


def run(command: list[str], parent: Path) -> int:
    """Supervise a trusted internal command under an explicitly selected parent."""
    root = private_socket_root(parent)
    processes = StageProcessGroup(root)
    try:
        with processes:
            status = processes.execute(command)
        if processes.lingering and status == 0:
            print("FAIL: connector stage left live processes after exit", file=sys.stderr)
            return 1
        return status if status >= 0 else 128 - status
    finally:
        if processes.safe_to_remove:
            shutil.rmtree(root)


def stage_command(connector: str, stage: str) -> list[str]:
    """Build a fixed repository stage command from closed literal choices."""
    if connector == "envoy":
        selected_connector = "envoy"
    elif connector == "traefik":
        selected_connector = "traefik"
    else:
        raise ValueError("unsupported private socket connector")
    if stage == "start_smoke":
        selected_stage = "start_smoke"
    elif stage == "minimal_runtime_smoke":
        selected_stage = "minimal_runtime_smoke"
    elif stage == "no_crs_baseline":
        selected_stage = "no_crs_baseline"
    else:
        raise ValueError("unsupported private socket stage")
    return ["/bin/sh", str(Path(__file__).resolve().with_name("run-connector-stage.sh")),
            selected_connector, selected_stage]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--socket-parent", type=Path, required=True)
    parser.add_argument("--connector", choices=("envoy", "traefik"), required=True)
    parser.add_argument("--stage", choices=("start_smoke", "minimal_runtime_smoke", "no_crs_baseline"), required=True)
    args = parser.parse_args(argv)
    try:
        return run(stage_command(args.connector, args.stage), args.socket_parent)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"FAIL: private socket stage: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
