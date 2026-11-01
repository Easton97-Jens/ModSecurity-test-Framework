#!/usr/bin/env python3
"""Read a Framework-generated NGINX case environment without shell evaluation.

The ordinary harness keeps compatibility with the Framework's shell fragment.
The GitHub-hosted functional-A root path instead reads each bounded value through
this parser through an inherited directory capability.  Generated content is
therefore never sourced or passed to ``eval`` while the NGINX master is being
exercised as root.
"""

from __future__ import annotations

import argparse
import os
import shlex
import stat
import sys


_MAX_ENV_BYTES = 16 * 1024
_MAX_VALUE_BYTES = 4096
_CASE_ENVIRONMENT_PARTS = ("conf", "case.env")
# The root Functional-A harness opens only its already validated, freshly
# private runtime directory on this descriptor.  The reader deliberately has
# no path-valued CLI or environment input: possession of this descriptor is
# the capability to read the fixed generated record below it.
_FUNCTIONAL_RUNTIME_ROOT_DESCRIPTOR = 3
_ALLOWED_KEYS = frozenset(
    {
        "CASE_NAME",
        "REQUEST_METHOD",
        "REQUEST_PATH",
        "REQUEST_HAS_BODY",
        "REQUEST_HEADERS_FILE",
        "REQUEST_BODY_FILE",
        "AUDIT_LOG_FILE",
        "AUDIT_LOG_DIR",
        "EXPECT_STATUS",
        "EXPECT_INTERVENTION",
        "EXPECT_RULE_ID",
        "EXPECT_RESPONSE_CONTAINS",
        "EXPECT_TRANSPORT",
        "EXPECT_AUDIT_LOG_REQUIRED",
        "NGINX_PHASE4_MODE",
    }
)
_HEADER = "# Generated from common test case. Do not edit."


class CaseEnvironmentError(ValueError):
    """The generated case fragment is not a complete bounded data record."""


def _reject_control_characters(value: str, *, key: str) -> None:
    if any(character in value for character in ("\x00", "\r", "\n")):
        raise CaseEnvironmentError(f"{key} contains a forbidden control character")
    if len(value.encode("utf-8")) > _MAX_VALUE_BYTES:
        raise CaseEnvironmentError(f"{key} exceeds the bounded value size")


def _directory_flags() -> int:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise CaseEnvironmentError("case environment requires no-follow directory support")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | no_follow


def _require_private_owned_directory(descriptor: int, *, name: str) -> None:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o022
    ):
        raise CaseEnvironmentError(f"{name} is not a private owner-controlled directory")


def _read_bounded_regular_file(descriptor: int) -> bytes:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_mode & 0o022
        or before.st_nlink != 1
        or before.st_size > _MAX_ENV_BYTES
    ):
        raise CaseEnvironmentError("case environment is not a bounded private regular file")

    content = bytearray()
    while True:
        remaining = _MAX_ENV_BYTES + 1 - len(content)
        block = os.read(descriptor, min(4096, remaining))
        if not block:
            break
        content.extend(block)
        if len(content) > _MAX_ENV_BYTES:
            raise CaseEnvironmentError("case environment exceeds the bounded file size")

    after = os.fstat(descriptor)
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        raise CaseEnvironmentError("case environment changed while being read")
    return bytes(content)


def _read_private_case_environment(runtime_root_descriptor: int) -> bytes:
    root_descriptor = -1
    conf_descriptor = -1
    environment_descriptor = -1
    try:
        root_descriptor = os.dup(runtime_root_descriptor)
        _require_private_owned_directory(root_descriptor, name="runtime root")
        conf_descriptor = os.open(_CASE_ENVIRONMENT_PARTS[0], _directory_flags(), dir_fd=root_descriptor)
        _require_private_owned_directory(conf_descriptor, name="runtime configuration directory")
        environment_descriptor = os.open(
            _CASE_ENVIRONMENT_PARTS[1],
            os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=conf_descriptor,
        )
        return _read_bounded_regular_file(environment_descriptor)
    except OSError as error:
        raise CaseEnvironmentError(f"cannot open private case environment: {error}") from error
    finally:
        for descriptor in (environment_descriptor, conf_descriptor, root_descriptor):
            if descriptor >= 0:
                os.close(descriptor)


def _parse_case_environment_value(rendered: str, *, key: str, line_number: int) -> str:
    try:
        tokens = shlex.split(rendered, posix=True, comments=False)
    except ValueError as error:
        raise CaseEnvironmentError(
            f"invalid shell quoting for {key} at {line_number}"
        ) from error
    if len(tokens) != 1:
        raise CaseEnvironmentError(
            f"{key} at {line_number} must contain exactly one quoted value"
        )
    value = tokens[0]
    _reject_control_characters(value, key=key)
    return value


def _parse_case_environment_line(
    line: str, *, line_number: int, values: dict[str, str], saw_header: bool
) -> bool:
    if not line:
        raise CaseEnvironmentError(f"blank line at {line_number} is not permitted")
    if line.startswith("#"):
        if saw_header or line != _HEADER or line_number != 1:
            raise CaseEnvironmentError(f"unexpected comment at {line_number}")
        return True
    if "=" not in line:
        raise CaseEnvironmentError(f"missing assignment at {line_number}")
    key, rendered = line.split("=", 1)
    if key not in _ALLOWED_KEYS:
        raise CaseEnvironmentError(f"unexpected key at {line_number}: {key!r}")
    if key in values:
        raise CaseEnvironmentError(f"duplicate key at {line_number}: {key}")
    values[key] = _parse_case_environment_value(rendered, key=key, line_number=line_number)
    return saw_header


def read_case_environment_from_descriptor(runtime_root_descriptor: int) -> dict[str, str]:
    """Return the fixed no-follow ``conf/case.env`` below one open root descriptor."""

    raw = _read_private_case_environment(runtime_root_descriptor)
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CaseEnvironmentError("case environment is not UTF-8") from error

    values: dict[str, str] = {}
    saw_header = False
    for line_number, line in enumerate(content.splitlines(), start=1):
        saw_header = _parse_case_environment_line(
            line, line_number=line_number, values=values, saw_header=saw_header
        )
    if not saw_header:
        raise CaseEnvironmentError("case environment lacks the generated-file header")
    missing = sorted(_ALLOWED_KEYS.difference(values))
    if missing:
        raise CaseEnvironmentError(f"case environment is missing required keys: {', '.join(missing)}")
    return values


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key", required=True, choices=sorted(_ALLOWED_KEYS))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        value = read_case_environment_from_descriptor(
            _FUNCTIONAL_RUNTIME_ROOT_DESCRIPTOR
        )[args.key]
    except CaseEnvironmentError as error:
        print(f"nginx case environment rejected: {error}", file=sys.stderr)
        return 2
    print(value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
