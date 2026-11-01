#!/usr/bin/env python3
"""Launch the No-CRS fixture through a trusted private namespace boundary.

Only pre-installed, root-owned system programs run before the connector
harness. ``/usr/bin/unshare`` first creates a one-identity user/mount/PID
namespace and makes its mount propagation private. A fixed ``dash`` command
then mounts a bounded ``nosuid,nodev,noexec`` tmpfs at ``/tmp`` *inside that
private namespace only*. ``/usr/bin/bwrap`` builds the final minimal filesystem
view, disables further user namespaces, and clears every capability set before
it invokes worktree code. The fixture is released by namespace teardown, never
by a host-side path-based directory deletion.

The launcher deliberately refuses a host-root or set-id caller. A missing
system binary, unavailable namespace primitive, malformed setup attestation,
or non-zero final capability state is a fail-closed ``BLOCKED`` condition.
There is no sudo route and no fallback to the former check-then-``rmdir``
cleanup design.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root

import argparse
import ctypes
from dataclasses import dataclass
import errno
import json
import os
from pathlib import Path
import select
import signal
import stat
import sys
import time
from typing import Mapping, Sequence




from modsecurity_connector_ci.lib.verified_run_id import VerifiedRunIdError, validate_verified_run_id  # noqa: E402


EXIT_BLOCKED = 77
EXIT_TIMEOUT = 124
DEFAULT_TIMEOUT_SECONDS = 300.0
MAX_TIMEOUT_SECONDS = 900.0
SETUP_TIMEOUT_SECONDS = 10.0
CHILD_STOP_TIMEOUT_SECONDS = 5.0
MAX_ARGUMENTS = 64
MAX_ARGUMENT_LENGTH = 16384
_ROOT = Path(os.sep)
SYSTEM_BIN_ROOT = (_ROOT / 'usr/bin')
SYSTEM_LINKED_BIN_ROOT = (_ROOT / 'bin')
PRIVATE_TMPFS_MOUNT = (_ROOT / 'tmp')
SAFE_PATH = os.pathsep.join(
    str(root)
    for root in (
        (_ROOT / 'usr/local/sbin'),
        (_ROOT / 'usr/local/bin'),
        (_ROOT / 'usr/sbin'),
        SYSTEM_BIN_ROOT,
        (_ROOT / 'sbin'),
        SYSTEM_LINKED_BIN_ROOT,
    )
)

TRUSTED_UNSHARE = SYSTEM_BIN_ROOT / "unshare"
TRUSTED_BWRAP = SYSTEM_BIN_ROOT / "bwrap"
TRUSTED_DASH = SYSTEM_BIN_ROOT / "dash"
TRUSTED_MOUNT = SYSTEM_BIN_ROOT / "mount"
TRUSTED_PYTHON = SYSTEM_BIN_ROOT / "python3"
FIXTURE_ROOT = PRIVATE_TMPFS_MOUNT / "msconnector-lighttpd-no-crs-fixture"

# This string is passed as a single, immutable argv element to the root-owned
# shell. The unprivileged launcher never executes worktree code while the
# outer user namespace has CAP_SYS_ADMIN. Its only caller-independent operation
# is the tmpfs mount followed by an argv-preserving exec of bwrap. A fixed,
# test-only phase flag is supplied directly by the launcher rather than copied
# from the caller environment.
PRIVATE_TMPFS_SETUP = (
    "set -eu; "
    'if [ "${LIGHTTPD_NAMESPACE_PROBE_PHASES-}" = "1" ]; then '
    'printf "%s\\n" "lighttpd_no_crs_fixture_namespace: probe phase outer-unshare-entered" >&2; fi; '
    f"{TRUSTED_MOUNT} -t tmpfs -o mode=0755,nosuid,nodev,noexec,size=64m "
    f"tmpfs {PRIVATE_TMPFS_MOUNT}; "
    'if [ "${LIGHTTPD_NAMESPACE_PROBE_PHASES-}" = "1" ]; then '
    'printf "%s\\n" "lighttpd_no_crs_fixture_namespace: probe phase outer-tmpfs-mounted" >&2; fi; '
    'if [ "${LIGHTTPD_NAMESPACE_PROBE_PHASES-}" = "1" ]; then '
    'printf "%s\\n" "lighttpd_no_crs_fixture_namespace: probe phase bwrap-exec" >&2; fi; '
    "exec \"$@\""
)

# This verifier is executed by a root-owned system Python only *after* bwrap
# has created the private root, disabled new user namespaces, and dropped all
# capabilities. It is an enforcement boundary, not merely test evidence: no
# worktree harness command is exec'd until every final-state assertion passes.
_FINAL_NAMESPACE_STATE_VERIFIER_TEMPLATE = r'''
import os
from pathlib import Path
import stat
import sys

def blocked(message):
    print(f"lighttpd_no_crs_fixture_namespace: BLOCKED: {message}", file=sys.stderr)
    raise SystemExit(77)

try:
    inherited_descriptors = os.listdir("/proc/self/fd")
except OSError:
    blocked("namespace final verifier cannot inspect inherited descriptors")
for entry in inherited_descriptors:
    try:
        descriptor = int(entry, 10)
    except ValueError:
        continue
    if descriptor < 3:
        continue
    try:
        os.close(descriptor)
    except OSError as error:
        if error.errno != 9:
            blocked("namespace final verifier cannot close inherited descriptor")

if len(sys.argv) < 2 or not os.path.isabs(sys.argv[1]):
    blocked("namespace final verifier has no absolute harness command")

try:
    status = {}
    for row in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
        key, separator, value = row.partition(":")
        if separator:
            status[key] = value.strip()
except OSError:
    blocked("namespace final verifier cannot inspect process status")
for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
    if status.get(field) != "0000000000000000":
        blocked(f"namespace final verifier retained {field}")
if status.get("NoNewPrivs") != "1":
    blocked("namespace final verifier requires no_new_privs")

try:
    rows = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
except OSError:
    blocked("namespace final verifier cannot inspect mountinfo")
matches = []
for row in rows:
    before, separator, after = row.partition(" - ")
    fields = before.split()
    if separator and len(fields) >= 6 and fields[4] == __PRIVATE_TMPFS_MOUNT__:
        matches.append((fields, after.split()))
if len(matches) != 1:
    blocked("namespace final verifier has no unique private tmpfs")
fields, after = matches[0]
if (
    not after
    or after[0] != "tmpfs"
    or not {"nosuid", "nodev", "noexec"}.issubset(set(fields[5].split(",")))
    or any(field.startswith(("shared:", "master:")) for field in fields[6:])
):
    blocked("namespace final verifier private tmpfs is unsafe")

try:
    details = os.lstat(__FIXTURE_ROOT__)
except OSError:
    blocked("namespace final verifier fixture root is unavailable")
if (
    not stat.S_ISDIR(details.st_mode)
    or details.st_uid != os.geteuid()
    or stat.S_IMODE(details.st_mode) != 0o700
):
    blocked("namespace final verifier fixture root is unsafe")
os.environ["LIGHTTPD_NO_CRS_FIXTURE_ROOT_IDENTITY"] = f"{details.st_dev}:{details.st_ino}"
if os.environ.get("LIGHTTPD_NAMESPACE_PROBE_PHASES") == "1":
    print(
        "lighttpd_no_crs_fixture_namespace: probe phase final-state-verified",
        file=sys.stderr,
    )
os.execvpe(sys.argv[1], sys.argv[1:], os.environ)
'''

FINAL_NAMESPACE_STATE_VERIFIER = (
    _FINAL_NAMESPACE_STATE_VERIFIER_TEMPLATE
    .replace("__PRIVATE_TMPFS_MOUNT__", repr(str(PRIVATE_TMPFS_MOUNT)))
    .replace("__FIXTURE_ROOT__", repr(str(FIXTURE_ROOT)))
)

SYSTEM_READONLY_BINDS = (
    Path("/usr"),
    Path("/bin"),
    Path("/sbin"),
    Path("/lib"),
    Path("/lib64"),
    Path("/etc"),
)
MAX_READONLY_BINDS = 16

PR_SET_PDEATHSIG = 1
LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.prctl.argtypes = [
    ctypes.c_int,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
]
LIBC.prctl.restype = ctypes.c_int


class NamespaceUnavailable(RuntimeError):
    """The trusted private namespace boundary cannot be proved available."""


_PROBE_PHASE_PREFIX = "lighttpd_no_crs_fixture_namespace: probe phase "
_PROBE_PHASES = frozenset(
    {
        "runner-start",
        "helper-raised-before-return",
        "helper-returned",
        "caller-identity-validated",
        "trusted-binaries-validated",
        "setup-pipe-created",
        "setup-pipe-inheritable",
        "namespace-command-build-started",
        "namespace-command-built",
        "namespace-fork-started",
        "namespace-child-forked",
        "setup-wait-started",
        "setup-attestation-failed",
        "setup-attested",
        "child-exited-after-setup",
    }
)


def _emit_probe_phase(enabled: bool, phase: str) -> None:
    """Emit only an allowlisted diagnostic phase for the test-only probe."""

    if not enabled:
        return
    if phase not in _PROBE_PHASES:
        raise NamespaceUnavailable("namespace probe phase is invalid")
    print(f"{_PROBE_PHASE_PREFIX}{phase}", file=sys.stderr)


@dataclass(frozen=True)
class CallerIdentity:
    """The sole host identity eligible for the one-identity namespace map."""

    uid: int
    gid: int


@dataclass(frozen=True)
class ProductionRuntimePaths:
    """Validated Parent-owned paths used by the full lifecycle."""

    runtime_root: Path
    smoke_root: Path
    verified_root: Path
    evidence: Path
    parent_host: Path | None
    run_id: str


def _required_environment_value(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name)
    if not value:
        raise NamespaceUnavailable(
            "No-CRS namespace requires Parent-owned Lighttpd runtime roots"
        )
    return value


def _bounded_timeout(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("timeout must be numeric") from error
    if not 0 < parsed <= MAX_TIMEOUT_SECONDS:
        raise argparse.ArgumentTypeError(
            f"timeout must be in the range (0, {MAX_TIMEOUT_SECONDS:g}]"
        )
    return parsed


def _caller_identity() -> CallerIdentity:
    if os.name != "posix" or sys.platform != "linux":
        raise NamespaceUnavailable("No-CRS fixture namespace requires Linux")
    if os.geteuid() == 0 or os.getegid() == 0:
        raise NamespaceUnavailable("No-CRS fixture namespace launcher refuses a host-root caller")
    if os.getuid() != os.geteuid() or os.getgid() != os.getegid():
        raise NamespaceUnavailable("No-CRS fixture namespace launcher refuses set-id callers")
    return CallerIdentity(uid=os.geteuid(), gid=os.getegid())


def _require_root_owned_directory(path: Path) -> None:
    try:
        details = path.lstat()
    except OSError as error:
        raise NamespaceUnavailable(f"cannot inspect trusted directory: {path}") from error
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != 0
        or stat.S_IMODE(details.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise NamespaceUnavailable(f"trusted directory is unsafe: {path}")


def _require_trusted_executable_file(path: Path, details: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != 0
        or stat.S_IMODE(details.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
        or not details.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    ):
        raise NamespaceUnavailable(f"trusted namespace binary {label} is unsafe: {path}")


def _require_trusted_system_executable(path: Path) -> None:
    """Accept only a root-owned, non-writable executable below trusted dirs."""

    if not path.is_absolute() or path.parent not in {SYSTEM_BIN_ROOT, SYSTEM_LINKED_BIN_ROOT}:
        raise NamespaceUnavailable(f"trusted namespace binary path is invalid: {path}")
    for directory in (_ROOT, (_ROOT / 'usr'), SYSTEM_BIN_ROOT):
        _require_root_owned_directory(directory)
    try:
        details = path.lstat()
    except OSError as error:
        raise NamespaceUnavailable(f"trusted namespace binary is unavailable: {path}") from error
    if not stat.S_ISLNK(details.st_mode):
        _require_trusted_executable_file(path, details, "file")
        return
    try:
        resolved = path.resolve(strict=True)
        resolved_details = resolved.lstat()
    except OSError as error:
        raise NamespaceUnavailable(f"trusted namespace binary symlink is unsafe: {path}") from error
    if resolved.parent != SYSTEM_BIN_ROOT:
        raise NamespaceUnavailable(f"trusted namespace binary symlink is unsafe: {path}")
    _require_trusted_executable_file(path, resolved_details, "symlink target")


def _require_trusted_system_binaries() -> None:
    for path in (
        TRUSTED_UNSHARE,
        TRUSTED_BWRAP,
        TRUSTED_DASH,
        TRUSTED_MOUNT,
        TRUSTED_PYTHON,
    ):
        _require_trusted_system_executable(path)


def _require_trusted_system_bind_root(path: Path) -> None:
    """Require a root-owned, non-writable system tree before ro-binding it."""

    try:
        source = path.resolve(strict=True)
    except OSError as error:
        raise NamespaceUnavailable(f"trusted system bind root is unavailable: {path}") from error
    if not source.is_absolute() or (
        source != Path("/etc") and not _is_beneath(source, Path("/usr"))
    ):
        raise NamespaceUnavailable(f"trusted system bind root is outside the fixed system roots: {path}")
    current = source
    while current != current.parent:
        try:
            details = current.lstat()
        except OSError as error:
            raise NamespaceUnavailable(f"cannot inspect trusted system bind root: {path}") from error
        if (
            not stat.S_ISDIR(details.st_mode)
            or details.st_uid != 0
            or stat.S_IMODE(details.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise NamespaceUnavailable(f"trusted system bind root is unsafe: {path}")
        current = current.parent


def _validate_command(command: Sequence[str]) -> list[str]:
    if not command or len(command) > MAX_ARGUMENTS:
        raise NamespaceUnavailable("namespace harness command has an invalid argument count")
    result: list[str] = []
    for index, value in enumerate(command):
        if not isinstance(value, str) or not value or len(value) > MAX_ARGUMENT_LENGTH:
            raise NamespaceUnavailable("namespace harness command has an unsafe argument")
        if "\x00" in value or "\n" in value or "\r" in value:
            raise NamespaceUnavailable("namespace harness command has an unsafe argument")
        if index == 0 and not os.path.isabs(value):
            raise NamespaceUnavailable("namespace harness command must start with an absolute executable")
        result.append(value)
    return result


_FORWARDED_ENVIRONMENT = (
    "BUILD_ROOT",
    "CACHE_ROOT",
    "CONNECTOR_COMPONENT_CACHE",
    "CONNECTOR_ROOT",
    "CONNECTOR_REVISION",
    "FRAMEWORK_ROOT",
    "FULL_LIFECYCLE_EVIDENCE_OUTPUT",
    "FULL_LIFECYCLE_EXECUTED_TARGET",
    "FULL_LIFECYCLE_HOST_PROFILE",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LIGHTTPD_CONFIG_ROOT",
    "LIGHTTPD_CONNECTOR_BUILD_ROOT",
    "LIGHTTPD_EXPOSE_HOST_TRANSACTION_ID",
    "LIGHTTPD_INCLUDE_DIR",
    "LIGHTTPD_LOG_ROOT",
    "LIGHTTPD_MODULE_DIR",
    "LIGHTTPD_PATCHED_ROOT",
    "LIGHTTPD_PATCHED_SMOKE_DIR",
    "LIGHTTPD_RESULT_ROOT",
    "LIGHTTPD_SMOKE_PORT",
    "LOG_ROOT",
    "MODSECURITY_INCLUDE_DIR",
    "MODSECURITY_LIB_DIR",
    "MODSECURITY_PREFIX",
    "MSCONNECTOR_CRS_RUNTIME",
    "MSCONNECTOR_EXPECTED_RULE_ID",
    "MSCONNECTOR_RULES_FILE",
    "NO_CRS_ARTIFACT_PROFILE",
    "NO_CRS_RUN_ID",
    "NO_CRS_SELECTED_CASE_IDS",
    "PARENT_HOST_RUNTIME_ROOT",
    "PYTHON",
    "RESULTS_DIR",
    "RUNTIME_BASE",
    "RUNTIME_ROOT",
    "TMP_ROOT",
    "VERIFIED_RUN_ROOT",
)


def _child_environment(
    base: Mapping[str, str], *, emit_probe_phase_markers: bool = False
) -> dict[str, str]:
    """Forward only bounded data values after bwrap clears the environment."""

    result = {
        "PATH": SAFE_PATH,
        "HOME": str(PRIVATE_TMPFS_MOUNT),
        "TMPDIR": str(PRIVATE_TMPFS_MOUNT),
        "TMP": str(PRIVATE_TMPFS_MOUNT),
        "TEMP": str(PRIVATE_TMPFS_MOUNT),
        "LIGHTTPD_NO_CRS_FIXTURE_ROOT": str(FIXTURE_ROOT),
        "LIGHTTPD_NO_CRS_FIXTURE_NAMESPACE_ACTIVE": "1",
        "TEST_ROOT": str(_repository_root()),
        "PYTHONPATH": os.pathsep.join((str(_repository_root()), str(_repository_root() / "connector_suite"))),
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    for name in _FORWARDED_ENVIRONMENT:
        if name == "HOME":
            continue
        value = base.get(name)
        if value is None:
            continue
        if not isinstance(value, str) or len(value) > MAX_ARGUMENT_LENGTH:
            raise NamespaceUnavailable(f"namespace environment value for {name} is unsafe")
        if "\x00" in value or "\n" in value or "\r" in value:
            raise NamespaceUnavailable(f"namespace environment value for {name} is unsafe")
        result[name] = value
    if emit_probe_phase_markers:
        result["LIGHTTPD_NAMESPACE_PROBE_PHASES"] = "1"
    return result


def _production_runtime_paths(environment: Mapping[str, str]) -> ProductionRuntimePaths:
    try:
        run_id = validate_verified_run_id(
            _required_environment_value(environment, "NO_CRS_RUN_ID")
        )
    except VerifiedRunIdError as error:
        raise NamespaceUnavailable("No-CRS namespace run ID is unsafe") from error
    paths = ProductionRuntimePaths(
        runtime_root=_normalized_production_path(environment, "RUNTIME_ROOT"),
        smoke_root=_normalized_production_path(
            environment, "LIGHTTPD_PATCHED_SMOKE_DIR"
        ),
        verified_root=_normalized_production_path(environment, "VERIFIED_RUN_ROOT"),
        evidence=_normalized_production_path(
            environment, "FULL_LIFECYCLE_EVIDENCE_OUTPUT"
        ),
        parent_host=_normalized_production_path(
            environment, "PARENT_HOST_RUNTIME_ROOT"
        )
        if environment.get("PARENT_HOST_RUNTIME_ROOT")
        else None,
        run_id=run_id,
    )
    return paths


def _normalized_production_path(environment: Mapping[str, str], name: str) -> Path:
    """Accept one absolute runtime path without lexical parent traversal.

    The canonical resolver already rejects ``..`` components. Repeat that
    boundary here because these values determine the sole writable bwrap bind;
    accepting a lexically equivalent parent path would let normalization widen
    the intended Parent-owned runtime namespace.
    """

    path = Path(_required_environment_value(environment, name))
    if not path.is_absolute() or ".." in path.parts:
        raise NamespaceUnavailable("No-CRS namespace runtime roots must be normalized absolute paths")
    return path


def _expected_production_smoke_root(paths: ProductionRuntimePaths) -> Path:
    with_crs_smoke = paths.runtime_root / "host"
    # The canonical No-CRS resolver owns this exact connector-run root. Keep
    # the run identifier a validated single segment so a caller cannot widen
    # the only writable namespace bind to a sibling or arbitrary descendant.
    no_crs_smoke = (
        paths.verified_root
        / "runs"
        / "lighttpd"
        / paths.run_id
        / "lighttpd-runtime"
    )
    if paths.smoke_root == with_crs_smoke and paths.parent_host == with_crs_smoke:
        return with_crs_smoke
    if paths.smoke_root == no_crs_smoke and paths.parent_host is None:
        return no_crs_smoke
    raise NamespaceUnavailable("No-CRS namespace writable root is not an exact Parent Lighttpd runtime root")


def _safe_production_writable_root(environment: Mapping[str, str]) -> Path:
    """Materialize exactly the Parent-owned Lighttpd host runtime root.

    bwrap presents the rest of the host root read-only. The one writable bind
    is intentionally the existing Parent runtime output root, never `/tmp`, a
    broad cache, or an arbitrary caller-selected directory.
    """

    paths = _production_runtime_paths(environment)
    expected_smoke = _expected_production_smoke_root(paths)
    if paths.evidence != expected_smoke / "first-byte-evidence.json":
        raise NamespaceUnavailable("No-CRS namespace evidence output is not the exact Parent runtime artifact")
    patched_root_value = environment.get("LIGHTTPD_PATCHED_ROOT")
    if not patched_root_value:
        raise NamespaceUnavailable("No-CRS namespace requires the pinned patched Lighttpd root")
    _require_real_directory(Path(patched_root_value), "patched Lighttpd runtime root")
    try:
        from connector_suite.adapters.lighttpd.harness.safe_runtime_output import verified_runtime_output_root

        verified_runtime_output_root(paths.smoke_root)
    except (ImportError, OSError, ValueError) as error:
        raise NamespaceUnavailable("No-CRS namespace writable root is unsafe") from error
    if paths.smoke_root == PRIVATE_TMPFS_MOUNT or PRIVATE_TMPFS_MOUNT in paths.smoke_root.parents:
        raise NamespaceUnavailable("No-CRS namespace writable root must not overlay private /tmp")
    return paths.smoke_root


def _require_production_harness(command: Sequence[str]) -> None:
    """Accept the one full-lifecycle entrypoint used by the Parent runner."""

    harness = _validate_command(command)
    expected = _repository_root() / "connector_suite/adapters/lighttpd/harness/run_patched_full_lifecycle.sh"
    if len(harness) != 2 or harness[0] != "/bin/sh" or Path(harness[1]) != expected:
        raise NamespaceUnavailable("No-CRS namespace command is not the pinned Parent lifecycle harness")


def _is_beneath(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _require_real_directory(path: Path, label: str) -> Path:
    """Return one absolute, non-symlink directory safe to ro-bind.

    These roots are selected before any capability-bearing setup begins. They
    can only become visible to the harness read-only, while the sole writable
    runtime output root is bound separately after them.
    """

    if not path.is_absolute() or path == Path("/"):
        raise NamespaceUnavailable(f"{label} must be one non-root absolute directory")
    if path == PRIVATE_TMPFS_MOUNT or PRIVATE_TMPFS_MOUNT in path.parents:
        raise NamespaceUnavailable(f"{label} must not use the private tmpfs path")
    try:
        details = path.lstat()
    except OSError as error:
        raise NamespaceUnavailable(f"{label} is unavailable") from error
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
        raise NamespaceUnavailable(f"{label} must be a real directory")
    return path


def _repository_root() -> Path:
    """Return the explicit Framework source root, including for fixture selftests."""
    try:
        root = test_root()
    except (OSError, ValueError) as error:
        raise NamespaceUnavailable("TEST_ROOT must identify the explicit Framework checkout") from error
    return _require_real_directory(root, "Framework test root")


def _readonly_runtime_bind_roots(environment: Mapping[str, str]) -> list[Path]:
    """Build the minimum read-only view required by the full host lifecycle."""

    framework_root = _repository_root()
    candidate_roots = [framework_root]
    if environment.get("CONNECTOR_ROOT"):
        try:
            repository_root = connector_root()
        except (OSError, ValueError) as error:
            raise NamespaceUnavailable("production namespace requires an explicit valid Connector checkout") from error
        _require_expected_connector_root(environment, repository_root)
        candidate_roots.extend(_runtime_bind_candidates(environment, repository_root))
    elif any(environment.get(name) for name in ("FRAMEWORK_ROOT", "LIGHTTPD_PATCHED_ROOT", "RUNTIME_ROOT")):
        raise NamespaceUnavailable("production namespace requires explicit CONNECTOR_ROOT")
    return _deduplicate_runtime_bind_roots(candidate_roots)


def _require_expected_connector_root(
    environment: Mapping[str, str], repository_root: Path
) -> None:
    connector_root = environment.get("CONNECTOR_ROOT")
    if connector_root is not None and Path(connector_root) != repository_root:
        raise NamespaceUnavailable("namespace CONNECTOR_ROOT is not the active Parent checkout")
    framework_root = environment.get("FRAMEWORK_ROOT")
    if framework_root is None or Path(framework_root) != test_root():
        raise NamespaceUnavailable("namespace FRAMEWORK_ROOT is not the explicit Framework test root")


def _runtime_bind_candidates(
    environment: Mapping[str, str], repository_root: Path
) -> list[Path]:
    candidates = [repository_root]
    for name in ("LIGHTTPD_PATCHED_ROOT", "MODSECURITY_LIB_DIR", "MODSECURITY_PREFIX"):
        value = environment.get(name)
        if value:
            candidates.append(Path(value))
    python_value = environment.get("PYTHON")
    if python_value and os.path.isabs(python_value):
        python_path = Path(python_value)
        try:
            resolved_python = python_path.resolve(strict=True)
        except OSError as error:
            raise NamespaceUnavailable("namespace PYTHON is unavailable") from error
        if not _is_beneath(resolved_python, Path("/usr")):
            candidates.append(resolved_python.parent.parent)
    return candidates


def _deduplicate_runtime_bind_roots(candidate_roots: Sequence[Path]) -> list[Path]:
    result: list[Path] = []
    trusted_roots = (*SYSTEM_READONLY_BINDS,)
    for candidate in candidate_roots:
        root = _require_real_directory(Path(os.path.abspath(candidate)), "namespace read-only runtime root")
        if any(_is_beneath(root, trusted) for trusted in trusted_roots):
            continue
        if any(_is_beneath(root, existing) for existing in result):
            continue
        result = [existing for existing in result if not _is_beneath(existing, root)]
        result.append(root)
    if len(result) > MAX_READONLY_BINDS:
        raise NamespaceUnavailable("namespace read-only runtime roots exceed the bounded limit")
    return result


def _namespace_bind_arguments(
    *,
    environment: Mapping[str, str],
    writable_roots: Sequence[Path],
) -> list[str]:
    """Return only fixed system, read-only runtime, tmpfs and output binds."""

    arguments: list[str] = []
    for system_root in SYSTEM_READONLY_BINDS:
        _require_trusted_system_bind_root(system_root)
        arguments.extend(("--ro-bind", str(system_root), str(system_root)))
    for runtime_root in _readonly_runtime_bind_roots(environment):
        arguments.extend(("--ro-bind", str(runtime_root), str(runtime_root)))
    # This is the noexec tmpfs created by the fixed outer system-binary setup,
    # not a host /tmp bind. The bwrap bind keeps its mount flags intact.
    arguments.extend(("--bind", str(PRIVATE_TMPFS_MOUNT), str(PRIVATE_TMPFS_MOUNT)))

    seen: set[Path] = set()
    for root in writable_roots:
        root = Path(root)
        if not root.is_absolute() or root in seen:
            raise NamespaceUnavailable("namespace writable bind root is invalid")
        _require_real_directory(root, "namespace writable runtime root")
        if root == PRIVATE_TMPFS_MOUNT or PRIVATE_TMPFS_MOUNT in root.parents:
            raise NamespaceUnavailable("namespace writable root must not use private /tmp")
        seen.add(root)
        arguments.extend(("--bind", str(root), str(root)))
    return arguments


def build_trusted_namespace_command(
    command: Sequence[str],
    *,
    environment: Mapping[str, str],
    writable_roots: Sequence[Path] = (),
    info_descriptor: int | None = None,
    emit_probe_phase_markers: bool = False,
) -> list[str]:
    """Build the fixed system-binary-only setup chain.

    The outer ``unshare`` performs the explicit propagation change before it
    executes bwrap. bwrap owns the only capability-bearing inner setup and
    clears its bounding set before the supplied command is reached.
    """

    harness = _validate_command(command)
    child_environment = _child_environment(
        environment, emit_probe_phase_markers=emit_probe_phase_markers
    )
    binds = _namespace_bind_arguments(
        environment=environment,
        writable_roots=writable_roots,
    )
    if info_descriptor is None or info_descriptor < 3:
        raise NamespaceUnavailable("namespace setup attestation descriptor is invalid")

    bwrap = [
        str(TRUSTED_BWRAP),
        "--unshare-user",
        "--unshare-pid",
        "--disable-userns",
        "--assert-userns-disabled",
        "--die-with-parent",
        "--new-session",
        *binds,
        # bwrap creates the fixed root while it still owns the namespace
        # setup. Harness code receives only this private, mode-0700 child.
        "--dir",
        str(FIXTURE_ROOT),
        "--chmod",
        "0700",
        str(FIXTURE_ROOT),
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--uid",
        "0",
        "--gid",
        "0",
        "--cap-drop",
        "ALL",
        "--info-fd",
        str(info_descriptor),
        "--clearenv",
    ]
    for name, value in sorted(child_environment.items()):
        bwrap.extend(("--setenv", name, value))
    bwrap.extend(("--", str(TRUSTED_PYTHON), "-c", FINAL_NAMESPACE_STATE_VERIFIER, *harness))
    return [
        str(TRUSTED_UNSHARE),
        "--user",
        "--map-root-user",
        "--mount",
        "--pid",
        "--fork",
        "--kill-child=SIGKILL",
        "--mount-proc=/proc",
        "--propagation",
        "private",
        str(TRUSTED_DASH),
        "-c",
        PRIVATE_TMPFS_SETUP,
        "lighttpd-no-crs-private-tmpfs",
        *bwrap,
    ]


def _linux_prctl(option: int, first: int, label: str) -> None:
    if LIBC.prctl(option, first, 0, 0, 0) == 0:
        return
    error = ctypes.get_errno()
    raise NamespaceUnavailable(f"{label} is unavailable: {os.strerror(error)}")


def _arm_parent_death_signal() -> None:
    """Reject the small parent-death setup race before execing unshare."""

    parent = os.getppid()
    if parent <= 1:
        raise NamespaceUnavailable("namespace supervisor has no live parent")
    _linux_prctl(PR_SET_PDEATHSIG, signal.SIGKILL, "parent-death signal setup")
    if os.getppid() != parent:
        raise NamespaceUnavailable("namespace supervisor disappeared during parent-death setup")


def _seal_inherited_descriptors(kept: set[int]) -> None:
    """Prevent caller-provided descriptors crossing the privileged setup edge."""

    try:
        entries = os.listdir("/proc/self/fd")
    except OSError as error:
        raise NamespaceUnavailable("cannot inspect inherited namespace descriptors") from error
    for entry in entries:
        try:
            descriptor = int(entry, 10)
        except ValueError:
            continue
        if descriptor in kept:
            continue
        try:
            os.set_inheritable(descriptor, False)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise NamespaceUnavailable("cannot seal inherited namespace descriptor") from error


def _require_setup_child_running(child: int) -> None:
    try:
        pid, _status = os.waitpid(child, os.WNOHANG)
    except ChildProcessError:
        raise NamespaceUnavailable("namespace setup child disappeared") from None
    if pid == child:
        raise NamespaceUnavailable("trusted namespace setup did not attest readiness")


def _parse_setup_attestation(payload: bytearray) -> bool:
    try:
        record = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    valid = (
        isinstance(record, dict)
        and isinstance(record.get("child-pid"), int)
        and record["child-pid"] > 0
        and isinstance(record.get("mnt-namespace"), int)
        and record["mnt-namespace"] > 0
        and isinstance(record.get("pid-namespace"), int)
        and record["pid-namespace"] > 0
    )
    if not valid:
        raise NamespaceUnavailable("trusted namespace setup attestation is invalid")
    return True


def _read_setup_attestation(descriptor: int, child: int) -> None:
    """Require bwrap's setup record before treating later exits as harness exits."""

    deadline = time.monotonic() + SETUP_TIMEOUT_SECONDS
    payload = bytearray()
    try:
        while time.monotonic() < deadline:
            ready, _write, _error = select.select([descriptor], [], [], 0.05)
            if not ready:
                _require_setup_child_running(child)
                continue
            chunk = os.read(descriptor, 4096)
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > 16384:
                raise NamespaceUnavailable("trusted namespace setup attestation is too large")
            if _parse_setup_attestation(payload):
                return
    finally:
        os.close(descriptor)
    raise NamespaceUnavailable("trusted namespace setup attestation timed out")


def _terminate_and_reap(child: int) -> None:
    """Bounded process-group cleanup for the direct trusted unshare child."""

    try:
        pid, _status = os.waitpid(child, os.WNOHANG)
    except ChildProcessError:
        return
    if pid == child:
        return
    for signum in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(child, signum)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + CHILD_STOP_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            try:
                pid, _status = os.waitpid(child, os.WNOHANG)
            except ChildProcessError:
                return
            if pid == child:
                return
            time.sleep(0.05)
    raise NamespaceUnavailable("trusted namespace supervisor did not stop after bounded SIGTERM/SIGKILL")


def _wait_for_child(child: int, timeout_seconds: float) -> int:
    """Wait boundedly and preserve a caller signal as a regular cleanup case."""

    deadline = time.monotonic() + timeout_seconds
    interruption: list[int] = []

    def record_signal(signum: int, _frame: object) -> None:
        interruption.append(signum)

    previous = {
        signum: signal.signal(signum, record_signal)
        for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
    }
    try:
        while True:
            pid, status = os.waitpid(child, os.WNOHANG)
            if pid == child:
                return os.waitstatus_to_exitcode(status)
            if interruption:
                _terminate_and_reap(child)
                return 128 + interruption[0]
            if time.monotonic() >= deadline:
                _terminate_and_reap(child)
                return EXIT_TIMEOUT
            time.sleep(0.05)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def _exec_namespace_child(
    setup_read: int,
    setup_write: int,
    arguments: Sequence[str],
    *,
    emit_probe_phase_markers: bool,
) -> None:
    """Enter the supervisor chain, preserving fail-closed child exits."""

    try:
        os.close(setup_read)
        os.setsid()
        _arm_parent_death_signal()
        _seal_inherited_descriptors({0, 1, 2, setup_write})
        child_environment = {"PATH": SAFE_PATH}
        if emit_probe_phase_markers:
            child_environment["LIGHTTPD_NAMESPACE_PROBE_PHASES"] = "1"
        os.execve(str(TRUSTED_UNSHARE), arguments, child_environment)
    except NamespaceUnavailable as error:
        print(f"No-CRS namespace blocked: {error}", file=sys.stderr)
        os._exit(EXIT_BLOCKED)
    except Exception as error:
        print(f"No-CRS namespace setup failed: {error}", file=sys.stderr)
        os._exit(126)


def run_isolated(
    command: Sequence[str],
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    environment: Mapping[str, str] | None = None,
    writable_roots: Sequence[Path] = (),
    emit_probe_phase_markers: bool = False,
) -> int:
    """Run after the trusted setup boundary as the invoking non-root identity."""

    _caller_identity()
    _emit_probe_phase(emit_probe_phase_markers, "caller-identity-validated")
    if not 0 < timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise NamespaceUnavailable("namespace timeout is invalid")
    _require_trusted_system_binaries()
    _emit_probe_phase(emit_probe_phase_markers, "trusted-binaries-validated")
    setup_read, setup_write = os.pipe()
    _emit_probe_phase(emit_probe_phase_markers, "setup-pipe-created")
    os.set_inheritable(setup_write, True)
    _emit_probe_phase(emit_probe_phase_markers, "setup-pipe-inheritable")
    child = -1
    try:
        _emit_probe_phase(emit_probe_phase_markers, "namespace-command-build-started")
        arguments = build_trusted_namespace_command(
            command,
            environment=os.environ if environment is None else environment,
            writable_roots=writable_roots,
            info_descriptor=setup_write,
            emit_probe_phase_markers=emit_probe_phase_markers,
        )
        _emit_probe_phase(emit_probe_phase_markers, "namespace-command-built")
        _emit_probe_phase(emit_probe_phase_markers, "namespace-fork-started")
        child = os.fork()
        if child == 0:
            _exec_namespace_child(
                setup_read,
                setup_write,
                arguments,
                emit_probe_phase_markers=emit_probe_phase_markers,
            )
        _emit_probe_phase(emit_probe_phase_markers, "namespace-child-forked")
        os.close(setup_write)
        setup_write = -1
        _emit_probe_phase(emit_probe_phase_markers, "setup-wait-started")
        try:
            _read_setup_attestation(setup_read, child)
        except (Exception, KeyboardInterrupt, SystemExit):
            _emit_probe_phase(emit_probe_phase_markers, "setup-attestation-failed")
            raise
        setup_read = -1
        _emit_probe_phase(emit_probe_phase_markers, "setup-attested")
        status = _wait_for_child(child, timeout_seconds)
        if status != 0:
            _emit_probe_phase(emit_probe_phase_markers, "child-exited-after-setup")
        return status
    except (Exception, KeyboardInterrupt, SystemExit):
        if child > 0:
            _terminate_and_reap(child)
        raise
    finally:
        for descriptor in (setup_read, setup_write):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout-seconds", type=_bounded_timeout, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args(argv)
    if not arguments.command or arguments.command[0] != "--":
        parser.error("one absolute harness command must follow --")
    arguments.command = arguments.command[1:]
    if not arguments.command or not os.path.isabs(arguments.command[0]):
        parser.error("the harness command must be absolute")
    return arguments


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        writable_root = _safe_production_writable_root(os.environ)
        _require_production_harness(arguments.command)
        return run_isolated(
            arguments.command,
            timeout_seconds=arguments.timeout_seconds,
            writable_roots=(writable_root,),
        )
    except NamespaceUnavailable as error:
        print(f"lighttpd_no_crs_fixture_namespace: BLOCKED: {error}", file=sys.stderr)
        return EXIT_BLOCKED
    except (OSError, RuntimeError, ValueError) as error:
        print(f"lighttpd_no_crs_fixture_namespace: FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
