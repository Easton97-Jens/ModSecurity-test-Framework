#!/usr/bin/env python3
"""Resolve and safely apply reviewed stable CPython 3.13 patch updates.

The updater deliberately trusts only the documented, public Python.org JSON
endpoint.  It does not consume a GitHub token, follow redirects, scrape HTML,
or update anything except the Framework-root ``.python-version`` file.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Callable, Protocol
from urllib import error, request
from urllib.parse import urlsplit


CANONICAL_VERSION_FILE = ".python-version"
METADATA_URL = "https://www.python.org/api/v2/downloads/release/"
METADATA_HOST = "www.python.org"
METADATA_PATH = "/api/v2/downloads/release/"
MAX_METADATA_BYTES = 1_000_000
DEFAULT_TIMEOUT_SECONDS = 20.0
MAX_TIMEOUT_SECONDS = 60.0
VERSION_PATTERN = re.compile(r"^3\.13\.(0|[1-9][0-9]*)$")
RELEASE_NAME_PATTERN = re.compile(r"^Python 3\.13\.(0|[1-9][0-9]*)$")
LEADING_ZERO_RELEASE_PATTERN = re.compile(r"^Python 3\.13\.0[0-9]+$")
RELEASE_DATE_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$"
)
SUCCESS_STATUSES = {"current", "update_available"}


class UpdaterFailure(Exception):
    """A fail-closed updater error with a documented status."""

    def __init__(self, status: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class ResponseLike(Protocol):
    status: int
    headers: Any

    def geturl(self) -> str: ...

    def read(self, amount: int = -1) -> bytes: ...

    def close(self) -> None: ...


OpenUrl = Callable[[request.Request, float], ResponseLike]


@dataclass(frozen=True, order=True)
class PythonVersion:
    patch: int

    @property
    def text(self) -> str:
        return f"3.13.{self.patch}"

    @classmethod
    def parse(cls, value: str) -> "PythonVersion":
        match = VERSION_PATTERN.fullmatch(value)
        if match is None:
            raise UpdaterFailure(
                "invalid_current_version",
                "the canonical version must be an exact stable 3.13.<numeric patch>",
            )
        return cls(patch=int(match.group(1)))


@dataclass(frozen=True)
class UpdateResult:
    status: str
    current: str | None
    candidate: str | None
    message: str
    source: str = METADATA_URL
    updated: bool = False

    def as_json(self) -> dict[str, object]:
        return asdict(self)


class NoRedirectHandler(request.HTTPRedirectHandler):
    """Reject every redirect instead of changing the metadata authority."""

    def redirect_request(
        self,
        req: request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> request.Request:
        raise error.HTTPError(req.full_url, code, "redirects are forbidden", headers, fp)


def framework_root() -> Path:
    return Path(__file__).resolve().parents[2]


def canonical_version_path(root: Path) -> Path:
    return root / CANONICAL_VERSION_FILE


def require_regular_file(path: Path, description: str) -> os.stat_result:
    try:
        details = path.lstat()
    except OSError as exc:
        raise UpdaterFailure("invalid_current_version", f"{description} is unavailable") from exc
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
        raise UpdaterFailure(
            "invalid_current_version", f"{description} must be a regular non-symlink file"
        )
    return details


def read_canonical_version(root: Path) -> PythonVersion:
    path = canonical_version_path(root)
    require_regular_file(path, CANONICAL_VERSION_FILE)
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise UpdaterFailure(
            "invalid_current_version", "the canonical version file cannot be decoded"
        ) from exc
    if not content.endswith("\n") or content.count("\n") != 1:
        raise UpdaterFailure(
            "invalid_current_version",
            "the canonical version file must contain exactly one newline-terminated value",
        )
    return PythonVersion.parse(content[:-1])


def validate_metadata_url(url: str) -> None:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise UpdaterFailure("blocked_metadata", "metadata URL has an invalid port") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != METADATA_HOST
        or port not in {None, 443}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != METADATA_PATH
        or parsed.query
        or parsed.fragment
    ):
        raise UpdaterFailure("blocked_metadata", "metadata URL is outside the trusted endpoint")


def default_open_url(http_request: request.Request, timeout: float) -> ResponseLike:
    opener = request.build_opener(NoRedirectHandler())
    return opener.open(http_request, timeout=timeout)


def response_content_type(response: ResponseLike) -> str:
    headers = response.headers
    if hasattr(headers, "get_content_type"):
        return str(headers.get_content_type()).lower()
    if hasattr(headers, "get"):
        return str(headers.get("Content-Type", "")).split(";", 1)[0].lower()
    return ""


def fetch_release_metadata(
    *, timeout: float = DEFAULT_TIMEOUT_SECONDS, opener: OpenUrl | None = None
) -> list[dict[str, object]]:
    """Fetch the fixed endpoint with bounded input and no redirects."""

    validate_metadata_url(METADATA_URL)
    http_request = request.Request(
        METADATA_URL,
        headers={
            "Accept": "application/json",
            "User-Agent": "ModSecurity-test-Framework-python-version-updater/1",
        },
        method="GET",
    )
    open_url = opener or default_open_url
    response: ResponseLike | None = None
    try:
        response = open_url(http_request, timeout)
        if response.status != 200:
            raise UpdaterFailure(
                "blocked_metadata", f"metadata endpoint returned HTTP {response.status}"
            )
        if response.geturl() != METADATA_URL:
            raise UpdaterFailure("blocked_metadata", "metadata endpoint attempted a redirect")
        if response_content_type(response) != "application/json":
            raise UpdaterFailure("unsupported_response", "metadata response is not JSON")
        payload = response.read(MAX_METADATA_BYTES + 1)
    except UpdaterFailure:
        raise
    except error.HTTPError as exc:
        status = "blocked_network" if exc.code in {408, 429, 500, 502, 503, 504} else "blocked_metadata"
        raise UpdaterFailure(status, f"metadata request returned HTTP {exc.code}") from exc
    except (error.URLError, TimeoutError, OSError) as exc:
        raise UpdaterFailure("blocked_network", "metadata request could not be completed") from exc
    finally:
        if response is not None:
            response.close()

    if not isinstance(payload, bytes) or len(payload) > MAX_METADATA_BYTES:
        raise UpdaterFailure("unsupported_response", "metadata response exceeds its byte limit")
    try:
        decoded = payload.decode("utf-8")
        parsed = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdaterFailure("unsupported_response", "metadata response is not valid UTF-8 JSON") from exc
    if not isinstance(parsed, list):
        raise UpdaterFailure("unsupported_response", "metadata response must be a JSON array")
    if not all(isinstance(record, dict) for record in parsed):
        raise UpdaterFailure("unsupported_response", "metadata response contains a non-object record")
    return [dict(record) for record in parsed]


def stable_313_releases(records: list[dict[str, object]]) -> dict[int, PythonVersion]:
    """Select published, non-prerelease stable 3.13 releases from strict records."""

    releases: dict[int, PythonVersion] = {}
    for record in records:
        name = record.get("name")
        if not isinstance(name, str):
            raise UpdaterFailure("unsupported_response", "metadata release name is missing")
        if LEADING_ZERO_RELEASE_PATTERN.fullmatch(name):
            raise UpdaterFailure("unsupported_response", "metadata release uses a leading-zero patch")
        match = RELEASE_NAME_PATTERN.fullmatch(name)
        if match is None:
            continue
        is_published = record.get("is_published")
        is_prerelease = record.get("pre_release")
        if type(is_published) is not bool or type(is_prerelease) is not bool:
            raise UpdaterFailure("unsupported_response", "metadata release flags are invalid")
        if not is_published or is_prerelease:
            continue
        patch = int(match.group(1))
        expected_slug = f"python-313{patch}"
        if record.get("slug") != expected_slug:
            raise UpdaterFailure("unsupported_response", "metadata release slug is inconsistent")
        release_date = record.get("release_date")
        if not isinstance(release_date, str) or not RELEASE_DATE_PATTERN.fullmatch(release_date):
            raise UpdaterFailure("unsupported_response", "metadata release date is invalid")
        if patch in releases:
            raise UpdaterFailure("unsupported_response", "metadata contains duplicate stable releases")
        releases[patch] = PythonVersion(patch=patch)
    return releases


def resolve_update(
    root: Path, *, timeout: float = DEFAULT_TIMEOUT_SECONDS, opener: OpenUrl | None = None
) -> UpdateResult:
    """Return a no-write status for the local canonical version and official metadata."""

    try:
        current = read_canonical_version(root)
    except UpdaterFailure as exc:
        return UpdateResult(exc.status, None, None, exc.message)
    try:
        releases = stable_313_releases(fetch_release_metadata(timeout=timeout, opener=opener))
    except UpdaterFailure as exc:
        return UpdateResult(exc.status, current.text, None, exc.message)
    if not releases:
        return UpdateResult(
            "no_stable_3_13_release",
            current.text,
            None,
            "metadata contains no published stable CPython 3.13 release",
        )
    latest = releases[max(releases)]
    if latest < current:
        return UpdateResult(
            "downgrade_detected",
            current.text,
            latest.text,
            "official metadata would downgrade the reviewed Python version",
        )
    if latest == current:
        return UpdateResult("current", current.text, None, "the reviewed Python version is current")
    return UpdateResult(
        "update_available",
        current.text,
        latest.text,
        "a newer published stable CPython 3.13 patch is available",
    )


def require_expected_candidate(result: UpdateResult, expected: str | None) -> UpdateResult:
    if expected is None:
        return result
    try:
        expected_version = PythonVersion.parse(expected)
    except UpdaterFailure:
        return UpdateResult(
            "blocked_metadata",
            result.current,
            result.candidate,
            "the expected candidate is not an exact stable CPython 3.13 patch",
        )
    if result.status != "update_available" or result.candidate != expected_version.text:
        return UpdateResult(
            "blocked_metadata",
            result.current,
            result.candidate,
            "the expected candidate does not match freshly resolved official metadata",
        )
    return result


def atomic_write_canonical_version(root: Path, expected: PythonVersion, candidate: PythonVersion) -> None:
    """Atomically replace only the canonical non-symlink file after a stale check."""

    path = canonical_version_path(root)
    original_mode = stat.S_IMODE(require_regular_file(path, CANONICAL_VERSION_FILE).st_mode)
    try:
        observed = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise UpdaterFailure("blocked_metadata", "cannot re-read the canonical version") from exc
    if observed != f"{expected.text}\n":
        raise UpdaterFailure("blocked_metadata", "the canonical version changed during update")
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=root, prefix=".python-version.", suffix=".tmp", text=False
        )
    except OSError as exc:
        raise UpdaterFailure("blocked_metadata", "cannot create a local update file") from exc
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, original_mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(f"{candidate.text}\n".encode("ascii"))
            stream.flush()
            os.fsync(stream.fileno())
        require_regular_file(path, CANONICAL_VERSION_FILE)
        if path.read_text(encoding="utf-8") != f"{expected.text}\n":
            raise UpdaterFailure("blocked_metadata", "the canonical version changed during update")
        os.replace(temporary_path, path)
    except UpdaterFailure:
        raise
    except OSError as exc:
        raise UpdaterFailure("blocked_metadata", "cannot atomically update the canonical version") from exc
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def runner_temp_child(path: Path, *, allow_existing: bool) -> Path:
    runner_temp_value = os.environ.get("RUNNER_TEMP")
    if not runner_temp_value:
        raise UpdaterFailure("blocked_metadata", "RUNNER_TEMP is required for runner-owned output")
    runner_temp = Path(runner_temp_value)
    try:
        runner_temp = runner_temp.resolve(strict=True)
        resolved_parent = path.parent.resolve(strict=True)
    except OSError as exc:
        raise UpdaterFailure("blocked_metadata", "runner-owned output path cannot be resolved") from exc
    if not runner_temp.is_dir() or not resolved_parent.is_relative_to(runner_temp):
        raise UpdaterFailure("blocked_metadata", "output must be a strict child of RUNNER_TEMP")
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise UpdaterFailure("blocked_metadata", "output path must be an absolute file path")
    try:
        details = path.lstat()
    except FileNotFoundError:
        details = None
    except OSError as exc:
        raise UpdaterFailure("blocked_metadata", "output path cannot be inspected") from exc
    if details is not None:
        if not allow_existing or stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
            raise UpdaterFailure("blocked_metadata", "output path is not a safe regular file")
    return path


def write_candidate_file(candidate: PythonVersion, path: Path) -> None:
    target = runner_temp_child(path, allow_existing=False)
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(f"{candidate.text}\n".encode("ascii"))
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise UpdaterFailure("blocked_metadata", "cannot write the runner candidate file") from exc


def write_github_outputs(result: UpdateResult) -> None:
    output_value = os.environ.get("GITHUB_OUTPUT")
    if not output_value:
        raise UpdaterFailure("blocked_metadata", "GITHUB_OUTPUT is required for requested output")
    output_path = runner_temp_child(Path(output_value), allow_existing=True)
    update_available = "true" if result.status == "update_available" else "false"
    candidate = result.candidate or ""
    lines = (
        f"status={result.status}",
        f"update_available={update_available}",
        f"candidate={candidate}",
    )
    try:
        with output_path.open("a", encoding="ascii", newline="\n") as stream:
            stream.write("\n".join(lines) + "\n")
    except OSError as exc:
        raise UpdaterFailure("blocked_metadata", "cannot write GitHub step output") from exc


def render_result(result: UpdateResult, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result.as_json(), sort_keys=True, separators=(",", ":")))
        return
    fields = [f"status={result.status}", f"current={result.current or ''}"]
    if result.candidate is not None:
        fields.append(f"candidate={result.candidate}")
    print(" ".join(fields))
    print(result.message)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--check", action="store_true", help="Resolve without source-tree writes.")
    operation.add_argument("--update", action="store_true", help="Atomically update .python-version.")
    parser.add_argument(
        "--expected-candidate",
        help="Require freshly resolved metadata to match this exact candidate before proceeding.",
    )
    parser.add_argument(
        "--write-candidate-file",
        type=Path,
        help="Create the resolved candidate only in a new RUNNER_TEMP file.",
    )
    parser.add_argument(
        "--write-github-output",
        action="store_true",
        help="Write safe scalar status outputs to the runner-provided GITHUB_OUTPUT file.",
    )
    parser.add_argument("--json", action="store_true", help="Emit a one-line JSON result.")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.timeout <= 0 or args.timeout > MAX_TIMEOUT_SECONDS:
        result = UpdateResult(
            "blocked_metadata", None, None, "timeout must be greater than zero and at most 60 seconds"
        )
        render_result(result, as_json=args.json)
        return 2
    if args.write_candidate_file is not None and not args.check:
        result = UpdateResult(
            "blocked_metadata", None, None, "candidate files are allowed only in --check mode"
        )
        render_result(result, as_json=args.json)
        return 2

    result = require_expected_candidate(
        resolve_update(framework_root(), timeout=args.timeout), args.expected_candidate
    )
    try:
        if args.write_candidate_file is not None:
            if result.status != "update_available" or result.candidate is None:
                raise UpdaterFailure(
                    "blocked_metadata", "a candidate file requires a validated available update"
                )
            write_candidate_file(PythonVersion.parse(result.candidate), args.write_candidate_file)
        if args.update and result.status == "update_available" and result.candidate is not None:
            current = PythonVersion.parse(str(result.current))
            candidate = PythonVersion.parse(result.candidate)
            atomic_write_canonical_version(framework_root(), current, candidate)
            result = UpdateResult(
                result.status,
                result.current,
                result.candidate,
                result.message,
                updated=True,
            )
        if args.write_github_output:
            write_github_outputs(result)
    except UpdaterFailure as exc:
        result = UpdateResult(exc.status, result.current, result.candidate, exc.message)
        if args.write_github_output:
            try:
                write_github_outputs(result)
            except UpdaterFailure:
                pass

    render_result(result, as_json=args.json)
    return 0 if result.status in SUCCESS_STATUSES else 2


if __name__ == "__main__":
    raise SystemExit(main())
