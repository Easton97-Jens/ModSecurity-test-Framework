#!/usr/bin/env python3
"""Check and safely update upstream version pins from ci/lib/common.sh."""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

DEFAULT_BUILD_ROOT = Path("/src/ModSecurity-conector-build")
SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_COMMON_SH = SCRIPT_DIR.parent / "lib" / "common.sh"
NO_SAFE_UPDATER_MESSAGE = "No safe updater implemented for this source yet."
SHA256_SUFFIX = ".sha256"
ARCHIVE_BZ2_EXTENSION = ".tar.bz2"
APACHE_DOWNLOAD_HOST = "downloads.apache.org"
MODSECURITY_V3_COMPONENT = "ModSecurity v3"

TRACKED_NAME_RE = re.compile(
    r"VERSION|RELEASE|TAG|SOURCE_URL|GIT_URL|SHA256|CHECKSUM|REF|BRANCH|COMMIT|URL"
)
PARAM_EXPANSION_RE = re.compile(r"\$\{((?!\d)\w+):?[-=]([^{}]*)\}", re.ASCII)
BRACED_VAR_RE = re.compile(r"\$\{((?!\d)\w+)\}", re.ASCII)
PLAIN_VAR_RE = re.compile(r"\$((?!\d)\w+)", re.ASCII)
PREFIX_REMOVAL_RE = re.compile(r"\$\{((?!\d)\w+)#([^{}]*)\}", re.ASCII)
SHA256_RE = re.compile(r"\b([A-Fa-f0-9]{64})\b")
SHA256_VALUE_RE = re.compile(r"^[a-f0-9]{64}$")
GIT_COMMIT_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SAFE_REF_RE = re.compile(r"^(?!.*\.\.)(?!/)(?!.*//)[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
SAFE_VERSION_RE = re.compile(r"^\d+(?:\.\d+)+$")
RELEASE_TAG_RE = re.compile(r"^v\d+\.\d+\.\d+$")
MODSECURITY_V3_RELEASE_TAG_RE = re.compile(r"^v3\.\d+\.\d+$")
SAFE_HTTPS_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")
SAFE_HTTPS_PATH_RE = re.compile(r"^/[A-Za-z0-9._~/-]*$")
URL_PATH_DYNAMIC_VALUE_RE = re.compile(
    r"\$(?:\{[A-Za-z_](?a:\w)*\}|[A-Za-z_](?a:\w)*)|\d+\.\d+(?:\.\d+)*"
)
NGINX_RELEASE_ASSET_RE = re.compile(r"^nginx-([A-Za-z0-9][A-Za-z0-9._-]*)\.tar\.gz$")
OPTIONAL_EMPTY_VARIABLES = {
    "APACHE_BIN",
    "APACHECTL_BIN",
    "APXS_BIN",
    "MODSECURITY_APACHE_REPO_URL",
    "MODSECURITY_APACHE_GIT_URL",
    "MODSECURITY_NGINX_REPO_URL",
    "MODSECURITY_NGINX_GIT_URL",
    "MODSECURITY_PKG_CONFIG",
    "MODSECURITY_LIB_DIR",
    "MODSECURITY_INCLUDE_DIR",
    "MODSECURITY_RULE_PREAMBLE_FILE",
    "NGINX_BIN",
    "PCRE2_SHA256",
    "PCRE2_SHA256_URL",
}
APPROVED_LITERAL_VARIABLES = {
    "APR_UTIL_PINNED_VERSION",
    "APR_UTIL_PINNED_SOURCE_URL",
    "APR_UTIL_PINNED_SHA256",
    "APR_UTIL_PINNED_SHA256_URL",
    "CRS_APPROVED_REPO_URL",
    "CRS_APPROVED_COMMIT",
    "CRS_RELEASE_TAG",
    "MODSECURITY_V3_APPROVED_REPO_URL",
    "MODSECURITY_V3_APPROVED_COMMIT",
    "MODSECURITY_V3_RELEASE_TAG",
}

STATUS_CURRENT = "current"
STATUS_OUTDATED = "outdated"
STATUS_UNKNOWN = "unknown"
STATUS_NOT_APPLICABLE = "not_applicable"
STATUS_BLOCKED = "blocked"
STATUS_ERROR = "error"
STATUS_REVIEW_REQUIRED = "review_required"

MAINTENANCE_OUTCOME_NO_UPDATES = "no_updates"
MAINTENANCE_OUTCOME_MANUAL_REVIEW_ONLY = "manual_review_only"
MAINTENANCE_OUTCOME_SAFE_UPDATES = "safe_updates"
MAINTENANCE_OUTCOME_SAFE_UPDATES_WITH_MANUAL_REVIEW = "safe_updates_with_manual_review"
MAINTENANCE_OUTCOME_FATAL = "fatal"
MAINTENANCE_OUTCOMES = frozenset(
    {
        MAINTENANCE_OUTCOME_NO_UPDATES,
        MAINTENANCE_OUTCOME_MANUAL_REVIEW_ONLY,
        MAINTENANCE_OUTCOME_SAFE_UPDATES,
        MAINTENANCE_OUTCOME_SAFE_UPDATES_WITH_MANUAL_REVIEW,
        MAINTENANCE_OUTCOME_FATAL,
    }
)
FATAL_STATUSES = frozenset({STATUS_UNKNOWN, STATUS_BLOCKED, STATUS_ERROR})
CRS_COMPONENT = "OWASP Core Rule Set"
CRS_APPROVED_REPOSITORY = "coreruleset/coreruleset"
MODSECURITY_V3_APPROVED_REPOSITORY = "owasp-modsecurity/ModSecurity"
MANUAL_REVIEW_VARIABLES = {
    CRS_COMPONENT: (
        "CRS_APPROVED_REPO_URL",
        "CRS_RELEASE_TAG",
        "CRS_APPROVED_COMMIT",
        "CRS_REPO_URL",
        "CRS_GIT_REF",
    ),
    MODSECURITY_V3_COMPONENT: (
        "MODSECURITY_V3_APPROVED_REPO_URL",
        "MODSECURITY_V3_RELEASE_TAG",
        "MODSECURITY_V3_APPROVED_COMMIT",
        "MODSECURITY_REPO_URL",
        "MODSECURITY_GIT_REF",
        "MODSECURITY_V3_GIT_URL",
        "MODSECURITY_V3_GIT_REF",
    ),
}


class UpstreamBlocked(RuntimeError):
    """The upstream source could not be checked right now."""


class UpstreamUnknown(RuntimeError):
    """The upstream structure is not safe enough for an automated decision."""


class UpstreamError(RuntimeError):
    """The upstream source returned contradictory or invalid data."""


@dataclasses.dataclass
class VariableEntry:
    name: str
    line: int
    raw: str
    default: str
    resolved: str
    tracked: bool
    style: str


@dataclasses.dataclass
class UpdateChange:
    variable: str
    line: int
    old: str
    new: str


@dataclasses.dataclass
class ComponentResult:
    component: str
    status: str
    message: str
    variables: list[str]
    current: str = ""
    latest: str = ""
    source: str = ""
    updates: list[UpdateChange] = dataclasses.field(default_factory=list)
    details: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True)
class ComponentSpec:
    """Declarative ownership and provenance policy for one atomic group."""

    name: str
    authority: str
    variables: tuple[str, ...]
    strategy: str
    asset_template: str = ""
    tag_format: str = ""
    stable_rule: str = "draft=false, prerelease=false; reject alpha/beta/rc/nightly"
    update_policy: str = "latest stable"
    automatic: bool = True


@dataclasses.dataclass(frozen=True)
class MaintenanceDisposition:
    """Classify a checked candidate without relaxing fatal source states."""

    outcome: str
    safe_updates_available: bool
    manual_review_required: bool
    manual_review_components: tuple[str, ...]
    fatal_components: tuple[str, ...]
    automatic_updates: tuple[UpdateChange, ...]
    automatic_update_variables: tuple[str, ...]


def validate_entries(entries: dict[str, VariableEntry]) -> list[str]:
    """Return tracked variables that resolve to empty without being documented as optional."""
    missing: list[str] = []
    for item in sorted(entries.values(), key=lambda current: current.line):
        if (
            item.tracked
            and not item.resolved
            and item.name not in OPTIONAL_EMPTY_VARIABLES
        ):
            missing.append(item.name)
    return missing


def build_root() -> Path:
    return Path(os.environ.get("BUILD_ROOT", str(DEFAULT_BUILD_ROOT))).resolve()


def is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def require_safe_build_write_target(path: Path) -> Path:
    target = path.resolve()
    root = build_root()
    if is_under(target, root):
        return target
    raise UpstreamError(f"refusing to write outside BUILD_ROOT ({root}): {target}")


def require_safe_common_sh_update_target(path: Path) -> Path:
    target = path.resolve()
    canonical_common_sh = DEFAULT_COMMON_SH.resolve()
    if target == canonical_common_sh:
        return target
    if target.name == canonical_common_sh.name:
        return require_safe_build_write_target(target)
    raise UpstreamError(
        "refusing to update a file other than the canonical common.sh or a "
        f"BUILD_ROOT test fixture: {target}"
    )


def resolve_value(raw_value: str, resolved: dict[str, str]) -> str:
    value = raw_value
    for _ in range(30):
        before = value

        def replace_param(match: re.Match[str]) -> str:
            name = match.group(1)
            fallback = match.group(2)
            current = resolved.get(name, "")
            return current if current else fallback

        value = PARAM_EXPANSION_RE.sub(replace_param, value)
        value = PREFIX_REMOVAL_RE.sub(
            lambda match: (
                resolved.get(match.group(1), "")[len(match.group(2)) :]
                if resolved.get(match.group(1), "").startswith(match.group(2))
                else resolved.get(match.group(1), "")
            ),
            value,
        )
        if value == before:
            break
    value = BRACED_VAR_RE.sub(lambda match: resolved.get(match.group(1), ""), value)
    value = PLAIN_VAR_RE.sub(lambda match: resolved.get(match.group(1), ""), value)
    return value


def parse_common_assignment(line: str) -> tuple[str, str, str] | None:
    assign_re = re.compile(r'^([A-Z][A-Z0-9_]*)="\$\{\1:-(.*)\}"\s*$')
    unset_assign_re = re.compile(r'^([A-Z][A-Z0-9_]*)="\$\{\1-(.*)\}"\s*$')
    colon_re = re.compile(r'^:\s+"\$\{([A-Z][A-Z0-9_]*):=(.*)\}"\s*$')
    literal_re = re.compile(r'^([A-Z][A-Z0-9_]*)="([^"$`]*)"\s*$')
    derived_literal_re = re.compile(r'^([A-Z][A-Z0-9_]*)="([^"`]*)"\s*$')

    for style, pattern in (
        ("colon-default", colon_re),
        ("assignment-default", assign_re),
        ("assignment-unset-default", unset_assign_re),
    ):
        match = pattern.match(line)
        if match:
            return style, match.group(1), match.group(2)

    match = literal_re.match(line)
    if match and match.group(1) in APPROVED_LITERAL_VARIABLES:
        return "literal-assignment", match.group(1), match.group(2)
    match = derived_literal_re.match(line)
    if not match or match.group(1) not in APPROVED_LITERAL_VARIABLES:
        return None
    # Only passive parameter references are accepted in reviewed literal aliases.
    if re.sub(r"\$[A-Z][A-Z0-9_]*|\$\{[A-Z][A-Z0-9_]*(?:#[^{}]*)?\}", "", match.group(2)).find("$") >= 0:
        return None
    return "literal-assignment", match.group(1), match.group(2)


def parse_common_lines(lines: list[str]) -> dict[str, VariableEntry]:
    """Parse already-rendered common.sh lines without touching a write target."""

    entries: dict[str, VariableEntry] = {}
    resolved: dict[str, str] = {}

    for line_no, line in enumerate(lines, start=1):
        assignment = parse_common_assignment(line)
        if assignment is None:
            continue
        style, name, default = assignment
        value = resolve_value(default, resolved)
        resolved[name] = value
        tracked = bool(TRACKED_NAME_RE.search(name) or TRACKED_NAME_RE.search(default))
        entries[name] = VariableEntry(
            name=name,
            line=line_no,
            raw=line,
            default=default,
            resolved=value,
            tracked=tracked,
            style=style,
        )
    return entries


def parse_common(common_sh: Path) -> tuple[list[str], dict[str, VariableEntry]]:
    lines = common_sh.read_text(encoding="utf-8").splitlines()
    return lines, parse_common_lines(lines)


def entry(entries: dict[str, VariableEntry], name: str) -> VariableEntry | None:
    return entries.get(name)


def value(entries: dict[str, VariableEntry], name: str) -> str:
    current = entry(entries, name)
    return current.resolved if current else ""


def trusted_https_path_prefix(path: str) -> str:
    dynamic_value = URL_PATH_DYNAMIC_VALUE_RE.search(path)
    if dynamic_value is not None:
        return path[: dynamic_value.start()]
    return path.rsplit("/", 1)[0] + "/"


def require_safe_https_update_url(
    variable: str,
    new_default: str,
    trusted_default: str | None = None,
) -> None:
    parsed = urlparse(new_default)
    try:
        port = parsed.port
        hostname = parsed.hostname
    except ValueError as exc:
        raise UpstreamError(
            f"refusing invalid HTTPS URL for {variable}: {new_default!r}"
        ) from exc
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not hostname
        or not SAFE_HTTPS_HOST_RE.fullmatch(hostname)
        or ".." in hostname
        or (port is not None and not 1 <= port <= 65535)
        or not SAFE_HTTPS_PATH_RE.fullmatch(parsed.path or "/")
        or ".." in parsed.path
        or "//" in parsed.path
    ):
        raise UpstreamError(
            f"refusing invalid HTTPS URL for {variable}: {new_default!r}"
        )
    if trusted_default is None:
        return
    trusted = urlparse(trusted_default)
    try:
        trusted_port = trusted.port
        trusted_hostname = trusted.hostname
    except ValueError as exc:
        raise UpstreamError(
            f"refusing URL update without a trusted HTTPS authority for {variable}: "
            f"{trusted_default!r}"
        ) from exc
    if (
        trusted.scheme != "https"
        or not trusted.netloc
        or trusted.username is not None
        or trusted.password is not None
        or not trusted_hostname
        or not SAFE_HTTPS_HOST_RE.fullmatch(trusted_hostname)
        or ".." in trusted_hostname
        or (trusted_port is not None and not 1 <= trusted_port <= 65535)
        or ".." in trusted.path
        or "//" in trusted.path
        or hostname != trusted_hostname
        or port != trusted_port
        or not parsed.path.startswith(trusted_https_path_prefix(trusted.path or "/"))
    ):
        raise UpstreamError(
            f"refusing HTTPS authority change for {variable}: {new_default!r}"
        )


def require_shell_safe_default(
    variable: str,
    new_default: str,
    trusted_default: str | None = None,
) -> None:
    if not isinstance(new_default, str) or not new_default:
        raise UpstreamError(f"refusing empty or non-text shell default for {variable}")
    if any(
        ch in new_default
        for ch in (
            " ",
            "\t",
            "\n",
            "$",
            "`",
            '"',
            "'",
            ";",
            "{",
            "}",
            "(",
            ")",
            "#",
            "&",
            "|",
            "<",
            ">",
            "\\",
        )
    ):
        raise UpstreamError(
            f"refusing unsafe shell default for {variable}: {new_default!r}"
        )
    if variable == "VERSION" or variable.endswith("_VERSION"):
        if not SAFE_VERSION_RE.fullmatch(new_default):
            raise UpstreamError(
                f"refusing invalid version for {variable}: {new_default!r}"
            )
        return
    if variable == "SHA256" or variable.endswith("_SHA256"):
        if not SHA256_VALUE_RE.fullmatch(new_default):
            raise UpstreamError(
                f"refusing invalid SHA-256 value for {variable}: {new_default!r}"
            )
        return
    if variable == "URL" or variable.endswith("_URL"):
        require_safe_https_update_url(variable, new_default, trusted_default)
        return
    if ".." in new_default or new_default.startswith("/") or "//" in new_default:
        raise UpstreamError(
            f"refusing traversal-like shell default for {variable}: {new_default!r}"
        )


def plan_update(
    entries: dict[str, VariableEntry], variable: str, new_default: str
) -> UpdateChange | None:
    current = entry(entries, variable)
    require_shell_safe_default(
        variable,
        new_default,
        current.default if current is not None else None,
    )
    if current is None:
        return None
    if current.default == new_default:
        return None
    return UpdateChange(
        variable=variable, line=current.line, old=current.default, new=new_default
    )


def is_template_value(raw_default: str, variable: str) -> bool:
    return f"${variable}" in raw_default or f"${{{variable}}}" in raw_default


def is_transitively_derived(
    entries: dict[str, VariableEntry], target: str, authority: str, seen: set[str] | None = None
) -> bool:
    """Return true when a passive assignment ultimately references authority."""
    def dependencies(name: str, visited: set[str]) -> set[str]:
        if name in visited or name not in entries:
            return {name}
        visited.add(name)
        references = set(BRACED_VAR_RE.findall(entries[name].default))
        references.update(PLAIN_VAR_RE.findall(entries[name].default))
        result = {name}
        for reference in references:
            result.update(dependencies(reference, visited))
        return result

    target_dependencies = dependencies(target, set())
    authority_dependencies = dependencies(authority, set())
    return authority in target_dependencies or bool(
        (target_dependencies & authority_dependencies) - {target, authority}
    )


def replace_default_line(line: str, variable: str, new_default: str) -> str:
    escaped = re.escape(variable)
    colon_re = re.compile(rf'^(:\s*"\$\{{{escaped}:=)(.*)(\}}"\s*)$')
    assign_re = re.compile(rf'^({escaped}\s*=\s*"\$\{{{escaped}:=)(.*)(\}}"\s*)$')
    default_re = re.compile(rf'^({escaped}\s*=\s*"\$\{{{escaped}:-)(.*)(\}}"\s*)$')
    unset_default_re = re.compile(rf'^({escaped}\s*=\s*"\$\{{{escaped}-)(.*)(\}}"\s*)$')
    for pattern in (colon_re, assign_re, default_re, unset_default_re):
        match = pattern.match(line)
        if match:
            return f"{match.group(1)}{new_default}{match.group(3)}"
    literal_re = re.compile(rf'^({escaped}\s*=\s*")([^"`]*)("\s*)$')
    match = literal_re.match(line)
    if match and variable in APPROVED_LITERAL_VARIABLES:
        return f"{match.group(1)}{new_default}{match.group(3)}"
    raise UpstreamError(f"cannot safely update line for {variable}: {line}")


def render_updated_lines(lines: list[str], updates: list[UpdateChange]) -> list[str]:
    """Validate and render an update plan without mutating its target."""

    seen: set[str] = set()
    replacements: list[tuple[int, str]] = []
    for update in updates:
        if update.variable in seen:
            raise UpstreamError(f"duplicate update for {update.variable}")
        seen.add(update.variable)
        if update.line < 1:
            raise UpstreamError(
                f"invalid update line for {update.variable}: {update.line}"
            )
        index = update.line - 1
        try:
            current_line = lines[index]
        except IndexError as exc:
            raise UpstreamError(
                f"invalid update line for {update.variable}: {update.line}"
            ) from exc
        assignment = parse_common_assignment(current_line)
        if (
            assignment is None
            or assignment[1] != update.variable
            or assignment[2] != update.old
        ):
            raise UpstreamError(
                f"update no longer matches {update.variable} at line {update.line}"
            )
        require_shell_safe_default(update.variable, update.new, assignment[2])
        replacements.append(
            (index, replace_default_line(current_line, update.variable, update.new))
        )
    updated_lines = list(lines)
    for index, replacement in replacements:
        updated_lines[index] = replacement
    return updated_lines


def apply_updates(
    common_sh: Path, lines: list[str], updates: list[UpdateChange]
) -> None:
    if not updates:
        return
    target = require_safe_common_sh_update_target(common_sh)
    updated_lines = render_updated_lines(lines, updates)
    target.write_text("\n".join(updated_lines) + "\n", encoding="utf-8")


def consume_decimal_digits(text: str, start: int) -> int:
    end = start
    while end < len(text) and text[end].isdecimal():
        end += 1
    return end


def dotted_version_text(text: str) -> str:
    start = 0
    while start < len(text):
        if not text[start].isdecimal():
            start += 1
            continue
        end = consume_decimal_digits(text, start)
        dotted_end = end
        while dotted_end < len(text) and text[dotted_end] == ".":
            next_start = dotted_end + 1
            next_end = consume_decimal_digits(text, next_start)
            if next_end == next_start:
                break
            dotted_end = next_end
        if dotted_end != end:
            return text[start:dotted_end]
        start = end
    raise UpstreamUnknown(f"no dotted numeric version in {text!r}")


def version_tuple(text: str) -> tuple[int, ...]:
    version = dotted_version_text(text)
    return tuple(int(part) for part in version.split("."))


def compare_versions(left: str, right: str) -> int:
    left_tuple = version_tuple(left)
    right_tuple = version_tuple(right)
    width = max(len(left_tuple), len(right_tuple))
    left_tuple = left_tuple + (0,) * (width - len(left_tuple))
    right_tuple = right_tuple + (0,) * (width - len(right_tuple))
    if left_tuple < right_tuple:
        return -1
    if left_tuple > right_tuple:
        return 1
    return 0


def same_series(left: str, right: str) -> bool:
    left_tuple = version_tuple(left)
    right_tuple = version_tuple(right)
    return (
        len(left_tuple) >= 2
        and len(right_tuple) >= 2
        and left_tuple[:2] == right_tuple[:2]
    )


def markdown_escape(value_text: str) -> str:
    return value_text.replace("|", "\\|").replace("\n", "<br>")


class HttpClient:
    def __init__(self, timeout: float) -> None:
        self.timeout = timeout

    def _headers(self, url: str, accept: str | None = None) -> dict[str, str]:
        headers = {
            "User-Agent": "ModSecurity-test-Framework common.sh version checker",
        }
        if accept:
            headers["Accept"] = accept
        parsed = urlparse(url)
        token = os.environ.get("GITHUB_TOKEN")
        if token and parsed.netloc == "api.github.com":
            headers["Authorization"] = f"Bearer {token}"
            headers["X-GitHub-Api-Version"] = "2022-11-28"
        return headers

    def get_text(self, url: str, accept: str | None = None) -> str:
        request = Request(url, headers=self._headers(url, accept))
        try:
            with urlopen(request, timeout=self.timeout) as response:  # nosec B310
                raw = response.read()
                charset = response.headers.get_content_charset() or "utf-8"
                return raw.decode(charset, errors="replace")
        except HTTPError as exc:
            if exc.code in {403, 429}:
                remaining = exc.headers.get("x-ratelimit-remaining")
                reset = exc.headers.get("x-ratelimit-reset")
                detail = f"HTTP {exc.code}"
                if remaining == "0" and reset:
                    detail += f"; GitHub rate limit reset={reset}"
                raise UpstreamBlocked(f"{url}: {detail}") from exc
            if exc.code == 404:
                raise UpstreamUnknown(f"{url}: HTTP 404") from exc
            raise UpstreamError(f"{url}: HTTP {exc.code}") from exc
        except (TimeoutError, URLError) as exc:
            raise UpstreamBlocked(f"{url}: {exc}") from exc

    def get_json(self, url: str) -> dict[str, Any]:
        text = self.get_text(url, accept="application/vnd.github+json")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise UpstreamError(f"{url}: invalid JSON") from exc
        if not isinstance(data, dict):
            raise UpstreamError(f"{url}: JSON response is not an object")
        return data


def parse_sha256(text: str, expected_filename: str) -> str:
    matches: list[str] = []
    for line in text.splitlines():
        # Accept only the two conventional SHA-256 manifest forms.  Substring
        # matching would permit a checksum for a similarly named asset.
        match = re.fullmatch(
            r"\s*([A-Fa-f0-9]{64})\s+[*]?([^\s]+)\s*", line
        )
        bsd_match = re.fullmatch(
            r"\s*SHA256\s*\(([^)]+)\)\s*=\s*([A-Fa-f0-9]{64})\s*", line
        )
        if match and match.group(2) == expected_filename:
            matches.append(match.group(1).lower())
            continue
        if bsd_match and bsd_match.group(1) == expected_filename:
            matches.append(bsd_match.group(2).lower())
    if not matches:
        raise UpstreamBlocked(f"official checksum did not name {expected_filename}")
    if len(matches) != 1:
        raise UpstreamBlocked(f"official checksum for {expected_filename} is ambiguous")
    return matches[0]


def fetch_sha256(client: HttpClient, checksum_url: str, expected_filename: str) -> str:
    return parse_sha256(client.get_text(checksum_url), expected_filename)


def latest_from_listing(
    html: str,
    filename_prefix: str,
    extension: str,
    current_version: str,
    restrict_to_current_series: bool,
) -> str:
    pattern = re.compile(
        rf"{re.escape(filename_prefix)}-(\d+(?:\.\d+)+){re.escape(extension)}"
    )
    versions = sorted(
        {match.group(1) for match in pattern.finditer(html)}, key=version_tuple
    )
    if restrict_to_current_series:
        versions = [
            candidate
            for candidate in versions
            if same_series(candidate, current_version)
        ]
    if not versions:
        raise UpstreamUnknown(
            f"No safe updater implemented for this source yet: no matching {filename_prefix} "
            f"versions found in official listing."
        )
    return versions[-1]


def missing_variables_result(
    component: str,
    entries: dict[str, VariableEntry],
    variables: list[str],
) -> ComponentResult | None:
    missing = [name for name in variables if name not in entries]
    if not missing:
        return None
    return ComponentResult(
        component=component,
        status=STATUS_UNKNOWN,
        message=f"missing variables: {', '.join(missing)}",
        variables=variables,
    )


def is_expected_tarball_url(
    current_url: str,
    allowed_host: str,
    filename: str,
) -> bool:
    parsed = urlparse(current_url)
    return (
        parsed.scheme == "https"
        and parsed.netloc == allowed_host
        and parsed.path.endswith("/" + filename)
    )


def append_planned_update(
    updates: list[UpdateChange],
    entries: dict[str, VariableEntry],
    variable: str,
    new_default: str,
) -> None:
    update = plan_update(entries, variable, new_default)
    if update is not None:
        updates.append(update)


def collect_tarball_updates(
    entries: dict[str, VariableEntry],
    *,
    version_var: str,
    source_url_var: str,
    sha_var: str,
    sha_url_var: str,
    current_sha: str,
    latest_version: str,
    latest_url: str,
    latest_sha_url: str,
    latest_sha: str,
) -> list[UpdateChange]:
    updates: list[UpdateChange] = []
    append_planned_update(updates, entries, version_var, latest_version)
    if not is_transitively_derived(entries, source_url_var, version_var):
        append_planned_update(updates, entries, source_url_var, latest_url)
    if not is_transitively_derived(entries, sha_url_var, source_url_var):
        append_planned_update(updates, entries, sha_url_var, latest_sha_url)
    if current_sha:
        append_planned_update(updates, entries, sha_var, latest_sha)
    return updates


def official_tarball_check(
    component: str,
    entries: dict[str, VariableEntry],
    client: HttpClient,
    *,
    version_var: str,
    source_url_var: str,
    sha_var: str,
    sha_url_var: str,
    filename_prefix: str,
    extension: str,
    allowed_host: str,
    restrict_to_current_series: bool,
    plan_updates: bool = True,
) -> ComponentResult:
    variables = [version_var, source_url_var, sha_var, sha_url_var]
    missing_result = missing_variables_result(component, entries, variables)
    if missing_result is not None:
        return missing_result

    current_version = value(entries, version_var)
    current_url = value(entries, source_url_var)
    current_sha = value(entries, sha_var)
    current_sha_url = value(entries, sha_url_var)
    filename = f"{filename_prefix}-{current_version}{extension}"
    if not is_expected_tarball_url(current_url, allowed_host, filename):
        return ComponentResult(
            component=component,
            status=STATUS_UNKNOWN,
            message=NO_SAFE_UPDATER_MESSAGE,
            variables=variables,
            current=current_version,
            source=current_url,
            details={"reason": "source URL is not the expected official tarball URL"},
        )

    listing_url = current_url.rsplit("/", 1)[0] + "/"
    latest_version = latest_from_listing(
        client.get_text(listing_url),
        filename_prefix,
        extension,
        current_version,
        restrict_to_current_series,
    )
    latest_filename = f"{filename_prefix}-{latest_version}{extension}"
    latest_url = listing_url + latest_filename
    latest_sha_url = latest_url + SHA256_SUFFIX
    latest_sha = fetch_sha256(client, latest_sha_url, latest_filename)
    comparison = compare_versions(current_version, latest_version)

    if comparison > 0:
        return ComponentResult(
            component=component,
            status=STATUS_UNKNOWN,
            message="Configured version is newer than the official listing; refusing to guess.",
            variables=variables,
            current=current_version,
            latest=latest_version,
            source=listing_url,
        )

    if comparison < 0:
        updates = collect_tarball_updates(
            entries,
            version_var=version_var,
            source_url_var=source_url_var,
            sha_var=sha_var,
            sha_url_var=sha_url_var,
            current_sha=current_sha,
            latest_version=latest_version,
            latest_url=latest_url,
            latest_sha_url=latest_sha_url,
            latest_sha=latest_sha,
        ) if plan_updates else []
        return ComponentResult(
            component=component,
            status=STATUS_OUTDATED,
            message="A newer official tarball is available.",
            variables=variables,
            current=current_version,
            latest=latest_version,
            source=listing_url,
            updates=updates,
            details={
                "latest_source_url": latest_url,
                "latest_sha256_url": latest_sha_url,
                "latest_sha256": latest_sha,
            },
        )

    official_current_sha = fetch_sha256(
        client,
        current_sha_url or latest_sha_url,
        filename,
    )
    if current_sha and current_sha.lower() != official_current_sha:
        updates: list[UpdateChange] = []
        append_planned_update(updates, entries, sha_var, official_current_sha)
        return ComponentResult(
            component=component,
            status=STATUS_OUTDATED,
            message="Configured checksum differs from the official checksum.",
            variables=variables,
            current=current_version,
            latest=latest_version,
            source=listing_url,
            updates=updates,
            details={
                "official_sha256": official_current_sha,
                "configured_sha256": current_sha,
            },
        )

    return ComponentResult(
        component=component,
        status=STATUS_CURRENT,
        message="Version and official checksum source are current.",
        variables=variables,
        current=current_version,
        latest=latest_version,
        source=listing_url,
        details={
            "sha256_mode": "literal" if current_sha else "sha256_url",
            "official_sha256": official_current_sha,
        },
    )


def check_apr_util_release_provenance(
    entries: dict[str, VariableEntry], client: HttpClient
) -> ComponentResult:
    """Resolve and atomically advance APR-util's authoritative version/digest."""

    pinned_variables = [
        "APR_UTIL_PINNED_VERSION",
        "APR_UTIL_PINNED_SOURCE_URL",
        "APR_UTIL_PINNED_SHA256",
        "APR_UTIL_PINNED_SHA256_URL",
    ]
    runtime_variables = [
        "APR_UTIL_VERSION",
        "APR_UTIL_SOURCE_URL",
        "APR_UTIL_SHA256",
        "APR_UTIL_SHA256_URL",
    ]
    variables = [*pinned_variables, *runtime_variables]
    missing_result = missing_variables_result("APR-util", entries, variables)
    if missing_result is not None:
        return missing_result

    for pinned, runtime in zip(pinned_variables, runtime_variables, strict=True):
        if value(entries, pinned) != value(entries, runtime):
            return ComponentResult(
                component="APR-util",
                status=STATUS_UNKNOWN,
                message="APR-util runtime configuration must equal the reviewed provenance tuple.",
                variables=variables,
                current=value(entries, "APR_UTIL_VERSION"),
                source=value(entries, "APR_UTIL_SOURCE_URL"),
                details={"pinned_variable": pinned, "runtime_variable": runtime},
            )

    result = official_tarball_check(
        "APR-util",
        entries,
        client,
        version_var="APR_UTIL_VERSION",
        source_url_var="APR_UTIL_SOURCE_URL",
        sha_var="APR_UTIL_SHA256",
        sha_url_var="APR_UTIL_SHA256_URL",
        filename_prefix="apr-util",
        extension=ARCHIVE_BZ2_EXTENSION,
        allowed_host=APACHE_DOWNLOAD_HOST,
        restrict_to_current_series=True,
        plan_updates=False,
    )
    result.variables = variables
    if result.status == STATUS_OUTDATED:
        latest_sha = str(result.details.get("latest_sha256", ""))
        updates = [
            update
            for update in (
                plan_update(entries, "APR_UTIL_PINNED_VERSION", result.latest),
                plan_update(entries, "APR_UTIL_PINNED_SHA256", latest_sha),
            )
            if update is not None
        ]
        if len(updates) != 2:
            raise UpstreamError("APR-util atomic update did not contain version and SHA-256")
        result.updates = updates
        result.message = "A newer official APR-util tarball and exact checksum are available."
        result.details.update(
            {
                "asset_name": f"apr-util-{result.latest}{ARCHIVE_BZ2_EXTENSION}",
                "atomic_group": pinned_variables,
                "checksum_strategy": "official <asset>.sha256",
            }
        )
    return result


def haproxy_source_series(current_url: str, current_version: str) -> str | None:
    match = re.fullmatch(
        r"https://www\.haproxy\.org/download/(\d+\.\d+)/src/haproxy-(\d+\.\d+\.\d+)\.tar\.gz",
        current_url,
    )
    if match is None or match.group(2) != current_version:
        return None
    return match.group(1)


def check_haproxy(
    entries: dict[str, VariableEntry], client: HttpClient
) -> ComponentResult:
    variables = [
        "HAPROXY_VERSION",
        "HAPROXY_SOURCE_URL",
        "HAPROXY_SHA256_URL",
        "HAPROXY_SHA256",
    ]
    missing_result = missing_variables_result("HAProxy", entries, variables)
    if missing_result is not None:
        return missing_result
    current_version = value(entries, "HAPROXY_VERSION")
    current_url = value(entries, "HAPROXY_SOURCE_URL")
    configured_sha = value(entries, "HAPROXY_SHA256").lower()
    current_sha_url = (
        value(entries, "HAPROXY_SHA256_URL") or current_url + SHA256_SUFFIX
    )
    series = haproxy_source_series(current_url, current_version)
    if series is None:
        return ComponentResult(
            component="HAProxy",
            status=STATUS_UNKNOWN,
            message=NO_SAFE_UPDATER_MESSAGE,
            variables=variables,
            current=current_version,
            source=current_url,
            details={
                "reason": "source URL is not the expected official HAProxy tarball URL"
            },
        )
    if not configured_sha:
        return ComponentResult(
            component="HAProxy",
            status=STATUS_BLOCKED,
            message="HAPROXY_SHA256 is required for safe HAProxy updates.",
            variables=variables,
            current=current_version,
            source=current_url,
        )

    listing_url = f"https://www.haproxy.org/download/{series}/src/"
    latest_version = latest_from_listing(
        client.get_text(listing_url),
        "haproxy",
        ".tar.gz",
        current_version,
        restrict_to_current_series=True,
    )
    latest_filename = f"haproxy-{latest_version}.tar.gz"
    latest_url = f"{listing_url}{latest_filename}"
    latest_sha_url = latest_url + SHA256_SUFFIX
    latest_sha = fetch_sha256(client, latest_sha_url, latest_filename)
    comparison = compare_versions(current_version, latest_version)

    if comparison > 0:
        return ComponentResult(
            component="HAProxy",
            status=STATUS_UNKNOWN,
            message="Configured version is newer than the official HAProxy series listing; refusing to guess.",
            variables=variables,
            current=current_version,
            latest=latest_version,
            source=listing_url,
        )

    if comparison < 0:
        updates = collect_tarball_updates(
            entries,
            version_var="HAPROXY_VERSION",
            source_url_var="HAPROXY_SOURCE_URL",
            sha_var="HAPROXY_SHA256",
            sha_url_var="HAPROXY_SHA256_URL",
            current_sha=configured_sha,
            latest_version=latest_version,
            latest_url=latest_url,
            latest_sha_url=latest_sha_url,
            latest_sha=latest_sha,
        )
        return ComponentResult(
            component="HAProxy",
            status=STATUS_OUTDATED,
            message="A newer official HAProxy tarball and checksum are available.",
            variables=variables,
            current=current_version,
            latest=latest_version,
            source=listing_url,
            updates=updates,
            details={
                "latest_source_url": latest_url,
                "latest_sha256_url": latest_sha_url,
                "latest_sha256": latest_sha,
            },
        )

    official_current_sha = fetch_sha256(
        client, current_sha_url, f"haproxy-{current_version}.tar.gz"
    )
    if configured_sha != official_current_sha:
        updates: list[UpdateChange] = []
        append_planned_update(updates, entries, "HAPROXY_SHA256", official_current_sha)
        return ComponentResult(
            component="HAProxy",
            status=STATUS_OUTDATED,
            message="Configured HAProxy checksum differs from the official checksum.",
            variables=variables,
            current=current_version,
            latest=latest_version,
            source=listing_url,
            updates=updates,
            details={
                "official_sha256": official_current_sha,
                "configured_sha256": configured_sha,
            },
        )

    return ComponentResult(
        component="HAProxy",
        status=STATUS_CURRENT,
        message="Version and official checksum are current for the configured HAProxy series.",
        variables=variables,
        current=current_version,
        latest=latest_version,
        source=listing_url,
        details={"official_sha256": official_current_sha},
    )


def github_repo_path(repo_url: str) -> str | None:
    parsed = urlparse(repo_url.strip())
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or parsed.query
        or parsed.fragment
    ):
        return None
    repo = parsed.path.removeprefix("/").removesuffix(".git").strip("/")
    parts = repo.split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return None
    return f"{parts[0]}/{parts[1]}"


def latest_github_release(client: HttpClient, repo_path: str) -> dict[str, Any]:
    release = client.get_json(f"https://api.github.com/repos/{repo_path}/releases/latest")
    if release.get("draft") is True or release.get("prerelease") is True:
        raise UpstreamUnknown(f"GitHub latest release for {repo_path} is not stable")
    tag = str(release.get("tag_name", "")).lower()
    if re.search(r"(?:^|[._-])(alpha|beta|rc|nightly|dev)(?:[._-]|\d|$)", tag):
        raise UpstreamUnknown(f"GitHub latest release for {repo_path} is not stable")
    return release


def github_release_by_tag(
    client: HttpClient, repo_path: str, tag: str
) -> dict[str, Any]:
    return client.get_json(
        f"https://api.github.com/repos/{repo_path}/releases/tags/{tag}"
    )


def release_tag_name(release: dict[str, Any], repo_path: str) -> str:
    tag = release.get("tag_name")
    if not isinstance(tag, str) or not tag.strip():
        raise UpstreamUnknown(
            f"GitHub latest release for {repo_path} did not include tag_name"
        )
    tag = tag.strip()
    if not SAFE_REF_RE.fullmatch(tag):
        raise UpstreamError(
            f"GitHub release tag for {repo_path} is not shell-safe: {tag!r}"
        )
    return tag


def check_github_release_ref(
    component: str,
    entries: dict[str, VariableEntry],
    client: HttpClient,
    *,
    repo_var: str,
    ref_var: str,
) -> ComponentResult:
    variables = [repo_var, ref_var]
    repo_url = value(entries, repo_var)
    current_ref = value(entries, ref_var)
    if not repo_url or not current_ref:
        return ComponentResult(
            component=component,
            status=STATUS_UNKNOWN,
            message=NO_SAFE_UPDATER_MESSAGE,
            variables=variables,
            current=current_ref,
            source=repo_url,
            details={"reason": "repository URL or ref is empty"},
        )
    if (
        not SAFE_REF_RE.fullmatch(current_ref)
        or current_ref in {"latest", "master", "main"}
        or "/" in current_ref
    ):
        return ComponentResult(
            component=component,
            status=STATUS_UNKNOWN,
            message=NO_SAFE_UPDATER_MESSAGE,
            variables=variables,
            current=current_ref,
            source=repo_url,
            details={
                "reason": "ref is branch-like or dynamic, not a concrete release tag"
            },
        )
    repo_path = github_repo_path(repo_url)
    if not repo_path:
        return ComponentResult(
            component=component,
            status=STATUS_UNKNOWN,
            message=NO_SAFE_UPDATER_MESSAGE,
            variables=variables,
            current=current_ref,
            source=repo_url,
            details={
                "reason": "repository URL is not an official github.com owner/repo URL"
            },
        )
    latest_ref = release_tag_name(latest_github_release(client, repo_path), repo_path)
    comparison = compare_versions(current_ref, latest_ref)
    if comparison > 0:
        return ComponentResult(
            component=component,
            status=STATUS_UNKNOWN,
            message="Configured ref is newer than the latest GitHub release; refusing to guess.",
            variables=variables,
            current=current_ref,
            latest=latest_ref,
            source=f"https://github.com/{repo_path}",
        )
    if comparison < 0:
        updates: list[UpdateChange] = []
        update = plan_update(entries, ref_var, latest_ref)
        if update:
            updates.append(update)
        return ComponentResult(
            component=component,
            status=STATUS_OUTDATED,
            message="A newer official GitHub release tag is available.",
            variables=variables,
            current=current_ref,
            latest=latest_ref,
            source=f"https://github.com/{repo_path}/releases/latest",
            updates=updates,
        )
    return ComponentResult(
        component=component,
        status=STATUS_CURRENT,
        message="Release tag is current.",
        variables=variables,
        current=current_ref,
        latest=latest_ref,
        source=f"https://github.com/{repo_path}/releases/latest",
    )


def manual_release_provenance_precondition(
    component: str,
    entries: dict[str, VariableEntry],
    *,
    expected_repository: str,
    release_tag_var: str,
    approved_commit_var: str,
    expected_tag: re.Pattern[str],
    aliases: dict[str, str],
    variables: list[str],
) -> ComponentResult | None:
    """Validate the fixed tuple before deferring an atomic manual decision."""

    repository_var = next(name for name in variables if name.endswith("_REPO_URL"))
    repository_url = value(entries, repository_var)
    current_tag = value(entries, release_tag_var)
    if github_repo_path(repository_url) != expected_repository:
        return ComponentResult(
            component=component,
            status=STATUS_UNKNOWN,
            message="Reviewed release provenance must use its fixed official repository.",
            variables=variables,
            current=current_tag,
            source=repository_url,
            details={
                "reason": "approved repository does not match the reviewed identity"
            },
        )
    if expected_tag.fullmatch(current_tag) is None:
        return ComponentResult(
            component=component,
            status=STATUS_UNKNOWN,
            message="Reviewed release provenance must use its expected immutable release-tag form.",
            variables=variables,
            current=current_tag,
            source=repository_url,
            details={
                "reason": "release tag is not in the reviewed component-specific form"
            },
        )
    approved_commit = value(entries, approved_commit_var)
    if GIT_COMMIT_SHA1_RE.fullmatch(approved_commit) is None:
        return ComponentResult(
            component=component,
            status=STATUS_BLOCKED,
            message=f"{approved_commit_var} must be a reviewed 40-hex immutable commit.",
            variables=variables,
            current=current_tag,
            source=repository_url,
            details={
                "reason": f"{approved_commit_var} is required before release provenance can be checked"
            },
        )
    for alias, expected_value in aliases.items():
        if value(entries, alias) != expected_value:
            return ComponentResult(
                component=component,
                status=STATUS_UNKNOWN,
                message="Runtime release metadata must remain bound to the reviewed provenance tuple.",
                variables=variables,
                current=current_tag,
                source=repository_url,
                details={
                    "reason": f"{alias} does not match its reviewed provenance value"
                },
            )
    return None


def review_required_release_result(
    result: ComponentResult,
    *,
    expected_tag: re.Pattern[str],
    manual_variables: tuple[str, ...],
    message: str,
    reason: str,
) -> ComponentResult:
    """Convert only a validated newer tag into an explicit manual review state."""

    if result.status != STATUS_OUTDATED:
        return result
    if expected_tag.fullmatch(result.latest) is None:
        return cast(
            ComponentResult,
            dataclasses.replace(
                result,
                status=STATUS_UNKNOWN,
                updates=[],
                message="Latest upstream release tag is outside the reviewed component-specific form.",
                details={
                    "reason": "latest release tag is outside the reviewed update contract"
                },
            ),
        )
    return cast(
        ComponentResult,
        dataclasses.replace(
            result,
            status=STATUS_REVIEW_REQUIRED,
            updates=[],
            message=message,
            details={"reason": reason, "manual_variables": list(manual_variables)},
        ),
    )


def check_crs_release_provenance(
    entries: dict[str, VariableEntry], client: HttpClient
) -> ComponentResult:
    """Classify a valid CRS tag/commit transition as explicitly manual only."""

    variables = [
        "CRS_APPROVED_REPO_URL",
        "CRS_RELEASE_TAG",
        "CRS_APPROVED_COMMIT",
        "CRS_REPO_URL",
        "CRS_GIT_REF",
    ]
    precondition = manual_release_provenance_precondition(
        CRS_COMPONENT,
        entries,
        expected_repository=CRS_APPROVED_REPOSITORY,
        release_tag_var="CRS_RELEASE_TAG",
        approved_commit_var="CRS_APPROVED_COMMIT",
        expected_tag=RELEASE_TAG_RE,
        aliases={
            "CRS_REPO_URL": value(entries, "CRS_APPROVED_REPO_URL"),
            "CRS_GIT_REF": value(entries, "CRS_RELEASE_TAG"),
        },
        variables=variables,
    )
    if precondition is not None:
        return precondition
    result = check_github_release_ref(
        CRS_COMPONENT,
        entries,
        client,
        repo_var="CRS_APPROVED_REPO_URL",
        ref_var="CRS_RELEASE_TAG",
    )
    result.variables = variables
    return review_required_release_result(
        result,
        expected_tag=RELEASE_TAG_RE,
        manual_variables=MANUAL_REVIEW_VARIABLES[CRS_COMPONENT],
        message=(
            "A newer CRS release is available, but updating its release tag and immutable "
            "commit requires a reviewed provenance change."
        ),
        reason="update CRS_RELEASE_TAG and CRS_APPROVED_COMMIT together after commit provenance review",
    )


def check_modsecurity_v3_release_provenance(
    entries: dict[str, VariableEntry], client: HttpClient
) -> ComponentResult:
    """Classify a valid ModSecurity-v3 tag/commit transition as manual only."""
    variables = [
        "MODSECURITY_V3_APPROVED_REPO_URL",
        "MODSECURITY_V3_RELEASE_TAG",
        "MODSECURITY_V3_APPROVED_COMMIT",
        "MODSECURITY_REPO_URL",
        "MODSECURITY_GIT_REF",
        "MODSECURITY_V3_GIT_URL",
        "MODSECURITY_V3_GIT_REF",
    ]
    precondition = manual_release_provenance_precondition(
        MODSECURITY_V3_COMPONENT,
        entries,
        expected_repository=MODSECURITY_V3_APPROVED_REPOSITORY,
        release_tag_var="MODSECURITY_V3_RELEASE_TAG",
        approved_commit_var="MODSECURITY_V3_APPROVED_COMMIT",
        expected_tag=MODSECURITY_V3_RELEASE_TAG_RE,
        aliases={
            "MODSECURITY_REPO_URL": value(entries, "MODSECURITY_V3_APPROVED_REPO_URL"),
            "MODSECURITY_GIT_REF": value(entries, "MODSECURITY_V3_RELEASE_TAG"),
            "MODSECURITY_V3_GIT_URL": value(
                entries, "MODSECURITY_V3_APPROVED_REPO_URL"
            ),
            "MODSECURITY_V3_GIT_REF": value(entries, "MODSECURITY_V3_RELEASE_TAG"),
        },
        variables=variables,
    )
    if precondition is not None:
        return precondition
    result = check_github_release_ref(
        MODSECURITY_V3_COMPONENT,
        entries,
        client,
        repo_var="MODSECURITY_V3_APPROVED_REPO_URL",
        ref_var="MODSECURITY_V3_RELEASE_TAG",
    )
    result.variables = variables
    return review_required_release_result(
        result,
        expected_tag=MODSECURITY_V3_RELEASE_TAG_RE,
        manual_variables=MANUAL_REVIEW_VARIABLES[MODSECURITY_V3_COMPONENT],
        message=(
            "A newer ModSecurity v3 release is available, but updating its release tag and "
            "immutable commit requires a reviewed provenance change."
        ),
        reason=(
            "update MODSECURITY_V3_RELEASE_TAG and MODSECURITY_V3_APPROVED_COMMIT "
            "together after commit provenance review"
        ),
    )


def release_asset_metadata(release: dict[str, Any], asset_name: str) -> dict[str, Any]:
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise UpstreamUnknown("GitHub release response did not include an assets list")
    matches: list[dict[str, Any]] = []
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        if asset.get("name") == asset_name:
            matches.append(asset)
    if not matches:
        raise UpstreamUnknown(f"GitHub release did not include asset {asset_name}")
    if len(matches) != 1:
        raise UpstreamUnknown(f"GitHub release asset {asset_name} is ambiguous")
    return matches[0]


def find_release_asset(release: dict[str, Any], asset_name: str) -> str:
    asset = release_asset_metadata(release, asset_name)
    url = asset.get("browser_download_url")
    if not isinstance(url, str) or not url:
        raise UpstreamUnknown(
            f"GitHub release asset {asset_name} has no browser download URL"
        )
    return url


def release_asset_sha256(release: dict[str, Any], asset_name: str) -> str:
    asset = release_asset_metadata(release, asset_name)
    digest = asset.get("digest")
    if not isinstance(digest, str):
        raise UpstreamUnknown(
            f"GitHub release asset {asset_name} has no published digest"
        )
    match = re.fullmatch(r"sha256:([A-Fa-f0-9]{64})", digest.strip())
    if not match:
        raise UpstreamUnknown(
            f"GitHub release asset {asset_name} has no usable SHA-256 digest"
        )
    return match.group(1).lower()


def nginx_release_asset_name(release_tag: str) -> str:
    version = release_tag.removeprefix("release-")
    asset_name = f"nginx-{version}.tar.gz"
    if ".." in asset_name or not NGINX_RELEASE_ASSET_RE.fullmatch(asset_name):
        raise UpstreamError(
            f"NGINX release tag cannot form a safe release asset name: {release_tag!r}"
        )
    return asset_name


def check_nginx_release_provenance(
    entries: dict[str, VariableEntry], client: HttpClient
) -> ComponentResult:
    """Verify the reviewed NGINX tag, official release asset, and SHA-256 tuple.

    This check intentionally never produces update edits. A new upstream tag
    changes both the asset identity and its digest, so it must be reviewed and
    changed as one provenance tuple rather than mechanically updating a tag.
    """

    variables = [
        "NGINX_SOURCE_REPO_URL",
        "NGINX_RELEASE_TAG",
        "NGINX_SOURCE_GIT_REF",
        "NGINX_RELEASE_ASSET_NAME",
        "NGINX_SHA256",
    ]
    missing = [name for name in variables if name not in entries]
    if missing:
        return ComponentResult(
            component="NGINX",
            status=STATUS_UNKNOWN,
            message=f"missing variables: {', '.join(missing)}",
            variables=variables,
        )

    repo_url = value(entries, "NGINX_SOURCE_REPO_URL")
    release_tag = value(entries, "NGINX_RELEASE_TAG")
    source_ref = value(entries, "NGINX_SOURCE_GIT_REF")
    asset_name = value(entries, "NGINX_RELEASE_ASSET_NAME")
    configured_sha256 = value(entries, "NGINX_SHA256").lower()
    current = f"{release_tag} / {asset_name} / {configured_sha256}"
    repo_path = github_repo_path(repo_url)
    if not repo_path:
        return ComponentResult(
            component="NGINX",
            status=STATUS_UNKNOWN,
            message="NGINX source is not an official HTTPS GitHub owner/repo URL.",
            variables=variables,
            current=current,
            source=repo_url,
        )
    if (
        release_tag == "latest"
        or not SAFE_REF_RE.fullmatch(release_tag)
        or "/" in release_tag
    ):
        return ComponentResult(
            component="NGINX",
            status=STATUS_UNKNOWN,
            message="NGINX_RELEASE_TAG must be a fixed release tag for provenance verification.",
            variables=variables,
            current=current,
            source=repo_url,
        )
    if source_ref != release_tag:
        return ComponentResult(
            component="NGINX",
            status=STATUS_UNKNOWN,
            message="NGINX_SOURCE_GIT_REF must equal NGINX_RELEASE_TAG for a fixed release asset.",
            variables=variables,
            current=current,
            source=repo_url,
        )
    expected_asset_name = nginx_release_asset_name(release_tag)
    if asset_name != expected_asset_name:
        return ComponentResult(
            component="NGINX",
            status=STATUS_UNKNOWN,
            message="NGINX release tag and release asset name are not an atomic expected pair.",
            variables=variables,
            current=current,
            source=repo_url,
            details={"expected_asset_name": expected_asset_name},
        )
    if not re.fullmatch(r"[a-f0-9]{64}", configured_sha256):
        return ComponentResult(
            component="NGINX",
            status=STATUS_UNKNOWN,
            message="NGINX_SHA256 must be a non-empty 64-character SHA-256 value.",
            variables=variables,
            current=current,
            source=repo_url,
        )

    current_release = github_release_by_tag(client, repo_path, release_tag)
    resolved_tag = release_tag_name(current_release, repo_path)
    if resolved_tag != release_tag:
        return ComponentResult(
            component="NGINX",
            status=STATUS_UNKNOWN,
            message="GitHub release metadata did not resolve to the configured NGINX release tag.",
            variables=variables,
            current=current,
            source=f"https://github.com/{repo_path}/releases/tag/{release_tag}",
            details={"resolved_release_tag": resolved_tag},
        )
    official_asset_url = find_release_asset(current_release, asset_name)
    expected_asset_url = (
        f"https://github.com/{repo_path}/releases/download/{release_tag}/{asset_name}"
    )
    if official_asset_url != expected_asset_url:
        return ComponentResult(
            component="NGINX",
            status=STATUS_UNKNOWN,
            message="GitHub release asset URL does not match the configured tag/asset download endpoint.",
            variables=variables,
            current=current,
            source=f"https://github.com/{repo_path}/releases/tag/{release_tag}",
            details={
                "official_asset_url": official_asset_url,
                "expected_asset_url": expected_asset_url,
            },
        )
    official_sha256 = release_asset_sha256(current_release, asset_name)
    if configured_sha256 != official_sha256:
        return ComponentResult(
            component="NGINX",
            status=STATUS_UNKNOWN,
            message="Configured NGINX_SHA256 does not match the official GitHub release asset digest.",
            variables=variables,
            current=current,
            source=f"https://github.com/{repo_path}/releases/tag/{release_tag}",
            details={"official_asset_sha256": official_sha256},
        )

    latest_release = latest_github_release(client, repo_path)
    latest_tag = release_tag_name(latest_release, repo_path)
    if not re.fullmatch(r"release-\d+(?:\.\d+)+", latest_tag):
        raise UpstreamUnknown("latest NGINX release tag has an unexpected format")
    comparison = compare_versions(release_tag, latest_tag)
    if comparison < 0:
        latest_asset = nginx_release_asset_name(latest_tag)
        latest_url = find_release_asset(latest_release, latest_asset)
        expected_url = f"https://github.com/{repo_path}/releases/download/{latest_tag}/{latest_asset}"
        if latest_url != expected_url:
            raise UpstreamUnknown("latest NGINX asset URL is not the exact release endpoint")
        latest_sha = release_asset_sha256(latest_release, latest_asset)
        updates = [update for update in (
            plan_update(entries, "NGINX_RELEASE_TAG", latest_tag),
            plan_update(entries, "NGINX_SHA256", latest_sha),
        ) if update is not None]
        if len(updates) != 2:
            raise UpstreamError("NGINX atomic update did not contain tag and SHA-256")
        return ComponentResult(
            component="NGINX", status=STATUS_OUTDATED,
            message="A newer stable NGINX tag, exact asset, and published digest are available.",
            variables=variables, current=current, latest=latest_tag,
            source=f"https://github.com/{repo_path}/releases/latest", updates=updates,
            details={"asset_name": latest_asset, "latest_source_url": latest_url,
                     "official_sha256": latest_sha, "sha_source": "GitHub release asset digest",
                     "atomic_group": variables},
        )
    if comparison > 0:
        raise UpstreamUnknown("configured NGINX release is newer than latest upstream")

    return ComponentResult(
        component="NGINX",
        status=STATUS_CURRENT,
        message=(
            "Configured release tag, official release asset, and published SHA-256 digest "
            "match the reviewed NGINX provenance tuple. New NGINX releases require a "
            "separate atomic review update."
        ),
        variables=variables,
        current=current,
        latest=release_tag,
        source=f"https://github.com/{repo_path}/releases/tags/{release_tag}",
        details={
            "official_asset_url": official_asset_url,
            "official_asset_sha256": official_sha256,
        },
    )


def check_pcre2(
    entries: dict[str, VariableEntry], client: HttpClient
) -> ComponentResult:
    variables = [
        "PCRE2_VERSION",
        "PCRE2_SOURCE_URL",
        "PCRE2_SHA256",
        "PCRE2_SHA256_URL",
    ]
    missing = [name for name in variables if name not in entries]
    if missing:
        return ComponentResult(
            component="PCRE2",
            status=STATUS_UNKNOWN,
            message=f"missing variables: {', '.join(missing)}",
            variables=variables,
        )
    current_version = value(entries, "PCRE2_VERSION")
    current_url = value(entries, "PCRE2_SOURCE_URL")
    match = re.fullmatch(
        r"https://github\.com/([^/]+/[^/]+)/releases/download/pcre2-(\d+(?:\.\d+)+)/pcre2-(\d+(?:\.\d+)+)\.tar\.bz2",
        current_url,
    )
    if (
        not match
        or match.group(2) != current_version
        or match.group(3) != current_version
    ):
        return ComponentResult(
            component="PCRE2",
            status=STATUS_UNKNOWN,
            message=NO_SAFE_UPDATER_MESSAGE,
            variables=variables,
            current=current_version,
            source=current_url,
            details={
                "reason": "source URL is not the expected official GitHub release asset URL"
            },
        )
    repo_path = match.group(1)
    latest_release = latest_github_release(client, repo_path)
    latest_tag = release_tag_name(latest_release, repo_path)
    latest_version = re.sub(r"^pcre2-", "", latest_tag)
    version_tuple(latest_version)
    latest_asset_name = f"pcre2-{latest_version}{ARCHIVE_BZ2_EXTENSION}"
    latest_asset_url = find_release_asset(latest_release, latest_asset_name)
    latest_sha256 = release_asset_sha256(latest_release, latest_asset_name)
    comparison = compare_versions(current_version, latest_version)

    if comparison > 0:
        return ComponentResult(
            component="PCRE2",
            status=STATUS_UNKNOWN,
            message="Configured version is newer than the latest GitHub release; refusing to guess.",
            variables=variables,
            current=current_version,
            latest=latest_version,
            source=f"https://github.com/{repo_path}",
        )
    if comparison < 0:
        updates: list[UpdateChange] = []
        update = plan_update(entries, "PCRE2_VERSION", latest_version)
        if update:
            updates.append(update)
        source_entry = entries["PCRE2_SOURCE_URL"]
        if not is_template_value(source_entry.default, "PCRE2_VERSION"):
            update = plan_update(entries, "PCRE2_SOURCE_URL", latest_asset_url)
            if update:
                updates.append(update)
        update = plan_update(entries, "PCRE2_SHA256", latest_sha256)
        if update:
            updates.append(update)
        return ComponentResult(
            component="PCRE2",
            status=STATUS_OUTDATED,
            message="A newer official GitHub release asset is available.",
            variables=variables,
            current=current_version,
            latest=latest_version,
            source=f"https://github.com/{repo_path}/releases/latest",
            updates=updates,
            details={
                "asset_name": latest_asset_name,
                "latest_source_url": latest_asset_url,
                "official_sha256": latest_sha256,
                "sha_source": "GitHub release asset digest",
            },
        )

    current_release = github_release_by_tag(
        client, repo_path, f"pcre2-{current_version}"
    )
    current_asset_url = find_release_asset(
        current_release, f"pcre2-{current_version}{ARCHIVE_BZ2_EXTENSION}"
    )
    current_official_sha = release_asset_sha256(
        current_release, f"pcre2-{current_version}{ARCHIVE_BZ2_EXTENSION}"
    )
    if current_asset_url != current_url:
        update = plan_update(entries, "PCRE2_SOURCE_URL", current_asset_url)
        updates = [update] if update else []
        return ComponentResult(
            component="PCRE2",
            status=STATUS_OUTDATED,
            message="Configured PCRE2 source URL differs from the official GitHub release asset.",
            variables=variables,
            current=current_version,
            latest=latest_version,
            source=f"https://github.com/{repo_path}/releases/tag/pcre2-{current_version}",
            updates=updates,
            details={"official_source_url": current_asset_url},
        )
    if value(entries, "PCRE2_SHA256").lower() != current_official_sha:
        update = plan_update(entries, "PCRE2_SHA256", current_official_sha)
        return ComponentResult(
            component="PCRE2", status=STATUS_OUTDATED,
            message="Configured PCRE2 SHA-256 differs from the published asset digest.",
            variables=variables, current=current_version, latest=latest_version,
            source=f"https://github.com/{repo_path}/releases/tag/pcre2-{current_version}",
            updates=[update] if update else [],
            details={"official_sha256": current_official_sha, "sha_source": "GitHub release asset digest"},
        )
    return ComponentResult(
        component="PCRE2",
        status=STATUS_CURRENT,
        message="Version and release asset URL are current.",
        variables=variables,
        current=current_version,
        latest=latest_version,
        source=f"https://github.com/{repo_path}/releases/latest",
    )


def check_github_binary_release(
    component: str, entries: dict[str, VariableEntry], client: HttpClient, *,
    repo: str, version_var: str, download_var: str, sha_var: str,
    sha_url_var: str, asset_template: str, manifest_template: str,
) -> ComponentResult:
    """Resolve an exact GitHub asset and its official digest/manifest atomically."""
    variables = [version_var, download_var, sha_var, sha_url_var]
    missing = missing_variables_result(component, entries, variables)
    if missing:
        return missing
    current_version = value(entries, version_var)
    release = latest_github_release(client, repo)
    tag = release_tag_name(release, repo)
    if not tag.startswith("v") or tag[1:] != dotted_version_text(tag):
        raise UpstreamUnknown(f"{component} release tag has an unexpected format")
    latest_version = tag[1:]
    asset = asset_template.format(version=latest_version, tag=tag)
    asset_url = find_release_asset(release, asset)
    expected_url = f"https://github.com/{repo}/releases/download/{tag}/{asset}"
    if asset_url != expected_url:
        raise UpstreamUnknown(f"{component} asset URL is not the exact release endpoint")
    sha_source = "GitHub release asset digest"
    try:
        digest = release_asset_sha256(release, asset)
        checksum_url = f"https://api.github.com/repos/{repo}/releases/latest"
    except UpstreamUnknown:
        manifest = manifest_template.format(version=latest_version, tag=tag)
        checksum_url = find_release_asset(release, manifest)
        digest = fetch_sha256(client, checksum_url, asset)
        sha_source = f"official manifest {manifest}"
    comparison = compare_versions(current_version, latest_version)
    if comparison > 0:
        raise UpstreamUnknown(f"configured {component} version is newer than upstream")
    updates: list[UpdateChange] = []
    if comparison < 0:
        append_planned_update(updates, entries, version_var, latest_version)
    if not is_template_value(entries[download_var].default, version_var):
        append_planned_update(updates, entries, download_var, asset_url)
    append_planned_update(updates, entries, sha_var, digest)
    if not is_template_value(entries[sha_url_var].default, version_var):
        append_planned_update(updates, entries, sha_url_var, checksum_url)
    status = STATUS_OUTDATED if updates else STATUS_CURRENT
    return ComponentResult(
        component=component, status=status,
        message=("A complete trusted release tuple is available." if updates else "Release tuple is current."),
        variables=variables, current=current_version, latest=latest_version,
        source=f"https://github.com/{repo}/releases/latest", updates=updates,
        details={"asset_name": asset, "latest_source_url": asset_url,
                 "sha_source": sha_source, "sha256_url": checksum_url,
                 "official_sha256": digest, "atomic_group": variables},
    )


def check_lighttpd(entries: dict[str, VariableEntry], client: HttpClient) -> ComponentResult:
    variables = ["LIGHTTPD_VERSION", "LIGHTTPD_RELEASE_INDEX_URL", "LIGHTTPD_LATEST_URL",
                 "LIGHTTPD_DOWNLOAD_URL", "LIGHTTPD_SHA256", "LIGHTTPD_SHA256_URL"]
    missing = missing_variables_result("lighttpd", entries, variables)
    if missing:
        return missing
    base = value(entries, "LIGHTTPD_RELEASE_INDEX_URL")
    latest_url = value(entries, "LIGHTTPD_LATEST_URL")
    if base != "https://download.lighttpd.net/lighttpd/releases-1.4.x/" or latest_url != base + "latest.txt":
        raise UpstreamUnknown("lighttpd release index must use its canonical official host")
    latest_text = client.get_text(latest_url).strip()
    match = re.search(r"lighttpd-(\d+(?:\.\d+)+)\.tar\.xz", latest_text)
    latest = match.group(1) if match else dotted_version_text(latest_text)
    asset = f"lighttpd-{latest}.tar.xz"
    source_url = base + asset
    checksum_url = base + f"lighttpd-{latest}.sha256sum"
    digest = fetch_sha256(client, checksum_url, asset)
    updates: list[UpdateChange] = []
    if compare_versions(value(entries, "LIGHTTPD_VERSION"), latest) < 0:
        append_planned_update(updates, entries, "LIGHTTPD_VERSION", latest)
    append_planned_update(updates, entries, "LIGHTTPD_SHA256", digest)
    return ComponentResult(
        component="lighttpd", status=STATUS_OUTDATED if updates else STATUS_CURRENT,
        message="Official latest.txt release and exact SHA-256 are verified.", variables=variables,
        current=value(entries, "LIGHTTPD_VERSION"), latest=latest, source=latest_url, updates=updates,
        details={"asset_name": asset, "latest_source_url": source_url,
                 "sha_source": checksum_url, "official_sha256": digest, "atomic_group": variables},
    )


def check_nginx_quic_tls(entries: dict[str, VariableEntry], client: HttpClient) -> ComponentResult:
    variables = ["NGINX_QUIC_TLS_VERSION", "NGINX_QUIC_TLS_SOURCE_URL", "NGINX_QUIC_TLS_SOURCE_SHA256"]
    missing = missing_variables_result("OpenSSL (NGINX QUIC/TLS)", entries, variables)
    if missing:
        return missing
    release = latest_github_release(client, "openssl/openssl")
    tag = release_tag_name(release, "openssl/openssl")
    match = re.fullmatch(r"openssl-(\d+(?:\.\d+)+)", tag)
    if not match:
        raise UpstreamUnknown("OpenSSL stable release tag has an unexpected format")
    latest = match.group(1)
    asset = f"openssl-{latest}.tar.gz"
    source_url = find_release_asset(release, asset)
    expected = f"https://github.com/openssl/openssl/releases/download/{tag}/{asset}"
    if source_url != expected:
        raise UpstreamUnknown("OpenSSL asset URL is not the exact release endpoint")
    digest = release_asset_sha256(release, asset)
    updates: list[UpdateChange] = []
    if compare_versions(value(entries, "NGINX_QUIC_TLS_VERSION"), latest) < 0:
        append_planned_update(updates, entries, "NGINX_QUIC_TLS_VERSION", latest)
    append_planned_update(updates, entries, "NGINX_QUIC_TLS_SOURCE_SHA256", digest)
    return ComponentResult(
        component="OpenSSL (NGINX QUIC/TLS)", status=STATUS_OUTDATED if updates else STATUS_CURRENT,
        message="Official OpenSSL release asset digest is verified.", variables=variables,
        current=value(entries, "NGINX_QUIC_TLS_VERSION"), latest=latest,
        source="https://github.com/openssl/openssl/releases/latest", updates=updates,
        details={"asset_name": asset, "latest_source_url": source_url,
                 "sha_source": "GitHub release asset digest", "official_sha256": digest,
                 "atomic_group": variables},
    )


def unknown_component(
    component: str,
    entries: dict[str, VariableEntry],
    variables: list[str],
    reason: str,
) -> ComponentResult:
    return ComponentResult(
        component=component,
        status=STATUS_UNKNOWN,
        message=NO_SAFE_UPDATER_MESSAGE,
        variables=variables,
        current=", ".join(
            f"{name}={value(entries, name)}" for name in variables if name in entries
        ),
        details={"reason": reason},
    )


def not_applicable_component(
    component: str,
    entries: dict[str, VariableEntry],
    variables: list[str],
    reason: str,
) -> ComponentResult:
    """Describe a tracked local-policy entry that has no updater contract."""

    return ComponentResult(
        component=component,
        status=STATUS_NOT_APPLICABLE,
        message=reason,
        variables=variables,
        current=", ".join(
            f"{name}={value(entries, name)}" for name in variables if name in entries
        ),
        details={"reason": reason},
    )


COMPONENT_SPECS: tuple[ComponentSpec, ...] = (
    ComponentSpec("Envoy", "envoyproxy/envoy", ("ENVOY_VERSION", "ENVOY_SOURCE_URL", "ENVOY_DOWNLOAD_URL", "ENVOY_SHA256", "ENVOY_SHA256_URL"), "github_release_asset_or_manifest", "envoy-{version}-linux-x86_64"),
    ComponentSpec("Traefik", "traefik/traefik", ("TRAEFIK_VERSION", "TRAEFIK_SOURCE_URL", "TRAEFIK_DOWNLOAD_URL", "TRAEFIK_SHA256", "TRAEFIK_SHA256_URL"), "github_release_manifest", "traefik_v{version}_linux_amd64.tar.gz"),
    ComponentSpec("lighttpd", "download.lighttpd.net", ("LIGHTTPD_VERSION", "LIGHTTPD_SOURCE_URL", "LIGHTTPD_RELEASE_INDEX_URL", "LIGHTTPD_LATEST_URL", "LIGHTTPD_DOWNLOAD_URL", "LIGHTTPD_SHA256", "LIGHTTPD_SHA256_URL"), "latest_txt_sha256sum", "lighttpd-{version}.tar.xz", update_policy="latest stable 1.4.x"),
    ComponentSpec(CRS_COMPONENT, CRS_APPROVED_REPOSITORY, MANUAL_REVIEW_VARIABLES[CRS_COMPONENT], "release_tag_peeled_commit", tag_format="vX.Y.Z", automatic=False, update_policy="manual immutable-commit review"),
    ComponentSpec(MODSECURITY_V3_COMPONENT, MODSECURITY_V3_APPROVED_REPOSITORY, MANUAL_REVIEW_VARIABLES[MODSECURITY_V3_COMPONENT], "release_tag_peeled_commit", tag_format="v3.X.Y", automatic=False, update_policy="manual immutable-commit review"),
    ComponentSpec("Apache httpd", APACHE_DOWNLOAD_HOST, ("HTTPD_VERSION", "HTTPD_SOURCE_URL", "HTTPD_SHA256", "HTTPD_SHA256_URL"), "apache_listing_sha256", "httpd-{version}.tar.bz2", update_policy="latest compatible 2.4.x"),
    ComponentSpec("APR", APACHE_DOWNLOAD_HOST, ("APR_VERSION", "APR_SOURCE_URL", "APR_SHA256", "APR_SHA256_URL"), "apache_listing_sha256", "apr-{version}.tar.bz2", update_policy="latest compatible major.minor series"),
    ComponentSpec("APR-util", APACHE_DOWNLOAD_HOST, ("APR_UTIL_PINNED_VERSION", "APR_UTIL_PINNED_SOURCE_URL", "APR_UTIL_PINNED_SHA256", "APR_UTIL_PINNED_SHA256_URL", "APR_UTIL_VERSION", "APR_UTIL_SOURCE_URL", "APR_UTIL_SHA256", "APR_UTIL_SHA256_URL"), "apache_listing_sha256", "apr-util-{version}.tar.bz2", update_policy="latest compatible 1.6.x"),
    ComponentSpec("PCRE2", "PCRE2Project/pcre2", ("PCRE2_VERSION", "PCRE2_SOURCE_URL", "PCRE2_SHA256", "PCRE2_SHA256_URL"), "github_release_asset_digest", "pcre2-{version}.tar.bz2"),
    ComponentSpec("NGINX", "nginx/nginx", ("NGINX_SOURCE_REPO_URL", "NGINX_RELEASE_TAG", "NGINX_SOURCE_GIT_REF", "NGINX_RELEASE_ASSET_NAME", "NGINX_SHA256"), "github_release_asset_digest", "nginx-{version}.tar.gz", tag_format="release-X.Y.Z"),
    ComponentSpec("OpenSSL (NGINX QUIC/TLS)", "openssl/openssl", ("NGINX_QUIC_TLS_VERSION", "NGINX_QUIC_TLS_SOURCE_URL", "NGINX_QUIC_TLS_SOURCE_SHA256"), "github_release_asset_digest", "openssl-{version}.tar.gz", tag_format="openssl-X.Y.Z"),
    ComponentSpec("HAProxy", "www.haproxy.org", ("HAPROXY_VERSION", "HAPROXY_SOURCE_URL", "HAPROXY_SHA256_URL", "HAPROXY_SHA256"), "haproxy_series_sha256", "haproxy-{version}.tar.gz", update_policy="latest compatible major.minor series"),
    ComponentSpec("go-ftw", "coreruleset/go-ftw", ("GO_FTW_SOURCE_URL", "GO_FTW_PROMPT_EXPECTED_LATEST", "GO_FTW_GIT_REF"), "github_release_tag", automatic=False, update_policy="prompt metadata; installation is external"),
    ComponentSpec("Albedo", "coreruleset/albedo", ("ALBEDO_SOURCE_URL", "ALBEDO_PROMPT_EXPECTED_LATEST", "ALBEDO_GIT_REF"), "github_release_tag", automatic=False, update_policy="prompt metadata; installation is external"),
    ComponentSpec("Expat", "libexpat/libexpat", ("EXPAT_SOURCE_URL", "EXPAT_GIT_URL", "EXPAT_GIT_REF", "EXPAT_PROMPT_EXPECTED_LATEST"), "not_applicable", automatic=False, update_policy="legacy prompt-only metadata; no repository fetch"),
    ComponentSpec("ModSecurity Apache connector", "repo-local", ("MODSECURITY_APACHE_GIT_URL", "MODSECURITY_APACHE_GIT_REF"), "not_applicable", automatic=False),
    ComponentSpec("ModSecurity NGINX connector", "repo-local", ("MODSECURITY_NGINX_GIT_URL", "MODSECURITY_NGINX_GIT_REF"), "not_applicable", automatic=False),
    ComponentSpec("Default branch", "local policy", ("DEFAULT_BRANCH",), "not_applicable", automatic=False),
)

CANONICAL_COMPONENTS = tuple(spec.name for spec in COMPONENT_SPECS)


def check_all(
    entries: dict[str, VariableEntry], client: HttpClient,
    selected: set[str] | None = None,
) -> list[ComponentResult]:
    checks: list[ComponentResult] = []

    def nginx_check() -> ComponentResult:
        return check_nginx_release_provenance(entries, client)

    component_calls = [
        ("Envoy", lambda: check_github_binary_release("Envoy", entries, client, repo="envoyproxy/envoy", version_var="ENVOY_VERSION", download_var="ENVOY_DOWNLOAD_URL", sha_var="ENVOY_SHA256", sha_url_var="ENVOY_SHA256_URL", asset_template="envoy-{version}-linux-x86_64", manifest_template="checksums.txt.asc")),
        ("Traefik", lambda: check_github_binary_release("Traefik", entries, client, repo="traefik/traefik", version_var="TRAEFIK_VERSION", download_var="TRAEFIK_DOWNLOAD_URL", sha_var="TRAEFIK_SHA256", sha_url_var="TRAEFIK_SHA256_URL", asset_template="traefik_v{version}_linux_amd64.tar.gz", manifest_template="traefik_v{version}_checksums.txt")),
        ("lighttpd", lambda: check_lighttpd(entries, client)),
        (
            "OWASP Core Rule Set",
            lambda: check_crs_release_provenance(entries, client),
        ),
        (
            MODSECURITY_V3_COMPONENT,
            lambda: check_modsecurity_v3_release_provenance(entries, client),
        ),
        (
            "ModSecurity Apache connector",
            lambda: not_applicable_component(
                "ModSecurity Apache connector",
                entries,
                ["MODSECURITY_APACHE_GIT_URL", "MODSECURITY_APACHE_GIT_REF"],
                "connector source is repo-local unless explicitly configured",
            ),
        ),
        (
            "ModSecurity NGINX connector",
            lambda: not_applicable_component(
                "ModSecurity NGINX connector",
                entries,
                ["MODSECURITY_NGINX_GIT_URL", "MODSECURITY_NGINX_GIT_REF"],
                "connector source is repo-local unless explicitly configured",
            ),
        ),
        (
            "Apache httpd",
            lambda: official_tarball_check(
                "Apache httpd",
                entries,
                client,
                version_var="HTTPD_VERSION",
                source_url_var="HTTPD_SOURCE_URL",
                sha_var="HTTPD_SHA256",
                sha_url_var="HTTPD_SHA256_URL",
                filename_prefix="httpd",
                extension=ARCHIVE_BZ2_EXTENSION,
                allowed_host=APACHE_DOWNLOAD_HOST,
                restrict_to_current_series=True,
            ),
        ),
        (
            "APR",
            lambda: official_tarball_check(
                "APR",
                entries,
                client,
                version_var="APR_VERSION",
                source_url_var="APR_SOURCE_URL",
                sha_var="APR_SHA256",
                sha_url_var="APR_SHA256_URL",
                filename_prefix="apr",
                extension=ARCHIVE_BZ2_EXTENSION,
                allowed_host=APACHE_DOWNLOAD_HOST,
                restrict_to_current_series=True,
            ),
        ),
        (
            "APR-util",
            lambda: check_apr_util_release_provenance(entries, client),
        ),
        ("PCRE2", lambda: check_pcre2(entries, client)),
        ("NGINX", nginx_check),
        ("OpenSSL (NGINX QUIC/TLS)", lambda: check_nginx_quic_tls(entries, client)),
        ("HAProxy", lambda: check_haproxy(entries, client)),
        ("go-ftw", lambda: not_applicable_component("go-ftw", entries, ["GO_FTW_SOURCE_URL", "GO_FTW_PROMPT_EXPECTED_LATEST", "GO_FTW_GIT_REF"], "prompt-only metadata; no source is fetched by this repository")),
        ("Albedo", lambda: not_applicable_component("Albedo", entries, ["ALBEDO_SOURCE_URL", "ALBEDO_PROMPT_EXPECTED_LATEST", "ALBEDO_GIT_REF"], "prompt-only metadata; no source is fetched by this repository")),
        ("Expat", lambda: not_applicable_component("Expat", entries, ["EXPAT_SOURCE_URL", "EXPAT_GIT_URL", "EXPAT_GIT_REF", "EXPAT_PROMPT_EXPECTED_LATEST"], "legacy prompt-only metadata; no source is fetched by this repository")),
        (
            "Default branch",
            lambda: not_applicable_component(
                "Default branch",
                entries,
                ["DEFAULT_BRANCH"],
                "DEFAULT_BRANCH is a local policy default, not an upstream release source",
            ),
        ),
    ]
    for component, call in component_calls:
        if selected is not None and component not in selected:
            continue
        try:
            checks.append(call())
        except UpstreamUnknown as exc:
            checks.append(
                ComponentResult(
                    component=component,
                    status=STATUS_UNKNOWN,
                    message=str(exc),
                    variables=[],
                )
            )
        except UpstreamBlocked as exc:
            checks.append(
                ComponentResult(
                    component=component,
                    status=STATUS_BLOCKED,
                    message=str(exc),
                    variables=[],
                )
            )
        except UpstreamError as exc:
            checks.append(
                ComponentResult(
                    component=component,
                    status=STATUS_ERROR,
                    message=str(exc),
                    variables=[],
                )
            )
    return checks


def inventory(entries: dict[str, VariableEntry]) -> list[dict[str, Any]]:
    rows = []
    for item in sorted(entries.values(), key=lambda current: current.line):
        if not item.tracked:
            continue
        rows.append(
            {
                "name": item.name,
                "line": item.line,
                "default": item.default,
                "resolved": item.resolved,
                "style": item.style,
            }
        )
    return rows


INVENTORY_NAME_RE = re.compile(
    r"(?:_VERSION|_RELEASE_TAG|_GIT_REF|_APPROVED_COMMIT|_SOURCE_URL|"
    r"_DOWNLOAD_URL|_RELEASE_ASSET_NAME|_SHA256|_SOURCE_SHA256|_SHA256_URL|"
    r"_CHECKSUM(?:_URL)?|_PROMPT_EXPECTED_LATEST)$"
)


def inventory_ownership_errors(entries: dict[str, VariableEntry]) -> list[str]:
    owned = {name for spec in COMPONENT_SPECS for name in spec.variables}
    relevant = {name for name in entries if INVENTORY_NAME_RE.search(name)}
    return sorted(relevant - owned)


def flatten_updates(results: list[ComponentResult]) -> list[UpdateChange]:
    updates: list[UpdateChange] = []
    for result in results:
        updates.extend(result.updates)
    ordered: dict[str, UpdateChange] = {}
    for update in updates:
        previous = ordered.get(update.variable)
        if previous and previous.new != update.new:
            raise UpstreamError(
                f"conflicting updates for {update.variable}: {previous.new!r} vs {update.new!r}"
            )
        ordered[update.variable] = update
    return sorted(ordered.values(), key=lambda update: update.line)


def append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def reviewed_manual_variables(result: ComponentResult) -> tuple[str, ...] | None:
    """Return the only manual pin set that may be deferred by maintenance mode."""

    expected = MANUAL_REVIEW_VARIABLES.get(result.component)
    declared = result.details.get("manual_variables")
    if (
        expected is None
        or result.updates
        or not isinstance(declared, list)
        or declared != list(expected)
    ):
        return None
    return expected


def manual_review_pin_values(
    results: list[ComponentResult], entries: dict[str, VariableEntry]
) -> dict[str, str]:
    """Capture exact reviewed-pin source lines for a later byte-for-byte check."""

    values: dict[str, str] = {}
    for result in results:
        if result.status != STATUS_REVIEW_REQUIRED:
            continue
        variables = reviewed_manual_variables(result)
        if variables is None:
            raise UpstreamError(
                f"manual review metadata is invalid for {result.component}"
            )
        for variable in variables:
            current = entry(entries, variable)
            if current is None:
                raise UpstreamError(
                    f"manual review pin {variable} is missing for {result.component}"
                )
            previous = values.get(variable)
            if previous is not None and previous != current.raw:
                raise UpstreamError(
                    f"manual review pin {variable} has conflicting source lines"
                )
            values[variable] = current.raw
    return values


def manual_review_pin_digest(
    results: list[ComponentResult], entries: dict[str, VariableEntry]
) -> str:
    """Hash a canonical, non-secret proof of the exact manual pin source lines."""

    pins = manual_review_pin_values(results, entries)
    if not pins:
        return ""
    payload = "".join(f"{name}\0{pins[name]}\n" for name in sorted(pins))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def require_manual_review_pins_unchanged(
    before: dict[str, str], after: dict[str, VariableEntry]
) -> None:
    """Reject a candidate if an automatic plan touched a manual source line."""

    for variable, raw_line in before.items():
        updated = entry(after, variable)
        if updated is None or updated.raw != raw_line:
            raise UpstreamError(
                f"automatic candidate changed manual review pin {variable}"
            )


def manual_review_variable_names(results: list[ComponentResult]) -> set[str]:
    """Return the declared manual variables from already-recognized review rows."""

    names: set[str] = set()
    for result in results:
        if result.status != STATUS_REVIEW_REQUIRED:
            continue
        reviewed = reviewed_manual_variables(result)
        if reviewed is not None:
            names.update(reviewed)
    return names


def update_matches_automatic_plan(
    update: UpdateChange,
    result: ComponentResult,
    entries: dict[str, VariableEntry],
    manual_variables: set[str],
) -> bool:
    """Accept only an exact automatic update that cannot touch a manual pin."""

    current = entry(entries, update.variable)
    try:
        require_shell_safe_default(
            update.variable,
            update.old,
            current.default if current is not None else None,
        )
        require_shell_safe_default(
            update.variable,
            update.new,
            current.default if current is not None else None,
        )
    except UpstreamError:
        return False
    return bool(
        current is not None
        and update.variable in result.variables
        and update.line == current.line
        and update.old == current.default
        and update.variable not in manual_variables
    )


def automatic_plan_errors(
    automatic_results: list[ComponentResult],
    entries: dict[str, VariableEntry],
    manual_variables: set[str],
) -> list[str]:
    """Return every component whose automatic update set is incomplete or unsafe."""

    invalid_components: list[str] = []
    seen_variables: dict[str, str] = {}
    for result in automatic_results:
        if not result.updates:
            append_unique(invalid_components, result.component)
            continue
        for update in result.updates:
            if not update_matches_automatic_plan(
                update, result, entries, manual_variables
            ):
                append_unique(invalid_components, result.component)
                continue
            previous_component = seen_variables.get(update.variable)
            if previous_component is not None:
                append_unique(invalid_components, result.component)
                append_unique(invalid_components, previous_component)
                continue
            seen_variables[update.variable] = result.component
    return invalid_components


def maintenance_update_plan(
    results: list[ComponentResult], entries: dict[str, VariableEntry]
) -> tuple[list[UpdateChange], list[str]]:
    """Return only complete automatic plans, or their affected fatal components."""

    automatic_results = [
        result for result in results if result.status == STATUS_OUTDATED
    ]
    plan_errors = automatic_plan_errors(
        automatic_results,
        entries,
        manual_review_variable_names(results),
    )
    if plan_errors:
        return [], plan_errors
    try:
        updates = flatten_updates(automatic_results)
    except UpstreamError:
        return [], [result.component for result in automatic_results]
    expected_count = sum(len(result.updates) for result in automatic_results)
    if len(updates) != expected_count:
        return [], [result.component for result in automatic_results]
    return updates, []


def reviewed_component_groups(
    results: list[ComponentResult],
) -> tuple[list[str], list[str]]:
    """Separate fail-closed statuses from explicitly recognized manual review."""

    fatal_components: list[str] = []
    manual_components: list[str] = []
    for result in results:
        if result.status in FATAL_STATUSES:
            append_unique(fatal_components, result.component)
        elif result.status == STATUS_REVIEW_REQUIRED:
            destination = (
                manual_components
                if reviewed_manual_variables(result) is not None
                else fatal_components
            )
            append_unique(destination, result.component)
    return fatal_components, manual_components


def append_review_components_as_fatal(
    fatal_components: list[str], results: list[ComponentResult]
) -> None:
    """Preserve failure when a reviewed pin snapshot cannot be proven exact."""

    for result in results:
        if result.status == STATUS_REVIEW_REQUIRED:
            append_unique(fatal_components, result.component)


def manual_review_pins_are_valid(
    results: list[ComponentResult], entries: dict[str, VariableEntry]
) -> bool:
    try:
        manual_review_pin_values(results, entries)
    except UpstreamError:
        return False
    return True


def append_unique_values(destination: list[str], values: list[str]) -> None:
    for value in values:
        append_unique(destination, value)


def build_maintenance_disposition(
    fatal_components: list[str],
    manual_components: list[str],
    automatic_updates: list[UpdateChange],
) -> MaintenanceDisposition:
    """Construct the sole terminal disposition after every safety check ran."""

    if fatal_components:
        return MaintenanceDisposition(
            outcome=MAINTENANCE_OUTCOME_FATAL,
            safe_updates_available=False,
            manual_review_required=bool(manual_components),
            manual_review_components=tuple(manual_components),
            fatal_components=tuple(fatal_components),
            automatic_updates=(),
            automatic_update_variables=(),
        )

    safe_updates_available = bool(automatic_updates)
    if safe_updates_available:
        outcome = (
            MAINTENANCE_OUTCOME_SAFE_UPDATES_WITH_MANUAL_REVIEW
            if manual_components
            else MAINTENANCE_OUTCOME_SAFE_UPDATES
        )
    else:
        outcome = (
            MAINTENANCE_OUTCOME_MANUAL_REVIEW_ONLY
            if manual_components
            else MAINTENANCE_OUTCOME_NO_UPDATES
        )
    return MaintenanceDisposition(
        outcome=outcome,
        safe_updates_available=safe_updates_available,
        manual_review_required=bool(manual_components),
        manual_review_components=tuple(manual_components),
        fatal_components=(),
        automatic_updates=tuple(automatic_updates),
        automatic_update_variables=tuple(
            update.variable for update in automatic_updates
        ),
    )


def maintenance_disposition(
    results: list[ComponentResult],
    entries: dict[str, VariableEntry],
    *,
    defer_reviewed_provenance: bool,
) -> MaintenanceDisposition:
    """Classify maintenance work without converting unsafe states into success."""

    fatal_components, manual_components = reviewed_component_groups(results)
    if not manual_review_pins_are_valid(results, entries):
        append_review_components_as_fatal(fatal_components, results)
    if manual_components and not defer_reviewed_provenance:
        append_unique_values(fatal_components, manual_components)
    automatic_updates, plan_errors = maintenance_update_plan(results, entries)
    append_unique_values(fatal_components, plan_errors)
    return build_maintenance_disposition(
        fatal_components,
        manual_components,
        automatic_updates,
    )


def result_to_dict(result: ComponentResult) -> dict[str, Any]:
    data = dataclasses.asdict(result)
    data["updates"] = [dataclasses.asdict(update) for update in result.updates]
    data.update({
        "latest_upstream": result.latest,
        "latest_compatible": result.latest,
        "selected_target": result.latest,
        "official_source": result.source,
        "asset_name": result.details.get("asset_name", ""),
        "sha_source": result.details.get("sha_source", result.details.get("latest_sha256_url", "")),
        "official_sha256": result.details.get("official_sha256", result.details.get("latest_sha256", "")),
        "maintenance_outcome": "update_planned" if result.updates else result.status,
    })
    spec = next((item for item in COMPONENT_SPECS if item.name == result.component), None)
    data["update_policy"] = spec.update_policy if spec else ""
    return data


def make_summary(
    common_sh: Path,
    entries: dict[str, VariableEntry],
    results: list[ComponentResult],
    updates_applied: list[UpdateChange],
    disposition: MaintenanceDisposition,
) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    missing_required = validate_entries(entries)
    manual_review_pins_sha256 = (
        manual_review_pin_digest(results, entries)
        if disposition.manual_review_required
        else ""
    )
    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "common_sh": str(common_sh),
        "maintenance_outcome": disposition.outcome,
        "safe_updates_available": disposition.safe_updates_available,
        "manual_review_required": disposition.manual_review_required,
        "manual_review_components": list(disposition.manual_review_components),
        "manual_review_pins_preserved": disposition.manual_review_required,
        "manual_review_pins_sha256": manual_review_pins_sha256,
        "automatic_update_variables": list(disposition.automatic_update_variables),
        "fatal_components": list(disposition.fatal_components),
        "status_counts": counts,
        "components": [result_to_dict(result) for result in results],
        "inventory": inventory(entries),
        "missing_required": missing_required,
        "updates_applied": [dataclasses.asdict(update) for update in updates_applied],
    }


def markdown_component_action(result: dict[str, Any]) -> str:
    """Describe a component action without changing its terminal status."""

    if result.get("updates"):
        return ", ".join(update["variable"] for update in result["updates"])
    if result["status"] in {STATUS_UNKNOWN, STATUS_REVIEW_REQUIRED}:
        return result.get("details", {}).get("reason") or "manual review"
    if result["status"] == STATUS_BLOCKED:
        return "retry when upstream is reachable"
    return "none"


def append_markdown_component_rows(
    lines: list[str], components: list[dict[str, Any]]
) -> None:
    for result in components:
        lines.append(
            "| {component} | {current} | {latest} | `{status}` | {action} |".format(
                component=markdown_escape(result["component"]),
                current=markdown_escape(result.get("current") or ""),
                latest=markdown_escape(result.get("latest") or ""),
                status=markdown_escape(result["status"]),
                action=markdown_escape(markdown_component_action(result)),
            )
        )


def append_markdown_component_section(
    lines: list[str], heading: str, components: list[str]
) -> None:
    if not components:
        return
    lines.extend(["", heading, ""])
    for component in components:
        lines.append(f"- `{markdown_escape(component)}`")


def append_markdown_applied_updates(
    lines: list[str], updates: list[dict[str, Any]]
) -> None:
    if not updates:
        return
    lines.extend(["", "## Applied Updates", ""])
    lines.append("| Variable | Line | Before | After |")
    lines.append("| --- | ---: | --- | --- |")
    for update in updates:
        lines.append(
            "| {variable} | {line} | `{old}` | `{new}` |".format(
                variable=markdown_escape(update["variable"]),
                line=update["line"],
                old=markdown_escape(update["old"]),
                new=markdown_escape(update["new"]),
            )
        )


def append_markdown_inventory(
    lines: list[str], inventory_rows: list[dict[str, Any]]
) -> None:
    lines.extend(["", "## Inventory", ""])
    lines.append("| Variable | Line | Resolved value |")
    lines.append("| --- | ---: | --- |")
    for item in inventory_rows:
        lines.append(
            "| {name} | {line} | `{resolved}` |".format(
                name=markdown_escape(item["name"]),
                line=item["line"],
                resolved=markdown_escape(item["resolved"]),
            )
        )


def markdown_summary(summary: dict[str, Any]) -> str:
    lines = [
        "# common.sh version check",
        "",
        f"- Generated: `{summary['generated_at']}`",
        f"- File: `{summary['common_sh']}`",
        f"- Maintenance outcome: `{summary['maintenance_outcome']}`",
        "",
        "## Components",
        "",
        "| Komponente | aktuelle Version | neueste Version | Status | Aktion |",
        "| --- | --- | --- | --- | --- |",
    ]
    append_markdown_component_rows(lines, summary["components"])
    if summary["missing_required"]:
        lines.extend(["", "## Missing required values", ""])
        lines.extend(f"- `{name}`" for name in summary["missing_required"])
    append_markdown_component_section(
        lines,
        "## Manual provenance review required",
        summary["manual_review_components"],
    )
    append_markdown_component_section(
        lines,
        "## Fatal components",
        summary["fatal_components"],
    )
    append_markdown_applied_updates(lines, summary["updates_applied"])
    append_markdown_inventory(lines, summary["inventory"])
    lines.append("")
    return "\n".join(lines)


def plain_summary(summary: dict[str, Any]) -> str:
    lines = [
        f"common.sh version check: {summary['common_sh']}",
        f"maintenance outcome: {summary['maintenance_outcome']}",
    ]
    for result in summary["components"]:
        line = f"{result['status']}: {result['component']}"
        if result.get("current"):
            line += f" current={result['current']}"
        if result.get("latest"):
            line += f" latest={result['latest']}"
        line += f" - {result['message']}"
        lines.append(line)
    updates = summary["updates_applied"]
    if updates:
        lines.append("applied updates:")
        for update in updates:
            lines.append(
                f"  {update['variable']} line {update['line']}: {update['old']} -> {update['new']}"
            )
    return "\n".join(lines) + "\n"


def exit_code(
    results: list[ComponentResult],
    entries: dict[str, VariableEntry] | None = None,
    *,
    defer_reviewed_provenance: bool = False,
) -> int:
    """Keep the legacy default strict while exposing an explicit maintenance mode."""

    if entries is None:
        statuses = {result.status for result in results}
        if statuses.intersection(FATAL_STATUSES) or (
            STATUS_REVIEW_REQUIRED in statuses and not defer_reviewed_provenance
        ):
            return 2
        if STATUS_OUTDATED in statuses:
            return 1
        return 0

    disposition = maintenance_disposition(
        results,
        entries,
        defer_reviewed_provenance=defer_reviewed_provenance,
    )
    if disposition.outcome == MAINTENANCE_OUTCOME_FATAL:
        return 2
    return 1 if disposition.safe_updates_available else 0


def write_summary_files(summary: dict[str, Any], markdown: str) -> None:
    root = build_root()
    output_dir = root / "results" / "common-version-check"
    require_safe_build_write_target(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "summary.md").write_text(markdown, encoding="utf-8")


def common_path_from_args(path_text: str | None) -> Path:
    if path_text:
        return Path(path_text).resolve()
    return DEFAULT_COMMON_SH.resolve()


def parse_arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check", action="store_true", help="check common.sh without modifying it"
    )
    mode.add_argument(
        "--update", action="store_true", help="apply safe updates to common.sh"
    )
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="print JSON summary")
    output.add_argument(
        "--markdown", action="store_true", help="print Markdown summary"
    )
    parser.add_argument(
        "--write-files",
        action="store_true",
        help="write summary files under BUILD_ROOT",
    )
    parser.add_argument(
        "--defer-reviewed-provenance",
        action="store_true",
        help=(
            "allow only explicitly classified manual provenance reviews to defer "
            "while applying independent safe updates"
        ),
    )
    parser.add_argument("--common-sh", help=argparse.SUPPRESS)
    parser.add_argument(
        "--timeout", type=float, default=20.0, help="network timeout in seconds"
    )
    parser.add_argument("--component", action="append", default=[], metavar="NAME",
                        help="check only this canonical component (repeatable)")
    parser.add_argument("--list-components", action="store_true",
                        help="print canonical component names and exit")
    return parser.parse_args(argv)


def append_missing_required_result(
    results: list[ComponentResult], entries: dict[str, VariableEntry]
) -> None:
    missing_required = validate_entries(entries)
    if not missing_required:
        return
    results.append(
        ComponentResult(
            component="common.sh required values",
            status=STATUS_ERROR,
            message="Required tracked variables resolved to empty: "
            + ", ".join(missing_required),
            variables=missing_required,
            details={
                "action": "define a value or add the variable to OPTIONAL_EMPTY_VARIABLES"
            },
        )
    )


def prepare_update_candidate(
    common_sh: Path,
    lines: list[str],
    updates: list[UpdateChange],
    manual_pins: dict[str, str],
) -> tuple[Path, list[str], dict[str, VariableEntry]]:
    """Render and validate every local invariant before the first file write."""

    target = require_safe_common_sh_update_target(common_sh)
    candidate_lines = render_updated_lines(lines, updates)
    candidate_entries = parse_common_lines(candidate_lines)
    if validate_entries(candidate_entries):
        raise UpstreamError(
            "candidate common.sh leaves required tracked variables empty"
        )
    require_manual_review_pins_unchanged(manual_pins, candidate_entries)
    return target, candidate_lines, candidate_entries


def revalidate_update_candidate(
    candidate_entries: dict[str, VariableEntry],
    manual_pins: dict[str, str],
    manual_components: tuple[str, ...],
    *,
    defer_reviewed_provenance: bool,
    revalidate: Callable[[dict[str, VariableEntry]], list[ComponentResult]] | None,
) -> None:
    """Require a fresh candidate view to settle before a mutation is allowed."""

    if revalidate is None:
        return
    candidate_results = revalidate(candidate_entries)
    append_missing_required_result(candidate_results, candidate_entries)
    candidate_disposition = maintenance_disposition(
        candidate_results,
        candidate_entries,
        defer_reviewed_provenance=defer_reviewed_provenance,
    )
    if candidate_disposition.outcome not in {
        MAINTENANCE_OUTCOME_NO_UPDATES,
        MAINTENANCE_OUTCOME_MANUAL_REVIEW_ONLY,
    }:
        raise UpstreamError(
            "candidate revalidation did not settle to no updates or manual review only"
        )
    if candidate_disposition.manual_review_components != manual_components:
        raise UpstreamError("candidate revalidation changed manual review components")
    require_manual_review_pins_unchanged(manual_pins, candidate_entries)


def reversed_updates(updates: list[UpdateChange]) -> list[UpdateChange]:
    """Return an exact inverse plan suitable for the existing safe write path."""

    return [
        UpdateChange(
            variable=update.variable,
            line=update.line,
            old=update.new,
            new=update.old,
        )
        for update in updates
    ]


def rollback_update_candidate(
    target: Path, candidate_lines: list[str], updates: list[UpdateChange]
) -> None:
    """Rollback through the same BUILD_ROOT-checked update primitive as writes."""

    apply_updates(target, candidate_lines, reversed_updates(updates))


def verify_written_candidate(
    common_sh: Path,
    candidate_lines: list[str],
    candidate_entries: dict[str, VariableEntry],
    manual_pins: dict[str, str],
) -> tuple[list[str], dict[str, VariableEntry]]:
    """Reject any post-write mismatch before reporting the update as successful."""

    updated_lines, updated_entries = parse_common(common_sh)
    if updated_lines != candidate_lines or updated_entries != candidate_entries:
        raise UpstreamError("written common.sh does not match its validated candidate")
    require_manual_review_pins_unchanged(manual_pins, updated_entries)
    return updated_lines, updated_entries


def apply_requested_updates(
    update_requested: bool,
    rc: int,
    common_sh: Path,
    lines: list[str],
    entries: dict[str, VariableEntry],
    results: list[ComponentResult],
    *,
    defer_reviewed_provenance: bool = False,
    revalidate: Callable[[dict[str, VariableEntry]], list[ComponentResult]]
    | None = None,
) -> tuple[int, list[UpdateChange], list[str], dict[str, VariableEntry]] | None:
    if not update_requested:
        return rc, [], lines, entries
    disposition = maintenance_disposition(
        results,
        entries,
        defer_reviewed_provenance=defer_reviewed_provenance,
    )
    if disposition.outcome == MAINTENANCE_OUTCOME_FATAL:
        print(
            "blocked: refusing to update while one or more upstream checks failed",
            file=sys.stderr,
        )
        return 2, [], lines, entries
    if not disposition.safe_updates_available:
        return rc, [], lines, entries

    updates = list(disposition.automatic_updates)
    manual_pins = manual_review_pin_values(results, entries)
    try:
        target, candidate_lines, candidate_entries = prepare_update_candidate(
            common_sh,
            lines,
            updates,
            manual_pins,
        )
        revalidate_update_candidate(
            candidate_entries,
            manual_pins,
            disposition.manual_review_components,
            defer_reviewed_provenance=defer_reviewed_provenance,
            revalidate=revalidate,
        )
        apply_updates(common_sh, lines, updates)
    except (OSError, UpstreamError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return None

    try:
        updated_lines, updated_entries = verify_written_candidate(
            common_sh,
            candidate_lines,
            candidate_entries,
            manual_pins,
        )
    except (OSError, UpstreamError) as exc:
        try:
            rollback_update_candidate(target, candidate_lines, updates)
        except (OSError, UpstreamError) as rollback_exc:
            print(f"error: {exc}; rollback failed: {rollback_exc}", file=sys.stderr)
            return None
        print(f"error: {exc}", file=sys.stderr)
        return None
    print("applied updates:", file=sys.stderr)
    for update in updates:
        print(
            f" - {update.variable} line {update.line}: {update.old} -> {update.new}",
            file=sys.stderr,
        )
    return 0, updates, updated_lines, updated_entries


def emit_summary(
    summary: dict[str, Any],
    markdown: str,
    json_requested: bool,
    markdown_requested: bool,
) -> None:
    if json_requested:
        print(json.dumps(summary, indent=2, sort_keys=True))
    elif markdown_requested:
        print(markdown)
    else:
        print(plain_summary(summary), end="")


def main(argv: list[str] | None = None) -> int:
    args = parse_arguments(argv)

    if args.list_components:
        print("\n".join(CANONICAL_COMPONENTS))
        return 0
    unknown_names = sorted(set(args.component) - set(CANONICAL_COMPONENTS))
    if unknown_names:
        print(f"error: unknown component(s): {', '.join(unknown_names)}", file=sys.stderr)
        return 2
    selected = set(args.component) if args.component else None

    common_sh = common_path_from_args(args.common_sh)
    lines, entries = parse_common(common_sh)
    client = HttpClient(timeout=args.timeout)
    results = check_all(entries, client, selected)
    append_missing_required_result(results, entries)
    ownership_errors = inventory_ownership_errors(entries)
    if ownership_errors:
        results.append(ComponentResult(
            component="common.sh component inventory", status=STATUS_ERROR,
            message="Relevant upstream variables lack an owner: " + ", ".join(ownership_errors),
            variables=ownership_errors,
        ))
    disposition = maintenance_disposition(
        results,
        entries,
        defer_reviewed_provenance=args.defer_reviewed_provenance,
    )
    rc = exit_code(
        results,
        entries,
        defer_reviewed_provenance=args.defer_reviewed_provenance,
    )

    def revalidate(
        candidate_entries: dict[str, VariableEntry],
    ) -> list[ComponentResult]:
        return check_all(candidate_entries, HttpClient(timeout=args.timeout), selected)

    update_result = apply_requested_updates(
        args.update,
        rc,
        common_sh,
        lines,
        entries,
        results,
        defer_reviewed_provenance=args.defer_reviewed_provenance,
        revalidate=revalidate,
    )
    if update_result is None:
        return 2
    rc, updates_applied, lines, entries = update_result

    summary = make_summary(common_sh, entries, results, updates_applied, disposition)
    markdown = markdown_summary(summary)
    if args.write_files:
        try:
            write_summary_files(summary, markdown)
        except UpstreamError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    emit_summary(summary, markdown, args.json, args.markdown)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
