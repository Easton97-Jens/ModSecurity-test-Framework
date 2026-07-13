#!/usr/bin/env python3
"""Check and safely update upstream version pins from ci/lib/common.sh."""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

DEFAULT_BUILD_ROOT = Path("/src/ModSecurity-conector-build")
SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_COMMON_SH = SCRIPT_DIR.parent / "lib" / "common.sh"
FRAMEWORK_ROOT = SCRIPT_DIR.parents[1]

TRACKED_NAME_RE = re.compile(
    r"VERSION|RELEASE|TAG|SOURCE_URL|GIT_URL|SHA256|CHECKSUM|REF|BRANCH|COMMIT|URL"
)
PARAM_EXPANSION_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*):[-=]([^{}]*)\}")
BRACED_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
PLAIN_VAR_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")
SHA256_RE = re.compile(r"\b([A-Fa-f0-9]{64})\b")
SAFE_REF_RE = re.compile(r"^(?!.*\.\.)(?!/)(?!.*//)[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
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
    "NGINX_SHA256",
    "PCRE2_SHA256",
    "PCRE2_SHA256_URL",
}

STATUS_CURRENT = "current"
STATUS_OUTDATED = "outdated"
STATUS_UNKNOWN = "unknown"
STATUS_BLOCKED = "blocked"
STATUS_ERROR = "error"


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


def validate_entries(entries: dict[str, VariableEntry]) -> list[str]:
    """Return tracked variables that resolve to empty without being documented as optional."""
    missing: list[str] = []
    for item in sorted(entries.values(), key=lambda current: current.line):
        if item.tracked and not item.resolved and item.name not in OPTIONAL_EMPTY_VARIABLES:
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


def require_safe_write_target(path: Path) -> None:
    target = path.resolve()
    allowed_roots = [FRAMEWORK_ROOT.resolve(), build_root()]
    if any(is_under(target, root) for root in allowed_roots):
        return
    roots = ", ".join(str(root) for root in allowed_roots)
    raise UpstreamError(f"refusing to write outside allowed roots ({roots}): {target}")


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
        if value == before:
            break
    value = BRACED_VAR_RE.sub(lambda match: resolved.get(match.group(1), ""), value)
    value = PLAIN_VAR_RE.sub(lambda match: resolved.get(match.group(1), ""), value)
    return value


def parse_common(common_sh: Path) -> tuple[list[str], dict[str, VariableEntry]]:
    lines = common_sh.read_text(encoding="utf-8").splitlines()
    entries: dict[str, VariableEntry] = {}
    resolved: dict[str, str] = {}
    assign_re = re.compile(r'^([A-Z][A-Z0-9_]*)="\$\{\1:-(.*)\}"\s*$')
    colon_re = re.compile(r'^:\s+"\$\{([A-Z][A-Z0-9_]*):=(.*)\}"\s*$')

    for line_no, line in enumerate(lines, start=1):
        style = ""
        name = ""
        default = ""
        match = colon_re.match(line)
        if match:
            style = "colon-default"
            name = match.group(1)
            default = match.group(2)
        else:
            match = assign_re.match(line)
            if match:
                style = "assignment-default"
                name = match.group(1)
                default = match.group(2)
        if not name:
            continue
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
    return lines, entries


def entry(entries: dict[str, VariableEntry], name: str) -> VariableEntry | None:
    return entries.get(name)


def value(entries: dict[str, VariableEntry], name: str) -> str:
    current = entry(entries, name)
    return current.resolved if current else ""


def require_shell_safe_default(variable: str, new_default: str) -> None:
    if any(ch in new_default for ch in (" ", "\t", "\n", "$", "`", "\"", "'", ";", "{", "}", "(", ")", "#", "&", "|", "<", ">", "\\")):
        raise UpstreamError(f"refusing unsafe shell default for {variable}: {new_default!r}")
    if ".." in new_default or new_default.startswith("/") or "//" in new_default:
        raise UpstreamError(f"refusing traversal-like shell default for {variable}: {new_default!r}")


def plan_update(
    entries: dict[str, VariableEntry], variable: str, new_default: str
) -> UpdateChange | None:
    require_shell_safe_default(variable, new_default)
    current = entry(entries, variable)
    if current is None:
        return None
    if current.default == new_default:
        return None
    return UpdateChange(variable=variable, line=current.line, old=current.default, new=new_default)


def is_template_value(raw_default: str, variable: str) -> bool:
    return f"${variable}" in raw_default or f"${{{variable}}}" in raw_default


def replace_default_line(line: str, variable: str, new_default: str) -> str:
    escaped = re.escape(variable)
    colon_re = re.compile(rf'^(:\s*"\$\{{{escaped}:=)(.*)(\}}"\s*)$')
    assign_re = re.compile(rf'^({escaped}\s*=\s*"\$\{{{escaped}:=)(.*)(\}}"\s*)$')
    default_re = re.compile(rf'^({escaped}\s*=\s*"\$\{{{escaped}:-)(.*)(\}}"\s*)$')
    for pattern in (colon_re, assign_re, default_re):
        match = pattern.match(line)
        if match:
            return f"{match.group(1)}{new_default}{match.group(3)}"
    raise UpstreamError(f"cannot safely update line for {variable}: {line}")


def apply_updates(common_sh: Path, lines: list[str], updates: list[UpdateChange]) -> None:
    if not updates:
        return
    require_safe_write_target(common_sh)
    seen: set[str] = set()
    for update in updates:
        if update.variable in seen:
            raise UpstreamError(f"duplicate update for {update.variable}")
        seen.add(update.variable)
        index = update.line - 1
        lines[index] = replace_default_line(lines[index], update.variable, update.new)
    common_sh.write_text("\n".join(lines) + "\n", encoding="utf-8")


def version_tuple(text: str) -> tuple[int, ...]:
    match = re.search(r"\d+(?:\.\d+)+", text)
    if not match:
        raise UpstreamUnknown(f"no dotted numeric version in {text!r}")
    return tuple(int(part) for part in match.group(0).split("."))


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
    return len(left_tuple) >= 2 and len(right_tuple) >= 2 and left_tuple[:2] == right_tuple[:2]


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
        match = SHA256_RE.search(line)
        if not match:
            continue
        fields = line.split()
        names = [field.lstrip("*") for field in fields[1:]]
        if not names or expected_filename in names or expected_filename in line:
            matches.append(match.group(1).lower())
    unique = sorted(set(matches))
    if not unique:
        raise UpstreamBlocked(f"official checksum did not name {expected_filename}")
    if len(unique) != 1:
        raise UpstreamBlocked(f"official checksum for {expected_filename} is ambiguous")
    return unique[0]


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
    versions = sorted({match.group(1) for match in pattern.finditer(html)}, key=version_tuple)
    if restrict_to_current_series:
        versions = [candidate for candidate in versions if same_series(candidate, current_version)]
    if not versions:
        raise UpstreamUnknown(
            f"No safe updater implemented for this source yet: no matching {filename_prefix} "
            f"versions found in official listing."
        )
    return versions[-1]


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
) -> ComponentResult:
    variables = [version_var, source_url_var, sha_var, sha_url_var]
    missing = [name for name in variables if name not in entries]
    if missing:
        return ComponentResult(
            component=component,
            status=STATUS_UNKNOWN,
            message=f"missing variables: {', '.join(missing)}",
            variables=variables,
        )

    current_version = value(entries, version_var)
    current_url = value(entries, source_url_var)
    current_sha = value(entries, sha_var)
    current_sha_url = value(entries, sha_url_var)
    parsed = urlparse(current_url)
    filename = f"{filename_prefix}-{current_version}{extension}"
    if parsed.scheme != "https" or parsed.netloc != allowed_host or not parsed.path.endswith("/" + filename):
        return ComponentResult(
            component=component,
            status=STATUS_UNKNOWN,
            message="No safe updater implemented for this source yet.",
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
    latest_sha_url = latest_url + ".sha256"
    latest_sha = fetch_sha256(client, latest_sha_url, latest_filename)
    updates: list[UpdateChange] = []
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
        update = plan_update(entries, version_var, latest_version)
        if update:
            updates.append(update)
        source_entry = entries[source_url_var]
        if not is_template_value(source_entry.default, version_var):
            update = plan_update(entries, source_url_var, latest_url)
            if update:
                updates.append(update)
        sha_url_entry = entries[sha_url_var]
        if not is_template_value(sha_url_entry.default, source_url_var):
            update = plan_update(entries, sha_url_var, latest_sha_url)
            if update:
                updates.append(update)
        if current_sha:
            update = plan_update(entries, sha_var, latest_sha)
            if update:
                updates.append(update)
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
        update = plan_update(entries, sha_var, official_current_sha)
        if update:
            updates.append(update)
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


def check_haproxy(entries: dict[str, VariableEntry], client: HttpClient) -> ComponentResult:
    variables = ["HAPROXY_VERSION", "HAPROXY_SOURCE_URL", "HAPROXY_SHA256_URL", "HAPROXY_SHA256"]
    missing = [name for name in variables if name not in entries]
    if missing:
        return ComponentResult(
            component="HAProxy",
            status=STATUS_UNKNOWN,
            message=f"missing variables: {', '.join(missing)}",
            variables=variables,
        )
    current_version = value(entries, "HAPROXY_VERSION")
    current_url = value(entries, "HAPROXY_SOURCE_URL")
    configured_sha = value(entries, "HAPROXY_SHA256").lower()
    current_sha_url = value(entries, "HAPROXY_SHA256_URL") or current_url + ".sha256"
    match = re.fullmatch(
        r"https://www\.haproxy\.org/download/(\d+\.\d+)/src/haproxy-(\d+\.\d+\.\d+)\.tar\.gz",
        current_url,
    )
    if not match or match.group(2) != current_version:
        return ComponentResult(
            component="HAProxy",
            status=STATUS_UNKNOWN,
            message="No safe updater implemented for this source yet.",
            variables=variables,
            current=current_version,
            source=current_url,
            details={"reason": "source URL is not the expected official HAProxy tarball URL"},
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

    series = match.group(1)
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
    latest_sha_url = latest_url + ".sha256"
    latest_sha = fetch_sha256(client, latest_sha_url, latest_filename)
    comparison = compare_versions(current_version, latest_version)
    updates: list[UpdateChange] = []

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
        update = plan_update(entries, "HAPROXY_VERSION", latest_version)
        if update:
            updates.append(update)
        source_entry = entries["HAPROXY_SOURCE_URL"]
        if not is_template_value(source_entry.default, "HAPROXY_VERSION"):
            update = plan_update(entries, "HAPROXY_SOURCE_URL", latest_url)
            if update:
                updates.append(update)
        sha_url_entry = entries["HAPROXY_SHA256_URL"]
        if not is_template_value(sha_url_entry.default, "HAPROXY_SOURCE_URL"):
            update = plan_update(entries, "HAPROXY_SHA256_URL", latest_sha_url)
            if update:
                updates.append(update)
        update = plan_update(entries, "HAPROXY_SHA256", latest_sha)
        if update:
            updates.append(update)
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

    official_current_sha = fetch_sha256(client, current_sha_url, f"haproxy-{current_version}.tar.gz")
    if configured_sha != official_current_sha:
        update = plan_update(entries, "HAPROXY_SHA256", official_current_sha)
        if update:
            updates.append(update)
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
    if parsed.scheme != "https" or parsed.netloc != "github.com" or parsed.query or parsed.fragment:
        return None
    repo = parsed.path.removeprefix("/").removesuffix(".git").strip("/")
    parts = repo.split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return None
    return f"{parts[0]}/{parts[1]}"


def latest_github_release(client: HttpClient, repo_path: str) -> dict[str, Any]:
    return client.get_json(f"https://api.github.com/repos/{repo_path}/releases/latest")


def github_release_by_tag(client: HttpClient, repo_path: str, tag: str) -> dict[str, Any]:
    return client.get_json(f"https://api.github.com/repos/{repo_path}/releases/tags/{tag}")


def release_tag_name(release: dict[str, Any], repo_path: str) -> str:
    tag = release.get("tag_name")
    if not isinstance(tag, str) or not tag.strip():
        raise UpstreamUnknown(f"GitHub latest release for {repo_path} did not include tag_name")
    tag = tag.strip()
    if not SAFE_REF_RE.fullmatch(tag):
        raise UpstreamError(f"GitHub release tag for {repo_path} is not shell-safe: {tag!r}")
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
            message="No safe updater implemented for this source yet.",
            variables=variables,
            current=current_ref,
            source=repo_url,
            details={"reason": "repository URL or ref is empty"},
        )
    if not SAFE_REF_RE.fullmatch(current_ref) or current_ref in {"latest", "master", "main"} or "/" in current_ref:
        return ComponentResult(
            component=component,
            status=STATUS_UNKNOWN,
            message="No safe updater implemented for this source yet.",
            variables=variables,
            current=current_ref,
            source=repo_url,
            details={"reason": "ref is branch-like or dynamic, not a concrete release tag"},
        )
    repo_path = github_repo_path(repo_url)
    if not repo_path:
        return ComponentResult(
            component=component,
            status=STATUS_UNKNOWN,
            message="No safe updater implemented for this source yet.",
            variables=variables,
            current=current_ref,
            source=repo_url,
            details={"reason": "repository URL is not an official github.com owner/repo URL"},
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


def find_release_asset(release: dict[str, Any], asset_name: str) -> str:
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise UpstreamUnknown("GitHub release response did not include an assets list")
    matches: list[str] = []
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        if asset.get("name") == asset_name and isinstance(asset.get("browser_download_url"), str):
            matches.append(asset["browser_download_url"])
    unique = sorted(set(matches))
    if not unique:
        raise UpstreamUnknown(f"GitHub release did not include asset {asset_name}")
    if len(unique) != 1:
        raise UpstreamUnknown(f"GitHub release asset {asset_name} is ambiguous")
    return unique[0]


def check_pcre2(entries: dict[str, VariableEntry], client: HttpClient) -> ComponentResult:
    variables = ["PCRE2_VERSION", "PCRE2_SOURCE_URL", "PCRE2_SHA256", "PCRE2_SHA256_URL"]
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
    if not match or match.group(2) != current_version or match.group(3) != current_version:
        return ComponentResult(
            component="PCRE2",
            status=STATUS_UNKNOWN,
            message="No safe updater implemented for this source yet.",
            variables=variables,
            current=current_version,
            source=current_url,
            details={"reason": "source URL is not the expected official GitHub release asset URL"},
        )
    repo_path = match.group(1)
    latest_release = latest_github_release(client, repo_path)
    latest_tag = release_tag_name(latest_release, repo_path)
    latest_version = re.sub(r"^pcre2-", "", latest_tag)
    version_tuple(latest_version)
    latest_asset_name = f"pcre2-{latest_version}.tar.bz2"
    latest_asset_url = find_release_asset(latest_release, latest_asset_name)
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
        return ComponentResult(
            component="PCRE2",
            status=STATUS_OUTDATED,
            message="A newer official GitHub release asset is available.",
            variables=variables,
            current=current_version,
            latest=latest_version,
            source=f"https://github.com/{repo_path}/releases/latest",
            updates=updates,
            details={"latest_source_url": latest_asset_url},
        )

    current_release = github_release_by_tag(client, repo_path, f"pcre2-{current_version}")
    current_asset_url = find_release_asset(current_release, f"pcre2-{current_version}.tar.bz2")
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
    return ComponentResult(
        component="PCRE2",
        status=STATUS_CURRENT,
        message="Version and release asset URL are current.",
        variables=variables,
        current=current_version,
        latest=latest_version,
        source=f"https://github.com/{repo_path}/releases/latest",
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
        message="No safe updater implemented for this source yet.",
        variables=variables,
        current=", ".join(f"{name}={value(entries, name)}" for name in variables if name in entries),
        details={"reason": reason},
    )


def check_all(entries: dict[str, VariableEntry], client: HttpClient) -> list[ComponentResult]:
    checks: list[ComponentResult] = []
    if value(entries, "NGINX_RELEASE_TAG") == "latest":
        nginx_check = lambda: unknown_component(
            "NGINX",
            entries,
            ["NGINX_SOURCE_REPO_URL", "NGINX_RELEASE_TAG", "NGINX_SOURCE_GIT_REF", "NGINX_SHA256"],
            "NGINX_RELEASE_TAG is dynamic or release resolution is not pinned in common.sh",
        )
    else:
        nginx_check = lambda: check_github_release_ref(
            "NGINX",
            entries,
            client,
            repo_var="NGINX_SOURCE_REPO_URL",
            ref_var="NGINX_RELEASE_TAG",
        )
    component_calls = [
        (
            "OWASP Core Rule Set",
            lambda: check_github_release_ref(
                "OWASP Core Rule Set",
                entries,
                client,
                repo_var="CRS_REPO_URL",
                ref_var="CRS_GIT_REF",
            ),
        ),
        (
            "ModSecurity v3",
            lambda: check_github_release_ref(
                "ModSecurity v3",
                entries,
                client,
                repo_var="MODSECURITY_V3_GIT_URL",
                ref_var="MODSECURITY_V3_GIT_REF",
            ),
        ),
        (
            "ModSecurity Apache connector",
            lambda: unknown_component(
                "ModSecurity Apache connector",
                entries,
                ["MODSECURITY_APACHE_GIT_URL", "MODSECURITY_APACHE_GIT_REF"],
                "connector source is repo-local unless explicitly configured",
            ),
        ),
        (
            "ModSecurity NGINX connector",
            lambda: unknown_component(
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
                extension=".tar.bz2",
                allowed_host="downloads.apache.org",
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
                extension=".tar.bz2",
                allowed_host="downloads.apache.org",
                restrict_to_current_series=True,
            ),
        ),
        (
            "APR-util",
            lambda: official_tarball_check(
                "APR-util",
                entries,
                client,
                version_var="APR_UTIL_VERSION",
                source_url_var="APR_UTIL_SOURCE_URL",
                sha_var="APR_UTIL_SHA256",
                sha_url_var="APR_UTIL_SHA256_URL",
                filename_prefix="apr-util",
                extension=".tar.bz2",
                allowed_host="downloads.apache.org",
                restrict_to_current_series=True,
            ),
        ),
        ("PCRE2", lambda: check_pcre2(entries, client)),
        ("NGINX", nginx_check),
        ("HAProxy", lambda: check_haproxy(entries, client)),
        (
            "Default branch",
            lambda: unknown_component(
                "Default branch",
                entries,
                ["DEFAULT_BRANCH"],
                "DEFAULT_BRANCH is a local policy default, not an upstream release source",
            ),
        ),
    ]
    for component, call in component_calls:
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


def result_to_dict(result: ComponentResult) -> dict[str, Any]:
    data = dataclasses.asdict(result)
    data["updates"] = [dataclasses.asdict(update) for update in result.updates]
    return data


def make_summary(
    common_sh: Path,
    entries: dict[str, VariableEntry],
    results: list[ComponentResult],
    updates_applied: list[UpdateChange],
) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    missing_required = validate_entries(entries)
    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "common_sh": str(common_sh),
        "status_counts": counts,
        "components": [result_to_dict(result) for result in results],
        "inventory": inventory(entries),
        "missing_required": missing_required,
        "updates_applied": [dataclasses.asdict(update) for update in updates_applied],
    }


def markdown_summary(summary: dict[str, Any]) -> str:
    lines = [
        "# common.sh version check",
        "",
        f"- Generated: `{summary['generated_at']}`",
        f"- File: `{summary['common_sh']}`",
        "",
        "## Components",
        "",
        "| Komponente | aktuelle Version | neueste Version | Status | Aktion |",
        "| --- | --- | --- | --- | --- |",
    ]
    for result in summary["components"]:
        action = "none"
        if result.get("updates"):
            action = ", ".join(update["variable"] for update in result["updates"])
        elif result["status"] == STATUS_UNKNOWN:
            action = result.get("details", {}).get("reason") or "manual review"
        elif result["status"] == STATUS_BLOCKED:
            action = "retry when upstream is reachable"
        lines.append(
            "| {component} | {current} | {latest} | `{status}` | {action} |".format(
                component=markdown_escape(result["component"]),
                current=markdown_escape(result.get("current") or ""),
                latest=markdown_escape(result.get("latest") or ""),
                status=markdown_escape(result["status"]),
                action=markdown_escape(action),
            )
        )
    if summary["missing_required"]:
        lines.extend(["", "## Missing required values", ""])
        for name in summary["missing_required"]:
            lines.append(f"- `{name}`")
    updates = summary["updates_applied"]
    if updates:
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
    lines.extend(["", "## Inventory", ""])
    lines.append("| Variable | Line | Resolved value |")
    lines.append("| --- | ---: | --- |")
    for item in summary["inventory"]:
        lines.append(
            "| {name} | {line} | `{resolved}` |".format(
                name=markdown_escape(item["name"]),
                line=item["line"],
                resolved=markdown_escape(item["resolved"]),
            )
        )
    lines.append("")
    return "\n".join(lines)


def plain_summary(summary: dict[str, Any]) -> str:
    lines = [f"common.sh version check: {summary['common_sh']}"]
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


def exit_code(results: list[ComponentResult]) -> int:
    statuses = {result.status for result in results}
    if STATUS_ERROR in statuses or STATUS_BLOCKED in statuses:
        return 2
    if STATUS_OUTDATED in statuses:
        return 1
    return 0


def write_summary_files(summary: dict[str, Any], markdown: str) -> None:
    root = build_root()
    output_dir = root / "results" / "common-version-check"
    require_safe_write_target(output_dir)
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="check common.sh without modifying it")
    mode.add_argument("--update", action="store_true", help="apply safe updates to common.sh")
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="print JSON summary")
    output.add_argument("--markdown", action="store_true", help="print Markdown summary")
    parser.add_argument("--write-files", action="store_true", help="write summary files under BUILD_ROOT")
    parser.add_argument("--common-sh", help=argparse.SUPPRESS)
    parser.add_argument("--timeout", type=float, default=20.0, help="network timeout in seconds")
    args = parser.parse_args(argv)

    common_sh = common_path_from_args(args.common_sh)
    lines, entries = parse_common(common_sh)
    client = HttpClient(timeout=args.timeout)
    results = check_all(entries, client)
    missing_required = validate_entries(entries)
    if missing_required:
        results.append(
            ComponentResult(
                component="common.sh required values",
                status=STATUS_ERROR,
                message="Required tracked variables resolved to empty: "
                + ", ".join(missing_required),
                variables=missing_required,
                details={"action": "define a value or add the variable to OPTIONAL_EMPTY_VARIABLES"},
            )
        )
    rc = exit_code(results)
    updates_applied: list[UpdateChange] = []

    if args.update:
        if rc == 2:
            print("blocked: refusing to update while one or more upstream checks failed", file=sys.stderr)
        else:
            updates = flatten_updates(results)
            if updates:
                try:
                    apply_updates(common_sh, lines, updates)
                except UpstreamError as exc:
                    print(f"error: {exc}", file=sys.stderr)
                    return 2
                updates_applied = updates
                lines, entries = parse_common(common_sh)
                print("applied updates:", file=sys.stderr)
                for update in updates_applied:
                    print(
                        f" - {update.variable} line {update.line}: {update.old} -> {update.new}",
                        file=sys.stderr,
                    )
                rc = 0
            elif rc == 1:
                print("outdated values found, but no safe update could be planned", file=sys.stderr)

    summary = make_summary(common_sh, entries, results, updates_applied)
    markdown = markdown_summary(summary)
    if args.write_files:
        try:
            write_summary_files(summary, markdown)
        except UpstreamError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    elif args.markdown:
        print(markdown)
    else:
        print(plain_summary(summary), end="")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
