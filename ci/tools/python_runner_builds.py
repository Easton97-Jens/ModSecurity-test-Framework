"""Check the official setup-python manifest without credentials or redirects."""

import json
from http.client import HTTPException
from urllib import request


MANIFEST_URL = "https://raw.githubusercontent.com/actions/python-versions/main/versions-manifest.json"
MAX_BYTES = 8_000_000
RUNNER = "ubuntu-26.04"
TARGET = {"platform": "linux", "platform_version": "26.04", "arch": "x64"}


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_manifest(*, timeout=20.0, opener=None):
    """Read only the fixed public manifest, bounded and without auth headers."""
    req = request.Request(MANIFEST_URL, headers={"Accept": "application/json"})
    open_url = opener or request.build_opener(NoRedirect()).open
    try:
        response = open_url(req, timeout=timeout)
    except (OSError, HTTPException) as error:
        raise ValueError(
            "official setup-python manifest could not be fetched"
        ) from error
    try:
        content_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower()
        if (
            response.status != 200
            or response.geturl() != MANIFEST_URL
            or content_type not in {"application/json", "text/plain"}
        ):
            raise ValueError(
                "setup-python manifest response is not the fixed official JSON source"
            )
        try:
            raw = response.read(MAX_BYTES + 1)
        except (OSError, HTTPException) as error:
            raise ValueError("official setup-python manifest read failed") from error
    finally:
        response.close()
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise ValueError("setup-python manifest exceeds its byte limit")
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, list) or not all(
        isinstance(row, dict) for row in payload
    ):
        raise ValueError("setup-python manifest must be an array of release records")
    return payload


def require_build(manifest, version):
    """Require the same stable CPython version and exact maintained runner tuple."""
    releases = [row for row in manifest if row.get("version") == version]
    if len(releases) != 1 or releases[0].get("stable") is not True:
        raise ValueError(
            f"CPython {version} has no unique stable setup-python manifest release"
        )
    files = releases[0].get("files")
    if not isinstance(files, list) or not all(isinstance(row, dict) for row in files):
        raise ValueError("setup-python release has no valid file inventory")
    builds = [
        row
        for row in files
        if all(row.get(key) == value for key, value in TARGET.items())
    ]
    if len(builds) != 1:
        raise ValueError(
            f"CPython {version} is published but its {RUNNER}/x64 setup-python build is unavailable"
        )
    filename = f"python-{version}-linux-26.04-x64.tar.gz"
    url = builds[0].get("download_url", "")
    if (
        builds[0].get("filename") != filename
        or not isinstance(url, str)
        or not url.startswith(
            "https://github.com/actions/python-versions/releases/download/"
        )
        or not url.endswith("/" + filename)
        or any(char in url for char in "?#\r\n")
    ):
        raise ValueError(
            "setup-python build identity is outside the official release contract"
        )
