#!/usr/bin/env python3
"""Read adapter-owned connector metadata without linking C code.

The productive connector smokes intentionally avoid C/Python FFI. This helper
parses the repo-owned adapter metadata sources so shell/Python reporting code
can use the same values that the C helper smoke validates.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


FRAMEWORK_ROOT = Path(os.environ.get("FRAMEWORK_ROOT", Path(__file__).resolve().parents[2])).resolve()
REPO_ROOT = Path(os.environ.get("CONNECTOR_ROOT", FRAMEWORK_ROOT)).resolve()
CONNECTOR_PATHS = {
    "apache": REPO_ROOT / "connectors/apache/metadata.c",
    "nginx": REPO_ROOT / "connectors/nginx/metadata.c",
}
SHELL_PREFIX_RE = re.compile(r"[A-Za-z_]\w*", re.ASCII)


@dataclass(frozen=True)
class AdapterMetadata:
    connector: str
    component: str
    source_url: str
    source_branch: str
    source_commit: str
    source_version: str
    license: str
    source_kind: str
    imported_path: str

    @property
    def imported_path_absolute(self) -> str:
        return str(REPO_ROOT / self.imported_path)


def c_unescape(value: str) -> str:
    return bytes(value, "utf-8").decode("unicode_escape")


def c_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def load_metadata(connector: str) -> AdapterMetadata:
    path = CONNECTOR_PATHS[connector]
    text = path.read_text(encoding="utf-8")
    try:
        initializer = text[text.index("static const msconnector_") :]
    except ValueError as exc:
        raise ValueError(f"{path} does not contain an adapter metadata initializer") from exc
    values = [c_unescape(match) for match in re.findall(r'"((?:\\.|[^"\\])*)"', initializer)]
    if len(values) < 8:
        raise ValueError(f"{path} does not contain the expected adapter metadata string set")
    return AdapterMetadata(
        connector=connector,
        component=values[0],
        source_url=values[1],
        source_branch=values[2],
        source_commit=values[3],
        source_version=values[4],
        license=values[5],
        source_kind=values[6],
        imported_path=values[7],
    )


def load_all() -> dict[str, AdapterMetadata]:
    return {connector: load_metadata(connector) for connector in CONNECTOR_PATHS}


def validate_prefix(prefix: str) -> None:
    if not SHELL_PREFIX_RE.fullmatch(prefix):
        raise ValueError(f"invalid shell variable prefix: {prefix}")


def print_shell(metadata: AdapterMetadata, prefix: str) -> None:
    validate_prefix(prefix)
    fields = {
        "CONNECTOR": metadata.connector,
        "COMPONENT": metadata.component,
        "SOURCE": metadata.source_kind,
        "SOURCE_REPO": metadata.component,
        "SOURCE_URL": metadata.source_url,
        "SOURCE_BRANCH": metadata.source_branch,
        "SOURCE_COMMIT": metadata.source_commit,
        "SOURCE_VERSION": metadata.source_version,
        "LICENSE": metadata.license,
        "IMPORTED_PATH": metadata.imported_path_absolute,
        "IMPORTED_RELATIVE_PATH": metadata.imported_path,
    }
    for name, value in fields.items():
        print(f"{prefix}_{name}={shell_quote(value)}")


def print_json(connector: str | None) -> None:
    if connector:
        payload: object = asdict(load_metadata(connector))
    else:
        payload = {name: asdict(metadata) for name, metadata in load_all().items()}
    print(json.dumps(payload, indent=2, sort_keys=True))


def write_c_smoke() -> None:
    apache = load_metadata("apache")
    nginx = load_metadata("nginx")
    print(
        f'''#include "connectors/apache/metadata.h"
#include "connectors/nginx/metadata.h"

#include <assert.h>
#include <string.h>

static void assert_origin(const msconnector_origin *origin,
    const char *component,
    const char *source_url,
    const char *source_commit,
    const char *source_version,
    const char *license_name) {{
    assert(!msconnector_origin_is_empty(origin));
    assert(strcmp(origin->component, component) == 0);
    assert(strcmp(origin->source_repository, source_url) == 0);
    assert(strcmp(origin->source_commit, source_commit) == 0);
    assert(strcmp(origin->source_describe, source_version) == 0);
    assert(strcmp(origin->license, license_name) == 0);
}}

int main(void) {{
    const msconnector_apache_adapter_metadata *apache;
    const msconnector_nginx_adapter_metadata *nginx;
    msconnector_origin apache_origin;
    msconnector_origin nginx_origin;

    apache = msconnector_apache_adapter_metadata_get();
    nginx = msconnector_nginx_adapter_metadata_get();
    apache_origin = msconnector_apache_adapter_origin();
    nginx_origin = msconnector_nginx_adapter_origin();

    assert(apache != 0);
    assert(nginx != 0);
    assert_origin(&apache->origin, "{c_escape(apache.component)}",
        "{c_escape(apache.source_url)}", "{c_escape(apache.source_commit)}",
        "{c_escape(apache.source_version)}", "{c_escape(apache.license)}");
    assert_origin(&nginx->origin, "{c_escape(nginx.component)}",
        "{c_escape(nginx.source_url)}", "{c_escape(nginx.source_commit)}",
        "{c_escape(nginx.source_version)}", "{c_escape(nginx.license)}");
    assert_origin(&apache_origin, "{c_escape(apache.component)}",
        "{c_escape(apache.source_url)}", "{c_escape(apache.source_commit)}",
        "{c_escape(apache.source_version)}", "{c_escape(apache.license)}");
    assert_origin(&nginx_origin, "{c_escape(nginx.component)}",
        "{c_escape(nginx.source_url)}", "{c_escape(nginx.source_commit)}",
        "{c_escape(nginx.source_version)}", "{c_escape(nginx.license)}");

    assert(strcmp(apache->source_kind, "{c_escape(apache.source_kind)}") == 0);
    assert(strcmp(apache->imported_path, "{c_escape(apache.imported_path)}") == 0);
    assert(strcmp(nginx->source_kind, "{c_escape(nginx.source_kind)}") == 0);
    assert(strcmp(nginx->imported_path, "{c_escape(nginx.imported_path)}") == 0);

    return 0;
}}'''
    )


def require_contains(path: Path, values: list[str]) -> list[str]:
    text = path.read_text(encoding="utf-8")
    return [value for value in values if value and value not in text]


def metadata_values(metadata: AdapterMetadata) -> list[str]:
    return [
        metadata.component,
        metadata.source_url,
        metadata.source_branch,
        metadata.source_commit,
        metadata.source_version,
        metadata.license,
        metadata.imported_path,
    ]


def shared_metadata_values(metadata: AdapterMetadata) -> list[str]:
    return [
        metadata.component,
        metadata.source_url,
        metadata.source_commit,
        metadata.source_version,
        metadata.license,
    ]


def shared_doc_paths() -> list[Path]:
    return [
        FRAMEWORK_ROOT / "docs/imports/connector-code-import-plan.md",
        FRAMEWORK_ROOT / "docs/imports/sources.md",
        REPO_ROOT / "docs/licensing/license-and-origin.md",
    ]


def connector_doc_paths(connector: str) -> list[Path]:
    return [
        REPO_ROOT / f"connectors/{connector}/ORIGIN.md",
        REPO_ROOT / f"licenses/{connector}/ORIGIN.md",
    ]


def missing_value_errors(path: Path, values: list[str]) -> list[str]:
    return [f"{path}: missing {value!r} from adapter metadata" for value in require_contains(path, values)]


def drift_errors_for_connector(connector: str, metadata: AdapterMetadata) -> list[str]:
    errors: list[str] = []
    for path in connector_doc_paths(connector):
        errors.extend(missing_value_errors(path, metadata_values(metadata)))

    for path in shared_doc_paths():
        errors.extend(missing_value_errors(path, shared_metadata_values(metadata)))

    analysis_path = FRAMEWORK_ROOT / f"docs/imports/import-analysis-{connector}.md"
    errors.extend(missing_value_errors(analysis_path, [metadata.source_url, metadata.source_version]))
    return errors


def check_drift() -> int:
    errors: list[str] = []
    for connector, metadata in load_all().items():
        errors.extend(drift_errors_for_connector(connector, metadata))

    if errors:
        for error in errors:
            print(f"adapter_metadata_drift: {error}", file=sys.stderr)
        return 1
    print("adapter_metadata_drift: ok")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    json_parser = subparsers.add_parser("json", help="print adapter metadata as JSON")
    json_parser.add_argument("connector", nargs="?", choices=sorted(CONNECTOR_PATHS))

    shell_parser = subparsers.add_parser("shell", help="print shell assignments")
    shell_parser.add_argument("connector", choices=sorted(CONNECTOR_PATHS))
    shell_parser.add_argument("--prefix", required=True)

    subparsers.add_parser("c-smoke", help="write C smoke source using parsed metadata")
    subparsers.add_parser("check-drift", help="compare metadata with local docs")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "json":
        print_json(args.connector)
        return 0
    if args.command == "shell":
        print_shell(load_metadata(args.connector), args.prefix)
        return 0
    if args.command == "c-smoke":
        write_c_smoke()
        return 0
    if args.command == "check-drift":
        return check_drift()
    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
