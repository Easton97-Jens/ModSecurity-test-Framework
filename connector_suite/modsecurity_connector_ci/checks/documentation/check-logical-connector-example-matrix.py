#!/usr/bin/env python3
"""Validate the materializable examples for every logical connector profile.

This is deliberately independent of the generated configuration reference.  A
profile can therefore not appear complete merely because its options are
documented: each variant must contain the host configuration that selects the
common P1--P4 contract.  The checks use only source-backed keys and the
canonical example layout.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root

import argparse
import sys
from pathlib import Path


ROOT = connector_root()
VARIANTS = ("off", "safe", "strict")
PHASE4_MODE_TEMPLATE = "phase4_mode={variant}"
REQUEST_BODY_MODE_STREAMING = "request_body_mode=streaming"
RESPONSE_BODY_MODE_STREAMING = "response_body_mode=streaming"
RUNTIME_CONFIG = "msconnector-runtime.conf"
RESPONSE_COMPANION_MARKERS = {
    "haproxy-spoe-spop": ("response-companion=native-htx", "response-companion-socket"),
    "envoy-ext-authz": ("response_observer", RESPONSE_BODY_MODE_STREAMING),
    "traefik-forwardauth": ("modsecurityResponseObserver", "socketPath"),
}
EXPECTED_PROFILES = frozenset({
    "apache", "nginx", "haproxy-htx", "haproxy-spoe-spop", "envoy-ext-authz",
    "envoy-ext-proc", "traefik-forwardauth", "traefik-native-uds", "lighttpd-stock",
    "lighttpd-patched",
})


def _files(directory: str, names: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    return tuple(tuple(f"{directory}/{variant}/{name}" for name in names) for variant in VARIANTS)


# Each tuple is (logical profile, per-variant files, required source-backed
# materialization keys).  Tokens may be distributed over the files in a
# variant; this models a real host config plus its engine/companion config.
MATRIX = {
    "apache": (_files("examples/apache", ("httpd.conf",)),
                ("modsecurity_phase4_mode {variant}",)),
    "nginx": (_files("examples/nginx", ("nginx.conf",)),
               ("modsecurity_phase4_mode {variant}", "modsecurity_rules_file")),
    "haproxy-htx": (_files("examples/haproxy", ("haproxy-htx.cfg",)),
                    ("filter modsecurity-htx", "phase4-mode {variant}")),
    "haproxy-spoe-spop": (_files("examples/haproxy/spoe-spop", ("haproxy.cfg", "spoa-agent.conf", "spoe.cfg")),
                          ("filter spoe engine modsecurity", "response-companion=native-htx",
                           "response-companion-socket", "response-companion-uid", "response-companion-gid",
                          "phase4-mode {variant}")),
    "envoy-ext-authz": (_files("examples/envoy/ext-authz", ("envoy.yaml.in", RUNTIME_CONFIG)),
                        ("ext_authz", "response_observer", "request_body_mode=buffered",
                         RESPONSE_BODY_MODE_STREAMING, PHASE4_MODE_TEMPLATE)),
    "envoy-ext-proc": (_files("examples/envoy/ext-proc", ("envoy.yaml.in", "service.json", RUNTIME_CONFIG)),
                       ("processing_mode", "request_body_mode=streaming", RESPONSE_BODY_MODE_STREAMING,
                        PHASE4_MODE_TEMPLATE)),
    "traefik-forwardauth": (_files("examples/traefik/forwardauth", ("traefik-static.yaml", "traefik-dynamic.yaml", "traefik-engine-service.conf")),
                            ("forwardBody: true", "maxBodySize", "modsecurityResponseObserver", "socketPath",
                             "request_body_mode=buffered", RESPONSE_BODY_MODE_STREAMING, PHASE4_MODE_TEMPLATE)),
    "traefik-native-uds": (_files("examples/traefik/native-uds", ("traefik-static.yaml", "traefik-dynamic.yaml", "traefik-engine-service.conf")),
                           ("modsecurityNative", "engineMode: uds", REQUEST_BODY_MODE_STREAMING,
                            RESPONSE_BODY_MODE_STREAMING, PHASE4_MODE_TEMPLATE)),
    "lighttpd-stock": (_files("examples/lighttpd/stock", ("lighttpd-backend.conf", "stock-sidecar.args", RUNTIME_CONFIG)),
                       ("--listen", "--upstream", REQUEST_BODY_MODE_STREAMING, RESPONSE_BODY_MODE_STREAMING,
                        PHASE4_MODE_TEMPLATE)),
    "lighttpd-patched": (_files("examples/lighttpd/patched", ("lighttpd.conf", RUNTIME_CONFIG)),
                         ("mod_msconnector", REQUEST_BODY_MODE_STREAMING, RESPONSE_BODY_MODE_STREAMING,
                          PHASE4_MODE_TEMPLATE)),
}


def _variant_files(root: Path, relative: tuple[str, ...]) -> tuple[Path, ...]:
    return tuple(root / path for path in relative)


def _has_phase_coverage(text: str) -> bool:
    return any((
        all(f"P{phase}" in text for phase in range(1, 5)),
        "P1" in text and "P4" in text and "phase4_mode" in text,
        "modsecurity on" in text and "modsecurity_rules_file" in text and "phase4_mode" in text,
        "phase4-mode" in text and "filter modsecurity-htx" in text,
        "phase4_mode=" in text and "response_body_mode=" in text,
    ))


def _variant_errors(profile: str, variant: str, paths: tuple[str, ...], required: tuple[str, ...], root: Path) -> list[str]:
    missing = [path for path in paths if not (root / path).is_file()]
    if missing:
        return [f"{profile}/{variant}: missing materializable artifact(s): {', '.join(missing)}"]
    text = "\n".join((root / path).read_text(encoding="utf-8", errors="replace") for path in paths)
    errors = [
        f"{profile}/{variant}: missing visible applicable parameter {token.format(variant=variant)!r}"
        for token in required
        if token.format(variant=variant) not in text
    ]
    if not _has_phase_coverage(text):
        errors.append(f"{profile}/{variant}: no source-backed P1-P4 coverage declaration")
    for marker in RESPONSE_COMPANION_MARKERS.get(profile, ()):
        if marker not in text:
            errors.append(f"{profile}/{variant}: missing required response companion marker {marker!r}")
    if profile == "lighttpd-stock" and "--listen" not in text:
        errors.append(f"{profile}/{variant}: traffic-owning Stock sidecar is not materialized")
    return errors


def logical_connector_example_errors(root: Path) -> list[str]:
    errors: list[str] = []
    if set(MATRIX) != EXPECTED_PROFILES:
        errors.append("checker profile inventory does not contain exactly the ten logical connector IDs")
    for profile, (variant_paths, required) in MATRIX.items():
        for variant, paths in zip(VARIANTS, variant_paths):
            errors.extend(_variant_errors(profile, variant, paths, required, root))
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    errors = logical_connector_example_errors(args.repo_root.resolve())
    if errors:
        print("logical connector example matrix: FAIL", file=sys.stderr)
        print("\n".join(sorted(errors)), file=sys.stderr)
        return 1
    print("logical connector example matrix: PASS profiles=10 variants=30")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
