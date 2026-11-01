#!/usr/bin/env python3
"""Generate lightweight common SDK documentation placeholders."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
from pathlib import Path
ROOT = connector_root()
DOCS = source_path('docs/generated', root=ROOT)
FILES = {
    "common-sdk.md": "**Language:** English | [Deutsch](common-sdk.de.md)\n\n# Common SDK generated overview\n\nConnector-neutral common SDK metadata for config parsing, request/response helpers, rule merge/error/event helpers, manifests, runtime reports, origin governance, build contracts, C++ wrappers, limits, rule IDs, and log sanitizing. No connector runtime integration, real libmodsecurity binding, production readiness, or full-matrix readiness is claimed.\n",
    "common-sdk.de.md": "**Sprache:** [English](common-sdk.md) | Deutsch\n\n# Generierter Überblick zum Common SDK\n\nConnector-neutrale Common-SDK-Metadaten für Konfigurationsparser, Request/Response-Helfer, Rule-Merge/Error/Event-Helfer, Manifeste, Runtime-Reports, Origin-Governance, Build-Verträge, C++-Wrapper, Limits, Rule-IDs und Log-Sanitizing. Es wird keine Connector-Laufzeitintegration, keine echte libmodsecurity-Bindung, keine Produktionsreife und keine Full-Matrix-Bereitschaft behauptet.\n",
    "directives.md": "**Language:** English | [Deutsch](directives.de.md)\n\n# Common directives\n\nGenerated directive inventory for common scaffolding only.\n",
    "directives.de.md": "**Sprache:** [English](directives.md) | Deutsch\n\n# Common-Direktiven\n\nGeneriertes Direktiveninventar nur für Common-Scaffolding.\n",
    "capabilities.md": "**Language:** English | [Deutsch](capabilities.de.md)\n\n# Capability contract\n\n- phase4-hard-abort -> phase4 hard-abort-after-200 event test\n",
    "capabilities.de.md": "**Sprache:** [English](capabilities.md) | Deutsch\n\n# Fähigkeitsvertrag\n\n- phase4-hard-abort -> Phase-4-Hard-Abort-nach-200-Ereignistest\n",
    "connector-contract.md": "**Language:** English | [Deutsch](connector-contract.de.md)\n\n# Connector contract skeleton\n\nStandard targets: build-metadata, build-starter, build-runtime, self-test, self-test-runtime, smoke, clean. This is a Common SDK contract skeleton only and does not verify existing connectors.\n",
    "connector-contract.de.md": "**Sprache:** [English](connector-contract.md) | Deutsch\n\n# Connector-Vertragsskelett\n\nStandard-Targets: build-metadata, build-starter, build-runtime, self-test, self-test-runtime, smoke, clean. Dies ist nur ein Common-SDK-Vertragsskelett und verifiziert keine bestehenden Connectoren.\n",
    "origin-governance.md": "**Language:** English | [Deutsch](origin-governance.de.md)\n\n# Origin governance\n\nCommon origin governance tracks repository, branch, commit, describe, license, imported path, and source kind. Existing connectors are informational until explicitly adopted.\n",
    "origin-governance.de.md": "**Sprache:** [English](origin-governance.md) | Deutsch\n\n# Origin-Governance\n\nCommon-Origin-Governance verfolgt Repository, Branch, Commit, Describe, Lizenz, importierten Pfad und Source-Kind. Bestehende Connectoren sind informativ, bis sie explizit migriert werden.\n",
}
def main() -> int:
    DOCS.mkdir(parents=True, exist_ok=True)
    for name, text in FILES.items(): (DOCS / name).write_text(text, encoding="utf-8")
    print("generated common docs")
    return 0
if __name__ == "__main__": raise SystemExit(main())
