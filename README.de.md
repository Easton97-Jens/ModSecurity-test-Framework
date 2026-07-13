# ModSecurity Test Framework

**Sprache:** [English](README.md) | Deutsch

Dieses Repository stellt den gemeinsamen YAML-Fallkorpus, Runner, Normalizer,
Katalogchecks und Report-Generatoren für ModSecurity-Connector-Projekte bereit.
Es implementiert keinen Webserver- oder Proxy-Connector.

## Einstieg

- [Framework-Dokumentation](docs/README.de.md)
- [Architektur](docs/architecture.de.md)
- [Katalog und Fälle](docs/catalog-and-cases.de.md)
- [Testing und Evidence](docs/testing-and-evidence.de.md)
- [Connector-Integration](docs/connector-integration.de.md)
- [Entwicklung](docs/development.de.md)
- [Änderungsnachverfolgbarkeit](docs/change-traceability.de.md)
- [Variablen und Platzhalter](docs/reference/variables.de.md)
- [Glossar](docs/reference/glossary.de.md)

Die generierte [Coverage-Zusammenfassung](TEST-COVERAGE-SUMMARY.de.md) ist
eine bewusste Framework-Root-Ausnahme: Connector- und Framework-Checks
verwenden sie, und ihr Generator ist der einzige unterstützte Schreiber.

## Schnelle Validierung

```sh
make setup-dev
make quick-check
make check-documentation
```

Verwende explizite Werte für `FRAMEWORK_ROOT`, `CONNECTOR_ROOT`,
`BUILD_ROOT`, `SOURCE_ROOT`, `TMP_ROOT`, `LOG_ROOT` und `EVIDENCE_ROOT`
außerhalb von Git, wenn ein Befehl Repository- oder Runtime-Grenzen
überschreitet. Die Referenzdokumentation definiert Format, Defaults und
Sicherheitsregeln.

## Scope-Grenze

Connector-Repositories besitzen Host-Adapter, Konfiguration, Harnesses,
Capability-Manifeste, Runtime-Artefakte und Promotion-Entscheidungen. Das
Framework kann Fälle auswählen und berichten, leitet aber keine Host-
Unterstützung aus einem Starter-Check, generierten Bericht oder Exit-Code ab.
