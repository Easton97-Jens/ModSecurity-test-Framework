# Testing und Evidence

**Sprache:** [English](testing-and-evidence.md) | Deutsch

Diese Anleitung definiert den Framework-Testworkflow und die Grenze zwischen
einem Testergebnis, einem generierten Bericht und hochstufbarer
Connector-Evidence. Sie behauptet keine Connector-Unterstützung, die nicht
über den einschlägigen Host-Pfad beobachtet wurde.

## Testebenen

| Ebene | Zweck | Evidence-Grenze |
|---|---|---|
| Statische Checks | Syntax, Schemata, Links, Variablen und lokale Verträge | Kein Runtime-Unterstützungsanspruch |
| Katalogchecks | Fallauswahl und No-CRS-Schemavalidierung | Kein Host-Ausführungsanspruch |
| Starter-Checks | Build- oder Self-Test-Voraussetzungen | Niemals Connector-Runtime-PASS |
| Runtime-Smoke | Echter Host-Request durch den Connector | Nur beobachtete Host-Evidence |
| Generierte Berichte | Reproduzierbare Darstellung aktueller Eingaben | Reporting, keine Promotion |

`PASS` und `FAIL` beschreiben beobachtete Ergebnisse. `BLOCKED` beschreibt
eine fehlende Umgebung, Abhängigkeit, Harness oder Runtime-Voraussetzung.
`NOT_EXECUTABLE` bedeutet, dass ein Fall strukturell nicht auf diesen Connector
oder Run-Modus anwendbar ist. Keiner dieser Zustände ist ein PASS.

## Empfohlener Workflow

Führe Checks aus dem Framework-Checkout oder über das Connector-Repository mit
expliziten Integrationspfaden aus:

```sh
make setup-dev
make lint
make check-no-crs-catalog
make check-documentation
make quick-check
make check-test-matrix
```

Verwende einen beschreibbaren Build- und temporären Ort außerhalb von Git. Die
zentrale [Variablen- und Platzhalterreferenz](reference/variables.de.md)
definiert `FRAMEWORK_ROOT`, `CONNECTOR_ROOT`, `BUILD_ROOT`, `SOURCE_ROOT`,
`TMP_ROOT`, `LOG_ROOT` und `EVIDENCE_ROOT` einschließlich Ownership- und
Sicherheitsregeln.

Vollständige Connector-Validierung ist explizit:

```sh
make smoke-all
make runtime-matrix
make runtime-matrix-all
make test-no-crs
make test-with-crs
```

Schnelle Checks sind nützliches Feedback, ersetzen aber keinen echten
Connector-Smoke. Ein erfolgreicher Source-Build allein ist kein Lifecycle-,
Response-Body- oder Produktionsreife-Claim.

## Vertrag der Protokoll-Targets

Die öffentlichen Targets `make protocol-client`,
`make check-protocol-evidence` und
`make check-transport-hardening-evidence` behalten ihre kompatiblen Namen mit
Bindestrichen. Ihre Standard-Tools sind jeweils
`ci/checks/protocol/protocol_client.py`,
`ci/checks/protocol/check_protocol_evidence.py` und
`ci/checks/evidence/check_transport_hardening_evidence.py`.

`protocol-client` beendet sich mit `2`, wenn `PROTOCOL_URL` fehlt (und strikte
Evidence benötigt zusätzlich `PROTOCOL_FOLLOWUP_URL`).
`check-protocol-evidence` beendet sich mit `2`, wenn `PROTOCOL_ARTIFACT_DIR`
kein Verzeichnis ist, und `check-transport-hardening-evidence` beendet sich
mit `2`, wenn `CONNECTOR` fehlt. Nach diesen Guards meldet der vorhandene
Runner oder Checker sein eigenes Evidence-Ergebnis.
`make test-makefile-contract`, das auch von `make lint` ausgeführt wird,
verlangt statisch, dass jedes vom Makefile referenzierte lokale Python- oder
Shell-Skript existiert.

Dieser Vertrag beweist nur die Auflösung von Target zu Tool. H1-, H2- und
H3-Ergebnisse benötigen weiterhin die jeweiligen Client-, Host- und
Artefaktvoraussetzungen und werden getrennt als Runtime-Evidence berichtet.

## No-CRS- und Full-Lifecycle-Evidence

Die kanonische No-CRS-Implementierung ist
`ci/checks/catalog/no_crs_baseline.py`. Ihre Operationen `select`, `init`,
`finalize`, `validate` und `summarize` halten Auswahl, kanonische Artefakte
und Validierung getrennt.

Der Evidence-Pfad zeichnet nur geprüfte, normalisierte Metadaten auf. Er lehnt
unbegrenzte Request- oder Response-Payload-Felder ab und leitet keinen PASS aus
einem Exit-Code ab. Capability-Deklarationen und generierte Berichte ersetzen
kein beobachtetes Ergebnis. P1–P4, Phase-4-Safe-Behandlung, First-Byte-Timing
und No-Full-Response-Buffering-Assertions unterliegen ihren expliziten
Validator-Eingaben und der Promotion-Policy.

`RESPONSE_BODY` ist absichtlich nicht verifiziert und nicht hochgestuft, bis
die erforderliche stabile Connector-Evidence vorliegt. Eine Pass-Through-Response,
ein Late-Intervention-Log, eine leere Antwort oder ein quellabgeleiteter
Upstream-Test ist für sich kein Response-Body-Blocking-Beweis.

## Fallvarianten und Imports

Die Variante `no-crs` materialisiert nur lokale Regeln. Die Variante `with-crs`
lädt die konfigurierte Core Rule Set vor lokalen Fallregeln. Optionale
MRTS-Eingaben verwenden `MODSECURITY_MRTS_VARIANT` und hängen generierte
Fallwurzeln nur für den gewählten MRTS-Run an. Feature-Demo-Material bleibt
explizites Opt-in und stuft ein Ergebnis nicht hoch, nur weil es in einem
Bericht vorkommt.

[Katalog und Fälle](catalog-and-cases.de.md) beschreibt Schema, Provenienz,
Status- und Capability-Regeln.

## Generierte Berichte

Der Report-Generator besitzt die generierten Ausgaben unter
`testing/generated/` sowie die Framework-Root-Coverage-Zusammenfassung. Ändere
keine generierte Datei manuell. Aktualisieren über:

```sh
make refresh-framework-reports
make check-test-matrix
```

Der aktuelle Einstiegsbericht ist die
[Testabdeckungsübersicht](testing/test-coverage-overview.de.md). Die
detaillierte [Fallmatrix](testing/generated/coverage/case-matrix.generated.de.md)
und [Runtime-Matrix](testing/generated/runtime/runtime-matrix.generated.de.md)
bewahren die reproduzierbaren Details, die ältere manuelle Matrizen duplizierten.

## Privacy und Sicherheit

Tests, Normalizer und Report-Schreiber müssen Request- und Response-Payloads
aus kanonischen Event- und Decision-Metadaten heraushalten. Logs dürfen
geprüfte Hashes, Größen, Trunkierungsinformationen, Identifikatoren, Phase,
Status und Host-Version-Metadaten tragen, soweit das Schema es zulässt.
Redaktion und Control-Character-Sicherheit sind erforderlich, bevor Evidence
hochgestuft wird.

Hash-Chain-Daten sind nur für Smoke-Tamper-Detection nützlich. Dauerhafter
Manipulationsschutz erfordert Connector-eigene Schlüsselbehandlung,
Signaturen oder HMACs sowie geeignete Storage-Kontrollen.

## Historischer Kontext

Frühere Testanleitungen, Import-Maps, Response-Body-Untersuchungen und
PR-bezogene Pläne wurden hier zusammengeführt. Git bewahrt ihre detaillierten
historischen Beobachtungen; aktuelle Claims stammen aus dem ausführbaren
Katalog und aktueller generierter Evidence.
