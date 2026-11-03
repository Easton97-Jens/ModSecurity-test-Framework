# Änderungsprotokoll

**Sprache:** Deutsch | [English](20261103-01-measurement-sbom-readiness.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261103-01-measurement-sbom-readiness |
| UTC-Datum | 2026-11-03 |
| Framework-Basisrevision | `bb6c7580208a05c17d6d6674571731b6a71028cb` |
| Lieferung | Prüfbare Task-Worktree-Änderungen; kein Worker-Commit/PR |

## Motivation und Problemstellung

Der Messrunner band nur die Parentrevision, obwohl wiederverwendbare Mess-/
Testquellen im Framework liegen. Die Finalisierung akzeptierte fehlenden oder
abweichenden Frameworkbezug. Ein integrierter SBOM-Export bekannter ausgewählter
Quell-, Modul-, Umgebungs- und Artefakteingaben fehlte.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework besitzt Messrunner, Exporter und Regressionen. Produktquellen und
Promotion bleiben Parent-Aufgabe. MRTS bleibt unverändert. Explizite reguläre
Dateien, begrenztes JSON, keine automatische Auflösung/Ausführung, neue externe
Ausgabe und saubere finale Quellen begrenzen den Exporter. Lokale Sonar-Vorprüfung
bleibt ausdrücklich ausgesetzt; bestehende gehostete Prüfungen bleiben erhalten.

## Akzeptanzkriterien

Fehlenden/falschen Frameworkbezug vor der Messkombination zurückweisen; echte
Ausführung, Parentattribution und 100 Standardfälle erhalten. Deterministisches
CycloneDX 1.6 mit unabhängig erwarteten Identitäten, Eingabe-/Artefakthashes,
tatsächlichen Revisionen und immer unvollständigem Scope exportieren. Abweichende/
unsaubere finale Quellen, doppelte Eingabeauswahl, unsichere Eingaben und Überschreiben ablehnen.

## Untersuchte Alternativen

Eine Quellliste als vollständige Binär-SBOM würde Verlinkung falsch darstellen.
Für explizite bekannte Eingaben ist keine neue Resolver-/Scannerabhängigkeit
erforderlich. Historische Manifeste nachträglich zu ergänzen würde deren
ursprünglichen Bezug verfälschen.

## Implementierungsentscheidung

Frameworkrevision/-zustand zusätzlich zu Parent speichern und prüfen. Historische
Nachweise erhalten, aber nicht als endgültiges Commitpaar akzeptieren. Ein
Stdlib-Exporter verarbeitet Lockprofile oder explizite Quelltupel, Go-JSON-
Objektströme, Python-Distributionsarrays und gestreamte Artefakthashes. Releasehashes
gehören zu Distributionsreferenzen; Gitcommits sind keine Dateihashes. Gelieferte
Buildmetadaten bleiben Aussagen. Komposition bleibt unvollständig; kein Graph
wird erfunden.

## Geänderte Dateien und Tests

`ci/tools/export-component-sbom.py`, `tests/ci_security/test_component_sbom.py`,
Messrunner und `test_sonar_coverage.py`, gepaarte
`docs/testing/measurement-and-sbom-readiness.md` und dieses Protokollpaar.
Gemeinsame Quellbindungen/Katalogregistrierung gehören dem Koordinator; neue
Regressionen bleiben ausdrücklich On-demand. Keine Standarderweiterung vorgesehen.

## Befehle und Ergebnisse

Nachweise unter der genehmigten externen Speicherwurzel des aufrufenden Projekts:
`runs/20261103T115937Z-runtime-readiness/tooling`.

- Framework-Interpreter, explizite Parent-/Framework-Wurzeln, `ON_DEMAND_TESTS=1`:
  neuer Finalisierungstest vor Reparatur in allen drei fehlenden/abweichenden/
  unsauberen Frameworkfällen fehlgeschlagen (`framework-pair-before-corrected.log`).
  Eine frühere Probe ohne `CONNECTOR_REVISION` scheiterte an der Kontextzulassung;
  sie ist kein Fehlernachweis.
- Derselbe Kontext, `python -m unittest -v modsecurity_connector_tests.test_sonar_coverage
  tests.ci_security.test_component_sbom`: 33 Tests bestanden (`targeted-final.log`).
- Tatsächlicher Runtime-Lock plus Metadaten der ausgewählten Frameworkumgebung:
  Exit 0, zehn Komponenten, ausdrücklich unsaubere Entwicklung und unvollständiger
  Scope (`current-development.cdx.json`), kein finales integriertes Paarinventar.

Shellaufrufe verwenden RTK und den expliziten Framework-Interpreter. Offizielles
1.6-Schema liegt unter der Nachweiswurzel; der Koordinator dokumentiert dessen
Validierung und finale gemeinsame Dokumentations-/Integritätsprüfungen separat.

## Sicherheitsauswirkung

Keine Produktlückenbehebung oder Sicherheitsfreiheit behauptet. Keine Scanner,
Abhängigkeiten, Workflows, Zulassungen oder gehosteten Gates entfernt/geschwächt.
Fehlermeldungen geben keine beliebigen Eingabewerte wieder; Eingaben und
Buildbeschreibungen müssen vor Auswahl auf Geheimnisse geprüft sein.

## Dokumentation und Runtime-Evidenz

Der gepaarte Leitfaden definiert Eingaben, Voraussetzungen, vorbereitete Aufrufe
und Grenzen. Keine Runtimekampagne, Connectorpromotion oder Analyzerübernahme
durchgeführt. Historische gezielte Messungen bleiben historische Nachweise.

## Nicht ausgeführte Prüfungen

Keine vollständige Python-/Go-/Native-Messproduktion oder Profil-/Protokollkampagne.
Keine native/Container-Transitivitätsauflösung. Keine Toolchain-/Paketinstallation.
Kein Advisoryscan und kein automatisches Update wegen Alter. Kanonischer finaler
Interpreter und Prüfung des sauberen Paars bleiben Koordinatorvoraussetzungen.

## Einschränkungen und Restrisiko

Nur gelieferte Eingaben werden exportiert. Acht Cacherecords entsprechen nicht
zehn qualifizierten Runtimeprofilen. Module/Umgebungspakete beweisen keine
Binärverlinkung; Buildbeschreibungen keine Builds. Unsaubere Entwicklung
qualifiziert kein finales Paar. Vollständige native/Container-SBOM benötigt
genehmigten Resolver und tatsächliche Artefakt-/Build-/OS-Nachweise.

## Finaler Diff- und Review-Status

Gezielte Implementierung/Tests geprüft. Gemeinsame Bindungsgenerierung und finale
Repositoryprüfungen gehören nach Kombination der Frameworkarbeit dem Koordinator.
Parent-Gitlink unverändert; MRTS read-only. Keine Workerprozesse verbleiben.
