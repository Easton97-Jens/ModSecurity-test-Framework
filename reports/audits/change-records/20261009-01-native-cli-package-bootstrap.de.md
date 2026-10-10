# Änderungsprotokoll

**Sprache:** Deutsch | [English](20261009-01-native-cli-package-bootstrap.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261009-01-native-cli-package-bootstrap |
| UTC-Datum | 2026-10-09 |
| Framework-Basisrevision | 7db219af6b6e911b73de8b437f82e63efdb06bde |
| Issue oder Pull Request | Keine Referenz bei Implementierungsübergabe |

## Motivation und Problemstellung

Die eigenständige No-CRS-Ausführung ergänzte das Framework-Paketwurzelverzeichnis nicht. Native Finalisierung und Offline-Validierung scheiterten deshalb vor der Autoritätsprüfung mit `ModuleNotFoundError: No module named 'tests'`. Unit-Tests aus dem Repository-Wurzelverzeichnis verdeckten den Fehler.

## Betroffene Komponenten und Sicherheitsgrenzen

Betroffen sind der Framework-CLI-Bootstrap und Subprozess-Regressionstests. Explizite native Autorität, Dateieigentum, Byte-Versiegelung und geschlossene Schema-Prüfung bleiben wirksam.

## Akzeptanzkriterien

Isolierte Subprozesse aus unabhängigen externen Arbeitsverzeichnissen laden Autoritäts-, Bundle- und Contract-Reader des aktuellen Checkouts ohne PYTHONPATH. Finalisierungsaufbewahrung und Offline-Validierung akzeptieren ein gültiges lokales Testartefakt und weisen fehlende oder fehlerhafte Autorität zurück. Ein konkurrierendes, noch nicht importiertes `tests`-Paket kann das Checkout nicht überschatten.

## Untersuchte Alternativen

Ein PYTHONPATH-Wrapper würde direkte Dateiausführung nicht reparieren. Unqualifizierte Runner-Imports würden die Paketimporte innerhalb des Autoritäts-Readers nicht reparieren. Die CLI ergänzt daher ihr aufgelöstes Paketwurzelverzeichnis.

## Implementierungsentscheidung

Das aufgelöste `FRAMEWORK_ROOT` wird vor Produktimporten an den Anfang von `sys.path` verschoben; ein vorhandener Eintrag wird zuvor entfernt. Bestehende Verzeichnisse für unqualifizierte Module bleiben verfügbar. Autoritätsprüfung und Statussemantik ändern sich nicht.

## Geänderte Dateien und Tests

- `ci/checks/catalog/no_crs_baseline.py`: Paket-Bootstrap.
- `tests/no_crs/test_native_authority_cli_bootstrap.py`: vier Subprozess-Tests, mit fehlender und fehlerhafter Autorität in beiden nativen Pfaden.
- Dieses englische/deutsche Änderungsprotokollpaar.

## Befehle und Ergebnisse

Die folgende Darstellung macht den tatsächlich im isolierten Framework-Checkout
ausgeführten Interpreter-Präfix portabel. `<temporary-work-root>` ist ein
Darstellungsalias für das konfigurierte externe Codex-Speicherelternverzeichnis,
kein wörtliches Befehlsargument. Der Interpreter war das konfigurierte
Framework-eigene `venv/bin/python`; TMPDIR war das explizit ausgewählte externe
Aufgabenanalyseverzeichnis für Run-ID `nginx-all-required-20261008T124555Z`.
Der exakt aufgelöste lokale Aufruf bleibt im externen
`framework-native-cli-imports-report.md` dieses Runs erhalten.

```text
rtk proxy env TMPDIR=<temporary-work-root>/ModSecurity-conector/analysis/nginx-all-required-20261008T124555Z PYTHONNOUSERSITE=1 PYTHONPYCACHEPREFIX=<temporary-work-root>/ModSecurity-test-Framework/cache/pycache <temporary-work-root>/ModSecurity-test-Framework/venv/bin/python
```

| Befehlsuffix / Befehl | Exit-Code | Kurzergebnis | Run-ID oder genehmigter Evidenzpfad |
| --- | --- | --- | --- |
| `-m unittest tests.no_crs.test_native_authority_cli_bootstrap -v` vor Korrektur | 1 | Vier Tests, sechs fehlgeschlagene Teilfälle; fehlendes Paket und fremdes Paket beobachtet | Externes Analyseverzeichnis im Präfix |
| Derselbe fokussierte Befehl nach Korrektur | 0 | Vier Tests bestanden; Original-Byte-Aufbewahrung, Offline-Reader, Zurückweisung und Paketüberschattung geprüft | Dasselbe externe Verzeichnis |
| `rtk git diff --check` | 0 | Keine Whitespace-Fehler in verfolgten Dateien | Framework-Checkout |
| `rtk --version`, `rtk gain`, `rtk proxy which rtk` | 0 | RTK 0.51.0 verfügbar und verwendet | Lokale Befehlsprüfung |

Derselbe Interpreter-Präfix mit `-m unittest discover -s tests/no_crs -v`
endete mit Exit-Code 0. Der abschließende fokussierte Befehl bestand auch nach
Verschärfung des Überschattungstests: Das Checkout-Wurzelverzeichnis steht
hinter dem konkurrierenden Paket.
`rtk proxy env PYTHONNOUSERSITE=1 PYTHONPYCACHEPREFIX=<temporary-work-root>/ModSecurity-test-Framework/cache/pycache <temporary-work-root>/ModSecurity-test-Framework/venv/bin/python ci/checks/documentation/check-change-records.py`
bestand mit Exit-Code 0.

Nachdem dieses Protokollpaar portabel gemacht wurde, wurde derselbe
Dokumentationsprüfungs-Interpreter-Präfix für folgende vollständige Prüfungen
verwendet; alle endeten mit Exit-Code 0:
`ci/checks/documentation/check-repository-path-references.py`,
`ci/checks/documentation/check-variable-documentation.py`,
`ci/checks/documentation/check-change-records.py` und
`ci/checks/documentation/check-doc-links.py`. Dies sind Dokumentationsprüfungen,
keine erneute Runtime-Ausführung.

## Sicherheitsauswirkung

Es wird keine Sicherheitsbehebung behauptet. Die Paketpriorität des aktuellen Checkouts ist für noch nicht importierte Module deterministisch. Ungültige Autorität bleibt ein ContractError; Importausnahmen werden nicht unterdrückt.

## Dokumentation und Runtime-Evidenz

Dieses Dokument ist das gepaarte Framework-Protokoll. Subprozess-Proben laden die echte CLI mit `runpy.run_path` unter `-I -B` und rufen dieselben Aufbewahrungs-/Offline-Reader-Funktionen wie die CLI auf. Testartefakte begründen keine Git-/Build-/Runtime-Autorität. Diese Aufgabe erhob keine Host-Runtime- oder Lebenszyklusevidenz.

## Nicht ausgeführte Prüfungen

Vollständige Repository-Lint-Prüfung, CI, Quellbindung und nativer Runtime-Wiederholungslauf liegen beim Koordinator. Keine Abhängigkeiten, nativen Operationen, administrativen Aktionen oder Delivery-Operationen wurden ausgeführt.

## Einschränkungen und Restrisiko

Die Probe deckt die fehlerhafte native Schnittstelle statt eines vollständigen CLI-Lebenszyklus ab. Bereits importierte fremde Pakete liegen außerhalb dieses eigenständigen Frischprozessvertrags. Parent-Integration und anschließende native Finalisierung benötigen separate Evidenz.

## Finaler Diff- und Review-Status

Begrenzte Quell-/Teständerungen geprüft; Whitespace-Prüfung verfolgter Dateien bestanden. Keine Geheimnisse oder sensiblen Rohdaten aufgezeichnet. Uncommittete Übergabe; Git-Delivery liegt beim Koordinator. Parent-Gitlink unverändert; MRTS blieb schreibgeschützt im Aufgabenumfang.
