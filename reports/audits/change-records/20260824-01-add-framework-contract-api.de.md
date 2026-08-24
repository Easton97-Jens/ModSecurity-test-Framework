# Framework-Contract-API hinzufügen

**Sprache:** [English](20260824-01-add-framework-contract-api.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260824-01-add-framework-contract-api |
| UTC-Datum | 2026-08-24 |
| Framework-Basisrevision | c40e924ec5c341032908e0082feba1d37ed1dfda |
| Issue oder Pull Request | Framework-Draft-PR #110; Verifikation des Nachfolge-HEAD ausstehend |

## Motivation und Problemstellung

Externe Consumer luden Katalogskripte bisher über Dateipfade. Das
Fünf-Connector-CRS-Skript versuchte danach einen nackten Nachbarimport und
scheiterte außerhalb des Framework-Arbeitsverzeichnisses. Das Framework
benötigte eine stabile öffentliche Paketgrenze für Inventar, Auswahl,
Metadaten, typisierte Erwartungen, Ergebnisvalidierung und Profilverträge,
ohne Consumer-sys.path-Änderungen zu verlangen.

## Betroffene Komponenten und Sicherheitsgrenzen

- modsecurity_test_framework/: öffentliches Paket, statische Contract-Ressource
  und abhängigkeitsfreier Wheel-Builder.
- ci/tools/generate-framework-contract-catalog.py: deterministischer
  Pflegegenerator aus eingecheckten Quellen.
- ci/checks/catalog/five_connectors_with_crs_no_mrts.py: begrenzter
  Legacy-Nachbar-Lookup für direkte Dateikompatibilität.
- tests/contract_api/: API-, Paketinstallations-, External-CWD-, Sicherheits-
  und Kompatibilitäts-Controls.

Die relevante Grenze sind nicht vertrauenswürdige JSON-Capability-/Ergebnis-
Eingaben und das Laden von Paketressourcen. Die öffentliche API hat kein vom
Caller gewähltes Python-Modulladen, keine dynamische Fall-Discovery und keinen
CWD-basierten Framework-Ressourcen-Lookup.

## Akzeptanzkriterien

- Ein installiertes öffentliches Paket stellt die sieben angeforderten
  Contract-Operationen bereit.
- Die JSON-only-Modul-CLI unterstützt inventory, select, describe und
  validate; Vertragsfehler haben den dokumentierten Exit-Code 2.
- No-CRS- und CRS-Profilmetadaten laden mit Schema- und Framework-Commit-
  Bindung.
- Erwartungen sind eine strenge geschlossene getaggte Union und bewahren
  Nicht-HTTP-Semantik.
- Bestehende Katalogbefehle bleiben kompatibel, einschließlich des direkten
  externen Ladens des Fünf-Connector-Legacy-Skripts.
- Die öffentliche Eingabeverwaltung weist doppelte JSON-Keys, unsichere Pfade,
  übergroße Dokumente, ungültige Typen und widersprüchliche Testidentitäten ab.
- Die Paketressource wird reproduzierbar gegen eingecheckte Quellen geprüft.

## Untersuchte Alternativen

- Parent-Consumern das Ergänzen von Framework-Verzeichnissen zu sys.path zu
  empfehlen, wurde verworfen, weil es die fragile Importgrenze erhalten würde.
- Den YAML-Runner zur Consumer-Laufzeit dynamisch wiederzuverwenden, wurde
  verworfen, weil dies unbegrenzte Source-Discovery und Parser-Eingaben in den
  öffentlichen Pfad bringen würde.
- Eine Runtime-YAML-Abhängigkeit wurde verworfen, weil eine generierte,
  payloadfreie JSON-Ressource die Consumer-API direkt bedienen kann.

## Implementierungsentscheidung

Das neue öffentliche Modul lädt nur seinen gebündelten statischen
Contract-Katalog über eine paketrelative Ressource. Ein eingecheckter Generator
erstellt diesen Katalog aus den 166 No-CRS-Einträgen und dem YAML-Korpus,
vereinigt nur generische identische No-CRS-Quellrepräsentationen und weist
mehrdeutige Identitäten ab. Ein minimaler abhängigkeitsfreier PEP-517-Backend
hält den ausgecheckten Source-Commit in einem Wheel fest, während
Source-Checkouts ihren aktuellen HEAD über einen festen nicht-shellbasierten
Git-Aufruf auflösen.

Das Fünf-Connector-Legacy-Skript behält seine CLI und erhält nur einen festen
Framework-eigenen Katalogverzeichnis-Lookup. Neue Consumer verwenden die
Paket-API statt dieses internen Fallbacks.

## Geänderte Dateien und Tests

- pyproject.toml, modsecurity_test_framework/ und die generierte Contract-JSON:
  öffentliche installierbare API und Paketdaten.
- ci/tools/generate-framework-contract-catalog.py und Makefile:
  deterministische Katalogfrische und fokussiertes Testtarget.
- ci/checks/catalog/five_connectors_with_crs_no_mrts.py: Kompatibilität des
  Geschwisterimports beim direkten Laden.
- tests/contract_api/test_public_contract_api.py: externes Paket/CLI,
  Katalog/Profil, getaggte Union, Ergebnis-, Duplicate-, Pfad-, Commit-,
  Kategorie- und Wrapper-Controls.
- Gepaarte öffentliche API-Dokumentation und dieses englische/deutsche
  Change-Record-Paar.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| make test-contract-api mit dem ausgewählten Framework-Python und task-eigenen Build-Roots | 0 | 20 fokussierte öffentliche Paket-, External-CWD-, CLI-, Metadaten-, getaggte-Erwartungs-, Pfadalias-/Zwischen-Symlink-/FIFO-, Generator-Output- und Legacy-Controls bestehen. | framework-contract-api-20260824 |
| python ci/tools/generate-framework-contract-catalog.py --check | 0 | Der generierte payloadfreie Katalog stimmt mit dem eingecheckten Quellkatalog und den YAML-Fällen überein. | framework-contract-api-20260824 |
| make test-no-crs-contract | 0 | 98 native No-CRS-Contract-Tests bestehen. | framework-contract-api-20260824 |
| make test-five-connectors-with-crs-no-mrts-contract | 0 | 26 Tests bestehen beim vollständigen Retry nach einer bekannten FIFO-Observer-Timing-Race; auch das fokussierte Control bestand. | framework-contract-api-20260824 |
| make check-documentation, make test-change-record-contract, make test-makefile-contract und make check-no-crs-catalog | 0 | Dokumentations-, Traceability-, Makefile- und 166-Fälle-Katalog-Contracts bestehen. | framework-contract-api-20260824 |
| Changed-Python py_compile, git diff --check und make lint | 0 | Compilation, Whitespace und der vollständige native Lint-Target bestehen. | framework-contract-api-20260824 |
| Codex-Security-Diff-Scan und versiegelte Contract-Validierung vor der Remediation | 0, überholt | Vollständige Working-Tree-Coverage und null reportable Findings für den initialen Patch; die task-eigene Sonar-Remediation benötigt vor der Follow-up-Delivery einen Nachfolge-Scan. | framework-contract-api-20260824 |

## Sicherheitsauswirkung

Die neue API weist doppelte JSON-Keys, fehlerhaftes UTF-8, absolute/Traversal-
und Pfadalias-Eingaben, Zwischen-/End-Symlinks, Spezialdateien, übergroße
Eingaben, unbekannte Erwartungsarten, unerwartete Felder und Boolean-HTTP-
Status zurück. Der finale Descriptor-Open erfolgt nichtblockierend, sodass ein
writerloses FIFO abgewiesen wird statt zu hängen. Sie gibt nur stabile JSON-
Fehlercodes aus. Die Implementierung verwendet kein eval, exec, vom Caller
kontrollierten Modulnamen, Shell-Interpolation, keine Suppression und keine
Exception-Pfad-Offenlegung. Symlinks im Generator-Output-Parent und fehlerhafte
nicht-hashbare Enum-Werte werden ebenfalls zurückgewiesen; Letztere liefern den
dokumentierten Contract-Fehler/Exit-Code 2. Der Nachfolge-Security-Diff-Scan ist
ein erforderliches Delivery-Gate.

## Dokumentation und Runtime-Evidenz

Die gepaarte öffentliche API-Anleitung erläutert Installation, Imports,
Operationen, typisierte Erwartungen, JSON-CLI, Exit-Codes,
Eingabebeschränkungen, Pflege und Legacy-Kompatibilität. Die aufgeführten
Tests sind statische/Paket-Contract-Evidenz; es wird kein Connector-Host-
Runtime-, Request-Payload- oder Lifecycle-Runtime-Erfolg behauptet.

## Nicht ausgeführte Prüfungen

- Vollständige Connector-Smokes, Runtime-Matrix-, Protokoll- und MRTS-Matrix-
  Prüfungen gehören nicht zu dieser Paket/API-Änderung und benötigen
  connector-eigene Runtimes oder separat abgegrenzte MRTS-Autorität.
- Ruff ist in der ausgewählten Framework-virtuellen Umgebung nicht verfügbar
  und wurde nicht installiert, weil für diese Aufgabe keine Dependency-
  Installationsautorität besteht.
- Der initiale SonarCloud-Check des Draft-PR #110 scheiterte am New-Code-
  Quality-Gate wegen task-eigener Komplexitäts-/Pfad-Findings. Die abgeschlossene
  lokale Remediation benötigt weiterhin einen Nachfolge-Push und die
  Hosted-Check-/Review-Evidenz des exakten HEAD.

## Einschränkungen und Restrisiko

Die öffentliche Ressource stellt strukturierte Metadaten bereit, aber keine
Raw-Request-, Response-, Rule- oder Log-Payloads. Ein Source-Archiv ohne Git
kann keinen Commit liefern und meldet unavailable statt Provenienz zu erfinden.
Parent-Integration, ein Parent-Gitlink-Update und MRTS-Änderungen bleiben
out of scope. Es wird kein Sicherheitsrisiko akzeptiert.

## Finaler Diff- und Review-Status

Der initiale task-eigene Framework-Commit wurde als unabhängiger Draft-PR #110
gepusht. Sein initialer SonarCloud-Lauf meldete task-eigene Findings; die
begrenzte lokale Remediation und fokussierten Regressionstests sind
abgeschlossen, während ein Nachfolge-Security-Diff-Scan, Follow-up-Commit/
Push und die Hosted-Checks-/Review-Evidenz des exakten HEAD noch erforderlich
sind. Der Branch ist unabhängig; kein Merge, Rebase, Force-Push, Auto-Merge,
automatisches Ready-for-review, Parent-Change oder MRTS-Aktion ist autorisiert.
