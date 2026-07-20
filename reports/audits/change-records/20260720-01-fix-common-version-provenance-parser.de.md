# Change Record

**Sprache:** [English](20260720-01-fix-common-version-provenance-parser.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260720-01-fix-common-version-provenance-parser |
| UTC-Datum | 2026-07-20 |
| Framework-Basisrevision | efdbcbd98afeed0f39f8912ce1140aaa5742f507 |
| Issue oder Pull Request | FND-FRAMEWORK-0027 und FND-FRAMEWORK-0028; Framework-Draft-PR noch nicht erstellt. |

## Motivation und Problemstellung

Der aktuelle Framework-master scheitert im geplanten Common-Version-Check
fail-closed mit vier leeren ModSecurity-Repository-/Ref-Aliasen, obwohl
common.sh freigegebene literale ModSecurity-v3-Werte für Repository, Commit und
Release-Tag enthält. Der Parser ließ vor dem Alias-Auflösen nur gleichartige
CRS-Literal-Anker zu. Nach der Reparatur zeigte eine Sicherheitsreview zudem,
dass der generische Updater bei einem neueren ModSecurity-v3-Release nur den
Kompatibilitätsalias ohne seinen freigegebenen Immutable-Commit planen könnte.

## Betroffene Komponenten und Sicherheitsgrenzen

- ci/tools/check-common-versions.py
- tests/security_regression/test_common_versions_sonar_provenance.py

Die Grenze ist der Framework-Supply-Chain-Provenance-Checker. Freigegebene
Identitätsanker müssen vor erforderlichen Aliasen aufgelöst werden; fehlende
getrackte Provenance muss weiterhin fail-closed scheitern. Keine Parent- oder
MRTS-Grenze ändert sich.

## Akzeptanzkriterien

- Die drei freigegebenen ModSecurity-v3-Literal-Anker lösen sich vor Aliasen auf.
- Die vier erforderlichen ModSecurity-Repository-/Ref-Aliase lösen sich aus
  diesen Ankern auf.
- Fehlende Anker lassen die bestehende getrackte Variablenvalidierung weiter
  scheitern.
- Ein neueres ModSecurity-v3-Release kann nicht automatisch nur seinen
  Kompatibilitätsalias aktualisieren.
- Keine Optional-Variable, kein Provenance-Pin, keine Parent-Datei, kein
  Sonar-Control und keine MRTS-Datei ändern sich.

## Untersuchte Alternativen

Aliase als optional zu markieren, beliebige Literal-Zuweisungen zu parsen,
einen Provenance-Pin zu ändern oder den geplanten Check zu unterdrücken würde
eine fehlende Provenance-Bedingung verbergen oder ihr Control abschwächen. Die
Beschränkung der Allowlist auf die drei geprüften ModSecurity-v3-Identitätsnamen
bewahrt das vorhandene Design.

## Implementierungsentscheidung

Der Parser verwendet nun eine explizite Approved-Literal-Allowlist mit den
vorhandenen CRS-Identitätsnamen und den drei geprüften ModSecurity-v3-
Identitätsnamen. Eine fokussierte Fixture prüft positive Literal-/Alias-
Auflösung, die negative Missing-Anchor-fail-closed-Kontrolle und ein neueres
ModSecurity-v3-Release als unknown/manual-review-Zustand ohne Update-Plan.

## Geänderte Dateien und Tests

- ci/tools/check-common-versions.py: erkennt die drei geprüften literalen
  Identitätsvariablen MODSECURITY_V3_APPROVED_* und verweigert die Synthese
  eines partiellen ModSecurity-v3-Release-Tag-zu-Commit-Updates.
- tests/security_regression/test_common_versions_sonar_provenance.py: ergänzt
  fokussierte positive, Missing-Anchor- und Partial-Auto-Update-Regressionen.
- Dieses englische/deutsche Change-Record-Paar dokumentiert den
  Framework-only-Fix.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| python3 -m unittest discover -s tests/security_regression -p test_common_versions_sonar_provenance.py -v | 0 | 15 fokussierte Tests bestanden, einschließlich positiver Aliase, Missing-Anchor-Ablehnung und No-Partial-Update-Control. | 20260720T080314Z-parent-pr55-57-59-framework-update-3443af13 |
| python3 -m py_compile ci/tools/check-common-versions.py | 0 | Der geänderte Checker kompilierte mit externem Bytecode-Root. | 20260720T080314Z-parent-pr55-57-59-framework-update-3443af13 |
| make test-modsecurity-v3-provenance-contract | 0 | 10 Provenance-Contract-Tests bestanden mit task-eigenen Build- und Temp-Roots. | 20260720T080314Z-parent-pr55-57-59-framework-update-3443af13 |
| python3 ci/tools/check-common-versions.py --check --json --timeout 20 | 0 | Keine erforderliche Variable fehlt; ein neueres ModSecurity-v3-Release ist als review-pflichtiges unknown ohne Update-Plan sichtbar. | 20260720T080314Z-parent-pr55-57-59-framework-update-3443af13 |
| make check-bilingual-docs | 0 | Die gepaarte englische/deutsche Dokumentationsprüfung bestand. | 20260720T080314Z-parent-pr55-57-59-framework-update-3443af13 |
| make check-documentation | 0 | Dokumentationslinks, Variablendokumentation, Repository-Referenzen und Change-Record-Vertrag bestanden. | 20260720T080314Z-parent-pr55-57-59-framework-update-3443af13 |
| make lint | 0 | Die Framework-weiten Shell-, Syntax-, CI-Security-, Provenance-, Workflow-, Katalog-, Dokumentations- und Diff-Prüfungen bestanden. | 20260720T080314Z-parent-pr55-57-59-framework-update-3443af13 |
| git diff --check | 0 | Kein Whitespace-Fehler im Task-Diff. | lokaler Pre-Commit-Review |

## Sicherheitsauswirkung

Der ursprüngliche Parserpfad wurde vor dem Fix reproduziert: Freigegebene
Literale wurden ignoriert und erforderliche Aliase leer. Die neue Regression
entfernt diese Anker zusätzlich und beweist, dass validate_entries die Aliase
weiter abweist. Keine Optional-Liste, kein Trust-Pin, kein Scanner-Control und
keine MRTS-Grenze wurde abgeschwächt.
Der hinzugefügte Release-Wrapper hält eine ungeprüfte Tag-zu-Commit-Änderung in
einem unknown/manual-review-Zustand und erzeugt keinen privilegierten
automatischen Write.

## Dokumentation und Runtime-Evidenz

Dieses gepaarte Change-Record-Paar ist die einzige leserorientierte
Dokumentationsänderung. Es wurde keine Connector-Runtime- oder
Lifecycle-Evidenz erfasst, weil die Korrektur auf einen statischen
Framework-Provenance-Parser begrenzt ist.

## Nicht ausgeführte Prüfungen

Gehostete Exact-Head-CI, CodeQL, SonarCloud, Review und Konversations-Checks
warten auf den Framework-Draft-PR. Der beobachtete nicht schreibende
`--check --json`-Befehl endet bei Exit zero mit einem review-pflichtigen
Unknown-Zustand, ohne fehlende ModSecurity-Provenance-Variablen und ohne
partiellen ModSecurity-v3-Update-Plan. Die schreibende geplante Variante
`--update --markdown --write-files` wurde nicht gegen kanonisches common.sh
ausgeführt; ihre Exact-Head-Workflow-Evidence bleibt ausstehend. MRTS-Tests
sind nicht anwendbar und MRTS wurde nicht berührt.

## Einschränkungen und Restrisiko

Die Korrektur prüft oder ändert keine aktuellen Upstream-Pins. Ein neueres
ModSecurity-v3-Release bleibt bewusst manuelle Arbeit, bis ein sicherer
Tag-zu-Immutable-Commit-Resolver entwickelt und geprüft ist. Das unabhängige
Framework-Master-Sonar-Gate bleibt FND-SONAR-0002.

## Finaler Diff- und Review-Status

Der Task-Diff ist auf Parser-Allowlist, fokussierte Regression und dieses
gepaarte Record beschränkt. Whitespace-Review bestand. Unabhängige
Source-Security-Review und ihre Folgeprüfung sind ohne Bypass,
Berechtigungserweiterung oder MRTS-Änderung abgeschlossen. Exact-Head-gehostete
CI, CodeQL, SonarCloud, Review- und Konversations-Evidence bleiben nach dem
Öffnen des Draft-PR ausstehend. Keine Secrets oder rohen sensiblen Materialien
sind dokumentiert.
