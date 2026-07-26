# Change Record: Abgleich der Codex-Security-CSV-Findings

**Sprache:** [English](20260724-01-reconcile-codex-security-csv-findings.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260724-01-reconcile-codex-security-csv-findings |
| UTC-Datum | 2026-07-24 |
| Framework-Basisrevision | 77d73decd094a8f289fbe0ef2582f12430923e24 |
| Issue oder Pull Request | Draft-PR [#45](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/45) aus agent/fix-codex-security-csv-findings; keine Merge-Berechtigung |

## Motivation und Problemstellung

Der bereitgestellte Codex-Security-CSV-Export enthält 23 Framework-Findings, deren Scan-Revisionen
alle Vorfahren des aktuellen Defaults sind. Der Abgleich muss für jede Zeile eine exakte Disposition
bewahren, statt veraltete Scanner-Pfade oder reine Darstellungsstrings als aktuelle Exploits zu
behandeln. Fünf aktuell offene Kontrollen benötigten enge Framework-Korrekturen; die übrigen Zeilen
wurden als bereits behoben, nicht anwendbar oder False Positive nachgewiesen.

## Betroffene Komponenten und Sicherheitsgrenzen

- ci/provisioning/import-mrts-cases.py: ausgegebene MRTS-Provenance-Identität.
- ci/lib/runtime-component-common.sh und ci/provisioning/prepare-lighttpd-runtime.sh:
  Einhegung gestageter Sources.
- ci/lib/common.sh: Aufnahmeprüfung ignorierter Artefakte im Clean-Check.
- ci/checks/protocol/check_protocol_evidence.py: Policy für erzwungene Protocol-Selectoren.
- ci/tools/check-common-versions.py: Policy für unveränderliche ModSecurity-v3-Commit-Anker.

Die Änderungen sind Supply-Chain-, Filesystem-Containment-, Provenance- und
Protocol-Evidence-Kontrollen. Sie ändern weder Parent, Gitlink, Remote-Default-Branch noch
MRTS-Inhalt.

## Akzeptanzkriterien

- [x] Jede der 23 CSV-Zeilen hat genau eine dokumentierte Disposition.
- [x] Die fünf bestätigten CSV-Zeilen sind durch sechs separate fokussierte Root-Cause-Commits behoben.
- [x] Jede Korrektur hat einen Negativ-Regressionstest und eine Legitimate Control.
- [x] Englischer/deutscher Bericht und Change Record beschreiben dasselbe Ergebnis.
- [x] Der historische Draft-PR-#45-Review verzeichnete gleiche lokale, Remote- und PR-Head-SHA
  sowie 11 erfolgreiche terminale Hosted-Checks bei
  `a025724b2f07d70ffce29c1d6bef5e9b0e93fbcf`; dies ist keine Evidenz für einen späteren Head oder
  eine Merge-Berechtigung.
- [x] Die aktuelle lokale Nachvalidierung dokumentiert unten exakte Befehle und Ergebnisse; nach
  dem nächsten gepushten PR-Head ist eine neue Hosted-Analyse erforderlich.

## Untersuchte Alternativen

Jede veraltete Scan-Zeile weiterhin als offen zu behandeln würde bestehende Kontrollen duplizieren
und nicht-promotierbare Evidenzdarstellung als Runtime-Bypass falsch darstellen. Scanner-Ausgabe als
Cloud-Abschluss zu behandeln wäre ohne frischen authentifizierten Re-Scan unsicher. Der gewählte
Ansatz ordnet jede Zeile dem aktuellen Code zu und ändert nur nachgewiesene Lücken.

## Implementierungsentscheidung

Der Importer gibt das Repository aus, das die Task tatsächlich pinnt. Lighttpd grenzt einen
Stage-Pfad zuerst kanonisch ein und verweigert danach jede bereits vorhandene Source-Stage, sodass
ausführbarer Source nur aus dem verifizierten Missing-Source-Download-/Extract-Flow stammt. Der ModSecurity-v3-Guard prüft
ignorierte Artefakte zusammen mit anderem Checkout-Zustand. Der Protocol-Validator verlangt genau
einen erzwungenen Selector, der dem Profilselector entspricht. Der Version-Checker verwirft
fehlende oder ungültige unveränderliche Commit-Anker vor Netzwerkzugriffen. Eine nachfolgende
`MODSECURITY_V3_COMPONENT`-Konstante zentralisiert das wiederholte Komponentenlabel, ohne
Provenance-Entscheidungen, unterstützte Variablen oder Netzwerkbedingungen zu ändern. Alle
Ergänzungen sind fail-closed und bewahren die bestehenden Legitimate Controls.

## Geänderte Dateien und Tests

| Änderung / Commit | Produktivdateien | Regression Coverage |
| --- | --- | --- |
| d2d3320 | ci/provisioning/import-mrts-cases.py | tests/security_regression/test_import_mrts_cases_sonar.py |
| 19d8494 | ci/lib/runtime-component-common.sh; ci/provisioning/prepare-lighttpd-runtime.sh | tests/security_regression/test_ci_root_bootstrap_hardening.py |
| e60cb8c | ci/provisioning/prepare-lighttpd-runtime.sh | tests/security_regression/test_ci_root_bootstrap_hardening.py |
| e94074c | ci/lib/common.sh | tests/security_regression/test_modsecurity_v3_git_ref_provenance.py und Support-Fixture |
| 75f15ab | ci/checks/protocol/check_protocol_evidence.py | tests/protocol_client/test_check_protocol_evidence.py |
| f3aac14 | ci/tools/check-common-versions.py | tests/security_regression/test_common_versions_sonar_provenance.py |
| SonarQube-Cloud-`python:S1192`-Nacharbeit | ci/tools/check-common-versions.py | tests/security_regression/test_common_versions_sonar_provenance.py |

Die Abgleichsmatrix liegt unter reports/audits/findings/20260724-01-codex-security-csv-reconciliation
als Markdown, deutsches Markdown und JSON vor.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzergebnis | Evidenz |
| --- | --- | --- | --- |
| `rtk proxy -- python3 -B -m unittest tests.security_regression.test_import_mrts_cases_sonar -v` | 0 | 6 Tests bestanden; ausgegebenes Source-Repository ist die gepinnte Identität | aktuelle lokale Nachvalidierung |
| `rtk proxy -- python3 -B -m unittest discover -s tests/security_regression -p test_ci_root_bootstrap_hardening.py -v` | 0 | 11 Tests bestanden; externe, traversal-artige und enthaltene unverifizierte ausführbare Lighttpd-Stages wurden vor Ausführung abgewiesen | aktuelle lokale Nachvalidierung |
| `rtk proxy -- python3 -B -m unittest tests.security_regression.test_modsecurity_v3_git_ref_provenance.ModSecurityV3ProvenanceTests.test_rejects_recursive_topology_bypass_variants -v` | 0 | 1 fokussierter Test bestand; ein ignoriertes Checkout-Artefakt wurde abgewiesen | aktuelle lokale Nachvalidierung |
| `rtk proxy -- python3 -B -m unittest tests.protocol_client.test_check_protocol_evidence -v` | 0 | 16 Tests bestanden; Fallback-, doppelte und widersprüchliche Selector wurden abgewiesen | aktuelle lokale Nachvalidierung |
| `rtk proxy -- python3 -B -m unittest tests.security_regression.test_common_versions_sonar_provenance -v` | 0 | 16 Tests bestanden; fehlende/ungültige Commit-Anker blockieren vor Netzwerknutzung | aktuelle lokale Nachvalidierung |
| `rtk proxy -- bash -n ci/lib/common.sh ci/lib/runtime-component-common.sh ci/provisioning/prepare-lighttpd-runtime.sh` | 0 | geänderte Shell-Quellen werden erfolgreich geparst | aktuelle lokale Nachvalidierung |
| `rtk proxy -- python3 -m json.tool reports/audits/findings/20260724-01-codex-security-csv-reconciliation.json >/dev/null` | 0 | Abgleichs-JSON wird erfolgreich geparst | aktuelle lokale Nachvalidierung |
| `rtk proxy -- make check-documentation` | 0 | zweisprachige Links, Variablendokumentation, Repository-Pfadreferenzen und Change-Record-Vertrag bestanden | aktuelle lokale Nachvalidierung |
| `rtk proxy -- git diff --check` | 0 | aktueller PR-Working-Tree-Diff hat keine Whitespace-Fehler | aktuelle lokale Nachvalidierung |

## Sicherheitsauswirkung

Jede ursprüngliche Negativbedingung wird mit einer fokussierten Regression erneut geprüft:
falsches MRTS-Provenance-Label, extern gestagte oder bereits vorhandene In-Cache-Lighttpd-Source, ignorierte ModSecurity-v3-
Checkout-Reste, alternativer oder mehrdeutiger Protocol-Selector und fehlender/ungültiger
unveränderlicher Version-Anker. Legitime enthaltene Stages, korrekte Selector, saubere Checkouts
und gültige Anker bleiben akzeptiert. Das Design verwirft mehrdeutigen oder unverifizierten Zustand
vor einer Folgeaktion.

## Dokumentation und Runtime-Evidenz

Dieser Record und die Finding-Matrix haben englische und deutsche Gegenstücke. Es wurden keine
Connector-Runtime, kein Produktions-Lifecycle, kein Cloud-Finding-Abschluss, keine Parent-Aktion
und kein MRTS-Write erhoben oder durchgeführt. Quell-CSV und normalisierte Zeilendaten sind im
Task-Evidence-Run aufbewahrt.

## Nicht ausgeführte Prüfungen

Kein authentifizierter Codex-Security-Re-Scan war verfügbar; der Cloud-Abschluss ist daher
blocked_permissions. Bei diesem Record-Update waren kein Framework-Default-Branch-Update, kein
Merge, kein Parent-Gitlink-Update und keine MRTS-Mutation versucht worden. Die Hosted-Check-
Beobachtung beim historischen `a025724b2f07d70ffce29c1d6bef5e9b0e93fbcf`-Head bleibt nur
historische Evidenz; nach einem weiteren Push ist eine aktuelle Head-Analyse erforderlich.

## Einschränkungen und Restrisiko

Dies ist ein Source-Level-Framework-Abgleich. Bestehende vertrauenswürdige Abhängigkeits- und
Runtime-Voraussetzungen bleiben ihren dokumentierten Kontrollen unterworfen. Ein frischer
Cloud-Scan ist nötig, um den Status des Scan-Service zu ersetzen. Ein Draft-PR kann erst nach
gesonderter Autorisierung und Beobachtung aller Current-Head-Kontrollen bereitgemeldet und gemerged
werden.

## Finaler Diff- und Review-Status

Der historische Pre-Documentation-Review beobachtete local = remote = PR head bei
`a025724b2f07d70ffce29c1d6bef5e9b0e93fbcf` sowie 11 ausgeführte Checks einschließlich SonarQube
Cloud und CodeQL Actions/Python/C++. Diese historische Beobachtung belegt nicht den Status des
späteren `d8b6d129ad7ccb0978d7932c2a673e87f10f73d1`-Heads oder eines neueren Heads. Dieser Record
trifft keine Current-Head-Hosted-Check- oder Merge-Aussage und autorisiert keinen Merge.
