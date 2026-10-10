# First-Byte-Validierung: begrenzte Helper-Verantwortung

**Sprache:** [English](20261010-05-first-byte-validation-helper-limits.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261010-05-first-byte-validation-helper-limits |
| UTC-Datum | 2026-10-10 |
| Framework-Basisrevision | 873e51fbebbedb163a5c75a22a7abe0158861a40 |
| Issue oder Pull Request | Framework-PR #137; Parent-PR #396 |

## Motivation und Problemstellung

Die Sonaranalyse des exakten873 fand trotz GateOK zwei eingeführte Maintainability-Probleme: S3776 meldet Pair-Resolver-Komplexität16 über15; S107 meldet14 Pass-Error-Helperparameter über13. Beide erfordern keine Änderung des Evidenzvertrags.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-Katalognormalisierung und native Vertragstests. Originalgrenzen für versiegelte Events, Transaktion/Profil/Counter/Chronologie und unabhängige PASS-Validierung bleiben unverändert. Keine Parent-, MRTS- oder Connector-Produktänderung.

## Akzeptanzkriterien

Gezielte Strukturregressionen sind vor Implementierung rot und danach grün. Vollständige normalisierte Records und geordnete Validatorfehler bleiben für bestehende Pair-/Legacy-/Mismatch-/Provenanceinputs identisch; native NoCRS-, Dokumentations- und Syntaxprüfungen bestehen. Sonar der aktuellen Source bleibt separat erforderlich.

## Untersuchte Alternativen

Thresholdänderungen, Suppressions und reduzierte Evidenzvalidierung wurden verworfen. Ein größerer Validierungskontext-Refactor war unnötig: Provenancefehler sind ausschließlich ein geordnetes Präfix an einem Aufrufer.

## Implementierungsentscheidung

Unverändertes Legacy-Candidate-Prädikat für die übergebene Transaktion aus dem Pair-Resolver extrahieren. Provenance-Präfix-Passthroughparameter aus normalized_case_pass_errors entfernen und dasselbe geordnete Präfix am einzigen Aufrufer vor den unveränderten Helperfehlern initialisieren. Bestehende Statusguards, Kausalitätsprüfungen und Fehlerreihenfolge bleiben erhalten.

## Geänderte Dateien und Tests

`ci/checks/catalog/no_crs_baseline.py`, `tests/no_crs/test_no_crs_baseline.py` und dieses neue EN/DE-Recordpaar. Zwei native Strukturmethoden prüfen gezielte Legacy-Delegation und die13-Parametergrenze. Der vorherige First-Byte-Change-Record bleibt unverändert.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| RTK/Python offline first-byte-quality/regression.py | 1 | Zwei Strukturtests RED | nginx-full97-followup-20261010T084822Z/first-byte-quality |
| RTK/Python offline regression.py --proposed, erster Harness | 1 | Struktur GREEN; Harness verwendete nicht vorhandene Katalog-API, extern korrigiert | Dasselbe Analyseverzeichnis |
| RTK/Python offline regression.py --proposed, korrigiert | 0 | Zwei Strukturtests GREEN;32 vollständige Record-/Fehler-Differentialvektoren identisch, einschließlich echter Pair-Positivfälle | Dasselbe Analyseverzeichnis |
| RTK/Python native zwei Strukturtests, nur Tests | 1 | Zwei Tests/zwei Fehler, 0.006s | first-byte-quality/versioned-red.log |
| RTK/Python native SeparatedNginxFirstByteTest, integrierte Source | 0 | Acht Tests, keine Skips, 7.312s | first-byte-quality/versioned-green.log |
| RTK/Python regression.py --installed gegen erhaltene873-Source | 0 | Zwei Strukturtests;32 vollständige Ausgabedifferentiale identisch, echte Positivfälle PASS | first-byte-quality/versioned-differential.log |
| RTK/make test-no-crs-contract | 0 | 423 Tests, keine Skips, 181.211s | first-byte-quality/versioned-suite.log |
| RTK/make check-documentation test-change-record-contract | 0 | Dokumentation und vier CR-Tests, 0.087s | first-byte-quality/versioned-docs.log |
| RTK/Python AST-Parse; RTK/git diff --check | 0 | Beide geänderten Pythondateien gültig; Whitespace gültig | Beobachtete Toolreceipts |

## Sicherheitsauswirkung

Keine Security-Remediation wird behauptet; kein Validator, keine Rule, kein Gate oder Threshold wird gelockert. Transaktionsidentität, versiegelte Same-Run-Autorität, Native-Profilgrenzen und kausale Evidence bleiben identisch.

## Dokumentation und Runtime-Evidenz

Dieses EN/DE-Paar dokumentiert einen verhaltensgleichen Framework-Helperrefactor. Differentialprüfungen verwenden unveränderte echte AB-Evidence und negative In-Memory-Inputs. Keine neue Runtime-Evidence gesammelt; Replay ist keine neue Invocation und kein Full97.

## Nicht ausgeführte Prüfungen

Vollständiger nativer Lint, Sonar der aktuellen Source, Veröffentlichung und neue begrenzte Runtime bleiben Koordinatoraufgaben. Kein Full97 oder geschützter Workflow ausgeführt. Strukturdelegations-/Parameterprüfungen behaupten keine bereits abgeschlossene neue Remote-Sonaranalyse.

## Einschränkungen und Restrisiko

Struktur-/Differentialprüfungen ersetzen weder Sonar der aktuellen Source noch frische artefaktgebundene Runtime. Globale Required-Coverage und geschützte Voraussetzungen bleiben separat.

## Finaler Diff- und Review-Status

Nach explizitem GO vom sauberen873 und beobachtetem nativen Tests-only-RED integriert. Genau zwei Pythondateien plus dieses neue EN/DE-Paar sind geändert/untracked; vorheriger CR04, Katalog, Schemas, Required-Umfang, Parent und MRTS unverändert. Originalsource extern erhalten und vor Bearbeitung bytegleich bestätigt. Whitespace-/Scopeprüfungen bestehen. Unabhängiges finales statisches Review und Koordinator-Diffreview fanden keine wesentliche Vertrags- oder Scopeabweichung. Normale separate Veröffentlichung bleibt offen.
