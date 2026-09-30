# Verschachtelten ModSecurity-v3.0.17-Gitlink korrigieren

**Sprache:** [English](20260930-02-fix-modsecurity-v3-gitlink.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260930-02-fix-modsecurity-v3-gitlink |
| Zugehöriges Issue / PR | Parent-PR #398 |
| Status | Framework-Fix als Entwurf; CI- und Runtime-Verifikation ausstehend |
| Basisrevision | `bc8217d325809b9aba9a1d8c16964d71a01933ee` |

## Motivation und Problemstellung

Der freigegebene ModSecurity-v3.0.17-Quellcommit `1925753989ccce977cdaae417b55c9726c7cf02c` enthält `test/test-cases/secrules-language-tests` mit `f73c73027ef49ccf99c7911744929a71d15ff419`. Das Framework erwartet noch `a3d4405e5a2c90488c387e589c5534974575e35b`; die exakte Gitlink-Prüfung blockiert deshalb die Bereitstellung.

## Betroffene Komponenten und Sicherheitsgrenzen

Geändert werden nur Framework-eigene Dateien: `ci/lib/common.sh`, die Security-Regression-Fixture und dieses Change-Record-Paar. Keine Parent- oder MRTS-Datei wird bearbeitet. Parent-Gitlink-Disposition: `update_required` nach einem separat autorisierten Framework-Merge; MRTS-Auswirkung: `default_read_only`.

## Akzeptanzkriterien

- Beide Framework-Prüfungen und beide Test-Fixtures auf den exakten Gitlink im freigegebenen Upstream-Git-Tree setzen.
- Exakte Graphprüfung, offizielle Origins, Commit-Pins und Fail-Closed-Verhalten bei Abweichungen erhalten.
- Current-Head-Framework-CI und separate Parent-Runtime-Evidenz vor Integrationsaussagen einholen.

## Untersuchte Alternativen

Ein Abschalten der rekursiven Gitlink-Prüfung würde die Provenienzabweichung verbergen und wird nicht vorgenommen. Der freigegebene ModSecurity-Upstream-Commit muss für diese Korrektur nicht gewechselt werden.

## Implementierungsentscheidung

Die vier veralteten `secrules-language-tests`-SHA-Literale werden durch den verifizierten Wert `f73c73027ef49ccf99c7911744929a71d15ff419` ersetzt. Andere Root- und verschachtelte Gitlinks bleiben unverändert.

## Geänderte Dateien und Tests

`ci/lib/common.sh` (zwei Literale), `tests/security_regression/git_provenance_test_support.py` (zwei Fixture-Literale) und dieses englisch/deutsche Change-Record-Paar. Bestehende Provenienztests bleiben aktiv; kein Test und keine Sperre wird entfernt.

## Befehle und Ergebnisse

Eine schreibgeschützte GitHub-Git-Tree-Abfrage von `owasp-modsecurity/ModSecurity` bei `1925753989ccce977cdaae417b55c9726c7cf02c` fand genau einen `160000`-Eintrag für `test/test-cases/secrules-language-tests`, SHA `f73c73027ef49ccf99c7911744929a71d15ff419`. Die Repository-Suche fand den alten SHA nur in den zwei geänderten Dateien. Framework-CI steht aus; kein lokaler Test wird als bestanden behauptet.

## Sicherheitsauswirkung

Die exakte Provenienzprüfung bleibt erhalten und entspricht nun dem freigegebenen Upstream-Graphen. Unerwartete verschachtelte Gitlinks werden weiter zurückgewiesen; beliebige rekursive Submodule werden nicht akzeptiert. Keine Zugangsdaten, Payloads oder Rohlogs werden abgelegt.

## Dokumentation und Runtime-Evidenz

Dieses gepaarte Change Record dokumentiert die Korrektur. Keine generierten Dokumente oder Berichte ändern sich. `modsecurity_v3_framework_provisioning_failed` im Parent-NGINX-Job ist Fehlerbeleg, kein bestandener Runtime-Test; nach Pinning eines neuen Parent-Gitlinks erneut ausführen.

## Nicht ausgeführte Prüfungen

Framework-lokale Unit-, Lint-, Dokumentations- und Runtime-Prüfungen wurden in dieser projektlosen Windows-Task nicht ausgeführt. Hosted-Current-Head-Checks und Reviews müssen Auslieferungsevidenz liefern.

## Einschränkungen und Restrisiko

Die statische Git-Tree-Evidenz beweist den Pin-Fehler, nicht die vollständige Build-Kompatibilität. Der Framework-PR muss geprüft und separat gemergt werden, bevor die Parent-Integration seinen neuen Commit anvisieren kann. Hier wird weder automatisch gemergt noch der Parent-Gitlink geändert.

## Finaler Diff- und Review-Status

Dies ist eine Framework-Korrektur als Entwurf. Der abgegrenzte Diff und die Current-Head-CI müssen vor einer Verifikation geprüft werden; Parent-PR #398 bleibt eine separate Auslieferungseinheit als Entwurf.
