# Change Record: SonarQube-Cloud-S1192-Duplizierung des HAProxy-Entrypoints beheben

**Sprache:** [English](20260925-01-remediate-sonar-s1192-haproxy-entrypoint.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260925-01-remediate-sonar-s1192-haproxy-entrypoint |
| UTC-Datum | 2026-09-25 |
| Framework-Basisrevision | 6c248afe85c24ebdfb1cd66e171e908f7ef29d48 |
| Issue oder Pull Request | SonarQube-Cloud-Issue AaA1eamGk8_C4ZaY-OsO auf `master`; vorgeschlagener Framework-Branch `codex/framework-sonarqube-remediation-20260925` nach `master`. |

## Motivation und Problemstellung

Der aktuelle SonarQube-Cloud-New-Code-Readback für `master` meldet einen
offenen, task-eigenen `python:S1192`-Maintainability-Befund. Er identifiziert
drei Kopien des HAProxy-Kompatibilitäts-Smoke-Entrypoint-Literals im
Framework-Katalogchecker. Das Quality Gate besteht, aber der Befund bleibt
offen, bis eine frische Analyse des reparierten Pull-Request-Heads ihn nicht
mehr meldet.

## Betroffene Komponenten und Sicherheitsgrenzen

- `ci/checks/catalog/five_connectors_with_crs_no_mrts.py` besitzt einen
  geschlossenen Framework-Katalog für den Five-Connector-Evidenzvertrag.
- Der HAProxy-Entrypoint bleibt ein `compatibility-only`-statischer
  Katalogwert; diese Änderung ergänzt weder Runtime-Dispatch noch Credentials,
  Berechtigungen oder Connector-Capability-Verhalten.
- Dies ist eine Wartbarkeitsreparatur, keine Security-Remediation. Keine
  Parent-Datei, kein Parent-Gitlink, keine MRTS-Quelle und kein MRTS-Gitlink
  werden geändert.

## Akzeptanzkriterien

1. Die drei Katalog-/Checker-Verwendungen des HAProxy-Kompatibilitäts-Entrypoints
   referenzieren eine eng benannte modulweite Konstante mit unverändertem Wert.
2. Bestehende Katalogvalidierung und Contract-Test-Erwartungen behalten
   denselben Entrypoint und das Fail-Closed-Identity-Verhalten.
3. Es wird keine SonarQube-Suppression, Exclusion, Regel-/Profil-/Gate-Änderung
   oder unzusammenhängende Refaktorierung eingeführt.
4. Nach Erstellung des vorgeschlagenen Pull Requests wird ein frischer
   Exact-Head-GitHub- und SonarQube-Cloud-Readback beobachtet.

## Untersuchte Alternativen

- Unterdrücken, akzeptieren oder als False Positive markieren wurde abgelehnt:
  Das duplizierte Literal hat eine direkte, verhaltensbewahrende Quellreparatur.
- Die Wiederverwendung einer breiteren generischen Pfadkonstante wurde
  abgelehnt, weil der Wert die spezifisch ausgewählte HAProxy-Kompatibilitäts-
  Identität darstellt.
- Den Entrypoint oder sein Validierungsverhalten zu ändern wurde abgelehnt,
  weil dies die geprüfte Framework-/Parent-Grenze statt der Duplizierung ändern
  würde.

## Implementierungsentscheidung

`HAPROXY_COMPATIBILITY_ENTRYPOINT` ist die einzige modulweite Schreibweise
von `ci/runtime/run-haproxy-smoke.sh`. Der Katalogrecord, das
Expected-Entrypoint-Mapping und die Closed-Record-Validierung referenzieren
nun diese Konstante. Der aufgelöste String und jedes
Identity-Validierungsverhalten bleiben unverändert.

## Geänderte Dateien und Tests

- `ci/checks/catalog/five_connectors_with_crs_no_mrts.py`
- Dieser gepaarte englische/deutsche Change Record.

Die bestehende fokussierte Suite
`tests.ci_security.test_five_connector_with_crs_no_mrts_contract` prüft den
ausgewählten HAProxy-Kompatibilitäts-Entrypoint und negative
Katalogmutationen. Keine Testlogik änderte sich, da der extern beobachtbare
Wert unverändert ist.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | ---: | --- | --- |
| Verbundener SonarQube-Cloud-New-Code-Readback für `master` | 0 | Ein offener task-eigener `python:S1192`-Befund, AaA1eamGk8_C4ZaY-OsO, bei `ci/checks/catalog/five_connectors_with_crs_no_mrts.py:112` bestätigt; kein Raw-Payload gespeichert. | Projekt `Easton97-Jens_ModSecurity-test-Framework` |
| GitHub-Quell- und Policy-Readback an der Basisrevision | 0 | Genau drei Source-Kopien und die bestehende fokussierte Contract-Abdeckung bestätigt. | `6c248afe85c24ebdfb1cd66e171e908f7ef29d48` |

## Sicherheitsauswirkung

Es wurde keine Security-Remediation durchgeführt. Der Patch ändert nur eine
statische Wartbarkeitsdarstellung; er fügt kein Token, Secret, keine Permission,
keinen Workflow, kein Netzwerk-, Shell-Dispatch- oder Publish-Verhalten hinzu.

## Dokumentation und Runtime-Evidenz

Dieser gepaarte Change Record dokumentiert die Framework-eigene Reparatur.
Es wurde keine Connector-Runtime- oder Lifecycle-Evidenz erfasst, und es wird
keine Aussage über Connector-Support oder Promotion getroffen.

## Nicht ausgeführte Prüfungen

Vor dem ersten Connector-basierten Commit wurde kein lokaler Framework-Test
ausgeführt, weil diese Aufgabe keinen materialisierten Framework-Checkout und
keine konfigurierte Framework-virtuelle Umgebung besitzt. Current-Head-
GitHub-Workflows, Pull-Request-Review und frischer SonarQube-Cloud-Readback
sind nach Branch-Delivery erforderlich und werden hier nicht abgeleitet.

## Einschränkungen und Restrisiko

Der Befund ist nur behoben, wenn eine frische SonarQube-Cloud-Analyse für den
exakten Pull-Request-Head AaA1eamGk8_C4ZaY-OsO nicht mehr auflistet. Hosted-Validierung
bleibt von Connector-Runtime-Evidenz getrennt; ein erfolgreicher statischer
oder Contract-Check belegt kein Connector-Host-Verhalten.

## Finaler Diff- und Review-Status

Der Kandidatendiff wurde gegen Basis 6c248afe85c24ebdfb1cd66e171e908f7ef29d48 geprüft: eine Konstante plus drei
Referenzen und dieser gepaarte Record, ohne Suppression oder unzusammenhängende
Änderung. Der Task-Branch ist nicht gemergt; Parent-Gitlink-Disposition ist
`unchanged` und MRTS bleibt `default_read_only`. Es werden keine Secrets
oder rohen sensitiven Daten dokumentiert.
