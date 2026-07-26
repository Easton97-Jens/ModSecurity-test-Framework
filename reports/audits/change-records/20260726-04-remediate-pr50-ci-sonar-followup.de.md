# Änderungsnachweis: PR-#50-Follow-up für CI und SonarQube Cloud

**Sprache:** [English](20260726-04-remediate-pr50-ci-sonar-followup.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260726-04-remediate-pr50-ci-sonar-followup` |
| UTC-Datum | 2026-07-26 |
| Framework-Basisrevision | `a7ebf5a1d9cad2b0a65a7603476a1434fdb16cf6` |
| Issue oder Pull Request | Framework-PR [#50](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/50), Follow-up zu seinem aktuellen exakten Head `b0f3e745075d57ee727bdfcd61f6258d488d4dc1`; dieser Record beansprucht kein Merge-Ergebnis. |

## Motivation und Problemstellung

Das SonarQube-Cloud-Quality-Gate von PR #50 bestand, meldete aber zwei neue
Source-Code-Issues: einen wiederholten Redaktionsmarker im Protocol-Artefakt-
Validator und eine redundante Kontrollfluss-Anweisung im Command-Renderer. Der
Exact-Head-OSV-Vergleich scheiterte zudem, bevor er Evidenz erzeugen konnte,
weil der Scanner beim Auflösen des unveränderten Basis-Manifests eine Upstream-
Antwort `service unavailable` erhielt und Status `127` zurückgab.

## Betroffene Komponenten und Sicherheitsgrenzen

- `ci/checks/protocol/check_protocol_evidence.py` validiert kopierte Protocol-
  Command-Artefakte einschließlich ihrer verpflichtenden Redaktionsdarstellung.
- `ci/checks/protocol/protocol_client.py` erzeugt dieses begrenzte Artefakt.
- `.github/workflows/ci-security-osv.yml` vergleicht exakte Base- und Pull-
  Request-Dependency-Manifeste mit einem checksum-verifizierten Scanner und
  behält nur validierte Evidenz.
- Keine Parent-Source oder Gitlink, kein Framework-zu-MRTS-Gitlink, keine
  MRTS-Source sowie keine Änderungen an Scanner-Lock, Scanner-Version,
  Permissions, Gate, Exclusion oder Suppression.

## Akzeptanzkriterien

- Der Validator verwendet einen benannten kanonischen Redaktionsmarker für alle
  drei relevanten Vergleiche.
- Der Renderer enthält kein redundantes finales Loop-`continue` und bewahrt
  dieselbe gerenderte Ausgabe.
- Scanner-Status `127` erhält genau zwei begrenzte Retries; `0` und `1`
  bewahren die bestehende Ergebnisbehandlung, während ein finaler `127` oder
  jeder andere Status den Job weiter fehlschlagen lässt und keine Evidenz als
  valide markieren kann.
- Fokussierte Protocol- und CI-Security-Regressionen bestehen lokal; Hosted-
  Checks und SonarQube Cloud laufen vor der Auslieferung gegen den geänderten
  exakten PR-Head neu.

## Untersuchte Alternativen

- Status `127` als erfolgreich zu werten, `continue-on-error` zu verwenden,
  den OSV-Job zu entfernen oder partielle Evidenz zu behalten wurde verworfen,
  weil jede dieser Varianten ein fehlendes Security-Ergebnis verbergen würde.
- Jeden Fehler unbegrenzt zu wiederholen wurde verworfen, weil deterministische
  Scanner-Fehler schnell und sichtbar fehlschlagen müssen.
- Die SonarQube-Cloud-Konfiguration zu ändern oder eine Suppression hinzuzufügen
  wurde verworfen; beide gemeldeten Source-Issues haben direkte Korrekturen im
  Source-Code.

## Implementierungsentscheidung

Der Artefakt-Validator definiert `REDACTED_COMMAND_VALUE` und verwendet ihn in
jeder Redaktionsprüfung. Der Renderer entfernt nur das wirkungslose
`continue`. Der OSV-Workflow führt den ersten Scanner-Aufruf über den
bestehenden sichtbaren Helper aus und wiederholt ausschließlich Status `127`
nach einer bzw. zwei Sekunden. Das dritte Ergebnis folgt wieder der bisherigen
fail-closed Status-Regel. Eine fokussierte Shell-Regression verwendet einen
Fake-Scanner und belegt transiente Erholung, persistentes Fehlschlagen und den
legitimen Vulnerability-Ergebnisfall (`1`), ohne einen externen Dienst
aufzurufen.

## Geänderte Dateien und Tests

- `ci/checks/protocol/check_protocol_evidence.py` und
  `ci/checks/protocol/protocol_client.py` für die zwei Sonar-Issues.
- `.github/workflows/ci-security-osv.yml` für begrenztes, status-spezifisches
  Retry-Verhalten ohne Abschwächung der Kontrolle.
- `tests/ci_security/test_ci_security_evidence_contract.py` für die drei
  Scanner-Ergebnisse.
- Dieses Englisch/Deutsch-Record-Paar und der gepaarte Record-Index.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Fokussierte CI-Security- und Protocol-Testauswahl | 0 | 30 Tests bestanden, einschließlich transienter `127`-Erholung, persistentem `127`-Fehler nach drei Versuchen und erhaltener `1`-Behandlung. | Lokale Evidenz im externen Task-Worktree |
| `make lint` | 0 | Framework-Shell-, Python-, CI-Security-, Provenance-, Action-Pin-, Workflow-, Data-Flow-, Dokumentations-, Change-Record- und Whitespace-Contracts bestanden. | Lokale Evidenz im externen Task-Worktree |
| Vorheriger Exact-Head-OSV-Vergleich | 127 | Der Scanner konnte das unveränderte Basis-Manifest wegen eines nicht verfügbaren Upstream-Dienstes nicht auflösen; es entstand keine Vergleichsevidenz. | GitHub Actions `30204914941` / Job `89801198064` |

## Sicherheitsauswirkung

Der ursprüngliche Fehlerpfad wird durch einen Fake-Scanner mit Status `127`
nachgestellt: Die ersten zwei Fehler werden wiederholt, ein dritter gibt `127`
zurück und lässt den Caller fehlschlagen. Der alternative unerwartete
Statuspfad schlägt weiterhin sofort fehl. Der legitime Scanner-Finding-Status
`1` bleibt wie zuvor für den späteren Vergleich akzeptiert. Damit verbessert
die Korrektur die Verfügbarkeit bei einer transienten externen Abhängigkeit,
ohne einen fehlenden Security-Scan als valide Evidenz zu behandeln.

## Dokumentation und Runtime-Evidenz

Dieses gepaarte Record und seine Index-Einträge dokumentieren das reine
Framework-Follow-up. Die lokale Regression ist ein hermetischer Scanner-
Interface-Test; kein Live-Scanner-Dienstaufruf, Connector-Lifecycle, Parent-
Vorgang, MRTS-Vorgang, Hosted-Check, SonarQube-Cloud-Analyse, Review oder
Merge wird bisher beansprucht.

## Nicht ausgeführte Prüfungen

- Hosted Actions, SonarQube Cloud, Reviews, Branch Protection und die
  resultierende-Master-Prüfung benötigen den geänderten exakten PR-Head.

## Einschränkungen und Restrisiko

Bleibt der Upstream-Scanner-Dienst über alle drei Versuche nicht verfügbar,
bleibt der Job korrekt fehlgeschlagen und die PR-Integration blockiert. Der
Retry macht Scanner-Ergebnisse weder offline reproduzierbar noch behebt er eine
separate externe Abhängigkeitsstörung.

## Finaler Diff- und Review-Status

Das lokale Follow-up ist bei Erstellung dieses Records uncommitted. Es ist auf
die zwei gemeldeten Sonar-Issues, den verifizierten OSV-Verfügbarkeitsfix,
fokussierte Tests und erforderliche zweisprachige Nachverfolgbarkeit begrenzt.
Finaler Diff-/Security-Review, lokale Validierung, Exact-Head-Push, Hosted-
Validierung, geschützter Merge und die Finding-Archiv-Disposition bleiben
erforderlich.
