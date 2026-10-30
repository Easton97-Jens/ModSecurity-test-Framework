# Integrität der Transferabschlüsse in Protokollartefakten

**Sprache:** [English](20261030-02-protocol-terminal-integrity.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261030-02-protocol-terminal-integrity |
| UTC-Datum | 2026-10-30 |
| Framework-Basisrevision | `d3b47aec9410f7adc3bb40df1ea413c00c438e89` |
| Issue oder Pull Request | Separater Framework-Draft-Nachfolger des gemergten PR #112; Auslieferung im zugehörigen PR dokumentiert |

## Motivation und Problemstellung

Der Protokollartefakt-Prüfer vertraute einem normalen `PASS`, ohne den
Curl-Transferabschluss zu prüfen. Ein widersprüchlicher fehlgeschlagener
Transfer konnte deshalb seine Protokoll- und Herkunftsprüfungen bestehen.
Die primäre Schema-Version blieb ungeprüft; auch dem erfolgreichen unabhängigen
Follow-up strikter Evidence fehlte die Prüfung des Transferabschlusses.
Die Lücken wurden im Produzenten-/Aufrufercode nachgewiesen, nicht durch einen
neuen Runtime-Lauf.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-eigene Annahme von Protokollartefakten einschließlich des bestehenden
kanonischen No-CRS-Verbrauchers. Parent-Source und Framework-Gitlink bleiben
unverändert. MRTS ist read-only und unberührt. Die Protokollunterstützung der
Connectoren ändert sich dadurch nicht.

## Akzeptanzkriterien

Ganzzahlige Schema-Version1 verlangen; fehlende, falsch typisierte oder
widersprüchliche erfolgreiche Transferabschlüsse ablehnen. HTTP-Ablehnungen
mit Curl22/`http_response_error`, gewöhnlichen Erfolg ohne bekannte Inhaltslänge
und strikte fehlgeschlagene Primär-/Reset-Evidence erhalten. Jedes
`PASS`-Follow-up benötigt Curl0/`none`. Während des Testumbaus auf Nutzerwunsch
keine Testfälle, Assertions, Selektoren oder Harnesses hinzufügen.

## Untersuchte Alternativen

Vertrauen auf `PASS` lässt den Widerspruch ungeprüft. Curl0 als Pflicht für die
Primärbeobachtung verwirft gültige WAF-Ablehnungen. `response_complete: true`
als Pflicht verwirft unterstützte Curl-Write-out-Formate ohne Inhaltslänge.
Ein Parent-Gitlink-Update oder eine Kopie der Prüferlogik im Parent würde
Repository-Grenzen überschreiten.

## Implementierungsentscheidung

Erfolgreiche Transferabschlüsse bei der Artefaktannahme prüfen; den
wiederverwendbaren reinen Protokollbeobachtungsprüfer nicht verändern.
Ganzzahligen Exit-Code, passende Transportfehlerkategorie und beobachteten
HTTP-Status verlangen; Curl22 benötigt zusätzlich einen HTTP-Fehlerstatus.
Die Erfolgsprüfung gilt für normale Primärbeobachtungen und `PASS`-Follow-ups,
auch optionale Follow-ups. Primäre und Follow-up-Schema-Version müssen
ganzzahlig1 sein, keine JSON-Booleans oder Fließkommazahlen. Strikte
Primär-Evidence benötigt zusätzlich einen ganzzahligen fehlgeschlagenen
Exit-Code außer0/22 mit bekannter Produzenten-Kategorie oder begrenzter
stderr-abgeleiteter Fehlerkategorie bei unbekannten/Signal-Ausgängen. Ihre
Commit-/Teilantwort-/Reset-/Follow-up-Bedingungen bleiben getrennt und zwingend.

## Geänderte Dateien und Tests

Geändert wurden `ci/checks/protocol/check_protocol_evidence.py`, die zweisprachige
Testing-/Evidence-Dokumentation und dieser gepaarte Record. Zwei bestehende
Positivbeobachtungen in
`tests/protocol_client/test_check_protocol_evidence.py` und
`tests/no_crs/test_no_crs_baseline.py` erhalten nur bereits vom Produzenten
geschriebene Abschlussmetadaten für ihre bestehende HTTP403-Ablehnung.
Keine Testdefinition oder Assertion wurde ergänzt oder verändert; bestehende
Negativdaten bleiben unverändert.

## Befehle und Ergebnisse

Befehle verwenden RTK, Framework-eigenes Python3.14.4 und externe Temporär-/
Cache-Verzeichnisse. `<Framework-python>` bezeichnet den konfigurierten
Framework-Interpreter; `<task-evidence>` bezeichnet externe laufbezogene
Evidence, keinen Source-Pfad.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk bypass make test-protocol-client PYTHON=<Framework-python>` vor Implementierung | 0 | 31 bestehende Tests bestanden | Externer Befehlsnachweis |
| Bestehende Protokoll- und vier No-CRS-Prüfungen vor Positivdatenpflege | 2 / 1 | Alte Positivbeobachtungen wegen fehlender Abschlussdaten abgewiesen | `<task-evidence>/protocol-client.log`, `<task-evidence>/no-crs-protocol.log` |
| `rtk bypass <Framework-python> -m unittest` mit vier bestehenden No-CRS-Protokollmethoden | 0 | Vier bestehende Prüfungen bestanden | `<task-evidence>/no-crs-protocol-final.log` |
| `rtk bypass <Framework-python> -m py_compile` für drei geänderte Python-Dateien | 0 | Kompilierung bestanden | Externer Befehlsnachweis |
| `rtk bypass make test-protocol-client check-documentation PYTHON=<Framework-python>` nach strikter Primärkorrektur | 0 | 31 bestehende Tests, Links, zweisprachige/Pfadprüfungen und Change Records bestanden | `<task-evidence>/final-local-checks.log` |
| Vier bestehende No-CRS-Protokollmethoden nach strikter Primärkorrektur | 0 | Vier bestanden | `<task-evidence>/no-crs-protocol-strict-final.log` |
| `rtk bypass git diff --check` | 0 | Keine Whitespace-Fehler | Externer Befehlsnachweis |

Ein unabhängiger read-only Source-/Kompatibilitätsreview fand keinen Blocker.
Hosted CI/Sonar und Auslieferungsergebnisse bleiben im Draft-PR revisionsgebunden.

## Sicherheitsauswirkung

Stärkt die Evidence-Integrität, ohne Authentifizierung, Isolation, Quality Gates
oder Scanner-Einstellungen zu ändern. Dies ist eine Konsistenzkorrektur,
keine authentifizierte Attestierung und kein behaupteter Connector-Sicherheits-
befund. Gemäß aktueller Nutzervorgabe wurden keine neuen negativen
Regressionsfälle geschrieben; Source-Review und bestehende Prüfungen sind die
verfügbaren Nachweisebenen.

## Dokumentation und Runtime-Evidenz

Das EN/DE-Paar `docs/testing-and-evidence` erklärt Transferabschlüsse,
HTTP-Ablehnungskompatibilität und Abschlusssemantik ohne bekannte Inhaltslänge.
Keine Live-Host-, HTTP2-/HTTP3-Transport- oder Connector-Lifecycle-Qualifikation
wurde erhoben.

## Nicht ausgeführte Prüfungen

Keine neuen Tests, vollständige Runtime-Matrix, nativen Connector-Builds,
Dependency-Audits oder neue Coverage-Kampagne. Die fokussierten bestehenden
Prüfungen entsprechen dem Umfang dieses Python-Prüfers. Hosted CI/Sonar
benötigen eine veröffentlichte Revision und werden getrennt berichtet.
Das optionale lokale Gitleaks-Programm ist nicht verfügbar und wurde nicht
installiert. Der begrenzte Source-/Dokumentationsdiff wurde manuell auf neu
hinzugefügte Secrets geprüft.

## Einschränkungen und Restrisiko

Konsistente externe Beobachtungen werden dadurch nicht authentifiziert.
Bestehende Run-/Case-/Transaktions-/Stream- und Prüfsummenbindung bleibt nötig.
Der Parent behält seinen Framework-Pin bis zu einer separat autorisierten
Integration. Der übergeordnete Protokollparitäts-Workstream bleibt offen.

## Finaler Diff- und Review-Status

Nur aufgabeneigener Framework-Arbeitsbaum; keine Hauptcheckout-Änderung, kein
Merge, History-Rewrite, Default-Branch-Push oder Parent-Gitlink-Update.
Finaler begrenzter Diff, Whitespace-Prüfung, unabhängiger Review und
revisionsgebundene Auslieferung werden vor Übergabe extern dokumentiert.
