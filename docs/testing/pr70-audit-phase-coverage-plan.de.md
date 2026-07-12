# PR #70 Prüfungsphasen-Abdeckungsplan

**Sprache:** [English](pr70-audit-phase-coverage-plan.md) | Deutsch

Status: teilweise umgesetzt

In diesem Dokument wird aufgezeichnet, wie Upstream-ModSecurity-Apache PR #70 zugeordnet werden sollte
in dieses externe Test-Framework einbinden. Es handelt sich lediglich um einen lokalen Rahmenplan. Das tut es
Connector-Quelle, Apache oder NGINX Laufzeitsemantik, Submodul nicht ändern
Referenzen oder RESPONSE_BODY Promotion-Status.

Upstream PR: https://github.com/owasp-modsecurity/ModSecurity-apache/pull/70

Beobachtet PR Kopf: `73c4ae80743810d866771dd4183be2bea44947dd`

## Upstream PR Zusammenfassung

PR #70 ist eine Apache::Test-Harnessänderung mit dem Titel „Überwachungsprotokoll aktivieren und hinzufügen
00-Phasen-Tests". Der Pull-Request-Body beschreibt dies als Stufe 1 der Konvertierung
Automatisierte Tests für den libmodsecurity-Apache-Connector mit zwei Zielen:

- Ermöglichen Sie die Prüfung des Audit-Protokolls in automatisierten Tests
- Fügen Sie die erste Charge automatisierter Tests hinzu, insbesondere die Fünf-Phasen-Tests

Der PR ändert neun Dateien:

| Pfad | vorgelagerte Rolle | Rahmenbeschluss |
| --- | --- | --- |
| `Makefile.am` | Fügt einen `-postamble` hinzu, der `SecAuditEngine On` für Apache::Test aktiviert. | Nicht kopieren. Das externe Framework behält Prüfanweisungen im YAML-Fall `rules` mit fallspezifischen Protokollplatzhaltern bei. |
| `t/00-phases.t` | Fügt fünf Perl-Tests hinzu, die das Apache-Überwachungsprotokoll nach jeder Anfrage überprüfen. | Ordnen Sie das Verhalten nur YAML zu, nachdem stabile konnektorneutrale Behauptungen definiert wurden. |
| `t/conf/extra.conf.in` | Fügt globale Anweisungen für serielle Prüfprotokolle und fünf Apache `<Location>`-Blöcke mit phasenspezifischen Regeln hinzu. | Nur als Quellenbeweis verwenden. Verschieben Sie die Apache `<Location>`-Konfiguration nicht in gemeinsame Fälle. |
| `t/find_string_in_file.pl` | Liest nur neu angehängte Audit-Log-Bytes und Regex-Matches mit erwarteten Zeichenfolgen. | Bevorzugen Sie den vorhandenen Python-Runner- und Normalizer-Pfad. |
| `t/htdocs/00-phases/00-phases_01.html` | Statische Reaktionsvorrichtung für Phase 1. | Verwenden Sie YAML `response.body`, wenn ein abgeleiteter Fall Fixture-Inhalt benötigt. |
| `t/htdocs/00-phases/00-phases_02.html` | Statische Reaktionsvorrichtung für Phase 2. | Das Gleiche wie oben. |
| `t/htdocs/00-phases/00-phases_03.html` | Statische Reaktionsvorrichtung für Phase 3. | Das Gleiche wie oben. |
| `t/htdocs/00-phases/00-phases_04.html` | Statische Reaktionsvorrichtung für Phase 4. | Nicht als verifizierter RESPONSE_BODY-Nachweis verwenden. |
| `t/htdocs/00-phases/00-phases_05.html` | Statische Reaktionsvorrichtung für Phase 5. | Behalten Sie Phase 5 als reine Planphase bei, bis das Framework über explizite Fähigkeiten und Assertionssemantik verfügt. |

Die Upstream-Audit-Konfiguration verwendet serielle Audit-Protokollierung und umfassende Audit-Teile:

```apache
SecAuditEngine On
SecAuditLog @ServerRoot@/logs/audit_logs.txt
SecAuditLogParts ABIJDEFHZ
```

Das externe Framework verwendet in YAML bereits die sicherere Einzelfallform:

```apache
SecAuditEngine RelevantOnly
SecAuditLogType Serial
SecAuditLogParts ABHZ
SecAuditLog "@@AUDIT_LOG@@"
SecAuditLogStorageDir "@@AUDIT_LOG_DIR@@"
```

Dieses bestehende Muster sollte der Standard für die tragbare Abdeckung bleiben, weil
Der Runner materialisiert pro Fall Protokollpfade und Assertionsprüfungen, die nur stabil sind
Teilzeichenfolgen.

## Vorhandener Framework-Status

Das aktuelle Framework verfügt bereits über die richtige Eigentumsgrenze:

- YAML Fälle leben unter `tests/cases/`.
- Python-Runner- und Materializer-Code befindet sich unter `tests/runners/`.
- Normalisierer leben unter `tests/normalizers/`.
- Es gibt keine aktiven Perl-`.t`-Laufzeittests im Framework-Fallkorpus.
- Die Laufzeitausführung von Apache und NGINX bleibt in Connector-fähigen Smoke-Skripten.
- Audit-Log-Fälle werden als YAML `expect.audit_log` Teilzeichenfolgenprüfungen ausgedrückt.

Relevanter bestehender Versicherungsschutz:

| Bereich | aktueller Stand |
| --- | --- |
| Phase 1 | Vorhandene active/imported YAML Fälle unter `tests/cases/phases/phase1/` und Request-Header-Fälle. |
| Phase 2 | Vorhandene active/imported YAML Fälle unter `tests/cases/phases/phase2/`, einschließlich Abfrageargumente und Anforderungstext. |
| Phase 3 | Vorhandene Response-Header-YAML-Fälle unter `tests/cases/response/headers/`; Viele Randfälle bleiben ehemalige erwartete Fehlschläge. |
| Phase 4 | Vorhandene Response-Body-YAML-Probes sind nur ehemalige Expected-Failure-, Future-, Connector-Gap-, Experimental- oder Pass-Through-Probes. RESPONSE_BODY bleibt nicht verifiziert und nicht hochgestuft. |
| Phase 5 | Für `phase5` existiert noch keine Framework-Fähigkeit; Keine aktiven YAML-Fälle verwenden `phase:5`. |
| Audit-Protokoll | Vorhandene serielle Audit-Log-YAML-Fälle unter `tests/cases/audit-log/`; Stabile Prüfungen basieren auf Teilzeichenfolgen. |
| Anfragetext | Vorhandene active/imported roher Anforderungstext, JSON, XML, mehrteilige und URL-codierte Fälle. |
| Antwortkörper | Nur vorhandene Pass-Through- und frühere Expected-Failure-Probes; Keine verifizierte Sperraktion. |

Der Audit-Normalisierer ist absichtlich skelettartig. Es normalisiert Zeitstempel, PIDs,
Thread-IDs, Localhost-Ports und Transaktions-IDs, analysiert die Prüfung jedoch nicht
Abschnitte, kanonisieren Sie die Header-Reihenfolge oder gleichen Sie Apache/NGINX Audit-Format ab
Unterschiede. Ein umfassender Audit-Log-Vergleich muss aufgeschoben werden, bis dieser existiert.

## Plan importieren

### Minimale erste 00-Phasen-Gruppe

Erstellen Sie erst nach der Laufzeit eine kleine, von der Quelle abgeleitete `00-phases`-Gruppe
Erwartungen können mit vorhandenen stabilen Feldern ausgedrückt werden:

| Phase | anfängliches Ziel | erwartete Klassifizierung |
| --- | --- | --- |
| Phase 1 | Anforderungszeilen- oder Anforderungsheader-Regel. Das Prüfprotokoll sollte die Phase-1-Regelnachricht enthalten und keine Details zum Anforderungstext, Antwortheader oder Antworttext erfordern. | active/imported Kandidat nach Apache und NGINX bestanden. |
| Phase 2 | URL-codierter Anforderungstext oder ARGS-Regel unter Verwendung der vorhandenen `request_body`- und `form_urlencoded`-Unterstützung. | active/imported Kandidat, wenn beide Konnektoren bereits den vorhandenen Smoke-Pfad des Anforderungskörpers passieren. |
| Phase 3 | Grundlegende `RESPONSE_HEADERS`-Regel gegen einen stabil ausgegebenen Header. | nur aktiv bleiben, wenn bestehende `response_header_basic` stabil bleiben; sonst ehemalige expected-failure/runtime-difference. |
| Phase 4 | `RESPONSE_BODY` Nur Nachweise. | früherer erwarteter Fehler, nur zugeordnet, Verbindungslücke oder zurückgestellt. RESPONSE_BODY nicht bewerben. |
| Phase 5 | Beobachtung in der Protokollierungsphase. | Nur planbar, bis `phase5` als bekannte Funktion hinzugefügt wird und der Runner über stabile Behauptungen verfügt. |

Die erste Implementierung sollte die Upstream-Perl-Datei nicht kopieren. Es sollte hinzufügen
kleine YAML Fälle oder Vorrichtungen unter `tests/cases/` nur dort, wo das bestehende Schema
kann die Anfrage, Antwortvorrichtung, Regeln und erwartete Artefakte ausdrücken.

### Audit-Log-Behauptungen

Verwenden Sie fallbezogene Überwachungsprotokolldateien anstelle eines gemeinsam genutzten angehängten Protokolls:

- Behalten Sie `SecAuditEngine RelevantOnly` für blocking/auditlog-Prüfungen bei, es sei denn a
  Im Einzelfall sind `On` erforderlich.
- `SecAuditLogType Serial` behalten.
- Bevorzugen Sie `SecAuditLogParts ABHZ` für stabile Prüfungen.
- Schreiben Sie Protokolle über `@@AUDIT_LOG@@` und `@@AUDIT_LOG_DIR@@`.
- Behaupten Sie nur stabile Teilzeichenfolgen wie Regel-ID, Anforderung URI und Nachricht.
- Vermeiden Sie die Geltendmachung vollständiger Prüfabschnitte, Zeitstempel, Transaktions-IDs und Dynamik
  Pfade, Server-Banner, lokale Ports oder Header-Reihenfolge.

Jedem umfassenden Prüfungsvergleich sollte eine zusätzliche Normalisierungsarbeit vorausgehen:

- Abschnittsbewusster serieller Audit-Parser
- Transaktions-ID-Ersatz für alle beobachteten Formate
- absoluter Pfadersatz für generierte Laufzeitwurzeln
- Apache/NGINX Header-Reihenfolge und Groß-/Kleinschreibungsrichtlinie
- Konnektorspezifische Formatierung wird außerhalb allgemeiner Behauptungen behandelt

### Connector-Matrix

| Connector | Phase 1 | Phase 2 | Phase 3 | Phase 4 | Phase 5 | Audit-Protokoll |
| --- | --- | --- | --- | --- | --- | --- |
| Apache | Erwarteter Durchgang nach der von der Quelle errichteten Smokedichtigkeit | erwarteter Erfolg, bei dem die Unterstützung des Anforderungstexts bereits nachgewiesen ist | erwarteter Pass nur für stabiles Kopfballspiel | deferred/former erwarteter Fehler, bis RESPONSE_BODY Blockierung nachgewiesen ist | aufgeschoben | erwarteter Erfolg nur für stabile serielle Teilzeichenfolgen |
| NGINX | Erwarteter Durchgang nach der von der Quelle errichteten Smokedichtigkeit | erwarteter Erfolg, bei dem die Unterstützung des Anforderungstexts bereits nachgewiesen ist | erwarteter Pass nur für stabiles Kopfballspiel | hängt vom bestehenden NGINX Phase-4-Fähigkeitsstatus ab; Log-Only-Nachweise sind keine RESPONSE_BODY-Hochstufung | aufgeschoben | erwarteter Erfolg nur für stabile serielle Teilzeichenfolgen |

Die Matrix ist evidenzbasiert. Generierte Berichte und YAML-Metadaten gelten nicht
Fördern Sie frühere Fälle mit erwartetem Fehler, nur zugeordneten Fällen, zukünftigen Fällen, Connector-Gap-Fällen oder RESPONSE_BODY-Fällen.

## Nicht-Ziele

- `<workspace>/ModSecurity-conector` nicht aktualisieren.
- Aktualisieren Sie keine Submodule oder Connector-Quellenverweise.
- Ändern Sie die Apache- oder NGINX-Laufzeitkonfiguration nicht global.
- Kopieren Sie keine Apache::Test Perl-`.t`-Dateien in den gemeinsamen Laufzeitpfad.
- Fügen Sie keine breite CRS-Regressionsabdeckung hinzu.
- Stellen Sie keine vollständige Audit-Log-Gleichheit sicher, bevor Normalizer-Unterstützung vorhanden ist.
- Fördern Sie nicht RESPONSE_BODY oder Phase-4-Blockierung basierend auf PR #70.

## Sicherer nächster Schritt

Die erste aus der Quelle abgeleitete YAML-Gruppe wird unter implementiert
`tests/cases/audit-log/pr70-phases/`:

| Fall | Phase | Status | Absicht |
| --- | --- | --- | --- |
| `pr70_phase1_audit_request_header` | 1 | importiert | Anforderungsheader-Phase-1-Regel plus stabile serielle Prüfteilzeichenfolgen |
| `pr70_phase2_audit_urlencoded_body` | 2 | importiert | URL-codierte request-body/ARGS Phase-2-Regel plus stabile serielle Audit-Teilzeichenfolgen |
| `pr70_phase3_audit_response_header` | 3 | importiert | Statische Datei-Antwort-Header-Phase-3-Regel plus stabile serielle Audit-Teilzeichenfolgen |
| `pr70_phase4_response_body_audit_xfail` | 4 | importiert | RESPONSE_BODY Audit-Sonde wurde weiterhin nicht hochgestuft; Der frühere Verlauf erwarteter Fehler besteht nur aus Metadaten |

Phase 5 bleibt zurückgestellt, da das Framework noch keinen `phase5` hat.
Fähigkeit oder ein stabiles Protokollierungsphasen-Assertionsmodell.
