# Change Record

**Sprache:** [English](20261008-27-nginx-native-fact-contract.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261008-27-nginx-native-fact-contract |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | `160079c7d4fdccb32371fa2fb8871a1be1ee8125` |
| Issue oder Pull Request | Koordinator-eigene NGINX-All-required-Integration; kein neuer PR |

## Motivation und Problemstellung

Katalogerwartungen wie Connection-Reuse, MIME-Scope oder Split/EOS-Auswertung sind keine Common-Event-Schlüssel. Canonical-Consumer benötigen transparente Mappings aus tatsächlich authentifizierter Operationsevidenz statt aufgefüllter Erwartungsfelder oder synthetischer Events.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur neuer Framework-Faktenvertrag, fokussierte Tests und dieses Record-Paar. Quellen-/Run-Autorität und Authentifizierung unverändert aufbewahrter Originaldateien verbleiben beim strikten Bundle-Reader. Zentraler Normalizer, generische Validatoren, Schemas, Katalog, Parent-Source, MRTS und Gitlinks gehören nicht zu diesem Slice.

## Akzeptanzkriterien

Exakt42 deklarierte native Operationen erkennen, ohne Required-Scope zu verkleinern. Alle echten selektierten nativen Event-Schlüssel erhalten und LOGGING-Cleanup trennen. Native Mappings an unveränderte JSONL-Originalzeilen binden, Host-Mappings an versiegelte Receipts, originales Observation-JSON oder rohe H1-Wirebytes. Fehlende oder widersprüchliche Phase-, Rule-, Status- und Erwartungsfeldevidenz ablehnen. Kein status, canonical_status oder PASS zurückgeben.

## Untersuchte Alternativen

Erwartungsnamen in observed_event_fields zu kopieren, erfindet Evidenz. Access-Log-HTTP200 oder Cleanup-Allow als Request-Header-Event zu behandeln, vermischt Producer- und Lifecycle-Grenzen. Ein generischer Validator-Bypass ersetzt keine Integration.

## Implementierungsentscheidung

`derive_native_operation_contract(case, strict_reader_proof)` ruft den bestehenden Faktenprojektor auf. Zusätzlich zu dessen echten Fakten liefert es observed_rule_ids, mapped_evidence_fields, feldbezogene mapped_evidence_origins, native_event_origins, native_cause, semanticValues und semantic_evidence_origins. Native Event-Felder bleiben unverändert. Mapping-Ursprünge nennen echte Invocation, Originalartefakt-SHA256 und Source-Pointer; native Ursprünge zusätzlich Originalzeilen-Digest/-Index, Event-Index und TX.

Die geschlossene Case-Result-Tabelle beschreibt nur Operationssemantik nach Reader-Proof und tatsächlichen Mapping-Prüfungen. Engine-Limits werden aus nativen gelieferten/aufbewahrten Längen und echten rules.conf-Direktiven abgeleitet. MIME-Scope nutzt echten Content-Type und Engine-Retention. H1-Framing nutzt originale Downstream-Bytes. Connection-Reuse nutzt echte native Access-Zähler. Phase1-Keepalive-Client-Completion/EOS bleibt ausdrücklich ein separates Host-Mapping; native Prä-Send-EOS-/Transport-Felder behalten ihre Originalwerte. Write-Result nutzt geschlossene payloadfreie Fault-/Resume-Ledger. Rule-, Event-, Message- und Phase-Mappings dürfen nicht aus Host-Metadaten stammen.

Native Ursache und sichtbarer HTTP-Status bleiben getrennt. Prä-Connector-H1-Ablehnung erhält keinen erfundenen Engine-Event/TX. Fehlende echte Request-Header-Completion bleibt ein Fehler. Eine tatsächliche request_headers_complete-Zeile benötigt das exakte Source-förmige Completion-Tupel und reason native_return=1;common_completed=1. Cleanup bleibt LOGGING statt Phase1-Allow. Dependencies enthalten den genehmigten rein nativen Clean-Shutdown-HTTP200-Override des Koordinators (`c9e9b3fd246ded97040dc1253e530934b8e4bf71`), der generischen Status0 erhält, sowie die Korrektur des tatsächlich serialisierten Common-Vokabulars (`9f3f95d2f30be37799ad2bf654253bfa847c7783`): Request-Deny vor Host-Send heißt engine_decision/MSCONN_EVENT_ENGINE_DECISION; Event-Boundary-Callbacks heißen rule_match/allow. Source-Struct-Namen werden nicht als serialisierte Schlüssel erfunden.

## Geänderte Dateien und Tests

`tests/runners/nginx_native_operation_contract.py`, `tests/no_crs/test_nginx_native_operation_contract.py` und dieses EN/DE-Paar. Kontrollierte Fixtures prüfen strikten Pointer-Reader-Proof, alle12 Phase4-/MIME-Operationen, Originalzeilenbindung, fehlende/fremde/mutierte Fakten, Event-/Cleanup-Scope, Erwartungsresultat/-feld-Widersprüche, Statusunterscheidung, H1-Framing, Connection-Zähler und exakte P1-Completion. Der bestehende leichte Safe-Mode-Fixture lässt original_http_status/headers_sent weg: Diese Lücke wird ausdrücklich abgelehnt, bevor ein separater Unit-Fixture Source-zugewiesene Felder ergänzt. Kein Fixture ist Runtime-Evidenz.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk proxy env PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 python -m unittest tests.no_crs.test_nginx_native_operation_contract -v` | 1 | Initiales RED: neues Modul fehlt | Kontrollierter Unit-Aufruf |
| `rtk proxy env TMPDIR=<external-task-runs> PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 python -m unittest tests.no_crs.test_nginx_native_operation_contract -v` | 0 | 12 fokussierte Tests; Framework-eigener Interpreter | Kontrollierter Unit-Aufruf |
| `rtk proxy env TMPDIR=<external-task-runs> PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 python -m unittest tests.no_crs.test_nginx_native_operation_contract tests.no_crs.test_nginx_native_operation_projection tests.no_crs.test_nginx_native_operation_bundle -v` | 0 | 46 Tests nach beiden Koordinator-Korrekturen; nach finalem Client-EOS-Mapping wiederholt | Kontrollierter Unit-Aufruf |
| `rtk proxy env TMPDIR=<external-task-runs> PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 make test-no-crs-contract PYTHON=<framework-python> BUILD_ROOT=<external-build-root>` | 0 | 342 Tests nach Dependency-Korrekturen, vor letzter fokussierter Client-EOS-Verfeinerung | Task-Analyse: stream-a-native-fact-contract-final.log |
| `rtk proxy env PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 make check-documentation PYTHON=<framework-python>` | 0 | Links, zweisprachige Variablen, Pfade und Record-Vertrag | Framework-Dokumentationsprüfungen |
| `rtk proxy git diff --check` | 0 | Keine Whitespace-Fehler | Eigener Worktree |

## Sicherheitsauswirkung

Keine Produkt-Security-Remediation oder Authentifizierungsänderung. Das Seam stärkt Evidenztrennung: Native Felder dürfen nicht aus Erwartungen erfunden werden, LOGGING darf Phase1 nicht imitieren und Host-Mappings benötigen originale authentifizierte Observations. Ein Dictionary mit layer_verified ist keine Authentifizierung; Caller müssen den strikten Reader mit expliziter Autorität vorher aufrufen und Originalbytes offline erneut prüfen.

## Dokumentation und Runtime-Evidenz

Gepaartes englisches/deutsches Record. Alle Prüfungen verwenden kontrollierte Fixtures. Kein aktueller nativer Runtime-, Build-, vollständiger E2E- oder All-required-PASS-Claim. Die ursprüngliche97-Required-Selektion bleibt Koordinator-eigen und unverändert.

## Nicht ausgeführte Prüfungen

Keine native Runtime/Build/vollständige E2E: Serialisierter Koordinator-Slot und integriertes Modul sind Voraussetzungen. Ruff nicht verfügbar; keine Toolinstallation oder Remote-Analyse durchgeführt.

## Einschränkungen und Restrisiko

Unbewiesene Erwartungsfelder scheitern auch bei erkanntem Pfad geschlossen. Root-Integration muss strikte Quellenautorität, exakte Offline-Neuableitung und zentrale Canonical-Policy erhalten. Immutable projizierte Deskriptoren benötigen bewusstes Kopieren zur Serialisierung. Host-H1-Fakten beweisen kein H2-/H3-Verhalten.

## Finaler Diff- und Review-Status

Nur vier neue eigene Dateien. Dependency-Commits sind bestehende Koordinator-Arbeit, nicht Teil dieser Lieferung. Staged-Diff, Originalbyte-Grenzen und Whitespace geprüft; keine zentralen/Source-/Gitlink-Änderungen. Breitere Validierung und letzter fokussierter Lauf bestanden; normaler begrenzter Commit geht an den Koordinator.
