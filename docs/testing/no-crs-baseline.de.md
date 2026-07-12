# Kanonische No-CRS-Baseline für alle Connectoren

**Sprache:** [English](no-crs-baseline.md) | Deutsch

Status: Framework-Vertrag umgesetzt; Connector-Fähigkeiten bleiben von realer Evidence abhängig.

Das Framework besitzt den connector-neutralen Katalog, deterministische lokale
Regeln, Capability-Auswahl, Evidence-Normalisierung, Validierung und die reine
Ergebnis-Zusammenfassung. Das Connector-Repository besitzt weiterhin
Host-Build, Host-Konfiguration, Lifecycle-Steuerung, Request-Ausführung und rohe
Host-Evidence.

## Kanonische Verträge

- Evidence-Stufen: `source_contract`, `compile`, `link`, `config_load`,
  `start_smoke`, `minimal_runtime_smoke`, `no_crs_baseline`, `crs_smoke` und
  `extended_matrix`.
- Capability-Quelle: `connectors/<name>/capabilities.json`.
- Katalog: `tests/cases/no-crs-baseline/catalog.json`.
- Wiederverwendbare HTTP-Fälle: `tests/cases/no-crs-baseline/*.yaml`; bei der
  Auswahl über das alte `case_cli.py` muss `NO_CRS_BASELINE=1` gesetzt sein.
  Acht Katalogeinträge haben derzeit direkte YAML-Runner-Zuordnungen: Allow,
  Deny, alternativer Status, Transaction-ID, gepufferter Request-Body,
  gepufferter Response-Body, Log-only und Redirect. Der Phase-3-Probe bleibt
  plan-only, bis der gemeinsame Harness den kanonischen Upstream-Response-Header
  injizieren kann.
- Regeln: `tests/rules/no-crs-baseline.conf`. Regel `1100001` ist der native
  Kern-Probevertrag: `X-Modsec-Smoke: block` wird in Phase 1 mit HTTP 403
  abgewiesen.
- Schemata: `tests/schemas/no-crs-baseline/`.
- Artefaktlayout: `$EVIDENCE_ROOT/<connector>/<run-id>/` mit `manifest.json`,
  `result.json`, `results.jsonl`, optional `events.jsonl` sowie `logs/`,
  `config/` und `inventory/`.

Die kanonischen Fallstatus sind `PASS`, `FAIL`, `BLOCKED`, `UNSUPPORTED`,
`NOT_APPLICABLE` und `NOT_EXECUTED`. Nicht unterstützte oder nicht ausgeführte
Fälle erhöhen niemals die PASS-Anzahl. Exit 77 gilt ausschließlich für einen
Prerequisite-Blocker vor Beginn der Host-Ausführung.

## Full-Lifecycle-No-CRS-Vertrag

Der gleiche Katalog enthält nun eine Full-Lifecycle-Grundlage für Phase 1 bis
4. Er ergänzt 45 capability-gesteuerte Katalogeinträge (insgesamt 104), ohne
einen zweiten Runner oder ein zweites Evidence-Modell einzuführen. Die
deklarativen Fixtures liegen unter
`tests/cases/no-crs-baseline/full-lifecycle/`; Dateien für den
Content-Type-Scope liegen unter `tests/fixtures/no-crs-baseline/`.

Diese Fixtures verwenden bewusst `status: future` und
`not_executed_until_real_host`. Sie sind Inventar beziehungsweise Verträge für
einen connector-eigenen Host-Driver, keine synthetische Runtime-Evidence und
keine direkten `runner_case`-Zuordnungen. Jeder Katalogeintrag verlangt zudem
einen echten Host und verbietet synthetische PASS-Evidence.

Der Katalog deckt ab:

- Phase 1 Allow, Deny, alternativen Status, Redirect und Transaction-ID;
- Phase 2 Request-Body-Regel, einen über zwei Chunks geteilten Marker,
  exakt-am-Limit/über-Limit- und ProcessPartial-Metadaten sowie payloadfreie
  Events;
- Phase 3 Response-Header-Deny/Redirect vor dem Commit sowie Metadaten für
  originalen und sichtbaren Status;
- Phase 4 inkrementelle Ingestion, explizite End-of-Stream-Auswertung,
  Pre-Commit-Deny soweit vom Host unterstützt sowie getrennte
  Late-Intervention-Ergebnisse für `minimal`, `safe` und `strict`;
- Content-Type-Fälle innerhalb und außerhalb des Scope, mit Charset, ohne
  Content-Type sowie ungültige und Wildcard-Scope-Dateien;
- einen synchronisierten First-Byte-Nachweis: Der Upstream pausiert nach dem
  ersten Chunk, der Client muss diesen vor der Freigabe erhalten, erst dann
  folgt der spätere Marker;
- HTTP/1.1 Content-Length und Chunked, Keep-Alive, sequenzielle und parallele
  Requests, HTTP/2 sofern verfügbar sowie Client-/Upstream-Abbrüche;
- Request-/Response-Body-Limits und begrenzte, payloadfreie Event-Metadaten.

`response_body_incremental_ingest` bedeutet, dass Chunks die Engine ohne
connector-eigene Full-Response-Pufferung erreichen. Es bedeutet nicht
per-Chunk-Regelauswertung: `phase4_end_of_stream_evaluation` beschreibt
ausdrücklich das zulässige End-of-Stream-Auswertungsmodell.
`no_full_response_buffering` und `first_byte_before_response_end` können nur
mit einem kanonischen Event PASS werden, das beweist, dass der erste Client-Byte
ankam, während der Upstream noch nicht beendet war; ein Timeout oder eine
behauptete Dauer allein reicht nicht.

Das kanonische Metadatenvokabular bleibt absichtlich flach und payloadfrei. Es
ergänzt Late-Intervention-Modus, Content-Type-Scope, Limit-Ergebnis,
Chunk-/End-of-Stream-Flags, First-Byte-/Barrier-Status,
Protokoll/Transfer-Encoding, Connection-Reuse sowie Client-/Upstream-Abbruch.
Response- oder Request-Text, Match-Werte oder Intervention-Log-Inhalte werden
niemals akzeptiert.

Zur Kompatibilität mit dem begrenzten Common-JSON-Writer akzeptiert das
Event-Schema auch dessen feste Metadatenfelder: Zeitstempel/Level, Message- und
Entscheidungsmetadaten, HTTP-Reason-Text, Methode/URI/Client-IP,
`response_started`, `body_truncated`, `redacted` sowie Sequence-/Hash-Zähler.
Diese Felder bleiben in `events.jsonl`; Case-Result- und Result-Projektionen
übernehmen nur den geprüften Entscheidungs- und Lifecycle-Zustand. Ein
Connector-Normalizer muss potenziell sensible Freitexte oder
anfrageidentifizierende Werte vor dem Schreiben eines Events redigieren; die
Sperren für Payloads, Match-Werte, Secrets und verschachtelte Werte gelten
weiterhin.
Beim Einlesen werden Common-Lifecycle-Labels auf die Framework-Regelphasen
normalisiert: `connection` → 0, `uri`/`request_headers` → 1,
`request_body` → 2, `response_headers` → 3, `response_body` → 4 und
`logging` → 5. Unbekannte Phasenwerte werden verworfen, statt stillschweigend
als Evidence zu gelten.

### Opt-in-Artefaktprofil für den Full-Lifecycle-Lauf

Das Standardprofil `generic` erhält das oben beschriebene Legacy-Layout:
`events.jsonl` und die drei Host-Logs bleiben optional. Ein connector-eigener
Driver, der die Full-Lifecycle-Fälle des Katalogs tatsächlich ausführt, muss
für `select` und `init` `--artifact-profile full_lifecycle` setzen (oder für
die Make-Targets `NO_CRS_ARTIFACT_PROFILE=full_lifecycle`). Das Profil ist nur
für die Stufe `no_crs_baseline` gültig und wird in Plan, Inventar, Manifest und
Ergebnis festgehalten.

Für dieses Profil verlangt `finalize` host-erzeugte Eingaben für
`--source-events`, `--stdout-log`, `--stderr-log` und `--host-log`. Danach
verlangt es die folgenden produzierten Artefakte: `manifest.json`,
`result.json`, `results.jsonl`, `events.jsonl`, `inventory/run.json`,
`logs/stdout.log`, `logs/stderr.log` und `logs/host.log`. Leere reguläre
Dateien sind bei einem nicht eindeutigen oder fehlgeschlagenen Host-Lauf
zulässige Evidence, fehlende Eingaben werden jedoch verworfen statt erzeugt.
Das Profil stellt vollständige Nachvollziehbarkeit her; es macht weder ein
Future-Fixture zu ausgeführter Evidence noch erteilt es selbstständig PASS.

## Writer- und Validator-Ablauf

```sh
python3 ci/checks/catalog/no_crs_baseline.py select \
  --connector envoy \
  --capabilities "$CONNECTOR_ROOT/connectors/envoy/capabilities.json" \
  --output "$RUN_DIR/plan.json"

python3 ci/checks/catalog/no_crs_baseline.py init \
  --connector envoy \
  --capabilities "$CONNECTOR_ROOT/connectors/envoy/capabilities.json" \
  --plan "$RUN_DIR/plan.json" \
  --run-dir "$RUN_DIR" \
  --run-id "$RUN_ID" \
  --connector-root "$CONNECTOR_ROOT"

# Hier den echten Host ausführen und danach nur beobachtete Artefakte normalisieren.
python3 ci/checks/catalog/no_crs_baseline.py finalize \
  --run-dir "$RUN_DIR" \
  --capabilities "$CONNECTOR_ROOT/connectors/envoy/capabilities.json" \
  --source-result "$RAW_RESULT" \
  --source-events "$CANONICAL_EVENTS" \
  --stdout-log "$STDOUT_LOG" \
  --stderr-log "$STDERR_LOG" \
  --stage-rc "$HOST_RC" \
  --host-version "$HOST_VERSION" \
  --libmodsecurity-version "$LIBMODSECURITY_VERSION"

python3 ci/checks/catalog/no_crs_baseline.py validate \
  --evidence-root "$RUN_DIR" \
  --connector envoy \
  --capabilities "$CONNECTOR_ROOT/connectors/envoy/capabilities.json" \
  --check all
```

`finalize` akzeptiert außerdem wiederholbare Argumente
`--source-results-jsonl`, `--source-summary`, `--source-result` und
`--source-log NAME=PATH`. Ein Exitcode null erzeugt keinen PASS. Ein 403-Deny
wird nur mit der zusätzlich beobachteten Regel-ID `1100001` zu PASS; erwartete
Event-Felder verlangen ein tatsächlich beobachtetes Event.
`--source-events` akzeptiert ausschließlich normalisierte, flache kanonische
Metadata-JSONL; host-spezifische rohe Event-Logs müssen zuerst einen
connector-eigenen Normalizer durchlaufen. Zulässig sind Connector-,
Transaction- und Regel-ID, Phase, Status, HTTP-Status, Truncation,
Content-Type sowie geprüfte Body-Größen-/Hash-Metadaten. Unbekannte Felder,
verschachtelte Werte, doppelte JSON-Schlüssel sowie Payload- oder
Credential-Felder werden verworfen, bevor kanonische Evidence geschrieben wird.
`minimal_runtime_smoke` darf nur PASS sein, wenn sein Regel-`1100001`-Event
`connector`, `transaction_id`, `rule_id`, `phase` und `status` enthält, der
Event-Stream keine Body-Nutzlast enthält und konkrete Host- sowie
libModSecurity-Versionen erfasst sind. Das Inventar führt dieselbe
`evidence_stage` und dasselbe `ruleset` wie Manifest und Ergebnis; der Validator
verwirft Abweichungen.

Die einzelnen Validatornamen sind `schema`, `completeness`, `capability`,
`claim-policy`, `layout`, `body-payload` und `status`.

`select` und `init` akzeptieren außerdem
`--evidence-stage minimal_runtime_smoke`. Dieser Modus wählt nur die beiden
Allow-/Deny-Kernfälle, schreibt aber dasselbe Schema und Artefaktlayout. `init`
verlangt ein frisches Laufverzeichnis, kopiert und hasht das Capability-Manifest,
prüft einen extern erzeugten Plan gegen eine frische Auswahl und verbietet
Symlinks im Laufpfad. Alle kanonischen Writes und Artefaktkopien sind atomar und
No-Follow; der Layout-Validator verwirft jeden Symlink und jede nicht im
Manifest deklarierte Datei.

Der kanonische Writer schreibt derzeit `minimal_runtime_smoke` und
`no_crs_baseline`. Separate Current-Run-Artefaktwriter für `compile`, `link`,
`config_load` und `start_smoke` bleiben eine ausdrücklich ausgewiesene Lücke;
Stage-Deklarationen im Capability-Manifest gelten allein nicht als
Ausführungs-Evidence.

## Summary-Richtlinie

`summarize` liest ausschließlich kanonische `result.json`-Dateien der
Connectoren. Fehlende Dateien werden `NOT_EXECUTED`; bei mehreren Läufen ist
`--run-id` Pflicht. Mit `--reports-dir` erzeugt der Befehl die bilingualen
gemeinsamen und connector-spezifischen Berichte. Diese Berichte behaupten
bewusst keine CRS-, Production-Readiness-, Security-, Full-Matrix- oder
allgemeine Response-Body-Verifikation.
