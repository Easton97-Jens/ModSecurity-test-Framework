# Composite-Lifecycle-Evidence-Verifier

**Sprache:** [English](README.md) | Deutsch

`verify_matrix_evidence.py` prüft einen isolierten Lifecycle-Fall anhand des
rohen JSONL-Observer-Outputs des Composite-Coordinators. Das Werkzeug
transformiert oder synthetisiert keine Events und korreliert Fälle niemals über
Request-ID, URI, Adresse, Ankunftsreihenfolge oder Zeit.

```text
python3 connectors/composite_harness/verify_matrix_evidence.py CASE.manifest.json --json
# Runner-pinned invocation:
python3 connectors/composite_harness/verify_matrix_evidence.py CASE.manifest.json \
  --expected-event-log /absolute/path/case-001.events.jsonl --json
```

Ein erfolgreicher Status ist absichtlich `LIFECYCLE_ONLY`, niemals `PASS`:
Case-Driver, Manifest, Beobachtungen und Raw-Log liegen in einer vertrauten
Operator-Grenze. Der Verifier kann daher nur begrenzte Metadaten und
Lifecycle-Konsistenz prüfen. Er kann weder die Ausführung einer Regel/eines
Katalogvektors, das Laden eines Templates durch einen realen Host noch einen
vom Client beobachteten Host-Reset/-Abort beweisen. Die JSON-Ausgabe setzt
`"scope": "lifecycle_only"` und `"catalog_acceptance": false`.

Manifest und Event-Log sind benachbarte reguläre Nicht-Symlink-Dateien. Jedes
Manifest beschreibt genau ein isoliertes Fallartefakt:

```json
{
  "schema": "msc-composite-evidence/v1",
  "connector": "envoy",
  "case": "p4_safe",
  "case_artifact": {"id": "case-001", "event_log": "case-001.events.jsonl"},
  "expected_phases": ["P1", "P2", "P3", "P4"],
  "client_observation": "client.observation.json",
  "upstream_observation": "upstream.observation.json",
  "cleanup": {"count": 1, "status": "completed"}
}
```

Die beiden Observation-Dateien sind separat erfasste, benachbarte reguläre
Nicht-Symlink-Dateien. Das Schema der Client-Datei besteht exakt aus
`lease_observed`, `visible_status`, `redirect_location_verified`, `p4_outcome`,
`p4_visible_status` und `p4_response_committed`; das Schema der Upstream-Datei exakt aus
`lease_observed`, `request_terminal` und `response_observed`. Jede Datei ist
begrenzt, weist doppelte Schlüssel zurück und enthält nur Metadaten. Das
Manifest referenziert nur ihre Basenames; inline Observation-Assertions sind
ungültig.

Das Event-Log ist das unveränderte rohe Observer-JSONL. Zulässige
Record-Felder sind exakt `decision_id`, `connector`, `rule_id`, `phase`,
`outcome`, `reason`, `requested_action`, `actual_host_action`,
`visible_status`, `cleanup_outcome`, `event_time`, `request_path`,
`response_path` und `transport`; optionale Felder dürfen genau wie vom
Go-Observer emittiert fehlen. `request_path`, `response_path` und `transport`
binden jeden Record an die statische Pipeline des Connectors. `phase`
akzeptiert die erforderlichen P1--P4-Records und die Lifecycle-Records
`reservation`, `lease`, `claim`, `request_host_action`, `host_action`,
`neutral_outcome` und `terminal`. Jeder Record muss denselben Connector und genau eine
servergenerierte Decision-ID im isolierten Log enthalten. Der Verifier verlangt
die P1--P4-Records des Falls genau einmal und in Reihenfolge sowie einen
finalen `terminal`-Record mit `cleanup_outcome` `closed`. Lifecycle-Records
dürfen zwischen den erforderlichen Phasen stehen; sie werden niemals zum
Verbinden von Fällen verwendet.

Der Command-Writer begrenzt jeden JSONL-Record auf 2.048 Byte, behält ein
normales 1-MiB-Fenster und verschiebt einen Reset, bis die aktiven
Decision-Lifecycles vollständig sind. Bei begrenzter paralleler Aktivität
erlaubt er eine feste 8-MiB-Hartgrenze; kann sie keinen vollständigen Lifecycle
bewahren, schlägt der Observer fail-closed fehl. Ein fehlgeschriebener oder
fortschrittsloser Teil-Write wird zurückgerollt. Beim Start entfernt er nur
eine fehlerhafte abschließende JSONL-Sequenz und ergänzt vor einer späteren
Rotation für jeden schema-validen, nach einem Absturz offenen Lifecycle einen
`terminal`-Record mit `reason` und `cleanup_outcome` `restart_recovery`. Jeder
aktive Lifecycle reserviert eine maximale Terminal-Zeile. Fehlt einem
owner-only, vor dieser Reservierungsregel geschriebenen Log bei oder unterhalb
der Hartgrenze dieser Recovery-Platz, setzt der Start dieses nicht
wiederherstellbare alte Fenster sicher zurück, weil ein neu gestarteter
Coordinator seine Transaktionen nicht fortsetzen kann; aktuelle Writes schlagen
stattdessen fail-closed fehl, bevor sie ihre Terminal-Reservierung verbrauchen.
Dateien oberhalb der Hartgrenze werden ebenfalls zurückgesetzt. Ein lang
laufender Service behält deshalb nicht jeden historischen Lifecycle; jeder
Verifier-Fall verwendet ein frisches isoliertes Log und bleibt weit unter der
Retention-Grenze.

Die referenzierten Observation-Dateien enthalten nur begrenzte Metadaten.
Upstream- und Client-Lease-Beobachtungen müssen beide false sein. Sensitive
Payload-Felder (Body, Lease-Werte, Credentials, Secrets, Tokens, Passwörter)
und unbekannte Felder werden abgelehnt. Unterstützte Fälle sind `p1_allow`,
`p1_deny`, `p2_allow`, `p2_deny`, `p2_oversize`, `p3_deny`,
`p3_redirect`, `p4_safe`, `p4_strict`, `metadata_omitted` und
`p2_to_p3_timeout`.

Fall-Labels wählen Lifecycle-Konsistenzprüfungen; sie sind keine Assertion,
dass eine benannte Regel oder ein Katalogvektor lief. Auch ein Allow-Control
muss den vollständigen P1--P4-Lifecycle in seinem einzelnen Receipt enthalten.
Der Verifier prüft rohe Records statt Labels: `p1_allow` und `p2_allow`
verlangen rohe P1/P2-Allow-Entscheidungen, einen 2xx-Client-Status,
Upstream-Response-Beobachtung und keine Request-Termination; request-seitige
Host-Aktionen werden abgelehnt. `p1_deny` verlangt eine
P1-Deny-Entscheidung und einen passenden clientsichtbaren 4xx/5xx-Status,
Request-Termination und keine Upstream-Response-Beobachtung. `p2_deny` und
`p2_oversize` verlangen die Sequenz P1 Allow/P2 Deny; `p2_oversize` zusätzlich
übereinstimmenden nativen P2-, request-seitigen Deny- und Client-Status (403 oder
413). Hostpuffer-413 ohne natives P2 ist kein Lifecycle-Nachweis für diesen Fall.
`p3_deny` und `p3_redirect` verlangen P3 Deny/Redirect, den
passenden Client-Status und eine Upstream-Response-Beobachtung. `p3_redirect`
verlangt zusätzlich die wahre Attestation `redirect_location_verified`: Die
vertraute Client-Grenze muss genau ein `Location` mit dem kanonischen begrenzten
Target beobachtet haben; der Receipt behält nur dieses Boolean und niemals den
Header-Wert. `p4_safe`
verlangt eine P4-Observer-Entscheidung, eine rohe `host_action` `log_only`,
eine committed Upstream-Response und das Client-Ergebnis `none`. `p4_strict`
ist in diesem Harness immer `NON_PASS`: Eine Driver-seitige Assertion `abort`
oder `reset` ist kein unabhängiger Beweis für eine clientsichtbare
Envoy-/Traefik-Host-Primitive. Ein solches Ergebnis benötigt separaten
Real-Host-Beweis.

`metadata_omitted` ist bewusst prä-admission: Der äußere Companion kann
privat reservieren, aber die explizite ForwardAuth-Request-Allow-List lässt
den Lease weg. ForwardAuth liefert daher HTTP 503, bevor Common P1/P2
verarbeitet. Sein Receipt enthält folglich keine P1--P4- oder Lease-Events
und genau ein terminales `abort`-Cleanup, weder Upstream- noch committed
Client-Response. Ein fehlender UDS vor der Reservierung ist ebenfalls ein
prä-admission Transportfehler; der Runner verweigert deshalb die Bezeichnung
als korreliertes Composite-Evidence, statt einen Transaktions-Receipt zu
erfinden.

`p2_to_p3_timeout` verlangt rohe P1/P2-`allow`-Records, genau einen erzeugten
Lease, eine beobachtete Upstream-Anfrage ohne P3/P4-Record, HTTP 503, keine
committed P4-Client-Response und genau einen finalen `terminal`-Record mit
`reason` `timeout`. Der Traefik-Helper wählt seine feste Verzögerung der
Response-Header ausschließlich über das exakte Suffix des operatorgesteuerten
Runtime-Root-Falls; Katalogeingaben können dieses Transportverhalten nicht
aktivieren. Dies ist eine fail-closed Lifecycle-Kontrolle und kein Nachweis
eines clientsichtbaren P4-Aborts oder -Resets.

Der Exit-Status ist nur für `LIFECYCLE_ONLY` `0`; fehlerhafte und `NON_PASS`-
Receipts liefern `1`. Die JSON-Ausgabe ist payload-frei und enthält nur Status,
Scope, Catalog-Acceptance-Flag, Connector, Fall, Artefakt-ID, Decision-ID,
anwendbare Phasen und prägnante Fehler.

`--expected-event-log` ist für die alleinstehende Nutzung optional. Wenn es
angegeben ist, muss es eine absolute existierende reguläre Nicht-Symlink-Datei
sein und sein aufgelöster Pfad muss exakt dem vom Manifest referenzierten
Event-Log-Basename entsprechen.
