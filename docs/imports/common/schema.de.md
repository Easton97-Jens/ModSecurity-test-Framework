# Gemeinsames Testschema

**Sprache:** [English](schema.md) | Deutsch

Status: eingerüstet

Tragbare, häufige Fälle verwenden die folgende minimale Zuordnungsform:

```yaml
name: example

capabilities:
  query_args: true
  phase2: true
  intervention: true

rules: |
  SecRuleEngine On
  SecRule ARGS:test "@streq attack" "id:1,phase:2,deny,status:403"

request:
  method: GET
  path: "/?test=attack"
  headers:
    User-Agent: optional
  body: optional
  multipart:
    boundary: optional-boundary
    parts:
      - name: optional
        body: optional

response:
  body: optional origin response body

expect:
  status: 403
  intervention: deny
  rule_id: 1
  response_contains: optional pass-through text
  audit_log:
    required: false
  phase4_log:
    required: false
    contains:
      - optional stable substring
    not_contains:
      - optional stable substring
```

`request.body` und `request.multipart` schließen sich gegenseitig aus. Mehrteilige Körper
werden vom Shared Runner mit deterministischen CRLF Zeilenenden und materialisiert
ein generierter `Content-Type: multipart/form-data; boundary=...`-Header.

`response.body` ist optional. Wenn es weggelassen wird, schreibt der Harness einen kleinen Standardwert
Ursprungskörper unter der fallspezifischen Laufzeit-Docroot.

`capabilities` benennt das für den Fall erforderliche tragbare Verhalten. Strom minimal
Zu den Funktionen gehören `query_args`, `request_headers`, `request_body`,
`form_urlencoded`, `multipart`, `json`, `response_headers`, `response_body`,
`phase1`, `phase2`, `phase3`, `phase4`, `intervention`, `pass_through` und
`audit_log`.

`expect.intervention` ist auf `deny`, `pass` oder `none` beschränkt. Ein Durchgang
Der Fall sollte `intervention: none`, `status: 200` und normalerweise verwenden
`response_contains` um zu beweisen, dass die Anfrage den Ursprungsinhalt erreicht hat.

Audit-Log-Fälle behalten die Audit-Anweisungen in `rules` und verwenden sie
`@@AUDIT_LOG@@` / `@@AUDIT_LOG_DIR@@` Platzhalter. Der geteilte Runner
materialisiert diese Platzhalter in Fallpfaden gemäß `BUILD_ROOT`.
Stabile Audit-Log-Erwartungen leben in `expect.audit_log`; Werte werden geprüft als
Teilzeichenfolgen, also flüchtige IDs, Zeitstempel, Ports und absolute generierte Pfade
darf nicht erforderlich sein.

Nur NGINX PR #377 Nachweisfälle können konnektorspezifische Felder verwenden:

```yaml
nginx:
  files:
    phase4-content-types.conf: |
      application/json
  location_directives: |
    modsecurity_phase4_log "@@NGINX_PHASE4_LOG@@";
    modsecurity_phase4_content_types_file "@@NGINX_FILE:phase4-content-types.conf@@";
```

`nginx.location_directives` wird in eine eingebundene Datei innerhalb der NGINX gerendert.
`location /` Block. `nginx.files` schreibt deterministische fallspezifische Konfigurationsfixierungen
unter diesem Fall-Laufzeitkonfigurationsverzeichnis. Unterstützte Platzhalter sind
`@@NGINX_PHASE4_LOG@@` und `@@NGINX_FILE:<name>@@`. `expect.phase4_log` prüft
stabile Teilzeichenfolgen im generierten Phase-4-Protokoll und ist nur für gedacht
Connector-spezifische NGINX importierte oder frühere erwartete Fehlerfälle.

Offene Arbeiten werden in `docs/roadmap/todo-inventory.md` verfolgt:

- Definieren Sie ein maschinenlesbares JSON-Schema, nachdem sich die YAML-Form festgelegt hat.
- Konnektorspezifische Felder bei der allgemeinen Schemavalidierung ablehnen.
