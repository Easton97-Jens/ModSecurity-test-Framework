# Runner

**Sprache:** [English](README.md) | Deutsch

Status: eingerüstet

Die Runner-Schicht definiert die Adapterform, die von zukünftigen Connectortests erwartet wird.
Es implementiert keine vollständige server/proxy-Adaptersuite.

Jetzt implementiert:

- `case_cli.py materialize` liest einen freigegebenen YAML-Fall und schreibt eine Connector-Laufzeit
  Regeldatei, Anforderungs-headers/body-Dateien, deterministische mehrteilige Körper,
  Antwortvorrichtungen, Audit-Log-Pfade und Shell-Safe request/expectation
  Variablen. Ein optionaler `--rules-preamble-file` wird vor dem lokalen geschrieben
  Fallregeln für Varianten wie OWASP CRS.
- `case_cli.py assert-status` vergleicht den Status des echten Connectors HTTP, optional
  Inhalt des Antworttextes und optionaler Audit-Log-Inhalt mit den freigegebenen YAML
  Fallerwartung.
- `case_cli.py list-cases` wählt anwendbares Common oder Connector-spezifisch aus
  YAML Fälle für einen Connector-Bereich.
- `case_cli.py case-info` und `summarize-results` schreiben das normalisierte JSON Ergebnis
  Metadaten mit Herkunft, Kategorie, Umfang, erwartetem Status und beobachtetem Status.
- `runner_core.py` validiert das minimale Shared-Case-Schema und stellt das bereit
  Statuszusicherung, die von den Apache- und NGINX-Harnessesn verwendet wird. Die Basis `expect`
  Zuordnung wird für `MODSECURITY_TEST_VARIANT=no-crs` verwendet; ein Fall kann bieten
  `expect.variants.with-crs` für eine minimale With-CRS-Assertionsüberschreibung.

Die Apache- und NGINX-PoCs verwenden diesen Runner, also jede YAML-Datei unter
`tests/cases/` ist die einzige Quelle für die Regel, Anfrage, Header, optional
Hauptteil oder mehrteiliger Hauptteil, Antwortvorrichtung und erwarteter HTTP-Status.
Der Runner unterstützt optional auch durch Doppelpunkte getrennte `EXTRA_CASE_ROOTS`
Framework-eigene generierte Fälle.
Importierte, ausstehende, zukünftige, Lücken- und ehemalige-XFAIL-Klassen sind Metadatenwerte.
keine Statusverzeichnisse.
Audit-Log-Fälle verwenden auch YAML als Quelle für das stabile Audit-Log-Feld
Erwartungen.

Erforderliche Adaptermethoden:

- `prepare()`
- `start()`
- `stop()`
- `reload()`
- `apply_config()`
- `apply_rules()`
- `endpoint()`
- `send_request()`
- `collect_artifacts()`
- `cleanup()`

Nicht implementierte Adapter müssen `NotImplementedError` auslösen.

Beispiel:

```sh
python3 tests/runners/case_cli.py materialize \
  --case tests/cases/phases/phase2/phase2_args_block.yaml \
  --rules-file "$BUILD_ROOT/rules.conf" \
  --env-file "$BUILD_ROOT/case.env" \
  --headers-file "$BUILD_ROOT/request-headers.txt" \
  --body-file "$BUILD_ROOT/request-body.bin" \
  --docroot "$BUILD_ROOT/htdocs" \
  --audit-log-file "$BUILD_ROOT/audit.log" \
  --audit-log-dir "$BUILD_ROOT/audit"

python3 tests/runners/case_cli.py assert-status \
  --case tests/cases/phases/phase2/phase2_args_block.yaml \
  --actual-status 403 \
  --response-body-file "$BUILD_ROOT/response-body.txt" \
  --audit-log-file "$BUILD_ROOT/audit.log"
```
