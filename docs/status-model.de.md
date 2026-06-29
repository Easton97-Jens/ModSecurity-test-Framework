# Statusmodell

**Sprache:** [English](status-model.md) | Deutsch

Das Framework trennt Laufzeitergebnisse vom import/classification-Status.

## Laufzeitstatus

| Status | Bedeutung | Exit-Effekt |
| --- | --- | --- |
| `pass` | Das tatsächliche HTTP-Verhalten entsprach der YAML-Erwartung | Erfolg |
| `fail` | Der Server wurde ausgeführt, aber das Verhalten weicht von der YAML-Erwartung ab | Ausgang 1 |
| `blocked` | Quelle, Download, Build oder Laufzeitvoraussetzung fehlten | Ausgang 77 |
| `not_executable` | Der Fall konnte für den connector/runtime-Modus strukturell nicht realisiert werden | Ausgang 78 |
| `skipped` | Reserviert für explizites zukünftiges Sprungverhalten | nicht stillschweigend verwendet |

`fail` wird verwendet, wenn eine Regelvariable libmodsecurity oder das nicht erreicht
Der Connector gibt den falschen HTTP-Status zurück. `blocked` gilt nur für Voraussetzungen.

## Importstatus

| Status | Bedeutung |
| --- | --- |
| `fully-imported-common` | Von der Quelle abgeleiteter Fall, der über Apache- und NGINX-Real-Connector-Pfade weitergegeben wird |
| `connector-specific` | Gilt nur für einen benannten Connector |
| `mapped-only` | Die Quelle ist dokumentiert, aber nicht als aktiver Smoke ausführbar |
| `blocked` | Die relevante Quelle ist vorhanden, aber der aktuelle Harness kann sie nicht ausführen |
| `former_xfail` | Historische Migrationsmetadaten für Fälle, die jetzt durch normale Laufzeitbeweise ausgewertet werden |

`config/testing/import-status.json` ist das maschinenlesbare Manifest für den Importstatus
zählt. Connector-Zusammenfassungen kopieren diese Zählungen in `import_status`.

## Ergebnismetadaten

Jede Connector-Zusammenfassung JSON enthält:

- `connector_path: "real-world"`
- `validation_mode: "real-world-connector-path"`
- `environment`: `SMOKE_ENVIRONMENT`, sonst `github-actions` oder `local`
- `audit_behavior`: `stable`, `unstable` oder `unexpected`
- `verified_variables`: Wird nur aus dem Bestehen aktiver Fälle abgeleitet

Frühere XFAIL-Fälle behalten Migrationsmetadaten, aber PASS/FAIL/BLOCKED/NOT_EXECUTABLE
kommt jetzt nur noch aus Live-Laufzeitbeweisen.
