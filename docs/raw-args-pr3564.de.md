# PR #3564 RAW Nachweis der Argumentsammlung

**Sprache:** [English](raw-args-pr3564.md) | Deutsch

Status: Nur zugeordnete/nicht unterstützte lokale Quelle

Öffentliche Quelle: https://github.com/owasp-modsecurity/ModSecurity/pull/3564

PR #3564 fügt RAW URL-codierte Argumentsammlungen hinzu, die Argumente offenlegen sollen
Namen und Werte vor libmodsecurity URL Dekodierung:

- `ARGS_RAW`
- `ARGS_GET_RAW`
- `ARGS_POST_RAW`
- `ARGS_NAMES_RAW`
- `ARGS_GET_NAMES_RAW`
- `ARGS_POST_NAMES_RAW`

## Lokale Quellenprüfung

Frühere lokale Evidenz verwendete einen inzwischen eingestellten Helfer für
eine schreibgeschützte Suche der konfigurierten v3-Quelle. Er ist kein aktiver
Repository-Befehl; eine künftige Prüfung muss `MODSECURITY_V3_SOURCE_DIR`
direkt untersuchen und Befehl sowie Ausgabe mit der Lauf-Evidenz aufbewahren.

Lokal beobachtet am 15.05.2026 gegen `<workspace>/ModSecurity_V3`:

```text
raw_args_support: unsupported-local-source missing: ARGS_RAW ARGS_GET_RAW ARGS_POST_RAW ARGS_NAMES_RAW ARGS_GET_NAMES_RAW ARGS_POST_NAMES_RAW
```

Kein RAW-Argument YAML-Fall ist in diesem Repository für die aktuelle lokale Datei aktiv
Quelle. Dadurch wird vermieden, dass das Verhalten von PR #3564 vor der Implementierung beansprucht wird
vorhanden und über beide Anschlüsse getestet.

## Hochstufungskriterien

RAW Fälle können nur dann von „Nur zugeordnet“ zu „Aktiv gemeinsam“ wechseln, wenn alle Bedingungen erfüllt sind
sind wahr:

1. `MODSECURITY_V3_SOURCE_DIR` enthält die Sammlung PR #3564 RAW
   Implementierungs- und Regressionsdaten.
2. Die YAML-Fälle werden aus dieser Implementierung oder Regression abgeleitet
   Daten.
3. Apache gibt den erwarteten HTTP-Status über den echten Connector-Pfad zurück.
4. NGINX gibt den erwarteten HTTP-Status über den echten Connector-Pfad zurück.

Bis dahin bleibt die RAW-Argumentunterstützung nur zugeordnet und darf nicht in erscheinen
`verified_variables`.
