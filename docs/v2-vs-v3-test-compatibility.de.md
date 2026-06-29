# V2 vs. V3 Testkompatibilität

**Sprache:** [English](v2-vs-v3-test-compatibility.md) | Deutsch

Status: umgesetzt

In diesem Dokument wird aufgezeichnet, wie lokale ModSecurity v2- und v3-Tests im wiederverwendet werden
Connector-Kompatibilitäts-Framework. Die Quellbäume unter `<workspace>/*`
bleiben schreibgeschützte Referenzen.

## Quellrollen

| Quelle | Rolle in diesem Monorepo | Regel importieren |
| --- | --- | --- |
| `ModSecurity_V3/test/` | Primäre libmodsecurity v3 API/regression-Referenz | Von der Quelle abgeleitete YAML können in den allgemeinen Smoke gelangen, wenn sowohl Apache als auch NGINX bestehen |
| `ModSecurity_V2/tests/` | Historische semantics/regression Kompatibilitätsreferenz | Es werden nur portable Operator-, Transformations-, Regel- und Sammlungssemantiken importiert |
| v2 Apache-Harness-Dateien | Historische Connector-Referenz | Nur zugeordnet; Wird nicht als Architektur für neue Connector verwendet |

## Kompatibilitätsunterschiede

| Bereich | v2 Quellform | v3-Quellform | Monorepo-Handhabung |
| --- | --- | --- | --- |
| Betreiber | Semantische Vorrichtungen im Perl-Stil `tests/op/*.t` | JSON Regressionsfälle wie `operator-rx.json` | Wird in minimales HTTP YAML konvertiert, wenn das Verhalten konnektorneutral ist |
| Transformationen | `tests/tfn/*.t`-Einrichtungen im Perl-Stil | JSON Transformationsregressionen | Nur für textsichere Fälle konvertiert; binary/NUL Fälle bleiben zugeordnet |
| Auftragsverarbeiter anfordern | Apache-Regressions-`.t`-Dateien | JSON Parser-Regressionen | Rohe JSON-, einfache Multipart-, FILES- und XML-Grundlagen, die nach Apache+NGINX-Durchlauf importiert werden |
| XML | v2 schema/DTD/parser Tests | v3 `variable-XML` und Parser JSON Fälle | Winziger XML-Körper importiert; schema/DTD/parser-error Fälle zugeordnet |
| Mehrteilige Dateien | v2 target/multipart Parsertests | v3 FILES/MULTIPART Variablenregressionen | Deterministische kleine Datei-Uploads importiert; malformed/streaming Fälle zugeordnet |
| API Smoke | v2 ist keine v3 API-Quelle | v3 public C API ist primär | Bestehende `src/v3-api-smoke` bleiben vom Connector `smoke-all` getrennt |
| Logging/audit | v2/v3 Protokolle unterscheiden sich und enthalten flüchtige Felder | v3 audit/debug Fälle existieren | Smoke im stabilen Prüffeld ist vorhanden; Debug-Text und komplexe Audit-Varianten abgebildet |

## Aktive Importe

Bei den aktiven V2/V3-Importen handelt es sich um allgemeine Connector-Tests, nicht um kopierte Upstream-Tests.
Jeder YAML enthält Herkunftsmetadaten und wird über denselben Apache ausgeführt
und NGINX Harnesses wie andere häufige Fälle.

Lokal beobachtet am 15.05.2026:

| Quellfamilie | Aktive Fälle importiert | Apache | NGINX |
| --- | ---: | --- | --- |
| V2 operators/transformations | 10 | passieren | passieren |
| V3 mehrteilig FILES/XML/operator/action/collections/audit | 14 | passieren | passieren |

In der zweiten Kompatibilitäts-Importwelle wurde absichtlich eine Quellenbestätigung verwendet
Werte aus den V2/V3 Fixtures. Beispielsweise verwendet `urlDecode` `Test+Case` ->
`Test Case`, `htmlEntityDecode` verwendet das Fragment `&lt;&gt;` -> `<>`, V2 `pm`
verwendet Parameter `abc` mit Eingabe `abcdefghi`, V2 `containsWord` verwendet Parameter `abc`
mit Eingabe `abc def ghi` und V3 `pm` verwendet `@pm 1 2 3` mit `param1=123`.
Der Fall V3 `issue-2196` `nolog,pass` wird nicht mehr als aktiv gezählt
allgemeiner Import, da GitHub Actions die Audit-Log-Ausgabe lokal beobachtet hat
Apache und NGINX führen beobachtete leere Überwachungsprotokolle aus.

## Nur zugeordnet

Folgendes bleibt zugeordnet, bis ein zukünftiger Schritt dedizierte Unterstützung hinzufügt:

- XML schema/DTD Validierungsvorrichtungen.
- XML Parser-Fehlerfälle.
- Mehrteiliger fehlerhafter Körper und streaming/buffering-Randfälle.
- Dateigestützte Operatoren und externe Datendateien.
- Optionale Bibliotheksoperatoren.
- NUL, Binär-, Nicht-ASCII- und ungültige Eingabetransformationszweige.
- Nur API-v3-Tests, die stattdessen über ein dediziertes API Smoke-Ziel laufen sollten
  als der Apache/NGINX Connector Smoke.
