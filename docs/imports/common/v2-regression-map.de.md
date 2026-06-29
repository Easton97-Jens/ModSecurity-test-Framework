# ModSecurity v2-Regressionskarte

**Sprache:** [English](v2-regression-map.md) | Deutsch

Status: umgesetzt

Lokale Quelle: `<local ModSecurity v2 checkout>/tests/`
Upstream-Quelle: https://github.com/owasp-modsecurity/ModSecurity

Der v2-Baum wird nur als Regressions-, Semantik- und Kompatibilitätsquelle verwendet.
In dieses Monorepo wird keine v2-Architektur oder Apache-Harness-Code importiert.

Beobachtetes lokales Inventar am 15.05.2026: 115 Dateien unter `tests/`.

| Originalpfad | source_repo | Version | Kategorie | Zweck | tragbar | stecker_spezifisch | motorspezifisch | Zielort | Status | erforderliche_Kapazitäten | bekannte_Einschränkungen |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `tests/op/streq.t` | ModSecurity_V2 | v2/master beobachtet 2.9.13 | Betreiber | Semantik von String-Gleichheitsoperatoren | ja | Nein | ja | `tests/cases/transformations/v2_operator_streq_block.yaml` | importiert | Operatoren, Abfrageargumente, Phase2 | Vom Perl-Operator-Harness in die Interventionsbehauptung HTTP konvertiert |
| `tests/op/contains.t` | ModSecurity_V2 | v2/master beobachtet 2.9.13 | Betreiber | Semantik von Teilstring-Operatoren | ja | Nein | ja | `tests/cases/transformations/v2_operator_contains_block.yaml` | importiert | Operatoren, Abfrageargumente, Phase2 | Es bleiben nur Randfälle mit leeren Zeichenfolgen zugeordnet |
| `tests/op/beginsWith.t` | ModSecurity_V2 | v2/master beobachtet 2.9.13 | Betreiber | Semantik des Präfixoperators mit Parameter `abcdef`, Eingabe `abcdefghi`, ret 1 | ja | Nein | ja | `tests/cases/transformations/v2_operator_begins_with_block.yaml` | importiert | Operatoren, Abfrageargumente, Phase2 | Nur Leerzeichenfolge- und Nichtübereinstimmungszweige bleiben zugeordnet |
| `tests/op/endsWith.t` | ModSecurity_V2 | v2/master beobachtet 2.9.13 | Betreiber | Suffixoperator-Semantik mit Parameter `ghi`, Eingabe `abcdefghi`, ret 1 | ja | Nein | ja | `tests/cases/transformations/v2_operator_ends_with_block.yaml` | importiert | Operatoren, Abfrageargumente, Phase2 | NUL-haltiger Zweig bleibt nur zugeordnet |
| `tests/op/pm.t` | ModSecurity_V2 | v2/master beobachtet 2.9.13 | Betreiber | Phrase-Match-Semantik mit Parameter `abc`, Eingabe `abcdefghi`, ret 1 | ja | Nein | ja | `tests/cases/transformations/v2_operator_pm_block.yaml` | importiert | Operatoren, Abfrageargumente, Phase2 | Nur lange Phrasenlisten- und No-Match-Zweige bleiben zugeordnet |
| `tests/op/containsWord.t` | ModSecurity_V2 | v2/master beobachtet 2.9.13 | Betreiber | Semantik von Wortgrenzen-Teilzeichenfolgen unter Verwendung von Parameter `abc`, Eingabe `abc def ghi`, ret 1 | ja | Nein | ja | `tests/cases/transformations/v2_operator_contains_word_block.yaml` | importiert | Operatoren, Abfrageargumente, Phase2 | Nur negative Wortgrenzenzweige bleiben zugeordnet |
| `tests/op/*.t` | ModSecurity_V2 | v2/master beobachtet 2.9.13 | Betreiber | Operator-Semantikmatrix | teilweise | Nein | ja | `tests/cases/` oder Karten | kartiert | Betreiber | Operatoren optionaler Bibliotheken und dateigestützte Operatoren benötigen separate Fixture-Unterstützung |
| `tests/tfn/lowercase.t` | ModSecurity_V2 | v2/master beobachtet 2.9.13 | Transformationen | Semantik der Kleinbuchstabentransformation | ja | Nein | ja | `tests/cases/transformations/v2_transformation_lowercase_block.yaml` | importiert | Transformationen, Abfrageargumente, Phase2 | Nur eingebettete NUL-Fälle bleiben zugeordnet |
| `tests/tfn/trim.t` | ModSecurity_V2 | v2/master beobachtet 2.9.13 | Transformationen | Leading/trailing Entfernen von Leerzeichen | ja | Nein | ja | `tests/cases/transformations/v2_transformation_trim_block.yaml` | importiert | Transformationen, Abfrageargumente, Phase2 | Nur komplexe Leerzeichen und NUL-Fälle bleiben zugeordnet |
| `tests/tfn/urlDecode.t` | ModSecurity_V2 | v2/master beobachtet 2.9.13 | Transformationen | URL Dekodierungstransformation mit Eingabe `Test+Case`, Ausgabe `Test Case`, ret 1 | ja | Nein | ja | `tests/cases/request/uri/v2_transformation_url_decode_block.yaml` | importiert | Transformationen, Anfrage-URI, Phase1 | Es bleiben nur Vollbyte-, NUL- und ungültige Codierungszweige zugeordnet |
| `tests/tfn/htmlEntityDecode.t` | ModSecurity_V2 | v2/master beobachtet 2.9.13 | Transformationen | HTML Entitätsdekodierungstransformation mit `&lt;&gt;` -> `<>` | ja | Nein | ja | `tests/cases/request/headers/v2_transformation_html_entity_decode_block.yaml` | importiert | Transformationen, Anforderungsheader, Phase1 | NUL, nbsp, Nicht-ASCII und ungültige Entitätszweige bleiben nur zugeordnet |
| `tests/tfn/*.t` | ModSecurity_V2 | v2/master beobachtet 2.9.13 | Transformationen | Transformationssemantikmatrix | teilweise | Nein | ja | `tests/cases/` oder Karten | kartiert | Transformationen | In vielen Fällen ist eine binary/NUL-Fixture-Darstellung erforderlich, die nicht im YAML-Smokeschema enthalten ist |
| `tests/regression/misc/00-multipart-parser.t` | ModSecurity_V2 | v2/master beobachtet 2.9.13 | mehrteilig | Multipart-Parser-Verhalten und Parser-Fehler | teilweise | Nein | ja | Karten | Nur zugeordnet | mehrteilig, Dateien, Anfragetext | In Apache/NGINX-derived-Fällen besteht eine normale Textfeldabdeckung; Fehlerhafte Parser-Fälle bleiben aktivem Smoke nicht zugeordnet |
| `tests/regression/rule/10-xml.t` | ModSecurity_V2 | v2/master beobachtet 2.9.13 | xml | XML Parser, Schema und DTD Verhalten | teilweise | Nein | ja | Karten | Nur zugeordnet | xml, Body-Prozessoren, Fixtures | Die Schema/DTD-Validierung erfordert vor dem aktiven Import die Materialisierung der Fixture-Datei |
| `tests/regression/rule/15-json.t` | ModSecurity_V2 | v2/master beobachtet 2.9.13 | json | JSON Körperprozessor- und Parserverhalten | teilweise | Nein | ja | Karten | Nur zugeordnet | json, Body-Prozessoren | Roher JSON-Body-Matching wird an anderer Stelle behandelt; Parsed JSON Sammlungsparität bleibt zugeordnet |
| `tests/regression/target/00-targets.t` | ModSecurity_V2 | v2/master beobachtet 2.9.13 | Sammlungen | Variable/collection Deckung einschließlich ARGS, FILES, XML | teilweise | Nein | ja | Karten und importierte häufige Fälle | kartiert | Sammlungen, Dateien, XML | Einige Variablen erfordern das Hochladen temporärer Pfade oder die Parser-Einrichtung XML |
| `tests/regression/action/*.t` | ModSecurity_V2 | v2/master beobachtet 2.9.13 | Aktionen | Störende und protokollierende Aktionen | teilweise | Nein | ja | `tests/cases/` und Karten | kartiert | Aktionen, Audit-Log | Protokolltext und v2-Audit-Formatierung sind nicht portierbar |
| `tests/regression/config/*.t` | ModSecurity_V2 | v2/master beobachtet 2.9.13 | Regelparser | Directive/config Verhalten | teilweise | Nein | ja | Karten | Nur zugeordnet | Regelparser | Umgebungsspezifische Pfade und Dateien benötigen Fixture-Unterstützung |
| `tests/regression/misc/00-phases.t` | ModSecurity_V2 | v2/master beobachtet 2.9.13 | Phasenverarbeitung | Phasenlebenszyklusverhalten | teilweise | teilweise | ja | Karten und Minimalfälle | kartiert | Phase1, Phase2, Phase3, Phase4 | Das genaue hook/log-Verhalten ist konnektorspezifisch |
| `tests/run-regression-tests.pl.in` | ModSecurity_V2 | v2/master beobachtet 2.9.13 | Connector-spezifisch | Historisches Apache-Regressionsgeschirr | Nein | ja | Nein | Nur Dokumentation | Nur zugeordnet | Apache-Laufzeit | Nicht importiert; Die v2-Apache-Architektur ist kein Modell für neue Konnektoren |

## Aktive, von V2 abgeleitete Importe

Diese aktiven Fälle wurden lokal durch `make smoke-common` mit beobachtet
`BUILD_ROOT=<local-build-root>`; Sowohl Apache als auch NGINX wurden zurückgegeben
die erwarteten HTTP 403.

| Fall | Quelle | Status |
| --- | --- | --- |
| `v2_operator_streq_block.yaml` | `tests/op/streq.t` | vollständig importiert-gemeinsam |
| `v2_operator_contains_block.yaml` | `tests/op/contains.t` | vollständig importiert-gemeinsam |
| `v2_operator_begins_with_block.yaml` | `tests/op/beginsWith.t` | vollständig importiert-gemeinsam |
| `v2_operator_ends_with_block.yaml` | `tests/op/endsWith.t` | vollständig importiert-gemeinsam |
| `v2_operator_pm_block.yaml` | `tests/op/pm.t` | vollständig importiert-gemeinsam |
| `v2_operator_contains_word_block.yaml` | `tests/op/containsWord.t` | vollständig importiert-gemeinsam |
| `v2_transformation_lowercase_block.yaml` | `tests/tfn/lowercase.t` | vollständig importiert-gemeinsam |
| `v2_transformation_trim_block.yaml` | `tests/tfn/trim.t` | vollständig importiert-gemeinsam |
| `v2_transformation_url_decode_block.yaml` | `tests/tfn/urlDecode.t` | vollständig importiert-gemeinsam |
| `v2_transformation_html_entity_decode_block.yaml` | `tests/tfn/htmlEntityDecode.t` | vollständig importiert-gemeinsam |
