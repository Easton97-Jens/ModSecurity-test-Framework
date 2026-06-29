# Importanalyse: ModSecurity v2

**Sprache:** [English](import-analysis-modsecurity-v2.md) | Deutsch

Status: umgesetzt

Lokale Quelle: `<workspace>/ModSecurity_V2`
Beobachtete Referenz: `v2/master`, `v2.9.13`

## Rolle

v2 ist nicht die Architekturquelle für neue Konnektoren. Es wird verwendet für:

- Regressionstest-Quelle
- Semantik-Referenz
- Kompatibilitätsreferenz
- historischer Apache-Implementierungskontext

## Build-System

Beobachtete Dateien:

- `configure.ac`
- `Makefile.am`
- `apache2/Makefile.am`
- `tests/Makefile.am`
- `tests/run-regression-tests.pl.in`

v2 ist im Hauptbaum eng mit Apache verbunden. Die `tests/Makefile.am`
Erstellt eine `msc_test`-Binärdatei aus vielen `apache2/*`-Quellen und eigenständigen Helfern.

## Regressionswert

v2-Regressionsdateien unter `tests/regression/`, `tests/op/` und `tests/tfn/`
bleiben nützlich für Regelsemantik, Transformationen, Operatoren, Phasenverhalten,
und Kompatibilitätserwartungen.

## Nicht tragbare Architektur

Die folgenden Informationen sind historisch bzw. konnektorspezifisch und dürfen nicht übertragen werden
direkt in neue Anschlüsse:

- Interna des Apache-Moduls unter `apache2/`
- APR Annahmen zum Lebenszyklus von Pool- und Apache-Anfragen
- v2-Anforderungsdatensatzstrukturen
- v2 parser/internal Funktionsaufrufe werden von libmodsecurity v3 public nicht verfügbar gemacht API
- Verhalten des Apache-Server-Root-Perl-Testgeschirrs

## Wiederverwendungsklassifizierung

| Komponente | Quelle | Umfang | Kompatibilität | Entscheidung |
| --- | --- | --- | --- | --- |
| `tests/op/*.t` | v2 | motorspezifisch | teilweise | Kandidat für tragbares Mapping nach v3 API Überprüfung |
| `tests/tfn/*.t` | v2 | motorspezifisch | teilweise | Kandidat für tragbare Transformationstests |
| `tests/regression/*/*.t` | v2 | gemischt | teilweise | Ordnen Sie jeden Fall den erforderlichen phase/capability zu. |
| `apache2/*` | v2 | Connector-spezifisch | inkompatibel | Nur historische Referenz |
| `tests/run-regression-tests.pl.in` | v2 | Connector-spezifisch | inkompatibel | Nur als Harnessreferenz |

## TODO

- Erstellen Sie pro Test eine Zuordnung von Perl-Strukturen der Version 2 zu Fällen im JSON-Stil der Version 3.
- Markieren Sie Fälle, die eine reine Apache-Konfiguration, ein Dateisystemlayout oder ein Protokollformat erfordern, als
  Connector-spezifisch.
