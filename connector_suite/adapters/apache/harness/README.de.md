# Apache-Smoke-Harness

**Sprache:** [English](README.md) | Deutsch

Status: Adaptereigener Quellrauchkabelbaum

Bei diesem Harness handelt es sich um einen connector-spezifischen Proof-of-Concept-Runner für den Apache
Modul, das aus der zum Adapter gehörenden `connectors/apache/src`-Quelle erstellt wurde, wurde materialisiert
unter `$BUILD_ROOT/apache-build/connector-src`. Es handelt sich nicht um eine vollständige Regression
Testsuite.

Lokal beobachtet am 15.05.2026: Der vom Quellcode erstellte Apache httpd `2.4.67` wurde zurückgegeben
der von YAML erwartete HTTP-Status für alle aktuell freigegebenen Minimalfälle.

## Grenzen

- Verwendet nur Artefakte unter `BUILD_ROOT`.
- Erstellt oder ändert kein `<external-source-root>/*`-Repository.
- Der Quell-Checkout wird nicht erstellt oder verändert. alle generierten Autotools und
  Laufzeitdateien bleiben unter `BUILD_ROOT`.
- Meldet `pass` nur, wenn Apache den von YAML erwarteten HTTP-Status für a zurückgibt
  echte lokale Anfrage.
- Standardmäßig wird der von der Quelle erstellte httpd unter verwendet
  `$BUILD_ROOT/apache-runtime/httpd/bin/httpd`.
- Liest Regel, Anfrage, Header, Text, mehrteiligen Text, Antwortvorrichtung usw
  erwarteter Status von YAML bis `modules/ModSecurity-test-Framework/tests/runners/case_cli.py`.

## Nutzung

```sh
REFRESH=1 \
BUILD_HTTPD_FROM_SOURCE=1 \
BUILD_ROOT=/src/ModSecurity-conector-build \
make smoke-apache

BUILD_ROOT=/src/ModSecurity-conector-build \
make smoke-apache
```

So verwenden Sie explizite externe Tools anstelle der von der Quelle erstellten Standardtools:

```sh
APXS=/path/to/apxs \
APACHE_HTTPD=/path/to/httpd \
BUILD_ROOT=/src/ModSecurity-conector-build \
sh connectors/apache/harness/run_apache_smoke.sh
```

Wenn Apache, das Modul oder `libmodsecurity.so` fehlen, beendet das Skript `77`
und markiert das Ergebnis als `blocked`.

## Geteilte Fälle

Standardmäßig iteriert der Harness jede `*.yaml`-Datei in:

```text
modules/ModSecurity-test-Framework/tests/cases/
modules/ModSecurity-test-Framework/tests/cases/
modules/ModSecurity-test-Framework/tests/cases/connector-specific/apache/
```

So führen Sie eine Teilmenge aus:

```sh
BUILD_ROOT=/src/ModSecurity-conector-build \
SMOKE_CASES="phase1_header_block phase2_args_block" \
make smoke-apache
```

Der Harness materialisiert die Apache-Regeldatei, die Anforderungsvariablen und die Anforderung
Header, Anforderungstext, mehrteiliger Text und Antwort-Fixture aus jeder YAML-Datei
zur Laufzeit. Es verwendet nur `/__modsec_smoke_ready` mit deaktivierter ModSecurity
Bereitschaftsprüfungen. Duplizieren Sie nicht die Regel, den Anforderungspfad, die Anforderungsmethode usw.
Header, Text, Antwortvorrichtung oder erwarteter HTTP-Status im Harness.
