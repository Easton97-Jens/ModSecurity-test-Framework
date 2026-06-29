# MRTS Integration

**Sprache:** [English](mrts.md) | Deutsch

MRTS ist eine Framework-eigene Testgenerierungsquelle für ModSecurity-Kompatibilität
Sonden. Es handelt sich nicht um Connector-Code, und Connector-Repositorys sollten dies nur tun
Delegieren Sie an die Framework-MRTS-Ziele.

MRTS ist als erforderliches Framework-Submodul in `tools/MRTS` enthalten. Initialisieren Sie es
nach dem Klonen des Frameworks:

```sh
git submodule update --init --recursive
```

MRTS-Ziele verwenden standardmäßig `tools/MRTS`. Sie können auch ein separates lokales verwenden
Checkout:

```sh
MRTS_ROOT=/path/to/MRTS make mrts-generate
```

Wenn `tools/MRTS` fehlt oder nicht initialisiert ist, zielt MRTS auf den Exit mit Status 77 ab.
Führen Sie `git submodule update --init --recursive` aus, um den Standard-Checkout wiederherzustellen.

MRTS Quelleingaben werden direkt aus dem MRTS Submodul gelesen:

```text
$MRTS_ROOT/config_tests/
$MRTS_ROOT/feature_demo/config_tests/
```

Das standardmäßig ausführbare Korpus ist das Upstream-MRTS-Config-Test-Korpus:

```text
$MRTS_ROOT/config_tests/
```

Feature-Demo-Konfigurationstests bleiben als optional/demo-Abdeckung sichtbar, sie sind es aber
standardmäßig als pending/non-runtime importiert:

```text
$MRTS_ROOT/feature_demo/config_tests/
```

Goldene Referenzen leben unter `$MRTS_ROOT/generated/` und
`$MRTS_ROOT/feature_demo/generated/`. Sie sind nur drift/reference-Eingaben: sie
werden niemals in `mrts.load` enthalten, niemals als Laufzeit-Framework-Fälle importiert,
und niemals an `EXTRA_CASE_ROOTS` angehängt.

Generierte MRTS-Dateien befinden sich unter `$MRTS_BUILD_ROOT`, der Standardwert ist
`$BUILD_ROOT/mrts`. Dazu gehören generierte ModSecurity-Regeln und generierte go-ftw
YAML-Tests, importierte Framework-YAML-Fälle und `mrts.load`:

```text
$MRTS_BUILD_ROOT/upstream-config-tests/{rules,ftw,framework-cases,mrts.load}
$MRTS_BUILD_ROOT/feature-demo/{rules,ftw,framework-cases,mrts.load}
```

## Befehle

```sh
make mrts-generate
make test-no-mrts
make test-with-mrts
make test-with-mrts-feature-demo
make test-mrts-matrix
make mrts-ftw
```

`make test-no-mrts` erfordert kein MRTS und hängt keine MRTS-Fallwurzeln an.
Wenn `EXTRA_CASE_ROOTS` bereits vom Aufrufer gesetzt ist, bleibt es erhalten.

`make test-with-mrts` generiert einmal MRTS Artefakte, schreibt einmal `mrts.load`,
importiert generierte Framework-Fälle einmal und hängt den Build-Root-Upstream an MRTS
Framework-Fallverzeichnis in `EXTRA_CASE_ROOTS` und führt den vorhandenen Connector aus
raucht. Standardmäßig umfasst `mrts.load` nur generierte Regeln von
`upstream-config-tests`.

Für die Feature-Demo-Laufzeit ist nur eine explizite Anmeldung möglich:

```sh
MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO=1 make test-with-mrts-feature-demo
```

Der Opt-in-Pfad prüft auf Regel-ID-Kollisionen, bevor er die Feature-Demo zulässt
Regeln in `mrts.load`.

`make mrts-ftw` führt go-ftw direkt aus, wenn `go-ftw` und
`tests/mrts/ftw.mrts.config.yaml` sind verfügbar. Es ist optional und nicht Bestandteil
von `smoke-all`.

## Varianten und Ergebnisse

MRTS kombiniert mit den bestehenden CRS-Varianten:

```text
$BUILD_ROOT/results/no-crs/no-mrts
$BUILD_ROOT/results/no-crs/with-mrts
$BUILD_ROOT/results/with-crs/no-mrts
$BUILD_ROOT/results/with-crs/with-mrts
```

Wenn `RESULTS_DIR` explizit festgelegt ist, wird es von MRTS-Helfern beibehalten.

## Abdeckungsklassifizierung

Importierte MRTS-Fälle tragen `metadata.source: mrts` und werden nach Phase gezählt.
Topic, variable/collection, Connector-Bereich und MRTS-Korpus, wenn ihr Fallstammverzeichnis ist
wird durch `EXTRA_CASE_ROOTS` eingebunden.

Fälle werden nur dann mit `active` gekennzeichnet, wenn Anforderung, Erwartung, Phase und Variable vorliegen
Die Klassifizierung ist zuverlässig. Ansonsten sind sie mit `pending` gekennzeichnet:

```text
MRTS classification incomplete
```

Der generierte MRTS-Nachweis bleibt optional und variantenspezifisch. Das ist nicht der Fall
PASS-Status allein fördern und bestehende RESPONSE_BODY/phase-4 nicht befördern
Die Politik bleibt unverändert.

Berichtskategorien unterscheiden `runnable: upstream-config-tests`,
`optional/demo: feature-demo`, `golden-only: upstream-generated` und
`legacy/reference: framework-curated`.

## Natives Infrastruktur-Overlay

Das Framework enthält ein experimentelles NGINX PR24-Overlay
`tests/mrts/infra-overlays/nginx-pr24/`. Das Overlay wird bereitgestellt
`$MRTS_NATIVE_ROOT` für native MRTS-Läufe und alle Laufzeitpfade, Ports, Module,
Protokoll- und Befehlsänderungen erfolgen nur in dieser Staging-Kopie. Ersetzen Sie dieses Overlay
mit `$MRTS_ROOT/config_infra/nginx_linux` einmal MRTS PR 24 wird upstream zusammengeführt.
