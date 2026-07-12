# Connector-Code-Importplan

**Sprache:** [English](connector-code-import-plan.md) | Deutsch

Status: umgesetzt

Dieses Dokument definiert den kontrollierten Importpfad für den vorhandenen Apache und
NGINX Anschlüsse. Die externen Repositorys bleiben schreibgeschützte Quellen. Lokal
Pfade sind Beispiele; Upstream-GitHub-Repositorys sind die portablen Referenzen:

| Connector | Lokaler Bezug | Stromaufwärts |
| --- | --- | --- |
| Apache | `/root/conecter/ModSecurity-apache` | https://github.com/owasp-modsecurity/ModSecurity-apache |
| NGINX | `/root/conecter/ModSecurity-nginx` | https://github.com/owasp-modsecurity/ModSecurity-nginx |

Importierter und migrierter Connector-Code wird in Connector-spezifischen Bereichen gespeichert:

- `connectors/apache/src/`
- `connectors/nginx/src/`

In diesem Schritt wird kein Apache- oder NGINX-Code in `common/` verschoben. Ersteres
`upstream/`-Verzeichnisse waren temporäre reference/import-Datenbanken und wurden entfernt
Erst nachdem die Funktionalität in den gepflegten Projektcode verschoben wurde, blieb der Ursprung bestehen
dokumentiert, und reale Smokeentwicklungen gingen vorüber. NGINX hat diesen Zustand in Phase 10 erreicht.
Apache hat diesen Zustand in Phase 11 erreicht: seine Modulquelle, Autotools/APXS
Eingaben und erforderliche `.in`-Vorlagen sind jetzt unter `connectors/apache/src` verfügbar.
und der ehemalige `connectors/apache/upstream/`-Baum wurde nach einem frischen entfernt
Materialisierter Aufbau und Smokedurchgang vergingen.

## Quellrevisionen

| Connector | Lokaler Bezug | Stromaufwärts | Beobachteter Commit | Beobachtet version/tag | Lizenz |
| --- | --- | --- | --- | --- | --- |
| Apache | `/root/conecter/ModSecurity-apache` | https://github.com/owasp-modsecurity/ModSecurity-apache | `0488c77f69669584324b70460614a382224b4883` | `v0.0.9-beta1-26-g0488c77` | Apache-2.0 |
| NGINX | `/root/conecter/ModSecurity-nginx` | https://github.com/owasp-modsecurity/ModSecurity-nginx | `9eb44fd9ab0988756e1ab8ce5aa5548ddbe57846` | `v1.0.4-14-g9eb44fd` | Apache-2.0 |

## Grenze importieren

Die Quelle im Besitz des Apache-Adapters umfasst Quell- und Autotools/APXS-Build-Eingaben
nur:

- `LICENSE`, `AUTHORS`, `CHANGES`, `README.md`
- `autogen.sh`, `configure.ac`, `Makefile.am`
- `build/apxs-wrapper.in`, `build/ax_prog_apache.m4`,
`build/find_apxs.m4`, `build/find_libmodsec.m4`
- Connector-Quelldateien unter `src/`
- minimale Apache-Testvorlagen, auf die in `configure.ac` verwiesen wird

NGINX Adaptereigene Quelle enthält nur Quell- und NGINX Modul-Build-Eingaben:

- `config` unter `connectors/nginx/src`
- Connector-Quelldateien unter `connectors/nginx/src`
- `SOURCE_MAP.json` Aufzeichnung des Basis-Upstream-Commits und PR #377 Patch
  Herkunft

Apache- und NGINX-Attributionsdateien bleiben unter `licenses/apache/` und
`licenses/nginx/`; Nach der Phase bleibt kein lokaler `connectors/*/upstream/`-Baum übrig
11.

Folgendes wird absichtlich nicht importiert:

- `.git`, `.github`, `.travis.yml`, Release-Skripte, Windows-Build-Bäume
- generierte Autotools-Dateien, `.deps`, Objektdateien, Bibliotheken, Protokolle, Caches
- Komplette Upstream-Testsuiten als Rohkopien
- Laufzeitdateien, die von lokalen Smoke-Läufen generiert werden

## Verwendung von Harnessesn

`modules/ModSecurity-test-Framework/ci/provisioning/prepare-apache-build.sh` und `modules/ModSecurity-test-Framework/ci/provisioning/prepare-nginx-build.sh` verwenden das
Adaptereigene Monorepo-Quellen standardmäßig, wenn Connector-Quellumgebungsvariablen vorhanden sind
nicht gesetzt:

- `MODSECURITY_APACHE_SOURCE_DIR=connectors/apache`
- `MODSECURITY_NGINX_SOURCE_DIR=connectors/nginx`

Externe Quellen werden weiterhin unterstützt, indem diese Umgebungsvariablen explizit festgelegt werden. Die
Helfer kopieren oder materialisieren immer noch Quellen in `$BUILD_ROOT`, bevor sie bauen.
Sie erstellen oder verändern den Quell-Checkout nicht direkt.

Für Monorepo-Standard-NGINX-Builds ist die direkte Build-Eingabe jetzt die generierte
`$BUILD_ROOT/nginx-build/connector-src` Baum. Es wird materialisiert aus
Nur Adapter-eigene `connectors/nginx/src/`-Quellen und generierte Manifeste. Die
NGINX `config` Datei wird im Stammverzeichnis gespeichert `config`; Adapter-Quelldateien
erfolgen unter `src/`.

Für Monorepo-Standard-Apache-Builds wird Phase 11 generiert
`$BUILD_ROOT/apache-build/connector-src` aus `connectors/apache/src` und Verwendungen
dieser materialisierte Baum als produktive Autotools/APXS Build-Eingabe.

## Priorität der Berichtsmetadaten

Smokezusammenfassungen verwenden Connector-Ursprungsmetadaten in dieser Reihenfolge:

1. explizit `APACHE_ORIGIN_*`, `NGINX_ORIGIN_*` oder `CONNECTOR_ORIGIN_*`
   Umgebungsüberschreibungen;
2. Quellmetadaten des externen Connectors vom lokalen Git, wenn ein expliziter externer
   `MODSECURITY_APACHE_SOURCE_DIR` oder `MODSECURITY_NGINX_SOURCE_DIR` wird verwendet;
3. Adaptereigene Metadaten, geparst aus `connectors/apache/metadata.c` oder
   `connectors/nginx/metadata.c` für die Standard-Monorepo-Importe.

Bei den Adaptermetadaten handelt es sich ausschließlich um report/build-summary-Daten. Es ist nicht verlinkt
die Apache- oder NGINX-Module und ändert das Laufzeitverhalten des Connectors nicht.

`ci/checks/catalog/check-adapter-metadata-drift.sh` hält diese Adapter-eigenen Werte ausgerichtet
mit den Ursprungskarten, Lizenzdokumenten und Importdokumentation. Das generierte
Schattenquellenmanifeste beschreiben die Build-Kopie-Zusammensetzung; zusammenfassende Ursprungsmetadaten
beschreibt weiterhin die Herkunft der Quelle.

## Risiken

| Risiko | Auswirkungen | Kontrolle |
| --- | --- | --- |
| Lebenszykluskonflikt zwischen Apache und NGINX | Gemeinsam genutzter Code könnte das Hook-spezifische Verhalten verlieren | Halten Sie die Importe getrennt; Keine `common/`-Extraktion in diesem Schritt |
| Buildsystem-Annahmen | Die Modul-Builds Autotools/APXS und NGINX haben unterschiedliche Eingaben | Behalten Sie native Build-Eingaben und Dokumentbefehle bei |
| Verhalten des Antwortfilters | Phase 4 und `RESPONSE_BODY` unterscheiden sich je nach Anschluss | Behalten Sie die Blockierung des Antworttexts mapped/former bei erwartetem Fehler bei, bis dies nachgewiesen ist |
| Unterschiede im Audit-Log | Die Connector/runtime-Konfiguration kann sich auf Protokollartefakte auswirken | Verwenden Sie nur vorhandene Smokezusammenfassungen aus der Praxis |
| Flussaufwärts gelegene Herkunftsdrift | Importierte Dateien können von den Quell-Repos abweichen | Pflegen Sie `ORIGIN.md` mit Commit und Quellpfad |

## PR #377 Status

ModSecurity-nginx PR #377
(https://github.com/owasp-modsecurity/ModSecurity-nginx/pull/377) wurde abgerufen
nur unter `$BUILD_ROOT` zur Überprüfung. Quelländerungen von PR Kopf
`3d72b004ff27a78ea19c6b945870e2cae62a97ac` wurden auf den Adapter angewendet, der sich im Besitz des Adapters befindet
NGINX Body-Filter, gemeinsamer Header und Moduldatei. Rohe PR Tests und Dokumente waren
nicht kopiert. Das Verhalten der Phase 4 bleibt evidenzsensitiv und
`RESPONSE_BODY` wird durch diese Quellmigration nicht als verifiziert gezählt.

## Annahme

Dieser Import ist nur akzeptabel, wenn:

- importierte Dateien sind in `connectors/apache/ORIGIN.md` und dokumentiert
  `connectors/nginx/ORIGIN.md`;
- `make lint` besteht;
- Apache- und NGINX-Smoketests durchlaufen weiterhin echte Server-Connector-Pfade;
- Externe Quellrepositorys bleiben unverändert.

## Beobachtete Verifizierung

Beobachtet, nachdem die Build-Helfer standardmäßig auf Monorepo-Importe verkabelt wurden:

```sh
REFRESH=1 BUILD_ROOT=/src/ModSecurity-conector-import-build \
  BUILD_HTTPD_FROM_SOURCE=1 BUILD_NGINX_FROM_SOURCE=1 make smoke-apache

REFRESH=1 BUILD_ROOT=/src/ModSecurity-conector-import-build \
  BUILD_HTTPD_FROM_SOURCE=1 BUILD_NGINX_FROM_SOURCE=1 make smoke-nginx

BUILD_ROOT=/src/ModSecurity-conector-import-build make smoke-all
BUILD_ROOT=/src/ModSecurity-conector-build make smoke-all
```

Alle aufgelisteten Smokebefehle wurden mit `pass`-Ergebnissen abgeschlossen. Phase 9 ändert die
NGINX monorepo-default Quellpfad zu `connectors/nginx/src`; generierter Build,
log und Laufzeitartefakte bleiben unter den konfigurierten `BUILD_ROOT`-Werten.
