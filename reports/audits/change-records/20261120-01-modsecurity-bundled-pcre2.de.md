# Change Record

**Sprache:** [English](20261120-01-modsecurity-bundled-pcre2.md) | Deutsch

**Prüfsnapshot vor der Veröffentlichung.** Dieser Record erfasst die implementierte Provisionierungsänderung sowie die beobachteten lokalen Prüfungen und Builds. Erfolg gehosteter CI, Merge oder Parent-Pinänderung werden nicht behauptet.

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261120-01-modsecurity-bundled-pcre2 |
| UTC-Datum | 2026-11-20 |
| Framework-Basisrevision | `95f228936efe17fda24f21323ad87cd698940b48` |
| Issue oder Pull Request | Draft-Pull-Request aus dem Aufgabenbranch `fix/modsecurity-bundled-pcre2-20261119`. |

## Motivation und Problemstellung

Das gemeinsame libModSecurity-Prefix (`v3.0.17`) wurde ohne `--with-pcre2` konfiguriert, gegen die PCRE2-Header der Distribution (10.46 auf dem lokalen Ubuntu-Testhost) kompiliert und ohne `DT_RUNPATH` veröffentlicht. Die Harnesses für NGINX, HAProxy und lighttpd setzen nur `MODSECURITY_LIB_DIR` auf den Bibliothekspfad, daher lud dort jeder libModSecurity-Prozess das PCRE2 der Distribution statt des zentralen Pins `PCRE2_VERSION=10.49` aus `ci/lib/common.sh`. Nur Apache lud das gepinnte PCRE2 über sein eigenes internes PCRE2-Prefix. PCRE2 ab 10.47 exportiert versionierte Symbole (`PCRE2_10.47`); ein gegen den Pin gebautes Binary kann von einer älteren Distributionsbibliothek nicht bedient werden, was der Loader als `no version information available` und der Linker als undefinierte Referenzen `pcre2_*@PCRE2_10.47` meldet.

## Betroffene Komponenten und Sicherheitsgrenzen

Die Änderung beschränkt sich auf den gemeinsamen libModSecurity-Cache-Eintrag aus `prepare-runtime-components.py`. Host-Harnesses, Adapter, Parent-Connectoren und MRTS bleiben unverändert. Das PCRE2-Archiv wird über den bestehenden digest-prüfenden Archiv-Cache mit dem verpflichtenden literalen Pin `PCRE2_SHA256` und derselben `PCRE2_SOURCE_URL` bezogen, die der Apache-Build bereits verwendet; es kommt kein neuer Netzwerkendpunkt hinzu. Die Extraktion nutzt den `tarfile`-Filter `data` und akzeptiert genau ein Wurzelverzeichnis.

## Akzeptanzkriterien

libModSecurity wird gegen das gepinnte PCRE2 kompiliert und gelinkt. Das veröffentlichte Prefix enthält die gepinnte `libpcre2-8.so.0` neben `libmodsecurity.so.3`; diese hat `NEEDED libpcre2-8.so.0`, `DT_RUNPATH` genau `$ORIGIN` und kein veraltetes `RPATH`. Jedes andere Ergebnis lässt den Build scheitern, und es wird nichts veröffentlicht. Die Cache-Identität bindet das PCRE2-Tupel und die Ausgabe-Layout-Version 2, sodass kein Layout-1-Eintrag wiederverwendet wird. Auch die mitgelieferten ModSecurity-Werkzeuge linken gegen den Pin. Ein fehlendes oder abweichendes Archiv, ein unlesbares Archiv, ein nicht ausführbares Build-Werkzeug und eine scheiternde `readelf`-Prüfung schlagen jeweils mit festgehaltenem Grund geschlossen fehl.

## Untersuchte Alternativen

Den PCRE2-Pfad in jede Harness aufzunehmen, beträfe fünf Adapter und erreichte Verbraucher ohne Harness wie CGo-Binaries trotzdem nicht. Eine eigene gemeinsame PCRE2-Cache-Komponente würde das Cache-Schema und jeden Connector-Schlüssel ändern. Ein absoluter `DT_RUNPATH` auf das endgültige Prefix ist zirkulär, weil der endgültige Pfad den aus den Build-Flags abgeleiteten Cache-Schlüssel enthält. Nachbearbeitung mit `patchelf` setzt ein Werkzeug voraus, das die Hosts nicht bereitstellen. PCRE2 im libModSecurity-Prefix mitzuliefern und per `$ORIGIN` zu finden, deckt jeden Verbraucher ab, der das Prefix lädt.

## Implementierungsentscheidung

`build_modsecurity_staging_entry` installiert zuerst das gepinnte PCRE2 in das Staging-Prefix (`./configure --prefix=<staging>`, dieselbe Konfiguration wie im Apache-Quellbuild) und entfernt dessen libtool-Archive, damit libtool den temporären Staging-Pfad nicht fest einträgt. Danach wird ModSecurity mit `--with-pcre2=<staging>` konfiguriert. Die Build-Umgebung setzt `LD_RUN_PATH=$ORIGIN`, das der Linker unverändert übernimmt, wenn kein explizites `-rpath` angegeben ist. Außerdem stellt sie `-L<staging>/lib` an die erste Stelle, damit Abhängigkeits-Flags wie `-L/usr/lib/<triplet>` die mitgelieferten Werkzeuge, Beispiele und Testprogramme nicht auf das PCRE2 der Distribution lenken. Automake setzt zielspezifische `*_LDFLAGS` vor `$(LDFLAGS)`, daher wird das Flag an die Befehle `CC` und `CXX` angehängt (die Compiler, die `toolchain_identity()` erfasst) und zusätzlich `LDFLAGS` vorangestellt; jede Link-Zeile beginnt mit dem Compilerbefehl. Der Staging-Pfad bleibt außerhalb der Cache-Identität. Nach dem Kopieren der Ausgaben prüft `modsecurity_bundled_pcre2_blocker` Header, Bibliothek und die dynamischen ELF-Einträge per `readelf -d`. `readelf` ist nun ein erforderliches Build-Werkzeug. `MODSECURITY_OUTPUT_LAYOUT_VERSION` ist 2, und die `extra_inputs` der Identität erhalten `bundled_pcre2` (Version, Quell-URL, SHA-256, Run-Path).

## Geänderte Dateien und Tests

- `connector_suite/modsecurity_connector_ci/provisioning/components/prepare-runtime-components.py`: mitgeliefertes PCRE2, Run-Path-Prüfung, Identität und geschlossen scheiternde Fehlerpfade.
- `connector_suite/modsecurity_connector_tests/test_runtime_component_cache_contract.py`: acht neue On-Demand-Tests (Identitätsbindung, Configure- und Umgebungs-Flags einschließlich Compiler-Präfix und `LDFLAGS`-Reihenfolge, `$ORIGIN`-Prüfung gegen fehlenden, Staging- und veralteten Run-Path, scheiternde ELF-Prüfung, Archivaufbau, unlesbares Archiv, nicht ausführbare PCRE2- und ModSecurity-Build-Werkzeuge, persistierter Prüffehler); der Staging-Build-Test simuliert die neue PCRE2-Stufe; der Layout-Versions-Test patcht die aktuelle Version plus eins.
- `connector_suite/config/testing/active-cases.json`: Quell-Digest über `update-inventory-bindings.py --apply` erneuert; kein aktiver Fall hinzugefügt oder entfernt.
- `connector_suite/reports/testing/test-selection-archive.generated.json`: Aktualisierung über den nativen Generator (`update-test-archive.py`) für die acht neuen On-Demand-Tests; On-Demand-Definitionen 8476 auf 8484, und `inventory_sha256` ändert sich mit dem erneuerten Quell-Digest.
- `docs/reference/variables.md`, `docs/reference/variables.de.md`: die PCRE2-Zeile beschreibt das mitgelieferte Prefix und den Run-Path-Vertrag.
- `reports/audits/change-records/20261120-01-modsecurity-bundled-pcre2.md` und `.de.md`: dieses Record-Paar.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `readelf -d` / `ldd` auf dem bestehenden Layout-1-Prefix | 0 | Kein `RUNPATH`; NGINX, sein Modul und libModSecurity lösten `libpcre2-8.so.0` gegen die Distributionsbibliothek auf. | Lokale Diagnose `devtest-20261119T093840Z` |
| `update-inventory-bindings.py --check`, danach `--apply`, danach `--check` | 1, 0, 0 | Eine Drift (`prepare-runtime-components.py`), aktualisiert, danach `INVENTORY_BINDINGS_VERIFIED`. | Lokale Framework-Validierung |
| `ON_DEMAND_TESTS=1 python -P -m unittest` für `test_runtime_component_cache_contract` und `test_runtime_component_cache_identity` | 0 | 64 Tests bestanden; ein früherer Lauf scheiterte an einem Staging-Build-Test, der die PCRE2-Stufe noch nicht simulierte. Ausdrückliche Nutzerfreigabe für genau diese zwei archivierten Module. | Lokale Framework-Validierung |
| `update-test-archive.py --check`, nativer Generator, `--check` | 1, 0, 0 | Das gehostete `scaffold-lint` meldete beim ersten Push das veraltete Archiv; neu erzeugt, danach `Specialist archive matches current inventory and retained source definitions`. | Lokale Framework-Validierung |
| `make check-variable-documentation`, `make check-doc-links` | 0, 0 | Variablendokumentation und Links bestanden. | Lokale Framework-Validierung |
| `sonar analyze secrets --stdin` auf jeder geänderten Datei | 0 | Alle ausgewählten Eingaben bestanden; rohe Scannerausgabe unterdrückt. | Lokale Framework-Validierung |
| `make prepare-runtime-components RUNTIME_COMPONENT_TARGET=all`, Zwischenrevision | 2 | PCRE2 10.49 in das Staging-Prefix gebaut; ModSecurity-`configure` erkannte dort `PCRE2_VERSION=10.49`, und `libmodsecurity.so` wurde gelinkt; das mitgelieferte `modsec-rules-check` scheiterte mit undefinierten `pcre2_*@PCRE2_10.47`, weil `-L/usr/lib/<triplet>` vor dem mitgelieferten Pfad stand. Daraus folgte die `LDFLAGS`-Reihenfolge. | Lokaler Lauf `pcre2-bundle-20261119` |
| Dasselbe Ziel mit `LDFLAGS`-Reihenfolge, in einem privaten Mount-Namespace | 2 | `modsec-rules-check` linkte nun gegen das mitgelieferte PCRE2; `examples/multithread` scheiterte auf dieselbe Weise, weil sein zielspezifisches `multithread_LDFLAGS` vor `$(LDFLAGS)` steht. Daraus folgte das Compiler-Präfix der finalen Revision. Aus dem Home-Verzeichnis wurden nur Go-Telemetriezähler umgeleitet. | Lokaler Lauf `pcre2-bundle-r2-20261120` |
| Dasselbe Ziel mit der finalen Revision, in einem privaten Mount-Namespace mit schreibgeschütztem Quell-Checkout | 0 | libModSecurity veröffentlicht mit `NEEDED libpcre2-8.so.0`, `DT_RUNPATH` genau `$ORIGIN` und der gepinnten `libpcre2-8.so.0` (10.49, Symbolversionen `PCRE2_10.47` bis `PCRE2_10.49`) im eigenen `lib/`; ohne `LD_LIBRARY_PATH` wird das mitgelieferte PCRE2 aufgelöst. Die Connector-Builds für Apache, NGINX und HAProxy wurden dagegen abgeschlossen. Mit den Harness-Bibliothekspfaden lösen `httpd`, `mod_security3.so`, NGINX und sein Modul PCRE2, APR, APR-util und libModSecurity ausschließlich aus dem externen Cache auf. Nur Go-Telemetriezähler wurden umgeleitet; in keinem Worktree entstand ein Build-Artefakt. | Lokaler Lauf `pcre2-bundle-r3-20261120` |
| `make prepare-envoy-runtime`, `prepare-traefik-runtime`, `prepare-lighttpd-runtime` | 0, 0, 0 | Nicht betroffene Open-Connector-Runtimes wurden bereitgestellt. | Lokaler Lauf `pcre2-bundle-20261119` |

Der verifizierte Build nutzte Revision `059c714f` von `prepare-runtime-components.py`; die finale Revision hält nur den PCRE2-Prüfgrund fest, bevor das Fehlermanifest geschrieben wird, was ein Unit-Test abdeckt. Der Build lief mit Python 3.15.2, GCC 15.2.0, Parent-Revision `b79c3d93efbb8330f121caf8fb7c1a7874195e57` und dieser Framework-Basis plus Aufgabenänderungen. Cache-, Build-, Log- und temporäre Roots lagen außerhalb beider Git-Worktrees.

## Sicherheitsauswirkung

Die Änderung entfernt einen stillen Rückfall auf eine ungeprüfte Distributionsbibliothek zur Laufzeit und behält die bestehende Pflicht eines literalen Digests für das PCRE2-Archiv bei. Die Veröffentlichung scheitert nun geschlossen, wenn Run-Path oder mitgelieferte Bibliothek nicht dem Vertrag entsprechen. Keine Validierungs-, Authentisierungs-, Isolations- oder Schwärzungsregel wird abgeschwächt. Andere libModSecurity-Abhängigkeiten (libxml2, curl, Lua, YAJL, MaxMindDB, ssdeep) kommen weiterhin aus der Distribution und liegen außerhalb des Umfangs.

## Dokumentation und Runtime-Evidenz

Dieses englisch/deutsche Record-Paar und die englisch/deutsche Variablenreferenz dokumentieren denselben Umfang. Die lokalen Builds belegen nur die Provisionierungsebene; ein Connector-Runtime-Smoke-, Lifecycle- oder Matrixergebnis wird nicht behauptet.

## Nicht ausgeführte Prüfungen

Gehostete CI, ein vollständiger `quick-check`, die Standardsuite `make test`, Connector-Runtime-Smokes und der übrige archivierte On-Demand-Katalog sind für diesen Snapshot nicht gelaufen. Der NGINX-Build kompiliert weiterhin gegen die PCRE2-Header der Distribution und ist nicht Teil dieser Änderung.

## Einschränkungen und Restrisiko

NGINX- und HAProxy-Binaries laden das mitgelieferte PCRE2 nur über `MODSECURITY_LIB_DIR` im Harness-Bibliothekspfad; NGINX wird noch nicht mit einem Run-Path dorthin gelinkt. Der Run-Path von Apache `httpd` zeigt weiterhin auf sein temporäres Staging-Verzeichnis (bereits vorher so) und hängt daher ebenfalls vom Harness-Bibliothekspfad ab. Ein Host ohne `readelf` blockiert den libModSecurity-Build jetzt mit `missing_readelf`.

## Finaler Diff- und Review-Status

Der finale Diff enthält die sechs geänderten Dateien und dieses Record-Paar. Unit-Tests, Inventarbindungen, Dokumentationsprüfungen, Secrets-Scans und die Whitespace-Prüfung bestanden. Die Framework-Auslieferung bleibt von Parent- und MRTS-Auslieferung getrennt; der Parent-Framework-Gitlink bleibt unverändert, und ein Merge wird nicht behauptet.
