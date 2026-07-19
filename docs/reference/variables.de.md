# Framework-Variablen und Platzhalter

**Sprache:** [English](variables.md) | Deutsch

Diese Referenz beschreibt Werte, die ein Aufrufer beim Test-Framework setzen
kann. Ein Beispiel erklärt seine wichtigsten Eingaben zusätzlich direkt vor
oder nach dem Befehl; diese Seite ist die zentrale Referenz für wiederkehrende
Namen.

## Schnellreferenz

| Variable | Bereich | Pflicht | Standard | Format | Kurzbeschreibung |
|---|---|---:|---|---|---|
| [`FRAMEWORK_ROOT`](#framework_root) | Pfade | Nein | Framework-Checkout | absoluter Pfad | Wurzel dieses Framework-Repositorys |
| [`CONNECTOR_ROOT`](#connector_root) | Pfade | zielabhängig | aktuelles Verzeichnis | absoluter Pfad | Wurzel des Connector-Repositorys |
| [`BUILD_ROOT`](#build_root-source_root-tmp_root-und-log_root) | Build | Nein | zustandslokaler Pfad | absoluter, beschreibbarer Pfad | generierte Build-Artefakte |
| [`SOURCE_ROOT`](#build_root-source_root-tmp_root-und-log_root) | Provisionierung | Nein | zustandslokaler Pfad | absoluter Pfad | Quelle für abgerufene Komponenten |
| [`TMP_ROOT`](#build_root-source_root-tmp_root-und-log_root) | Runtime | Nein | unter `BUILD_ROOT` | absoluter, beschreibbarer Pfad | temporäre Runtime-Dateien |
| [`LOG_ROOT`](#build_root-source_root-tmp_root-und-log_root) | Logging | Nein | unter `BUILD_ROOT` | absoluter, beschreibbarer Pfad | Build- und Runtime-Logs |
| [`EVIDENCE_ROOT`](#evidence_root) | Evidence | Nein | unter `BUILD_ROOT` | absoluter, beschreibbarer Pfad | No-CRS-Evidence-Läufe |
| [`NO_CRS_RUN_ID`](#no_crs_run_id) | No-CRS | kanonische Läufe | `local` | dateisystemsicheres Token | Kennung eines Evidence-Laufs |
| [`CONNECTOR`](#connector-capabilities_file-evidence_stage-und-no_crs_artifact_profile) | No-CRS | Connector-Ziele | keiner | Connector-Schlüssel | Auswahl des Capability-Manifests |
| [`PYTHON`](#werkzeuge-statuswerte-und-sensible-daten) | Werkzeuge | Nein | `.venv/bin/python` oder `python3` | Pfad zu ausführbarem Programm | Interpreter für Make |
| [`PROTOCOL_URL`](#protocol_url) | Protokoll | `protocol-client` | keiner | `http(s)://`-URL | explizites Client-Ziel |

## Repository-, Build- und Runtime-Pfade

### `FRAMEWORK_ROOT`

| Eigenschaft | Bedeutung |
|---|---|
| Zweck | Findet Framework-Tests, CI-Werkzeuge, Katalogdateien und Framework-Berichte. |
| Format | Absoluter Pfad zum Checkout dieses Repositorys. |
| Pflicht | Für Make optional; erforderlich, wenn ein verschachteltes CI-Skript aus einem anderen Verzeichnis gestartet wird. |
| Standard | Framework-Checkout; das CI-Pfad-Bootstrap erkennt ihn vom Einstiegspunkt aus. |
| Gesetzt durch | Makefile, Aufrufer oder CI-Pfad-Bootstrap. |
| Gültigkeit | Ein Befehl und seine Kindprozesse. |
| Beispiel | `/work/ModSecurity-test-Framework` |
| Auswirkung | Ändert, wo Framework-eigener Quellcode und Dokumentation gelesen werden. |
| Sicherheit | Keinen Checkout ausführen, dem Sie nicht vertrauen. |

### `CONNECTOR_ROOT`

| Eigenschaft | Bedeutung |
|---|---|
| Zweck | Findet Connector-Quellcode, Capability-Manifeste und Connector-Berichte. |
| Format | Absoluter Pfad zur Wurzel des Connector-Repositorys. |
| Pflicht | Erforderlich, wenn ein Ziel Connector-eigene Dateien liest; für reine Framework-Katalogchecks optional. |
| Standard | Für die meisten Ziele aktuelles Verzeichnis; für Framework-Berichtsaktualisierungen Framework-Wurzel. |
| Gesetzt durch | Aufrufer, Makefile oder Runtime-Skript. |
| Gültigkeit | Ein Connector-Befehl oder Berichts-Generierungslauf. |
| Beispiel | `/work/ModSecurity-conector` |
| Auswirkung | Wählt `connectors/<connector>/` und `reports/testing/`. |
| Sicherheit | Muss vertrauenswürdig sein; Schreiber validieren Ausgabepfade. |

### `BUILD_ROOT`, `SOURCE_ROOT`, `TMP_ROOT` und `LOG_ROOT`

| Eigenschaft | `BUILD_ROOT` | `SOURCE_ROOT` | `TMP_ROOT` | `LOG_ROOT` |
|---|---|---|---|---|
| Zweck | Build-Ausgabe | Quellen | temporäre Dateien | Diagnosen |
| Format | absoluter, beschreibbarer Pfad | absoluter Pfad | absoluter, beschreibbarer Pfad | absoluter, beschreibbarer Pfad |
| Pflicht | optional | optional | optional | optional |
| Repository-Standard | zustandslokal | zustandslokal | `BUILD_ROOT/tmp` | `BUILD_ROOT/logs` |
| Gesetzt durch | Makefile, `ci/lib/common.sh` oder Aufrufer | gleich | gleich | gleich |
| Beispiel | `<temporary-work-root>/build` | `<temporary-work-root>/src` | `<temporary-work-root>/tmp` | `<temporary-work-root>/logs` |
| Auswirkung | hält generierte Ausgabe außerhalb von Git | wählt Quellen | isoliert flüchtige Dateien | wählt Log-Speicherort |
| Sicherheit | keinen Checkout oder unisolierten gemeinsamen Pfad verwenden | Herkunft prüfen | vor Freigabe prüfen | vor Freigabe prüfen |

Die Beispiele sind temporäre Runtime-Pfade, keine repository-relativen Pfade
und keine verpflichtenden Host-Standards.

## Evidence und No-CRS

### `EVIDENCE_ROOT`

| Eigenschaft | Bedeutung |
|---|---|
| Zweck | Wurzel für kanonische No-CRS-Evidence-Verzeichnisse. |
| Format | Absoluter, beschreibbarer Pfad. |
| Pflicht | Lokal optional; für einen veröffentlichten kanonischen Lauf benötigt. |
| Standard | `BUILD_ROOT/no-crs-evidence`. |
| Gesetzt durch | Makefile oder Aufrufer. |
| Gültigkeit | Ein oder mehrere Evidence-Läufe. |
| Beispiel | `<temporary-work-root>/evidence` |
| Auswirkung | Enthält `<connector>/<run-id>/`-Artefakte. |
| Sicherheit | Keine Secrets, Benutzernamen oder Tickettexte im Pfad verwenden. |

### `NO_CRS_RUN_ID`

| Eigenschaft | Bedeutung |
|---|---|
| Zweck | Kennzeichnet einen Evidence-Lauf. |
| Format | Kurzes, dateisystemsicheres Token ohne `/` oder `..`. |
| Pflicht | Für kanonische Evidence erforderlich; lokal optional. |
| Standard | `local`. |
| Gesetzt durch | Aufrufer, Workflow oder Orchestrator. |
| Gültigkeit | Ein vollständiger Connector- oder Aggregatlauf. |
| Beispiel | `six-connectors-core-20260712T164725Z` |
| Auswirkung | Benennt Evidence-, Plan-, Summary- und Log-Unterverzeichnisse. |
| Sicherheit | Niemals Zugangsdaten, personenbezogene Daten oder Kunden-IDs verwenden. |

### `CONNECTOR`, `CAPABILITIES_FILE`, `EVIDENCE_STAGE` und `NO_CRS_ARTIFACT_PROFILE`

| Variable | Zweck | Pflicht | Standard | Beispiel |
|---|---|---:|---|---|
| `CONNECTOR` | Wählt den Connector-Katalogkontext. | Ja für Connector-Ziele | keiner | `nginx` |
| `CAPABILITIES_FILE` | Manifest für Auswahl und Validierung. | Nein | `CONNECTOR_ROOT/connectors/CONNECTOR/capabilities.json` | `/work/ModSecurity-conector/connectors/nginx/capabilities.json` |
| `EVIDENCE_STAGE` | Vorhandene aufzuzeichnende Stage. | Nein | `no_crs_baseline` | `minimal_runtime_smoke` |
| `NO_CRS_ARTIFACT_PROFILE` | Vorhandenes Artefakt-Layoutprofil. | Nein | `generic` | `full_lifecycle` |

Aufrufer oder Makefile setzen diese Werte für eine plan/init/finalize-Sequenz.
Sie verändern Auswahl- und Validierungspfade, niemals Connector-Runtime-Semantik.
Nur kataloggestützte Werte verwenden. Zugehörige Orchestrierungswerte sind
`NO_CRS_RUN_DIR`, `PLAN_FILE`, `NO_CRS_STAGE_RC`, `NO_CRS_STAGE_REASON`,
`NO_CRS_FINALIZE_ARGS`, `NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR` und
`NO_CRS_SUMMARY_ROOT`; ihre Standards liegen unter `BUILD_ROOT` oder
`EVIDENCE_ROOT`. `NO_CRS_STAGE_REASON` darf keine Secrets oder
personenbezogenen Daten enthalten.

## Protokoll, Cache und Provisionierung

### `PROTOCOL_URL`

| Eigenschaft | Bedeutung |
|---|---|
| Zweck | Expliziter Endpunkt für `make protocol-client`. |
| Format | `http://`- oder `https://`-URL. |
| Pflicht | Ja für `make protocol-client`. |
| Standard | Kein Standard. |
| Gesetzt durch | Aufrufer oder Workflow. |
| Gültigkeit | Ein `protocol-client`-Aufruf. |
| Beispiel | `https://127.0.0.1:8443/phase4` |
| Auswirkung | Wählt das Ziel, das in payload-freier Client-Evidence protokolliert wird. |
| Sicherheit | Test-URLs können interne Hostnamen offenlegen. |

`PROTOCOL_PROFILE` hat den Standard `http1`; `PROTOCOL_ARTIFACT_DIR` liegt
unter `BUILD_ROOT`; `PROTOCOL_STRICT` und `PROTOCOL_INSECURE` haben den
Standard `0`. `PROTOCOL_FOLLOWUP_URL` ist nur für strikte Evidence erforderlich.
Optionale Bindungsfelder sind `PROTOCOL_CONNECTOR`, `PROTOCOL_INTEGRATION_MODE`,
`PROTOCOL_RUN_ID`, `PROTOCOL_TRANSACTION_ID`, `PROTOCOL_TRANSPORT_CASE_ID`,
`PROTOCOL_RULE_ID`, `PROTOCOL_PHASE`, `PROTOCOL_STREAM_ID`,
`PROTOCOL_UPSTREAM_PROTOCOL`, `PROTOCOL_QUIC_UDP_OBSERVED` und
`PROTOCOL_OBSERVATION_SIDECAR`. `PROTOCOL_CACERT` ist ein Zertifikatspfad;
ein privater Schlüssel ist geheim und darf hier niemals übergeben oder
aufgezeichnet werden.

Die stabilen öffentlichen Targets behalten ihre Namen mit Bindestrichen und
verwenden gepflegte Tools mit Unterstrichen: `make protocol-client` führt
`ci/checks/protocol/protocol_client.py` aus,
`make check-protocol-evidence` führt
`ci/checks/protocol/check_protocol_evidence.py` aus und
`make check-transport-hardening-evidence` führt
`ci/checks/evidence/check_transport_hardening_evidence.py` aus.

`MRTS_ROOT`, `MRTS_BUILD_ROOT`, `MRTS_DEFINITIONS`, `MRTS_RULES_OUT`,
`MRTS_FTW_OUT`, `MRTS_LOAD_FILE` und `MRTS_CASE_ROOT` wählen vorhandene
MRTS-Eingaben oder generierte Pfade. `MODSECURITY_MRTS_VARIANT` akzeptiert
`no-mrts` oder `with-mrts`; `MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO=1`
aktiviert optionale Demo-Inhalte erst nach Kollisionsprüfungen.

`CRS_APPROVED_REPO_URL` und `CRS_APPROVED_COMMIT` sind zentrale literale
Provenance-Werte in `ci/lib/common.sh`, derzeit
`https://github.com/coreruleset/coreruleset.git` und
`55b09f5acfd16413e7b31041100711ceb7adc89c`. Sie sind keine Caller-Eingaben.
`CRS_GIT_REF=v4.28.0` bleibt zentrale Release-Metadaten für die
Versionsberichterstattung; es ist niemals ein Git-Selektor. `fetch-crs.sh`
weist eine abweichende `CRS_REPO_URL` oder `CRS_GIT_REF` vor der
Git-Ausführung ab, und Umgebungsversuche zum Ersetzen der beiden freigegebenen
Provenance-Literale werden durch die zentrale Definition überschrieben.

`CRS_SOURCE_DIR` muss ein nicht vorhandener Pfad unter dem zulässigen externen
`SOURCE_ROOT` sein; ein vorhandenes Verzeichnis oder ein Link wird nicht
wiederverwendet, sondern abgewiesen. Der Fetch-Pfad initialisiert ein frisches
Repository, setzt und liest den exakten HTTPS-Origin zurück, lädt nur den
freigegebenen vollständigen Commit ohne Tags oder rekursive Submodule und
vergleicht `FETCH_HEAD^{commit}`, das aufgelöste Commit-Objekt und das finale
`HEAD^{commit}` mit derselben Identität. Ein `.gitmodules`-Manifest wird
fail-closed abgewiesen, bis eine separat freigegebene
Submodule-Provenance-Regel existiert. `CRS_RUNTIME_DIR` und
`MODSECURITY_RULE_PREAMBLE_FILE` bleiben Runtime-Pfadeingaben. CRS-Pins nicht
in Workflows duplizieren. `CACHE_ROOT`, `VERIFIED_COMPONENT_CACHE` und
`CONNECTOR_COMPONENT_CACHE` sind Cache-Pfade und benötigen Herkunftsprüfungen.

## Werkzeuge, Statuswerte und sensible Daten

`PYTHON` verwendet `.venv/bin/python`, falls vorhanden, sonst `python3`.
`PYTHONDONTWRITEBYTECODE=1` ist Repository-Standard. `REFRESH`, `SMOKE_CASES`,
`CASE_SCOPE`, `FORCE_ALL_CASES`, `EXTRA_CASE_ROOTS`, `RESULTS_DIR` und die
`VERIFIED_*`-Wurzeln begrenzen vorhandene Läufe; sie fügen keine Fähigkeiten
oder Fälle hinzu. Connector-Familienüberschreibungen (`APXS_*`, `NGINX_*`,
`HAPROXY_*`, `ENVOY_*`, `TRAEFIK_*` und `LIGHTTPD_*`) sind optionale
Überschreibungen der gepinnten Standards in `ci/lib/common.sh`.

`make lint` ist statische Validierung, kein Runtime-Beweis.
`make check-no-crs-catalog` validiert die Katalogstruktur.
`make protocol-client` benötigt `PROTOCOL_URL`. Exit `0` bedeutet nur, dass
der aufgerufene Befehl seine Checks abgeschlossen hat; es bedeutet nicht, dass
jeder Katalogfall PASS ist. `1` ist ein allgemeiner Fehler, `2` ein ungültiges
Argument oder ein Vertragsfehler und `77` eine ausdrücklich nicht verfügbare
Voraussetzung. Fallstatus sind `PASS`, `FAIL`, `BLOCKED`, `NOT EXECUTED`,
`NOT APPLICABLE` und `UNSUPPORTED`; siehe [Glossar](glossary.de.md).

Private Schlüssel, Tokens, Cookies, Authorization-Header, Passwörter, API-Keys
und Client-Secrets niemals in kanonische Evidence committen, loggen oder
kopieren. In einem nicht ausführbaren Beispiel `<secret-from-secure-store>`
statt eines Wertes verwenden.

## Weitere dokumentierte Eingaben und Platzhalter

Die folgenden Werte erscheinen in fokussierten Build-, Import-, Test- oder
historischen Kompatibilitäts-Guides. Sie sind optionale Überschreibungen, sofern
das benannte Target nichts anderes verlangt. Ihre Quelle der Wahrheit ist das
Target oder `ci/lib/common.sh`; ein leerer oder nicht verfügbarer Wert muss zu
einem klaren Voraussetzung-Fehler führen, nicht zu einem angenommenen PASS.
Build-Pfade sind absolute Runtime-Pfade und sollen außerhalb des Git-Worktrees
liegen. Versions-, URL- und Prüfsummenüberschreibungen benötigen vor der Nutzung
eine Herkunftsprüfung.

| Namen | Bereich und Format | Standard / gesetzt durch | Beispiel und Sicherheitshinweis |
|---|---|---|---|
| `ALLOW_EXTERNAL_CONNECTOR_REPOS` | Boolean zur Quellenbeschaffung | `0`; Aufrufer oder CI | `1` stimmt externen Source-Fetches zu; Repository vorher prüfen. |
| `BUILD_HTTPD_FROM_SOURCE`, `BUILD_NGINX_FROM_SOURCE`, `BUILD_PCRE2_FROM_SOURCE`, `XDG_STATE_HOME` | Build-Boolean oder State-Home-Pfad | Target-Standard oder Host-State-Home; Aufrufer | `1` aktiviert den benannten Source-Build; `XDG_STATE_HOME=<temporary-work-root>/state` wählt ein State-Home außerhalb von Git. |
| `APACHE_BIN`, `APACHECTL_BIN`, `APXS_BIN`, `HTTPD_PREFIX`, `HTTPD_VERSION`, `APR_VERSION`, `APR_UTIL_VERSION` | Apache-Programm-, Pfad- oder Versionsüberschreibung | zentraler Pin oder Host-Erkennung | `/opt/httpd/bin/httpd`; eine Host-Installation ist keine portable Evidence. |
| `NGINX_BIN`, `NGINX_GITHUB_REPO`, `NGINX_RELEASE_TAG`, `NGINX_SOURCE_GIT_REF`, `NGINX_RELEASE_ASSET_NAME`, `NGINX_SOURCE_MODE`, `NGINX_SOURCE_REPO_URL`, `NGINX_SHA256` | NGINX-Programm-, GitHub-URL-, Release-Tag/-Ref-, Release-Asset-Name-, Source-Mode- oder SHA-256-Digest-Überschreibung | überprüftes Release-Tupel: `release-1.31.2`, passender Ref, `nginx-1.31.2.tar.gz` und `af2a957c41da636ddc4f883e4523c6d140b4784dbce42000c364ae5092aa473c` | Der unterstützte Mode `github-release` lädt das exakte offizielle GitHub-Release-Asset. Bei einem festen Release muss `NGINX_SOURCE_GIT_REF` gleich `NGINX_RELEASE_TAG` sein; Tag, Asset-Name und Digest sind ein atomar zu prüfendes Provenance-Tupel. Das Provisioning blockiert explizit leere, Whitespace enthaltende, fehlerhafte, abweichende oder tupel-inkonsistente Werte vor Lookup, Cache-Nutzung, Download oder Extraction; der Versionsprüfer aktualisiert dieses Tupel nie automatisch. |
| `PCRE2_VERSION`, `PCRE_CONFIG` | Abhängigkeitsversion oder Programm | zentraler Pin oder Host-Erkennung | `PCRE_CONFIG=/usr/bin/pcre2-config`; ein Host-Pfad ist nur ein Beispiel. |
| `PCRE2_VERSION`, `PCRE2_SOURCE_URL`, `PCRE2_SHA256`, `PCRE2_SHA256_URL`, `PCRE_CONFIG` | Abhängigkeitsversion, HTTPS-Quell-URL, 64-hex SHA-256, Versionswerkzeug-Metadaten oder Programm | zentraler Pin oder Host-Erkennung | `PCRE2_SHA256=<64-hex>` muss nicht leer, syntaktisch gültig und exakt passend zum Archiv sein, bevor die Extraktion erfolgt. Leere, nur aus Whitespace bestehende, fehlerhafte oder nicht passende Werte blockieren vor `tar`; `PCRE2_SHA256_URL` ist kein Fallback. |
| `MODSECURITY_APACHE_SOURCE_DIR`, `MODSECURITY_NGINX_SOURCE_DIR`, `MODSECURITY_SOURCE_DIR`, `MODSECURITY_V3_SOURCE_DIR`, `MODSECURITY_V3_DIR`, `MODSECURITY_V3_ROOT` | absoluter Source-/Build-Pfad | unter `SOURCE_ROOT` oder `BUILD_ROOT` | `<temporary-work-root>/src/libmodsecurity`; nicht auf einen nicht vertrauenswürdigen Checkout zeigen. |
| `MODSECURITY_GIT_REF`, `LIBMODSECURITY_VERSION`, `MODSECURITY_INCLUDE_DIR`, `MODSECURITY_LIB_DIR`, `MODSECURITY_INC`, `MODSECURITY_LIB`, `MODSECURITY_PKG_CONFIG` | Ref-, Versions-, Include-/Lib-/pkg-config-Überschreibung | zentraler Pin oder Erkennung | `MODSECURITY_GIT_REF=v3/master`; Pins mit ihrer Herkunft prüfen. |
| `MODSECURITY_TEST_VARIANT` | Testvarianten-Enum | `no-crs` oder Target-Auswahl | `with-crs` lädt CRS vor lokalen Regeln; die Katalogsemantik bleibt unverändert. |
| `MRTS_NATIVE_ROOT` | absoluter MRTS-Source-Pfad | aus `MRTS_ROOT` abgeleitet | `<temporary-work-root>/src/MRTS`; generierte Ausgabe bleibt unter `MRTS_BUILD_ROOT`. |
| `FORCE_ALL_CASES`, `REFRESH`, `RESPONSE_BODY_PROBE_REPEAT` | Test-/Report-Boolean oder positive Anzahl | Target-Standard | `FORCE_ALL_CASES=1`; Evidence wird nicht automatisch promotet. |
| `RESULTS_DIR`, `LOG_DIR`, `RUN_DIR`, `STDOUT_LOG`, `STDERR_LOG`, `RAW_RESULT` | generierte Runtime-/Evidence-Pfade | unter `BUILD_ROOT` oder Run-Verzeichnis | `<temporary-work-root>/build/results`; Logs können sensible Diagnosen enthalten. |
| `CANONICAL_EVENTS`, `HOST_RC`, `HOST_VERSION`, `NAME`, `NO_CRS_BASELINE`, `RUN_ID` | Evidence-Metadatenwert oder `--source-log NAME=PATH`-Label | Evidence-Tool oder Aufrufer | `RUN_ID=six-connectors-core-20260712T164725Z`; keine Secrets in Metadaten ablegen. |
| `GITHUB_WORKSPACE`, `RUNNER_TEMP` | von CI bereitgestellte absolute Pfade | GitHub-Actions-Runner | vom Runner gesetzt; auf einem lokalen Host nicht voraussetzen. |
| `HOME`, `PWD`, `TMPDIR` | Host-Shell-Pfade | Host-Shell | aus der Shell übernommen; für Reproduzierbarkeit explizite Framework-Wurzel verwenden. |
| `TARGET` | Make-Target-Name | von `make` oder Aufrufer | `TARGET=linux-glibc`; erlaubte Werte hängen vom aufgerufenen Upstream-Build ab. |
| `USER_TOKEN` | sensibles Authentifizierungsdatum | kein Repository-Standard | `<secret-from-secure-store>`; nie committen, loggen oder als sichtbares Prozessargument übergeben. |

| Platzhalter | Zu ersetzender Wert | Erlaubte Werte und Beispiel |
|---|---|---|
| `<connector>` | Connector-Katalogschlüssel | `apache`, `nginx`, `haproxy`, `envoy`, `traefik` oder `lighttpd`; zum Beispiel `nginx`. |
| `<run-id>` | dateisystemsicheres Evidence-Run-Token | kein `/` oder `..`; zum Beispiel `six-connectors-core-20260712T164725Z`. |
| `<workspace>` | portable Checkout-Überordnung oder CI-Workspace | absoluter Workspace-Pfad, zum Beispiel `/work/modsecurity`. |
| `<temporary-work-root>` | portabler Alias für ein temporäres Arbeitsverzeichnis eines Generators | absoluter, beschreibbarer Pfad außerhalb des Git-Worktrees, zum Beispiel ein vom Aufrufer bereitgestelltes `TMP_ROOT`; dies ist ein Darstellungsalias und kein wörtlicher Pfad zum Kopieren in einen Befehl. |
| `<case>` und `<name>` | Katalog-Fallkennung oder Metadatenname | vorhandenen YAML-`name` verwenden, zum Beispiel `request-headers-basic`. |
| `<TAG>` | vorhandenes Upstream-Tag | geprüftes Upstream-Tag verwenden, zum Beispiel `v1.27.0`. |
| `<local-paths>`, `<system-paths>`, `<local-build-root>` und `<Location>` | Dokumentationsplatzhalter für Listen oder Konfigurationsabschnitt | mit lokal verwendeten Pfaden oder Abschnitt ersetzen; zum Beispiel `<temporary-work-root>/build` oder `<Location /protected>`. |
| `<secret-from-secure-store>` | nicht ausführbarer Secret-Platzhalter | über den freigegebenen Secret Store abrufen; niemals als commitbares Literal verwenden. |
