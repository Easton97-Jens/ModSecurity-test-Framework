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
| `<fresh-source-root>` | Fünf-Connector-CRS-Fixture | `verify-fixture` und `validate` | keines | absolutes Verzeichnis | Frische CRS-Source-Wurzel mit `coreruleset/` |
| `<private-root>` | Fünf-Connector-Evidenz | `validate` und `aggregate` | keines | privates absolutes Verzeichnis | Extern erzeugte Evidenz und Validator-Ausgaben |

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

### Fünf-Connector-With-CRS-/No-MRTS-Befehlsplatzhalter

`ci/checks/catalog/five_connectors_with_crs_no_mrts.py` verwendet explizite,
validierte Befehlsargumente. Sein geschlossenes Profil ist
`five-connectors-with-crs-no-mrts` für `apache`,
`haproxy`, `envoy`, `traefik` und `lighttpd`; `nginx` wird absichtlich nur für
dieses Profil zurückgewiesen.

| Platzhalter | Erforderlich für | Bedeutung und Einschränkung |
|---|---|---|
| `<fresh-source-root>` | `verify-fixture`, `validate`, `aggregate` | Absolute Source-Wurzel mit frischem `coreruleset/`-Checkout. Der Validator prüft die gepinnte CRS-Regeldatei; er lädt keine unkontrollierte Source herunter und verwendet keine wieder. |
| `<private-root>` | `validate`, `aggregate` | Absolutes, nicht verlinktes, nicht gruppen-/weltlesbares Verzeichnis außerhalb des Framework-Checkouts. Es enthält vom Host bereitgestellte Eingaben und erhält neue Ergebnisartefakte; vorhandene Ergebniswege werden abgelehnt. |
| `<fixed-connector>` | `validate` | Genau eines von `apache`, `haproxy`, `envoy`, `traefik` oder `lighttpd`. |
| `<id>` | `validate`, `aggregate` | Sicheres Korrelationstoken, das nur von den fünf zu validierenden Evidenz-Bundles geteilt wird. Keine Secrets, personenbezogenen Daten oder Kundenkennungen verwenden. |

Der Validator leitet das Framework-Commit aus seinem sauberen Checkout ab und
weist eine vom Aufrufer gelieferte Überschreibung zurück. Diese Argumente
validieren nur Evidenz. Sie provisionieren kein CRS, starten keinen Connector,
führen kein MRTS aus und begründen keinen Connector-Runtime-PASS.

| Make-Variable | Verwendet von | Bedeutung und Einschränkung |
|---|---|---|
| `FIVE_CONNECTORS_WITH_CRS_NO_MRTS_EVIDENCE_ROOT` | `five-connectors-with-crs-no-mrts-validate`, `five-connectors-with-crs-no-mrts-aggregate` | Private Evidence-Wurzel für den festen Validator; sie muss dieselben Pfad- und Berechtigungsanforderungen wie `<private-root>` erfüllen. |
| `FIVE_CONNECTORS_WITH_CRS_NO_MRTS_RUN_ID` | `five-connectors-with-crs-no-mrts-validate`, `five-connectors-with-crs-no-mrts-aggregate` | Erforderliche sichere Run-ID. |
| `FIVE_CONNECTORS_WITH_CRS_NO_MRTS_CONNECTOR` | `five-connectors-with-crs-no-mrts-validate` | Erforderliches Mitglied der geschlossenen Liste; die Python-CLI weist jeden anderen Connector zurück. |

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

`NO_CRS_FINALIZE_ARGS` akzeptiert zusätzliche `finalize`-Optionen. Sein Wert
wird mit POSIX-Shell-ähnlicher Quotierung in einzelne Argumente zerlegt;
Optionwerte mit Leerzeichen müssen daher quotiert werden. Der Wert wird als
Argumentdaten an den Finalizer übergeben und nicht als Make- oder Shell-Code
ausgewertet; Steueroperatoren wie `;` und Make-Funktionssyntax wie `$(...)`
bleiben literale Argumente.

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

`CRS_APPROVED_REPO_URL`, `CRS_APPROVED_COMMIT`, `CRS_RELEASE_TAG`,
`CRS_RULE_FILE_SHA256` und `CRS_GIT_REF` bilden das zentrale CRS-
Provenance-Tupel in `ci/lib/common.sh`; sie sind keine Caller-Eingaben.
`fetch-crs.sh` weist eine abweichende `CRS_REPO_URL` oder `CRS_GIT_REF` vor der
Git-Ausführung ab, lädt nur die exakte zentrale Tag-Ref und verlangt, dass ihr
aufgelöstes Objekt `CRS_APPROVED_COMMIT` entspricht; eine Caller-selektierte Ref
wird nie akzeptiert. Umgebungsversuche zum Ersetzen der beiden freigegebenen
Provenance-Literale werden durch die zentrale Definition überschrieben.
`CRS_RULE_FILE_SHA256` bindet die geprüfte SQLi-Regeldatei an diesen
unveränderlichen Commit; die begrenzte automatische CRS-v4-Wartung löst Tag,
aufgelösten Commit und Regel-Digest als eine prüfbare Gruppe auf und aktualisiert
sie gemeinsam.

`CRS_SOURCE_DIR` muss ein nicht vorhandener Pfad unter dem zulässigen externen
`SOURCE_ROOT` sein; ein vorhandenes Verzeichnis oder ein Link wird nicht
wiederverwendet, sondern abgewiesen. Der Fetch-Pfad initialisiert ein frisches
Repository, setzt und liest den exakten HTTPS-Origin zurück, lädt den
freigegebenen vollständigen Commit ohne automatische Tags oder rekursive
Submodule, lädt danach nur die exakte geprüfte Tag-Ref und vergleicht ihr
aufgelöstes Objekt, `FETCH_HEAD^{commit}`, das aufgelöste Commit-Objekt und das
finale `HEAD^{commit}` mit derselben Identität. Ein fehlender `.gitmodules`-Pfad wird
akzeptiert. Der eine vorhandene Root-Pfad `.gitmodules` wird nur als reguläre,
nicht verlinkte, null Byte große Git-Empty-Blob
`e69de29bb2d1d6434b8b29ae775ad8c2e48c5391` im freigegebenen Tree, Checkout-
Index und Worktree akzeptiert. Der freigegebene Tree und Checkout-Index dürfen
keinen Gitlink enthalten; es darf kein verschachteltes Manifest, keine lokale
`submodule.*`-Konfiguration und keine `.git/modules`-Registry existieren.
Jeder andere Manifest- oder Submodule-Zustand wird vor der Nutzung abgewiesen;
eine rekursive Submodule-Initialisierung findet nicht statt. Derselbe Checkout-
Verifier läuft in `prepare-crs.sh` unmittelbar bevor es Source-Templates,
Rules oder Plugins liest oder Runtime-Dateien schreibt; eine Ersetzung nach
dem Fetch wird daher an der Source-Consumption-Grenze abgewiesen.
`CRS_RUNTIME_DIR` und `MODSECURITY_RULE_PREAMBLE_FILE` bleiben Runtime-Pfadeingaben. CRS-Pins nicht
in Workflows duplizieren. `CACHE_ROOT`, `VERIFIED_COMPONENT_CACHE` und
`CONNECTOR_COMPONENT_CACHE` sind Cache-Pfade und benötigen Herkunftsprüfungen.

`MODSECURITY_V3_APPROVED_REPO_URL` und `MODSECURITY_V3_APPROVED_COMMIT` sind
die kanonischen ModSecurity-v3-Provenance-Werte in `ci/lib/common.sh`.
`MODSECURITY_V3_RELEASE_TAG` ist nur Release-Metadatum. Die
Legacy-Aliase `MODSECURITY_REPO_URL`, `MODSECURITY_V3_GIT_URL`,
`MODSECURITY_GIT_REF` und `MODSECURITY_V3_GIT_REF` normalisieren bei leeren
oder nicht gesetzten Werten zu diesen geprüften Werten; ein nichtleerer
abweichender Wert wird vor der Git-Nutzung abgewiesen und selektiert nie ein
Objekt. Der V3-Fetch-Pfad initialisiert ein frisches Repository, prüft seinen
literalen Origin, lädt den vollständigen Commit ohne Tags oder automatische
rekursive Submodule und vergleicht gefetchte, aufgelöste und ausgecheckte
Commit-Identität. Danach initialisiert er ausschließlich die statisch
freigegebene rekursive Topologie ausdrücklich. Ein V3-Build-Input muss diese
Root-Identität und den exakten Graphen mit acht Kindern aus `(Pfad, Origin,
Commit)` besitzen, der durch die Helfer `ci_modsecurity_v3_*_gitlinks` in
`ci/lib/common.sh` deklariert ist; jeder Checkout muss nicht verlinkt,
enthalten, abgetrennt, sauber und mit genau einem freigegebenen `origin` sein.
`.gitmodules` und Gitlinks werden nur als dieser exakte statische Graph
akzeptiert; fehlende, zusätzliche oder abweichende Topologie wird abgewiesen.
Der einzige Entry-Point für frische Provisionierung ist
`ci_provision_approved_modsecurity_v3_checkout`; er verlangt ein nicht
vorhandenes Ziel direkt unter einem bestehenden kanonischen, nicht verlinkten
Parent, erzeugt dieses Ziel privat und verwendet keine vorhandene V3-Quelle
erneut. Seine Provenance-Operationen verwenden das geprüfte `/usr/bin/git`
statt des Caller-`PATH`, führen Operationen nach `init` aus dem kanonischen
physischen Verzeichnis des neuen Roots mit explizitem Worktree aus, während
`GIT_DIR` und `GIT_WORK_TREE` für Gits rekursiven Helfer nicht gesetzt bleiben,
und löschen lokale Redirect-, Attributes-, Sparse-Checkout- und
benutzerdefinierte Recursive-Update-Konfiguration vor der Submodule-
Verarbeitung.

## Common-Version-Resolver

`ci/tools/check-common-versions.py` ist der datengetriebene, atomare Resolver
für die externen Komponenten-Provenance-Standards in `ci/lib/common.sh`. Seine
Registry `COMPONENT_DEFINITIONS` ist das einzige Inventar: Jeder Datensatz
benennt Komponentenvariablen, vertrauenswürdigen Upstream und Hosts, Regeln für
stabile Releases und Kompatibilität, Prüfsummenstrategie, Resolver-Adapter,
Update-Policy und eine atomare Update-Gruppe. Resolver-Adapter enthalten keine
unabhängige Komponenten-Policy. Eine relevante Provenance-Variable ohne
Registry-Eigentümer ist ein Fehler; ebenso wird eine Variable mit mehr als
einem Eigentümer abgewiesen.

Der Resolver verwendet nur den im Datensatz bezeichneten offiziellen Upstream.
Er weist Redirects und unerwartete finale URLs ab und prüft den offiziellen
Asset-Digest oder den aufgelösten Commit eines Git-Tags, bevor er einen
Kandidaten akzeptiert. Ändert sich ein automatischer Datensatz, aktualisiert
er jedes geänderte Mitglied dessen atomarer Gruppe gemeinsam: Version/Tag,
abgeleitete Source- oder Download-URL, gegebenenfalls Asset-Name, Checksum-URL
und SHA-256. URLs mit einer Versionsvariablen werden aus der aktualisierten
Gruppe erzeugt und nicht unabhängig ausgewählt.

| Komponente | Policy | Strategie für offizielles Latest und Provenance |
|---|---|---|
| Envoy | automatic | Neuestes GitHub-Release `v<version>` ohne Draft und Prerelease; Linux-Asset und Release-Digest oder offizielles Checksum-Manifest. |
| Traefik | automatic | Neuestes GitHub-Release `v<version>` ohne Draft und Prerelease; Linux-Archiv und GitHub-Release-Digest oder offizielles Checksum-Manifest. |
| lighttpd | automatic | Neueste stabile numerische Version aus dem offiziellen `releases-1.4.x/latest.txt`; die explizite `LIGHTTPD_SERIES` sowie Release-Root und Serien-Basis-URL werden gemeinsam mit Archiv und SHA-256-Manifest geprüft. |
| Apache httpd | automatic | Neueste numerische Version in der offiziellen Apache-Liste, auf die dokumentierte aktuelle Major/Minor-Serie begrenzt; offizielle SHA-256-Datei pro Asset. |
| APR | automatic | Neueste numerische Version in der offiziellen Apache-Liste, auf die dokumentierte aktuelle Major/Minor-Serie begrenzt; offizielle SHA-256-Datei pro Asset. |
| APR-util | automatic | Neueste numerische Version in der offiziellen Apache-Liste, auf die dokumentierte aktuelle Major/Minor-Serie begrenzt; offizielle SHA-256-Datei pro Asset. |
| PCRE2 | automatic | Neuestes GitHub-Release `pcre2-<version>` ohne Draft und Prerelease; Digest des Release-Assets. |
| NGINX | automatic | Neuestes GitHub-Release `release-<version>` ohne Draft und Prerelease; Digest des Release-Assets und passendes Release-Tag/Ref/Asset-Tupel. |
| OpenSSL for NGINX QUIC/TLS | automatic | Neuestes GitHub-Release `openssl-<version>` ohne Draft und Prerelease; Digest des Release-Assets. |
| HAProxy | automatic | Neueste numerische Version im offiziellen HAProxy-Verzeichnis, durch das explizite `HAPROXY_SERIES`- und Release-Root/Basis-URL-Tupel begrenzt; offizielle SHA-256-Datei pro Asset. |
| HAProxy HTX | automatic | Neueste numerische Version im offiziellen HAProxy-Verzeichnis innerhalb des eigenen expliziten HTX-Serien-, Release-Root- und Basis-URL-Tupels; die offizielle SHA-256-Datei pro Asset wird mit diesem Tupel aktualisiert und nie aus dem normalen HAProxy-Ergebnis abgeleitet. |
| OWASP Core Rule Set | automatic | Neuestes GitHub-Release ohne Draft und Prerelease, das `v4.x.x` entspricht; festes Repository, unveränderlicher aufgelöster Git-Tag-Commit und SHA-256 der geprüften SQLi-Regeldatei werden als eine atomare Provenance-Gruppe aktualisiert. Releases außerhalb von `v4.x.x` werden niemals automatisch übernommen. |
| ModSecurity v3 | manual_review | Neuestes stabiles GitHub-Release `v3.<version>` und dessen unveränderlicher aufgelöster Git-Tag-Commit werden zur Prüfung gemeldet; der geprüfte Tag/Commit-Pin wird nicht automatisch geändert. |
| ModSecurity Apache connector | not_applicable | Repository-lokale Connector-Quelle, solange sie nicht ausdrücklich konfiguriert wird; kein Common-Version-Abrufvertrag existiert. |
| ModSecurity NGINX connector | not_applicable | Repository-lokale Connector-Quelle, solange sie nicht ausdrücklich konfiguriert wird; kein Common-Version-Abrufvertrag existiert. |
| go-ftw | automatic | Obligatorische globale GitHub-Release-/Tag-/unveränderliche-Commit-Provenance-Prüfung in jedem Wartungslauf. |
| Albedo | automatic | Obligatorische globale GitHub-Release-/Tag-/unveränderliche-Commit-Provenance-Prüfung in jedem Wartungslauf. |
| CI maintenance globals | automatic | Obligatorische globale Prüfung der kanonischen Python-/PyYAML-Pins, des neuesten stabilen Node.js-Pins einschließlich Major-Übergängen, der Workflow-Actions und CI-Security-Tools; Artefakte und generierte Views werden als ein Plan geprüft. |
| Expat | not_applicable | Legacy-Metadaten haben keinen Framework-Source-Abrufverbraucher. |
| Default branch | not_applicable | Lokaler Policy-Standard, keine Upstream-Release-Quelle. |

`manual_review` ist eine beabsichtigte Erhaltungsgrenze, kein fehlgeschlagenes
Update: Der Resolver meldet das neueste Release und beweist, dass Review-Pins
unverändert bleiben, während unabhängige automatische Gruppen mit
`--defer-reviewed-provenance` aktualisiert werden. `not_applicable` verhindert,
dass ein künftiger lokaler Hinweis oder Connector-Standard unbemerkt zu einer
Updater-Eingabe wird. Der gemeinsame Wartungsorchestrator nimmt go-ftw, Albedo
und alle CI-Wartungsglobals immer auf; `--component` filtert ausschließlich
zusätzliche Runtime-/Source-Komponenten. Daher enthalten geplante, manuell
gestartete, vollständige und komponentenbezogene Läufe dieselben obligatorischen
globalen Ergebnisse in einem gemeinsamen Plan. `unknown`, `blocked` und
`error` sind fail-closed und verhindern einen Update-Kandidaten.

`--list-components` gibt die exakten auswählbaren Namen der Registry aus. Mit
einer oder mehreren exakten Optionen `--component <name>` werden nur die
ausgewählten Datensätze aufgelöst; ein unbekannter Name wird abgewiesen.

```sh
python3 ci/tools/check-common-versions.py --list-components
python3 ci/tools/resolve-canonical-maintenance.py --check \
  --component 'Envoy' --plan "$RUNNER_TEMP/common-version-maintenance.json"
```

Ohne `--component` verarbeitet der Orchestrator jeden Runtime-/Source-Datensatz
in deterministischer Reihenfolge und ergänzt immer die obligatorischen globalen
Scopes. Mit `--component` werden nur zusätzliche Runtime-/Source-Datensätze
gefiltert; go-ftw, Albedo, Python, PyYAML, Node, Workflow-Actions und
CI-Security-Tools bleiben im Plan. `--check` ist read-only. Ein Plan enthält
typisierte sichere Updates, deterministische Manual-Review-Einträge, Quell-/
Kandidaten-Hashes und den Status generierter Views. Nur ein separat
autorisierter, SHA-256-gebundener Safe-Update-Plan darf angewendet werden.

Der Workflow `Check common.sh versions` ruft den gemeinsamen Orchestrator nach
Zeitplan, bei `workflow_dispatch` sowie für vollständige und
komponentenbezogene Läufe auf. Die Eingabe `component` filtert nur zusätzliche
Runtime-/Source-Datensätze. Resolver- und Kandidatenjobs bleiben gegenüber dem
Checkout read-only; der separat geschützte Publisher löst einen SHA-256-
gebundenen Plan erneut auf und validiert ihn, bevor er seinen Draft Pull
Request erstellen oder aktualisieren kann. Runtime-, Python-, Workflow- und
CRS-Views werden im selben Plan geprüft. Manual-Review-Issues werden nur durch
einen vertrauenswürdigen Default-Branch-Job aus dem typisierten Plan
abgeglichen; Pull Requests erhalten keine Issue-Schreibrechte.

Ein Node.js-Major-Update wird weiterhin nur als Draft-PR mit Literal-Pin
vorgeschlagen. Seine Änderung an `ci/lib/common.sh` liegt im
Pull-Request-Pfad der CI-Security-Quality-Prüfung; daher läuft Pyright mit
dieser Node.js-Kandidatenlaufzeit vor Hosted-CI, SonarQube-Cloud-Prüfung und
einer separat autorisierten Integrationsentscheidung.

## Werkzeuge, Statuswerte und sensible Daten

`PYTHON` verwendet `.venv/bin/python`, falls vorhanden, sonst `python3`.
`PYTHONDONTWRITEBYTECODE=1` ist Repository-Standard. `REFRESH`, `SMOKE_CASES`,
`CASE_SCOPE`, `FORCE_ALL_CASES`, `EXTRA_CASE_ROOTS`, `RESULTS_DIR` und die
`VERIFIED_*`-Wurzeln begrenzen vorhandene Läufe; sie fügen keine Fähigkeiten
oder Fälle hinzu. Connector-Familienvariablen (`APXS_*`, `NGINX_*`,
`HAPROXY_*`, `ENVOY_*`, `TRAEFIK_*` und `LIGHTTPD_*`) sind Target-Eingaben und
Kompatibilitätsaliase. Geprüfte Upstream-Version/URL/Asset/Digest-Tupel sind
kanonische Literale in `ci/lib/common.sh`; Versuche, diese Tupelfelder zu
ersetzen, werden abgewiesen. Runtime-Pfade und vom Host ermittelte Programme
bleiben dort Aufrufer-Eingaben, wo das Target sie ausdrücklich erlaubt.

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

## Kanonische Python-CI-Pins

`CI_CANONICAL_PYTHON_VERSION`, `CI_CANONICAL_PYYAML_VERSION` und
`CI_CANONICAL_PYYAML_SHA256` in `ci/lib/common.sh` sind die einzigen manuell
gepflegten Werte für den CI-Interpreter und sein geprüftes PyYAML-Wheel. Die
unterstützte Artefakt-/Plattform-Identität des Wheels gehört zum selben
kanonischen Wartungsplan und darf nicht unabhängig driften. Die committeten
Dateien `.python-version` und `requirements-ci.lock` sind generierte Ansichten.
Mit `ci/tools/sync-canonical-python-pins.py --check` werden sie netzwerkfrei
geprüft; `--write` aktualisiert sie atomar.

## Weitere dokumentierte Eingaben und Platzhalter

Die folgenden Werte erscheinen in fokussierten Build-, Import-, Test- oder
historischen Kompatibilitäts-Guides. Sie sind Target-Eingaben, sofern das
benannte Target nichts anderes verlangt. Aktive Upstream-Tupelfelder werden aus
den kanonischen Definitionen in `ci/lib/common.sh` und generierten Ansichten
gelesen; sie sind keine unabhängigen Dokumentationsstandards. Ein leerer oder
nicht verfügbarer Wert muss zu einem klaren Voraussetzung-Fehler führen, nicht
zu einem angenommenen PASS. Build-Pfade sind absolute Runtime-Pfade und sollen
außerhalb des Git-Worktrees liegen. Ausdrücklich erlaubte Source-Eingaben
benötigen weiterhin eine Herkunftsprüfung.

| Namen | Bereich und Format | Standard / gesetzt durch | Beispiel und Sicherheitshinweis |
|---|---|---|---|
| `ALLOW_EXTERNAL_CONNECTOR_REPOS` | Boolean zur Quellenbeschaffung | `0`; Aufrufer oder CI | `1` stimmt externen Source-Fetches zu; Repository vorher prüfen. |
| `BUILD_HTTPD_FROM_SOURCE`, `BUILD_NGINX_FROM_SOURCE`, `BUILD_PCRE2_FROM_SOURCE`, `XDG_STATE_HOME` | Build-Boolean oder State-Home-Pfad | Target-Standard oder Host-State-Home; Aufrufer | `1` aktiviert den benannten Source-Build; `XDG_STATE_HOME=<temporary-work-root>/state` wählt ein State-Home außerhalb von Git. |
| `APACHE_BIN`, `APACHECTL_BIN`, `APXS_BIN`, `HTTPD_PREFIX`, `HTTPD_VERSION`, `APR_VERSION` | Apache-Programm-/Pfad-Eingabe oder kanonisches Versionsfeld | kanonisches Tupel in `ci/lib/common.sh` oder Host-Erkennung für Programme | `/opt/httpd/bin/httpd`; eine Host-Installation ist keine portable Evidence. |
| `APR_UTIL_PINNED_VERSION`, `APR_UTIL_PINNED_SOURCE_URL`, `APR_UTIL_PINNED_SHA256`, `APR_UTIL_PINNED_SHA256_URL`, `APR_UTIL_VERSION`, `APR_UTIL_SOURCE_URL`, `APR_UTIL_SHA256`, `APR_UTIL_SHA256_URL` | überprüftes APR-util-Provider-, Asset- und SHA-256-Tupel | kanonisches Tupel in `ci/lib/common.sh`; generierte Lock-/Manifest-Ansichten werden dagegen geprüft | Runtime-Werte müssen exakt Provider, Version, Asset, Digest und Checksum-URL des kanonischen Tupels entsprechen. Leere, fehlerhafte, abweichende, Mirror-, Host-, Pfad- oder Versionswerte blockieren vor Apache-Provisionierung, Download, Cache-Nutzung oder Extraktion. Die Checksum-URL ist ergänzende Metadaten und niemals ein Digest-Fallback. |
| `NGINX_BIN`, `NGINX_GITHUB_REPO`, `NGINX_RELEASE_TAG`, `NGINX_SOURCE_GIT_REF`, `NGINX_RELEASE_ASSET_NAME`, `NGINX_SOURCE_MODE`, `NGINX_SOURCE_REPO_URL`, `NGINX_SHA256` | NGINX-Programm-, Kompatibilitäts-GitHub-URL-Alias-, fester Release-Tag/-Ref-, Release-Asset-Name-, Source-Mode- oder SHA-256-Digest-Eingabe | überprüftes festes Source-Tupel; siehe [feste NGINX-Release-Provenance](#feste-nginx-release-provenance) | NGINX akzeptiert nur den überprüften Provenance-Pfad `github-release`. Ein fließender `latest`-Tag oder -Ref wird abgewiesen und ist kein unterstützter Kompatibilitätsmodus. |
| `PCRE2_VERSION`, `PCRE_CONFIG` | Abhängigkeitsversion oder Programm | zentraler Pin oder Host-Erkennung | `PCRE_CONFIG=/usr/bin/pcre2-config`; ein Host-Pfad ist nur ein Beispiel. |
| `PCRE2_VERSION`, `PCRE2_SOURCE_URL`, `PCRE2_SHA256`, `PCRE2_SHA256_URL`, `PCRE_CONFIG` | Abhängigkeitsversion, HTTPS-Quell-URL, 64-hex SHA-256, Versionswerkzeug-Metadaten oder Programm | zentraler Pin oder Host-Erkennung | `PCRE2_SHA256=<64-hex>` muss nicht leer, syntaktisch gültig und exakt passend zum Archiv sein, bevor die Extraktion erfolgt. Leere, nur aus Whitespace bestehende, fehlerhafte oder nicht passende Werte blockieren vor `tar`; `PCRE2_SHA256_URL` ist kein Fallback. |
| `MODSECURITY_APACHE_SOURCE_DIR`, `MODSECURITY_NGINX_SOURCE_DIR`, `MODSECURITY_SOURCE_DIR`, `MODSECURITY_V3_SOURCE_DIR`, `MODSECURITY_V3_DIR`, `MODSECURITY_V3_ROOT` | absoluter Source-/Build-Pfad | unter `SOURCE_ROOT` oder `BUILD_ROOT` | `<temporary-work-root>/src/libmodsecurity`; V3-Source muss ein geprüfter eigenständiger Checkout sein, nie ein nicht vertrauenswürdiger Checkout. |
| `MODSECURITY_GIT_REF`, `MODSECURITY_V3_GIT_REF`, `LIBMODSECURITY_VERSION`, `MODSECURITY_INCLUDE_DIR`, `MODSECURITY_LIB_DIR`, `MODSECURITY_INC`, `MODSECURITY_LIB`, `MODSECURITY_PKG_CONFIG` | Release-Metadaten, Versions-, Include-/Lib-/pkg-config-Eingabe | kanonischer Pin oder Erkennung | Leere Legacy-Aliase normalisieren zum kanonischen V3-Tupel; der vollständige geprüfte Commit, nicht ein Alias, selektiert die V3-Quelle. |
| `MODSECURITY_TEST_VARIANT` | Testvarianten-Enum | `no-crs` oder Target-Auswahl | `with-crs` lädt CRS vor lokalen Regeln; die Katalogsemantik bleibt unverändert. |
| `MRTS_NATIVE_ROOT` | absoluter MRTS-Source-Pfad | aus `MRTS_ROOT` abgeleitet | `<temporary-work-root>/src/MRTS`; generierte Ausgabe bleibt unter `MRTS_BUILD_ROOT`. |
| `FORCE_ALL_CASES`, `REFRESH`, `RESPONSE_BODY_PROBE_REPEAT` | Test-/Report-Boolean oder positive Anzahl | Target-Standard | `FORCE_ALL_CASES=1`; Evidence wird nicht automatisch promotet. |
| `RESULTS_DIR`, `LOG_DIR`, `RUN_DIR`, `STDOUT_LOG`, `STDERR_LOG`, `RAW_RESULT` | generierte Runtime-/Evidence-Pfade | unter `BUILD_ROOT` oder Run-Verzeichnis | `<temporary-work-root>/build/results`; Logs können sensible Diagnosen enthalten. |
| `CANONICAL_EVENTS`, `HOST_RC`, `HOST_VERSION`, `NAME`, `NO_CRS_BASELINE`, `RUN_ID` | Evidence-Metadatenwert oder `--source-log NAME=PATH`-Label | Evidence-Tool oder Aufrufer | `RUN_ID=six-connectors-core-20260712T164725Z`; keine Secrets in Metadaten ablegen. |
| `GITHUB_WORKSPACE`, `RUNNER_TEMP` | von CI bereitgestellte absolute Pfade | GitHub-Actions-Runner | vom Runner gesetzt; auf einem lokalen Host nicht voraussetzen. |
| `HOME`, `PWD`, `TMPDIR` | Host-Shell-Pfade | Host-Shell | aus der Shell übernommen; für Reproduzierbarkeit explizite Framework-Wurzel verwenden. |
| `TARGET` | Make-Target-Name | von `make` oder Aufrufer | `TARGET=linux-glibc`; erlaubte Werte hängen vom aufgerufenen Upstream-Build ab. |
| `USER_TOKEN` | sensibles Authentifizierungsdatum | kein Repository-Standard | `<secret-from-secure-store>`; nie committen, loggen oder als sichtbares Prozessargument übergeben. |

### Feste NGINX-Release-Provenance

Die NGINX-Source-Provisionierung ist ein fester, überprüfter Release-Pfad und
kein rollierender Kanal. Lässt ein Aufrufer das Tupel ungesetzt, wird der
statische überprüfte Standard verwendet. Ein explizit übergebener leerer Wert
ist ungültig und wird fail-closed abgewiesen; `NGINX_SOURCE_GIT_REF` darf nur
aus dem expliziten überprüften `NGINX_RELEASE_TAG` abgeleitet werden.

| Tupelfeld | Erforderlicher überprüfter Wert |
|---|---|
| `NGINX_SOURCE_MODE` | kanonisches `NGINX_SOURCE_MODE` in `ci/lib/common.sh` |
| `NGINX_SOURCE_REPO_URL` | kanonisches `NGINX_SOURCE_REPO_URL` in `ci/lib/common.sh` |
| `NGINX_RELEASE_TAG` | kanonisches `NGINX_RELEASE_TAG` in `ci/lib/common.sh` |
| `NGINX_SOURCE_GIT_REF` | aus dem kanonischen Release-Tag abgeleitet |
| `NGINX_RELEASE_ASSET_NAME` | abgeleitetes kanonisches Asset-Feld |
| `NGINX_SHA256` | kanonischer Digest in `ci/lib/common.sh` |

`NGINX_GITHUB_REPO` ist nur ein Kompatibilitätsalias; er kann keinen anderen
Origin als das kanonische NGINX-Repository wählen. Archivendpunkt und Assetname
werden aus dem kanonischen Release-Tupel abgeleitet; siehe `ci/lib/common.sh`
und die generierte Runtime-Manifestansicht.

Für NGINX ist `latest` sowohl als `NGINX_RELEASE_TAG` als auch als
`NGINX_SOURCE_GIT_REF` verboten. Diese Werte, ein fehlender Tag/Ref/Asset/Digest,
ein ungültiger Digest, ein nicht kanonisches Source-Repository oder ein anderer
Source-Mode sowie ein Tag/Ref/Asset-Mismatch werden vor Cache-Auswahl,
Netzwerkanfrage, Download oder Extraktion abgewiesen. Die NGINX-
Provenance-Prüfung löst ausschließlich den konfigurierten Tag über
`/releases/tags/<tag>` auf; sie verwendet nie den NGINX-Endpunkt
`/releases/latest`. Ein neueres NGINX-Release erfordert eine separate atomare
Prüfung des vollständigen Tupels.

Die Cache-Wiederverwendung ist an ein nicht verlinktes Manifest und einen Key
über das vollständige Tupel `(Source-Repository, Source-Mode, Release-Tag,
Source-Ref, Release-Asset-Name, erwarteter SHA-256)` gebunden. Ein Cache-Eintrag
mit fehlender, abweichender oder alter `latest`-Identität kann nicht
wiederverwendet werden. Das ausgewählte Archiv muss vor Staging oder Extraktion
dem nicht leeren, 64-hexadezimalen Wert `NGINX_SHA256` entsprechen; die gestagte
Kopie wird erneut geprüft. Diese Source-Provenance-Prüfungen behaupten kein
Connector- oder Produktionsruntime-Ergebnis.

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
