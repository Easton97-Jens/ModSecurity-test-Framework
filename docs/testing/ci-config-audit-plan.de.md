# CI Konfigurationsüberwachungs- und Bereinigungsplan

**Sprache:** [English](ci-config-audit-plan.md) | Deutsch

Datum: 20.05.2026

Dieses Dokument prüft den aktuellen `ci/`, Makefile, Dokumente und GitHub-Workflow
Konfiguration nach dem ersten Central-Config-Bereinigungsdurchlauf. Es ist eine Planung
Dokument, kein Laufzeitbeweis.

## Prüfungsumfang

Geprüfte Pfade:

- `ci/`
- `Makefile`
- `README.md`
- `docs/testing/`
- `.github/workflows/`

Die primäre Suche umfasste lokale Arbeitsbereichspfade, Systeminstallationsannahmen,
GitHub-Quell-URLs und build/source-root-Variablen:

```sh
rg "<local-paths>|<system-paths>|github.com|MODSECURITY|BUILD_ROOT|SOURCE_ROOT" ci Makefile README.md docs/testing .github/workflows
```

## Aktueller positiver Zustand

- `modules/ModSecurity-test-Framework/ci/lib/common.sh` existiert und ist passiv: Es definiert nur Variablen und Funktionen.
- `modules/ModSecurity-test-Framework/ci/lib/common.sh` definiert jetzt canonical/passive Quellaliase
  (`MODSECURITY_SOURCE_DIR`, `MODSECURITY_V3_SOURCE_DIR`,
  `MODSECURITY_V3_ROOT`) und optionale Installationsbereitschaftslisten hints/search.
- `make cloud-quick-check` ist derzeit framework/generator/lint orientiert und
  ruft `quick-all`, `installed-readiness` nicht auf, oder der vollständige Anschluss raucht.
- `quick-framework-check.yml` ist leichtgewichtig und automatisch.
- `test-full-smoke-sequential.yml` ist nur manuell über `workflow_dispatch` möglich.
- Es existieren noch lokale Laufzeitziele: `smoke-all`, `smoke-apache`,
  `smoke-nginx`, `quick-all` und `quick-check`.
- Keine aktuelle Prüfungsfeststellung erfordert eine Änderung von `connectors/apache/src/` oder
  `connectors/nginx/src/`.

## Wirkungsvolle Erkenntnisse

### 1. Lokale Pfadstandards aus den Laufzeitstandards entfernt

Der Folgepatch entfernte Laufzeitstandards, die stillschweigend von der lokalen Version abhingen
Arbeitsbereichspfade:

| Bereich | Aktueller Befund | Risiko |
| --- | --- | --- |
| `modules/ModSecurity-test-Framework/ci/lib/common.sh` | `DEFAULT_BUILD_ROOT` verwendet jetzt einen portablen lokalen state/output Pfad | `/src` bleibt nur als expliziter `BUILD_ROOT` verwendbar. |
| `modules/ModSecurity-test-Framework/ci/lib/common.sh` | Legacy-V3-Quellverzeichnis-Fallback-Variable entfernt | Es bleibt kein Fallback für den übergeordneten Arbeitsbereich bestehen. |
| `Makefile` | `BUILD_ROOT` wird jetzt standardmäßig über lokale state/output-Einstellungen festgelegt | Make impliziert nicht mehr `/src`. |
| `modules/ModSecurity-test-Framework/ci/provisioning/build-v3-under-src.sh` / `modules/ModSecurity-test-Framework/ci/runtime/run-v3-api-smoke.sh` / `modules/ModSecurity-test-Framework/ci/provisioning/check-v3-api-smoke-prereqs.sh` | `MODSECURITY_V3_DIR` Standardwerte unter `BUILD_ROOT` | v3 API-Helfer verwenden nicht mehr standardmäßig `/src`. |
| `ci/provisioning/find-modsecurity-v3.sh` | Überprüft nur explizite Aliase und `$SOURCE_ROOT/ModSecurity_V3` | Es bleibt keine automatische Geschwister-Repo-Erkennung bestehen. |
| Mehrere Skripte | Sicherheitsvorrichtungen schützen immer noch zerstörerische Ziele auf Root-Ebene | Hierbei handelt es sich um Löschsicherheitsüberprüfungen, nicht um Quellen-Fallbacks. |

Empfehlung:

- Behalten Sie die Zentralisierung der Pfadrichtlinie bei, um sie in Zukunft zu bereinigen, falls weitere Duplikate auftreten.
- Erfordern explizite `MODSECURITY_SOURCE_DIR`/`MODSECURITY_V3_SOURCE_DIR` oder a
  `SOURCE_ROOT`-abgeleiteter abgerufener Checkout.
- Behandeln Sie `/src` nur als expliziten, vom Benutzer bereitgestellten Build-Root.
- Halten Sie GitHub-Workflows mit `$RUNNER_TEMP` explizit.

Risiko:

- Mittel. Das Entfernen lokaler Fallbacks ändert das Komfortverhalten, passt sich aber an
  das Repo mit expliziter source/build-Konfiguration und vermeidet überraschende lokale
  Kupplung.

### 2. Die Benennung des Quellverzeichnisses ist nicht vollständig zentralisiert

`modules/ModSecurity-test-Framework/ci/lib/common.sh` zentralisiert jetzt das Repo URLs/refs und die angeforderte kanonische Quelle
Aliase. Die verbleibende Folgearbeit besteht darin, die abgerufenen Quellverzeichnisse zu trennen
Adaptereigene Quellverzeichnisse expliziter anzeigen.

| Erforderliche Variable | Aktueller Stand |
| --- | --- |
| `MODSECURITY_SOURCE_DIR` | Als kanonischer Alias definiert |
| `MODSECURITY_V3_SOURCE_DIR` | Als Kompatibilitätsalias definiert |
| `MODSECURITY_V3_ROOT` | Als Kompatibilitätsalias definiert |
| `MODSECURITY_APACHE_SOURCE_DIR` | Zentral definiert; standardmäßig repo-local |
| `MODSECURITY_NGINX_SOURCE_DIR` | Zentral definiert; standardmäßig repo-local |

Empfehlung:

- Kanonische `MODSECURITY_SOURCE_DIR="${MODSECURITY_SOURCE_DIR:-...}"` hinzufügen.
- Definieren Sie `MODSECURITY_V3_SOURCE_DIR` und `MODSECURITY_V3_ROOT` als Aliase für
  `MODSECURITY_SOURCE_DIR`, wobei vorhandene Umgebungsüberschreibungen gewinnen.
- Halten Sie die lokalen Repository-Quellverzeichnisse im Besitz des Adapters als separate Variablen explizit:
  `APACHE_ADAPTER_SOURCE_DIR` und `NGINX_ADAPTER_SOURCE_DIR`.

Risiko:

- Niedrig bis mittel. Die Alias-Rangfolge muss explizit sein, um eine Beschädigung der alten Umgebung zu vermeiden
  Namen.

### 3. Die Repo-URL-Richtlinie ist explizit

Derzeit referenzierte externe Quellen:

| Quelle | Standort | Status |
| --- | --- | --- |
| `https://github.com/owasp-modsecurity/ModSecurity.git` | `modules/ModSecurity-test-Framework/ci/lib/common.sh`, workflow/docs | Kern-Repo, erwartet |
| `https://github.com/owasp-modsecurity/ModSecurity-apache` | Nur docs/import Metadaten | Historische Connector-Referenz, kein Standardabruf |
| `https://github.com/owasp-modsecurity/ModSecurity-nginx` | Nur docs/import Metadaten | Historische Connector-Referenz, kein Standardabruf |
| `https://github.com/nginx/nginx` | `modules/ModSecurity-test-Framework/ci/lib/common.sh`, NGINX Build-Helfer, manueller Workflow | NGINX Serverquellenabhängigkeit |
| `https://downloads.apache.org/httpd/...` | `modules/ModSecurity-test-Framework/ci/lib/common.sh` | Apache/httpd Serverquellenabhängigkeit |
| `https://downloads.apache.org/apr/...` | `modules/ModSecurity-test-Framework/ci/lib/common.sh` | APR/APR-util Serverquellenabhängigkeit |
| `https://github.com/PCRE2Project/pcre2/...` | `modules/ModSecurity-test-Framework/ci/lib/common.sh` | Abhängigkeit der Bibliotheksquelle |

Empfehlung:

- Die Standardabrufrichtlinie gilt nur für den ModSecurity-Kern.
- Apache/NGINX Connector-Repositorys erfordern
  `ALLOW_EXTERNAL_CONNECTOR_REPOS=1` plus explizite URLs und Quellverzeichnisse.
- Von der Quelle erstellte Serverabhängigkeiten bleiben konfigurierbare Laufzeit-Build-Eingaben.
  keine Connector-Repos.

Risiko:

- Hoch, wenn blind geändert wird. Die vollständige lokale Quelle baut derzeit Smoke auf
  auf server/library Quell-Downloads, es sei denn, es handelt sich um von der Quelle erstellte Ausgaben oder installierte Tools
  werden mitgeliefert.

### 4. Durch die Wiederverwendung von Fetch werden vorhandene Git-Checkouts nicht validiert

`modules/ModSecurity-test-Framework/ci/provisioning/fetch-smoke-sources.sh` aktuell:

- klont konfigurierte URL/ref in das konfigurierte Ziel.
- verwendet ein vorhandenes `.git`-Verzeichnis ohne Validierung:
  - Fernbedienung URL
  - aktuelle branch/ref/commit
  - schmutziger Arbeitsbaum
  - abgetrennter HEAD Zustand

Empfehlung:

- Fügen Sie einen `ci_validate_git_checkout "$dest" "$url" "$ref"`-Helfer hinzu.
- Wenn ein bestehender Checkout fehlerhaft ist oder Remote URL/ref nicht übereinstimmt, kehren Sie zurück
  `BLOCKED` mit einer Korrekturmeldung.
- Nicht automatisch zurücksetzen, automatisch abrufen oder überschreiben.
- Halten Sie das `REFRESH`-Verhalten explizit, wenn eine zukünftige Bereinigung Ersetzungslogik hinzufügt.

Risiko:

- Mittel. Die Validierung blockiert möglicherweise zuvor tolerierte lokale Zustände, dies ist jedoch der Fall
  sicherer, als stillschweigend die falsche Quelle zu verwenden.

### 5. Die automatische Erkennung lokaler Quellen ist explizit

`ci/provisioning/find-modsecurity-v3.sh` sucht jetzt:

1. `MODSECURITY_SOURCE_DIR`
2. `MODSECURITY_V3_SOURCE_DIR`
3. `MODSECURITY_V3_ROOT`
4. `$SOURCE_ROOT/ModSecurity_V3`

Empfehlung:

- Aktualisieren Sie die `doctor`- und Smoke-Preflight-Nachrichten so, dass sie lauten: „Führen Sie `make fetch-deps` aus oder.“
  set `MODSECURITY_SOURCE_DIR`".

Risiko:

- Medium. Dadurch wird die praktische automatische Entwicklererkennung entfernt, aber verhindert
  versehentliche Verwendung unbeabsichtigter lokaler Geschwister-Repos.

### 6. Die installierte Bereitschaft ist immer noch mit der Ausgabe des Arztes vermischt

`modules/ModSecurity-test-Framework/ci/tools/doctor.sh` ursprünglich überprüfte Build-Tools, Python-Deps, Quellpfade,
GitHub-Erreichbarkeit, generierte Build-Ausgaben und installiert
Apache/NGINX/libmodsecurity Bereitschaft in einem Fluss. Es meldet installiert
Komponenten sogar für die Source-Build-Validierung.

`modules/ModSecurity-test-Framework/ci/runtime/smoke-installed.sh` ist explizit schreibgeschützt, was gut ist, aber das
Die installierte Erkennungslogik enthält weiterhin fest codierte Systempfade:

- `/lib/x86_64-linux-gnu`
- `/usr/lib/x86_64-linux-gnu`
- `/usr/local/lib`
- `/usr/lib64`
- `/usr/lib`
- `/usr/include`
- `/usr/local/include`
- `/opt/include`

Empfehlung:

- Arztbereiche klar aufteilen:
  - `SOURCE-BUILD READINESS`
  - `OPTIONAL INSTALLED READINESS`
- Die Quell-Build-Bereitschaft darf kein System-Apache, NGINX, erfordern oder installiert sein
  libmodsecurity.
- Verschieben Sie installierte Suchpfadlisten als optionale Bereitschaft nach `modules/ModSecurity-test-Framework/ci/lib/common.sh`
  Standardwerte.
- Behalten Sie die installierte Bereitschaft bei und geben Sie `BLOCKED` zurück, wenn sie unvollständig sind, aber dokumentieren Sie sie
  dass dadurch der an der Quelle entstehende Smoke nicht blockiert wird.

Risiko:

- Niedrig bis mittel. Die Ausgabesemantik ändert sich, das Laufzeitverhalten jedoch nicht.

### 7. Der manuelle Full-Smoke-Workflow enthält weiterhin Laufzeitstandards

`.github/workflows/test-full-smoke-sequential.yml` ist nur manuell, aber immer noch
enthält:

- direkt `MODSECURITY_V3_GIT_URL`
- direkt `MODSECURITY_V3_GIT_REF`
- direkt `NGINX_SOURCE_REPO_URL`
- `NGINX_RELEASE_TAG=latest`
- vollständige `make smoke-*` Befehle

Empfehlung:

- Behalten Sie den Status „Nur manuell“ bei.
- Sorgen Sie dafür, dass die Workflow-Umgebung kanonische Namen verwendet:
  `MODSECURITY_REPO_URL`, `MODSECURITY_GIT_REF` und alle zukünftigen expliziten
  `NGINX_SOURCE_REPO_URL`.
- Bevorzugen Sie angeheftete tags/refs aus Gründen der Reproduzierbarkeit gegenüber `latest`.
- Fügen Sie einen Workflow-Kommentar hinzu, dass es nicht erforderlich ist CI und fetch/build Server sein kann
  Quellabhängigkeiten.

Risiko:

- Niedrig, wenn das reine manuelle Verhalten unverändert bleibt.

### 8. Build-Abhängigkeitsversionen sind nicht zentralisiert

`modules/ModSecurity-test-Framework/ci/lib/common.sh` besitzt jetzt:

- `HTTPD_VERSION`
- `APR_VERSION`
- `APR_UTIL_VERSION`
- `PCRE2_VERSION`
- Quell-URLs und optionale Prüfsummen

- `NGINX_SOURCE_MODE`
- `NGINX_SOURCE_REPO_URL`
- `NGINX_RELEASE_TAG`
- `NGINX_SOURCE_GIT_REF`
- `NGINX_SHA256`

Empfehlung:

- Leere Prüfsummenvariablen optional lassen; Lokale Hashes werden weiterhin aufgezeichnet, wenn
  Es ist keine Upstream-Prüfsumme konfiguriert.

Risiko:

- Niedrig für reine Zentralisierung; mittel, wenn die Prüfsummenrichtlinie streng wird.

## Sichere sofortige Änderungen

Diese können sicher im nächsten kleinen Patch durchgeführt werden. Der erste Durchgang implementierte diese
Elemente ohne Änderung der Smokesemantik zur Laufzeit:

- Fehlende passive Aliase in `modules/ModSecurity-test-Framework/ci/lib/common.sh` hinzufügen:
  `MODSECURITY_SOURCE_DIR`, `MODSECURITY_V3_ROOT`, `APACHECTL_BIN`,
  `MODSECURITY_PKG_CONFIG`, `MODSECURITY_LIB_DIR`,
  `MODSECURITY_INCLUDE_DIR`.
- Installierte Bereitschaftssuchlisten in passive variables/functions. verschieben
- Aktualisieren Sie die Dokumente, um `/src` als explizites Beispiel und nicht als Anforderung aufzurufen.
- `doctor`-Überschriften aktualisieren, um „Source-Build“ und „Optional Installed“ zu trennen
  Bereitschaft ohne Änderung der Ausstiegspolitik.

Umsetzungsstand:

- `modules/ModSecurity-test-Framework/ci/lib/common.sh` definiert jetzt die fehlenden Quellaliase und optional installiert
  Hinweise sowie zentralisierte candidate/search-list-Variablen für die Installationsbereitschaft.
- `modules/ModSecurity-test-Framework/ci/tools/doctor.sh` meldet jetzt `SOURCE-BUILD READINESS` und
  `OPTIONAL INSTALLED READINESS` separat.
- `modules/ModSecurity-test-Framework/ci/runtime/smoke-installed.sh` verbraucht jetzt die zentralisierte Installationsbereitschaft
  candidate/search-list Variablen.
- Die Dokumentation stellt nun klar, dass es sich bei `/src` um ein austauschbares Build-Artefakt handelt
  Standort, Installationsbereitschaft ist eine optionale Diagnose und `make smoke-all`
  bleibt der lokal maßgebliche Laufzeitnachweispfad.

## Ehemaliger erwarteter Fehler YAML und CI Helfer-Follow-up

Die nächste konservative Bereinigung behebt nur die fehlerhafte erwartete Fehlersyntax YAML. Die
Reparierte Fälle waren zuvor für den Matrixgenerator nicht lesbar, was dazu führte
Sie werden trotz der Deklaration ihrer Quelldateien als `unknown`-Berichtszeilen angezeigt
ein historischer erwarteter Fehlerstatus.

Nur-Syntax-Reparaturen:

- JSON Anforderungstexte mit eingebetteten Anführungszeichen verwenden jetzt YAML-sichere Skalare.
- XML Anforderungstexte mit eingebetteten Attribut-Anführungszeichen verwenden jetzt YAML-sichere Skalare.
- `origin.reason`-Werte, die mit `@operator` beginnen, werden in Anführungszeichen gesetzt.
- Der ausgehende mehrzeilige Prüfprotokoll-Prüfkörper ist als ein YAML-Block eingerückt
  Skalar.

Kein Teststatus, erwartetes HTTP Ergebnis, Eingriffserwartung, Laufzeit
Verifizierungsanspruch oder RESPONSE_BODY Klassifizierung wurde geändert.

Bei der Prüfung des `ci/`-Skripts wurde festgestellt, dass die meisten Hilfsprogramme immer noch von Makefile-Zielen referenziert werden.
Laufzeit-Smoke-Skripte, Dokumente oder Kompatibilitäts-Wrapper. Zwei abgestandene Standalone
Python-Helfer für die Prüfung des zusammenfassenden Schemas in der Praxis und das erwartete Audit-Protokoll
Fixture-Generierung wurden entfernt. Der schlanke gemeinsame Workflow verwendet jetzt die
Shared Case Runner CLI für diese Prüfungen, anstatt gelöschte `ci/` aufzurufen
Helfer.

Runtime/build/fetch/debug Helfer wurden bewusst beibehalten, es sei denn, der Verweis
Die Prüfung ergab, dass sie tot waren. Die vollständige Laufzeitvalidierung bleibt lokal.

## Follow-up zur Framework-Extraktion

Die gemeinsam genutzte test/runtime/coverage-Ebene ist jetzt Eigentum des Geschwisters
`ModSecurity-test-Framework` Auschecken und Verbrauchen durch konfigurierbar
`FRAMEWORK_ROOT` / `CONNECTOR_ROOT` Pfade.

In das Framework verschoben:

- häufige YAML Fälle und Schemanotizen
- Shared Case Runner und Normalisierer
- Matrix-, Coverage-, Runtime-Snapshot- und Runtime-Matrix-Generatoren
- generische Source-Build-Smoke-Orchestrierungshelfer

In diesem Connector-Repository gespeichert:

- Apache/NGINX Connectorquelle und Harnesses
- Adapter-Metadaten und Connector-Materialisierungsprüfungen
- `config/testing/import-status.json`
- Connector-spezifische Fälle gemäß `connectors/<connector>/tests/`
- generierte Connector-Berichte gemäß `docs/testing/generated`

Connector-lokale `ci/`-Einstiegspunkte, die sich mit Framework-eigenen Helfern überschneiden, sind
Nur Kompatibilitäts-Wrapper; sie delegieren an `$FRAMEWORK_ROOT`. Kein früherer erwarteter Misserfolg,
Der Status „Ausstehend“, „Anschlusslücke“ oder „RESPONSE_BODY“ wurde durch die Extraktion heraufgestuft.

## Änderungen, die getrennt erfolgen sollten

Dies bleiben separate Folgemaßnahmen:

- Checkout-remote/ref/dirty-Validierung in `fetch-smoke-sources.sh` hinzufügen.
- `NGINX_RELEASE_TAG=latest` anpinnen oder entfernen.

## Vorgeschlagene Folge-Implementierungsanordnung

1. Fügen Sie fehlende passive Aliase und Hilfsvariablen für die Installationsbereitschaft hinzu
   `modules/ModSecurity-test-Framework/ci/lib/common.sh`.
2. Refactor `doctor` Ausgabe in Source-Build- und optional-Installed-Abschnitte;
   bestehende BLOCKED/PASS Ehrlichkeit bewahren.
3. Git-Checkout-Validierung zu `fetch-smoke-sources.sh` hinzufügen.
4. Bewegliche Server-Quellen-Referenzen anheften oder entfernen, wo es sinnvoll ist.
5. Aktualisieren Sie den manuellen Full-Smoke-Workflow names/env bei Bedarf weiter und pinnen Sie ihn an
   Schiedsrichter verschieben, wo es praktisch ist.

## Nicht-Ziele für diesen Audit-Durchgang

- Keine `make smoke-all` Ausführung.
- Keine Full-Smoke PASS Ansprüche.
- Keine RESPONSE_BODY-Aktion.
- Keine Änderungen unter `connectors/apache/src/` oder `connectors/nginx/src/`.
- Keine Laufzeitsemantikänderungen ohne einen separaten überprüften Patch.
