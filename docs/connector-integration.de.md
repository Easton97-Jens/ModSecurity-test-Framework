# Connector-Integration

**Sprache:** [English](connector-integration.md) | Deutsch

Das Framework besitzt sämtliche Tests und Testinfrastruktur, einschließlich
connectorspezifischer Host-Testadapter, Harnesses, Provisionierung, Auswahl,
Sammlung, Normalisierung, Validierung und Testreport-Generierung. Das
Connector-Repository besitzt produktive Hostadapter, Build, Runtime-Konfiguration,
Installation und Delivery sowie kleine gepinnte Testeinstiege.

## Ownership-Grenze

| Bereich | Eigentümer |
|---|---|
| Sämtliche Tests, Fallzulassung, Fixtures und Normalisierung | Framework |
| Host-Testadapter, Harnesses und Testkomponenten-Vorbereitung | Framework |
| Produktive Host-Hooks, Filter, Plugins und Direktiven | Connector-Repository |
| Produkt-Build und produktive Runtime-Konfiguration | Connector-Repository |
| Connector-Capabilities, Integrationsmodus und Produkt-Promotion | Connector-Repository mit revisionsgebundener Evidence |
| Sammlung, Validierung und generierte Cross-Case-Sicht | Framework mit deklarierten laufbezogenen Inputs |

[Die Testschnittstelle](connector-test-suite.de.md) verlangt explizite
`TEST_ROOT`, `CONNECTOR_ROOT`, exakte Revision, Profil und externe Ausgabe.
Das Framework hat kein Connector-Submodul. Ein Framework-Starter- oder
Self-Test-PASS beweist niemals einen Host-Lifecycle; fehlende erforderliche
Hostvoraussetzungen bleiben `BLOCKED`.

## Adaptervertrag

Ein Adapter muss seine Grenze explizit machen, statt Host-Objekte an Shared
Code weiterzugeben. Das normale Runner-Modell deckt Vorbereitung, Start,
Stopp, Reload, Konfigurations- und Regelanwendung, Endpoint-Ermittlung,
Request-Ausführung, Artefaktsammlung und Cleanup ab. Ein Connector kann eine
gleichwertige host-spezifische Form implementieren, muss aber die
Evidence-Grenze bewahren: Nur beobachtetes Verhalten wird Runtime-Evidence.

Host-spezifische Phasenreihenfolge, Request- und Response-Body-Zustellung,
Interventionsverhalten, Logging, Connection-Handling und
Konfigurations-Merge-Regeln bleiben Connector-eigen. Das Framework macht aus
einer deklarierten Capability keinen Implementierungsclaim.

## Gepflegte Provenienz

Die folgenden Quellfakten bleiben absichtlich hier erhalten, weil
Adapter-Metadaten-Driftchecks sie validieren.

| Komponente | Upstream | Geprüfter Ref | Commit | Version | Lizenz | Adapter-eigener Pfad |
|---|---|---|---|---|---|---|
| ModSecurity-apache | https://github.com/owasp-modsecurity/ModSecurity-apache | master | `0488c77f69669584324b70460614a382224b4883` | `v0.0.9-beta1-26-g0488c77` | Apache-2.0 | `connectors/apache` |
| ModSecurity-nginx | https://github.com/owasp-modsecurity/ModSecurity-nginx | master | `9eb44fd9ab0988756e1ab8ce5aa5548ddbe57846` | `v1.0.4-14-g9eb44fd` | Apache-2.0 | `connectors/nginx` |
| ModSecurity v3 | `MODSECURITY_V3_APPROVED_REPO_URL` | `MODSECURITY_V3_RELEASE_TAG`-Metadaten; nur Commit-Fetch | `MODSECURITY_V3_APPROVED_COMMIT` | `LIBMODSECURITY_VERSION`-Metadaten | Apache-2.0 | Konfigurierte Engine-Quelle |
| ModSecurity v2 | https://github.com/owasp-modsecurity/ModSecurity | v2/master | `02eed22d74667b32091eece088a8ebdf64b6ba67` | `v2.9.13` | Apache-2.0 | Historische Semantikreferenz |

Produktive Apache- und NGINX-Adapterquellen sind absichtlich
connector-spezifisch. Ihre Attribution, Lizenz, Origin und Source-Maps bleiben
auch im Connector-Repository. Das Framework validiert Dokumentationsmetadaten,
ohne C-Code des Connectors zu linken.

Die ModSecurity-v3-Akquise akzeptiert nur den kanonischen HTTPS-Origin und den
geprüften vollständigen Commit aus Framework-`ci/lib/common.sh`. Der Release-Tag ist
Metadatum und kein Git-Selektor: Leere Legacy-Aliase `MODSECURITY_*` normalisieren zur
geprüften Identität; ein nichtleerer abweichender Wert stoppt vor einer
Git-Nutzung. Der Fetch-Pfad erstellt immer einen frischen Checkout, prüft den
gepinnten Root und initialisiert erst danach dessen rekursive Submodule
ausdrücklich. Ein Build-Pfad akzeptiert einen vorhandenen Checkout nur nach
Prüfung des exakten Roots und der statisch freigegebenen rekursiven Topologie
mit acht Kindern: Jedes Kind hat gepinnten Pfad, Origin und Commit, einen nicht
verlinkten physischen Worktree und enthaltenen Gitdir, genau ein `origin`,
abgetrenntes `HEAD` und einen sauberen normalen Index. `.gitmodules` und
Gitlinks werden damit nicht generisch akzeptiert: Jede fehlende, zusätzliche,
abweichende, verlinkte oder ausbrechende Topologie wird fail-closed abgewiesen.
Frische V3-Provisionierung ist ausschließlich über
`ci_provision_approved_modsecurity_v3_checkout` verfügbar: Sie akzeptiert ein
nicht vorhandenes Kind unter einem bestehenden kanonischen, nicht verlinkten
Parent, erzeugt einen privaten `0700`-Root und verwendet das geprüfte,
root-eigene sowie nicht gruppen- oder welt-schreibbare `/usr/bin/git` mit
bereinigtem `PATH`. Jede Operation nach `init` wechselt in diesen kanonischen
physischen Root und setzt ihren Worktree explizit, ohne `GIT_DIR` oder
`GIT_WORK_TREE` zu exportieren; dadurch bleibt der normale Worktree-Kontext
für Gits rekursiven Submodule-Helfer erhalten. Sie ignoriert externe
Attributes- und Sparse-Checkout-Zustände und entfernt lokale Werte für `core.worktree`,
`core.attributesfile`, `core.sparseCheckout` und `submodule.*.update` vor
rekursiver Git-Verarbeitung. Die Grenze löscht außerdem Dynamic-Loader-
Variablen, bevor sie eigene Prozesse startet; ein Caller muss die aufrufende
Shell weiterhin aus einer vertrauenswürdigen Umgebung starten.

## Sechs-Connector-Grenze

| Connector | Framework-Rolle | Erforderliche Evidence-Quelle |
|---|---|---|
| Apache | Anwendbare Fälle auswählen und materialisieren | Framework-Apache-Testadapter und beobachtete Hostartefakte |
| NGINX | Anwendbare Fälle auswählen und materialisieren | Framework-NGINX-Testadapter und beobachtete Hostartefakte |
| HAProxy | Anwendbare Fälle auswählen und normalisieren | Framework-Testadapter des gewählten Integrationsmodus und beobachtete Hostartefakte |
| Envoy | Anwendbare Fälle auswählen und normalisieren | Framework-Testadapter des gewählten Integrationsmodus und beobachtete Hostartefakte |
| Traefik | Anwendbare Fälle auswählen und normalisieren | Framework-Testadapter des gewählten Integrationsmodus und beobachtete Hostartefakte |
| lighttpd | Anwendbare Fälle auswählen und normalisieren | Framework-Testadapter des gewählten Integrationsmodus und beobachtete Hostartefakte |

Der gewählte Integrationsmodus, das Capability-Manifest, die
produktive Konfigurationsreferenz gehören zum Connector-Repository.
Das Framework erfasst und validiert beobachtete Lifecycle-Ergebnisse. Dadurch wird Dokumentations-, Compatibility- oder
Prototyp-Material nicht als native Runtime-Implementierung behandelt.

### With-CRS-/No-MRTS-Fünf-Connector-Profil

Das Framework definiert außerdem ein enges Evidenzvalidierungsprofil mit dem
Namen `five-connectors-with-crs-no-mrts`. Es ersetzt die obige
Sechs-Connector-Grenze nicht: Es wählt nur Apache, HAProxy, Envoy, Traefik und
lighttpd und schließt NGINX nur von diesem Profil aus.

Für jeden ausgewählten Connector muss der Connector-Owner begrenzte Raw- und
normalisierte Evidenz für die kanonischen CRS-Allow- und Block-Kontrollen
erzeugen. Der Framework-Validator prüft die konfigurierte Adapteridentität,
Request- und Transaktionskorrelation, gepinnte CRS-Provenance, das
`942270`-`deny`-Ergebnis, explizite No-MRTS-Receipt-Felder und
Cleanup-Receipt-Felder. Er akzeptiert weder dynamische Adapterauswahl noch ein
unvollständiges Fünf-Connector-Aggregat.

Dies ist eine Validierungsgrenze für vom Host bereitgestellte Evidenz;
die Definition dieses Profils führt keinen Framework-Host-Harness aus. Das Profil und ein erfolgreicher Validatorlauf belegen
nicht, dass fünf Hosts liefen, ein Connector produktionsreif ist oder MRTS-
Prozesse außerhalb des gelieferten Evidenzvertrags fehlten. Diese Runtime-
Fakten bleiben Verantwortung des Connector-Repositories. Eine erfolgreiche
Framework-Ausgabe ist ausdrücklich `CONTRACT_VALIDATED` mit
`host_runtime_status: UNATTESTED`, kein Connector-Host-`PASS`.

Das ausgewählte HAProxy-Tupel für dieses Profil ist
`haproxy-spoe-spop-agent` mit `spoe-spop-agent`. Sein Framework-Smoke-
Entrypoint ruft den Framework-eigenen SPOE/SPOP-Smoke-Harness für das
explizit ausgewählte Connector-Produkt auf. Das echte
native HTX-Tupel `haproxy-native-htx-filter` mit `native-htx-filter` bleibt
eine explizite separate Parent-Full-Lifecycle-Identität und wird als Evidenz
für das Fünf-Connector-Profil abgewiesen. Diese Bindung ändert keine
Capability-Kategorie eines Pfads und stuft kein Host-Runtime-Ergebnis hoch.

## Compatibility-Pfade

Der vom Fünf-Connector-Profil ausgewählte HAProxy-SPOE/SPOP-Smoke-Pfad ist ein
Compatibility-Entrypoint, kein nativer HTX-Filter. Der native HTX-
Full-Lifecycle-Pfad bleibt separat identifiziert und darf nicht als
SPOE/SPOP-Evidenz umbenannt werden. Historische HAProxy-SPOE/SPOA-Discovery-,
Disabled-Key-, Report-Schema- und Readiness-Notizen beweisen weiterhin keine
Host-Runtime. Aktuelle Arbeit muss den im Connector-Repository deklarierten
Integrationsmodus und kanonische Evidence verwenden; weder Adapter-Metadaten
noch historischer Planungstext erzeugen eine Capability oder Promotion.

Dieselbe Regel gilt für importierte Apache-, NGINX-, v2-, v3- und
MRTS-Referenzen: Ihr Code oder ihre Tests sind Eingaben für Review und
Ableitung, aber kein ausführbarer Beweis in einem anderen Connector.

## Eine Integration aktualisieren

1. Adapter-Metadaten und Connector-Origin-Datensätze mit der Adapter-Quelle
   ausrichten.
2. Integrationsmodus und Capability-Grenze im Connector-Repository deklarieren.
3. Einen echten Host-Harness bereitstellen, bevor Runtime-Unterstützung
   behauptet wird.
4. Begrenzte Artefakte normalisieren und über den anwendbaren Evidence-Vertrag
   validieren.
5. Framework-Berichte erst regenerieren, nachdem ihre Input-Evidence aktuell ist.

## MRTS-Vorbereitung

Für den gepinnten MRTS-Generator gilt die validierte Paketschnittstelle in
[MRTS-Vorbereitung und Übergabe](mrts-preparation.de.md).

## Historischer Kontext

Getrennte Importanalysen, Connectorpläne und HAProxy-SPOE/SPOA-Dokumente wurden
hier zusammengeführt. Git bewahrt die detaillierte Migrationshistorie; dieses
Dokument bewahrt den aktuellen Ownership- und Attribution-Vertrag.
