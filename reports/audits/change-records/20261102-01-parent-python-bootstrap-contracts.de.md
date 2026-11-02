# Change Record

**Sprache:** [English](20261102-01-parent-python-bootstrap-contracts.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261102-01-parent-python-bootstrap-contracts |
| UTC-Datum | 2026-11-02 |
| Framework-Basisrevision | `91145b7ba721bdec4e89af754cf40bf496fd2a08` |
| Issue oder Pull Request | Angeforderte Reparatur der Parent-Runs `41412784227` und `41412832386`; Framework-PR #158; ursprünglicher Record entstand vor PR-Erstellung |

## Motivation und Problemstellung

Aktuelle Parent-Python-Updater-Prüfungen lehnen die Framework-Composite-
Bootstrap-Reihenfolge, veraltete Job-Inventare und nicht unterstützte geschützte
oder historische Workflow-Komposition ab. Der Kontext-Binder führte zuvor Python
vor Setup und Interpreter-Verifikation aus. Diese Framework-Änderung repariert
wiederverwendbare Verträge; native Parent-Änderungen bleiben eine eigene Lieferung.

## Betroffene Komponenten und Sicherheitsgrenzen

Die 18 Implementierungen unter `.github/actions/connector-ci/`, der
Framework-eigene Python-Workflow-Checker und
`modsecurity_test_framework/workflow_sources.py` erhalten die Grenze zwischen
Parent-Gitlink, ausgechecktem Framework-Code, unveränderlichen Remote-Actions
und authentifizierter geschützter Ausführung. MRTS bleibt unverändert.

## Akzeptanzkriterien

Shell-Source-Nachweis vor ausgechecktem Interpreter-Verifier; Setup und
Verifikation vor Kontextbindung. Normales Inventar entspricht 47 aktuellen Jobs.
Geschützte Jobs behalten den exakten authentifizierten Verifier. Historische
Komposition akzeptiert nur ihre geprüfte unveränderliche Form. Bestehende
negative Umgehungstests bestehen.

## Untersuchte Alternativen

Eine pauschale First-Use-/Kontext-Ausnahme würde ungeprüftes Python akzeptieren.
Ein direkter Verifier statt geschütztem Wrapper verlöre Authentifizierung. Den
historischen Reusable-Aufrufer als lokalen normalen Job einzuordnen würde
Ausführung erfinden. Alle drei Alternativen wurden abgelehnt.

## Implementierungsentscheidung

Shell-Gitlink-/HEAD-Gleichheit, exakte Setup-/Verifier-/Kontext-Reihenfolge,
getrennte geschlossene Inventarklassen und ein geschlossenes historisches
Workflow-Call-Mapping. Geprüft werden sechs verpflichtende String-Inputs,
gleichnamige Weitergabe, Deny-Default-Berechtigungen, `contents: read`, genau ein
unveränderlicher verschachtelter Aufruf auf
`8ae707d72f1a8acb25d239e55e28a73cbc7522b1` und fehlende Concurrency-Overrides.
Nur zwei geschützte Broker-Jobs erlauben den exakten authentifizierten Verifier
`ci/run-trusted-framework.py --tool python-interpreter`.

## Geänderte Dateien und Tests

18 Composite-Action-Definitionen; Connector-Python-Workflow-Checker und dessen
`test_python_version_contract.py`; `workflow_sources.py` und
`tests/connector_adapter/test_workflow_sources.py`; zweisprachige
Connector-Integrationsdokumentation und dieser Record. Tests führen positive und
negative Source-Gates aus, lehnen unbelegte Kontext-Ausnahmen ab, mutieren
historische Grants/Pins/Inputs/Jobs und lehnen direkte Verifier in geschützten
Jobs ab.

## Befehle und Ergebnisse

`FRAMEWORK_PYTHON` bezeichnet die explizite Framework-eigene Python-3.14-Test-venv.
Der lokale Ausführungsplan enthält vollständige Kontext-/Umgebungsargumente.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk bypass env ON_DEMAND_TESTS=1 PYTHONPATH=.:connector_suite "$FRAMEWORK_PYTHON" -m unittest tests.connector_adapter.test_workflow_sources modsecurity_connector_tests.test_python_version_contract -q` mit explizitem Source-/Revisionskontext | 0 | 62 Tests bestanden; Parent-Aufrufer von `430d3194fa04ca4aafcdaef6aeb256d21dc18f0c` auf Feature-Framework-Source projiziert | Lokale begrenzte Prüfung |
| `rtk bypass git diff --check` | 0 | Keine Whitespace-Fehler im Implementierungsdiff | Lokale begrenzte Prüfung |

Zusätzliche Regressionen aktualisieren `connector_suite/modsecurity_connector_tests/test_framework_workflow_pin_projection.py` und den unabhängigen Helper `framework_sha_fixture.py`. Gegen den getrennten Parent-Patch bestanden 10 Projektionstests und 39 Updater-Tests: Die sechs frühen Selected-Action-Gate-Pins bleiben geschlossen, folgen dem bestehenden Pin-Synchronisierer, weisen veraltete/fehlende/zusätzliche/symbolische Identitäten ab und stoppen einen geänderten Gitlink samt geändertem Checkout vor Verifier-Ausführung. Unabhängiges Review bestand außerdem 24 Shell-Zulassungsfälle. Native Dokumentationsprüfungen und Ruff-Lint bestanden. Vollständiger Datei-Formatter-Drift in drei historischen Python-Dateien besteht auch in der Basis; diese unabhängigen Bereiche wurden erhalten. Die zuvor formatierte `workflow_sources.py` bleibt formatiert.

Gehostete Scaffold-Validierung identifizierte den unveränderlichen Connector-Source-Vertrag als weiteren betroffenen Owner. Genau die 18 geprüften Composite-SHA-Einträge in `ci/tooling/connector-actions.lock.json` und ihr Aggregat in `ci/checks/security/connector_action_pins.py` wurden nach Authentifizierung des bisherigen Vertrags deterministisch durch ein externes Skript erneuert. Dieser gepflegte Snapshot hat keinen eingecheckten Generator. Action-Records, Quellenregister, Autorität und sechs unveränderte Quellen bleiben erhalten. Natives `rtk make check-canonical-common-pins PYTHON="$FRAMEWORK_PYTHON"` und sechs Tests aus `tests.ci_security.test_connector_action_pins` bestanden, einschließlich manipulierter früher Identitäts-/Checkout-/Selektorprüfungen über alle 18 Composites.

Der gehostete Sonar-Job `125190844829` von PR #158 scheiterte anschließend bei
der Installation der Voraussetzungen, weil sein Index-Update nur die
Microsoft-Quelle für Ubuntu 26.04 lud. Die geprüfte Reparatur in
`.github/workflows/sonarqube.yml` prüft den exakten Ubuntu-26.04-/resolute-Host
und vorhandenen regulären/lesbaren Signaturschlüssel, schreibt eine feste
Root-eigene Deb822-Quelle für offizielle HTTPS-Ubuntu-Archive/Sicherheitsarchive
und macht jeden Index-Update-Fehler fatal. Vollständige bisherige Paketliste,
Signaturen, Source-/Secret-Grenze, nativer Umfang und Quality Gate bleiben
erzwungen. Das exakte Programmprofil `sonar_pr_secret_allowed` ist angepasst;
zwölf negative Mutationen lehnen fremde Ursprünge/Suites/Keyrings, unsignierte
Optionen, Host-/Index-Umgehungen und entfernte Abhängigkeiten ab. Lokales APT
oder Systemkonfiguration wurden nicht verändert. Der gepaarte Tooling-Leitfaden
erklärt diese Provisionierungsgrenze.

Mit der expliziten Framework-Python-3.15-venv der Aufgabe bestand `rtk bypass env
TMPDIR=$BUILD_EVIDENCE/contracts/tmp
PYTHONPYCACHEPREFIX=$BUILD_EVIDENCE/contracts/pycache "$FRAMEWORK_PYTHON315" -m
unittest tests.security_regression.test_sonar_analysis_contract -q` 20 Tests.
`$BUILD_EVIDENCE` und `$FRAMEWORK_PYTHON315` sind portable Aliase im lokalen Plan.
Der Sonar-Workflow bestand den vollständigen Workflow-Checker, Actionlint,
`bash -n` des geparsten Run-Texts, Ruff-Lint für die zwei geänderten Python-Dateien
und `git diff --check`. Diese Prüfungen führten APT nicht aus und belegen kein
gehostetes Analyseergebnis; der reparierte Stand benötigt einen neuen
gehosteten Sonar-Lauf.

Der Parent-Folgecommit erreichte auf dem Hosted-Runner erfolgreich die
Interpreterprüfung mit Python 3.15.1 und verweigerte danach veraltete geprüfte
Framework-Quelldigests. `connector_suite/config/testing/active-cases.json` wurde
über den vorhandenen Einstieg `update-inventory-bindings.py --apply` erneuert.
Der strukturelle Vergleich belegt ausschließlich zehn geänderte SHA-256-Werte;
alle anderen Felder und Listenlängen sind identisch. Das Inventar behält 80
Ausführungseinträge, 100 Standardfälle, 2.686 Katalogfälle und 2.586 On-Demand-Fälle.
Generatorprüfung und native Connector-Zulassung (`--check`, keine Matrix)
bestanden; 72 fokussierte Inventartests bestanden mit zwei übersprungenen Tests.
Nach fünf zusätzlichen Sonar-Wartbarkeitskorrekturen bestanden 62 Workflowquellen-
und Python-Vertragstests unter Python 3.15.2. Der historische Broker behält seine
exakte Revision, Berechtigungen und weitergeleiteten Eingaben.

## Sicherheitsauswirkung

Die Änderung repariert Bootstrap-/Source-Vertragskorrektheit und erhält
unveränderliche Referenzen, Berechtigungen, authentifizierte geschützte
Einstiegspunkte und Fehler-Gates. Ursprüngliche Reihenfolgefehler und alternative
Umgehungen durch unbelegten Kontext oder direkten geschützten Verifier decken
negative Tests ab. Dies ist keine Connector-Sicherheitsbewertung.

## Dokumentation und Runtime-Evidenz

`docs/connector-integration.md` und die deutsche Begleitdatei beschreiben den
Bootstrap und die begrenzte Komposition. Tests liefern statische Source- und
lokale Shell-Evidenz. Dieser Record belegt keine vollständig erfolgreiche CI für den aktuellen
Commit, Connector-Host-Runtime, Merge oder Parent-Pin-Aktualisierung.

## Nicht ausgeführte Prüfungen

Hosted-Sonar auf Framework `44d5481cff7c7c75974e9f1f61a10f6eee4a286d` bestand die
APT-Bereitstellung und erreichte die Analyse. Die verbliebenen Befunde im neuen
Code wurden ohne Unterdrückungen bearbeitet; die erneute Analyse steht noch aus.
Connector-Runtime-Matrizen liegen außerhalb dieser Workflow-Vertragsänderung.
Das vollständige Default-Inventar wurde nicht erweitert oder abgeschwächt.

## Einschränkungen und Restrisiko

Native Parent-Reihenfolgereparaturen und der Bezug dieser Framework-Revision
sind getrennte Voraussetzungen kombinierter CI-Kompatibilität. Der alte
Parent-Framework-Pin liefert diese neuen Verträge nicht. Historische
verschachtelte Workflow-Inhalte bleiben unveränderlich; ihre Schnittstelle zu
komponieren führt sie nicht aus.

## Finaler Diff- und Review-Status

Implementierungsdiff und Whitespace geprüft; keine Secrets oder Rohlogs erfasst.
Unabhängiges Review fand keinen offenen Blocker; gehostete Prüfungen bleiben vor finaler Lieferung offen.

Der nächste gehostete Parent-Commit bestand die Inventar-Digestgrenze; sein NGINX-Setup/Quick-Check verweigerte anschließend korrekt das abgeleitete Spezialistenarchiv. `connector_suite/reports/testing/test-selection-archive.generated.json` wurde mit dem vorhandenen `update-test-archive.py` neu erzeugt. Die vorherigen Inventar- und Quelldigests entsprachen exakt der letzten Archiv-Basis. Die Änderung beschreibt den neuen Inventar-Digest, 16 vorhandene und einen neuen Quelleintrag sowie 35 zusätzliche On-Demand-Definitionen. Native Quellen, Framework-Fallkataloge und extrahierte native Definitionen bleiben unverändert. Dies beschreibt deklarative Verfügbarkeit, keine zusätzliche automatische Auswahl oder Ausführungsevidenz. Der vollständige native Einstieg `make check-active-inventory` bestand mit beiden Ansichten unter Python 3.15.2.

Dauerhafter Updater-Folgefix: Ein normaler Python-Patch oder kanonisches
Komponentenupdate würde sonst das vollständig quellgebundene `common.sh`
ändern, ohne Inventar/Archiv zu erneuern. Der exakte Einstieg
`sync-maintenance-test-views.py`, geordnete native Ableitung und genau diese zwei
generierten Pfade wurden in Candidate-, Publisher- und Rollback-Profile der
Common-Wartung aufgenommen. Python-Veröffentlichung behält die einzelne
Zuweisung und vier exakte Pfade; vor dem Draft-Checkout prüft vertrauenswürdiger
Code feste reguläre Git-Blobs, unveränderte Modi, den strikten ASCII-Python-
Selektor und bytegenaue basisabgeleitete Metadaten. Zu große Blobs werden vor
dem Einlesen verweigert, fremder Git-/Kontextbezug und zusätzliche Metadaten-
änderungen abgelehnt. Im bewusst minimalen Snapshot des Workflow-Tool-Validators
läuft keine Vollquellableitung. Eigenständige Schreibläufe brechen beim Fehler
ab; Common-Maintenance stellt beim Generatorfehler seinen Snapshot wieder her.

Validierung mit tatsächlichem Python 3.15.2: 105 kombinierte Publisher-/Security-/
Python-/Wartungstests bestanden (20,373 s), einschließlich zwölf Helper-Fällen
und 33 kanonischen Workflow-/Rollback-Fällen. Ruff-Lint/Format bestanden für alle
sieben geänderten/neuen Python-Dateien, Actionlint für alle drei geänderten
Workflows. Exakte geprüfte Programmhashes und geschlossene Metadaten-Pfadmengen
wurden gemeinsam angepasst. Die Metadatenansichten werden erst nach Abschluss
dieser Quell-/Teständerungen erneuert.

Ein synthetischer Offline-Pinwechsel von `3.15.2` auf `3.15.3` durchlief die echten
nativen Python-Pin- und Testansicht-Generatoren: Genau vier Ausgabedateien änderten
sich, im Inventar ausschließlich der vorhandene Common-Quelldigest und im Archiv
der daraus abgeleitete Digest. Keine Auswahl änderte sich. Alle vier Taskdateien
wurden bytegenau wiederhergestellt; dies behauptet kein Upstream-Release. Finale
reale Metadaten-Erzeugung, schreibgeschützte Prüfung und vollständige native
Inventar-/Archivzulassung bestanden. Das finale Archiv erhält 8.021 On-Demand-
Definitionen; diese sind von 2.686 auswählbaren Katalogfällen und den unveränderten
100 automatischen Standardfällen zu unterscheiden.

Die gehostete Qualitätsprüfung fand drei Typfehler wegen optionaler Imports im neuen Test-Fixture-Loader. Eine explizite Laufzeitprüfung verwirft nun fehlende Modulspezifikation oder Loader vor dem Import; zwölf Helper-Tests und vollständiges Ruff-Lint/Format bestanden erneut. Lokales Pyright bleibt ohne Node nicht ausführbar; das neue gehostete Ergebnis muss dies belegen. Der Archiv-Quelldigest wurde über denselben nativen Helper erneuert.

Die abschließende Sonar-Prüfung meldete einen verbleibenden CLI-zu-Git-Argumentpfad bei der Kandidatenprüfung. Der Helper akzeptiert nun keine Revisionsargumente per CLI: Der Kandidatenmodus verwendet ausschließlich die festen Referenzen `origin/master` und `origin/automation/update-framework-python-315`. Nach Prüfung des angegebenen Checkouts liefert die Root-Auswahl die vertrauenswürdige Tool-Root-Konstante. Zwei Regressionstests prüfen diese festen Referenzen und verweigern Überschreibungen vor dem Prozessstart. Git-Optionsgrenzen, begrenzte Blobs, Modusprüfungen und bytegenaue Begleitprüfungen bleiben wirksam.

Die abschließenden 107 gezielten Tests bestanden mit Python 3.15.2 (21,222 s), einschließlich aller 14 Helper-Fälle. Ruff-Lint/Format und Actionlint bestanden. Die native Neugenerierung erhielt die automatische Auswahl unverändert und ergänzte ausschließlich die zwei neuen On-Demand-Testdefinitionen auf insgesamt 8.023 archivierte Definitionen.

Der aktuelle Default-Branch wurde durch die Wartungs-Import-/Diagnosekorrektur auf `ea442cf90861ddc6d555e67352d053d4ad95f731` aktualisiert. Er wurde in diesen Feature-Branch integriert; sichere Diagnosen und aufbewahrte Fehlerartefakte bleiben erhalten. Das kombinierte Resolver-Programm ist an SHA-256 `99d1d2f4bd3416cdf82dab590c2dee5bdf1937570a2c4a94fdd91e76ce06a98a` gebunden. OSV ergänzt genau ein exaktes Kompatibilitätstupel des aktuellen Default-Branches mit dessen geprüftem Selektor `3.14.10`; beide früheren exakten Tupel bleiben unterstützt.

Der neu übermittelte Lauf `41436076145`, Job `125246693705`, scheiterte auf dieser Default-Revision, weil der kanonischen Wartung die registrierte Ausgabe `.github/workflows/ci-findings-regressions.yml` des nativen Updaters in der Transaktions-Pfadrichtlinie fehlte. Genau ein Dateiname wird ergänzt. Drei Regressionstests prüfen Registry-Vollständigkeit, echte native Workflow-Projektion und Anwenden/Rollback samt Ablehnung benachbarter Pfade. Der unveränderte aufrufergebundene Plan (interner SHA-256 `9d99bdc3523a4ba69e8280ce031461744d8c8f09b769750c6cb1c8d09a7177db`) wurde offline gegen die exakte archivierte Fehlerrevision mit ausschließlich dieser Ein-Pfad-Korrektur nachgespielt: Alle 43 sicheren Updates bestanden über 22 generierte Pfade. Dabei wurden keine Komponentenupdates veröffentlicht.

Der verschachtelte CRS-Regressionsrunner erhält nun einen explizit gewählten externen `PYTHONPYCACHEPREFIX`; Bytecode-Schreibschutz und die ursprüngliche geschlossene Umgebung bleiben erhalten. Ein kalter Python-3.15-Testmodulimport benötigte 2,128 s und überschritt die vorhandene Bereitschaftsfrist von 2 s bereits vor dem FIFO-Zugriff. Mit dem normalen vorgewärmten externen Cache bestand der unveränderte FIFO-Test in 1,237 s; das vollständige CRS-Modul mit zehn Tests bestand in 58,329 s einschließlich der verschachtelten Vertragssuite mit 29 Fällen. Eine unabhängige schreibgeschützte Probe bestand ebenfalls. FIFO-Fristen, Ablehnungsassertions, Reader-Kontrollen und CLI-Timeouts wurden nicht verändert.

Der Nutzer bat zusätzlich um die Versionen aus den offenen Dependency-Review-Issues: #161 (CPython 3.15.2) ist durch die Interpreter-Umstellung abgedeckt; #160 wird mit Ruff 0.17.3 statt 0.16.10 umgesetzt. Das [offizielle Ruff-Release 0.17.3](https://github.com/astral-sh/ruff/releases/tag/0.17.3) ist das aktuelle stabile Release und weder Draft noch Vorabversion. Sein unveränderlicher Tag-Commit ist `ba65abf8ba7bfbcc059f7fb9712be5ba9cab6abc`; der SHA-256 des Linux-x64-GNU-Artefakts `2b0890f5a55900af741f133918c2656919bbf18c2ab7741b4ca8403a90e647a9` stimmt mit offizieller Prüfsumme und GitHub-Artefaktdigest überein. Der vorhandene native prüfsummengebundene Fetcher installierte das geprüfte Binary im externen Task-Speicher. Beide exakten Befehle des Qualitätsworkflows bestanden damit: Lint und Formatprüfung von 42 Dateien. Regeln, Formatkonfiguration und Quellformatierung mussten nicht geändert werden. Ausschließlich die drei veränderten Ruff-Pinfelder und ihr generierter Lock-Eintrag werden aktualisiert; andere kompatible Updates aus dem archivierten 43-Update-Plan gehören nicht zu diesem zusätzlichen Issue-Umfang.

Der Default-Branch wurde anschließend durch ein unabhängiges MRTS-Gitlink-Update auf `68ca7b411db12ed96ee6208aa792b43e8043470c` aktualisiert. Das noch unveröffentlichte Wartungs-Kompatibilitätstupel bezeichnet nun ausschließlich diese exakte Basis mit dem unabhängig geprüften Selektor `3.14.10`. Der Feature-Branch integriert die Wartungscode-Korrektur aus `ea442cf`; MRTS wird weder geändert noch initialisiert. Die vorhandene Framework- und Parent-MRTS-Revision bleibt in der geprüften Integration ausgewählt.
