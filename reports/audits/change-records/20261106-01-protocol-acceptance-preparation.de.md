# Change Record zur Vorbereitung der Protokollabnahme

**Sprache:** [English](20261106-01-protocol-acceptance-preparation.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261106-01-protocol-acceptance-preparation |
| UTC-Datum | 2026-11-06 |
| Framework-Basisrevision der Fortsetzung | `b5d8d9442d7751c04ee84f478f594fc84a236e3b` |
| Issue oder Pull Request | [Framework-PR #169](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/169); finale Delivery-Identitäten und CI-Belege bleiben extern |

## Motivation und Problemstellung

Reale moderne Protokollqualifikation vorbereiten, ohne die 100 Standardfälle
oder bestehende Assertions zu ändern. Der ursprüngliche NGINX-Vorbereitungslauf
zeigte vier erforderliche H2-Reset-Fehler. Diese Fortsetzung beweist und behebt
deren Abhängigkeitsursache, verstärkt Client- und Evidenzkontrollen und ergänzt
getrennte H2-Vorbereitungspfade für Apache, lokales HTX, SPOP/HTX-Companion und
Envoy. Die umfassende Abnahme bleibt **NOT_RUN**; eine globale Bereitschaft der
Vorbereitung wird nicht erklärt.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework verantwortet Opt-in-Registries, Runner, Clients, Regeln, Reader,
Provisionierungshelfer, Tests, Compile-Inventar und zweisprachige Dokumentation.
Externe Parent-Abhängigkeiten verantworten Connector-Produktänderungen,
Profilmetadaten und Gitlink-Delivery. MRTS bleibt schreibgeschützt. Native
Testbeobachter ergänzen private verifizierte Quellkopien um Lebenszyklusmetadaten;
sie ersetzen weder Cleanup noch Entscheidungen. Artefakte und Evidenz bleiben
begrenzt, quellgebunden und außerhalb des Checkouts.

## Akzeptanzkriterien

Alle 25 NGINX-IDs und die Standardauswahl mit 100 Fällen erhalten; weitere 32 IDs
als acht Szenarien für jedes von vier getrennten H2-Profilen registrieren.
Erforderlich sind echtes TLS/ALPN oder explizites h2c, unabhängige native und
Wire-Identitäten, reale P2-POST-Bodies, Phasen-/Regelkorrelation, erste Bytes vor
EOS, isolierte Beendigung, gesunder Peer/Folge-Request und Target-Cleanup vor
Peer-Freigabe oder Schließen der physischen Verbindung. Fehlende,
widersprüchliche, veraltete oder beschädigte Evidenz sowie Schreibfehler müssen
scheitern. Wiederholungen am finalen Commit-Paar und aktuelle Head-CI bleiben
eigene Abschlussanforderungen.

## Untersuchte Alternativen

Timeout-Erhöhungen, schwächere Reset-Erwartungen, Unsupported-Umetikettierung
und reine Mock-Qualifikation würden erforderliches Verhalten verdecken. Eine
Erweiterung des Standardinventars würde dessen Vertrag ändern. Getrennte
Opt-in-Adapter erhalten die Auswahl und zeigen den beobachtbaren Lebenszyklus
jedes nativen Profils.

## Implementierungsentscheidung

Ein unabhängiges TLS/ALPN-Raw-Frame-Experiment trennte Server-Flush und
Client-Verarbeitung. Bei gehaltenem Peer verzögerte ungepatchtes NGINX den RST
etwa zwölf Sekunden; ein PING nach einer Sekunde gab ihn sofort frei. Der native
Quellcode zeigte eingereihte RST-Ausgabe ohne Schreibereignis, solange ein
anderer Stream aktiv blieb. Der kleine versionierte NGINX-Patch stellt an diesem
Rückkehrpfad das Schreibereignis der Verbindung zu. Der native Vorbereiter wendet
ihn nach Archivprüfung mit Fuzz null an und bindet seine Bytes für H2 und H3 in
Provenienz und Cache-Identität ein.

Der NGINX-libcurl-Client behält geprüfte TLS-1.3-Untergrenze, Peer-/Host-Prüfung
und CA-Konfiguration. Loopback-h2c bleibt explizit. Callback-ABI und numerische
JSON-Felder bleiben typisiert. Die neuen Nicht-NGINX-Adapter verwenden einen
verifizierten TLS-1.3-Raw-H2-Client mit HPACK-Statusdekodierung und echtem
begrenztem P2-POST. Natives Cleanup, Common-Engine-Entscheidungen, tatsächliche
Host-Aktionen und Wire-Ergebnisse bleiben getrennt. Native Manifeste prüfen die
geschlossene Produktquellmenge, exakte Beobachtertransformation, verifizierte
Archivbytes, Bibliothek und Binärdatei. Wiederverwendung erfordert eine frische
Byte-Zulassungsprüfung.

Externe Parent-Produktkorrekturen betreffen unter anderem Envoys nativen späten
Strict-Response-Pfad und dessen Profilpolicy. SPOP-Request-Phasen und der
HTX-Response-Companion behalten getrennte Eigentumsbelege; ein früher SPOP-Deny
darf keinen HTX-CLAIM erfinden. Leere SPOP-Testrequests senden explizit
`Content-Length: 0`; dies dokumentiert die aktuelle NOTIFY-ABI-Grenze und beweist
nicht jede H2-Body-Rahmung.

## Geänderte Dateien und Tests

Die Fehleruploadquelle hat ein separates exaktes Framework-eigenes aktuelles
Amendment mit unveränderlichem Migrationshash als Anker. Historische Lock mit
24 Quellen und sämtliche Actionpins bleiben unverändert. Nur die geprüften
Ersatzbytes sind zugelassen; Rückkehr ohne Diagnosen, breitere Uploadpfade,
falsche Baselineanker und geänderte Sicherheitsbedingungen werden weiterhin
abgewiesen. Zehn gezielte Vertragstests bestehen.

Die gehostete c042-Analyse meldete 83 offene Vorkommen. Jedes wird anhand seines
Vorkommens und seiner Quellgrenze geprüft. Validierung, Traffic und Cleanup der
Adapter sind ohne entfernte Prädikate aufgeteilt; wiederholte Nachweisdateinamen
sind Konstanten. Runtimewurzeln weisen lexikalische Traversierung explizit ab
und verwenden die native Deskriptor-/Ownershipprüfung ohne Linkverfolgung. Der
Apache-Beobachter erhält einen vererbten eigenen Append-Deskriptor statt eines
Umgebungspfads. Das sind Quelländerungen, keine Scanner-Ausnahmen oder
FALSE_POSITIVE-Serverentscheidungen. Finale gehostete Analyse und erforderliches
Quality Gate bleiben eigenständige Nachweise.

Der kanonische Apache-CRS-Launcher führt vor Hoststart einen frischen nativen
Ausführungskontext-Preflight durch. Er erbt Launcher-Credentials, prüft natives
PASS und übereinstimmende beobachtete UID/GID, erhält den privaten Snapshot und
gibt im Joblog nur den numerischen Identitätsnachweis aus. Fehler oder Nicht-PASS
verhindern den Hoststart. Sechs gezielte Kontrollen bestehen; die drei kanonischen
CRS-Ergebnisdateien, echte 403-/Regel942270-Audit- und Cleanupanforderungen bleiben.

- NGINX-Lifecycle-Runner, Protokollvertrag/-client/-regeln und Negativkontrollen
  unter `connector_suite/` und `tests/`.
- `ci/provisioning/patches/nginx/h2-close-stream-flush.patch`, nativer
  NGINX-Buildhelfer und Quell-/Cache-Zulassung in der Runtime-Provisionierung.
- `tests/runners/native_h2_probe.py` und `non_nginx_h2_acceptance.py`; getrennte
  Apache-, HAProxy-HTX-, HAProxy-SPOP/HTX- und Envoy-Harnesses samt gezielten Tests.
- Native Apache-/HAProxy-Beobachter-Buildhelfer und verifizierte Quellzulassung.
- CFamily-Compile-Rezepte/-inventar und native generierte Archivprojektionen;
  Standardfallauswahl und Vertrag der Offline-Ausnahmen bleiben erhalten.
- Der zweisprachige [Protokollleitfaden](../../../docs/protocol-acceptance-preparation.de.md)
  und dieser Record. Parent-Produkt-/Dokumentationsänderungen sind externe Abhängigkeiten.

## Befehle und Ergebnisse

`F` bezeichnet den ausgewählten Framework-Checkout, `P` den expliziten
Parent-Checkout und `PYTHON` den vorhandenen Framework-eigenen Interpreter
Python 3.15.2. Alle Shellbefehle laufen über RTK. Exakte Befehle, Umgebung,
Quellhashes, private Pfade, Preflight und Rohresultate bleiben in der externen
Fortsetzungsevidenz. Für die Abweichung von der konfigurierten Python-Version
wurde keine Toolchain installiert.

| Befehl oder Verfahren | Ergebnis | Externe Evidenz |
| --- | --- | --- |
| Vier unveränderte NGINX-H2-Regressionsfälle vor dem Patch | 4 FAIL; nativer Abort sofort, Reset erst nach gehaltenem Peer-Timeout | `h2/baseline-and-diagnosis.json` |
| Unabhängiges Raw-TLS-H2-Experiment mit/ohne PING | Ungepatchter RST verzögert; PING löst Ausgabe aus; gepatchter RST ohne PING nach etwa 0,015 Sekunden bei gesundem Peer/Folge-Request | `h2/diagnosis.md` |
| Frische native gepatchte NGINX-H2-/H3-Builds | PASS; genaue Quell-/Archiv-/Patch-Identität erhalten | `h2/targeted-before-after.json` |
| Dieselben vier H2-Regressionsfälle nach dem Patch | 4 PASS; alle ursprünglichen Reset-/Isolationsassertions erhalten | `h2/targeted-before-after.json` |
| Acht bestehende benachbarte H2-/H3-Hostfälle | 8 PASS am frischen H3-fähigen Build; eigenes Cleanup geprüft | `h2/targeted-before-after.json` |
| Gezielte NGINX-Patch-/Archivprüfungen | 25 PASS | `h2/unit-validation.json` |
| Reale TLS-1.2-only-Negativhandshakes und CLI-/Debug-Kontrollen | 3 Handshake-Ablehnungen, 28 Kontrollen PASS | `validation/client-current/` |
| Strikte C17-Callback-ABI-Positiv- und Const-Negativkompilierung | Kanonische Callback-Typen bestehen; zwei inkompatible kanonische Zuweisungen scheitern | `validation/abi-controls/` |
| Lokales natives HTX-H2 mit acht Szenarien | 8 PASS, 24 Transaktionen, 8 Cleanup-Barrieren bei weiter aktivem Peer/TLS | `profiles/haproxy/verification-receipt.json` |
| `rtk bypass env ... "$PYTHON" -P -m unittest connector_suite.modsecurity_connector_tests.test_haproxy_h2_acceptance -v` | 15 PASS; Archiv-, Beobachter-, Reader- und Artefaktzulassungskontrollen | `profiles/haproxy/unit-final.log` |
| HTX-Korruption realer Bundles, Artefaktnegative und tatsächlicher Wire-Schreibfehler | 100 Kontrollen PASS; realer Schreibfehler bleibt FAIL bei geprüftem Cleanup | `profiles/haproxy/focused-controls.json` |
| Nativer Envoy-H2-Kandidat | 8 PASS, 24 Transaktionen, 8 Cleanup-Barrieren bei aktivem Peer | `profiles/envoy/candidate-verification-hardened.json` |
| Finaler SPOP/HTX-v4-Kandidat | 8 PASS, 24 Transaktionen, 8 Cleanup-Barrieren bei aktivem Peer; EOS-Regel des Eigentümers über eindeutiges Handle/Lease korreliert | `profiles/spop/candidate-verification-hardened.json` |
| Apache-Quell-/Cache-/Provisionierungsverträge | 191 PASS, 5 Pin-abhängige Skips; frischer HTTPD-/Modulbuild PASS; H2-Cleanuptiming in Prüfung | `apache/final-apache-contracts` |
| `rtk bypass make check-documentation PYTHON="$PYTHON"` und begrenztes `rtk bypass git diff --check` | Exit 0; Links, zweisprachige Variablen, Repository-Pfade, Change-Record-Vertrag und Whitespace bestehen | `profiles/haproxy/change-record-documentation.log` |

Ein SPOP/HTX-v4-Zwischenkandidat hatte sechs bestandene und zwei fehlgeschlagene
Szenarien. Der finale Kandidat schließt die eigentümerspezifische
EOS-/Handoff-Beobachtungslücke durch einen diagnostischen Beobachter in einer
Quellkopie; Common-Produktquellen bleiben unverändert. Apaches erste tatsächliche H2-Auswahl bestand sechs Szenarien und erhielt
Strict-/Upstream-Resetfehler. Unabhängige Frames ohne/mit PING zeigen fehlende
Abortbenachrichtigung statt NGINX-Queueing; Parent besitzt die H2-Errorbucket-
Korrektur. Der lokale CRS-Preflight blockiert an der nicht zugeordneten
Default-Workeridentität der vorhandenen Fixture; gehostetes CRS und Aggregate
am aktuellen Paar bleiben erforderlich.

Ein anschließender vollständiger verwalteter Apache-Build bestand; seine erste
H2-Auswahl bestand alle acht Fälle und drei H1-Nachbarn. Die Wiederholung mit
gehärtetem Beobachter erhielt dann einen intermittierenden Strict-Cleanupfehler:
Reset und Folgezugriff gelangen, aber natives Cleanup wartete auf den gehaltenen
Peer. Der frühere PASS ersetzt diesen Fehler nicht; Ursache und finale
Wiederholung am eingecheckten Commitpaar bleiben zu prüfen.

Gepinnte HTTPD-Quellen und eine native APR-Interleavingkontrolle zeigen einen
zweiten Abhängigkeitsfehler: Der Abschluss eines gehaltenen Resetstreams reiht
seine Bereinigung ein, ohne den Poller der physischen Verbindung zu wecken;
ein Wakeup allein kehrt in den unterbrochenen Poll zurück. Der versionierte
zweiteilige Patch weckt den Poller und gibt ausstehende Bereinigung an den
bestehenden sicheren äußeren Cleanuppunkt zurück. Shutdown und Abort behalten
Priorität. Fünf native Kontrollen prüfen ursprünglichen Timeout, unzureichendes
Wakeup allein, kombinierte Korrektur und beide Shutdownpfade. Frischer verwalteter
Build und echte Qualifizierung am eingecheckten Commitpaar bleiben getrennt nötig.

Die unabhängige Prüfung nahm die frühere Envoy-Cancelqualifizierung zurück:
Upstreamfreigabe erlaubte normalen EOS-Abschluss. Der gehärtete Treiber hält EOS
bis zum nativen Cancelcleanup. Beide Leser weisen nun widersprüchliches TLS/ALPN,
fehlende Request-/Body-/Barrierennachweise, falsche Phasen/doppelte Entscheidungen
und falsche Resetcodes zurück. SPOP-Wirewriterfehler umgehen kein eigenes Cleanup.
Neunzehn gezielte Tests, frische acht Fälle je Profil und der tatsächliche
Writerfehler-Cleanup-Test bestehen; die begrenzte unabhängige Zweitprüfung
schließt diese Lücken. Originalreceipts und ausdrückliche Qualifizierungskorrektur
bleiben erhalten. Kandidatennachweise ersetzen keine Läufe am finalen Paar.

## Sicherheitsauswirkung

Der NGINX-Abhängigkeitspatch stellt rechtzeitige requestlokale Reset-Zustellung
wieder her, ohne Isolation zu schwächen oder erforderliche Fehler zu ändern.
Native Provenienz lehnt veraltete oder fremde Quellen/Artefakte ab. Die
Client-TLS-Konfiguration scheitert geschlossen; TLS-1.2-only-Kontrollen prüfen
reale Ablehnung. Authentifizierung, Compilerwarnungen, Assertions, Fähigkeiten
und Analyse-Gates werden nicht gelockert. Keine Sonar-Unterdrückung oder
serverseitige Issue-Einstufung wird angewandt. Evidenz enthält keine Credentials,
privaten Schlüssel oder rohen Response-Handles; SPOP/HTX korreliert Hashes.

## Dokumentation und Runtime-Evidenz

Leitfaden und Record in EN/DE beschreiben getrennte 25-/32-Registries, Befehle,
beobachtbare Grenzen und Kandidatenevidenz. Frühere versiegelte Läufe bleiben
historisch: Das ursprüngliche Commit-Paar hatte 21/25 bestandene neue
NGINX-Fälle, vier H2-Fehler und acht benachbarte PASS. Das unabhängige kausale
Experiment und unveränderte gezielte Wiederholungen schließen diesen konkreten
Abhängigkeitsfehler. Historische und Kandidatenevidenz werden nicht als finale
Commit-Head-Qualifikation umetikettiert. Absolute lokale Pfade und vollständige
Quell-/Artefaktidentitäten bleiben in externen Belegen.

Die sechs offenen und 30 durch Analyse geschlossenen Sonar-Vorkommen erhalten
jeweils eine sachliche Einzelprüfung in externem `sonar/per-occurrence-review.json`
und dessen Markdown-Begleiter. Kanonische ABI-Kompilierung und reale
TLS-Kontrollen stützen die technische Prüfung; sie setzen keinen serverseitigen
Status `FALSE_POSITIVE` und belegen kein bestandenes aktuelles Quality Gate.

## Nicht ausgeführte Prüfungen

Umfassende Abnahme: **NOT_RUN**, ausdrücklich zurückgestellt. Lokaler Sonar-Scan,
Installation, Dienststart und Login: nicht ausgeführt. Die 25+8-NGINX-Wiederholung
am finalen Commit-Paar, vollständige finale Nicht-NGINX-Qualifikation,
Apache-Host-/CRS-Evidenz und maßgebliche aktuelle GitHub-/Sonar-/CodeQL-Ergebnisse
stehen aus. Diese Vorbereitungsarbeit autorisiert oder vollzieht keinen Merge.

## Einschränkungen und Restrisiko

Kandidaten-PASS gelten nur für zugelassene Quellbytes/Artefakte und ausgewählte
Profile. Der Apache-Abschluss bleibt offen. Die SPOP-MRC1-Grenze überträgt weder
die Response-Regel-ID noch ein separates Strict-Ergebnis; ein unabhängiger
Beobachter beim Eigentümer verbindet diese Entscheidung mit Handle/Lease,
nativer Host-Aktion und Wire. Alle
zehn logischen Profile behalten getrennte Fähigkeitsbehauptungen; Stock-/Patch-
lighttpd behalten ihren bestehenden H1-Vertrag. Build-, Registry-, Unit- oder
Kandidaten-Hostevidenz bedeutet keine globale Bereitschaft oder Capability-Promotion.

## Finaler Diff- und Review-Status

Der bestehende Framework-[PR #169](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/169)
und externe Parent-[PR #445](https://github.com/Easton97-Jens/ModSecurity-conector/pull/445)
bleiben getrennte Delivery-Grenzen. Die ausdrücklich erlaubten ursprünglichen
Pushes und Draft-PRs implizieren keinen Merge. Dieser Record ersetzt veraltete
inkrementelle Anhänge durch den Fortsetzungsumfang. Finaler Quellfreeze,
Generatorprüfungen, Review, Qualifikation des Commit-Paars und exakte Head-CI-Belege
bleiben erforderlich; ihre Ergebnisse müssen vor Erklärung des
Vorbereitungsabschlusses festgehalten werden.
