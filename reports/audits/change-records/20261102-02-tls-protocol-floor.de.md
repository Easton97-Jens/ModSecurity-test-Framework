# Change Record: explizite TLS-Protokolluntergrenze

**Sprache:** [English](20261102-02-tls-protocol-floor.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261102-02-tls-protocol-floor |
| UTC-Datum | 2026-11-02 |
| Framework-Basisrevision | `f11d4617ff98ad615c72c1b6672fc386394db41e` |
| Issue oder Pull Request | GitHub-CodeQL-Meldungen #17–#21; Kandidaten-PR beim Entwurf dieses Records noch nicht erstellt |

## Motivation und Problemstellung

Die fünf verbleibenden offenen `py/insecure-protocol`-Meldungen betreffen SSL-Kontexte ohne explizite Protokolluntergrenze. Frühere Prüfungen des tatsächlichen Hosts wiesen altes TLS bereits durch Plattformvorgaben ab. Diese Änderung legt einen expliziten Quellvertrag fest; sie behauptet keinen zuvor ausnutzbaren alten Handshake auf diesem Host.

## Betroffene Komponenten und Sicherheitsgrenzen

Die Grenze umfasst zwei Framework-eigene HAProxy-Harness-Clientkontexte und drei Serverkontexte von Loopback-Fixtures. Clients behalten CA-Prüfung und Hostnamenprüfung. Parent-Produktquellen und Framework-Gitlink bleiben unverändert; MRTS bleibt `default_read_only`. Frühere einzelne Meldungseinstufungen bleiben unangetastet.

## Akzeptanzkriterien

Alle fünf tatsächlichen Kontexte verlangen explizit TLS 1.2, behalten ihre unbeschränkte Obergrenze und unterstützen TLS 1.2/1.3. Die tatsächlichen Kontexte müssen TLS 1.0/1.1 abweisen, nachdem permissive Peers diese Protokolle als Positivkontrolle erfolgreich ausgehandelt haben. Clients müssen falsche Hostnamen und nicht vertrauenswürdige Zertifikate abweisen. Die eigenständige native Clientkopie sowie bestehende tatsächliche Loopback-/Kindprozesskontrollen bleiben nutzbar. Native Metadaten, Dokumentation, Sicherheitsverträge, unabhängiges Review und Hosted-Prüfungen des exakten Heads müssen bestehen. Unverändertes natives CodeQL muss die fünf betroffenen Ergebnisse weglassen und die übrigen Rohergebnisse erhalten. Die Schließung auf Master benötigt gesondert autorisierte Integration und anschließende Analyse.

## Untersuchte Alternativen

Die Abhängigkeit von aktuellen OpenSSL-Vorgaben lässt den Quellvertrag implizit. Dismissal, Unterdrückung, Ausschlüsse oder abgeschwächte Abfragen setzen die gewünschte Korrektur nicht um. Ein gemeinsam importiertes Kontextmodul würde den Vertrag der eigenständigen Quellkopie des nativen Clients verletzen. Eine TLS-1.2-Obergrenze würde TLS 1.3 unnötig deaktivieren. Fünf kleine lokale Kontextfabriken vermeiden diese Änderungen.

## Implementierungsentscheidung

Jeden bestehenden Konstruktor in eine lokale Fabrik auslagern, `context.minimum_version = ssl.TLSVersion.TLSv1_2` setzen und die Fabrik an der bisherigen Laufzeit-Aufrufstelle nutzen. Zertifikatladen, CA-Prüfung, Hostnamenprüfung, Socket-Behandlung und strikte EOF-Behandlung bleiben erhalten. Keine Obergrenze setzen und keinen externen Import in den kopierten nativen Client einführen.

Die Regression nutzt echte `ssl.MemoryBIO`-Peers und tatsächliche Anwendungsbytes mit begrenzter Handshake-Schleife. Bewusst permissive alte Peers existieren ausschließlich in socketfreien Positivkontrollen; die tatsächlich geprüften Kontexte werden niemals abgeschwächt. Nicht verfügbare alte Kontrollen scheitern explizit. Die verpflichtende CI-Ausführung behandelt jeden Skip als blockiert.

Das gewählte [CodeQL-SSL-Modell](https://github.com/github/codeql/blob/6e9f9e38390175c41b99070a423c875f450759ca/python/ql/src/Security/CWE-327/Ssl.qll#L130) modelliert diese Mindestversionszuweisung als Protokollbeschränkung. Diese Quellmodellevidenz benötigt weiterhin die Scannerbestätigung am exakten Kandidaten.

## Geänderte Dateien und Tests

- `connector_suite/adapters/haproxy/harness/i12_companion_host.py` und `i12_native_sequences.py`: explizite Fabriken für geprüfte Clientkontexte, die die tatsächlichen Pfade verwenden.
- `connector_suite/modsecurity_connector_tests/test_envoy_transport_hardening_contract.py`, `test_haproxy_htx_transaction_id.py` und `test_haproxy_i12_companion_host.py`: explizite Serverkontextfabriken für bestehende Fixtures. Die Kindprozess-Assertion des Companions ermittelt ihr erwartetes Skript über den bestehenden Auswahlvertrag `source_path` statt über einen veralteten Parent-Pfad.
- `tests/security_regression/test_tls_protocol_floor.py`: sieben Methoden, 32 expandierte Szenarien: fünf Quell-Untergrenzenprüfungen, zwei alte Positivkontrollen, zehn Abweisungen alter Protokolle, zehn moderne Positivkontrollen, vier negative Client-Authentifizierungsprüfungen und eine isolierte Prüfung der eigenständigen Kopie.
- `.github/workflows/ci-findings-regressions.yml`: betroffene Pfade aufnehmen und die neue Regression zusammen mit drei bestehenden tatsächlichen Loopback-/Kindprozesskontrollen ohne zulässige Skips ausführen. Scanner-Abfragen, Kategorien, Ausschlüsse und Berechtigungen bleiben unverändert.
- Native Generatoren aktualisieren genau drei Inventar-Quellhashes, ergänzen sieben archivierte Definitionen (7.966 auf 7.973) und aktualisieren Quell-/Aufrufermetadaten der Migration. Alle Fall-IDs und Selektoren bleiben unverändert: Standard 100 Fälle/80 Ausführungen, optional 2.586/1.140 und 1.993 ursprüngliche IDs erhalten.

## Befehle und Ergebnisse

Alle Verfahren verwenden RTK und den Framework-eigenen Interpreter. `FRAMEWORK_ROOT` bezeichnet den Task-Worktree; `RUN_ROOT` bezeichnet die konfigurierte externe Evidenzwurzel für Run-ID `framework-tls-floor-20261102`. Genaue Aufrufe und Lifecycle-Ergebnisse verbleiben im dortigen Ausführungsplan; Rohlogs und private Zertifikatschlüssel werden hier nicht kopiert.

| Befehl oder beobachtetes Verfahren | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Fokussierte Quell-Untergrenzenregression vor den fünf Zuweisungen | Ungleich null | Fünf Subtest-Fehler: `MINIMUM_SUPPORTED` unterscheidet sich von TLS 1.2; belegt die fehlende explizite Eigenschaft, keinen aushandelbaren alten Exploit | RUN_ROOT |
| Framework-Interpreter, `-m unittest discover -s tests/security_regression -p test_tls_protocol_floor.py -v`, mit explizitem Framework-Quellkontext und externer Temporärwurzel | 0 | Sieben Methoden bestanden, keine Skips; sämtliche 32 Szenarien oben bestanden | RUN_ROOT |
| Drei explizite bestehende Selektoren: Envoy mit geprüftem Loopback und wurzelgebundener Evidenz, HAProxy HTX mit geprüftem Loopback-Zertifikat, tatsächlicher harmloser TLS-Clientprozess des Companions | 0 | Drei bestanden nach Korrektur des quellenabhängig erwarteten argv | RUN_ROOT |
| Versuch mit lokalem pytest | Ungleich null | `No module named pytest`; keine Abhängigkeit installiert | RUN_ROOT |
| Exakter neuer Workflow-Python-Block, aus der eingecheckten YAML extrahiert und mit Framework-Interpreter ausgeführt | 0 | Zehn Methoden bestanden, keine Skips: sieben neue und drei tatsächliche Kontrollen | RUN_ROOT |
| Native `update-inventory-bindings.py --apply` / `--check`, `update-test-archive.py` / `--check`, `build-migration-map.py` / `--check` | 0 | Sämtliche Generierungs-/Aktualitätsprüfungen bestanden; obige Zahlen und Selektoren erhalten | RUN_ROOT |
| `py_compile` für sechs Quellen, `actionlint .github/workflows/ci-findings-regressions.yml`, beide nativen CI-Sicherheitsvertragsskripte | 0 | Syntax, Workflow-Lint und Scanner-/Evidenzverträge bestanden | RUN_ROOT |
| Neues unabhängiges Kandidatenreview auf Bypass/Regression, nur lesend | Abgeschlossen | Kein konkreter verbleibender Bypass oder neu eingeführter Verhaltensfehler gefunden | Aktueller Task |
| `rtk make check-documentation check-canonical-common-pins check-canonical-python-pins check-canonical-workflow-pins check-canonical-crs-contract-pins` mit explizitem Framework-Interpreter/Build-Root | 0 | Dokumentation, Record-Paar, Pfade/Links und alle vier kanonischen Pinprüfungen bestanden | RUN_ROOT |
| Hosted-CodeQL/CI/Sonar | Vor Commit ausstehend | Ergebnisse des exakten Kandidaten müssen beobachtet werden; frühere Revisionen werden nicht eingesetzt | Aktueller Task |

## Sicherheitsauswirkung

Die fünf ursprünglichen Kontextpfade verbieten nun explizit Protokollversionen unter TLS 1.2. Die tatsächlichen Fabriken werden gegen beide alten Versionen geprüft; permissive Kontrollen belegen, dass der Fehler nicht nur fehlende Plattformunterstützung ist. Erfolgreiches TLS 1.2/1.3 und die unveränderte Obergrenze decken moderne Kompatibilität ab. Falsche Hostnamen und Zertifikate einer anderen Autorität werden weiterhin von beiden Clients abgewiesen. Kein produktives Sicherheitsniveau, keine Authentifizierungsanforderung und keine Scannerkontrolle wird reduziert.

## Dokumentation und Runtime-Evidenz

Dieses EN/DE-Paar bildet die lesergerichtete Dokumentationsänderung. Evidenz umfasst begrenzte echte TLS-Aushandlung im Speicher, tatsächliche geprüfte Loopback-Anfragen und einen echten Kindprozess; dies sind Framework-Komponentenprüfungen. Sie belegen keine historische I12-Qualifikation, Connector-Promotion oder vollständige Connector-Kampagne. Parent-Gitlink unverändert; MRTS bleibt im Task nur lesend. Kein Meldungs-Dismissal und keine Master-Integration werden vorgenommen.

## Nicht ausgeführte Prüfungen

Die vollständige historische I12-Kampagne liegt außerhalb dieser angefragten Änderung an fünf Kontexten. Das vollständige ältere pytest-Modul wird wegen lokal fehlendem pytest nicht als bestanden bezeichnet; quellenspezifische unittest-, Protokoll-/Kopie- und tatsächliche Loopback-/Kindprozesskontrollen liefern ausgewählte lokale Evidenz. Hosted-CI/CodeQL/Sonar des exakten Heads sind vor Commit ausstehend; Endergebnisse gehören in PR und externe Lifecycle-Evidenz.

## Einschränkungen und Restrisiko

Lokales Python ist 3.14.4; der CI-Pin ist 3.14.8. Lokale Prüfungen ersetzen keine Hosted-Prüfungen des exakten Heads. Ein CodeQL-kompatibles Quellmuster beweist allein kein Verschwinden: Unverändertes Kandidaten-SARIF muss mit identischen Regeln und gleichem Umfang verglichen werden. Branch-Evidenz und Meldungszustand auf Master bleiben getrennt; automatisches `Fixed` erfordert gesondert autorisierten Merge und erfolgreichen Master-Scan. Kein ausnutzbarer alter Handshake und keine vollständige Laufzeitqualifikation werden behauptet.

## Finaler Diff- und Review-Status

Quell-, Test-, Workflow- und generierte Änderungen sind auf diese Korrektur begrenzt. Unabhängiges Review fand keinen konkreten Bypass/Verhaltensfehler; Whitespace-, Dokumentations- und kanonische Pinprüfungen bestanden. Commit und Hosted-Lifecycle verbleiben zum abschließenden Abgleich. Dieser Record enthält keine Secrets, privaten Zertifikatschlüssel, Zugangsdaten, rohen Anfrage-/Antwortinhalte oder vollständigen Logs.
