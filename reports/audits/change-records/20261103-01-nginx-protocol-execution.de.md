# Native NGINX-Protokollexecutoren und Quellkontextfixtures

[English](20261103-01-nginx-protocol-execution.md)

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261103-01-nginx-protocol-execution |
| UTC-Datum | 2026-11-03 |
| Framework-Basisrevision | bb6c7580208a05c17d6d6674571731b6a71028cb |
| Issue oder Pull Request | Taskbranch codex/runtime-protocols-20261103; Lieferung separat koordiniert |

## Motivation und Problemstellung

Den bestehenden H2/H3-Katalogfällen fehlten ausführbare native
NGINX-Deskriptoren. Zwei Wiringregressionen scheiterten zuvor an einem ungültigen
Produktfixture ohne Git. Gerenderte TLS-/QUIC-Listener und eine optionale nicht
promovierende Probe konnten Allow/Block und Fallbackfreiheit nicht qualifizieren.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-Auswahl, native Protokolldisposition, Quellsammlung, kanonische
Übernahme und unabhängige Nachweisprüfung. Der gewöhnliche Hosted-Lauf verwendet
frischen Preflight und bestehendes Cleanup eigener Prozesse. Geschützter Broker
und Connector-Produktfähigkeiten bleiben eigene Grenzen.

## Akzeptanzkriterien

Bestehende unterstützte moderne Fälle wählen echte Executoren. Falsche
HTTP-Version, fehlendes/falsches unabhängig beobachtetes Server-ALPN,
widersprüchliches Client-ALPN, fehlende Streamidentität, unbeobachtetes
QUIC, fremde native Transaktion oder fehlgeschlagenes Cleanup verhindern PASS.
Native Originalevents bleiben unverändert. Der 100-Fälle-Standardumfang wächst
nicht.

## Untersuchte Alternativen

Buildflags zu promovieren, eine fremde optionale Probe zu verwenden,
Clientfakten in native Events einzufügen oder fehlende Resets/Multiplexing als
erfolgreich zu melden würde den Runtimevertrag nicht belegen.

## Implementierungsentscheidung

Geschlossene Executoren senden eigenständige Allow- und Vertragsrequests über
echte TLS-/H2- oder QUIC-/H3-Listener. Ein gemeinsamer Reader prüft originale
gehashte Bytes, exakte Quellidentitäten, native Access-/Rulekorrelation,
erzwungene Clientaushandlung und bidirektionale QUIC-Metadaten. Kanonische
Records benennen unabhängige Hostfakten ausdrücklich und öffnen ihre Nachweise
zur Validierung erneut. H1-Operationen bleiben bei modernen Aufrufen
unausgeführt; ihr Nennwert bleibt bestehen. Produktresets, Multiplexing, h2c
und moderne First-Byte-Verträge bleiben nicht unterstützt beziehungsweise
unimplementiert.

Das tatsächlich ausgeführte H3-OpenSSL-Backend von curl meldete akzeptiertes
ALPN nicht im Trace, während native Accessrecords unabhängig HTTP/3.0 und
ALPN h3 belegten. Der Clientparser erhält daher fehlendes Client-ALPN als
fehlend. Der Abschlussnachweis verlangt weiterhin passendes
`$ssl_alpn_protocol` in beiden originalen Accessrecords; ausdrücklich
widersprüchliches Client-ALPN scheitert. Neue Herkunftsfelder benennen
`alpn_source=nginx_access_ssl_alpn_protocol`, `client_alpn_observed` sowie
den tatsächlichen Clientwert `client_alpn` oder null. Kein Serverwert wird
als Clientbeobachtung ausgegeben.

Der unabhängige Review reproduzierte die Annahme widersprüchlicher Nativeentscheidungen, nicht committeter Safe-Evidenz und fehlender Allow-Events. Der korrigierte Reader verlangt originale saubere Allow-Completion, tatsächliche Denyabsicht und Interventionsstatus, exakte committete Safe-Semantik und beobachtete Ergebnisse. Die Libraryprüfung erfolgt vor Backend-Allokation. Kein Erwartungsfeld liefert ein beobachtetes Ergebnis.

## Geänderte Dateien und Tests

Neu sind `tests/runners/nginx_protocol.py`, native Einzel-/Auswahlrunner,
gezielte On-demand-Regressionen und zweisprachige Protokolldokumentation.
Kanonische Sammlung/Auswahl/Übernahme, Ergebnis-Schema, Hostdisposition und
Wiringfixture sind angepasst. Das Quellfixture erstellt ein echtes Gitcheckout
mit aktuellen Produktversionsverträgen.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| RTK, ursprüngliche zwei Wiringmethoden, Framework-Python3.14.4 | 1 | Beide reproduzieren den ungültigen Quellkontext vor der Auswahl | runtime-readiness/protocols Baseline-Toolreceipt |
| RTK, Framework-Python3.15.2, Protokollregressionen | 0 | 15 Tests: Protokoll-/ALPN-/Streamfakten, Fallback, Interventionssemantik, sauberes Allow, Paketmetadaten, kanonische Nachprüfung/Retention/exaktes Paar, Aliasfälle, Cleanup und fehlende Operationen | runtime-readiness/protocols |
| RTK, H3-Backend ohne Client-ALPN, Regression vor Korrektur | 1 | Tatsächliche Backendform trotz unabhängigem Server-ALPN abgelehnt; gezielt rot | runtime-readiness/protocols/h3-initial |
| RTK, Framework-Python3.15.2, Protokollregressionen nach ALPN-Herkunftskorrektur | 0 | 17 Tests: fehlendes Client-ALPN nur mit beiden Serverrecords zulässig; fehlendes/falsches Server- oder Client-ALPN abgewiesen | runtime-readiness/protocols |
| RTK, Framework-Python3.15.2, vollständiges Protokollwiringmodul | 0 | Zehn echte Make-Auswahl-/Init-Tests; kein Hoststart | runtime-readiness/protocols |
| RTK, fünf benachbarte Auswahl-/Autoritätsmodule | 1 | 37/40 bestehen; drei separate alte Nicht-Git-Autoritätsfixtures scheitern | runtime-readiness/protocols |

## Sicherheitsauswirkung

Fehlende Herkunft wird abgelehnt. QUIC-Beobachtung speichert weder Nutzlast noch
rohe Verbindungskennungen. Temporäres TLS-Material wird mit eigenen Prozessen
bereinigt. Scanner, Preflight, native Capabilities und Repositoryschutz werden
nicht abgeschwächt.

## Dokumentation und Runtime-Evidenz

Der zweisprachige Leitfaden nennt Voraussetzungen, Operationen und Grenzen.
Selbsttests belegen nur Quellverträge und Fehlererkennung. Frischer Lauf mit
zugelassenen Artefakten und exaktes Quellpaar bleiben separate
Koordinatornachweise; dieser Record behauptet keine Gesamt-Abnahme.

## Nicht ausgeführte Prüfungen

Keine vollständige Profil-/Protokollkampagne oder geschützte Brokeroperation
durch diesen Änderungsumfang. Lokales Sonar ist auf aktuelle ausdrückliche
Nutzeranweisung ausgesetzt; GitHub-Sonar/CodeQL bleiben unverändert. Frische
Hostnachweise und Lieferung meldet der Integrationskoordinator separat.

## Einschränkungen und Restrisiko

H3 benötigt HTTP3-fähiges curl und genehmigte Paketbeobachtung. Neue
Reset-/Multiplex-Produktfähigkeiten erfordern eigene Implementierung. Bestehende
Autoritätsfixture-Kontextfehler bleiben separate Regressionen, kein Protokoll-PASS.

## Finaler Diff- und Review-Status

Prüfbare Änderungen ausschließlich im Framework-Worktree; keine
Parent-Quell-/Gitlink- oder MRTS-Schreibaktion. Der Integrationskoordinator
verantwortet abschließende Gesamtprüfung, Inventarquellbindungen, Commit/PR
und tatsächliche Laufbereitschaftsaussagen.
