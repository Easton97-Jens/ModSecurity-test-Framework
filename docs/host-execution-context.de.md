# Host-Ausführungskontext

**Sprache:** Deutsch | [English](host-execution-context.md)

Reale Connector-Tests benötigen den Ausführungskontext des gewählten Profils. UID 0 allein belegt keine Host-Root-Rechte: UID/GID-Abbildungen, effektive Capabilities, Zusatzgruppen, Pfaddurchquerung und Socket-Zugriff sind ebenfalls relevant. In jeder neuen Sitzung und vor dem ausgewählten Harness ist ein frischer Preflight nötig; ein früheres PASS autorisiert oder belegt keinen späteren Runtime-Lauf.

## Kontexte und Berechtigung

Die beobachtete Codex-Sandbox bildet nur Identität 0 ab, besitzt keine effektiven Capabilities und hat `NoNewPrivs=1`. Der separat genehmigte Host-Befehlskontext hat vollständige Identitätsabbildungen, effektive Capabilities und `NoNewPrivs=0`. Dies sind Beobachtungen verschiedener Prozesskontexte, keine dauerhaften Garantien der Host-Konfiguration. Der Preflight erfasst die aktuellen UID/GID-Abbildungen, den User-Namespace, ausgewählte Capability-/Sicherheitsfelder und begrenzte Container-Marker erneut.

`require_escalated` beantragt über das Ausführungswerkzeug die ausdrückliche Genehmigung eines einzelnen Befehls. Es ist keine Option dieser Framework-CLI. Weder Helper noch Harness umgehen automatisch Sandbox-Beschränkungen, ändern Codex-Richtlinien, installieren Pakete oder verändern dauerhafte Host-Dienstkonfigurationen. Fehlt der benötigte Kontext, bleibt das Ergebnis `BLOCKED`; zulässige Alternativen sind ein genehmigter Host-Befehl, ein separat vorbereiteter Runner oder ein tatsächlich anderes Profil, dessen Vertrag zum verfügbaren Kontext passt. Das Root-Master-Profil darf nicht stillschweigend als rootless umbenannt werden.

Geschützte Exact-Head-Broker-Profile haben eigene Namespace-Identitäten und Vertrauensanforderungen. Ihr Launcher, die Broker-Identität, Provenienz und Exact-Head-Kontrollen bleiben maßgeblich; dieser allgemeine Preflight ersetzt oder verändert sie nicht. Die gewöhnliche NGINX-Worker-Identität darf nicht in ein geschütztes Broker-Profil übernommen werden.

## Explizite Profilanforderungen

| Anforderung | CLI-Vertrag |
| --- | --- |
| Profilbezeichnung | `--profile` immer angeben; die Bezeichnung wählt oder erschließt Anforderungen nicht automatisch. |
| Gewöhnlicher nativer NGINX-Root-Master | `--require-root-master --require-chown` sowie `--worker-user` und `--worker-group` des Profils explizit angeben. Nur Profile mit gesondertem Worker sollen einen solchen anfordern. |
| Worker-Dateien und -Verzeichnisse | `--worker-read`, `--worker-write` und `--worker-deny` für die vorbereiteten Profilpfade wiederholen. Operationen laufen in einem zeitlich begrenzten Kindprozess nach verifiziertem Wechsel von UID/GID/Zusatzgruppen. |
| Envoy-Observer-UDS | `--uds-path` für einen neuen Namen in einem privaten Verzeichnis der Socket-Identität unter dem genehmigten Runtime-Root angeben; für kürzere externe Socket-Pfade ist ein separat verifizierter privater `--uds-root` möglich. Die Probe bindet, verbindet und überträgt ein Byte. |
| Andere Profile | Nur deren tatsächliche Anforderungen angeben; NGINX-Root, chown oder Worker-Wechsel sind keine universellen Anforderungen. |

Leseproben öffnen eine Datei oder listen ein Verzeichnis; Schreibproben erzeugen und entfernen eine eindeutige temporäre Datei. Eine Deny-Probe verifiziert verweigertes Lesen einer Datei oder verweigertes Betreten eines Verzeichnisses: Eine gesperrte Verzeichnisauflistung allein genügt nicht; ein fehlender Pfad oder Symlink belegt keine Isolation. Pfade müssen absolut sein und dürfen keine Symlink-Komponenten enthalten. Der UDS-Pfad muss in das Linux-Socket-Limit passen; ein vorhandener Socket bleibt erhalten und blockiert die Probe. Probendateien und -Sockets werden entfernt und der zeitlich begrenzte Kindprozess wird abgeholt.

## Nativer Aufruf und Evidenz

Framework-eigenen Interpreter und Quellimportpfade verwenden. Im Framework-Checkout prüft dieses Beispiel nur den Kontext der aktuellen Identität, ohne Connector-Binary:

```sh
rtk bypass env PYTHONDONTWRITEBYTECODE=1 PYTHONSAFEPATH=1 \
  PYTHONPATH="$PWD:$PWD/connector_suite" "$PYTHON" -P \
  -m modsecurity_connector_ci.runtime.common.hostruntime_preflight \
  --execution-context-only --profile current-identity \
  --runtime-root /var/tmp/codex/ModSecurity-conector/host-context \
  --output-dir /var/tmp/codex/ModSecurity-conector/host-context/preflight
```

Vor dem Beispiel `PYTHON` auf den genehmigten Framework-Interpreter setzen. Einen frischen aufgabeneigenen Root und ein Ausgabe-Unterverzeichnis außerhalb von Quell-Checkouts, `/tmp` und Home-Speicher verwenden. Für diese vom Parent koordinierte Aufgabe ist `/var/tmp/codex/ModSecurity-conector` der genehmigte externe Root. Fixture-Eigentümer und -Rechte vor den Worker-Pfadflags gemäß autorisiertem Profil vorbereiten. Ein minimales PASS der aktuellen Identität erfüllt das anspruchsvollere NGINX-Profil nicht.

Die CLI erzeugt `status.json` und `summary.md`. Das bestehende Schema bleibt `schema_version=1`, `evidence_kind=preflight`, `runtime_status=NOT_RUN`, auch bei `status=PASS`. Kontextmetadaten und Reason-Codes der Einzelprüfungen beschreiben ausschließlich Voraussetzungen. Der Kontextmodus überspringt Binary-/Versions-/Abhängigkeitsprüfungen; für Runtime-Evidenz den gewählten Harness mit seinen regulären Binary-/Konfigurationsprüfungen separat ausführen. Aktuelle Einstiegspunkte integrieren die Kontextprüfung in NGINX-Smoke-/Lifecycle- und Envoy-Start-/Runtime-Pfade.

| Ergebnis | Bedeutung und nächster Schritt |
| --- | --- |
| Exit 0 / `PASS` | Deklarierte Proben bestanden in diesem Prozesskontext; mit der ausgewählten Runtime-Validierung fortfahren. |
| Exit 77 / `BLOCKED` | Umgebungs- oder deklarierter Voraussetzungsmangel; fehlgeschlagene Prüfung untersuchen und in geeignetem genehmigtem Kontext erneut ausführen. |
| Nicht abgebildeter Worker / fehlende Wechsel-Capabilities | Die Root-Bezeichnung reicht nicht; Worker-UID und alle benötigten Gruppen müssen abgebildet sein, und Wechsel-Capabilities müssen vorliegen. |
| Chown-, Worker-Zugriffs- oder UDS-Blocker | Autorisierte Runtime-Vorbereitung korrigieren oder kompatiblen Kontext wählen; Anforderungen an private Verzeichnisse und Deny-Pfade beibehalten. |
| Runtime-Fehler nach Preflight | Host-/Konfigurations-/Connector-Evidenz separat untersuchen; ein Preflight-PASS ist kein Runtime-PASS. |

Diese Proben begründen weder Connector-Promotion noch zwischengespeicherte Runtime-Aussagen. Dokumentationsprüfungen und Unit-Tests belegen nur ihre jeweilige Ebene; frische Connector-Runtime-Ergebnisse müssen tatsächliches Profil, Prozesskontext und externes Evidenzverzeichnis benennen.
