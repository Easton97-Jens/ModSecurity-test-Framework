# Änderungsnachweis: MRTS-Updater-Abstammung

**Sprache:** [English](20261115-01-mrts-updater-lineage.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261115-01-mrts-updater-lineage |
| UTC-Datum | 2026-11-15 |
| Framework-Basisrevision | `e4762167bed1ec6a28f7a207c8fb5b9ec258656a` |
| Issue oder Pull Request | Updater-Reparatur; der zugehörige PR dokumentiert den Lieferstatus. |

## Motivation und Problemstellung

Framework #174 änderte `tools/MRTS` von `9a855b092645733ea8ff73a512aff7bfe916407e` auf dessen Vorfahren `ee2174431c4edf97e66afe32558ce8454deb2397`. Der Updater prüfte SHA-Format und offiziellen Branch, verlangte aber keine vorwärts gerichtete Abstammung. Parent-Lauf `43690159562`, Validator-Job `132739018750`, wies diesen verschachtelten Rückwärtswechsel vor der Kandidatenvalidierung korrekt zurück.

Der Benutzer wählte ausdrücklich nur die Updater-Reparatur und behielt den bestehenden Pin bei. Diese Änderung verhindert künftige Rückwärtsveröffentlichungen; sie löst den bestehenden Parent-Kandidatenkonflikt nicht.

## Betroffene Komponenten und Sicherheitsgrenzen

Auflösung, schreibgeschützte Validierung und privilegierte Veröffentlichung des Framework-MRTS-Updaters sowie der bestehende versiegelte Workflow-Sicherheitsvertrag. Git-Objekte des Kandidaten sind Daten; der Prüfercode stammt aus der vertrauenswürdigen Framework-Standardrevision. Parent-Quellen/-Pins und MRTS-Quellen/-Checkout/-Branches liegen außerhalb dieser Änderung.

## Akzeptanzkriterien

Gleiche oder nachfolgende Commit-Objekte akzeptieren. Rückwärts-/abweichende Historien, fehlerhafte SHAs, fehlende Objekte, Nicht-Commit-Objekte, Git-Fehler und gefälschte Abstammung über Replacement-Objekte zurückweisen. Die Prüfung vor Resolver-Ausgaben, Kandidaten-Checkout und Indexänderung/Veröffentlichung erzwingen. Validator-Eingaben an beide Resolver-Identitäten binden. Bestehende Veröffentlichungsgrenzen und aktuellen MRTS-Pin erhalten.

## Untersuchte Alternativen

Eine abgeschwächte Parent-Abstammungsprüfung würde einen echten Rückwärtswechsel verbergen. Die Wiederherstellung des MRTS-Pins wurde vorgeschlagen und ausdrücklich abgelehnt. Der Publisher-Helfer aus einem bestehenden Wartungsbranch wäre veraltet oder würde dort vor seiner Einführung fehlen; er wird stattdessen aus der vertrauenswürdigen Standardrevision bezogen.

## Implementierungsentscheidung

Ein Bash-Helfer ohne zusätzliche Abhängigkeiten prüft lokale Git-Objekte bei deaktivierten Replacement-Objekten und deaktiviertem Lazy Fetch. Der Workflow lädt beide exakten Revisionen aus dem offiziellen MRTS-Repository und ruft den Helfer an jeder Grenze auf. Die Validierung weist außerdem einen geänderten aktuellen Framework-Gitlink zurück. Die Veröffentlichung prüft die Abstammung gegen den geladenen Standardbranch-Pin und lädt den Helfer mittels `git show origin/$DEFAULT_BRANCH:ci/tools/verify-mrts-update-lineage.sh`.

Der kanonische Publisher-SHA-256 wird an das unabhängig geprüfte Profil gebunden: `9eb62da1c72de0a2a409a9225bf27bbd6b5682823f5a1b55f21b99a9d2ec54a7`. Der exakte Profilvergleich bleibt verpflichtend; zusätzlich werden erforderliche Prüferaufrufe und Resolver-Bindungen geprüft.

## Geänderte Dateien und Tests

- `.github/workflows/update-submodules.yml`
- `ci/tools/verify-mrts-update-lineage.sh`
- `ci/checks/security/check-ci-security-contract.py`
- `tests/ci_security/test_mrts_update_lineage.py`
- `tests/ci_security/test_ci_security_contract.py`
- Dieses englisch/deutsche Change-Record-Paar.

Die fokussierte Auswahl umfasst 16 unittest-Methoden mit 37 aufgelösten Git-/Vertragsszenarien. Bestehende Abweisungen für fremde PR-Repositories, falsche offizielle Refs, Zugangsdaten, Force-Push und Publisher-Erweiterungen bleiben erhalten. Dies ist eine begrenzte Auswahl, keine technische Durchsetzung der umfassenderen Standardinventar-Grenze.

## Befehle und Ergebnisse

| Befehl oder Verfahren | Exit / Ergebnis |
| --- | --- |
| Framework-eigenes Python: neues Lineage-Testmodul und sechs ausgewählte Updater-Vertragsmethoden | 0; 16 Methoden bestanden, einschließlich drei Prüferentfernungen und drei Identitätsbindungsmutationen. |
| Neue Regression für entfernte Prüfer gegen den bisherigen Sicherheitsprüfer | Erwarteter Exit 1; an allen drei Grenzen fehlte die erforderliche prüferspezifische Abweisung. |
| `rtk bypass bash -n ci/tools/verify-mrts-update-lineage.sh` | 0. |
| `rtk bypass shellcheck ci/tools/verify-mrts-update-lineage.sh` | 0. |
| `rtk bypass actionlint .github/workflows/update-submodules.yml` | 0. |
| Framework-eigenes Python: `ci/checks/security/check-ci-security-contract.py` | 0; vollständiger aktueller Workflow-Sicherheitsvertrag bestanden. |
| Helfer gegen vorhandene tatsächliche MRTS-Objekte: `9a855b0 -> ee21744`; umgekehrt; gleich | Erwartete Exits 1, 0, 0; Git-Objekte ausschließlich lesend geprüft. |
| Explizite SSH-Secrets-Prüfungen | Abgeschlossene ausgewählte Quell-/Ergebnisscans mit Exit 0; daraus folgt keine vollständige Codequalitätsanalyse. |

Die exakten ausgewählten Befehle und privaten Abschlusslogs bleiben im externen Task-Laufverzeichnis erhalten. Die ausgewählten Vertragsmethoden sind `test_submodule_updater_requires_lineage_checks_at_all_boundaries`, `test_submodule_updater_requires_both_resolved_identity_bindings`, `test_submodule_updater_uses_the_reviewed_framework_profile`, `test_submodule_updater_rejects_fork_head_pr_identity_bypasses`, `test_submodule_updater_rejects_mrts_ref_token_and_force_push_bypasses` und `test_submodule_updater_rejects_extra_publisher_code_and_token_steps`.

Der erste gehostete Qualitätsjob `132748009785` an `defc43a5376431b9a056a52c236811be1ff376df` bestand Ruff-Lint und wies die Formatierung zweier Testdateien zurück. Die exakt gemeldeten Formatänderungen wurden übernommen; beide Python-ASTs bleiben identisch. Es wurde kein zusätzliches Werkzeug installiert. Gehostete Ergebnisse des aktuellen Heads stehen im PR.

## Sicherheitsauswirkung

Die Reparatur verhindert, dass ein offizieller, aber älterer MRTS-Branchstand automatisiert als Rückstufung veröffentlicht wird. Tatsächliche Gleich-/Vorwärtskontrollen bestehen; das gemeldete Rückwärts-Objektpaar wird abgewiesen. Eine Replace-Ref-Fälschung wird mit echten Git-Objekten geprüft. Bestehende Rechte, Draft-/Erstanbieter-PR-Regeln, exaktes Publisher-Profil und Veröffentlichung ohne Force-Push bleiben wirksam. Der unabhängige statische Review fand keinen wesentlichen Fehler an Abstammungs- oder Publisher-Vertrauensgrenzen.

## Dokumentation und Runtime-Evidenz

Beide Change-Record-Sprachen beschreiben denselben Umfang und dieselben Grenzen. Es gibt keine neue Connector- oder Host-Runtime-Evidenz. Die Helfertests verwenden echte isolierte Bare-Git-Fixtures; die tatsächlichen Objektkontrollen verändern MRTS nicht.

## Nicht ausgeführte Prüfungen

Change-Record-Vertrag, zweisprachige Dokumentation und lokale Dokumentationslinks wurden erfolgreich geprüft. Zu diesem lokalen Prüfzeitpunkt waren gehostete Analyse/Auslieferung noch nicht qualifiziert. Es wurden weder Updater-Veröffentlichung, MRTS-Änderung, Parent-Kandidaten-Quick-Check, Connector-Kampagne noch Gesamtabnahme gestartet. Ruff/Pyright fehlen lokal; es wurden keine Pakete installiert.

## Einschränkungen und Restrisiko

Der bestehende Pin `ee2174431c4edf97e66afe32558ce8454deb2397` bleibt auf ausdrückliche Benutzerentscheidung unverändert. Parent weist den Rückwärtswechsel des aktuellen Framework-Kandidaten weiterhin korrekt zurück. Diese Reparatur belegt keinen nun erfolgreichen Parent-Lauf. Das Lazy-Fetch-Verhalten partieller Klone ist abgesichert, wurde aber mit den lokalen vollständigen Objekt-Fixtures nicht ausgeführt. Gleichzeitige Remote-Änderungen nach beobachteten Refs bleiben eine normale Veröffentlichungs-Race-Grenze.

## Finaler Diff- und Review-Status

Der unabhängige Review des eingefrorenen Helfers/Workflows und der Prüfer-/Teständerungen war CLEAR und reproduzierte den kanonischen Publisher-Hash. Die begrenzten Quellen, ausgewählten Tests und Dokumentationsprüfungen sind abgeschlossen. Task-Branch-Auslieferung und gehostete Ergebnisse des aktuellen Heads werden separat im zugehörigen PR dokumentiert. Eine Merge-Freigabe wird daraus nicht abgeleitet.
