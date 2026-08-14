# Traefik-Runtime-Pin-Divergenz beheben

**Sprache:** [English](20260814-01-remediate-traefik-runtime-pin-divergence.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260814-01-remediate-traefik-runtime-pin-divergence` |
| UTC-Datum | 2026-08-14 |
| Framework-Basisrevision | `1260aaae411ecf88cf50dc480b80e2e20ac47901` |
| Finding | `FND-FRAMEWORK-0069` (`fixed`) |
| Issue oder Pull Request | [Framework-PR #78](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/78) von `fix/fnd-framework-0069-traefik-runtime-pin` nach `master` ist die task-eigene Delivery-Einheit. Der initiale Implementierungs-Commit `741dd30287d9d5fd38946ee317da4d1f91494b19` wurde normal gepusht; jeder spätere PR-Head benötigt eine frische Exact-Head-Prüfung. Merge-Fakten werden nur bei beobachteter PR- und Task-Lifecycle-Evidenz festgehalten. |

## Motivation und Problemstellung

Die aufbewahrte `F-GS-001`-Analyse zeigte, dass die aktive Framework-Traefik-Auflösung das geprüfte `3.7.10`-Linux-amd64-Release-Archiv und SHA-256 verwendete, während das benachbarte runtime-components-Manifest ein altes `3.7.5`-Archiv und einen alten Digest beschrieb. Das Manifest war kein aktiver Runtime-Reader, aber eine ungeprüfte konkurrierende Quelle für Artefakt-Provenance. Der Framework-Resolver akzeptierte außerdem eine passende lokale/PATH-Binärdatei ohne Nachweis des kanonischen Archiv-Digests.

## Betroffene Komponenten und Sicherheitsgrenzen

Framework-eigene Änderungen betreffen das kanonische Tupel in `ci/lib/common.sh`, Archiv-Preparation, generische Smoke-Auflösung, den Traefik-Manifest-Slice und Synchronisierer, Catalog-Guard, Lint-Wiring und fokussierte Regressionstests. Die Grenze führt von Caller-Environment/Cache/Archiv/Manifest zu Archiv-Extraktion, Binär-Staging und Connector-Ausführung. Die benachbarte Parent-Resolver-Bridge ist eine Consumer-Integration: Sie delegiert an die Framework-Grenze und führt keine zweite Versions- oder Digest-Autorität ein.

## Akzeptanzkriterien

- Nur Framework-`common.sh` definiert Traefik-Version und Release-Archiv-SHA-256 manuell; alle anderen Tupelfelder werden abgeleitet.
- Manifest-Output ist deterministisch und schlägt bei Version-/Hash-/URL-/Archiv-/Plattform-/fehlender-/fehlerhafter-/doppelter-Source-Divergenz fehl.
- Eine lokale oder aufrufergelieferte Binärdatei kann Framework-/Parent-Direkt-Entry-Points nicht erreichen, sofern kanonische Archivprüfung nicht gelang.
- Korrektes synthetisches Archivverhalten bleibt ein legitimer Offline-Control, Fokustests bestehen und der Check ist CI-sichtbar.

## Untersuchte Alternativen

Ein manuell gepflegtes Manifest hätte eine zweite Quelle der Wahrheit gelassen; seine Entfernung hätte ein bestehendes Catalog-Artefakt verloren; ein doppelter Parent-Pin hätte Ownership geteilt. Der gewählte deterministische Traefik-Slice-Generator und die dünne Parent-Bridge bewahren Framework-Autorität und lassen andere Manifest-Komponenten unverändert.

## Implementierungsentscheidung

`ci_traefik_set_canonical_tuple` besitzt das geprüfte Tupel und leitet die offiziellen HTTPS-URLs, Archivnamen und `linux_amd64`-Plattform ab. Der Provenance-Guard weist geerbten/Live-alternativen oder unvollständigen Zustand vor einer Download-, Archiv-, Extraktions- oder Prozesssenke ab. Der Preparer prüft ein vorhandenes oder heruntergeladenes kanonisches Archiv vor Staging erneut. Der Manifest-Synchronisierer validiert eine Source-Assignment und schreibt/prüft nur Traefik deterministisch.

Der Catalog-Guard läuft in Framework-Lint; Parent-Lint und der bestehende PR-sichtbare Workflow rufen denselben Guard auf. Direkte Parent-Smoke-/Native-Caller verwenden nur den zurückgegebenen Framework-Cache-Pfad. Dokumentation führt Preparation nun über das Framework statt einen veralteten Pin zu kopieren.

Der Resolver erhält ein blockiertes (`77`) Preparation-Ergebnis, statt es zu einem generischen Fehler abzuflachen. Der Parent-Lifecycle inventarisiert die kanonische Cache-Binärdatei nur nach erfolgreichem Staging, sodass ein geerbtes `TRAEFIK_BIN` nicht zu einer Prozesssenke nach einem Fehler werden kann.

### SonarQube-Cloud-Follow-up

Die SonarQube-Cloud-Analyse für PR #78 mit dem Head
`18da86f34827f34a5a99877796e21532fd31f824` meldete zwei task-eigene
`python:S6353`-Maintainability-Findings für den Versionsausdruck im neuen
Manifest-Synchronisierer. Der knappe `\d`-Ausdruck verwendet nun `re.ASCII`:
Er beseitigt beide Findings, ohne die bisherige ASCII-only-Grenze für
Release-Versionen zu erweitern. Die fokussierte Regression beweist, dass die
kanonische ASCII-Version akzeptiert wird, während eine selbstkonsistente
Version mit Arabic-Indic-Unicode-Ziffern vor der Archivnamen- oder URL-Ableitung
abgewiesen wird.

## Geänderte Dateien und Tests

- Framework-Runtime und Catalog: `ci/lib/common.sh`, `ci/provisioning/prepare-traefik-runtime.sh`, `ci/lib/connector-smoke-common.sh`, `ci/provisioning/runtime-components.manifest.json`, `ci/tools/sync-traefik-runtime-manifest.py`, `ci/checks/catalog/check-open-runtime-provisioning-contract.sh`, `ci/tools/check-common-versions.py` und `Makefile`.
- Framework-Regression: `tests/security_regression/test_traefik_runtime_pin_contract.py`.
- Das SonarQube-Cloud-Follow-up ändert nur den Versionsausdruck des
  Synchronisierers, diese fokussierte Regression und das englisch/deutsche
  Change-Record-Paar.
- Parent-Consumer-Bridge, Direkt-Entry-Tests, Workflow-Wiring und bilinguale Anleitung sind koordinierte Änderungen, keine zusätzlichen Framework-Pin-Autoritäten.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | ---: | --- | --- |
| `PYTHON=/usr/bin/python3 make test-traefik-runtime-pin-contract` | 0 | Zehn fokussierte positive/negative Pin-Contract-Tests einschließlich Blocked-Status-Weitergabe sowie ASCII-Akzeptanz und Unicode-Ziffern-Ablehnung bestanden. | Isolierter Framework-Worktree mit task-eigenen externen Build-/Tmp-Roots, 2026-08-14 |
| `python3 ci/tools/sync-traefik-runtime-manifest.py --write` zweimal, danach `--check` | 0 | Beide Schreibvorgänge erzeugten `7ea22e43269c85566ad86564171bb74fcbbd86800a3d861cbaf93b473ec12e1b`; der Check bestand. | Isolierter Framework-Worktree, 2026-08-14 |
| `sh ci/checks/catalog/check-open-runtime-provisioning-contract.sh` | 0 | Kanonisches Tupel, Archivpfad/-Export und Manifest-Vertrag bestanden. | Isolierter Framework-Worktree, 2026-08-14 |
| `PYTHON=/usr/bin/python3 make lint` | 0 | Vollständiges Framework-Lint nach dem Source-/Test-Follow-up einschließlich Security-, Dokumentations-, Change-Record-, Traefik-Contract- und Whitespace-Verträgen bestand. | Isolierter Framework-Build-Root, 2026-08-14 |
| Parent-Compiler-Guide- und Runtime-Environment-Contract-Suiten | 0 | Beide fokussierten Suiten bestanden je 21 Tests; der Runtime-Snapshot-Test deckt die kanonische Cache-Zuweisung nach Staging ab. | Separater isolierter Parent-Worktree, 2026-08-14 |

## Sicherheitsauswirkung

Die ursprüngliche statische Abweichung ist über den generierten Manifest-Check nicht mehr reproduzierbar. Negative Controls weisen veraltete/fehlerhafte/partielle/alternative Tupel, falsche Plattform, Caller-`TRAEFIK_BIN` und eine gleichversionierte Bare-Binary vor Archiv-Extraktion oder Runtime-Setup ab. Ein synthetisches exaktes Archiv wird als legitimer Control gestagt. Dies ist Dependency-Provenance-Hardening; es behauptet keine Ausführung eines bösartigen Artefakts oder eine Kompromittierung einer externen Quelle.

Das SonarQube-Cloud-Follow-up erhält die ASCII-only-Versionsinvariante des
Manifest-Parsers. `re.ASCII` verhindert, dass Pythons standardmäßiges Unicode-
`\d`-Verhalten verwechslungsanfällige Release-Ziffern im Pfad der Archiv- und
URL-Ableitung akzeptiert.

## Dokumentation und Runtime-Evidenz

Englisch-/deutschsprachige Connector- und Compiler-Anleitung kopieren den veralteten Pin nicht mehr und beschreiben Framework-Preparation. Es gab keinen externen Archivdownload und keinen Live-Traefik-Smoke-/Native-Run. Hosted-Checks für Framework-PR #78 müssen gegen seinen exakten aktuellen Head gelesen werden und gelten nicht als Evidenz einer Live-Release-Akquisition.

## Nicht ausgeführte Prüfungen

- Offizieller gepinnter Archivdownload und Digest-Check: kein aufbewahrtes Archiv und keine separate Autorisierung für Netzwerkanfrage.
- Live-Smoke-/Native-Connector-Control: benötigt das echte Archiv und lokale Runtime-Voraussetzungen.
- Exact-Head-Hosted-Check-Revalidierung nach jedem PR-Update und Resulting-Master-Revalidierung: Dies sind getrennte Delivery-Prüfungen; ihre Ergebnisse werden nur bei beobachteter PR- und Task-Lifecycle-Evidenz festgehalten.
- Parent-Gitlink-Update: hier nicht autorisiert. Die Cross-Repository-Policy verlangt erst einen gemergten, verifizierten Framework-Master-SHA vor einer separaten Parent-Pointer-Änderung.

## Einschränkungen und Restrisiko

Der Guard schützt nicht gegen Code-Ausführung, die Framework-Source bereits ändern oder beliebige Shell innerhalb derselben Vertrauensgrenze aufrufen kann. Das reale Upstream-Artefakt bleibt ungeprüft; Resulting-Master-Evidenz wird nur bei Beobachtung in PR- und Task-Lifecycle-Evidenz festgehalten. MRTS wurde nicht berührt.

## Finaler Diff- und Review-Status

Task-eigene Framework- und Parent-Diffs erhielten begrenzte Whitespace-Checks ohne Fehler. `FND-FRAMEWORK-0069` bleibt `fixed`, nicht `verified` oder `closed`. Die Framework-Implementierung wurde über Framework-PR #78 committed und normal gepusht. Die aktuelle Nutzerformulierung `bringe ihn in den master` wählt nur diesen task-eigenen Framework-PR für die kontrollierte Framework-Master-Integration; dieser Record autorisiert kein Parent-Gitlink-Update, keine Produktions-Delivery und keine MRTS-Aktionen.

Das dokumentierte SonarQube-Cloud-Source-/Test-Follow-up ist Teil von
Framework-PR #78. Sein Exact-Head-Delivery-Status ist in PR- und Task-Evidenz
festgehalten, nicht in diesem Change Record; jeder spätere PR-Head benötigt
weiterhin eine frische Exact-Head-Verifikation.
