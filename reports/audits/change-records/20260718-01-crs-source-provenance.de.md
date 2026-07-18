# Change Record: CRS-Quellherkunfts-Pin

**Sprache:** [English](20260718-01-crs-source-provenance.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260718-01-crs-source-provenance` |
| UTC-Datum | `2026-07-18` |
| Framework-Basisrevision | `cdc91a398d6c156eaff927d742b23018a3817fb6` |
| Issue oder Pull Request | `FND-FRAMEWORK-0004`; Framework-Draft-PR nach autorisierter Auslieferung ausstehend |

## Motivation und Problemstellung

`FND-FRAMEWORK-0004` bestätigte, dass ein mutabler `CRS_GIT_REF` die von der
Framework-CRS-Provisionierung verwendete Quelle auswählen konnte. Ein detached
Checkout von `FETCH_HEAD` band das konsumierte Objekt nicht an einen geprüften,
unveränderlichen Commit.

## Betroffene Komponenten und Sicherheitsgrenzen

- `ci/lib/common.sh` besitzt die geprüfte CRS-Quellidentität und den
  Durchsetzungshelfer.
- `ci/provisioning/fetch-crs.sh` ist die Git-/Provisionierungs-Konsumgrenze.
- `ci/tools/check-common-versions.py` darf kein Release-Label ohne den
  zugehörigen geprüften Commit automatisch aktualisieren.
- `ci/checks/catalog/check-crs-version-pinning.sh`, das Make-Target und die
  fokussierte Regression sichern den lokalen Vertrag ab.

Die Grenze ist Framework-eigene Supply-Chain-Herkunft. Parent-Produktsource
und Gitlink bleiben unverändert; MRTS-Quelle wurde weder initialisiert noch
verändert.

## Akzeptanzkriterien

1. Die Provisionierung akzeptiert vor einer Git-Nutzung nur die zentral
   geprüfte CRS-URL, das Release-Label und den vollständigen unveränderlichen
   Commit.
2. Neue und vorhandene Checkout-Pfade rufen diesen Commit ab, checken ihn aus
   und verifizieren ihn vor der Submodul-Verarbeitung.
3. Mutable Tags, Branches, Ref-Namespaces, abgekürzte Hashes, nicht zugehörige
   vollständige Hashes und Quellen-Overrides werden vor einer Git-Nutzung
   abgelehnt.
4. Ein geprüfter Commit-Kontrollfall funktioniert weiter über dieselbe Grenze.

## Untersuchte Alternativen

- Ein mutables Tag mit detached `FETCH_HEAD` wurde verworfen, weil sich das
  ausgewählte Objekt ändern kann.
- Das Release-Label vollständig durch einen Commit zu ersetzen, hätte den
  Release-orientierten Updater-Vertrag beschädigt. Der gewählte Ansatz behält
  ein geprüftes Label als Metadatum und verwendet den vollständigen Commit als
  konsumierte Identität.
- Das automatische Auflösen und Umschreiben eines neuen Release-Tags samt
  Commit wurde zurückgestellt: Ein Quellen-Update benötigt explizite
  Herkunftsprüfung, daher meldet der Updater es zur manuellen Paarprüfung.

## Implementierungsentscheidung

Die versionierte CRS-Identität enthält die erwartete Repository-URL, das
Release-Tag und den vollständigen kleingeschriebenen Commit
`55b09f5acfd16413e7b31041100711ceb7adc89c`. Effektive Aufruferwerte müssen
diesen geprüften Werten entsprechen. Der Fetcher erstellt oder verwendet ein
Repository, ruft nur den vollständigen Commit ab, checkt nur diesen aus,
vergleicht `HEAD^{commit}` und verarbeitet rekursive Submodule erst nach dem
Vergleich. Das Release-Tag wird keinem Git-Quellenauswahlbefehl übergeben.

## Geänderte Dateien und Tests

- `ci/lib/common.sh`
- `ci/provisioning/fetch-crs.sh`
- `ci/tools/check-common-versions.py`
- `ci/checks/catalog/check-crs-version-pinning.sh`
- `Makefile`
- `tests/security_regression/test_crs_provenance.py`
- `docs/reference/variables.md` und `docs/reference/variables.de.md`
- `docs/testing-and-evidence.md` und `docs/testing-and-evidence.de.md`

Die Regression führt das echte Fetch-Skript mit Fake-Git aus. Sie deckt die
ursprüngliche Klasse, Branch-/Ref-/Kurz-Hash- und nicht zugehörige
Voll-Hash-Bypässe, URL-Override, neue und vorhandene Checkouts, abweichendes
`HEAD`, den geprüften Commit-Kontrollfall und das Updater-Verhalten ab.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk make … test-crs-provenance-contract` | `0` | 4 fokussierte Herkunftstests bestanden | `20260718T082843Z-framework-fnd-0004-79ef062d` |
| `rtk env … make … test-makefile-contract test-no-crs-contract test-protocol-client` | `0` | 3 Makefile-Vertrags-, 81 No-CRS- und 16 Protocol-Client-Unit-/Vertragstests bestanden | Task-Run-`build`- und `tmp`-Wurzeln |
| `rtk env … sh ci/provisioning/fetch-crs.sh` (neu) | `0` | Geprüften Commit abgerufen und verifiziert | task-eigenes `tmp/fnd-0004-real-control` |
| `rtk env … sh ci/provisioning/fetch-crs.sh` (vorhanden) | `0` | Geprüften Commit erneut abgerufen und verifiziert | task-eigenes `tmp/fnd-0004-real-control` |
| `rtk env … CRS_GIT_REF=main sh ci/provisioning/fetch-crs.sh` | kontrollierter Block | Vor Fake-Git abgelehnt; Regression prüft Exit `77` | task-eigenes `tmp/fnd-0004-reproducer` |
| `rtk make … lint` mit task-eigenem `PYTHONPYCACHEPREFIX` | `0` | Statische, Unit-, Vertrags-, Doku- und Whitespace-Checks bestanden | Task-Run `build/pycache` |
| `rtk make … quick-check` mit task-eigenem `PYTHONPYCACHEPREFIX` | `0` | Breiterer Framework-Quick-Check bestanden | Task-Run `build/pycache` |
| `rtk shellcheck -S error -x …` | `0` | Keine ShellCheck-Fehler in geänderten Shell-Dateien | Framework-Worktree |

## Sicherheitsauswirkung

Der ursprüngliche Pfad ist erneut als blockiert validiert: Ein mutabler
Release-Ref-Override wird vor einer Git-Invocation abgelehnt. Die alternative
Bypass-Prüfung ist in der Regression ausführbar: Tag-/Ref-Namespace, Branch,
abgekürzter/nicht zugehöriger vollständiger Hash, URL-Override,
Vorhandener-Checkout-Refresh und Post-Checkout-Mismatch schlagen sicher fehl.
Der geprüfte Kontrollfall funktioniert für einen neuen und einen vorhandenen
Checkout; Git beobachtete in beiden Fällen den genehmigten Commit.

## Dokumentation und Runtime-Evidenz

Englische und deutsche Variablen- sowie Testdokumentation erklären jetzt das
geprüfte Tag-und-Commit-Paar und den gemockten Provisionierungsvertrag. Es
wurde keine Connector-Runtime- oder MRTS-Evidenz erhoben; der reale
Kontrollfall übte nur die CRS-Fetch-Grenze in einem registrierten privaten
Task-Verzeichnis aus.

## Nicht ausgeführte Prüfungen

- Vollständiger Connector-Smoke und `test-with-crs` wurden nicht ausgeführt,
  weil die Regression dieses Findings die Provisionierungsgrenze betrifft und
  diese Befehle weitergehende Connector-/Runtime-Voraussetzungen benötigen.
- Framework-CI, SonarQube Cloud, PR-Review und Review-Thread-Prüfungen sind
  bis Framework-Commit, Push und Erstellung des Draft-PR ausstehend.
- `ruff`, `pyright` und `gitleaks` sind in der autorisierten Umgebung nicht
  verfügbar; es wurde keine Tool-Installation vorgenommen. Der manuelle
  Secret-/Diff-Review der geänderten Bereiche fand nur die geprüfte öffentliche
  Commit-Identität, vorhandene Prüfsummen-Metadaten und dokumentierte nicht
  ausführbare Secret-Platzhalter.

## Einschränkungen und Restrisiko

Die Prüfung zeichnet eine Commit-Identität auf, keine Kette signierter
Release-Attestierungen. Rekursive Submodule werden durch Gitlinks des gepinnten
Root-Commits ausgewählt, aber hier nicht separat attestiert. Ein künftiges
CRS-Update benötigt ein geprüftes Tag-und-Commit-Paar; dies ist absichtlich
kein automatischer Updater-Pfad.

## Finaler Diff- und Review-Status

Lokaler Source-, Test-, Doku-, Whitespace- und Secret-/Diff-Review ist auf dem
isolierten Framework-Branch abgeschlossen. Ein Framework-Draft-PR steht nach
dem autorisierten Commit und Non-Force-Push aus. Es gab keinen Parent-Commit,
kein Parent-Gitlink-Update, keine MRTS-Quelländerung, keinen Merge und keinen
Force-Push.
