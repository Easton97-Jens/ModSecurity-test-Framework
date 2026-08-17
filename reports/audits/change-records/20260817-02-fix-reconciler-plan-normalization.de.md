# Change Record: 20260817-02-fix-reconciler-plan-normalization

**Sprache:** [English](20260817-02-fix-reconciler-plan-normalization.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260817-02-fix-reconciler-plan-normalization` |
| UTC-Datum | `2026-08-17` |
| Framework-Basisrevision | `d195b32e301fee31a72309c8c2b8bb5fe6f9f081` |
| Issue oder Pull Request | Der Resulting-Master-Workflow `32010750544` zeigte den Defekt; dieses Protokoll belegt keinen korrigierenden Pull Request oder Merge. |

## Motivation und Problemstellung

Die konfigurierte Review-Issue-App erreichte den vertrauenswürdigen Reconciliation-Pfad. Ein Producer-gültiger Plan, dessen aktives Review das optionale `state` ausließ, bestand die Rohvalidierung, scheiterte aber anschließend geschlossen, weil die CLI die normalisierte Darstellung erneut einer Rohplan-Digest-Validierung übergab. Die erste Normalisierung ergänzt `state: "active"`; dieses Feld ist nicht Teil des signierten Producer-Plans.

## Betroffene Komponenten und Sicherheitsgrenzen

Betroffen ist die Framework-Grenze des kanonischen Maintenance-Plan-Artefakts zwischen begrenztem Datei-Reader, Schema-/Digest-Validator und Review-Issue-Reconciliation-Kern. Die Korrektur erhält die Rohplan-SHA-256-Validierung vor Issue-Operationen sowie Trusted-Default-Branch- und App-Token-Gates; Parent-Quellcode, Parent-Gitlink, Connector-Runtime und der schreibgeschützte Checkout `tools/MRTS` bleiben außerhalb des Umfangs.

## Akzeptanzkriterien

1. Ein roher signierter Plan ohne optionales `state` eines aktiven Reviews kann den CLI-Dry-Run-Reconciliation-Pfad erfolgreich durchlaufen.
2. Die öffentliche API `reconcile()` validiert weiterhin rohe Aufruferdaten, bevor normalisierte Records verwendet werden.
3. Manipulierte Digests, unsichere Schemata, Trusted-Branch-Bedingungen und Token-Grenzen werden weiterhin abgewiesen.
4. Die englische und deutsche Sicherheitsdokumentation beschreiben dieselbe Rohplan- und Normalisierungsgrenze.

## Untersuchte Alternativen

- Das Zurückgeben von rohem JSON aus dem Reader und eine zweite Validierung würde den Digest erhalten, führt aber doppelte Validierung aus.
- Eine Neuberechnung von `plan_sha256` nach der Normalisierung wurde verworfen, weil dadurch die Producer-signierte Darstellung ersetzt würde.
- Das Entfernen der Digest-Validierung oder das Akzeptieren eines ungebundenen neu aufgelösten Plans wurde verworfen, weil beides die Maintenance-Supply-Chain-Grenze abschwächt.

## Implementierungsentscheidung

Der Reader validiert den begrenzten Rohplan vor der Annahme weiterhin und gibt seine validierte normalisierte Darstellung zurück. Ein privater Reconciliation-Kern verwendet diese Darstellung direkt. Die öffentliche API `reconcile()` validiert Rohdaten direkter Aufrufer vor dem Eintritt in denselben Kern, damit normalisierte Default-Werte niemals als zweites signiertes Artefakt behandelt werden.

## Geänderte Dateien und Tests

Der vorgesehene Framework-Umfang umfasst das Reconciliation-Werkzeug, einen fokussierten CI-Sicherheitsregressionstest, die gepaarte Sicherheitsdokumentation und dieses gepaarte Änderungsprotokoll. Der Test deckt CLI-Dry-Run-Reconciliation mit ausgelassenem aktivem Review-`state` ab; die bestehenden negativen Kontrollen für Digest-Manipulation und unsichere Schemata bleiben erhalten.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `rtk proxy gh run view 32010750544 --job 95329847123 --log` | `0` | Fehler der vertrauenswürdigen Reconciliation nach erfolgreichem App-Token-Mint beobachtet; sichere Fehlermeldung: `plan_sha256 does not match canonical plan`. | GitHub-Actions-Run `32010750544` |
| Fokussierte Reconciler-, Validate-only-, Lifecycle-, Resolver-, Canonical-Maintenance- und Workflow-Unittest-Suite | `0` | 48 Tests bestanden, einschließlich der neuen CLI-Dry-Run-Regression. | Framework-Task-Worktree |
| Scoped-Ruff-Prüfung für Reconciler-Quellcode und Test | `0` | Keine Lint-Befunde. | Framework-Task-Worktree |
| `rtk proxy ./ci/tools/safe-make.sh check-documentation` | `0` | Dokumentationslinks, Variablen-/Pfadreferenzen und der Change-Record-Vertrag bestanden. | Framework-Task-Worktree |
| `rtk proxy env RUFF_CACHE_DIR=<task-owned-external-cache> ./ci/tools/safe-make.sh lint` | `0` | Vollständiges Framework-Lint bestanden, einschließlich Sicherheits-, Runtime-, Dokumentations- und abschließender `git diff --check`-Validierung. | Framework-Task-Worktree |

## Sicherheitsauswirkung

Die Korrektur erhält die Rohartefakt-Validierung und verhindert, dass ein normalisierter Default mit Producer-signierter Eingabe verwechselt wird. Sie fügt keine Netzwerk-, Credential-, Berechtigungs-, Artefaktpfad- oder automatische Schreibberechtigung hinzu. Bestehende Kontrollen für manipulierte Digests, unsichere Eingaben, Trusted Branch, App-Token, Scope und Issue-Mutationen bleiben wirksam.

## Dokumentation und Runtime-Evidenz

Die gepaarten englischen/deutschen Sicherheitsleitfäden dokumentieren den Rohplan- und Normalisierungsvertrag. Workflow `32010750544` ist beobachtete Fehler-Evidenz; dieses Protokoll beansprucht keine erfolgreiche Hosted-Runtime, keinen Pull Request, kein SonarQube-Cloud-Ergebnis und keinen Merge.

## Nicht ausgeführte Prüfungen

- Hosted Checks, SonarQube-Cloud-Analyse und Delivery-Checks sind noch nicht als bestanden festgehalten.
- Ein Resulting-Master-Workflow nach dieser Korrektur kann erst existieren, wenn ein korrigierender Pull Request die vom Nutzer geforderten Gates besteht und regulär gemergt wird.

## Einschränkungen und Restrisiko

Die Korrektur bleibt lokal, bis der exakte PR-Head Hosted Checks besteht und SonarQube Cloud die vom Nutzer geforderten null neuen Issues und null New-Code-Duplizierung meldet. Es wird kein GitHub-App-Secret- oder Token-Wert festgehalten.

## Finaler Diff- und Review-Status

Die Quell-/Teständerung und die gepaarte Dokumentation haben fokussierte und vollständige lokale Reviews bestanden. Dieses Protokoll behauptet keinen Commit, Pull Request, Hosted-Check-Erfolg, SonarQube-Cloud-Ergebnis oder Merge.
