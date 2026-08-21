# HAProxy-Validierungsreihenfolge im privaten Worktree korrigieren

**Sprache:** [English](20260821-01-fix-haproxy-private-worktree-order.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260821-01-fix-haproxy-private-worktree-order |
| UTC-Datum | 2026-08-21 |
| Framework-Basisrevision | 554df7a75281ac80ea18035f29248b7c7386ffbb |
| Issue oder Pull Request | Parent-PR #309 zeigte den Fehler; Framework-Draft-PR ausstehend |

## Motivation und Problemstellung

Eine frische HAProxy-Bereitstellung scheiterte vor dem Hoststart, weil das
Framework `HAPROXY_RUNTIME_BUILD_WORKTREE/Makefile` validierte, bevor es das
bereits SHA-256-verifizierte Archiv in diesen privaten Worktree extrahierte.
Der Fehler war ein wahrheitsgemäßer Fail-Closed-Verfügbarkeitsfehler, machte
den gültigen verifizierten Buildpfad aber unerreichbar.

## Betroffene Komponenten und Sicherheitsgrenzen

- `ci/provisioning/prepare-haproxy-runtime.sh`
- `tests/security_regression/test_runtime_component_download.py`

Die Grenze ist der Übergang von der überprüften, erneut gehashten Archivkopie
im privaten `BUILD_ROOT` zum einzigen Source-Tree, der inspiziert und gebaut
werden darf. Der gemeinsame Source-Cache bleibt ausschließlich Diagnose-/Cache-
Eingabe und wird nie Build-Eingabe.

## Akzeptanzkriterien

- Die private Archivextraktion erfolgt vor der Makefile-Validierung.
- Validierung und Kompilierung behalten den privaten Worktree als einzige
  Source.
- Fehlende oder ungültige Makefiles und unsichere Pfade schlagen weiterhin
  fail-closed fehl.
- Eine frische reale Bereitstellung erzeugt die gestagte Binärdatei und
  passende Provenance.

## Untersuchte Alternativen

- Parent-seitiges Voranlegen oder Umgehen des Framework-Verifiers wurde
  verworfen: Es würde die Framework-eigene Provenance-Grenze schwächen.
- Die Validierung des gemeinsamen extrahierten Caches wurde verworfen, weil ein
  Cache-Writer ihn nach der Archivvalidierung verändern könnte.

## Implementierungsentscheidung

Nur die zwei vorhandenen Aufrufe wurden umgeordnet:

```text
download_and_verify → extract_source → prepare_build_worktree
→ verify_build_target → build_haproxy
```

Kein Lock, keine Version, URL, Digest, Cache-Reuse-Regel, Pfad-Containment-
Prüfung oder Fehlerstatus wurde geändert. Der vorhandene Reuse einer
verifizierten Binärdatei bleibt vor dieser Sequenz und unverändert.

## Geänderte Dateien und Tests

- `ci/provisioning/prepare-haproxy-runtime.sh`: erzeugt die private Extraktion
  vor der Inspektion ihres Makefiles.
- `tests/security_regression/test_runtime_component_download.py`: ein
  Regression-Contract fixiert die vollständige Lifecycle-Reihenfolge.
- Dieses englische/deutsche Change-Record-Paar.

Der neue Regressionstest schlug gegen die ursprüngliche Reihenfolge fehl und
besteht nach der Änderung. Der bestehende Private-Archive/Shared-Cache-Contract
besteht ebenfalls.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| `python3 -m unittest -v …test_haproxy_validates_the_makefile_after_private_archive_extraction` vor dem Fix | 1 | Bestätigte, dass `verify_build_target` vor der privaten Worktree-Vorbereitung lag. | Framework-Task-Worktree, erhaltenes Kommandoergebnis |
| `sh -n ci/provisioning/prepare-haproxy-runtime.sh` | 0 | Shellsyntax gültig. | Framework-Task-Worktree |
| Fokussierte Reihenfolge- plus Private-Archive-Tests | 0 | Reihenfolge- und Shared-Cache-Grenz-Controls bestehen. | Framework-Task-Worktree |
| `make -s test-runtime-component-download` | 0 | 20 Security-Regression-Tests bestehen. | Framework-Task-Worktree |
| Begrenztes frisches `prepare-haproxy-runtime.sh` mit task-eigenen externen Roots | 0 | Downloadte, rehashte, extrahierte privat, baute und stagte HAProxy 3.2.22. | Task-eigener externer Runtime-Root |
| Wiederholte begrenzte Bereitstellung | 0 | Nutzte die provenance-verifizierte gestagte Binärdatei wieder. | Task-eigener externer Runtime-Root |
| `make -s test-ci-security-contract` | 0 | 282 CI-/Security-Contract-Tests bestehen. | Framework-Task-Worktree |
| `make -s test-makefile-contract` | 0 | 3 Makefile-Contract-Tests bestehen. | Framework-Task-Worktree |
| `shellcheck ci/provisioning/prepare-haproxy-runtime.sh` | 1 | Bestehende Diagnosen an unveränderten Zeilen; keine neue reihenfolgespezifische Diagnose. | Framework-Task-Worktree |

## Sicherheitsauswirkung

Der ursprüngliche Fehlerpfad wurde mit dem Pre-Fix-Regressionstest erneut
geprüft. Nach der Änderung erreicht der reale Preparer die private Extraktion,
validiert ihr Makefile, baut, stagt und nutzt eine provenance-verifizierte
Binärdatei wieder. Der alternative Shared-Cache-Pfad bleibt durch den
vorhandenen Private-Archive-Regressionstest als Build-Eingabe ausgeschlossen.
Dies ist eine Verfügbarkeitsreparatur der Bereitstellung; sie akzeptiert keine
unverifizierte Source und lockert keine Sicherheitsprüfung.

## Dokumentation und Runtime-Evidenz

Dieses gepaarte Change Record ist die einzige leserorientierte
Dokumentationsänderung. Die begrenzte Bereitstellung ist ausschließlich
Framework-Provisioning-/Lifecycle-Evidenz; sie behauptet keinen Parent-
Connector-Hostrequest oder eine Matrix-Promotion.

## Nicht ausgeführte Prüfungen

- `make -s smoke-haproxy` und `make -s runtime-matrix-haproxy` wurden nicht
  ausgeführt: Sie benötigen Parent-Connector/-Runtime und ein separat
  autorisiertes Parent-Gitlink-Update, um diese Framework-Änderung zu nutzen.
- Hosted-Framework-PR-, SonarQube-Cloud- und Review-Prüfungen sind bis zur
  Auslieferung ausstehend.

## Einschränkungen und Restrisiko

Der Parent bleibt auf seinem bestehenden Framework-Gitlink gepinnt. Das
separate Parent-Pointer-Update und der Rerun von Parent-PR #309 sind nicht
Bestandteil dieser Framework-only-Änderung. Es wird kein Sicherheitsrisiko
akzeptiert.

## Finaler Diff- und Review-Status

Vor dem Commit bestanden der task-eigene Framework-Diff, die Whitespace-Prüfung
und ein fokussierter Security-Review. Keine Secrets, Raw-Logs, Credentials oder
Request-Payloads werden hier dokumentiert. Der Framework-Branch existiert; sein
Draft-PR ist ausstehend.
