# Änderungsnachweis: NGINX-Refresh-Owner-Root-Containment wiederherstellen

**Sprache:** [English](20260726-02-fix-nginx-refresh-owner-root.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260726-02-fix-nginx-refresh-owner-root` |
| UTC-Datum | 2026-07-26 |
| Framework-Basisrevision | `c27c644e088904b71b8380d16ee34f1b36f2c001` |
| Issue oder Pull Request | Kanonisches Parent-Finding `FND-CROSS-0008`; Framework-Task-Branch `agent/fix-nginx-cache-owner-root`. Draft-PR ist beim Schreiben dieses Records ausstehend; kein Framework-Merge ist autorisiert. |

## Motivation und Problemstellung

Die Parent-Runtime-Matrix liefert einen verifizierten Cache-gestützten
NGINX-Build, während jeder Matrix-Job ein separates lokales `BUILD_ROOT`
behält. Der Framework-NGINX-Provisioner verwendete bisher nur diesen lokalen
Root als Lösch-Owner für `REFRESH`; dadurch scheiterte der korrekte Cache-Build
fehlgeschlossen, bevor die Runtime-Matrix legitime Evidence erzeugen konnte.
Dieser Record behandelt nur die Framework-Hälfte des Cross-Repository-
Owner-Root-Vertrags; er aktualisiert weder Parent-Gitlink noch Matrix-Aufruf.

## Betroffene Komponenten und Sicherheitsgrenzen

- `ci/provisioning/prepare-nginx-build.sh` erhält einen expliziten validierten
  `NGINX_BUILD_OWNER_ROOT` ausschließlich für seinen bestehenden NGINX-
  `REFRESH`-Löschguard. Er defaultet auf `BUILD_ROOT` und erhält damit das
  Verhalten für Nicht-Cache-Caller.
- `safe_remove_runtime_path` bleibt der Lösch-Sink. Seine Canonical-Path-,
  Safe-Runtime-Path-, Owner-Root-Containment- und Unsafe-Root-Checks bleiben
  unverändert.
- Die kontrollierten Eingaben sind vorbereiteter NGINX-Build-Pfad und
  ausgewählter Owner Root. Das vertrauenswürdige Parent-Follow-up muss den
  engen verwalteten Connector-Cache-Build-Root ableiten; Framework entdeckt,
  weitet oder ersetzt ihn nicht.
- Parent-Source, Parent-Gitlink, Framework-`master`, MRTS-Source und der
  Framework-zu-MRTS-Gitlink liegen außerhalb dieser Änderung.

## Akzeptanzkriterien

- Ein Cache-gestützter NGINX-Build unter einem expliziten sicheren Owner Root
  refresht erfolgreich, während `BUILD_ROOT` separat bleibt.
- Ein Cache-Build außerhalb des Owner Roots, auch über einen Symlink erreicht,
  bleibt vor Löschung oder Download abgewiesen.
- Ein relativer expliziter Owner Root wird vor Archiv-/Netzwerkarbeit
  abgewiesen.
- Der Default-Owner-Root bleibt das bestehende `BUILD_ROOT`-Verhalten.
- Framework-only-Source, Test und gepaarter Change Record werden über einen
  normalen Draft-PR geliefert; Codex führt keinen Merge durch.

## Untersuchte Alternativen

- Das Aufweiten jedes Matrix-Job-`BUILD_ROOT` auf den Component-Cache wurde
  verworfen, weil es Job-Isolation beseitigen und Löschautorität aufweiten
  würde.
- Das Deaktivieren von `REFRESH` oder Löschguard wurde verworfen, weil es den
  Producer-Fehler verbergen und eine fehlgeschlossene Containment-Kontrolle
  abschwächen würde.
- Ein impliziter Cache-Root wurde verworfen: Nur ein expliziter Caller-Wert
  wird verwendet und als absoluter sicherer generierter Pfad validiert.

## Implementierungsentscheidung

`NGINX_BUILD_OWNER_ROOT` defaultet auf `BUILD_ROOT`, wird neben den anderen
generierten NGINX-Pfaden validiert und nur aus `safe_remove_dir` an
`safe_remove_runtime_path` übergeben. Bestehende Cache-, Symlink- und
Forbidden-Root-Kontrollen bleiben im Shared Helper. Der Archiv-
Regression-Harness akzeptiert den task-gebundenen `TEST_TMPDIR`, damit seine
temporären Dateien außerhalb von Source- und MRTS-Checkouts bleiben.

## Geänderte Dateien und Tests

- `ci/provisioning/prepare-nginx-build.sh` — expliziter Owner-Root-Parameter,
  Validierung und Löschguard-Handoff.
- `tests/security_regression/test_nginx_archive_digest.py` —
  Cache-contained-Positivkontrolle; Outside-Owner- und Symlink-
  Negativkontrollen; Relative-Owner-Root-Ablehnung; Unterstützung für einen
  task-gebundenen Temporary Root.
- Dieser englische/deutsche Change-Record-Paar.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| Fokussierte positive Regression vor der Source-Änderung | 1 | Erwartetes Pre-Fix-Scheitern: Cache-gestützter NGINX-Build lag außerhalb des joblokalen `BUILD_ROOT`. | `20260726T110116Z-framework-nginx-owner-root` |
| `rtk sh -n ci/provisioning/prepare-nginx-build.sh` | 0 | Aktualisierter Shell-Entrypoint hat gültige POSIX-Shell-Syntax. | Lokaler Task-Worktree |
| Ausgewählte `test_nginx_archive_digest`-Owner-Root-Kontrollen | 0 | Cache-contained Refresh bestand; Outside-Owner-, Symlink- und Relative-Owner-Root-Kontrollen wurden sicher abgewiesen. | Lokaler Task-Worktree; task-eigener `TEST_TMPDIR` |
| Die verbleibenden zwölf bestehenden `test_nginx_archive_digest`-Methoden in begrenzten Selektionen | 0 | Alle bisherigen Digest-, Archiv-Replacement-, HTTPS-, Cache-Refresh- und Override-Fälle bestanden. | Lokaler Task-Worktree; task-eigener `TEST_TMPDIR` |

## Sicherheitsauswirkung

Dies ist eine Remediation einer Containment-Kontrolle, kein behaupteter
Runtime-Exploit. Der ursprüngliche Same-Boundary-Nachweis scheiterte
fehlgeschlossen, weil ein legitimer Cache-Build nicht unter dem joblokalen
Owner lag. Die Positivregression übt nun den vorgesehenen
expliziten Owner-Handoff aus. Outside-Owner- und Symlink-Targets scheitern
weiter vor der Löschung; ein relativer Owner Root wird bei der Pfadvalidierung
abgewiesen. Kein Guard, keine Cache-Einschränkung und kein terminales
Evidence-Gate wird gelockert.

## Dokumentation und Runtime-Evidenz

Dieser gepaarte Change Record ist die einzige leserorientierte Framework-
Dokumentationsänderung. Es wird keine Host-Runtime-Evidence, kein Parent-
Matrix-Run, kein Framework-Merge, kein Parent-Gitlink-Update, kein SonarQube-
Cloud-Ergebnis und keine MRTS-Evidence behauptet. Diese bleiben getrennte
Current-Head- oder Cross-Repository-Schritte.

## Nicht ausgeführte Prüfungen

- Hosted-Framework-Actions, SonarQube Cloud, Reviews, Conversations und
  Branch-Protection-Auswertung sind noch nicht ausgeführt, weil sie für den
  zukünftigen exakten Draft-PR-Head gelten.
- Die vollständige Parent-Runtime-Matrix läuft nicht in diesem Framework-only-
  Worktree; sie benötigt das spätere Parent-Gitlink-/Matrix-Follow-up nach
  nutzergeprüfter Framework-Integration.

## Einschränkungen und Restrisiko

Framework validiert, dass der übergebene Owner Root absolut und sicher ist,
kann aber nicht feststellen, welchen verwalteten Cache-Teilbaum Parent wählen
muss. Das spätere Parent-#74-Follow-up muss den engen Connector-Cache-Build-
Root ableiten und validieren sowie neue Exact-Head-Producer- und Terminal-
Gate-Evidence erhalten. Bis dahin bleibt `FND-CROSS-0008` ein Release-Blocker.
Dieser Record autorisiert keinen Framework-Merge und keine MRTS-Aktion.

## Finaler Diff- und Review-Status

Der abgegrenzte Diff enthält nur NGINX-Provisioner, fokussierte Regression-
Suite und diesen gepaarten Record. Ursprüngliches positives Scheitern,
Same-Boundary-legitime Kontrolle und alternative Outside-Owner-/Symlink-
Kontrollen wurden geprüft. Lokale Whitespace-, Dokumentations- und Git-
Boundary-Checks bestanden; die Exact-Head-Checks des Draft-PR bleiben
ausstehend. Keine Secrets oder rohen Runtime-Payloads sind enthalten.
