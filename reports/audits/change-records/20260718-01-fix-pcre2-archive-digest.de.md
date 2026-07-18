# Change Record: 20260718-01-fix-pcre2-archive-digest

**Sprache:** [English](20260718-01-fix-pcre2-archive-digest.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260718-01-fix-pcre2-archive-digest` |
| UTC-Datum | 2026-07-18 |
| Framework-Basisrevision | `cdc91a398d6c156eaff927d742b23018a3817fb6` |
| Issue oder Pull Request | `FND-FRAMEWORK-0005`; Draft PR nach lokaler Verifikation ausstehend |

## Motivation und Problemstellung

`build_pcre2_from_source` akzeptierte einen leeren Literal-Digest und eine
leere Digest-URL und extrahierte anschließend das heruntergeladene PCRE2-
Archiv. Das verletzte die erforderliche Fail-Closed-Archivintegritätsgrenze in
`ci/provisioning/prepare-apache-build.sh`.

## Betroffene Komponenten und Sicherheitsgrenzen

Die betroffenen Framework-Pfade sind `ci/lib/common.sh`,
`ci/provisioning/prepare-apache-build.sh`, isolierte PCRE2-Fixture-Tests und
diese gepaarte Dokumentation. Die Sicherheitsgrenze ist das PCRE2-Archiv
zwischen der konfigurierten Source-URL und seiner ersten `tar`-Extraktion: Kein
Archiv darf diese Senke oder eine spätere Verarbeitung erreichen, bevor ein
nicht leerer, syntaktisch gültiger und exakt passender SHA-256-Digest
erfolgreich geprüft wurde.

## Akzeptanzkriterien

1. Der Standard-PCRE2-Digest ist gepinnt, während ein explizit leerer Override
   für eine Fail-Closed-Zurückweisung erhalten bleibt.
2. Leere, nur aus Whitespace bestehende, fehlerhafte und nicht passende PCRE2-
   Digests führen vor einem PCRE2-`tar`-Aufruf zu einem blockierten Ergebnis.
3. Ein passendes lokales Archiv-Fixture erreicht die reale Extraktionsgrenze
   erst nach Digest-Prüfung.
4. Die neue Kontrolle verwendet `PCRE2_SHA256_URL` nicht als optionalen
   Bypass.
5. Englische und deutsche Referenzdokumentation sowie dieses Change Record
   beschreiben dieselbe Kontrolle und Testgrenze.

## Untersuchte Alternativen

- Die weitere Akzeptanz von `PCRE2_SHA256_URL` als optionalem sekundären
  Verifier wurde verworfen, weil eine leere URL der ursprüngliche Bypass ist
  und das Upstream-Release-Asset keine stabile per-Asset-Prüfsummen-URL hat.
- Die Änderung der generischen HTTPD-/APR-Helfer wurde verworfen, weil das
  Finding und die erforderliche Abhilfe auf den PCRE2-Pfad beschränkt sind.
- Ein realer Download oder vollständiger Apache-Build wurde als unnötig
  verworfen: Das isolierte Full-Script-Fixture erreicht die reale Digest-zu-
  `tar`-Grenze.

## Implementierungsentscheidung

`PCRE2_SHA256` besitzt einen geprüften Literal-Pin mit einer
Parameterexpansion, die nur bei nicht gesetzter Variable standardmäßig greift.
`verify_required_pcre2_sha256` weist leere oder nicht 64-hex Werte zurück,
normalisiert gültige Hexadezimalnotation, berechnet den Archiv-SHA-256 und
blockiert bei Nichtübereinstimmung. Der PCRE2-Build ruft die Funktion
unmittelbar vor `extract_tar_strip` auf; der frühere optionale URL-Check und
der erfolgreiche Pfad „nur lokaler Hash protokolliert“ sind entfernt.
`PCRE2_SHA256_URL` bleibt nur für die Kompatibilität der Common-Version-
Metadaten erhalten, nie als Extraktionsprüfeingabe.

## Geänderte Dateien und Tests

Versionierte Framework-Änderungen:

- `ci/lib/common.sh`.
- `ci/provisioning/prepare-apache-build.sh`.
- `tests/fixtures/pcre2-digest/cases.json` und das lokale `configure`-
  Source-Fixture.
- `tests/security_regression/test_pcre2_archive_digest.py`.
- `docs/reference/variables.md` und `docs/reference/variables.de.md`.
- Dieses gepaarte Change Record.

Der Full-Script-Test verwendet nur ein generiertes lokales `.tar.bz2`-Archiv
und lokale Fake-Tools für `curl`, `tar`, Compiler und `make`. Er deckt leere,
Whitespace-, fehlerhafte und falsche Digests ohne PCRE2-`tar`-Marker sowie
einen passenden Digest mit genau einem Marker und erfolgreichem Fixture-Pfad
ab.

## Befehle und Ergebnisse

Alle schreibfähigen Befehle verwenden einen registrierten, aufgabenspezifischen
externen temporären Run; es werden kein realer Download und kein vollständiger
Apache-Build ausgeführt.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | ---: | --- | --- |
| Fokussierter PCRE2-Archiv-Digest-Unittest | 0 | Vier negative Digest-Fälle erreichten den PCRE2-`tar`-Spy nicht; die passende Kontrolle erreichte ihn | `20260718T092308Z-fnd-framework-0005-pcre2-digest-e064e1d8` |
| `make check-documentation` | 0 | Links, zweisprachige Variablenabdeckung und Repository-Pfadreferenzen bestanden | Derselbe Task-Run |
| `make lint` | 0 | Shell-Syntax, Python-Kompilierung, statische Framework-Checks, Security-Data-Flow-Checks, Katalog-, Dokumentations- und Diff-Checks bestanden | Derselbe Task-Run |
| `sh -n` und `bash -n` auf den geänderten Shell-Dateien | 0 | Syntax bestanden | Derselbe Task-Run |
| ShellCheck auf den geänderten Shell-Dateien | 1 | Die unveränderte Baseline hat 17 Diagnosen außerhalb der geänderten PCRE2-Kontrolle; keine neue Diagnose liegt in der modifizierten Logik | Verglichen mit sauberer Basis `cdc91a3` |
| `git diff --check` | 0 | Keine Whitespace-Fehler | Framework-Worktree |

## Sicherheitsauswirkung

Der ursprüngliche optionale Digest-Pfad ist durch ein erforderliches Literal-
Digest-Gate vor dem einzigen PCRE2-Extraktionsaufruf ersetzt. Die fokussierte
Regression testet die Bypass-Klassen leer, nur Whitespace, fehlerhaft und
nicht passend sowie die passende legitime Kontrolle durch das reale
Vorbereitungsskript erneut. In diesem Build-Pfad bleibt kein alternativer
PCRE2-URL-Fallback.

## Dokumentation und Runtime-Evidenz

Die gepaarten Referenzseiten dokumentieren die exakte Digest-Anforderung und
die Tatsache, dass `PCRE2_SHA256_URL` kein Fallback ist. Dieses gepaarte
Change Record dokumentiert die Sicherheitsgrenze und die Test-Evidenz.

Es wurde keine Connector-Runtime-, Netzwerkdownload- oder vollständige
Apache-Build-Evidenz erfasst. Das lokale Fixture beweist nur die Digest-
Extraktions-Enforcement-Grenze; es ist kein Produktions-Connector- oder
Lifecycle-Ergebnis.

## Nicht ausgeführte Prüfungen

- Die vollständige Runtime-`make test`-Matrix wird nicht ausgeführt. Sie kann
  Connector-Runtime-Abhängigkeiten fetchen oder bauen und ist für diese eng
  begrenzte Pre-Extraction-Kontrolle unnötig: Das isolierte Full-Script-
  Fixture beweist die reale Enforcement-Grenze ohne Download oder vollständigen
  Apache-Build.
- Current-Head-Draft-PR-CI-, Review- und SonarQube-Cloud-Gates stehen aus, bis
  der Framework-Commit gepusht ist und der Draft PR existiert.

## Einschränkungen und Restrisiko

Das isolierte Fixture validiert keinen Upstream-Downloadservice und keinen
vollständigen Apache-Build. Es beweist die erforderliche PCRE2-Archivgrenze mit
dem realen Produktionsskript und Extraktionsaufruf. Ein Archivtausch nach der
Verifikation wäre ein separates Filesystem-TOCTOU-Thema, nicht der hier
behandelte optionale Digest-Bypass.

## Finaler Diff- und Review-Status

Der lokale Framework-Diff wurde auf den benannten Scope, generierte Artefakte
und sensible Inhalte geprüft. `git diff --check` bestand. Kein Merge, keine
Parent-Änderung, kein Parent-Gitlink-Update und keine MRTS-Änderung sind
autorisiert. Commit, Draft PR und Current-Head-Checks werden erst nach ihrem
Auftreten dokumentiert.
