# Wiederherstellung der exakten ModSecurity-v3-Provenance-Prüfung für rekursive Topologie

**Sprache:** [English](20260723-02-remediate-modsecurity-v3-topology-provenance.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | `20260723-02-remediate-modsecurity-v3-topology-provenance` |
| UTC-Datum | 2026-07-23 |
| Framework-Basisrevision | `f98a8739cb13b583f23d646784b144e596b61441` |
| Issue oder Pull Request | Parent-eigener Remediation-Handoff; beim Erstellen des Records existiert kein Framework-PR |

## Motivation und Problemstellung

`ci_require_approved_modsecurity_v3_checkout` wies ein `.gitmodules`-Manifest
und jeden Gitlink kategorisch ab. Damit wies der Guard auch den bekannten,
geprüften ModSecurity-v3-Checkout bei
`0fb4aff98b4980cf6426697d5605c424e3d5bb60` ab, obwohl seine exakte rekursive
Topologie als aufbewahrte Task-Evidenz vorliegt. Die erforderliche Behebung
erlaubt nicht beliebige Submodule, sondern akzeptiert ausschließlich diese
konkrete Topologie und weist jede andere Checkout-Form fail-closed ab.

## Betroffene Komponenten und Sicherheitsgrenzen

- `ci/lib/common.sh` — ModSecurity-v3-Quellprovenance- und Git-Ausführungs-
  grenze, bevor ein Source-Build einen vorhandenen Checkout konsumiert.
- `ci/provisioning/fetch-smoke-sources.sh` — delegiert frische V3-
  Provisionierung an die schmale Framework-API statt einen generischen Clone-
  Pfad auszuführen.
- `tests/security_regression/` — hermetische Topologie-Controls plus
  Real-Git-Regressionsfälle für Write-Containment und lokale Konfiguration.
- Englische/deutsche Dokumentation — ausschließlich Quellgrenzenvertrag;
  daraus wird kein Connector-Runtime-Verhalten abgeleitet.

Die Änderung betrifft Supply-Chain- und Source-Integrity-Härtung. Sie ändert
weder den Parent-Checkout noch das originale MRTS.

## Akzeptanzkriterien

1. Der bekannte Root-Origin, der abgetrennte Commit und die exakte rekursive
   Topologie mit acht Kindern aus `(Pfad, Origin, Commit)` bestehen ohne
   Abschwächung eines Input-Controls.
2. Fehlende, zusätzliche, Origin- oder Commit-abweichende, verlinkte,
   ausbrechende, schmutzige, nicht normale Index-, attached-HEAD- oder
   Multi-Remote-Mitglieder schlagen vor dem Build-Konsum fehl.
3. Frische Provisionierung verwendet nur ein geprüftes root-eigenes sowie
   nicht gruppen- oder welt-schreibbares `/usr/bin/git`; sie löscht Caller-
   Git- und Dynamic-Loader-Zustand, setzt `PATH` zurück und sperrt Hooks,
   fsmonitor, automatisches rekursives Fetchen, lokalen File-Transport und
   interaktive Credential-Prompts.
4. Die fokussierte Regression besteht mit dem bereitgestellten isolierten
   CPython-3.14-Interpreter einschließlich Real-Git-Containment-/
   Konfigurations-Controls sowie legitimer und alternativer Umgehungs-Controls.
5. Dokumentation und der gepaarte Change Record beschreiben die statische
   Regel statt der überholten kategorischen Submodule-Ablehnung.

## Untersuchte Alternativen

- **Kategorische `.gitmodules`-/Gitlink-Ablehnung beibehalten:** verworfen,
  weil sie den bekannten legitimen geprüften Source blockiert und den
  Provenance-Vertrag nicht erfüllen kann.
- **Die eigenen `.gitmodules`-Daten des Checkouts parsen und vertrauen:**
  verworfen, weil dadurch untrusted Source-Metadaten ihre akzeptierte Topologie
  selbst wählen könnten.
- **Nur den Root prüfen:** verworfen, weil ein verschachteltes Kind Origin,
  Ref, Worktree, Gitdir oder Index-Zustand ändern kann, ohne die
  Root-Identität zu verändern.

## Implementierungsentscheidung

Das Framework deklariert Root-Gitlinks und die zwei verschachtelten
Gitlink-Sets als literale statische Daten in `ci/lib/common.sh`. Der Guard
prüft Root und jedes einzelne Kind gegen diese Daten, einschließlich
physischer Worktree-/Gitdir-Containment, eines literalen Origins, eines
abgetrennten exakten Commits, Object-Verifikation und sauberem normalen
Index-Zustand.

Frische Provisionierung ist in
`ci_provision_approved_modsecurity_v3_checkout` zentralisiert. Sie akzeptiert
nur ein nicht vorhandenes Ziel direkt unter einem bestehenden kanonischen,
nicht verlinkten Parent, erzeugt diesen Root privat mit Modus `0700` und
delegiert nie an einen generischen Clone. Die Grenze prüft vor der Verwendung
ein festes `/usr/bin/git`, löscht Caller-Git- und Dynamic-Loader-Variablen,
setzt `PATH` zurück und bindet jede Operation nach `init` an explizite
Worktree-Einstellungen im kanonischen physischen Root, während der normale
Worktree-Kontext für Gits Submodule-Helfer erhalten bleibt. Sie exportiert
weder `GIT_DIR` noch `GIT_WORK_TREE`, unterdrückt externe Attributes- und
Sparse-Zustände und löscht lokale Werte für `core.worktree`,
`core.attributesfile`, `core.sparseCheckout` und jedes
`submodule.*.update`-Key unmittelbar vor rekursiver Verarbeitung. Der Fetch-
Consumer ruft diese API auf und behält keine separate V3-Git-Sequenz.

## Geänderte Dateien und Tests

- `ci/lib/common.sh` — statische Topologie, fail-closed-Checkout-Prüfung und
  die gehärtete Fresh-Root-/Public-Provisioning-Grenze.
- `ci/provisioning/fetch-smoke-sources.sh` — V3-Fetch-Delegation an die
  öffentliche gehärtete Provisioning-API.
- `tests/security_regression/git_provenance_test_support.py` und
  `test_modsecurity_v3_git_ref_provenance.py` — exakte Fake-Topologie, eine
  testlokale Host-Git-Funktionsüberschreibung, Real-Git-Write-/
  Konfigurations-Fixtures, legitime Kontrollen und Umgehungsfälle.
- `docs/connector-integration*`, `docs/reference/variables*` und
  `docs/testing-and-evidence*` — synchronisierte englische/deutsche
  Vertragsaktualisierung.
- Dieser gepaarte Change Record und seine Index-Einträge — Change-Traceability.

## Befehle und Ergebnisse

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | ---: | --- | --- |
| `/bin/sh -n ci/lib/common.sh ci/provisioning/fetch-smoke-sources.sh` | 0 | Shell-Syntax akzeptiert | `20260723T162517Z-fnd-cross-0001-runtime-evidence-bcda7d1d` |
| `make test-modsecurity-v3-provenance-contract` mit isoliertem CPython 3.14.4 und task-eigenem `BUILD_ROOT`/`TMP_ROOT` | 0 | 18 Provenance-Tests in 201,531 Sekunden bestanden, einschließlich der Ausführung des realen rekursiven Git-Submodule-Helfers | `20260723T162517Z-fnd-cross-0001-runtime-evidence-bcda7d1d` |
| `make test-nginx-archive-digest` mit isoliertem CPython 3.14.4 und task-eigenem `BUILD_ROOT`/`TMP_ROOT` | 0 | 12 unabhängige Archiv-Integritäts-Tests in 217,161 Sekunden bestanden | `20260723T162517Z-fnd-cross-0001-runtime-evidence-bcda7d1d` |
| Parent-eigene nicht-gemockte Parent-zu-Framework-Provisioning-API-Validierung mit CPython 3.14.4 | 0 | Safe Bridge provisionierte Root `0fb4aff98b4980cf6426697d5605c424e3d5bb60`; `status=present`, `git_fsck=PASS`, acht freigegebene Submodule und sauberer Status | aufbewahrte JSON-Evidenz im Parent-Task-Run |
| `make check-documentation` mit isoliertem CPython 3.14.4 und task-eigenem `BUILD_ROOT`/`TMP_ROOT` | 0 | Links, Variablendokumentation, Repository-Pfadreferenzen und Change-Record-Vertrag bestanden | `20260723T162517Z-fnd-cross-0001-runtime-evidence-bcda7d1d` |
| `make lint` mit isoliertem CPython 3.14.4 und task-eigenem `BUILD_ROOT`/`TMP_ROOT` | 0 | Vollständiger Framework-Lint bestand, einschließlich 18 V3-Tests in 195,261 Sekunden, 12 NGINX-Archivtests in 218,834 Sekunden, Workflow-/Sicherheitsverträgen, Dokumentation und abschließendem `git diff --check` | `20260723T162517Z-fnd-cross-0001-runtime-evidence-bcda7d1d` |

## Sicherheitsauswirkung

Dies behebt den falsch abweisenden Provenance-Control, ohne daraus eine
generische Submodule-Erlaubnis zu machen. Es vervollständigt außerdem die
zugehörige FND-FRAMEWORK-0036-Fresh-Root-Grenze: Kein V3-Git-Programm wird aus
Caller-`PATH` gewählt, Git-Schreibvorgänge nach `init` können keinem lokalen
Worktree-Redirect oder externen Attributes-File folgen, und lokale
benutzerdefinierte Recursive-Update-Konfiguration wird entfernt, bevor sie
laufen kann. Die fokussierte Regression deckt legitime Kontrolle sowie
fehlende, zusätzliche, abweichende, verlinkte, ausbrechende, schmutzige,
Index-, Remote-, attached-HEAD-, feindliche-PATH-, Dynamic-Loader- und lokale
Konfigurations-Umgehungsklassen ab. Das originale MRTS wurde weder geschrieben
noch verändert.

## Dokumentation und Runtime-Evidenz

Die englische/deutsche Dokumentation unterscheidet jetzt eine exakte statische
rekursive Allowlist von generischem Submodule-Support und dokumentiert den
einen gehärteten Fresh-Provisioning-Entry-Point. Der fokussierte Check ist
ausschließlich Contract-Evidenz: Es wurden weder Connector-Runtime,
Netzwerk-Source-Fetch noch MRTS-Lifecycle-Evidenz erfasst.

## Nicht ausgeführte Prüfungen

- Hosted-Exact-Head-CI, SonarQube Cloud und ein Framework-PR existieren noch
  nicht; sie bleiben Delivery-Owner-Arbeit nach diesem isolierten Handoff.
- Connector-Smokes und MRTS-generierende Targets liegen außerhalb des
  Framework-only-Scopes und wurden nicht ausgeführt, weil das originale MRTS
  read-only ist.

## Einschränkungen und Restrisiko

Der statische Graph gilt absichtlich nur für den geprüften Root-Commit. Ein
künftiges Upstream-Root- oder Submodule-Update benötigt eine neue geprüfte
Provenance-Änderung und passende Tests. Das Framework löscht Dynamic-Loader-
Variablen vor Prozessen, die es selbst startet, aber gesourcter Shell-Code kann
den Dynamic-Loader-Zustand, mit dem ein Caller diese Shell gestartet hat, nicht
nachträglich schützen. Der Caller muss die Entry-Shell daher aus einer
vertrauenswürdigen Umgebung starten. Hermetische und Real-Git-Controls prüfen
die Entscheidungsgrenze des Guards, nicht eine Connector-Runtime. Lokale
Evidenz ersetzt keine Hosted-Exact-Head-PR-Validierung.

## Finaler Diff- und Review-Status

Das isolierte Framework bleibt an der aufgezeichneten Basisrevision detached
mit einem unstaged task-eigenen Patch. Dieser Worker ist zu keinem Commit,
Push, Branch-Anlegen, Pull Request oder Merge autorisiert und führt keinen
solchen aus. Shell-Syntax, fokussierte Make-Targets, die Parent-eigene
nicht-gemockte API-Kontrolle, Dokumentation, vollständiger Lint und der finale
Whitespace-Check sind oben eingetragen.
