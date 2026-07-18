# 20260718-01 — Immutable Full-SHA-Framework-Action-Pins erzwingen

**Sprache:** [English](20260718-01-fix-framework-actions-sha-pins.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20260718-01-fix-framework-actions-sha-pins |
| UTC-Datum | 2026-07-18 |
| Framework-Basisrevision | cdc91a398d6c156eaff927d742b23018a3817fb6 |
| Finding / Grundursachen-Gruppe | FND-FRAMEWORK-0003 / RC-FW-001-action-reference-immutability |
| Issue oder Pull Request | Die Draft-PR-Sammlung steht aus; dieser Record enthält absichtlich keine zukünftige PR-Nummer, URL oder Delivery-SHA. |

## Motivation und Sicherheitsgrenze

Die bisherige Inline-Workflow-Kontrolle akzeptierte mutable Major-Action-Tags
wie actions/checkout@v7. Ein geändertes Upstream-Tag konnte dadurch den Code
eines geplanten oder manuell gestarteten Framework-Workflows ohne immutable
Action-Identität verändern. Diese ausschließlich Framework-eigene Änderung
remediiert die externe uses:-Auflösungsgrenze aus FND-FRAMEWORK-0003.

Betroffene Framework-Pfade:

- .github/workflows/check-action-versions.yml
- .github/workflows/check-common-versions.yml
- .github/workflows/cleanup-artifacts.yml
- .github/workflows/lint.yml
- .github/workflows/test-common.yml
- ci/checks/security/check-workflow-action-pins.py
- tests/security_regression/test_workflow_action_pins.py
- Makefile

Parent-Source und Gitlinks sind nicht Teil dieser Änderung; MRTS bleibt
unberührt.

## Akzeptanzkriterien und Implementierungsentscheidung

Der Checker deckt .yml- und .yaml-Workflow-Dateien rekursiv ab; er erlaubt nur
eine lokale ./-Referenz oder einen externen vollständigen 40-stelligen
Git-Commit-SHA; und er lehnt mutable Major-Tags, Branches, verkürzte Hashes,
Docker-Formen und nicht unterstützte YAML-Kodierungen fail-closed ab. Zitierte
Full-SHA-Referenzen und auf einen Full-SHA gepinnte externe reusable Workflows
bleiben legitime Kontrollfälle.

Das Beibehalten des Inline-Regex wäre schwer testbar geblieben und hätte
mutable Tags erlaubt. Nur beobachtete Workflow-Zeilen zu pinnen würde eine
zukünftige Regression nicht verhindern. Eine YAML-Parser-Dependency würde die
Framework-Supply-Chain vergrößern. Der gewählte Standard-Library-Checker ist
die kleinste Framework-native Kontrolle: Er zentralisiert die Regel, scannt den
echten Workflow-Baum und stellt ein fokussiertes Regression-Target bereit.
Nicht unterstützte mehrdeutige YAML-Key-Formen werden abgelehnt statt permissiv
interpretiert.

Die sieben Referenzen behalten ihre bisherige Major-Version-Absicht, verwenden
nun aber diese überprüften Commits:

| Vorheriges Major-Tag | Immutable Commit-SHA |
| --- | --- |
| actions/checkout@v7 | 9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 |
| actions/setup-python@v6 | ece7cb06caefa5fff74198d8649806c4678c61a1 |
| actions/github-script@v9 | 3a2844b7e9c422d3c10d287c895573f7108da1b3 |
| peter-evans/create-pull-request@v8 | 5f6978faf089d4d20b00c7766989d076bb2fc7f1 |

Der Checker behandelt zitierte Scalar-Kodierungen, überspringt nur eingerückte
Literal-/Folded-Block-Scalar-Inhalte und schlägt für explizite Keys, YAML-Node-
Properties, Aliase und mehrzeilige Flow-/Quoted-Formen fail-closed fehl, die
uses verschleiern könnten. Docker-Referenzen werden abgelehnt, weil ein
Image-Digest nicht der geforderte Git-Commit-SHA ist. make lint führt das
fokussierte Regression-Target und den Validator auf den echten Workflows aus.

## Tests und Evidenz

Die initiale fokussierte Regression schlug vor der Enforcement-Änderung fehl,
während ein unzitierter Full-40-Character-SHA-Kontrollfall bestand. Die finale
fokussierte Suite enthält 21 Tests und deckt .yml/.yaml, Kommentare, Quotes und
Escapes, Literal-Script-Blöcke, lokale/Docker/reusable Formen, Branches,
verkürzte Hashes, Flow-Mappings, explizite Keys, YAML-Node-Properties, Aliase
und Full-SHA-Kontrollen ab. Die breitere tests/security_regression-Suite
enthält 34 Tests.

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| rtk env ... python -m unittest tests/security_regression/test_workflow_action_pins.py | 0 | 21 fokussierte Action-Pin-Regressionstests bestanden. | 20260718T092013Z-fnd-framework-0003-actions-sha-pins-41e9a058 |
| rtk env ... python ci/checks/security/check-workflow-action-pins.py | 0 | Die echten geänderten Workflows enthalten nur Full-SHA-externen Referenzen. | 20260718T092013Z-fnd-framework-0003-actions-sha-pins-41e9a058 |
| rtk env ... python -m unittest discover -s tests/security_regression -v | 0 | 34 Security-Regressionstests bestanden. | 20260718T092013Z-fnd-framework-0003-actions-sha-pins-41e9a058 |
| rtk env ... make lint ... | 0 | Framework-Lint, Workflow-Syntax, fokussierte Pin-Suite, Real-Checker und Dokumentationsaggregat bestanden; sein hartkodierter /tmp-CRS-Subcheck wurde separat wiederholt. | 20260718T092013Z-fnd-framework-0003-actions-sha-pins-41e9a058 |
| rtk sh ci/checks/catalog/check-crs-version-pinning.sh | 0 | Der CRS-Pinning-Subcheck bestand außerhalb der Sandbox. | 20260718T092013Z-fnd-framework-0003-actions-sha-pins-41e9a058 |
| rtk shellcheck -x ci/lib/common.sh ci/checks/catalog/check-common-helpers.sh | 1 | Dieselben zehn bestehenden Master-Diagnosen auf unveränderten Shell-Dateien; unabhängiges Baseline-Finding. | lokale Feasibility-Evidenz |
| task-lokales actionlint --version | 0 | Frische SHA-256-verifizierte Release-Entpackung aus dem versionierten Parent-Lock; meldete 1.7.12. | 20260718T110350Z-fnd-framework-0003-delivery-c3a1f003 |
| task-lokales zizmor --version | 0 | Frische SHA-256-verifizierte Release-Entpackung aus dem versionierten Parent-Lock; meldete 1.27.0. | 20260718T110350Z-fnd-framework-0003-delivery-c3a1f003 |
| rtk gh api repos/Easton97-Jens/ModSecurity-test-Framework/commits/cdc91a398d6c156eaff927d742b23018a3817fb6/check-runs | 0 | Base/Master hat unabhängige SonarCloud-Code-Analysis- und common-structure-Fehler. | GitHub-Base-Check-Evidenz |

Für die autorisierte Delivery-Revalidierung wurden das versionierte
Parent-Lock und sein repository-nativer Helper vor einer frischen,
task-eigenen lokalen Installation erneut geprüft. Der Helper verlangt die
exakte Upstream-Release-URL und das Asset, validiert SHA-256 vor dem Entpacken
und verändert weder System noch PATH.

| Tool | Exakte Upstream-Release-Identität | Exaktes Asset und SHA-256 |
| --- | --- | --- |
| actionlint | rhysd/actionlint v1.7.12; Release-Commit `914e7df21a07ef503a81201c76d2b11c789d3fca` | `actionlint_1.7.12_linux_amd64.tar.gz`; `8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8` |
| zizmor | zizmorcore/zizmor v1.27.0; Release-Commit `e2627367eb7c917a90503ce05a66872fd91da6fb` | `zizmor-x86_64-unknown-linux-gnu.tar.gz`; `277f2bd8fd37cf60c42ab7afca6faa884e65440fa31e02b44bdaae60f62a358f` |

| Befehl | Exit-Code | Kurzes Ergebnis | Run-ID oder zulässiger Evidenzpfad |
| --- | --- | --- | --- |
| rtk env ... python -m unittest discover -s tests/security_regression -p test_workflow_action_pins.py -v | 0 | 21 fokussierte Action-Pin-Regressionstests bestanden. | 20260718T110350Z-fnd-framework-0003-delivery-c3a1f003 |
| rtk env ... python ci/checks/security/check-workflow-action-pins.py | 0 | Alle fünf echten Framework-Workflows enthalten nur Full-SHA-externe Referenzen. | 20260718T110350Z-fnd-framework-0003-delivery-c3a1f003 |
| rtk env ... python -m unittest discover -s tests/security_regression -v | 0 | 34 Security-Regressionstests bestanden. | 20260718T110350Z-fnd-framework-0003-delivery-c3a1f003 |
| rtk env ... make lint | 0 | Framework-Lint, Shell-Syntax, Workflow-Syntax, fokussierte Pin-Suite, Real-Checker, CRS-Pinning und Dokumentationsaggregat bestanden. | 20260718T110350Z-fnd-framework-0003-delivery-c3a1f003 |
| rtk ... check-workflow-action-pins.py --workflow-root safe fixture | 0 | Full SHA, lokale Action, lokaler reusable Workflow, externer reusable Full SHA und Folded-Block-Scalar-Text wurden akzeptiert. | 20260718T110350Z-fnd-framework-0003-delivery-c3a1f003 |
| rtk ... check-workflow-action-pins.py --workflow-root unsafe fixture | 1 (erwartet) | Lehnte `@v4` mit Inline-Kommentar, Kurz-Hash, Docker, expliziten Key, Alias und externen reusable `@v1` ab. | 20260718T110350Z-fnd-framework-0003-delivery-c3a1f003 |
| task-lokales actionlint gegen alle fünf Workflows | 1 (nur Baseline) | Dieselbe unveränderte eingebettete Shell-Warnung SC2046 wie auf Framework-master; keine task-eigene actionlint-/ShellCheck-Diagnose. | Master- und Current-Run-Vergleich |
| task-lokales zizmor --offline gegen alle Workflows | 13 (nur Baseline) | Sieben `unpinned-uses`-High-Findings von Master wurden entfernt; nur vier bestehende `artipacked`-Findings bleiben. | Master- und Current-Run-Vergleich |
| task-lokales zizmor --offline --min-severity high gegen alle Workflows | 0 | Kein High- oder Critical-Finding bleibt auf dem Task-Branch. | 20260718T110350Z-fnd-framework-0003-delivery-c3a1f003 |
| rtk shellcheck ci/lib/common.sh ci/checks/catalog/check-common-helpers.sh | 1 (nur Baseline) | Dieselben zehn Diagnosen auf unveränderten Shell-Dateien auf Master und Task-Branch; keine task-eigene neue Diagnose. | Master- und Current-Run-Vergleich |
| rtk make check-bilingual-docs, check-doc-links, check-repository-path-references, check-documentation | 0 | Bilingualitäts-, Link-, Pfad- und Dokumentationsprüfungen bestanden. | 20260718T110350Z-fnd-framework-0003-delivery-c3a1f003 |
| rtk git diff --check | 0 | Kein Whitespace-Fehler. | 20260718T110350Z-fnd-framework-0003-delivery-c3a1f003 |

Die Codex-Security-Revalidierung und die ausführbare Fixture-Matrix fanden
keinen konkreten Bypass in der verlangten Matrix. Sie bestätigten die
fail-closed-Behandlung von expliziten Flow-Keys, Node-Properties und Aliasen;
zitierten/escaped Werten; Kommentaren; .yml/.yaml; lokalen, Docker-, reusable-,
Branch-, Kurz-Hash- und GitHub-Expression-Formen; sowie Literal-/Folded-
Block-Scalar-Grenzen. Die rohen actionlint- und zizmor-Aufrufe bleiben als
Baseline-Evidenz erhalten statt unterdrückt zu werden: Die verbleibenden
Diagnosen existieren auf dem unveränderten Framework-master.

## Dokumentation, Delivery und Restrisiko

Dieser englische Record und sein deutsches Gegenstück dokumentieren die
Framework-Änderung. Keine GitHub-Actions-Runtime-Ausführung wurde durchgeführt.
Bei dieser Record-Revision autorisiert der Nutzer nach dem finalen Scope-Review
den fokussierten Framework-Commit, normalen Push und die Draft-PR-Sammlung. Er
enthält absichtlich keine zukünftige Commit-SHA, Remote-SHA, PR-Nummer oder
PR-URL.

Kein Framework-Merge, Parent-Commit, Parent-Gitlink-Update oder MRTS-
Modifikation ist autorisiert. FND-FRAMEWORK-0001 bleibt von Framework-PR #23
abhängig, und FND-SONAR-0002 bleibt ein unabhängiger Sonar-Scope auf
Framework-master; keines wird hier verändert. Sie blockieren den autorisierten
Draft-PR nicht, erfordern aber eine spätere Revalidierung gegen den dann
aktuellen Framework-master, bevor `verified_pr` verwendet werden kann.

Der eingegrenzte Framework-Diff ist für die PR-Sammlung bereit. Der nach der
Erstellung verfasste PR-Body muss `finding_status: fixed`,
`pr_status: collected_draft_pr`,
`verification_status: pending_framework_baseline_revalidation`,
`dependency: Framework-PR #23`, `independent_blocker: FND-SONAR-0002`,
`requires_revalidation: true` und `merge_authorization: not_granted` zusammen
mit der beobachteten Gleichheit von lokaler, Remote- und PR-Head-SHA erfassen.
Kein dynamischer Upstream-Tag-Rewrite wurde durchgeführt.
