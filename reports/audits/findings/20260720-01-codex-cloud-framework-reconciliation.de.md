# Abgleich der Codex-Cloud-Framework-Befunde

**Sprache:** [English](20260720-01-codex-cloud-framework-reconciliation.md) | Deutsch

## Scope und Quelle

Dies ist der Framework-only-Abgleich für den 41-zeiligen Codex-Cloud-Export
`codex-security-findings-2026-07-20T17-18-10.034Z.csv` (SHA-256
`4836e7d8a1aba6088f1d125e7f48dd2cb333c2e7d4c1d19117d911c0aad45daf`). Er ist
der Finding-Record für Framework-Draft-PR #37 auf
`agent/master-post36-sonar-remediation`. Er autorisiert keinen Merge, keinen
Push nach `master`, keine Parent-Änderung und keine MRTS-Änderung.

`fixed_in_pr` bedeutet, dass der aktuelle kumulative Branch eine Framework-
Kontrolle und fokussierte Regression enthält. `already_safe` bedeutet, dass
Current-Source-Review und die aufgeführte Kontrolle zeigten, dass der gemeldete
Angriffspfad nicht vorliegt. `historical` bedeutet, dass der Befund durch PR #38
vor der Benutzeranweisung One-PR/no-master behoben war; er wird dokumentiert,
statt ihn stillschweigend erneut einzuführen.

Jede Zeile gehört den Framework-Maintainern, hat eine **hohe** Triage-
Konfidenz und unterliegt dem gemeinsamen Akzeptanzkriterium, dass ihre
aufgeführte Kontrolle den ursprünglichen Negative Case abweist, ohne eine
legitime Kontrolle zu brechen. Der Validierungsplan jeder Zeile ist die im
gepaarten Change Record `20260720-03-reconcile-codex-cloud-framework-security`
benannte fokussierte Regression/Control zuzüglich des jeweils passenden
aggregierten Contracts. Die Cloud-Closure bleibt bis zu einem authentifizierten
Rescan blockiert; keine lokale Disposition gilt stillschweigend als Cloud-
Closure.

## Dispositionen

| Cloud-Finding-ID | Schwere | Disposition | Framework-Kontrolle oder Evidenz |
| --- | --- | --- | --- |
| `48ddc89c01548191aac6fdc953d4a69b` | high | historical | PR-#38-Action-Pin-Flow-Sequence-Fix liegt bereits auf der Basisrevision. |
| `bcbd96f10f448191803aba3e3b8a0070` | high | fixed_in_pr | No-CRS-Provenance-Reads deaktivieren repository-selektierte Git-Hooks/fsmonitor. |
| `16149ebc6acc8191ac9ee9d7e69c0df6` | high | fixed_in_pr | Automatische APXS-Cache-/Build-Root-Ausführung wurde entfernt. |
| `932c7c43d8d88191a06ca768bba69f42` | high | already_safe | Shared-Temp-Discovery ist deaktiviert; Roots brauchen explizite Validierung. |
| `49dfbbb3887c819187fdbd9b670341c1` | high | already_safe | Lighttpd-Provisionierung behält Source-Provenance und Task-Root-Pfadguards. |
| `6645193c8a4081919df834437048f38c` | high | already_safe | RESPONSE_BODY-Display-Zeilen bleiben nicht promotierbar. |
| `54eada328eec819189aae57610065121` | medium | fixed_in_pr | Trusted-Base-OSV-Target-Workflow holt und SHA-verifiziert ein PR-Objekt ohne Checkout. |
| `864b7d9ee20081919d081396d2a233ad` | medium | fixed_in_pr | Workflow-Checker weist serialisierte Secret-/GitHub-Kontexte zurück. |
| `baea266fb5888191bb324059eba138a2` | medium | fixed_in_pr | Report-Normalizer weist Symlink-Output-Targets zurück. |
| `ee0623b9b9388191b29b09766e413ad8` | medium | fixed_in_pr | Protocol-Evidence weist Payload-capturing-curl-Argumente zurück. |
| `a0aff086d85c8191b2082624edf5307f` | medium | fixed_in_pr | Engine-Version-Capture ist begrenzt und redigiert. |
| `1026985814c481918b4b027a23781d3f` | medium | fixed_in_pr | Derselbe APXS-Cache-Execution-Root-Cause wie `16149…`. |
| `9a214a75c8588191882b8ac9d962680f` | medium | fixed_in_pr | Phase-4-Evidence bindet den Integration-Mode. |
| `79df193a47ac8191bc86540880a67c9b` | medium | fixed_in_pr | HAProxy verwendet task-eigene Build-Pfade statt Shared-Cache-Binary-Reuse. |
| `b7182cd323788191ab7ac23888fa4450` | medium | fixed_in_pr | Synthetische Probes können keine Real-Host-Lifecycle-Evidence minten. |
| `d977dab59b8881918b43fe4266be1701` | medium | fixed_in_pr | Phase-4-Content-Type-Checks weisen falschen HTTP-Status zurück. |
| `51d9936d46c081918bd41943cfca556e` | medium | fixed_in_pr | Log-only-Response-Body-Observation kann nicht zu verified PASS werden. |
| `63a331f94bcc8191a3e7f92bdbb7c7bf` | medium | fixed_in_pr | Source-Status-Aliase verstecken keinen Fehler mehr. |
| `712cf426a780819188abe4928484b4d7` | medium | already_safe | No-CRS-Summary validiert notwendige Result-Identity und Evidence vor PASS. |
| `fe1ef37482e08191b59d3408d055654b` | medium | fixed_in_pr | Runtime-Download/-Build benötigt explizites Opt-in. |
| `65bc10b56e808191a520045cfdfa2bae` | medium | fixed_in_pr | Source-Checkouts sind keine Runtime-Write-Roots. |
| `2df18b3855f4819199ca1ee44272f787` | medium | fixed_in_pr | Generiertes Markdown verwendet sichere verified Run-ID. |
| `ce59a7b5dfa881919172d51d9b5f02bd` | medium | already_safe | Explizite `HAPROXY_BIN`-Validierung blockiert unsicheren Fallback. |
| `c9ca53a179948191addf07c5cfa34f67` | medium | fixed_in_pr | Phase-1-Connector-Gap-Inventar ist nicht promotierbar klassifiziert. |
| `2ad2602367208191955e63da621fcf3f` | medium | already_safe | RUN_ONE_CASE weist ein unverifiziertes PASS-Result zurück. |
| `616c924be1f48191af25a59b90cc867b` | medium | fixed_in_pr | Generated-Report-Freshness weist injizierte Header-Zeilen zurück. |
| `0044ed827d5c8191a5b68bc7d257862a` | medium | already_safe | Runtime-Guard verweigert unsichere `/var`-Ziele. |
| `badab16622ec8191b449fd8a86283684` | medium | fixed_in_pr | Connector-Report-Freshness verlangt aktuelle Evidence. |
| `828ebddbd9a081918184d9d0169a66ec` | medium | fixed_in_pr | Runtime-Reports bevorzugen keine stale MRTS-Variant-Summaries mehr. |
| `f4db578ad0948191a1edcd79e393c733` | medium | fixed_in_pr | MRTS-generierte Pfade bleiben unter der Task-Build-Root. |
| `a4235836148c81919fe06cfb7046d481` | medium | fixed_in_pr | Nicht promotierbare Runtime-Klassifikationen melden NOT_EXECUTABLE. |
| `6f134b6136c481918d5576fa425a5957` | medium | fixed_in_pr | Strikte Response-Body-Abbrüche melden NOT_EXECUTABLE. |
| `b5a2c3f804a08191a3b7e679f0595af6` | medium | fixed_in_pr | HAProxy-Coverage verlangt tatsächliche, live, promotierbare Case-Evidence. |
| `0c88f026e99c819184283536e5ca8af5` | medium | already_safe | Bestehende HAProxy-Binaries benötigen verifizierte Provenance. |
| `6acb550c6d8881919d471e219a372279` | medium | fixed_in_pr | Starter-Output-, Result- und Log-Roots weisen Traversal und Escapes zurück. |
| `35b0191ac00c819199f15e78d1af47da` | medium | fixed_in_pr | CRS-403-Override benötigt Audit-Evidence für lokale Regel `2320`. |
| `2e073de989788191a9757339713f6b4e` | medium | fixed_in_pr | CRS-Source-/Runtime-Pfade sind auf Source-/Build-Roots begrenzt. |
| `0648f667c8a08191ab140169675aacb4` | low | already_safe | Version-Checker verlangt reviewed Tag plus immutable V3-Commit. |
| `ab82b17e04b481919f6af41953c716c4` | low | fixed_in_pr | Hash-Chain-Canonicalization hasht rohe Event-Werte vor Display-Redaction. |
| `5c1e67465d948191bf7bd26dd900273b` | informational | fixed_in_pr | AGENTS-Includes können beliebiges Markdown nicht von Documentation-Checks ausnehmen. |
| `3677a6db8d74819181aa8258ae94b410` | informational | already_safe | Security-Data-Flow-Inventar wird vor Runtime-Case-Validation gefiltert. |

## Verifikation und Restrisiko

Fokussierte Negative-/Control-Tests, Workflow-Contracts, Documentation-Checks,
Shell-Syntax-Checks und die vollständige No-CRS-Baseline sind im gepaarten
Change Record `20260720-03-reconcile-codex-cloud-framework-security`
verzeichnet. Dies sind statische Framework- oder Test-Harness-Checks, keine
Connector-Runtime-Behauptungen.

Der Benutzer erlaubte einen authentifizierten Cloud-Handoff, aber in dieser
Umgebung ist kein Cloud-Connector/API-Tool verfügbar. Ein frischer Codex-Cloud-
Scan und Finding-Closure sind daher `blocked_permissions`; dieser Record
behauptet keine Cloud-Closure. PR #37 bleibt der einzige Delivery-Container
und muss ungemergt bleiben.
