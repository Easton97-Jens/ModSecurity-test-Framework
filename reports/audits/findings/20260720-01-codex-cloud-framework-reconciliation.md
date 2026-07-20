# Codex Cloud Framework finding reconciliation

**Language:** English | [Deutsch](20260720-01-codex-cloud-framework-reconciliation.de.md)

## Scope and source

This is the Framework-only reconciliation for the 41-row Codex Cloud export
`codex-security-findings-2026-07-20T17-18-10.034Z.csv` (SHA-256
`4836e7d8a1aba6088f1d125e7f48dd2cb333c2e7d4c1d19117d911c0aad45daf`). It is
the finding record for Framework Draft PR #37 on
`agent/master-post36-sonar-remediation`. It does not authorize a merge, a
push to `master`, a Parent change, or an MRTS change.

`fixed_in_pr` means the current cumulative branch contains a Framework control
and focused regression. `already_safe` means current-source review and its
listed control showed the reported attack path is not present. `historical`
means the finding was fixed by PR #38 before the user's one-PR/no-master
instruction; it is recorded rather than silently reintroduced.

Each row is owned by the Framework maintainers, has **high** triage confidence,
and is governed by the shared acceptance criterion that its listed control
rejects the original negative case without breaking a legitimate control. The
validation plan for each row is the focused regression/control named by the
paired Change Record `20260720-03-reconcile-codex-cloud-framework-security`,
plus its relevant aggregate contract where one exists. Cloud closure remains
blocked until an authenticated rescan is available; no local disposition is
silently treated as a Cloud closure.

## Dispositions

| Cloud finding ID | Severity | Disposition | Framework control or evidence |
| --- | --- | --- | --- |
| `48ddc89c01548191aac6fdc953d4a69b` | high | historical | PR #38 action-pin flow-sequence fix is already on the base revision. |
| `bcbd96f10f448191803aba3e3b8a0070` | high | fixed_in_pr | No-CRS provenance reads disable repository-selected Git hooks/fsmonitor. |
| `16149ebc6acc8191ac9ee9d7e69c0df6` | high | fixed_in_pr | APXS automatic cache/build-root execution was removed. |
| `932c7c43d8d88191a06ca768bba69f42` | high | already_safe | Shared temporary-directory discovery is disabled; roots require explicit validation. |
| `49dfbbb3887c819187fdbd9b670341c1` | high | already_safe | Lighttpd provisioning retains source provenance and task-root path guards. |
| `6645193c8a4081919df834437048f38c` | high | already_safe | RESPONSE_BODY display rows remain non-promotable. |
| `54eada328eec819189aae57610065121` | medium | fixed_in_pr | Trusted-base OSV target workflow fetches and SHA-verifies a PR object without checkout. |
| `864b7d9ee20081919d081396d2a233ad` | medium | fixed_in_pr | Workflow checker rejects serialized secret/GitHub contexts. |
| `baea266fb5888191bb324059eba138a2` | medium | fixed_in_pr | Report normalizer rejects symlink output targets. |
| `ee0623b9b9388191b29b09766e413ad8` | medium | fixed_in_pr | Protocol evidence rejects payload-capturing curl arguments. |
| `a0aff086d85c8191b2082624edf5307f` | medium | fixed_in_pr | Engine-version capture is bounded and redacted. |
| `1026985814c481918b4b027a23781d3f` | medium | fixed_in_pr | Same APXS cache-execution root cause as `16149…`. |
| `9a214a75c8588191882b8ac9d962680f` | medium | fixed_in_pr | Phase-4 evidence binds integration mode. |
| `79df193a47ac8191bc86540880a67c9b` | medium | fixed_in_pr | HAProxy uses task-owned build paths instead of shared-cache binary reuse. |
| `b7182cd323788191ab7ac23888fa4450` | medium | fixed_in_pr | Synthetic probes cannot mint real-host lifecycle evidence. |
| `d977dab59b8881918b43fe4266be1701` | medium | fixed_in_pr | Phase-4 content-type checks reject a wrong HTTP status. |
| `51d9936d46c081918bd41943cfca556e` | medium | fixed_in_pr | Log-only response-body observations cannot become verified PASS. |
| `63a331f94bcc8191a3e7f92bdbb7c7bf` | medium | fixed_in_pr | Source-status aliases no longer hide failure. |
| `712cf426a780819188abe4928484b4d7` | medium | already_safe | No-CRS summary validates required result identity and evidence before PASS. |
| `fe1ef37482e08191b59d3408d055654b` | medium | fixed_in_pr | Runtime download/build requires an explicit opt-in. |
| `65bc10b56e808191a520045cfdfa2bae` | medium | fixed_in_pr | Source checkouts are not accepted as runtime write roots. |
| `2df18b3855f4819199ca1ee44272f787` | medium | fixed_in_pr | Generated Markdown uses a safe verified run identifier. |
| `ce59a7b5dfa881919172d51d9b5f02bd` | medium | already_safe | Explicit `HAPROXY_BIN` validation blocks unsafe fallback. |
| `c9ca53a179948191addf07c5cfa34f67` | medium | fixed_in_pr | Phase-1 connector-gap inventory is classified non-promotable. |
| `2ad2602367208191955e63da621fcf3f` | medium | already_safe | RUN_ONE_CASE rejects an unverified PASS result. |
| `616c924be1f48191af25a59b90cc867b` | medium | fixed_in_pr | Generated-report freshness rejects injected header lines. |
| `0044ed827d5c8191a5b68bc7d257862a` | medium | already_safe | Runtime guard denies unsafe `/var` destinations. |
| `badab16622ec8191b449fd8a86283684` | medium | fixed_in_pr | Connector report freshness requires current evidence. |
| `828ebddbd9a081918184d9d0169a66ec` | medium | fixed_in_pr | Runtime reports no longer prefer stale MRTS variant summaries. |
| `f4db578ad0948191a1edcd79e393c733` | medium | fixed_in_pr | MRTS generated paths are contained under the task build root. |
| `a4235836148c81919fe06cfb7046d481` | medium | fixed_in_pr | Non-promotable runtime classifications report NOT_EXECUTABLE. |
| `6f134b6136c481918d5576fa425a5957` | medium | fixed_in_pr | Strict response-body aborts report NOT_EXECUTABLE. |
| `b5a2c3f804a08191a3b7e679f0595af6` | medium | fixed_in_pr | HAProxy coverage requires actual, live, promotable case evidence. |
| `0c88f026e99c819184283536e5ca8af5` | medium | already_safe | Existing HAProxy binaries require verified provenance. |
| `6acb550c6d8881919d471e219a372279` | medium | fixed_in_pr | Starter output, result, and log roots reject traversal and escapes. |
| `35b0191ac00c819199f15e78d1af47da` | medium | fixed_in_pr | CRS 403 override requires audit evidence for local rule `2320`. |
| `2e073de989788191a9757339713f6b4e` | medium | fixed_in_pr | CRS source/runtime paths are constrained to source/build roots. |
| `0648f667c8a08191ab140169675aacb4` | low | already_safe | Version checker requires reviewed tag plus immutable V3 commit. |
| `ab82b17e04b481919f6af41953c716c4` | low | fixed_in_pr | Hash-chain canonicalization hashes raw event values before display redaction. |
| `5c1e67465d948191bf7bd26dd900273b` | informational | fixed_in_pr | AGENTS includes cannot exempt arbitrary Markdown from documentation checks. |
| `3677a6db8d74819181aa8258ae94b410` | informational | already_safe | Security-data-flow inventory is filtered before runtime-case validation. |

## Verification and residual risk

Focused negative/control tests, workflow contracts, documentation checks, shell
syntax checks, and the full No-CRS baseline are recorded in the paired Change
Record `20260720-03-reconcile-codex-cloud-framework-security`. These are
Framework static or test-harness checks, not connector runtime claims.

The user permitted an authenticated Cloud handoff, but no Cloud connector/API
tool is available in this environment. A fresh Codex Cloud scan and finding
closure are therefore `blocked_permissions`; this record does not claim Cloud
closure. PR #37 remains the only delivery container and must remain unmerged.
