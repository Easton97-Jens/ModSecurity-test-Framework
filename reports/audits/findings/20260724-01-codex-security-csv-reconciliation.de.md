# Abgleich des Codex-Security-CSV-Exports

**Sprache:** [English](20260724-01-codex-security-csv-reconciliation.md) | Deutsch

## Umfang und Methode

Dies ist der Framework-only-Abgleich des ausdrücklich bereitgestellten 23-zeiligen Codex-Security-Exports
`codex-security-findings-2026-07-24T17-04-36.095Z.csv` (SHA-256
`e28d182304f854ce01935f6f08e880900241fc67c45a4289e83f03f3192da7a4`, Scan
`user-cTR8W8YixbRnTZ4QJJXk1jpW:github-1240166325`). Der Export wurde mit dem
RFC-4180-kompatiblen Standard-CSV-Dialekt von Python geparst: Alle 23 Datenzeilen haben 17 Felder.
Die abweichende `Sniffer`-Einschätzung zu verdoppelten Anführungszeichen ist nur eine
Parserdiagnose und kein defekter Export.

Der aktuelle Framework-Default ist `77d73decd094a8f289fbe0ef2582f12430923e24`. Jede
Scan-Revision existiert und ist dessen Vorfahr; deshalb wurde jede Zeile vor einer Branch-Änderung
gegen den aktuellen Default erneut bewertet. `confirmed_open_fixed_in_task_branch` bedeutet,
dass die kumulative Task-Branch die benannte, fokussiert regression-getestete Korrektur enthält;
es ist kein Cloud-Abschluss. `documented_false_positive` bedeutet, dass die behauptete unsichere
Auswirkung durch die genannte aktuelle Kontrolle verhindert wird. `not_applicable` bedeutet, dass
die behauptete Runtime-Interpretation außerhalb des klassifizierten Inventars liegt.

Die Pfadhistorie wurde aufgelöst: Frühere Scanner-Pfade `ci/*.py` und `ci/*.sh` wurden in
`428dfb2741785ad` nach `ci/checks/`, `ci/lib/`, `ci/provisioning/`, `ci/reporting/` und
`ci/tools/` verlagert. Kein Parent-File, kein Gitlink und kein MRTS-Inhalt wurden geändert. MRTS
bleibt eine gepinnte, nur lesbare Abhängigkeit.

## Dispositionsmatrix pro Zeile

| # | Finding-ID | Schwere | Disposition | Aktueller Code-Nachweis / Task-Aktion |
| --- | --- | --- | --- | --- |
| 1 | `3e5b4a68b3288191a46e2e897019db4f` | high | documented_false_positive | `.gitmodules` pinnt das nutzerautorisierte `Easton97-Jens/MRTS`; Framework-Workflows setzen `submodules: false` und führen keine Remote-Submodule-Updates aus. Ein normales Update konsumiert den Gitlink, keine beliebige Fork-URL. |
| 2 | `6e64449e9d4481918fbcc63aef4ab41e` | high | confirmed_open_fixed_in_task_branch | `import-mrts-cases.py` schreibt jetzt `MRTS_SOURCE_REPOSITORY = "Easton97-Jens/MRTS"` statt des veralteten Upstream-Labels. Commit `d2d3320`; sechs fokussierte Importer-Tests bestanden. |
| 3 | `990e73aec6948191a3206a204a7d5881` | high | already_fixed_on_default | `ci/tools/check-github-actions-workflows.py` verwirft serialisierte `secrets`- und `github`-Kontexte; aktuelle Vertragstests decken die Negativfälle ab. |
| 4 | `932c7c43d8d88191a06ca768bba69f42` | high | already_fixed_on_default | `ci/lib/connector-smoke-common.sh` sucht kein gemeinsames temporäres Root; verifizierte Roots müssen explizit konfiguriert werden. |
| 5 | `49dfbbb3887c819187fdbd9b670341c1` | high | confirmed_open_fixed_in_task_branch | Lighttpd-Source-Staging verlangt zuerst kanonische Cache-Einhegung (19d8494) und verwirft danach jede bereits vorhandene Stage, bevor configure/autogen.sh laufen kann (e60cb8c). Die 11 Bootstrap-Tests decken externe, Traversal- und In-Cache-Executable-Marker-Fälle ab. |
| 6 | `6645193c8a4081919df834437048f38c` | high | documented_false_positive | Ein dargestelltes Response-Body-`PASS` behält `not_auto_promoted`, `response_body_non_verified`, `runtime_verified=false` und `promotion_allowed=false`; es kann keine promotierbare Evidenz werden. |
| 7 | `f2c4b104dc288191b7976a77bc5d6f02` | medium | confirmed_open_fixed_in_task_branch | `ci_modsecurity_v3_require_clean_checkout` nutzt nun `--ignored=matching`, wodurch ignorierte Build-Reste fail-closed abgewiesen werden. Commit `e94074c`; die 16 Provenance-Tests decken dies ab. |
| 8 | `ca36c37a1b8c8191bf5bba672b843f46` | medium | documented_false_positive | Die Response-Body-Runtime-Darstellung ist durch dieselben expliziten Evidenz-Flags wie in Zeile 6 nicht promotierbar. |
| 9 | `de250c7664b88191be2cf8ec9caf52f2` | medium | confirmed_open_fixed_in_task_branch | Protocol-Evidence akzeptiert exakt einen profilpflichtigen Forced-Selector; `--http3`, `--http2`, doppelte und widersprüchliche Selector werden verworfen. Commit `75f15ab`; 16 Protocol-Client-Tests bestanden. |
| 10 | `864b7d9ee20081919d081396d2a233ad` | medium | already_fixed_on_default | Der Workflow-Checker erkennt `toJSON(secrets)`- und `toJSON(github)`-Serialisierung und hat Regressionstests. |
| 11 | `ee0623b9b9388191b29b09766e413ad8` | medium | already_fixed_on_default | Das Parsing von Protocol-Capture-Kommandos verbietet Output-/Payload-Capture-Optionen einschließlich Output-File-Varianten. |
| 12 | `a0aff086d85c8191b2082624edf5307f` | medium | already_fixed_on_default | No-CRS-Engine-Version-Reads sind begrenzt und regex-beschränkt; geheimnisähnlicher oder zu langer Inhalt wird abgewiesen. |
| 13 | `712cf426a780819188abe4928484b4d7` | medium | already_fixed_on_default | No-CRS-Result-Summaries prüfen Identität, Schema, Profil, Connector und Security-Claims vor der Annahme eines PASS-Ergebnisses. |
| 14 | `ce59a7b5dfa881919172d51d9b5f02bd` | medium | already_fixed_on_default | Ein explizites `HAPROXY_BIN` wird als konfigurierter Runtime-Input erfasst und scheitert ohne Verifikation; es gibt keinen stillen Fallback. |
| 15 | `c9ca53a179948191addf07c5cfa34f67` | medium | already_fixed_on_default | Das Phase-1-Connector-Gap-Inventar enthält `classification: connector_gap` und `former_xfail` und ist nicht promotierbar. |
| 16 | `2ad2602367208191955e63da621fcf3f` | medium | already_fixed_on_default | `RUN_ONE_CASE` prüft strikte Result-Identität und Live-Execution-Evidenz, bevor ein Case-Ergebnis akzeptiert wird. |
| 17 | `f4db578ad0948191a1edcd79e393c733` | medium | already_fixed_on_default | Generierte MRTS-Pfade sind unter dem verifizierten Task-Build-Root eingehegt. |
| 18 | `a4235836148c81919fe06cfb7046d481` | medium | already_fixed_on_default | Der Case-Matrix-Normalizer wandelt einen rohen nicht-promotierbaren Pass in `NOT_EXECUTABLE` um. |
| 19 | `6f134b6136c481918d5576fa425a5957` | medium | documented_false_positive | Strikte Response-Body-Abbrüche behalten nicht-promotierbaren Zustand und normalisieren den semantischen Status; ein Darstellungsstring allein zählt nicht als PASS-Evidenz. |
| 20 | `0c88f026e99c819184283536e5ca8af5` | medium | already_fixed_on_default | Die Wiederverwendung vorhandener HAProxy-Source oder -Binary verlangt einen verifizierten Provenance-Marker. |
| 21 | `0648f667c8a08191ab140169675aacb4` | low | confirmed_open_fixed_in_task_branch | Der Common-Version-Checker blockiert jetzt fehlende oder ungültige unveränderliche ModSecurity-v3-Commit-Anker vor Netzwerkprüfungen. Commit `f3aac14`; 16 Provenance-Tests bestanden. |
| 22 | `2f9959fe71ec8191bb9c335685e68c15` | informational | documented_false_positive | Die Kommaform `except OSError, UnicodeError` ist ein gültiges Python-3-Exception-Tuple. Eine ungültige UTF-8-`.python-version` erzeugte die erwartete Decode-Diagnose. |
| 23 | `3677a6db8d74819181aa8258ae94b410` | informational | not_applicable | Security-Data-Flow-YAML-Dateien sind Connector-Gap-Inventar statt materialisierter Runtime-Cases; der Runner filtert sie vor der Runtime-Parameter-Validierung. |

## Validierung, Restrisiko und Cloud-Übergabe

Die fünf Task-Branch-Korrekturen haben fokussierte Negativ- und Legitimate-Control-Tests, die im
zugehörigen Change Record `20260724-01-reconcile-codex-security-csv-findings` festgehalten sind.
Die Tests validieren Framework-Kontrollen, keine Connector-Runtime-Behauptung.

Eine Cloud-Disposition oder ein Re-Scan ist über keinen authentifizierten Codex-Security-Service in
dieser Umgebung verfügbar; der Cloud-Abschluss ist daher `blocked_permissions`. Der aufbewahrte
CSV-Quellbestand, sein Digest, die normalisierte 23-Zeilen-Evidenz und diese Matrix sind eine
reproduzierbare Übergabe. Draft-PR #45 ist der einzige Auslieferungscontainer und gibt keine
Berechtigung zum Mergen, für Parent-Änderungen oder MRTS-Änderungen.
