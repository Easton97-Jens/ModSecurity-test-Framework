#!/usr/bin/env python3
"""Render compact NGINX-only evidence and bilingual reports from reviewed inputs.

The full external ledger remains the authority for physical proof. Observation
candidates never change statuses, approve an oracle, or qualify a request here.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path


BASELINE_SHA256 = "a3a901db7d70884d2f491c95246629071cd55280ad94ee0fd86049c2e954c7ff"
REPOSITORY_ROOT = connector_root()
JSON_FENCE = "```json"


def evidence_root():
    """Require an existing private run root configured by the operator."""
    value = os.environ.get("CODEX_RUN_ROOT")
    if not value:
        raise ValueError("CODEX_RUN_ROOT must name a protected project directory")
    root = Path(value)
    if not root.is_absolute() or root.parent == root or root != root.resolve() or not root.is_dir():
        raise ValueError("Canonical existing CODEX_RUN_ROOT required")
    info = root.lstat()
    if info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
        raise ValueError("CODEX_RUN_ROOT must be operator-owned and protected")
    return root


def trusted_ancestry(path, *, regular=False):
    """Reject writable/unowned ancestors before reaching any filesystem sink."""
    root = evidence_root()
    for component in reversed((path, *path.parents)):
        info = component.lstat()
        if info.st_uid not in (0, os.geteuid()) or stat.S_ISLNK(info.st_mode):
            raise ValueError("Path requires root/operator ownership without symlinks")
        transit = (component != path and not component.is_relative_to(root) and
                   info.st_uid == 0 and stat.S_ISDIR(info.st_mode) and info.st_mode & stat.S_ISVTX)
        if info.st_mode & 0o022 and not transit:
            raise ValueError("Path has a group/world-writable component")
        if component != path and not stat.S_ISDIR(info.st_mode):
            raise ValueError("Path ancestor must be a directory")
        if component == path and regular and not stat.S_ISREG(info.st_mode):
            raise ValueError("Evidence must be a regular file")


def evidence_path(path):
    """Accept evidence only inside the operator-owned project run boundary."""
    path = Path(path).absolute()
    if ".." in path.parts or not path.is_relative_to(evidence_root()):
        raise ValueError("Evidence path must remain inside the project run root")
    trusted_ancestry(path, regular=True)
    return path


def output_path(path, tracked_name):
    """Restrict publication to exactly this task's versioned report file."""
    path = Path(path).absolute()
    tracked = REPOSITORY_ROOT / tracked_name
    if ".." in path.parts or path != tracked:
        raise ValueError("Output is outside the NGINX report publication boundary")
    trusted_ancestry(path.parent)
    if path.exists() or path.is_symlink():
        trusted_ancestry(path, regular=True)
    return tracked


def select(value, keys):
    return {key: value[key] for key in keys if key in value}


def redact_local_paths(value):
    """Keep public reports reproducible without publishing a developer checkout."""
    if isinstance(value, dict):
        return {key: redact_local_paths(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_local_paths(item) for item in value]
    if isinstance(value, str):
        value = re.sub(
            r"/root/(?:git|conecter)/ModSecurity-conector/\.venv/bin/python",
            "python3",
            value,
        )
        return re.sub(
            r"/root/(?:git|conecter)/ModSecurity-conector",
            "<connector-root>",
            value,
        )
    return value


def public_summary(value):
    """Project approved facts; complete receipts remain external and hash-bound."""
    if "remaining_gaps" in value:
        result = select(value, ("schema_version", "scope", "source_head", "base", "branch",
                               "baseline_catalog_identity", "ledger_summary", "remaining_gaps",
                               "remaining_original_open_oracle_ids", "references", "sdk_mime",
                               "product_defect", "configuration_controls"))
        build = value["build_identity"]
        result["build_identity"] = {key: item for key, item in build.items()
                                    if key.endswith("sha256") or key == "sdk_version"}
        result["build_identity"]["compiled_parent_units"] = len(build["compiled_parent_units"])
        result["build_identity"]["compiled_nginx_generated_units"] = len(build["compiled_nginx_generated_units"])
        result["suite"] = {key: item for key, item in value["suite"].items()
                           if key != "receipt_references"}
        result["controllers"] = [{"reference": item["reference"], "result": select(item["result"], (
            "controller_exitcode", "exitcode", "signal", "timeout", "errors", "resource_violation",
            "supervisor_reaped", "surviving_namespace_pids", "outside_mount_leaks", "spec_sha256",
            "controller_sha256", "admission_sha256"))} for item in value["controllers"]]
        result["ordinary_regressions"] = [{**select(item, ("selected_id", "reference", "module_sha256", "cleanup")),
            "clients": [{**select(client, ("label", "pid", "exit_code", "signal", "direct_child_wait")),
                         "observation": select(client["observation"], ("pid", "uid", "status", "error",
                             "body_bytes", "body_sha256", "request_sha256", "response_sha256", "framing",
                             "framing_complete", "socket_eof", "socket_reset"))}
                        for client in item["clients"]]} for item in value["ordinary_regressions"]]
        result["oracle_corrections"] = [select(item, ("run_scoped_case_id", "original_oracle",
            "effective_oracle", "outcome", "retained_original_event_fields")) for item in value["oracle_corrections"]]
        result["qualified_failures"] = [select(item, ("run_scoped_case_id", "cause"))
                                         for item in value["qualified_failures"]]
        return result
    if "checks" in value:
        result = select(value, ("generated", "cleanup_fixture_patch_sha256", "tools", "limitations"))
        input_hashes = value.get("input_sha256", {})
        canonical_hashes = json.dumps(
            input_hashes,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        result["input_sha256_count"] = len(input_hashes)
        result["input_sha256_set_sha256"] = hashlib.sha256(canonical_hashes).hexdigest()
        result["checks"] = [select(check, ("name", "command", "cwd", "parent_revision", "scope",
            "exit_code", "status", "elapsed_seconds", "raw_log_sha256", "raw_log_bytes",
            "unittest_counts", "unittest_verdicts", "interpretation", "explicit_native_inputs"))
                            for check in value["checks"]]
        return result
    if "cases" in value:
        return {key: item for key, item in value.items() if key != "cases"}
    return select(value, ("scope", "source_sha256", "sdk_sha256", "steps", "passed"))


def check_public_value(item, forbidden, sensitive):
    if isinstance(item, dict):
        for key, child in item.items():
            if key in forbidden or sensitive.search(key):
                raise ValueError(f"Private artifact key rejected: {key}")
            check_public_value(child, forbidden, sensitive)
    elif isinstance(item, list):
        for child in item:
            check_public_value(child, forbidden, sensitive)


def check_public_artifact(value):
    """Fail closed if a future input adds private mappings or body material."""
    forbidden = {"environment", "exact_hex", "body_hex", "decision", "checks",
                 "request_body", "response_body", "raw_body"}
    sensitive = re.compile(r"(?:password|secret|credential|authorization|cookie|api_key|access_token|private_key)", re.I)
    # Verification's public check list is intentional; per-case decisions are not.
    for section in value.get("verification", []):
        for check in section["summary"].get("checks", []):
            check_public_value(check, forbidden, sensitive)
    without_checks = {**value, "verification": [{**section, "summary": {
        key: child for key, child in section["summary"].items() if key != "checks"}}
        for section in value.get("verification", [])]}
    check_public_value(without_checks, forbidden, sensitive)


def read(path):
    return json.loads(evidence_path(path).read_text(encoding="utf-8"))


def reference(path):
    path = evidence_path(path)
    content = path.read_bytes()
    return {"path": str(path.resolve()), "sha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content)}


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode()).hexdigest()


def public_source_hash_inventory(value):
    """Keep a record readable while binding its bulky per-path hash inventory."""
    if value is None:
        return None
    result = dict(value)
    source_hashes = result.pop("original_source_hashes", {})
    result["original_source_hashes_count"] = len(source_hashes)
    result["original_source_hashes_set_sha256"] = canonical_hash(source_hashes)
    return result


def public_selected_requirement(value):
    return public_source_hash_inventory(value)


def validate_compact_membership(ledger, baseline, observations):
    rows = ledger["rows"]
    ids = [row["run_scoped_case_id"] for row in rows]
    if len(ids) != 140 or len(set(ids)) != 140 or set(ids) != set(baseline):
        raise ValueError("Exactly the original 140 NGINX IDs are required")
    for verdict, key in (("PASS", "full_lifecycle_pass"), ("FAIL", "full_lifecycle_fail")):
        actual = sum(row["full_lifecycle_qualified"] and row["new_status"] == verdict for row in rows)
        if ledger["summary"][key] != actual:
            raise ValueError("Lifecycle summary differs from original-ID rows")
    if ledger["summary"]["original_ids"] != 140:
        raise ValueError("Selected-ID summary differs from original membership")
    gap_inputs = [read(path)["remaining_gaps"] for path in observations
                  if "remaining_gaps" in read(path)]
    if len(gap_inputs) != 1:
        raise ValueError("Exactly one reviewed remaining-gap mapping is required")
    gaps = gap_inputs[0]
    unqualified = {row["run_scoped_case_id"] for row in rows
                   if not row["full_lifecycle_qualified"]}
    if set(gaps) != unqualified or any(not isinstance(value, str) or not value.strip()
                                      for value in gaps.values()):
        raise ValueError("Remaining-gap mapping must exactly cover unqualified original IDs")
    return rows, gaps


def compact_row(index, row, baseline, gaps):
    case_id = row["run_scoped_case_id"]
    selected = row["selected_requirement"]
    if selected != baseline[case_id]["selected_requirement"] or row["baseline"] != baseline[case_id]:
        raise ValueError("Original selected contract or historical row changed")
    new = row["new_evidence"]
    packet = new["packet"] if new else None
    return {
        "run_scoped_case_id": case_id,
        "selected_requirement_sha256": canonical_hash(selected),
        "selected_requirement": public_selected_requirement(selected),
        "baseline_row_sha256": canonical_hash(row["baseline"]),
        "baseline_row_locator": {"input": "baseline", "run_scoped_case_id": case_id},
        "full_row_locator": {"input": "full_ledger", "row_index": index},
        "baseline_status": row["baseline"]["status"],
        "baseline_qualification_scope": row["baseline"].get("qualification_scope"),
        "new_status": row["new_status"],
        "full_lifecycle_qualified": row["full_lifecycle_qualified"],
        "new_packet": packet.get("receipt") if packet else None,
        "new_request_identity": new["request_identity"] if new else None,
        "new_oracle_review": public_source_hash_inventory(new["oracle_review"]) if new else None,
        "original_oracle_unresolved": bool(selected["expected_oracle"].get(
            "unresolved_expected_value_reason")),
        "remaining_gap": None if row["full_lifecycle_qualified"] else gaps[case_id],
    }


def compact(ledger, ledger_path, observations, verification):
    baseline_ref = ledger["inputs"]["baseline"]
    if baseline_ref["sha256"] != BASELINE_SHA256:
        raise ValueError("Unexpected immutable baseline")
    baseline_path = Path(baseline_ref["path"])
    if reference(baseline_path)["sha256"] != BASELINE_SHA256:
        raise ValueError("Baseline bytes changed")
    baseline = {row["run_scoped_case_id"]: row for row in read(baseline_path)["rows"]
                if row["leg_id"] == "nginx-native"}
    rows, gaps = validate_compact_membership(ledger, baseline, observations)
    compact_rows = [compact_row(index, row, baseline, gaps)
                    for index, row in enumerate(rows)]
    result = {"schema_version": 1, "profile": "nginx-native", "date": "2026-10-15",
            "canonical_hash_format": "UTF-8 JSON, sorted keys, separators=(',', ':'), ensure_ascii=False",
            "inputs": {"baseline": baseline_ref, "full_ledger": reference(ledger_path),
                       "observations": [reference(path) for path in observations],
                       "verification": [reference(path) for path in verification]},
            "summary": ledger["summary"],
            "observations": [{"input": reference(path), "summary": redact_local_paths(public_summary(read(path)))}
                             for path in observations],
            "verification": [{"input": reference(path), "summary": redact_local_paths(public_summary(read(path)))}
                             for path in verification],
            "rows": compact_rows}
    check_public_artifact(result)
    return result


def observation_header(item):
    summary = item["summary"]
    header = {key: value for key, value in summary.items() if key != "cases"}
    if "remaining_gaps" in summary:
        header = {key: summary[key] for key in (
            "source_head", "branch", "base", "scope", "sdk_mime", "product_defect",
            "remaining_original_open_oracle_ids")}
        header["build_identity"] = {key: value for key, value in summary["build_identity"].items()
                                    if key.endswith("sha256") or key == "sdk_version"}
        header["compiled_parent_unit_count"] = summary["build_identity"]["compiled_parent_units"]
        header["compiled_nginx_generated_unit_count"] = summary["build_identity"]["compiled_nginx_generated_units"]
        header["suite"] = {key: value for key, value in summary["suite"].items()
                           if key != "receipt_references"}
        header["qualified_failures"] = [{"case_id": failure["run_scoped_case_id"],
                                          "cause": failure["cause"]}
                                         for failure in summary["qualified_failures"]]
    return header


def append_verification(lines, verification):
    for item in verification:
        for check in item["summary"].get("checks", []):
            command = check.get("command", [])
            command = " ".join(command) if isinstance(command, list) else str(command)
            lines.append(f"| {check.get('name')} | {check.get('exit_code')} | {check.get('status')} | `{command.replace('|', '&#124;')}` |")
    for item in verification:
        if not item["summary"].get("checks"):
            lines += ["", JSON_FENCE, json.dumps(item, indent=2, ensure_ascii=False), "```", ""]


def report(data, machine_path, german=False):
    def choose(en, de):
        return de if german else en

    peer = "pr-410-i12-nginx-evidence-20261015" + (".md" if german else ".de.md")
    summary = data["summary"]
    qualified = sum(row["full_lifecycle_qualified"] for row in data["rows"])
    remaining = len(data["rows"]) - qualified
    lines = [choose("# I12 NGINX evidence, 2026-10-15", "# I12 NGINX-Nachweise, 2026-10-15"), "",
             choose(f"**Language:** English | [Deutsch]({peer})", f"**Sprache:** [English]({peer}) | Deutsch"), "",
             choose("Generated by `ci/runtime/lifecycle/i12/nginx/report.py`; edit its inputs or generator.",
                    "Generiert durch `ci/runtime/lifecycle/i12/nginx/report.py`; Eingaben oder Generator ändern."), "",
             choose("## Status and evidence boundaries", "## Status und Nachweisgrenzen"), "",
             choose("The selected original 140 IDs remain authoritative. Only an approved complete selected host packet qualifies a lifecycle PASS. Candidate observations, native unit tests, configuration checks and aliases never qualify additional requests.",
                    "Die 140 ausgewählten ursprünglichen IDs bleiben maßgeblich. Nur ein freigegebenes vollständiges ausgewähltes Hostpaket qualifiziert einen Lifecycle-PASS. Kandidatenbeobachtungen, native Unit-Tests, Konfigurationsprüfungen und Aliase qualifizieren keine zusätzlichen Requests."), "",
             choose(f"Current complete qualification covers **{qualified}/140 original IDs**: **{summary['full_lifecycle_pass']} PASS** and **{summary['full_lifecycle_fail']} FAIL**. **{remaining} IDs** still lack a complete lifecycle qualification. Baseline qualification resolved {summary['baseline_resolved_original_oracles']} of the original {summary['original_open_oracles']} open oracle expectations, and new evidence resolves {summary['newly_resolved_original_oracles']}; **{summary['remaining_original_open_oracles']} remain open**.",
                    f"Die aktuelle vollständige Qualifikation umfasst **{qualified}/140 ursprüngliche IDs**: **{summary['full_lifecycle_pass']} PASS** und **{summary['full_lifecycle_fail']} FAIL**. **{remaining} IDs** haben weiterhin keine vollständige Lifecycle-Qualifikation. Die Basisqualifikation löste {summary['baseline_resolved_original_oracles']} der ursprünglich {summary['original_open_oracles']} offenen Oracle-Erwartungen auf, und neue Nachweise lösen {summary['newly_resolved_original_oracles']} auf; **{summary['remaining_original_open_oracles']} bleiben offen**."), "",
             JSON_FENCE, json.dumps(data["summary"], indent=2, ensure_ascii=False), "```", "",
             choose("The original 43 open oracle expectations and their baseline reconciliation remain unchanged unless an explicit reviewed addition resolves them. A source interpretation alone does not fabricate a new successful host request.",
                    "Die ursprünglich 43 offenen Oracle-Erwartungen und ihre Basisabstimmung bleiben ohne explizite geprüfte Ergänzung unverändert. Eine Quellinterpretation allein erzeugt keinen neuen erfolgreichen Hostrequest."), "",
             choose("## Historical evidence and oracle semantics", "## Historische Nachweise und Oracle-Semantik"), "",
             choose("The historical 60-case batches retain 57 harness-reported passes, two configuration failures and one stale log oracle; those harness passes are not full lifecycle qualification. Fixture/oracle failures remain separate from real host execution and production defects. The original 42 native and 14 canonical executions retain their original revisions: host baseline `3a1bafecd0c38ccf20427d580c767ed42addf4aa`, product contract `a9d48bb58aa948aea7d79e20cdf09d3f239b7808`. The 31 derived rows, aliases and reused YAML files are not independent additional requests.",
                    "Die historischen 60-Fall-Batches behalten 57 vom Harness gemeldete bestandene Fälle, zwei Konfigurationsfehler und ein veraltetes Log-Oracle; diese Harness-Ergebnisse sind keine vollständige Lifecycle-Qualifikation. Fixture-/Oraclefehler bleiben von echten Hostausführungen und Produktfehlern getrennt. Die ursprünglichen 42 nativen und 14 kanonischen Ausführungen behalten ihre ursprünglichen Revisionen: Hostbasis `3a1bafecd0c38ccf20427d580c767ed42addf4aa`, Produktvertrag `a9d48bb58aa948aea7d79e20cdf09d3f239b7808`. Die 31 abgeleiteten Zeilen, Aliase und wiederverwendeten YAML-Dateien sind keine unabhängigen zusätzlichen Requests."), "",
             choose("Technical mapper failure maps to HTTP 500; genuinely invalid client headers map to HTTP 400. Native override, P1 and P2 expectations require actual selected source/host binding; conflicting original P2 expectations cannot be silently relabeled to the observed P1 denial. SDK 3.0.14 MIME fixture09 retains its MIME-list semantics without an invented `Clear` reset; separately measured fixture08 does not replace fixture09.",
                    "Technischer Mapperfehler ergibt HTTP 500; tatsächlich ungültige Clientheader ergeben HTTP 400. Native-Override-, P1- und P2-Erwartungen erfordern die tatsächliche ausgewählte Quell-/Hostbindung; widersprüchliche ursprüngliche P2-Erwartungen dürfen nicht stillschweigend zur beobachteten P1-Ablehnung umetikettiert werden. Die SDK-3.0.14-MIME-Fixture09 behält ihre MIME-Listensemantik ohne erfundenen `Clear`-Reset; separat gemessene Fixture08 ersetzt Fixture09 nicht."), "",
             choose("The body-null mapper fixture reaches the technical validation in P1 although its original selected oracle requires P2. Its HTTP 500 regression proves the repaired status mapping; it does not satisfy that original phase contract. The separately reproduced `NEED-request-empty` failure is a production defect: NGINX supplies a valid empty terminal buffer with null `pos`/`last`, and the connector rejects it as an invalid request body buffer range before P2. The ordinary module and the observed module reproduce this behavior. The productive correction belongs separately to #382.",
                    "Die Body-Null-Mapper-Fixture erreicht die technische Validierung in P1, obwohl ihr ursprüngliches ausgewähltes Oracle P2 verlangt. Ihre HTTP-500-Regression belegt die reparierte Statuszuordnung; sie erfüllt diesen ursprünglichen Phasenvertrag nicht. Der separat reproduzierte Fehler `NEED-request-empty` ist ein Produktfehler: NGINX liefert einen gültigen leeren Terminalbuffer mit Nullzeigern für `pos`/`last`, den der Connector vor P2 als ungültigen Requestbody-Bufferbereich ablehnt. Reguläres und beobachtetes Modul reproduzieren dieses Verhalten. Die produktive Korrektur gehört separat zu #382."), "",
             choose("Reviewed oracle corrections distinguish pre-commit P1 timeout (HTTP 504), post-commit P4 timeout (visible HTTP 200 with an aborted body), and native response-body Reject after commit (visible HTTP 200 with incomplete framing). These outcomes carry no invented rule match. Native invalid-return injection remains separate from an SDK rule intervention. ProcessPartial and Reject are judged from native returns and physical events for the selected request.",
                    "Geprüfte Oracle-Korrekturen unterscheiden P1-Timeout vor Commit (HTTP 504), P4-Timeout nach Commit (sichtbares HTTP 200 mit abgebrochenem Body) und natives Responsebody-Reject nach Commit (sichtbares HTTP 200 mit unvollständigem Framing). Diesen Ergebnissen wird kein erfundener Regelmatch zugeordnet. Native Invalid-Return-Injektion bleibt von einer SDK-Regelintervention getrennt. ProcessPartial und Reject werden anhand nativer Rückgaben und physischer Events des ausgewählten Requests beurteilt."), "",
             choose("The original mandatory event fields remain unchanged by those corrections. `phase4_body_reject` passes with its original required fields. Both timeout cases are fully observed FAIL: the original `run_id`, `transport_case_id` and `connection_id` event metadata are absent. Together with the body-null P2 fixture conflict and `NEED-request-empty`, these are the four qualified FAIL outcomes; only the empty-request case is classified here as a confirmed production defect. The request ProcessPartial case records two native append returns of 0 followed by native request-body processing return 1; a zero append return is not itself EOS.",
                    "Die ursprünglichen verpflichtenden Eventfelder bleiben durch diese Korrekturen unverändert. `phase4_body_reject` besteht mit seinen ursprünglich verlangten Feldern. Beide Timeoutfälle sind vollständig beobachtete FAIL: Die ursprünglichen Eventmetadaten `run_id`, `transport_case_id` und `connection_id` fehlen. Zusammen mit dem Body-Null-P2-Fixturekonflikt und `NEED-request-empty` ergeben sich die vier qualifizierten FAIL-Ergebnisse; nur der Fall mit leerem Request wird hier als bestätigter Produktfehler eingestuft. Der Request-ProcessPartial-Fall erfasst zwei native Append-Rückgaben von 0, gefolgt von nativem Requestbody-Processing mit Rückgabe 1; eine Null-Append-Rückgabe ist selbst kein EOS."), "",
             choose("The independent SDK 3.0.14 probe measures an empty MIME set for `Clear` followed by add in one load, one entry for add alone, and an empty set for add followed by `Clear`. Fixture09 deliberately omits `Clear`; its NGINX-specific MIME behavior is retained. Charset and unsupported MIME observations do not manufacture a configuration reset or a request-body MIME gate.",
                    "Der unabhängige SDK-3.0.14-Probe misst eine leere MIME-Menge für `Clear` gefolgt von Add in einem Ladevorgang, einen Eintrag für Add allein und eine leere Menge für Add gefolgt von `Clear`. Fixture09 verzichtet bewusst auf `Clear`; ihr NGINX-spezifisches MIME-Verhalten bleibt erhalten. Charset- und nicht unterstützte MIME-Beobachtungen erzeugen weder einen Konfigurationsreset noch ein Requestbody-MIME-Gate."), "",
             choose("## Physical lifecycle observations", "## Physische Lifecycle-Beobachtungen"), "",
             choose("The referenced candidate summaries retain actual Root-master/Nobody-worker identity, loaded connector/SDK mappings, client process exit/signal, exact bytes and framing, native API returns, physical events, commit ordering, finish/free and neighbor/cleanup measurements where available. Unknown measurements remain unknown. Host terminal callbacks paired with native process-body entry establish the measured EOS boundary; client EOF and zero-byte append do not establish native EOS. HTTP/1 observations do not prove HTTP/2 reset behavior.",
                    "Die referenzierten Kandidatenzusammenfassungen behalten tatsächliche Root-Master-/Nobody-Worker-Identität, geladene Connector-/SDK-Mappings, Clientprozess-Exit/Signal, exakte Bytes und Framing, native API-Rückgaben, physische Events, Commitreihenfolge, Finish/Free sowie Nachbar-/Cleanup-Messungen soweit verfügbar. Unbekannte Messungen bleiben unbekannt. Host-Terminalcallbacks zusammen mit nativem Process-Body-Eintritt belegen die gemessene EOS-Grenze; Client-EOF und Nullbyte-Append belegen kein natives EOS. HTTP/1-Beobachtungen beweisen kein HTTP/2-Resetverhalten."), ""]
    for item in data["observations"]:
        header = observation_header(item)
        lines += [JSON_FENCE, json.dumps({"input": item["input"], **header}, indent=2, ensure_ascii=False), "```", ""]
    lines += [choose("## Verification", "## Verifikation"), "",
              choose("Every check below reports its observed result, including failed setup attempts. Compiled/native/mutation checks establish their own layer and do not qualify a host lifecycle.",
                     "Jede folgende Prüfung nennt ihr beobachtetes Ergebnis einschließlich fehlgeschlagener Setupversuche. Kompilierte/native/Mutationsprüfungen belegen ihre eigene Ebene und qualifizieren keinen Host-Lifecycle."), "",
              choose("| Check | Exit | Status | Command |", "| Prüfung | Exit | Status | Befehl |"), "| --- | --- | --- | --- |"]
    append_verification(lines, data["verification"])
    lines += ["", choose("## Complete 140-ID ledger", "## Vollständiges 140-ID-Ledger"), "",
              choose(f"The [machine artifact](../{machine_path.as_posix()}) retains every original selected contract as a readable projection with its canonical full-contract hash, baseline status, new status and external raw-proof locators. Per-path source hashes stay in the externally bound baseline. The external baseline and full ledger are bound below by SHA256; heavy raw files are intentionally retained outside Git.",
                     f"Das [Maschinenartefakt](../{machine_path.as_posix()}) behält jeden ursprünglichen ausgewählten Vertrag als lesbare Projektion mit seinem kanonischen Vollvertragshash, Basisstatus, neuem Status und externen Rohbeleg-Locators. Pfadbezogene Quellhashes bleiben in der extern gebundenen Basis. Externe Basis und vollständiges Ledger sind unten durch SHA256 gebunden; schwere Rohdateien bleiben außerhalb von Git."), "",
              JSON_FENCE, json.dumps(data["inputs"], indent=2), "```", "",
              choose("### Qualified original IDs", "### Qualifizierte ursprüngliche IDs"), "",
              choose("Each row below is one original selected ID. Packet hashes and independent request identities are retained in the machine artifact; a retest of an already qualified ID does not add another original requirement.",
                     "Jede folgende Zeile ist eine ursprüngliche ausgewählte ID. Pakethashes und unabhängige Requestidentitäten stehen im Maschinenartefakt; der erneute Test einer bereits qualifizierten ID fügt keine weitere ursprüngliche Anforderung hinzu."), "",
              choose("| Original ID | Baseline | Current |", "| Ursprüngliche ID | Basis | Aktuell |"),
              "| --- | --- | --- |"]
    for row in data["rows"]:
        if row["full_lifecycle_qualified"]:
            lines.append(f"| `{row['run_scoped_case_id']}` | {row['baseline_status']} | {row['new_status']} |")
    lines += ["", choose("### Original IDs still without complete lifecycle qualification",
                         "### Ursprüngliche IDs weiterhin ohne vollständige Lifecycle-Qualifikation"), "",
              choose("The ten historical configuration PASS results remain configuration evidence. The unresolved-oracle column identifies original open expectations that still lack a resolved reviewed oracle; other rows may have a known oracle but incomplete physical proof. Gap reasons reproduce the canonical hash-bound mapping verbatim.",
                     "Die zehn historischen Konfigurations-PASS bleiben Konfigurationsnachweise. Die Spalte für offene Oracles kennzeichnet ursprünglich offene Erwartungen ohne aufgelöstes geprüftes Oracle; andere Zeilen können ein bekanntes Oracle, aber unvollständige physische Belege besitzen. Die englischen Lückenbegründungen geben die kanonische hashgebundene Zuordnung unverändert wieder."), "",
              choose("| Original ID | Current | Original oracle still open | Remaining evidence |",
                     "| Ursprüngliche ID | Aktuell | Ursprüngliches Oracle weiterhin offen | Fehlender Nachweis |"),
              "| --- | --- | --- | --- |"]
    for row in data["rows"]:
        if not row["full_lifecycle_qualified"]:
            review = row["new_oracle_review"] or {}
            unresolved = row["original_oracle_unresolved"] and not review.get("resolved")
            gap = str(row["remaining_gap"]).replace("|", "&#124;").replace("\n", " ")
            lines.append(f"| `{row['run_scoped_case_id']}` | {row['new_status']} | {str(unresolved).lower()} | {gap} |")
    lines += ["", choose("## Remaining work and risks", "## Verbleibende Arbeit und Risiken"), "",
              choose("Every unqualified row still needs the specific physical evidence listed above. Only the nine remaining open oracle expectations additionally need a resolved reviewed oracle. Native Reject/ProcessPartial limits, memory/file buffers, MIME/charset, P1–P4, pre/post-commit technical failures, P4 Safe/supported Strict, empty/single/multipart bodies and exactly-once EOS must be judged per original ID, never inferred from another case. The pre-existing release secret blocker remains unresolved. Any confirmed production correction belongs separately to #382. This change does not authorize a product fix, master merge or release.",
                     "Jede unqualifizierte Zeile benötigt weiterhin die oben konkret genannten physischen Nachweise. Nur die neun weiterhin offenen Oracle-Erwartungen benötigen zusätzlich ein aufgelöstes geprüftes Oracle. Native Reject-/ProcessPartial-Grenzen, Speicher-/Dateibuffer, MIME/Charset, P1–P4, technische Fehler vor/nach Commit, P4 Safe/unterstütztes Strict, leere/einzelne/mehrteilige Bodys und genau einmal EOS sind je ursprünglicher ID zu beurteilen und dürfen nie aus einem anderen Fall abgeleitet werden. Der bestehende Release-Secret-Blocker bleibt ungelöst. Jede bestätigte Produktkorrektur gehört separat zu #382. Diese Änderung autorisiert keinen Produktfix, Master-Merge oder Release."), "",
              choose("See the concise [PR #410 closeout](pr-410-i12-closeout-20261024.md).",
                     "Siehe den kompakten [Abschluss von PR #410](pr-410-i12-closeout-20261024.de.md)."), ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--observations", type=Path, action="append", default=[])
    parser.add_argument("--verification", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report-prefix", type=Path, required=True)
    args = parser.parse_args()
    args.ledger = evidence_path(args.ledger)
    args.observations = [evidence_path(path) for path in args.observations]
    args.verification = [evidence_path(path) for path in args.verification]
    # CLI destinations are assertions of the fixed publication contract. Never
    # carry a caller-supplied path to a write, even after checking equality.
    output_path(args.output, "ci/runtime/lifecycle/i12/nginx/evidence-20261015.json")
    machine = REPOSITORY_ROOT / "ci/runtime/lifecycle/i12/nginx/evidence-20261015.json"
    reports = [(False, REPOSITORY_ROOT / "docs/pr-410-i12-nginx-evidence-20261015.md"),
               (True, REPOSITORY_ROOT / "docs/pr-410-i12-nginx-evidence-20261015.de.md")]
    for german, destination in reports:
        suffix = ".de.md" if german else ".md"
        output_path(Path(str(args.report_prefix) + suffix), str(destination.relative_to(REPOSITORY_ROOT)))
    data = compact(read(args.ledger), args.ledger, args.observations, args.verification)
    machine.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for german, path in reports:
        path.write_text(report(data, machine.relative_to(REPOSITORY_ROOT), german), encoding="utf-8")


if __name__ == "__main__":
    main()
