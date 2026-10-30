#!/usr/bin/env python3
"""Render checked I12 ledgers without creating or transferring qualification."""
from modsecurity_test_framework.connector_context import load_source

import argparse
import collections
import hashlib
import importlib.util
import json
from pathlib import Path


def sibling(name):
    module = load_source(Path(__file__).with_name(name + '.py'))
    return module


ORACLES = sibling("generate-pr382-i12-oracle-reconciliation")
PATHS = ORACLES.PATHS
HOST_LEDGER = sibling("generate-pr382-i12-lifecycle-ledger")
HOST_STEM = "pr-382-i12-host-evidence-20261014"
INDEX_STEM = "pr-382-i12-missing-case-index-20261014"
HISTORICAL_REQUIREMENTS_SHA256 = "a0d47b8e1f89ff6e1f7289be7e618e68224b0a5034b59d58bd02eb5c8f60a9da"
SUMMARY_FIELDS = (
    "original_ids", "actually_executed_ids", "configuration_only_pass",
    "full_lifecycle_pass", "full_lifecycle_fail", "required_full_lifecycle_pass",
    "required_full_lifecycle_fail", "required_qualified_pass", "required_qualified_fail",
    "required_routes_with_full_case", "unqualified_ids",
)
JSON_FENCE = "```json\n"


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def historical_catalog(reconciliation):
    """Bind legacy results to their physical original requirements, not row labels."""
    inputs = reconciliation.get("input_evidence", [])
    if len(inputs) < 2:
        raise ValueError("Original historical requirements and selection evidence are missing")
    requirements_ref, selection_ref = (ORACLES.verify_reference(ref) for ref in inputs[:2])
    if (requirements_ref["sha256"] != HISTORICAL_REQUIREMENTS_SHA256 or
            selection_ref["sha256"] != ORACLES.SELECTION_SHA256):
        raise ValueError("Original historical requirements or selection bytes changed")
    original = ORACLES.original_contracts(
        json.loads(PATHS.read_text(requirements_ref["path"])),
        json.loads(PATHS.read_text(selection_ref["path"])))
    summary = reconciliation["summary"]
    if (summary["baseline_config_parser_pass"] != sum(row["status"] == "PASS" for row in original) or
            summary["baseline_observed_ids"] != sum(row["execution_observed"] is True for row in original)):
        raise ValueError("Historical counters differ from original physical evidence")
    return {row["run_scoped_case_id"]: row for row in original}


def validate(ledger, reconciliation, source_status):
    """Validate supplied identities and counts; never assign a result to a row."""
    if ledger.get("schema_version") != 1 or reconciliation.get("schema_version") != 1:
        raise ValueError("Unsupported ledger or reconciliation schema")
    if source_status.get("i12_status") not in {
        "I12_PARTIAL", "I12_BLOCKED", "I12_COMPLETE", "I12_HOST_EVIDENCE_COMPLETE_RELEASE_BLOCKED"
    }:
        raise ValueError("Source status must explicitly supply i12_status")
    rows = ledger["rows"]
    ids = [row["run_scoped_case_id"] for row in rows]
    digest = hashlib.sha256(("\n".join(ids) + "\n").encode()).hexdigest()
    contracts = [row["selected_requirement"] for row in rows]
    if len(ids) != 1484 or len(set(ids)) != 1484 or digest != ORACLES.ID_SHA256:
        raise ValueError("Original ordered ID stream changed")
    if ORACLES.canonical_digest(contracts) != ORACLES.CONTRACT_SHA256:
        raise ValueError("Original selected contracts changed")
    for data in (ledger, reconciliation):
        if (data["original_ordered_id_sha256"] != digest or
                data["original_selected_contract_sha256"] != ORACLES.CONTRACT_SHA256):
            raise ValueError("Original contract identity mismatch")
    if reconciliation["original_selected_contracts"] != contracts:
        raise ValueError("Reconciliation original order differs")
    required = sum(row["required_leg"] is True for row in rows)
    if required != 1406 or any(type(row["required_leg"]) is not bool for row in rows):
        raise ValueError("Original required membership changed")
    if len({row["leg_id"] for row in rows if row["required_leg"]}) != 13:
        raise ValueError("Required routes must remain separate")
    reviews = {item['run_scoped_case_id']:item for item in
               reconciliation['oracle_matrix'] + reconciliation['supplemental_dispositions']}
    historical = historical_catalog(reconciliation)
    for row in rows:
        validate_row(row, reviews, historical)
    validate_summary(ledger, reconciliation, source_status)


def validate_row(row, reviews, historical):
    identity, leg = row["run_scoped_case_id"], row["leg_id"]
    if identity.split("::")[1] != leg or row["selected_requirement"]["run_scoped_case_id"] != identity:
        raise ValueError("Original case or route identity mismatch")
    if row['oracle_reconciliation'] != reviews.get(identity):
        raise ValueError('Row oracle review differs from reconciliation')
    legacy = historical[identity]
    if (row["required_leg"] is not legacy["required_leg"] or
            row["historical_status"] != legacy["status"] or
            row["historical_execution_observed"] is not legacy["execution_observed"]):
        raise ValueError("Row history differs from original physical evidence")
    packet = row["current_lifecycle_packet"]
    full = row["qualification_scope"] == "full_host_lifecycle"
    if row["qualified_host_lifecycle_pass"] is not (full and row["status"] == "PASS"):
        raise ValueError("Configuration PASS cannot become lifecycle PASS")
    if packet is None:
        if full:
            raise ValueError("Full lifecycle requires a physical packet")
        expected_scope = "historical_configuration_only" if legacy["status"] == "PASS" else None
        if (row["status"] != legacy["status"] or
                row["execution_observed"] is not legacy["execution_observed"] or
                row["qualification_scope"] != expected_scope):
            raise ValueError("A row without a packet must preserve its historical result and scope")
        return
    validate_packet(row, packet, full)


def validate_packet_observations(row, packet, full):
    unknown = [field for field, item in packet["observations"].items()
               if item.get("applicable", True) and item.get("value") is None]
    if unknown != packet["unknown_fields"] or (full and unknown):
        raise ValueError("Unknown observation cannot become full qualification")
    if full and packet["outcome"] != row["status"]:
        raise ValueError("Full result lacks explicit oracle evaluation")


def validate_packet(row, packet, full):
    oracle = (row['oracle_reconciliation']['effective_oracle'] if row['oracle_reconciliation']
              else row['selected_requirement']['expected_oracle'])
    if oracle and oracle.get('unresolved_expected_value_reason'):
        oracle = None
    checked = HOST_LEDGER.reviewed_packet(packet['receipt'],row,oracle)
    if checked != packet:
        raise ValueError('Ledger observations or qualification differ from physical Root packet')
    if packet["full_lifecycle_qualified"] is not full:
        raise ValueError("Packet qualification differs from supplied row")
    if row["execution_observed"] is not True:
        raise ValueError("A physical host packet requires observed row execution")
    if not full and (row["status"] != "PARTIAL_HOST_MEASUREMENTS" or row["qualification_scope"] is not None):
        raise ValueError("An incomplete packet requires partial status and no qualification scope")
    validate_packet_observations(row, packet, full)
    for item in packet["observations"].values():
        for evidence in item.get("evidence", []) + item.get("capability_proof", []):
            ORACLES.verify_reference(evidence)


def validate_summary(ledger, reconciliation, source_status):
    rows = ledger["rows"]
    summary = ledger["summary"]
    full_rows = [row for row in rows if row["qualification_scope"] == "full_host_lifecycle"]
    expected = {
        "original_ids": len(rows),
        "actually_executed_ids": sum(row["execution_observed"] is True for row in rows),
        "configuration_only_pass": sum(row["qualification_scope"] == "historical_configuration_only" for row in rows),
        "full_lifecycle_pass": sum(row["status"] == "PASS" for row in full_rows),
        "full_lifecycle_fail": sum(row["status"] == "FAIL" for row in full_rows),
        "required_full_lifecycle_pass": sum(row["required_leg"] and row["status"] == "PASS" for row in full_rows),
        "required_full_lifecycle_fail": sum(row["required_leg"] and row["status"] == "FAIL" for row in full_rows),
        "required_qualified_pass": sum(row["required_leg"] and row["status"] == "PASS" for row in rows),
        "required_qualified_fail": sum(row["required_leg"] and row["status"] == "FAIL" for row in rows),
        "required_routes_with_full_case": len({row["leg_id"] for row in full_rows if row["required_leg"] and row["status"] == "PASS"}),
        "unqualified_ids": sum(row["qualification_scope"] is None for row in rows),
    }
    if any(type(summary[key]) is not int or summary[key] != expected[key] for key in SUMMARY_FIELDS):
        raise ValueError("Supplied ledger summary differs from rows")
    if summary["oracle_counts"] != reconciliation["summary"]:
        raise ValueError("Oracle summary differs between inputs")
    if (source_status['i12_status'] in ('I12_COMPLETE','I12_HOST_EVIDENCE_COMPLETE_RELEASE_BLOCKED') and
            (summary['required_qualified_pass'] != 1406 or summary['required_routes_with_full_case'] != 13)):
        raise ValueError('Complete status requires all1406 required PASS and all13 routes')
    oracle_summary = reconciliation["summary"]
    if (oracle_summary["original_open_oracles"] != 596 or
            oracle_summary["resolved_original_oracles"] + oracle_summary["unresolved_original_oracles"] != 596):
        raise ValueError("Original 596 oracle inventory changed")


def source_links(references):
    lines = []
    for name, ref in references.items():
        target = (f"`{ref['path']}`" if Path(ref["path"]).is_absolute()
                  else f"[{name}]({ref['path']})")
        lines.append(f"- {name}: {target} — SHA256 `{ref['sha256']}`.")
    return "\n".join(lines)


def route_table(rows, required, german):
    result = ["| Route | IDs | Executed | Config PASS | Lifecycle PASS | Lifecycle FAIL | Unqualified |",
              "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    groups = collections.defaultdict(list)
    for row in rows:
        if row["required_leg"] is required:
            groups[row["leg_id"]].append(row)
    for leg, members in groups.items():
        values = [len(members), sum(r["execution_observed"] is True for r in members),
                  sum(r["qualification_scope"] == "historical_configuration_only" for r in members),
                  sum(r["qualified_host_lifecycle_pass"] for r in members),
                  sum(r["qualification_scope"] == "full_host_lifecycle" and r["status"] == "FAIL" for r in members),
                  sum(r["qualification_scope"] is None for r in members)]
        result.append("| " + leg + " | " + " | ".join(str(n) for n in values) + " |")
    if german:
        result[0] = "| Route | IDs | Ausgeführt | Config PASS | Lifecycle PASS | Lifecycle FAIL | Unqualifiziert |"
    return "\n".join(result)


def packet_sections(ledger):
    blocks = []
    for row in ledger['rows']:
        packet = row['current_lifecycle_packet']
        if packet is not None:
            selected = {k:packet['observations'].get(k) for k in (
                'product_host_identity','source_config_binding','host_eos','native_eos',
                'finish_calls','native_free_calls','cleanup_receipts')}
            raw = json.loads(PATHS.read_text(packet['receipt']['path']))
            identity = {key:raw.get(key) for key in (
                'run_id','parent_sha','framework_sha','mrts_sha','product_contract_sha',
                'effective_config_sha256','rules_sha256')}
            blocks += [f"### {row['run_scoped_case_id']}", JSON_FENCE+json.dumps({'receipt':packet['receipt'],
                'packet_identity':identity,'status':row['status'],'qualification_scope':row['qualification_scope'],
                'unknown_fields':packet['unknown_fields'],'observations':selected},
                ensure_ascii=False,indent=2,sort_keys=True)+"\n```"]
    return blocks


def index_lines(ledger):
    index_rows = []
    for row in ledger['rows']:
        packet = row['current_lifecycle_packet']
        review = row['oracle_reconciliation']
        index_rows.append("\t".join((row['run_scoped_case_id'], 'status='+row['status'], 'execution_observed='+encoded(row['execution_observed']),
                     'qualification_scope='+encoded(row['qualification_scope']), 'required_leg='+encoded(row['required_leg']),
                     'original_oracle='+encoded(row['selected_requirement']['expected_oracle']),
                     'oracle_category='+encoded(review['category'] if review else None),
                     'packet='+encoded(packet['receipt'] if packet else None), 'unknown_fields='+encoded(packet['unknown_fields'] if packet else None))))
    return index_rows


def render_context(german):
    suffix = ".de.md" if german else ".md"
    title = "I12 aktuelle Host-Evidenz" if german else "I12 current host evidence"
    intro = ("Die folgenden Zahlen stammen aus dem geprüften aktuellen Ledger. Konfigurations-PASS und vollständige Host-Lifecycle-Abnahme bleiben getrennt."
             if german else "The following counts come from the checked current ledger. Configuration PASS and full host lifecycle qualification remain separate.")
    historical_note = ("Die verlinkten unveränderten Berichte dokumentieren den historischen Stand. Ihre CI-/Sonar-Ergebnisse gelten nur für den dort bezeichneten alten Head."
                       if german else "The linked unchanged reports preserve the historical checkpoint. Their CI/Sonar results apply only to the old head named there.")
    language = (f"**Sprache:** [English]({HOST_STEM}.md) | Deutsch" if german
                else f"**Language:** English | [Deutsch]({HOST_STEM}.de.md)")
    return suffix, title, intro, historical_note, language


def render(ledger, reconciliation, source_status, references, historical, german=False):
    validate(ledger, reconciliation, source_status)
    suffix, title, intro, historical_note, language = render_context(german)
    historical = {name: ref for name, ref in historical.items()
                  if name.endswith('-de' if german else '-en')}
    host = [f"# {title}", language, f"Status: **{source_status['i12_status']}**.", intro,
            "## " + ("Aktuelle Zähler" if german else "Current counts"), JSON_FENCE+json.dumps(ledger['summary'],indent=2,ensure_ascii=False,sort_keys=True)+"\n```",
            "## " + ("13 Pflichtrouten" if german else "13 required routes"), route_table(ledger['rows'], True, german),
            "## " + ("Getrennte diagnostische Kontrolle" if german else "Separate diagnostic control"), route_table(ledger['rows'], False, german),
            "## " + ("Aktueller Quellen-, CI- und Release-Stand" if german else "Current source, CI and release checkpoint"),
            JSON_FENCE+json.dumps(source_status,indent=2,ensure_ascii=False,sort_keys=True)+"\n```",
            "## " + ("Physische Lifecycle-Pakete" if german else "Physical lifecycle packets")]
    host += packet_sections(ledger)
    host += ["## " + ("Geprüfte Eingabequellen" if german else "Checked input sources"), source_links(references),
             "## " + ("Unveränderte historische Quellen" if german else "Unchanged historical sources"), historical_note, source_links(historical),
             f"[{'Vollständiger geordneter Index' if german else 'Complete ordered index'}]({INDEX_STEM}{suffix})."]
    index_language = (f"**Sprache:** [English]({INDEX_STEM}.md) | Deutsch" if german
                      else f"**Language:** English | [Deutsch]({INDEX_STEM}.de.md)")
    index_header = ["# " + ("I12 Index aller ausgewählten Fälle" if german else "I12 index of all selected cases"),
             index_language, f"Status: **{source_status['i12_status']}**.",
             f"Ordered ID stream SHA256: `{ledger['original_ordered_id_sha256']}`.",
             f"Original selected contract SHA256: `{ledger['original_selected_contract_sha256']}`.",
             f"[{title}]({HOST_STEM}{suffix})."]
    index_rows = index_lines(ledger)
    index = '\n\n'.join(index_header) + '\n\n```text\n' + '\n'.join(index_rows) + '\n```\n\n'
    index += historical_note + '\n\n' + source_links(historical) + '\n'
    return '\n\n'.join(host)+'\n', index


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('ledger','reconciliation','source-status','historical-host-en','historical-host-de','historical-index-en','historical-index-de','output-dir'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    args.output_dir = PATHS.output_path(args.output_dir)
    references = {name:ORACLES.reference(getattr(args,name.replace('-','_')).absolute()) for name in ('ledger','reconciliation','source-status')}
    ledger, reconciliation, status = (json.loads(PATHS.read_text(ref['path'])) for ref in references.values())
    history_sources = {name:ORACLES.reference(getattr(args,name.replace('-','_')).absolute()) for name in ('historical-host-en','historical-host-de','historical-index-en','historical-index-de')}
    historical = {name:{**ref,'path':'history/'+Path(ref['path']).name} for name,ref in history_sources.items()}
    validate(ledger,reconciliation,status)
    outputs = {}
    for german in (False,True):
        host,index = render(ledger,reconciliation,status,references,historical,german)
        suffix = '.de.md' if german else '.md'
        outputs[HOST_STEM+suffix],outputs[INDEX_STEM+suffix] = host.encode(),index.encode()
    for ref in history_sources.values():
        relative='history/'+Path(ref['path']).name
        if relative in outputs:
            raise ValueError('Historical source filenames must be distinct')
        outputs[relative]=PATHS.read_bytes(ref['path'])
    if any((args.output_dir/name).exists() for name in outputs):
        raise ValueError('Output already exists; preserve prior reports')
    for name,data in outputs.items():
        target=args.output_dir/name
        ORACLES.ensure_output_directory(target.parent)
        PATHS.create_bytes(target, data)


if __name__ == '__main__':
    main()
