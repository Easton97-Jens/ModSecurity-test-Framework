"""Unsigned Apache control inventory and explicit, validator-gated publication.

Captures do not authorize their own expectations. An approval file is a separate
Root review decision, bound to the exact candidate digest, original contract and
fully assembled packet. This tool never writes a Root decision on the caller's
behalf. Raw captures are retained even when dedicated producer receipts are absent.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile


def load_review():
    module = load_source(source_path('ci/runtime/lifecycle/apache-i12') / 'review.py')
    return module


REVIEW = load_review()
SHARED = REVIEW.LEDGER.SHARED
ORACLES = REVIEW.ORACLES
PATHS = REVIEW.LEDGER.PATHS
PRE_NATIVE_CASES = frozenset(SHARED.PRE_NATIVE_MAPPING)
OBSERVATION_FILE = 'observation.json'
CONFIG_ROLES = frozenset(('parser_process', 'source_manifest', 'effective_configuration',
    'invoked_image', 'cleanup_observer', 'isolation_receipt', 'native_module',
    'parser_stdout', 'parser_stderr', 'expectation_source'))
CONFIG_PRODUCERS = {'parser_process': 'configtest-process.json',
    'effective_configuration': 'httpd.conf', 'rules_file': 'rules.conf',
    'parser_stdout': 'configtest.stdout', 'parser_stderr': 'configtest.stderr',
    'cleanup_observer': 'configtest-cleanup.json', 'rules_absence': 'rules-absence.json'}
PRE_NATIVE_PRODUCERS = {'client_process': 'main/process.command.json',
    'client_receipt': 'main/receipt.json', 'request_wire': 'main/request.raw',
    'response_wire': 'main/response.raw', 'native_api': 'native-api.jsonl',
    'host_callback': 'host-eos.jsonl', 'backend_process': 'backend/requests.jsonl',
    'core_diagnostic': 'error.log', 'driver_observation': OBSERVATION_FILE,
    'effective_configuration': 'httpd.conf', 'rules_file': 'rules.conf'}
# Only these contract-defined producers are JSON documents. Inspecting their
# references never admits new files: every dependency must already be explicit
# in the hash-bound candidate or the separate supplemental review inventory.
CONFIG_JSON_PRODUCERS = frozenset(('parser_process', 'source_manifest', 'cleanup_observer'))
PRE_NATIVE_JSON_PRODUCERS = frozenset(('client_process', 'client_receipt', 'source_manifest',
    'isolation_receipt', 'event_observer', 'cleanup_observer', 'healthy_controls', 'driver_observation'))
EXCLUDED_ORACLE_BRANCHES = frozenset(('retest', 'applicability_receipt', 'expected_absence',
                                     'expected_absence_approval', 'visible_status_absence'))


def existing_references(root, mapping):
    """Roles here identify candidate producers, not their qualification."""
    return [REVIEW.reference(root / name, role) for role, name in mapping.items()
            if (root / name).is_file()]


def json_if_present(path):
    return REVIEW.read(path) if path.is_file() else None


def control_producers(root, configuration):
    evidence = existing_references(root, CONFIG_PRODUCERS if configuration else PRE_NATIVE_PRODUCERS)
    dedicated = {'source_manifest': 'source-manifest.json', 'isolation_receipt': 'isolation-receipt.json',
                 'native_module': 'native-module.so', 'invoked_image': 'invoked-image'}
    if not configuration:
        dedicated = {'source_manifest': 'source-manifest.json', 'isolation_receipt': 'isolation-receipt.json',
            'event_observer': 'event-observer.json', 'cleanup_observer': 'cleanup-observer.json',
            'healthy_controls': 'healthy-controls.json', 'loaded_image': 'loaded-image',
            'native_module': 'native-module.so', 'observer_image': 'observer-image.so'}
    return evidence + existing_references(root, dedicated)


def control_observations(root, plan, observed, configuration):
    physical = {'driver_observation': observed}
    if configuration:
        physical['parser_process'] = json_if_present(root / 'configtest-process.json')
        physical['cleanup'] = json_if_present(root / 'configtest-cleanup.json')
        physical['legacy_parser_command'] = json_if_present(root / 'configtest.command.json')
        return physical, None, []  # A controller run is not a parser identity.
    physical['client_process'] = json_if_present(root / 'main/process.command.json')
    physical['client_receipt'] = json_if_present(root / 'main/receipt.json')
    native_path = root / 'native-api.jsonl'
    native = REVIEW.json_lines(native_path) if native_path.is_file() else []
    admissions = [row for row in native if row.get('function') == 'observer'
                  and row.get('edge') == 'admitted' and row.get('profile') == 'apache-native'
                  and row.get('case') == plan['case_id']]
    identity = admissions[0] if len(admissions) == 1 else {}
    physical.update(native_observer_admission=admissions, host_pid=identity.get('pid'), uid=identity.get('uid'))
    missing = [] if identity.get('run') else ['identity:unique_physical_native_observer_admission']
    return physical, identity.get('run'), missing


def candidate(plan, root, attempt, spec_path, bindings, controller):
    """Extract controls without a native-main association or oracle evaluation."""
    configuration = plan['execution_kind'] == 'configtest'
    if not configuration and plan['case_id'] not in PRE_NATIVE_CASES:
        raise ValueError('Only original Apache parser controls have this review scope')
    observation_path = root / OBSERVATION_FILE
    observed = REVIEW.read(observation_path)
    if observed.get('original_id') != plan['original_id'] or observed.get('case_id') != plan['case_id']:
        raise ValueError('Physical control identity differs from the selected original ID')
    scope = 'configuration_control' if configuration else 'host_pre_native_rejection'
    # Dedicated receipts can be supplied by an existing producer. Their mere
    # presence is never treated as proof that the shared producer contract holds.
    evidence = control_producers(root, configuration)
    captures = existing_references(root, {'driver_observation': OBSERVATION_FILE,
        'parser_command': 'configtest.command.json', 'settings': 'settings.json',
        'host_io': 'host-io.jsonl', 'event_sink': 'events.jsonl',
        'process_observer': 'process-snapshots.jsonl', 'host_cleanup': 'host-cleanup.json',
        'before_client': 'precontrol/receipt.json', 'before_process': 'precontrol/process.command.json',
        'after_client': 'neighbor/receipt.json', 'after_process': 'neighbor/process.command.json'})
    captures.extend(existing_references(root.parent, {'admission': 'admission.json',
                                                     'binary_identity': 'binary-identity.json'}))
    captures.extend([REVIEW.reference(spec_path, 'admission_spec'),
                     REVIEW.reference(attempt / 'controller-result.json', 'controller_result')])
    for item in bindings.values():
        captures.append(REVIEW.reference(Path(item['ledger']), 'sealed_binding_ledger'))
    roles = SHARED.PRE_NATIVE_ROLES
    if configuration:
        rules_role = 'rules_absence' if any(e['role'] == 'rules_absence' for e in evidence) else 'rules_file'
        roles = CONFIG_ROLES | {rules_role}
    missing = ['producer:' + role for role in sorted(roles - {e['role'] for e in evidence})]
    missing.extend(('independent_original_oracle_review', 'explicit_root_packet_review',
                    'shared_control_validator_qualification'))
    physical, run_id, identity_missing = control_observations(root, plan, observed, configuration)
    missing.extend(identity_missing)
    return {'run_scoped_case_id': plan['original_id'], 'leg_id': 'apache-native',
        'actual_scenario_variant': plan['case_id'], 'original_selected_requirement': plan['original_contract'],
        'execution_kind': 'configuration_parser' if configuration else 'host_pre_native_rejection',
        'control_scope': scope, 'execution_observed': observed.get(
            'actual_config_execution' if configuration else 'actual_principal_execution') is True,
        'run_id': run_id, 'native_transaction_id': None, 'unsigned': True, 'reviewed_by': None,
        'candidate_is_not_an_approval': True, 'oracle_evaluated': False, 'oracle_sha256': None,
        'outcome': None, 'full_lifecycle_qualified': False, 'full_case_qualified': False,
        'role_evidence': evidence, 'physical_captures': captures, 'physical_observations': physical,
        'missing_requirements': missing,
        'producer_presence_is_not_qualification': True,
        'actual_admitted_spec_sha256': controller['spec_sha256']}


def references_in(value):
    """Enumerate nested physical references, preserving supplemental source proof."""
    if isinstance(value, dict):
        if 'path' in value and 'sha256' in value:
            yield value
        # A reference-shaped wrapper cannot conceal nested packet evidence.
        for item in value.values():
            yield from references_in(item)
    elif isinstance(value, list):
        for item in value:
            yield from references_in(item)


def read_candidate(path):
    """Accept a standalone control or its unchanged review_batch wrapper."""
    outer = REVIEW.read(path)
    selected = outer.get('control_candidate', outer)
    if (selected.get('run_scoped_case_id') != outer.get('run_scoped_case_id')
            or selected.get('leg_id') != outer.get('leg_id') or outer.get('unsigned') is not True):
        raise ValueError('Batch wrapper differs from its unsigned control identity')
    return selected


def verify_approval(candidate_path, selected, approval, row):
    bound = ORACLES.verify_reference(approval.get('candidate', {}))
    if bound['path'] != str(candidate_path) or bound['sha256'] != ORACLES.reference(candidate_path)['sha256']:
        raise ValueError('Approval does not bind the exact physical candidate')
    if (approval.get('reviewed_by') != 'root' or not isinstance(approval.get('reason'), str)
            or not approval['reason'].strip() or selected.get('unsigned') is not True):
        raise ValueError('Explicit separate Root approval of the unsigned candidate is required')
    packet = copy.deepcopy(approval['packet'])
    if (row['leg_id'] != 'apache-native' or selected['leg_id'] != row['leg_id']
            or selected['run_scoped_case_id'] != row['run_scoped_case_id']
            or selected['original_selected_requirement'] != row['selected_requirement']
            or packet.get('execution_kind') != selected['execution_kind']):
        raise ValueError('Approval must preserve the original Apache control contract and scope')
    return bound, packet


def producer_references(packet):
    """Inspect the fixed producer layer; never recursively follow arbitrary files.

    The shared Apache pre-native contract dereferences maps/status from isolation,
    sink from event_observer and four client receipts from healthy_controls. All
    are visible here inside those physical JSON producers. Other reference fields
    in the same fixed producer documents also require explicit inventory. Files
    discovered here are checked, not added to the allowed set or traversed again.
    """
    roles = CONFIG_JSON_PRODUCERS
    if packet.get('execution_kind') == 'host_pre_native_rejection':
        roles = PRE_NATIVE_JSON_PRODUCERS
    for ref in packet.get('measurement_evidence', []):
        if ref.get('role') in roles:
            physical = ORACLES.verify_reference(ref)
            document = json.loads(Path(physical['path']).read_text())
            yield from references_in(document)


def verify_inventory_references(references, allowed):
    for ref in references:
        verified = ORACLES.verify_reference(ref)
        if (verified['path'], verified['sha256']) not in allowed:
            raise ValueError('Reviewed packet contains evidence absent from the explicit review inventory')


def oracle_branch_keys(value):
    """Inspect only the supplied JSON structure, never referenced source files."""
    if isinstance(value, dict):
        yield from value
        for item in value.values():
            yield from oracle_branch_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from oracle_branch_keys(item)


def validate_control_oracle_scope(record):
    """Control publication does not import runtime/applicability witness graphs.

    Oracle retests, capability applicability and absence witnesses belong to their
    existing separate review contracts. Reject their selectors even when null or
    nested under a reference-shaped wrapper; this command does not dereference or
    automatically admit any of those physical graphs.
    """
    if record is None:
        return
    if not isinstance(record, dict):
        raise ValueError('Control oracle review must be a JSON object')
    excluded = EXCLUDED_ORACLE_BRANCHES.intersection(oracle_branch_keys(record))
    if excluded or record.get('category') == 'UNSUPPORTED_CAPABILITY':
        raise ValueError('Control approval excludes Oracle retest, applicability and absence branches')


def verify_review_inventory(selected, approval, packet):
    validate_control_oracle_scope(approval.get('oracle_review'))
    allowed = set()
    for ref in [*selected.get('role_evidence', []), *selected.get('physical_captures', []),
                *approval.get('supplemental_evidence', [])]:
        verified = ORACLES.verify_reference(ref)
        allowed.add((verified['path'], verified['sha256']))
    verify_inventory_references(references_in(packet), allowed)
    verify_inventory_references(references_in(approval.get('oracle_review')), allowed)
    verify_inventory_references(producer_references(packet), allowed)


def control_validator(selected, row):
    if selected['control_scope'] == 'host_pre_native_rejection':
        if row['selected_requirement'].get('case_id') not in PRE_NATIVE_CASES:
            raise ValueError('No shared Apache pre-native contract exists for this original case')
        return SHARED.reviewed_pre_native_packet
    if selected['control_scope'] == 'configuration_control':
        return SHARED.reviewed_configuration_packet
    raise ValueError('Unsupported Apache control review scope')


def approved_packet(candidate_path, approval_path, row, output):
    """Publish a caller-approved packet only after the unchanged shared validator.

    The approval contains reviewed_by=root, candidate=<physical reference>,
    reason, packet=<fully reviewed packet>, supplemental_evidence=[references]
    and optionally oracle_review=<existing shared oracle review record>.
    No field of the supplied packet is filled in or approved by this function.
    """
    candidate_path, approval_path = PATHS.input_path(candidate_path), PATHS.input_path(approval_path)
    selected, approval = read_candidate(candidate_path), REVIEW.read(approval_path)
    bound, packet = verify_approval(candidate_path, selected, approval, row)
    verify_review_inventory(selected, approval, packet)
    oracle = row['selected_requirement']['expected_oracle']
    if approval.get('oracle_review') is not None:
        oracle = ORACLES.review_record(approval['oracle_review'], row)['effective_oracle']
    validator = control_validator(selected, row)
    output = PATHS.new_output(output)
    if output.exists():
        raise FileExistsError(output)
    # Validate a private temporary packet, then atomically create the destination.
    # A validation failure leaves no published reviewed packet.
    with tempfile.TemporaryDirectory(prefix='apache-control-review-', dir=output.parent) as temporary:
        staged = Path(temporary) / 'packet.json'
        staged.write_text(json.dumps(packet, indent=2) + '\n')
        staged.chmod(0o600)
        result = validator(ORACLES.reference(staged), row, oracle)
        os.link(staged, output)
    return {'reference': ORACLES.reference(output), 'qualification_scope': result['qualification_scope'],
            'outcome': result['outcome'], 'full_lifecycle_qualified': False,
            'approval': ORACLES.reference(approval_path), 'candidate': bound}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('candidate', 'approval', 'baseline', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    selected = read_candidate(args.candidate)
    rows = REVIEW.LEDGER.apache_rows(REVIEW.read(args.baseline))
    row = next((item for item in rows if item['run_scoped_case_id'] == selected['run_scoped_case_id']), None)
    if row is None:
        raise ValueError('Candidate does not belong to the immutable Apache baseline')
    print(json.dumps(approved_packet(args.candidate, args.approval, row, args.output)))


if __name__ == '__main__':
    main()
