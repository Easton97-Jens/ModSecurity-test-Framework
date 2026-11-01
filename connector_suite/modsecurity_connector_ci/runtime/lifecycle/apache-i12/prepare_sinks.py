#!/usr/bin/env python3
"""Prepare five sealed native Apache sink cases; root launches the existing controller."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
import shutil


paths = load_tool('ci/runtime/lifecycle/apache-i12/paths.py')

RUN = paths.storage_root() / 'runs/e2e/20261014T182400Z-pr410-oracle-lifecycle'
DIRECT = paths.storage_root() / 'runs/e2e/20261013T125816Z-8c574cdf-i12-completion/apache-current-prep-v2/apache-runner.py'
INTERPOSER = paths.storage_root() / 'runs/i12-apache-410-20261015/sink/apr-sink-fault.so'
FAULTS = ['badpath', 'devfull', 'unwritable', 'closed-descriptor', 'physical-enospc', 'observe']


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def seal(tree):
    for path in sorted(tree.rglob('*'), reverse=True):
        path.chmod(0o555 if path.is_dir() or path.name.endswith('.py') else 0o444)
    tree.chmod(0o555)


def ledger(tree, destination):
    value = {'files': {str(p.relative_to(tree)): sha(p) for p in sorted(tree.rglob('*')) if p.is_file()}}
    destination.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def prepare(output, fault):
    output = paths.new_output(output)
    allowed = RUN / 'apache-i12-20261015/sinks-v1'
    if output == allowed or not output.is_relative_to(allowed):
        raise ValueError('new output must be below ' + str(allowed))
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    fixtures = output / 'fixtures'
    fixtures.mkdir(mode=0o700)
    artifacts = output / 'artifacts'
    shutil.copytree(RUN / 'apache-lifecycle/artifacts-v3', artifacts)
    artifacts.chmod(0o700)
    (artifacts / 'apache').chmod(0o700)
    shutil.copyfile(INTERPOSER, artifacts / 'apache/apr-sink-fault.so')
    shutil.copyfile(DIRECT, fixtures / 'direct-runner.py')
    shutil.copyfile(Path(__file__).with_name('sink_launch.py'), fixtures / 'launch.py')
    shutil.copyfile(RUN / 'apache-lifecycle/fixtures-v3/curl-raw-client.py', fixtures / 'curl-raw-client.py')
    original_cases = DIRECT.with_name('cases.json')
    original_fault = 'closed-descriptor' if fault == 'observe' else fault
    original_case = next(value for value in json.loads(original_cases.read_text()) if value['fault'] == original_fault)
    case = json.loads(json.dumps(original_case))
    if fault == 'observe':
        case.update(name='no-fault-control', case_id='E2E-APACHE-SINK-NO-FAULT-CONTROL', fault='observe')
        case['control_expectation'] = {'http_status': 403, 'backend_requests': 0, 'native_rule_id': 120016, 'native_rule_phase': 1, 'physical_event_sink_write_success': True}
    shutil.copyfile(original_cases, fixtures / 'original-cases.json')
    shutil.copyfile(Path(__file__).with_name('paths.py'), fixtures / 'paths.py')
    shutil.copyfile(Path(__file__).with_name('process_capture.py'), fixtures / 'process_capture.py')
    settings = {'storage_root': str(paths.storage_root()), 'runtime_root': str(paths.storage_root() / 'apache-sinks'), 'case': case, 'run_id': '20261015-apache-sink-' + fault,
        'original_cases_source': str(original_cases), 'original_cases_sha256': sha(original_cases),
        'original_case': original_case, 'original_helpers_source': str(DIRECT), 'original_helpers_sha256': sha(DIRECT),
        'interposer_source': str(INTERPOSER), 'interposer_sha256': sha(INTERPOSER),
        'no_synthesized_apr_return': True, 'physical_operation_observation_required': True,
        'original_expected_rule_id': 120016, 'actual_runtime': None,
        'apr_open_result': None, 'full_lifecycle_qualification': None,
        'binding': {'isolation_review_approved': True, 'input_sha256': {
            '/usr/sbin/apache2': sha(Path('/usr/sbin/apache2')),
            '/usr/lib/x86_64-linux-gnu/libmodsecurity.so.3.0.14': sha(Path('/usr/lib/x86_64-linux-gnu/libmodsecurity.so.3.0.14')),
            '/mnt/artifacts/apache/test-observed.so': sha(artifacts / 'apache/test-observed.so'),
            '/mnt/artifacts/apache/apr-sink-fault.so': sha(artifacts / 'apache/apr-sink-fault.so'),
            '/mnt/fixtures/direct-runner.py': sha(fixtures / 'direct-runner.py'),
            '/mnt/fixtures/launch.py': sha(fixtures / 'launch.py')}}}
    (fixtures / 'sink-settings.json').write_text(json.dumps(settings, indent=2) + '\n')
    spec = json.loads((RUN / 'apache-lifecycle/admission-spec-v3.json').read_text())
    for target, tree in [('/mnt/fixtures', fixtures), ('/mnt/artifacts', artifacts)]:
        receipt = output / (tree.name + '-ledger.json')
        ledger(tree, receipt)
        binding = next(item for item in spec['bindings'] if item['target'] == target)
        binding.update(source=str(tree), ledger=str(receipt), ledger_sha256=sha(receipt))
    destination = output / 'admission-spec.json'
    destination.write_text(json.dumps(spec, indent=2, sort_keys=True) + '\n')
    seal(output)
    print(destination)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-input-root', type=Path, required=True)
    parser.add_argument('--fault', choices=FAULTS, required=True)
    args = parser.parse_args()
    prepare(args.output_input_root, args.fault)
