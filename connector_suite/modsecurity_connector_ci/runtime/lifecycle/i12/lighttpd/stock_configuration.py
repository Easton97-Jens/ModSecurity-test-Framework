"""Retain actual Stock CLI/bootstrap observations without inventing configtest."""
import argparse
import json
from pathlib import Path

from modsecurity_connector_ci.runtime.lifecycle.i12.lighttpd.stock_packet import external_path, read, reference
from modsecurity_connector_ci.runtime.lifecycle.i12.lighttpd.stock_qualification import CONFIGURATION_CASES


def assemble(attempt, preparation, output):
    attempt, preparation, output = map(external_path, (attempt, preparation, output))
    output.mkdir(mode=0o700)
    controller = read(attempt / 'controller-result.json')
    result = []
    for case in sorted(CONFIGURATION_CASES):
        data = attempt / 'data' / case / 'lighttpd'
        contract_path = preparation / 'individual-inputs' / case / 'fixtures/fixture-contract.json'
        contract = read(contract_path)
        command = read(data / 'sidecar.actual-start-command.json')
        execution = read(data / 'execution-receipt.json')
        sidecar = next(row for row in execution['cleanup'] if row['actor'] == 'sidecar')
        actual_exit = sidecar['actual_before_cleanup_exit']
        client_path = data / 'main.actual-client-process.json'
        value = {'schema': 'lighttpd-stock-bootstrap-observation-v1',
            'run_scoped_case_id': contract['original_selected_requirement']['run_scoped_case_id'],
            'original_selected_requirement': contract['original_selected_requirement'],
            'original_oracle_unchanged': contract['original_oracle'],
            'execution_kind': 'host_start_then_http' if client_path.is_file() else 'host_start_only',
            'actual_sidecar_command': command, 'actual_startup_exit_before_cleanup': actual_exit,
            'actual_native_module': 'Statically linked Stock sidecar Runtime; no mod_msconnector plugin is invoked.',
            'configuration_inputs': read(data / 'configuration-input-observation.json'),
            'cleanup': execution['cleanup'], 'controller_errors': controller['errors'],
            'finite_configtest_exit_observed': False,
            'full_lifecycle_qualified': False, 'root_qualification': None,
            'qualification_missing_reason': 'Original parser exit0/1 contract requires independent Root disposition: delivered CLI starts a service or exits78; startup success is not finite parser exit0.',
            'physical_evidence': [reference(path) for path in (contract_path,
                data / 'sidecar.actual-start-command.json', data / 'configuration-input-observation.json',
                data / 'execution-receipt.json', data / 'logs/sidecar.stdout', data / 'logs/sidecar.stderr',
                attempt / 'controller-result.json')]}
        if client_path.is_file():
            value['actual_waited_http_client'] = read(client_path)
            value['physical_evidence'].append(reference(client_path, 'client_process'))
        destination = output / (case + '.json')
        destination.write_text(json.dumps(value, indent=2) + '\n')
        result.append({'case': case, 'actual_startup_exit': actual_exit, 'evidence': reference(destination)})
    (output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('attempt', 'preparation', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(assemble(args.attempt, args.preparation, args.output)))
