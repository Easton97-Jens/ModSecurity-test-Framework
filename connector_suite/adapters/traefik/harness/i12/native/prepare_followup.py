"""Extend sealed native inputs with private UDS fault and Strict host probes."""
import argparse
import json
from pathlib import Path
import shutil

from connector_suite.adapters.traefik.harness.i12.native.prepare import replace_once, save, seal, sha, validate_output, validate_prepared_root

DRIVER_FILE = 'driver.py'


def configure_faults(driver, mode, original):
    cases = "(('fault-mse1',500),('fault-result',500),('fault-postcommit',200),('fault-ack',403),('client-cancel',200),('neighbor',200))"
    driver = replace_once(driver, original, cases)
    driver = replace_once(driver, "    helper.write_dynamic_config(artifacts.dynamic_config, backend_port, engine_socket)",
                          "    proxy_socket = TASK / 'sockets/proxy.sock'\n    helper.write_dynamic_config(artifacts.dynamic_config, backend_port, proxy_socket)")
    needle = "        host_process = start('traefik'"
    position = driver.index(needle)
    driver = driver[:position] + "        proxy = start('proxy', ['/usr/local/bin/python3', '-P', FIXTURES / 'fault_proxy.py', proxy_socket, engine_socket], env, handles)\n        processes['proxy'] = (proxy, str(FIXTURES / 'fault_proxy.py'))\n        helper.wait_for_socket(proxy_socket, proxy, 'test-only fault relay')\n" + driver[position:]
    driver = replace_once(driver, "for label in ('traefik', 'engine', 'backend'):", "for label in ('traefik', 'proxy', 'engine', 'backend'):")
    driver = replace_once(driver, "    rules.extend([", "    rules.extend(['SecRule REQUEST_URI \"@streq /i12-eos-fault-ack\" \"id:1999301,phase:1,deny,status:403,log\"',")
    if mode == 'faults-v3':
        driver = replace_once(driver, "'SecResponseBodyLimit 1024'", "'SecResponseBodyLimit 32768'")
    return driver


def configure_mode(driver, mode, original):
    if mode in ('faults', 'faults-v2', 'faults-v3'):
        driver = configure_faults(driver, mode, original)
    elif mode == 'strict':
        driver = replace_once(driver, original, "(('allow-chunks',200),('p4-safe-late',200),('neighbor',200))")
        driver = replace_once(driver, "    helper.write_engine_config(artifacts.engine_config, inputs.rules_file, artifacts.event_path)",
                              "    helper.write_engine_config(artifacts.engine_config, inputs.rules_file, artifacts.event_path)\n    artifacts.engine_config.write_text(artifacts.engine_config.read_text().replace('phase4_mode=safe', 'phase4_mode=strict'))")
    elif mode == 'mime':
        driver = replace_once(driver, original, "(('request-type-missing',200),('request-charset-missing',200),('request-charset-iso',200),('response-type-missing',200),('response-charset-missing',200),('response-charset-iso',200),('mime-out',200),('neighbor',200))")
    else:
        raise ValueError('unknown followup mode')
    return driver


def prepare_followup(root, mode):
    root = validate_prepared_root(root)
    if mode not in ('faults', 'faults-v2', 'faults-v3', 'strict', 'mime'):
        raise ValueError('unknown followup mode')
    name = 'fixtures-' + mode
    fixtures = root / name
    for output in (fixtures, root / (name + '-ledger.json'), root / ('admission-' + mode + '.json')):
        validate_output(output, fresh=True)
    shutil.copytree(root / 'fixtures', fixtures)
    for path in (fixtures, *fixtures.rglob('*')):
        path.chmod(0o700 if path.is_dir() or path.stat().st_mode & 0o111 else 0o600)
    for filename in ('client.py', 'backend.py', 'fault_proxy.py'):
        shutil.copyfile(Path(__file__).parent / filename, fixtures / filename)
    driver = (fixtures / DRIVER_FILE).read_text()
    original = "(('allow-chunks',200),('p1-deny',403),('p2-deny',403),('p3-deny',403),('p4-safe-late',200),('mime-out',200),('neighbor',200))"
    driver = configure_mode(driver, mode, original)
    selected = {'strict': '2', 'mime': '7'}.get(mode, '5')
    driver = driver.replace("'selected_case_count': 7", "'selected_case_count': " + selected)
    driver = driver.replace("'selected_case_count': 6", "'selected_case_count': " + selected)
    driver = driver.replace("'tf-i12-native-20261015'", repr('tf-i12-native-' + mode + '-20261015'))
    (fixtures / DRIVER_FILE).write_text(driver)
    # Syntax validation occurs before immutable inputs are admitted.
    compile(driver, str(fixtures / DRIVER_FILE), 'exec')
    ledger = root / (name + '-ledger.json')
    save(ledger, seal(fixtures))
    ledger.chmod(0o444)
    admission = json.loads((root / 'admission.json').read_text())
    for binding in admission['bindings']:
        if binding['target'] == '/mnt/fixtures':
            binding.update(source=str(fixtures), ledger=str(ledger), ledger_sha256=sha(ledger))
    path = root / ('admission-' + mode + '.json')
    save(path, admission)
    path.chmod(0o444)
    print(json.dumps({'admission': str(path), 'sha256': sha(path), 'runtime_qualified': False}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('root', type=Path)
    parser.add_argument('mode', choices=('faults', 'faults-v2', 'faults-v3', 'strict', 'mime'))
    args = parser.parse_args()
    prepare_followup(args.root, args.mode)
