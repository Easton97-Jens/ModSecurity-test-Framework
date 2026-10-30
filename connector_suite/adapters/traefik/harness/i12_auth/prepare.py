"""Prepare a fresh, sealed Traefik forwardAuth capture; never launch a host.

Uses central traefik-forwardauth observation deltas on exact current product
sources before explicit fixture-only relocations. Every output byte is bound;
source export is not PASS.
"""
from modsecurity_test_framework.connector_context import load_source
import argparse
import ast
import hashlib
import importlib.util
import json
import os
import shutil
from pathlib import Path

CASES = ('allow', 'p1-deny', 'p2-deny', 'engine-limit', 'limit-boundary',
         'host-limit', 'p3-deny', 'p4-safe', 'large-response', 'observer-abort',
         'observer-no-handle', 'observer-invalid-handle', 'mrc1-error',
         'auth-cap-boundary', 'auth-cap-overlimit', 'neighbor')

def load(path, name):
    module = load_source(path)
    return module

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def replace(text, before, after):
    if text.count(before) != 1:raise ValueError('capture relocation boundary differs: ' + before[:80])
    return text.replace(before, after, 1)

def validate_owned_ancestor(ancestor):
    if not ancestor.exists():
        return
    metadata = ancestor.stat()
    if metadata.st_uid != os.getuid() or metadata.st_mode & 0o022:
        raise ValueError('output ancestry must be private and task-owned')


def validate_output_ancestry(output, storage):
    for component in (output, *output.parents, storage, *storage.parents):
        if component.is_symlink():raise ValueError('physical output path required')
    for ancestor in output.parents:
        validate_owned_ancestor(ancestor)
        if ancestor == storage:break
        if (ancestor / '.git').exists() or (ancestor / '.git').is_symlink():raise ValueError('Git checkout/metadata is forbidden')


def validate_output(output):
    output = output.absolute()
    if output.exists():raise ValueError('fresh output required')
    if output.resolve()!=output:raise ValueError('physical output path required')
    configured = os.environ.get('CODEX_TEMP_ROOT')
    if not configured:raise ValueError('configured external storage root required')
    storage = Path(configured)
    if not storage.is_absolute() or storage.resolve()!=storage or not storage.is_dir():
        raise ValueError('physical configured storage root required')
    if storage not in output.parents:raise ValueError('output outside authorized external storage')
    validate_output_ancestry(output, storage)
    return output


def stage_source(repository, output):
    exporter = load(repository / 'connectors/traefik/harness/i12/source_export.py', 'i12_source_export')
    source = output / 'source'
    exporter.export(repository, source)
    capture_root = repository / 'ci/runtime/lifecycle/i12'
    central = load(capture_root / 'capture_sources.py', 'i12_central_capture')
    registry = central.Registry(capture_root, repository)
    adapter = load(repository / 'connectors/traefik/harness/i12/current_capture.py',
                   'i12_current_capture')
    adapter.apply(central, registry, 'traefik-forwardauth', source)
    return source


def stage_fixtures(source, output, cases):
    fixture = output / 'fixtures';fixture.mkdir()
    captured = source / '.i12-capture/traefik-forwardauth/drivers'
    for name in ('cc-wrapper.sh', 'cxx-wrapper.sh', 'sdk-who.c'):
        shutil.copyfile(captured / name, fixture / name)
        if name.endswith('.sh'):(fixture / name).chmod(0o755)
    own = Path(__file__).resolve().parent
    for name in ('client.py', 'backend.py', 'auth_proxy.py', 'fault_peer.py', 'validate_config.py', 'tls_fixture.py'):shutil.copyfile(own / name, fixture / name)
    helper = source / 'connectors/traefik/response_observer/i12_observer.go'
    text = helper.read_text();start = text.index('\tif transactionID != ');end = text.index(' {\n\t\treturn', start)
    text = text[:start] + '\tif ' + ' && '.join('transactionID != "i12-auth-' + name + '"' for name in cases) + text[end:]
    helper.write_text(text)
    return fixture, captured


def prepare(repository, output, leg='traefik-forwardauth-request', cases=None):
    cases=CASES if cases is None else tuple(cases)
    if len(set(cases))!=len(cases) or any(name not in CASES for name in cases):raise ValueError('invalid bounded case selection')
    if 'neighbor' not in cases:cases=(*cases,'neighbor')
    if leg not in ('traefik-forwardauth-request', 'traefik-forwardauth-response-companion'):
        raise ValueError('invalid logical leg')
    repository = repository.resolve();output = validate_output(output)
    output.mkdir(parents=True, mode=0o700)
    source = stage_source(repository, output)
    fixture, captured = stage_fixtures(source, output, cases)
    driver = (captured / 'driver.py').read_text()
    driver = replace(driver, "LEG = 'traefik-forwardauth-request'", 'LEG = ' + repr(leg))
    driver = replace(driver, "CASE = 'I12::traefik-forwardauth-request::NEED-request-eos-once'", 'CASE = ' + repr('I12::'+leg+'::extended-host-capture'))
    driver = replace(driver, "RUN = 'tf-i12-request-20261014'", "RUN = 'i12-traefik-auth-20261015'")
    driver = replace(driver, "backend_port,auth_port,host_port=wait.free_port(),wait.free_port(),wait.free_port()",
        "backend_port,auth_port,host_port,engine_port=wait.free_port(),wait.free_port(),wait.free_port(),wait.free_port()")
    driver = replace(driver, "dynamic.write_text(helper.dynamic_config(backend_port,auth_port,Path(env['MSCONNECTOR_TRAEFIK_FORWARDAUTH_COMPANION_SOCKET'])))",
        "dynamic.write_text(helper.dynamic_config(backend_port,auth_port,Path(env['MSCONNECTOR_TRAEFIK_FORWARDAUTH_COMPANION_SOCKET'])).replace('        maxBodySize: 4096', '        maxBodySize: 4096\\n        maxResponseBodySize: 32768'))\n    assert 'maxResponseBodySize: 32768' in dynamic.read_text()")
    driver = replace(driver, "    helper.validate_forwardauth_p2_contract(dynamic.read_text())", "    text=dynamic.read_text().replace('\\n  middlewares:\\n', '\\n    fault:\\n      entryPoints: [web]\\n      rule: Path(`/mrc1-error`)\\n      priority: 100\\n      middlewares: [modsecurity-forwardauth, observer-fault]\\n      service: upstream\\n  middlewares:\\n    observer-fault:\\n      plugin:\\n        modsecurityResponseObserver:\\n          socketPath: /task/sockets/fault.sock\\n          timeoutMillis: 5000\\n', 1)\n    assert text.count('\\n  middlewares:')==1\n    dynamic.write_text(text)\n    helper.validate_forwardauth_p2_contract(dynamic.read_text())")
    driver = replace(driver, "    helper.validate_forwardauth_p2_contract(dynamic.read_text())", "    execute('authorization-relay-tls',['/usr/local/bin/python3','-P',FIXTURES/'tls_fixture.py',dynamic,str(auth_port)],env)\n    helper.validate_forwardauth_p2_contract(dynamic.read_text())\n    execute('validate-effective-yaml',['/usr/bin/python3','-B',FIXTURES/'validate_config.py',dynamic],env)")
    start = driver.index('    for index,nonce in enumerate((TARGET,NEIGHBOR)):')
    end = driver.index("    (TASK/'rules.conf').write_text", start)
    rules = [
        'SecRule REQUEST_HEADERS:X-Modsec-Smoke "@streq block" "id:1100001,phase:1,deny,status:403,log"',
        'SecRule REQUEST_BODY "@contains i12-block-request" "id:1100101,phase:2,deny,status:403,log"',
        'SecRule RESPONSE_HEADERS:X-I12-Response "@streq deny" "id:1100201,phase:3,deny,status:403,log"',
        'SecRule RESPONSE_BODY "@contains i12-block-response" "id:1100301,phase:4,deny,status:403,log"',
        'SecRule REQUEST_URI "@beginsWith /" "id:1999411,phase:1,pass,log"',
        'SecRule RESPONSE_BODY "@contains i12-response-marker" "id:1999414,phase:4,pass,log"']
    driver = driver[:start] + '    rules.extend(' + repr(rules) + ')\n' + driver[end:]
    start = driver.index("    product=json.loads((ARTIFACTS/'preparation-manifest.json').read_text())")
    end = driver.index("    command=['rtk','proxy'", start)
    driver = driver[:start] + "    write('build-manifest.json',{'run':RUN,'host_sha256':digest(host),'engine_sha256':digest(engine),'observer_sha256':digest(observer),'sdk_accessor_sha256':digest(accessor),'wrap_symbols':SYMBOLS,'source_inputs':{str(p.relative_to(SOURCE)):digest(p) for p in SOURCE.rglob('*') if p.is_file()},'configuration':{str(p):digest(p) for p in (TASK/'rules.conf',config,dynamic)},'qualification':'measurement_only','authorization_tls_public':{str(p):digest(p) for p in (TASK/'authorization-tls/ca.crt',TASK/'authorization-tls/server.crt',TASK/'authorization-tls/tls-receipt.json')},'authorization_response_capacity':32768,'host_request_limit':4096,'native_request_limit':1024})\n" + driver[end:]
    driver = replace(driver, "f'127.0.0.1:{auth_port}'],service_env", "f'127.0.0.1:{engine_port}'],service_env")
    driver = replace(driver, "wait.wait_for_port(auth_port,service,'actual forwardAuth native service')",
        "wait.wait_for_port(engine_port,service,'actual forwardAuth native service')\n        relay=start('authorization-relay',['/usr/local/bin/python3','-P',FIXTURES/'auth_proxy.py',str(auth_port),str(engine_port)],env,handles)\n        processes['authorization-relay']=(relay,str(FIXTURES/'auth_proxy.py'));wait.wait_for_port(auth_port,relay,'bounded authorization sample relay')")
    driver = replace(driver, "        host_process=start('traefik',command[2:],env,handles)", "        fault=start('fault-peer',['/usr/local/bin/python3','-P',FIXTURES/'fault_peer.py'],env,handles)\n        processes['fault-peer']=(fault,str(FIXTURES/'fault_peer.py'))\n        for _ in range(100):\n            if Path('/task/sockets/fault.sock').is_socket():break\n            time.sleep(0.01)\n        host_process=start('traefik',command[2:],env,handles)")
    start = driver.index("        for label,nonce in (('target',TARGET),('neighbor',NEIGHBOR)):")
    end = driver.index("        final['target_and_neighbor_commands_exit']=0", start)
    driver = driver[:start] + "        for label in " + repr(cases) + ":\n            try:execute('client-'+label,['/usr/local/bin/python3','-P',FIXTURES/'client.py',str(host_port),label],env)\n            except RuntimeError as error:final.setdefault('probe_failures',[]).append({'case':label,'message':str(error)})\n            final.setdefault('client_command_exits',{})[label]=json.loads((TASK/('client-'+label+'.command.json')).read_text())['exit_code']\n            time.sleep(0.15);snapshot('after-'+label,processes)\n" + driver[end:]
    driver = replace(driver, "        final['target_and_neighbor_commands_exit']=0", "        final['all_probe_commands_zero']=all(value==0 for value in final['client_command_exits'].values())")
    driver = replace(driver, "for label in ('traefik','engine','backend'):", "for label in ('traefik','fault-peer','authorization-relay','engine','backend'):")
    driver = replace(driver, "'selected_case_count':1,'neighbor_health_probe_count':1", "'selected_case_count':"+str(len(cases)-1)+",'neighbor_health_probe_count':1")
    driver = replace(driver, "'selected_case_count':1,'neighbor_count':1", "'selected_case_count':"+str(len(cases)-1)+",'neighbor_count':1")
    ast.parse(driver);(fixture / 'driver.py').write_text(driver)
    receipt = {'central_variant':'traefik-forwardauth','central_manifest_sha256':sha(repository/'ci/runtime/lifecycle/i12/manifest.json'),
        'source_application_receipt_sha256':sha(source/'i12-source-application-receipt.json'),
        'source_files':{str(p.relative_to(source)):sha(p) for p in source.rglob('*') if p.is_file()},
        'fixture_files':{p.name:sha(p) for p in fixture.iterdir()},
        'fixture_changes':['explicit bounded synthetic case ID admission','source-bound native phase rules','physical bounded authorization relay','thirteen distinct client probes plus neighbor','preserved authorization-response capacity32768','verified TLS relay with fresh runtime CA and IP-SAN leaf'],
        'logical_leg':leg,'cases':cases,'runtime_qualified':False,'host_launched':False}
    (output/'preparation.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--leg', choices=('traefik-forwardauth-request','traefik-forwardauth-response-companion'), default='traefik-forwardauth-request')
    parser.add_argument('--cases', nargs='+', choices=CASES)
    args=parser.parse_args();prepare(args.repository,args.output,args.leg,args.cases)
