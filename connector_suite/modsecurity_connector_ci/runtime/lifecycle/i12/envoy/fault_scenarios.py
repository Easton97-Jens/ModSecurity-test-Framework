#!/usr/bin/env python3
"""Seal one real-Envoy Response-EOS fault probe; never assign host acceptance."""
import argparse
import json
from pathlib import Path
import re

import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.evidence_io as E
import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.host_scenarios as H

PROXY_NAME = 'fault-proxy'
PROXY_RECEIPT = 'fault-proxy-build.json'
LABEL = 'ext-proc-drop-response-eos'


def verified(reference):
    actual = E.reference(reference['path'])
    if any(reference.get(key) != actual[key] for key in ('path', 'sha256', 'bytes')):
        raise ValueError('test proxy physical build input changed')
    return actual


def proxy_build(path):
    proof = E.read_json(path)
    if proof.get('schema') != 'i12.envoy.fault-proxy-build.v1':
        raise ValueError('unknown standalone proxy build schema')
    for field in ('binary', 'source', 'test_source'):
        verified(proof[field])
    if proof['source']['path'] != str(H.HERE / 'fault_proxy.go'):
        raise ValueError('proxy build must bind the selected Envoy test source')
    if not proof.get('actual_go_version', '').startswith('go version go1.27.2 '):
        raise ValueError('actual patched Go toolchain evidence required')
    commands = proof.get('commands', [])
    if not commands or any(type(row.get('exit_code')) is not int or row['exit_code'] != 0 for row in commands):
        raise ValueError('standalone proxy build and controls must be successful')
    inputs = proof.get('module_inputs', {})
    if len(inputs) != 2 or {Path(name).name for name in inputs} != {'go.mod', 'go.sum'}:
        raise ValueError('exact readonly proxy module inputs required')
    for name, digest in inputs.items():
        if E.reference(name)['sha256'] != digest:
            raise ValueError('proxy module inputs changed')
    return proof


def fault_driver(original):
    text = H.driver_source(original)
    anchor = "    for binary in [host,engine]:shutil.copyfile(ARTIFACTS/binary.name,binary);binary.chmod(0o700)"
    text = H.replace_once(text, anchor, anchor + "\n    proxy=TASK/'cache/fault-proxy'\n    shutil.copyfile(FIXTURES/'fault-proxy',proxy);proxy.chmod(0o700)")
    anchor = "        envoy=start('envoy',"
    start = """        proxy_process=start('fault-proxy',[proxy,'--listen','127.0.0.1:18084','--upstream','127.0.0.1:18083','--target',TARGET,'--mode','drop-response-eos','--events','/task/runtime/proxy-events.jsonl'],env,handles)
        processes['fault-proxy']=(proxy_process,str(proxy));wait_port(18084,proxy_process,'private test gRPC proxy')
"""
    text = H.replace_once(text, anchor, start + anchor)
    text = H.replace_once(text, "for name in ['envoy','engine','backend']:",
                          "for name in ['envoy','fault-proxy','engine','backend']:")
    anchor = "'rules_original_sha256':digest(FIXTURES/'native.rules')"
    text = H.replace_once(text, anchor, anchor + ",'test_proxy_sha256':digest(proxy),'test_proxy_build':json.loads((FIXTURES/'fault-proxy-build.json').read_text())")
    compile(text, H.DRIVER_FILE, 'exec')
    return text


def fault_contract(source):
    references = []
    for name, line, claim in (
        ('processor.go', 436, 'Peer EOF after response headers without responseDone returns Unavailable.'),
        ('processor.go', 899, 'Only received body bytes and EOS are delivered to the engine.'),
        ('common_runtime_engine.go', 432, 'Incomplete close preserves the native EOS gate; no successful Finish is inferred.'),
    ):
        path = source / 'connectors/envoy/ext_proc/internal/processor' / name
        reference = E.reference(path)
        reference.update(line=line, claim=claim)
        references.append(reference)
    return {'schema': 'i12.envoy.response-eos-fault-contract.v1',
        'execution_kind': 'deliberately_interposed_real_envoy_stream',
        'drop': 'first selected real ResponseBody with EndOfStream=true; never synthesize Continue or EOS',
        'engine_terminal_expected': {'grpc_status': 14, 'source': 'actual upstream Recv result after CloseSend'},
        'envoy_received_terminal_status': None,
        'envoy_received_terminal_status_reason': 'Proxy return does not prove what Envoy received.',
        'native_expected': {'request_bytes': 95, 'response_bytes': 96, 'request_eos': 1,
                            'response_eos': 0, 'P1': 1, 'P2': 1, 'P3': 1, 'P4': 0},
        'client_backend_commit_first_cause': 'must be measured independently; no host PASS assigned',
        'source_refs': references, 'host_lifecycle_qualified': False}


def prepare(args):
    args.only = ['ext-proc-streaming']
    run, old, source, native = H.preparation_inputs(args)
    proof = proxy_build(args.proxy_build_receipt)
    content = H.capture_content(args.parent_sha, native.get('envoy_registry_adapter'))
    isolated, controller = H.prepare_controller(run, old)
    bindings = H.prepare_shared_inputs(run, old, source, args.binaries)
    source_proof = H.source_binding_proof(source, native, args.parent_sha)
    fixture = run / 'host-fixtures' / LABEL
    fixture.mkdir(parents=True)
    template = H.fixture_template(old, 'ext-proc')
    for filename in (H.ENVOY_CONFIG, 'native.conf', 'extproc-service.json'):
        target = fixture / filename
        target.write_bytes(E.read_bytes(template / filename))
    shape = H.scenario_shape(template, args.parent_sha, LABEL, 'streaming', 200, True)
    shape['test_fault'] = 'drop-response-eos'
    H.write(fixture / 'shape.json', shape)
    (fixture / 'native.rules').write_text(H.scenario_rules('streaming', 40, shape['target']))
    yaml = E.read_bytes(fixture / H.ENVOY_CONFIG).decode()
    (fixture / H.ENVOY_CONFIG).write_text(H.replace_once(yaml, 'port_value: 18083', 'port_value: 18084'))
    H.write_fixture_sources(fixture, content, 'ext-proc', source_proof, native)
    (fixture / H.DRIVER_FILE).write_text(fault_driver(content(H.DRIVER_FILE)))
    (fixture / PROXY_NAME).write_bytes(E.read_bytes(proof['binary']['path']))
    (fixture / PROXY_NAME).chmod(0o700)
    (fixture / 'fault_proxy.go').write_bytes(E.read_bytes(proof['source']['path']))
    H.write(fixture / PROXY_RECEIPT, proof)
    H.write(fixture / 'fault-contract.json', fault_contract(source))
    H.generate_tls(fixture)
    case = H.fixture_admission(fixture, LABEL, shape, 200, True, bindings)
    H.write(run / 'host-scenarios.json', {'parent_sha': args.parent_sha,
        'controller': str(isolated / controller.name), 'controller_original_sha256': H.OLD_CONTROLLER_SHA,
        'controller_sha256': H.sha(isolated / controller.name),
        'capture_manifest_sha256': H.sha(H.HERE.parent / 'manifest.json'),
        'envoy_registry_adapter': content.registry_adapter, 'scenarios': [case],
        'test_topology': 'four isolated nonroot processes; added private loopback18084 proxy, no external listener',
        'host_lifecycle_qualified': False})
    print(json.dumps({'matrix': str(run / 'host-scenarios.json'), 'scenarios': 1, 'new_lifecycle_pass': 0}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('run-root', 'historical', 'source', 'binaries', 'build-receipt', 'proxy-build-receipt'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--parent-sha', required=True)
    args = parser.parse_args()
    if re.fullmatch(r'[a-f0-9]{40}', args.parent_sha) is None:
        parser.error('full Parent SHA required')
    prepare(args)


if __name__ == '__main__':
    main()
