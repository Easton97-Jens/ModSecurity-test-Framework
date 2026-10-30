#!/usr/bin/env python3
"""Prepare Envoy-only captures for the unchanged private v5 controller.

This produces sealed inputs, never a qualification or a controller launch.
The existing capture variant remains the source of the native observation seam.
"""
from modsecurity_test_framework.connector_context import load_source
import argparse
import ctypes
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
if __package__:
    from . import source_inventory, evidence_io
else:
    import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.source_inventory as source_inventory
    import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.evidence_io as evidence_io

HERE = Path(__file__).resolve().parent
STORAGE = evidence_io.STORAGE
CLIENT_FILE = 'client.py'
BACKEND_FILE = 'backend.py'
DRIVER_FILE = 'driver.py'
ENVOY_CONFIG = 'envoy.yaml'
OLD_CONTROLLER_SHA = '76d5319b726a8fdba12b01ccc946aac80e8442f72ad4e262ff314f3f1db838b8'
ADMISSION_SHA = '99d9206e12afcc7bea684da1a6d6fc08a32be282984d81300476312c875f230f'
HOST_SHA = '002c6e1c69ed0fa0ea381887247cadadfaec9481375fa8d8d2b1731eeabf40b8'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('capture adaptation anchor differs: ' + old[:100])
    return text.replace(old, new, 1)


def seal_tree(root):
    files = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError('special capture input')
        if path.is_file():
            files[str(path.relative_to(root))] = sha(path)
            path.chmod(0o555 if path.stat().st_mode & 0o111 else 0o444)
        else:
            path.chmod(0o555)
    root.chmod(0o555)
    ledger = root.parent / (root.name + '-ledger.json')
    write(ledger, {'files': files})
    ledger.chmod(0o444)
    return {'source': str(root), 'ledger': str(ledger), 'ledger_sha256': sha(ledger)}


def pin_namespace(boot, matcher):
    if not matcher(boot):
        raise ValueError('owned PID namespace pin unavailable')
    descriptor = os.open('/proc/' + str(boot['host_pid']) + '/ns/pid', os.O_RDONLY)
    try:
        if ('pid:[' + str(os.fstat(descriptor).st_ino) + ']' != boot['namespaces']['pid']
                or not matcher(boot)):
            raise ValueError('owned PID namespace pin identity mismatch')
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def controller_source(original, old, run):
    """Pin the owned PID namespace until cleanup; inode reuse is not a survivor."""
    text = replace_once(original, f"RUN = Path('{old}')", f"RUN = Path('{run}')")
    text = replace_once(text, 'def controller(spec_path):', inspect.getsource(pin_namespace) + '\n\ndef controller(spec_path):')
    text = replace_once(text, '    old_term = signal.getsignal(signal.SIGTERM)',
                        '    namespace_pin = None\n    old_term = signal.getsignal(signal.SIGTERM)')
    anchor = "                        raise ValueError('actual init identity or isolation mismatch')"
    text = replace_once(text, anchor, anchor + '\n                    namespace_pin = pin_namespace(boot, matching_init)')
    anchor = '                if matching_init(boot):\n                    os.kill(boot[\'host_pid\'], signal.SIGKILL)'
    text = replace_once(text, anchor, "                if boot is not None and namespace_pin is None:\n                    namespace_pin = pin_namespace(boot, matching_init)\n" + anchor)
    text = text.replace("boot['namespaces']['pid'] if boot else None", "boot['namespaces']['pid'] if namespace_pin is not None else None")
    text = replace_once(text, '                if not survivors and not outside_mount_leaks:',
                        '                if namespace_pin is not None and not survivors and not outside_mount_leaks:')
    text = replace_once(text, "'surviving_namespace_pids': survivors,", "'namespace_pin_verified': namespace_pin is not None, 'surviving_namespace_pids': survivors,")
    text = replace_once(text, "    print(json.dumps({'attempt': str(attempt), 'exitcode': rc, 'timeout': timeout}))",
                        "    if namespace_pin is not None: os.close(namespace_pin)\n    print(json.dumps({'attempt': str(attempt), 'exitcode': rc, 'timeout': timeout}))")
    compile(text, 'private-runtime-v5.py', 'exec')
    return text


def client_source(original):
    text = replace_once(original, "Content-Type: text/plain\\r\\n", "Content-Type: {shape.get('request_mime', 'text/plain')}\\r\\n")
    text = replace_once(text, '            connection.sendall(request)', '''            header, payload = request.split(b'\\r\\n\\r\\n', 1)
            connection.sendall(header + b'\\r\\n\\r\\n')
            parts = shape.get('request_parts', 1) if label == 'target' else 1
            width = max(1, (len(payload) + parts - 1) // parts)
            receipt['actual_send_calls'] = []
            for offset in range(0, len(payload), width):
                chunk = payload[offset:offset+width]
                connection.sendall(chunk)
                receipt['actual_send_calls'].append({'bytes': len(chunk), 'monotonic_ns': time.monotonic_ns()})
                if parts > 1: time.sleep(0.03)''')
    text = replace_once(text, "    if status != 200:\n        raise RuntimeError('response was not HTTP 200')", "    expected_status = shape.get('expected_status', 200) if label == 'target' else shape.get('neighbor_expected_status', 200)\n    if status != expected_status:\n        raise RuntimeError(f'expected HTTP {expected_status}, observed {status}')")
    text = replace_once(text, '    if response_body != expected:', '    if status == 200 and response_body != expected:')
    text = replace_once(text, "                if len(received) > 65536:", '''                if label == 'target' and shape.get('truncate_response') and receipt.get('first_entity_clock'):
                    (root / 'target.first-entity.json').write_text(json.dumps(receipt['first_entity_clock']))
                if label == 'target' and shape.get('cancel') and receipt.get('first_entity_clock'):
                    receipt['deliberate_cancel_after_entity_byte'] = True
                    exit_code = 0
                    raise ConnectionAbortedError('I12 deliberate client cancellation after first entity byte')
                if len(received) > 65536:''')
    text = replace_once(text, '''            transport = connection.unwrap()
            transport.settimeout(15)
            transport_tail = transport.recv(1)
            receipt['tcp_eof_clock'] = {'monotonic_ns':time.monotonic_ns(),'wall_ns':time.time_ns()}
            receipt['tcp_eof_observed'] = transport_tail == b''
            if transport_tail != b'': raise RuntimeError('unexpected trailing raw TCP bytes after TLS shutdown')''', '''            try:
                transport = connection.unwrap()
                transport.settimeout(15)
                transport_tail = transport.recv(1)
                receipt['tcp_eof_clock'] = {'monotonic_ns':time.monotonic_ns(),'wall_ns':time.time_ns()}
                receipt['tcp_eof_observed'] = transport_tail == b''
                if transport_tail != b'': raise RuntimeError('unexpected trailing raw TCP bytes after TLS shutdown')
            except ConnectionResetError as error:
                receipt['tcp_reset_observed'] = True
                receipt['tcp_close_error'] = {'type':type(error).__name__, 'errno':error.errno}
                # Preserve the reset and validate the actual HTTP framing below.
                # A complete HTTP entity does not imply graceful TCP/gRPC EOF.''')
    compile(text, CLIENT_FILE, 'exec')
    return text


def backend_source(original):
    text = original.replace('limit=1024', 'limit=65536').replace('length > 1024', 'length > 65536')
    text = replace_once(text, 'root.mkdir(mode=0o700)', "root.mkdir(mode=0o700)\n(root / 'receipts.jsonl').touch(mode=0o600)")
    text = replace_once(text, "        self.send_header('Content-Type', 'text/plain')", "        self.send_header('Content-Type', shape.get('response_mime', 'text/plain'))")
    text = replace_once(text, '        self.send_response(200)', "        if self.path == '/' + shape['target']: time.sleep(shape.get('response_header_delay', 0))\n        self.send_response(200)")
    text = replace_once(text, "        self.send_header('Content-Length', str(len(response)))", "        parts = shape.get('response_parts', 1) if self.path == '/' + shape['target'] else 1\n        self.send_header('Transfer-Encoding' if parts > 1 else 'Content-Length', 'chunked' if parts > 1 else str(len(response)))")
    text = replace_once(text, '        self.wfile.write(response)\n        self.wfile.flush()', '''        sends = []
        width = max(1, (len(response) + parts - 1) // parts)
        for offset in range(0, len(response), width):
            if shape.get('truncate_response') and self.path == '/' + shape['target'] and offset: break
            chunk = response[offset:offset+width]
            self.wfile.write((f'{len(chunk):x}\\r\\n'.encode() + chunk + b'\\r\\n') if parts > 1 else chunk)
            self.wfile.flush()
            sends.append({'bytes': len(chunk), 'monotonic_ns': time.monotonic_ns()})
            if shape.get('truncate_response') and self.path == '/' + shape['target']:
                deadline = time.monotonic() + 3
                while not Path('/task/client/target.first-entity.json').is_file() and time.monotonic() < deadline: time.sleep(0.01)
                if not Path('/task/client/target.first-entity.json').is_file(): raise RuntimeError('client first-entity barrier not observed before deliberate backend EOF')
            if parts > 1: time.sleep(0.03)
        if parts > 1 and not (shape.get('truncate_response') and self.path == '/' + shape['target']): self.wfile.write(b'0\\r\\n\\r\\n'); self.wfile.flush()''')
    begin, end = text.index('        self.send_response(200)'), text.index('        self.close_connection = True')
    output = text[begin:end]
    text = text[:begin] + "        sends = []\n        response_eos_written = False\n        write_error = None\n        try:\n" + ''.join('    ' + row + '\n' for row in output.splitlines()) + "            response_eos_written = not (shape.get('truncate_response') and self.path == '/' + shape['target'])\n        except (BrokenPipeError, ConnectionResetError, ssl.SSLError) as error:\n            write_error = {'type':type(error).__name__}\n" + text[end:]
    text = replace_once(text, "'response_status': 200,", "'response_status': 200, 'actual_response_send_calls': sends, 'response_eos_written': response_eos_written, 'response_write_error': write_error,")
    text = replace_once(text, '        sequence += 1', '')
    text = replace_once(text, '        global sequence', '''        global sequence
        sequence += 1
        own_sequence = sequence
        (root / f'{own_sequence}.request-line.raw').write_bytes(self.raw_requestline)
        (root / f'{own_sequence}.parsed-headers.json').write_text(json.dumps(list(self.headers.items())))''')
    text = text.replace("f'{sequence}", "f'{own_sequence}").replace("'sequence': sequence", "'sequence': own_sequence")
    text = replace_once(text, 'server = http.server.HTTPServer(', 'server = (http.server.ThreadingHTTPServer if shape.get("concurrent") else http.server.HTTPServer)(')
    compile(text, BACKEND_FILE, 'exec')
    return text


def driver_source(original):
    text = replace_once(original, "'source_git_baseline':'3a1bafecd0c38ccf20427d580c767ed42addf4aa plus v5 harness and declared private overlays'", "'source_git_baseline':SHAPE['parent_sha']")
    for key, previous in [('product_contract', 'a9d48bb58aa948aea7d79e20cdf09d3f239b7808'),
                          ('delivery_source_baseline', '02754040bced960cfc1857416cd7101bb3116ef4'),
                          ('delivery_scoped_verified', '8cc32dceb06121f589150a9794f28878c5e4ba2a')]:
        text = replace_once(text, f"'{key}':'{previous}'", f"'{key}':SHAPE['parent_sha']")
    text = replace_once(text, "    if result.returncode:\n        raise RuntimeError(f'{label} exited {result.returncode}')", "    if result.returncode and not label.endswith('-client'):\n        raise RuntimeError(f'{label} exited {result.returncode}')")
    native_start = "        native=start('engine',command,native_env,handles,(lifecycle_fd,));processes['engine']=(native,str(engine));wait_port(18083,native,'actual native gRPC engine')"
    text = replace_once(text, native_start, "        if not SHAPE.get('grpc_unavailable'):\n    " + native_start)
    text = replace_once(text, "        final['independent_backend_request_count']=len(receipts)", "        final['independent_completed_backend_request_count']=len(receipts)\n        final['independent_started_backend_request_count']=len(list((TASK/'backend').glob('*.request-line.raw')))\n        final['client_exit_codes']={label:json.loads((TASK/(label+'.command.json')).read_text())['exit_code'] for label in ['selected-target-client','separate-neighbor-client']}\n        if any(final['client_exit_codes'].values()): raise RuntimeError('client validation failed; both client/neighbor results retained')")
    start = "        execute('selected-target-client',['/usr/local/bin/python3','-P',FIXTURES/'client.py','18443','target'],env)\n        time.sleep(0.15);snapshot('after-target',processes)\n        execute('separate-neighbor-client',['/usr/local/bin/python3','-P',FIXTURES/'client.py','18443','neighbor'],env)"
    text = replace_once(text, start, '''        if SHAPE.get('concurrent'):
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=2) as clients:
                futures = [clients.submit(execute, name, ['/usr/local/bin/python3','-P',FIXTURES/'client.py','18443',label], env)
                           for name,label in [('selected-target-client','target'),('separate-neighbor-client','neighbor')]]
                for future in futures: future.result()
            snapshot('after-target',processes)
        else:
''' + '\n'.join('    ' + line for line in start.splitlines()))
    text = replace_once(text, "        if len(receipts)!=2 or [row['path'] for row in receipts]!=['/'+TARGET,'/'+NEIGHBOR]:raise RuntimeError('independent backend count/nonces differ')", "        expected = (['/' + TARGET] if SHAPE.get('target_backend', True) else []) + (['/' + NEIGHBOR] if SHAPE.get('neighbor_backend', True) else [])\n        if sorted(row['path'] for row in receipts) != sorted(expected): raise RuntimeError('independent backend count/nonces differ')")
    compile(text, DRIVER_FILE, 'exec')
    return text


def scenarios():
    return [
        ('ext-proc', 'concurrent', 200, True),
        ('ext-authz-request', 'concurrent', 200, True),
        ('ext-authz-response-companion', 'concurrent', 200, True),
        ('ext-proc', 'cancel', 200, True),
        ('ext-authz-response-companion', 'cancel', 200, True),
        ('ext-proc', 'grpc-unavailable', 500, False),
        ('ext-authz-request', 'grpc-unavailable', 500, False),
        ('ext-authz-response-companion', 'missing-lease', 503, True),
        ('ext-authz-response-companion', 'expired-lease', 503, True),
        ('ext-proc', 'incomplete-response', 200, True),
        ('ext-authz-response-companion', 'incomplete-response', 200, True),
        ('ext-proc', 'streaming', 200, True),
        ('ext-proc', 'p1-deny', 403, False),
        ('ext-proc', 'p2-deny', 403, False),
        ('ext-proc', 'p3-deny', 403, True),
        ('ext-proc', 'p4-deny-safe', 200, True),
        ('ext-proc', 'request-reject', 403, False),
        ('ext-proc', 'request-partial', 200, True),
        ('ext-proc', 'response-partial', 200, True),
        ('ext-proc', 'response-reject', 200, True),
        ('ext-proc', 'mime-out', 200, True),
        ('ext-authz-request', 'streaming', 200, True),
        ('ext-authz-request', 'p1-deny', 403, False),
        ('ext-authz-request', 'p2-deny', 403, False),
        ('ext-authz-request', 'host-reject', 413, False),
        ('ext-authz-request', 'host-partial', 503, False),
        ('ext-authz-request', 'request-reject', 403, False),
        ('ext-authz-request', 'request-partial', 200, True),
        ('ext-authz-response-companion', 'streaming', 200, True),
        ('ext-authz-response-companion', 'p3-deny', 403, True),
        ('ext-authz-response-companion', 'p4-deny-safe', 200, True),
        ('ext-authz-response-companion', 'response-partial', 200, True),
        ('ext-authz-response-companion', 'response-reject', 200, True),
        ('ext-authz-response-companion', 'mime-out', 200, True),
    ]


def check_rules(rules):
    """Parse the complete rule actions with the selected real native SDK first."""
    library = ctypes.CDLL('/usr/lib/x86_64-linux-gnu/libmodsecurity.so')
    library.msc_create_rules_set.restype = ctypes.c_void_p
    library.msc_rules_add.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p)]
    library.msc_rules_cleanup.argtypes = [ctypes.c_void_p]
    native = library.msc_create_rules_set()
    if not native: raise RuntimeError('native rules allocation failed')
    error = ctypes.c_char_p()
    # Runtime log destinations exist only after admission; parsing those path
    # directives is a separate host-start check. No rule/action is omitted.
    parsed = '\n'.join(line for line in rules.splitlines()
                       if not line.startswith(('SecAuditLog ', 'SecDebugLog ')))
    try:
        result = library.msc_rules_add(native, parsed.encode(), ctypes.byref(error))
        if result < 0: raise ValueError('native fixture rules rejected: ' + (error.value or b'unknown').decode())
    finally:
        library.msc_rules_cleanup(native)


def verify_hashes(root, expected, error):
    for relative, value in expected.items():
        if sha(root / relative) != value:
            raise ValueError(error)


def verify_physical_source(source):
    for path in source.rglob('*'):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError('source copy contains nonphysical input')
        if path.is_file() and path.stat().st_nlink != 1:
            raise ValueError('source copy contains hard-linked input')


def verify_build(source, binaries, proof, parent_sha):
    if (not proof.get('build_ready') or proof.get('actual_source_commit') != parent_sha
            or Path(proof['source_copy']) != source):
        raise ValueError('fresh build/source/Parent correspondence missing')
    source_inventory.verify(source, proof)
    verify_physical_source(source)
    for relative, expected in proof['binaries'].items():
        verify_hashes(binaries, {Path(relative).name: expected},
                      'binary differs from actual native build receipt')
    verify_hashes(source, proof['capture_application']['exact_written_sha256'],
                  'source differs from exact capture application')
    verify_hashes(source / 'connectors/envoy/ext_proc', proof['module_inputs'],
                  'patched module inputs differ from build')


def preparation_inputs(args):
    storage = evidence_io.configured_storage(required=True)
    if set(args.only) - {route + '-' + name for route, name, _, _ in scenarios()}:
        raise ValueError('unknown scenario selection')
    run = args.run_root.resolve(strict=True)
    if storage not in run.parents or not (run / '.codex-storage-budget.json').is_file():
        raise ValueError('registered external task run required')
    old = args.historical.resolve(strict=True)
    source = args.source.resolve(strict=True)
    if (source / '.git').exists() or storage not in source.parents:
        raise ValueError('external disposable source required')
    build_proof = json.loads(args.build_receipt.read_text())
    verify_build(source, args.binaries, build_proof, args.parent_sha)
    return run, old, source, build_proof


def capture_content(parent_sha=None, expected_adapter=None):
    capture = load_source(HERE.parent / 'capture_sources.py')
    registry = capture.Registry()
    registry, metadata = source_inventory.verified_registry(
        capture, registry, parent_sha,
        source_inventory.E4_MANIFEST if parent_sha == source_inventory.E4_REVISION
        else sha(HERE.parent / 'manifest.json'))
    if metadata != expected_adapter:
        raise ValueError('host capture registry adapter differs from native build')
    variant = registry.manifest['profiles']['envoy']
    def content(name):
        return registry.content(variant['capture_files'][name]['sha256']).decode()
    content.registry_adapter = metadata
    return content


def prepare_controller(run, old):
    controller = old / 'isolation/private-runtime-v5.py'
    admission = old / 'isolation/candidate-admission-v5.py'
    if sha(controller) != OLD_CONTROLLER_SHA or sha(admission) != ADMISSION_SHA:
        raise ValueError('unreviewed controller bytes')
    isolated = run / 'isolation'
    isolated.mkdir(mode=0o700)
    text = controller_source(controller.read_text(), old, run)
    (isolated / controller.name).write_text(text)
    shutil.copyfile(admission, isolated / admission.name)
    for path in isolated.iterdir(): path.chmod(0o444)
    return isolated, controller


def prepare_shared_inputs(run, old, source, binaries):
    host_source = run / 'host-source'
    shutil.copytree(source, host_source)
    source_binding = seal_tree(host_source) | {'target': '/mnt/src'}
    artifacts = run / 'host-artifacts'
    artifacts.mkdir()
    host = old / 'envoy-authz-lifecycle/artifacts-v1/envoy'
    if sha(host) != HOST_SHA: raise ValueError('unknown actual Envoy image')
    shutil.copyfile(host, artifacts / 'envoy')
    for name in ('msconnector_envoy_ext_proc', 'msconnector_composite'):
        shutil.copyfile(binaries / name, artifacts / name)
    for path in artifacts.iterdir(): path.chmod(0o700)
    artifact_binding = seal_tree(artifacts) | {'target': '/mnt/artifacts'}
    return source_binding, artifact_binding


def source_binding_proof(source, build_proof, parent_sha):
    inputs = {str(p.relative_to(source)): sha(p) for p in source.rglob('*') if p.is_file()}
    overlays = {}
    for relative, baseline in build_proof['source_before_overlay'].items():
        if inputs[relative] != baseline:
            overlays[relative] = {'baseline_a9_sha256': baseline, 'instrumented_sha256': inputs[relative],
                                  'baseline_parent_sha': parent_sha}
        inputs[relative] = baseline
    source_proof = {'source_inputs': inputs, 'approved_test_overlays': overlays, 'parent_sha': parent_sha,
                    'legacy_field_names': 'baseline_a9_sha256 is retained driver ABI; baseline_parent_sha is current'}
    return source_proof


def fixture_template(old, route):
    profiles = {'ext-proc': 'extproc-v3', 'ext-authz-request': 'request-v2'}
    return old / 'envoy-authz-lifecycle' / profiles.get(route, 'companion-v2') / 'fixtures'


def scenario_shape(template, parent_sha, label, name, status, backend):
    nonce = hashlib.sha256((parent_sha + label).encode()).hexdigest()[:12]
    target, neighbor = 'e-' + nonce, 'n-' + nonce
    shape = json.loads((template / 'shape.json').read_text())
    # Historical proposals are not effective configuration or approved oracles.
    shape.pop('expected_source_oracle_proposal_only', None)
    shape.pop('host_request_buffer_max_bytes', None)
    shape.update(case_id='I12-ENVOY-HOST::' + label, parent_sha=parent_sha,
                 target=target, neighbor=neighbor, expected_status=status, target_backend=backend,
                 request_parts=3, response_parts=3, request_mime='text/plain; charset=utf-8',
                 response_mime='text/plain; charset=utf-8', concurrent=name in ('concurrent', 'cancel'),
                 cancel=name == 'cancel', grpc_unavailable=name == 'grpc-unavailable',
                 response_header_delay=6 if name == 'expired-lease' else 0,
                 truncate_response=name == 'incomplete-response')
    if name in ('host-reject', 'host-partial'): shape['request_parts'] = 1
    if name in ('grpc-unavailable', 'missing-lease'):
        shape['neighbor_expected_status'] = status
    if name == 'grpc-unavailable': shape['neighbor_backend'] = False
    request, response = b'request-marker-' + b'a' * 80, b'response-marker-' + b'b' * 80
    if name.startswith('request-'): request = b'request-marker-' + b'a' * 2034
    if name.startswith('response-'): response = b'response-marker-' + b'b' * 2033
    if name in ('host-reject', 'host-partial'): request = b'a' * 96
    for key, payload in [('request', request), ('response', response), ('neighbor_request', b'health'), ('neighbor_response', b'healthy')]:
        shape[key + '_hex'] = payload.hex()
    shape['request_bytes'], shape['response_bytes'] = len(request), len(response)
    if name == 'mime-out': shape['response_mime'] = 'application/octet-stream'
    return shape


def scenario_rules(name, index, target):
    rules = '''SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecRequestBodyLimit 1024
SecRequestBodyNoFilesLimit 1024
SecRequestBodyLimitAction Reject
SecResponseBodyLimit 1024
SecResponseBodyLimitAction Reject
SecResponseBodyMimeType text/plain
SecAuditEngine On
SecAuditLogType Serial
SecAuditLogParts ABFHZ
SecAuditLog /task/runtime/native-audit.log
SecDebugLogLevel 9
SecDebugLog /task/runtime/native-debug.log
'''
    if name == 'request-partial': rules = rules.replace('SecRequestBodyLimitAction Reject', 'SecRequestBodyLimitAction ProcessPartial')
    if name == 'response-partial': rules = rules.replace('SecResponseBodyLimitAction Reject', 'SecResponseBodyLimitAction ProcessPartial')
    for phase, variable, marker in [(1, 'REQUEST_URI', target), (2, 'REQUEST_BODY', 'request-marker'), (3, 'RESPONSE_HEADERS:Content-Type', 'text/plain'), (4, 'RESPONSE_BODY', 'response-marker')]:
        action = 'deny,status:403' if name == f'p{phase}-deny' or phase == 4 and name == 'p4-deny-safe' else 'pass'
        if phase == 3:
            rules += f'SecRule REQUEST_URI "@streq /{target}" "id:{1900000+index*10+phase},phase:3,{action},log,t:none,chain,msg:\'I12 Envoy P3\'"\n'
            rules += f'SecRule {variable} "@contains {marker}" "t:none"\n'
        else:
            rules += f'SecRule {variable} "@contains {marker}" "id:{1900000+index*10+phase},phase:{phase},{action},log,t:none,msg:\'I12 Envoy P{phase}\'"\n'
    check_rules(rules)
    return rules


def configure_fixture(fixture, route, name):
    yaml = (fixture / ENVOY_CONFIG).read_text()
    if route != 'ext-proc':
        yaml = yaml.replace('max_request_bytes: 33', 'max_request_bytes: ' + ('32' if name.startswith('host-') else '4096'))
        if name == 'host-partial': yaml = yaml.replace('allow_partial_message: false', 'allow_partial_message: true')
        if name == 'missing-lease':
            yaml = replace_once(yaml, '              metadata_options:\n                forwarding_namespaces:\n                  untyped:\n                  - envoy.filters.http.ext_authz\n', '')
    (fixture / ENVOY_CONFIG).write_text(yaml)


def write_fixture_sources(fixture, content, route, source_proof, build_proof):
    for filename, value in [(DRIVER_FILE, driver_source(content(DRIVER_FILE))), (CLIENT_FILE, client_source(content(CLIENT_FILE))), (BACKEND_FILE, backend_source(content('backend-extproc.py' if route == 'ext-proc' else BACKEND_FILE))), ('sdk-who.c', content('sdk-who.c')), ('cc-wrapper.sh', content('cc-wrapper.sh')), ('cxx-wrapper.sh', content('cxx-wrapper.sh'))]:
        (fixture / filename).write_text(value)
        if filename.endswith('.sh'): (fixture / filename).chmod(0o700)
    write(fixture / 'scoped-product-source-a9.json', source_proof)
    write(fixture / 'actual-build-provenance-v1.json', build_proof)


def generate_tls(fixture):
    command = ['rtk', 'proxy', 'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1', '-keyout', str(fixture / 'loopback.key'), '-out', str(fixture / 'loopback.crt')]
    result = subprocess.run(command, capture_output=True, timeout=30, check=False)
    if result.returncode: raise RuntimeError('synthetic TLS generation failed')


def fixture_admission(fixture, label, shape, status, backend, bindings):
    source_binding, artifact_binding = bindings
    fixture_binding = seal_tree(fixture) | {'target': '/mnt/fixtures'}
    admission_spec = {'mode': 'nonroot', 'timeout_seconds': 120, 'setup_timeout_seconds': 120,
                      'resource_limits': {'memory_bytes': 3221225472, 'processes': 384, 'output_bytes': 2147483648},
                      'argv': ['/usr/local/bin/python3', '-P', '/mnt/fixtures/driver.py'],
                      'bindings': [source_binding, artifact_binding, fixture_binding],
                      'environment': {'CONNECTOR_ROOT': '/mnt/src'}}
    spec_path = fixture.parent / (label + '-admission.json')
    write(spec_path, admission_spec)
    spec_path.chmod(0o444)
    return {'label': label, 'route': shape['leg'], 'spec': str(spec_path), 'expected_http_status': status,
            'expected_target_backend': backend, 'qualification': 'unreviewed_capture_input'}


def prepare_fixture(args, context, index, scenario):
    run, old, content, source_proof, build_proof, bindings = context
    route, name, status, backend = scenario
    label = route + '-' + name
    fixture = run / 'host-fixtures' / label
    fixture.mkdir(parents=True)
    template = fixture_template(old, route)
    for filename in (ENVOY_CONFIG, 'native.conf', 'extproc-service.json'):
        if (template / filename).is_file():
            shutil.copyfile(template / filename, fixture / filename)
    shape = scenario_shape(template, args.parent_sha, label, name, status, backend)
    write(fixture / 'shape.json', shape)
    (fixture / 'native.rules').write_text(scenario_rules(name, index, shape['target']))
    configure_fixture(fixture, route, name)
    write_fixture_sources(fixture, content, route, source_proof, build_proof)
    generate_tls(fixture)
    return fixture_admission(fixture, label, shape, status, backend, bindings)


def prepare(args):
    run, old, source, build_proof = preparation_inputs(args)
    content = capture_content(args.parent_sha, build_proof.get('envoy_registry_adapter'))
    isolated, controller = prepare_controller(run, old)
    bindings = prepare_shared_inputs(run, old, source, args.binaries)
    source_proof = source_binding_proof(source, build_proof, args.parent_sha)
    context = run, old, content, source_proof, build_proof, bindings
    matrix = []
    for index, scenario in enumerate(scenarios()):
        label = scenario[0] + '-' + scenario[1]
        if args.only and label not in args.only:
            continue
        matrix.append(prepare_fixture(args, context, index, scenario))
    write(run / 'host-scenarios.json', {'parent_sha': args.parent_sha, 'controller': str(isolated / controller.name),
          'controller_original_sha256': OLD_CONTROLLER_SHA, 'controller_sha256': sha(isolated / controller.name),
          'only_controller_change': 'task run root relocation and verified PID namespace FD lifetime pin until cleanup; all admission, UID, caps, namespaces, containment, budgets and cleanup checks unchanged',
          'capture_manifest_sha256': sha(HERE.parent / 'manifest.json'),
          'envoy_registry_adapter': content.registry_adapter, 'scenarios': matrix})
    print(json.dumps({'scenarios': len(matrix), 'matrix': str(run / 'host-scenarios.json')}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('run-root', 'historical', 'source', 'binaries', 'build-receipt'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--parent-sha', required=True)
    parser.add_argument('--only', action='append', default=[])
    args = parser.parse_args()
    if not re.fullmatch('[a-f0-9]{40}', args.parent_sha): parser.error('full Parent SHA required')
    prepare(args)


if __name__ == '__main__':
    main()
