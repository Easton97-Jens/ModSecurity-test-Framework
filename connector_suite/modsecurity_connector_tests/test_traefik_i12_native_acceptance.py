"""Focused producer controls, including real FD and short-write failure paths."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import textwrap
from types import SimpleNamespace
import unittest
from unittest import mock

REPO = connector_root()


from modsecurity_connector_ci.runtime.lifecycle.i12.capture_sources import Registry
from modsecurity_connector_ci.lib.i12_process_observation import ProcessObservation

NATIVE = REPO / 'connectors/traefik/harness/i12/native'
EXTERNAL = Path(os.environ.get('CODEX_TEMP_ROOT', '/var/tmp/codex/ModSecurity-conector')) / 'native-acceptance-tests'


def load(name):
    module = load_source(NATIVE / (name + '.py'))
    return module


PROBE = r'''
#define _POSIX_C_SOURCE 200809L
#include "msconnector/generic_mapper.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
int msconnector_generic_map_request(const msconnector_generic_request_source *s,
 const msconnector_request_mapper_contract *c, msconnector_request *o, char *e, size_t n) {
 (void)s;(void)c;(void)o;(void)e;(void)n;return 1;
}
extern const msconnector_request *i12_acceptance_native_request(const msconnector_request *, msconnector_request *);
extern void i12_acceptance_native_created(void *);
extern void i12_acceptance_native_released(void *);
extern int i12_acceptance_native_transaction_result(void *, const char *, int);
static int first_result, second_result, wrong_result;
static void *response_thread(void *pointer) {
 wrong_result=i12_acceptance_native_transaction_result((void *)"other", "append_response_body", 0);
 first_result=i12_acceptance_native_transaction_result(pointer,"append_response_body",0);
 second_result=i12_acceptance_native_transaction_result(pointer,"append_response_body",0);
 return NULL;
}
int main(int argc, char **argv) {
 const char *line="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n";
 FILE *stream;int descriptor,put,flushed,closed,p_errno,f_errno,c_errno,recovered=-2;
 if(argc==3) {
  msconnector_request request={0},changed;
  const msconnector_request *selected_request;
  pthread_t thread;int target=0;int result;
  request.uri=argv[2];
  selected_request=i12_acceptance_native_request(&request,&changed);
  i12_acceptance_native_created(&target);
  if(strcmp(argv[1],"response")==0) {
   if(pthread_create(&thread,NULL,response_thread,&target)!=0)return 5;
   if(pthread_join(thread,NULL)!=0)return 6;
   i12_acceptance_native_released(&target);
   result=i12_acceptance_native_transaction_result(&target,"append_response_body",0);
   printf("{\"first\":%d,\"second\":%d,\"wrong\":%d,\"released\":%d}\n",first_result,second_result,wrong_result,result);
  } else {
   result=i12_acceptance_native_transaction_result(&target,strcmp(argv[1],"response-header")==0?"process_response_headers":"process_request_headers",0);
   printf("{\"original_headers\":%zu,\"original_body\":%zu,\"selected_headers\":%zu,\"selected_body\":%zu,\"result\":%d}\n",request.header_count,request.body.size,selected_request->header_count,selected_request->body.size,result);
  }
  return 0;
 }
 if(argc!=2)return 2;
 descriptor=openat(AT_FDCWD,argv[1],O_WRONLY|O_CREAT|O_APPEND,0600);
 if(descriptor<0){printf("{\"open\":-1,\"errno\":%d}\n",errno);return 0;}
 stream=fdopen(descriptor,"a");if(stream==NULL)return 3;
 if(setvbuf(stream,NULL,_IOLBF,0)!=0)return 4;
 put=fputs(line,stream);p_errno=errno;
 flushed=fflush(stream);f_errno=errno;
 if(getenv("I12_ACCEPTANCE_VERIFY_RECOVERY")!=NULL) { recovered=fputs("RECOVERED\n",stream);(void)fflush(stream); }
 closed=fclose(stream);c_errno=errno;
 printf("{\"put\":%d,\"put_errno\":%d,\"flush\":%d,\"flush_errno\":%d,\"close\":%d,\"close_errno\":%d,\"recovered\":%d}\n",
 put,p_errno,flushed,f_errno,closed,c_errno,recovered);return 0;
}
'''


class NativeLoopbackAdmissionControls(unittest.TestCase):
    def test_case_execution_keeps_neighbor_rotation_state_and_callbacks(self):
        with mock.patch.dict(sys.modules, {'base_driver': SimpleNamespace()}):
            driver = load('acceptance_driver')
        created = {'batch_index': 0, 'pid': 123, 'native_log_start': 0}
        start = mock.Mock(return_value=created)
        stop = mock.Mock()
        runtime = SimpleNamespace(neighbor_uses=0, neighbor_batch=None,
            lifecycle_path=Path('unused-native.jsonl'), neighbor_socket=Path('unused.sock'),
            start_neighbor_batch=start, stop_neighbor_batch=stop)
        execution = driver.CaseExecution({}, runtime)
        execution.fixture = {}
        execution.result = {}
        with mock.patch.object(driver.base, 'write', create=True) as write:
            execution.prepare_neighbor()
        start.assert_called_once_with(0)
        stop.assert_not_called()
        write.assert_called_once_with('neighbor-batch-0-start.json', created)
        self.assertIs(runtime.neighbor_batch, created)
        self.assertIs(execution.result['neighbor_batch'], created)
        self.assertEqual(runtime.neighbor_uses, 1)

    def test_backend_manifest_rejects_other_paths_and_symlinks(self):
        backend = load('acceptance_backend')
        EXTERNAL.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.TemporaryDirectory(prefix='manifest-admission-', dir=EXTERNAL) as directory:
            root = Path(directory)
            manifest = root / 'acceptance-manifest.json'
            manifest.write_text('{"cases": []}')
            with mock.patch.object(backend, 'MANIFEST', str(manifest)):
                self.assertEqual(backend.manifest_cases(str(manifest)), {'cases': []})
                noncanonical_path = str(root / '..' / manifest.name)
                with self.assertRaises(ValueError):
                    backend.manifest_cases(noncanonical_path)
                target = root / 'target.json'
                target.write_text('{"cases": []}')
                manifest.unlink()
                manifest.symlink_to(target)
                symlink_path = str(manifest)
                with self.assertRaises(ValueError):
                    backend.manifest_cases(symlink_path)

    def test_backend_closes_nonloopback_peer_before_recording_or_body_reads(self):
        backend = load('acceptance_backend')
        server = object.__new__(backend.Backend)
        server.socket = mock.Mock()
        connection = mock.Mock()
        with mock.patch.object(server.socket, 'accept',
                return_value=(connection, ('192.0.2.1', 2000))), mock.patch.object(backend, 'record') as recorded:
            with self.assertRaises(OSError):
                server.get_request()
        connection.close.assert_called_once_with()
        connection.settimeout.assert_not_called()
        recorded.assert_not_called()

    def test_backend_port_admission_is_bounded(self):
        backend = load('acceptance_backend')
        for value in ('0', '-1', '65536', 'not-a-port'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                backend.bounded_port(value)
        self.assertEqual(backend.bounded_port('65535'), 65535)

    def test_backend_bind_failure_closes_transport_and_rejects_external_binds(self):
        backend = load('acceptance_backend')
        for address in (('0.0.0.0', 0), ('192.0.2.1', 80), ('127.0.0.1', -1)):
            with self.subTest(address=address), self.assertRaises(ValueError):
                backend.Backend(address, backend.Handler)
        transport = mock.Mock()
        transport.bind.side_effect = OSError('bind unavailable')
        with mock.patch.object(backend.socket, 'socket', return_value=transport):
            with self.assertRaises(OSError):
                backend.Backend(('127.0.0.1', 0), backend.Handler)
        transport.close.assert_called_once_with()

    def test_backend_serves_concurrent_loopback_connections_and_closes_socket(self):
        backend = load('acceptance_backend')
        both_arrived = threading.Barrier(2)

        class ConcurrentHandler(backend.socketserver.BaseRequestHandler):
            def handle(self):
                both_arrived.wait(timeout=2)
                self.request.sendall(b'complete')

        server = backend.Backend(('127.0.0.1', 0), ConcurrentHandler)
        server.root = EXTERNAL
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01})
        thread.start()
        try:
            with mock.patch.object(backend, 'record') as recorded:
                with socket.create_connection(server.server_address, timeout=2) as first:
                    with socket.create_connection(server.server_address, timeout=2) as second:
                        for connection in (first, second):
                            self.assertEqual(connection.recv(8), b'complete')
                            self.assertEqual(connection.recv(1), b'')
                self.assertEqual(recorded.call_count, 2)
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()
        self.assertFalse(thread.is_alive())
        self.assertEqual(server.fileno(), -1)


class NativePrivateToolchainControls(unittest.TestCase):
    def setUp(self):
        EXTERNAL.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.temporary = tempfile.TemporaryDirectory(prefix='private-go-', dir=EXTERNAL)
        self.root = Path(self.temporary.name)
        self.prepare = load('prepare')
        self.acceptance = load('acceptance_prepare')
        self.toolchain = self.root / 'toolchain'
        (self.toolchain / 'bin').mkdir(parents=True)
        (self.toolchain / 'VERSION').write_text('go1.27.2\ntime 2026-10-01T00:00:00Z\n')
        (self.toolchain / 'bin/go').write_bytes(b'unit-test-go-executable')
        (self.toolchain / 'bin/go').chmod(0o700)
        self.fake_sha = hashlib.sha256(b'unit-test-go-executable').hexdigest()

    def tearDown(self):
        self.temporary.cleanup()

    def test_exact_production_go_identity_and_regular_tree_copy(self):
        self.assertEqual(self.prepare.GO_SHA256,
            '548d3c32f83fa81152f543eb1526be7884cfe0526eb5e9ce29d3eca14786e7e0')
        with mock.patch.object(self.prepare, 'GO_SHA256', self.fake_sha):
            inventory = self.prepare.validate_private_toolchain(self.toolchain)
            receipt = self.prepare.stage_private_toolchain(self.toolchain, self.root / 'artifacts', inventory)
        self.assertEqual(receipt['files'], inventory)
        self.assertFalse(receipt['system_toolchain_changed'])
        self.assertEqual(receipt['namespace_root'], '/mnt/artifacts/toolchains/go1.27.2')
        copied = self.root / 'artifacts/toolchains/go1.27.2'
        self.assertEqual((copied / 'bin/go').read_bytes(), (self.toolchain / 'bin/go').read_bytes())

    def test_wrong_version_hash_and_missing_executable_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            self.prepare.validate_private_toolchain(self.toolchain)
        with mock.patch.object(self.prepare, 'GO_SHA256', self.fake_sha):
            (self.toolchain / 'VERSION').write_text('go1.27.1\n')
            with self.assertRaisesRegex(ValueError, 'VERSION'):
                self.prepare.validate_private_toolchain(self.toolchain)
            (self.toolchain / 'VERSION').write_text('go1.27.2\n')
            (self.toolchain / 'bin/go').chmod(0o600)
            with self.assertRaisesRegex(ValueError, 'executable'):
                self.prepare.validate_private_toolchain(self.toolchain)

    def test_source_symlinks_special_files_and_copy_mutation_are_rejected(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.toolchain, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'physical'):
            self.prepare.validate_private_toolchain(alias)
        with mock.patch.object(self.prepare, 'GO_SHA256', self.fake_sha):
            extra = self.toolchain / 'linked'
            extra.symlink_to(self.toolchain / 'VERSION')
            with self.assertRaisesRegex(ValueError, 'nonsymlink'):
                self.prepare.validate_private_toolchain(self.toolchain)
            extra.unlink()
            os.mkfifo(extra)
            with self.assertRaisesRegex(ValueError, 'regular'):
                self.prepare.validate_private_toolchain(self.toolchain)
            extra.unlink()
            inventory = self.prepare.validate_private_toolchain(self.toolchain)
            (self.toolchain / 'additional').write_text('changed after validation')
            with self.assertRaisesRegex(ValueError, 'changed during copy'):
                self.prepare.stage_private_toolchain(self.toolchain, self.root / 'changed-artifacts', inventory)

    def test_copy_does_not_follow_a_new_symlink_after_source_validation(self):
        with mock.patch.object(self.prepare, 'GO_SHA256', self.fake_sha):
            inventory = self.prepare.validate_private_toolchain(self.toolchain)
            (self.toolchain / 'new-link').symlink_to(self.toolchain / 'VERSION')
            with self.assertRaisesRegex(ValueError, 'nonsymlink'):
                self.prepare.stage_private_toolchain(self.toolchain, self.root / 'linked-artifacts', inventory)

    def test_invalid_toolchain_is_rejected_before_output_is_created(self):
        output = self.root / 'no-output'
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            self.prepare.prepare(REPO, self.root / 'historical', output, self.toolchain)
        self.assertFalse(output.exists())

    def central_driver(self):
        registry = Registry()
        identity = registry.manifest['profiles']['traefik-native']['capture_files']['drivers/driver.py']['sha256']
        return registry.content(identity).decode('utf-8')

    def test_driver_exact_once_offline_contract_and_pre_host_guard(self):
        text = self.acceptance.instrument_private_toolchain(self.central_driver())
        compile(text, 'private-go-base-driver.py', 'exec')
        self.assertNotIn('/usr/local/go/bin/go', text)
        self.assertEqual(text.count('GO_SHA256 = '), 1)
        self.assertEqual(text.count("execute('go-toolchain-version'"), 1)
        for token in ("GOROOT='/mnt/artifacts/toolchains/go1.27.2'", "GOENV='off'", "GOWORK='off'",
                      "GOTOOLCHAIN='local'", "GOPROXY='off'", "GOSUMDB='off'"):
            self.assertIn(token, text)
        self.assertLess(text.index('actual_go_sha256 != GO_SHA256'), text.index("execute('go-toolchain-version'"))
        self.assertLess(text.index("write('go-toolchain-binding.json'"), text.index('helper.stage_native_runtime(inputs)'))
        with self.assertRaises(ValueError):
            self.acceptance.instrument_private_toolchain(text)
        changed_driver = self.central_driver().replace("GO='/usr/local/go/bin/go'", "GO='/other/go'")
        with self.assertRaises(ValueError):
            self.acceptance.instrument_private_toolchain(changed_driver)

    def test_driver_rejects_inherited_toolchain_and_changed_controller_path(self):
        text = self.acceptance.instrument_private_toolchain(self.central_driver())
        start = text.index("    if any(key.startswith('GO')")
        end = text.index('    env.update(', start)
        selection = textwrap.dedent(text[start:end])
        allowed = {'PATH': '/opt/controller:/usr/local/bin:/usr/bin:/usr/sbin:/bin'}
        for bad in ({'GO': '/evil/go'}, {'GOROOT': '/evil'}, {'GOTOOLCHAIN': 'auto'},
                    {'GOENV': '/evil/config'}, {'GOPROXY': 'https://example.invalid'}, {'PATH': '/evil'}):
            with self.subTest(environment=bad), mock.patch.dict(os.environ, allowed | bad, clear=True):
                with self.assertRaisesRegex(RuntimeError, 'unchanged controller'):
                    exec(selection, {'os': os})
        with mock.patch.dict(os.environ, allowed, clear=True):
            namespace = {'os': os}
            exec(selection, namespace)
            self.assertEqual(namespace['env'], allowed)

    def test_transformed_environment_preserves_controller_rtk_lookup(self):
        text = self.acceptance.instrument_private_toolchain(self.central_driver())
        start = text.index('    env.update(')
        end = text.index("    go_root = Path(env['GOROOT'])", start)
        namespace = {'env': {}, 'host': self.root / 'host'}
        exec(textwrap.dedent(text[start:end]), namespace)
        environment = namespace['env']
        self.assertEqual(environment['PATH'],
            '/mnt/artifacts/toolchains/go1.27.2/bin:/opt/controller:/usr/local/bin:/usr/bin:/usr/sbin:/bin')
        self.assertEqual(environment['GO'], '/mnt/artifacts/toolchains/go1.27.2/bin/go')
        controller = self.root / 'controller'
        controller.mkdir()
        proxy = controller / 'rtk'
        proxy.write_text('#!/bin/sh\nexit 0\n')
        proxy.chmod(0o700)
        lookup_path = environment['PATH'].replace('/mnt/artifacts/toolchains/go1.27.2', str(self.toolchain))
        lookup_path = lookup_path.replace('/opt/controller', str(controller))
        self.assertEqual(shutil.which('rtk', path=lookup_path), str(proxy))
        self.assertEqual(shutil.which('go', path=lookup_path), str(self.toolchain / 'bin/go'))

    def test_runtime_receipt_requires_actual_version_root_and_hash(self):
        text = self.acceptance.instrument_private_toolchain(self.central_driver())
        guard = textwrap.dedent(text[text.index("    go_root = Path(env['GOROOT'])"):text.index('    rules = [')])
        environment = {'GO': str(self.toolchain / 'bin/go'), 'GOROOT': str(self.toolchain),
            'GOTOOLCHAIN': 'local', 'GOPROXY': 'off', 'GOSUMDB': 'off', 'GOENV': 'off', 'GOWORK': 'off'}
        for wrong in ('hash', 'version', 'root', None):
            calls, receipts = [], []
            def execute(label, argv, env):
                calls.append(label)
                value = 'go version go1.27.2 linux/amd64\n' if label.endswith('version') else str(self.toolchain) + '\ngo1.27.2\n'
                if wrong == 'version' and label.endswith('version'):
                    value = 'go version go1.27.1 linux/amd64\n'
                if wrong == 'root' and label.endswith('environment'):
                    value = '/other/root\ngo1.27.2\n'
                (self.root / (label + '.stdout')).write_text(value)
            namespace = {'env': environment, 'Path': Path, 'TASK': self.root, 'execute': execute,
                'write': lambda name, value: receipts.append((name, value)),
                'digest': self.prepare.sha, 'GO_SHA256': 'wrong' if wrong == 'hash' else self.fake_sha}
            if wrong:
                with self.assertRaises(RuntimeError):
                    exec(guard, namespace)
                self.assertEqual(receipts, [])
                if wrong == 'hash':
                    self.assertEqual(calls, [])
            else:
                exec(guard, namespace)
                self.assertEqual(receipts[0][0], 'go-toolchain-binding.json')
                self.assertEqual(receipts[0][1]['go_sha256'], self.fake_sha)
                self.assertTrue(receipts[0][1]['verified_before_host_execution'])


class NativeAcceptanceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root

        storage = validate_output_root(REPO, Path(
            os.environ.get('I12_TEST_ROOT') or os.environ['RUNNER_TEMP']))
        cls.temporary = tempfile.TemporaryDirectory(prefix='controls-', dir=storage)
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.plan = load('acceptance_plan')
        cls.client = load('acceptance_client')
        cls.binary = None
        cls._native_probe_checked = False
        cls._native_probe_error = None

    @classmethod
    def ensure_native_probe(cls):
        if cls._native_probe_error is not None:
            raise AssertionError(cls._native_probe_error)
        if cls._native_probe_checked:
            return
        cls._native_probe_checked = True
        compiler = shutil.which('gcc')
        if compiler:
            source = cls.root / 'probe.c'
            source.write_text(PROBE)
            cls.binary = cls.root / 'probe'
            symbols = ('openat', 'setvbuf', 'fputs', 'fflush', 'fclose', 'msconnector_generic_map_request')
            command = [compiler, '-std=c17', '-pthread', '-Wall', '-Wextra', '-Werror', '-I', str(REPO / 'common/include'),
                       str(source), str(NATIVE / 'acceptance_faults.c'),
                       *('-Wl,--wrap=' + symbol for symbol in symbols), '-o', str(cls.binary)]
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            if result.returncode:
                cls._native_probe_error = result.stderr
                raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_all118_input_ids_remain_distinct_and_unqualified(self):
        framework = self.root / 'framework'
        (framework / 'tests/rules').mkdir(parents=True, exist_ok=True)
        (framework / 'tests/rules/no-crs-baseline.conf').write_text('SecRuleEngine On\n')
        rows, proposals = [], []
        for index in range(118):
            special = ['event_json_limit', 'NEED-request-charset-present', 'NEED-request-charset-missing', 'NEED-response-charset-present', 'NEED-response-charset-missing', 'response_short_write_resume', 'response_write_would_block_resume']
            name = special[index] if index < len(special) else 'case-' + str(index)
            identifier = self.plan.PREFIX + name
            contract = {'case_id': name, 'expected_oracle': {'native_result': 'allow', 'visible_status': 200}}
            rows.append({'route': self.plan.ROUTE, 'id': identifier, 'classification': 'runtime',
                'original124_member': index < 55, 'original_contract': contract,
                'original_catalog_case': {'case_id': name, 'phase': 1, 'request': {}}})
            if index < 55:
                proposals.append({'id': identifier, 'route': self.plan.ROUTE,
                    'fixture': self.plan.default_fixture() | {'rules_lines': ['SecRuleEngine On']},
                    'expected': {'native_result': 'allow', 'visible_status': 200}})
        result = self.plan.build({'rows': rows}, {'rows': proposals}, framework)
        self.assertEqual([r['id'] for r in result['cases']], [r['id'] for r in rows])
        self.assertEqual(len({r['transaction_id'] for r in result['cases']}), 118)
        readiness = [value for row in result['cases'] + result['supplementary_executions'] for value in row['readiness_ids']]
        self.assertEqual(len(readiness), len(set(readiness)))
        self.assertTrue(all(r['qualification'] is None and not r['expected_approval'] for r in result['cases']))
        self.assertEqual(len(result['supplementary_executions']), 15)
        variant = result['supplementary_executions'][0]
        self.assertEqual(variant['id'], result['cases'][0]['id'])
        self.assertNotEqual(variant['key'], result['cases'][0]['key'])
        self.assertIsNone(variant['expected'])
        self.assertEqual(variant['fixture']['max_event_json_bytes'], 1024)
        self.assertEqual(len(result['cases']), 118)
        charset = [v for v in result['supplementary_executions'] if '-cs-' in v['key']]
        self.assertEqual(len({v['key'] for v in charset}), 12)
        self.assertTrue(all(v['id'] in {r['id'] for r in result['cases']} for v in charset))
        self.assertTrue(all(v['expected'] is None and not v['expected_approval'] for v in charset))
        backpressure = [v for v in result['supplementary_executions'] if v['key'].endswith('-bp8m')]
        self.assertEqual(len(backpressure), 2)
        for v in backpressure:
            self.assertEqual(len(bytes.fromhex(v['fixture']['backend']['body_hex'])), 8 * 1024 * 1024 + len(b'no-crs-response-body-marker'))
            self.assertEqual(sum(v['fixture']['backend']['chunk_lengths']), 8 * 1024 * 1024 + len(b'no-crs-response-body-marker'))
            self.assertEqual(v['fixture']['backend']['chunk_lengths'][0], 8192)
            self.assertTrue(v['fixture']['backend']['barrier'])
            self.assertTrue(v['fixture']['request']['kernel_backpressure'])
            self.assertFalse(v['fixture']['request']['slow_reader'])
            self.assertIn('SecResponseBodyLimit 16777216', v['fixture']['rules_lines'])
            self.assertIsNone(v['expected'])
        for v in charset:
            response = 'NEED-response' in v['id']
            side = v['fixture']['backend' if response else 'request']
            self.assertIn(side['body_hex'], ('636166e9', '636166c3a9'))
            self.assertEqual(v['fixture_sha256'], self.plan.json_digest(v['fixture']))
            self.assertIn(r'@rx \xE9', '\n'.join(v['fixture']['rules_lines']))

    def test_canonical_runner_directives_do_not_replace_shared_baseline_rules(self):
        framework = self.root / 'fixture-baseline'
        fixture = framework / 'tests/cases/no-crs-baseline/deny.yaml'
        fixture.parent.mkdir(parents=True, exist_ok=True)
        fixture.write_text('rules: |\n  SecRuleEngine On\n  SecAuditEngine RelevantOnly\nrequest:\n')
        baseline = 'SecRuleEngine On\nSecRule REQUEST_HEADERS:X-Modsec-Smoke "@streq block" "id:1100001,phase:1,deny,status:403"\n'
        case = {'case_id': 'deny_header_marker_403', 'phase': 1, 'request': {'headers': [
            {'name': 'X-Modsec-Smoke', 'value': 'block'}]}}
        row = {'original_catalog_case': case, 'original_contract': {
            'runner_case': str(fixture.relative_to(framework))}}
        result = self.plan.canonical_fixture(row, {case['case_id']: case}, framework, baseline)
        rules = '\n'.join(result['rules_lines'])
        self.assertIn('id:1100001,phase:1,deny,status:403', rules)
        self.assertIn('SecAuditEngine RelevantOnly', rules)
        self.assertEqual(rules.count('id:1100001'), 1)

    def test_canonical_yaml_wire_preserves_literal_chunks_limits_and_content_type_variants(self):
        framework = test_root()
        base = framework / 'tests/cases/no-crs-baseline/full-lifecycle'
        fixtures = [
            ('phase2_body_limits', 'POST', '/no-crs/full-lifecycle/request-limit', [], b'0123456789abcdef'),
            ('phase2_marker_split_across_chunks', 'POST', '/no-crs/full-lifecycle/request-chunks', [15, 11], b'no-crs-request-body-marker'),
            ('phase4_marker_split_across_chunks', 'GET', '/no-crs/full-lifecycle/response-chunks', [16, 11], b'no-crs-response-body-marker'),
            ('phase4_late_intervention', 'GET', '/no-crs/full-lifecycle/late-intervention', [7, 27], b'prefix no-crs-response-body-marker'),
            ('phase4_first_byte_before_response_end', 'GET', '/no-crs/full-lifecycle/first-byte', [18, 27], b'first-byte-prefix no-crs-response-body-marker'),
        ]
        for name, method, uri, chunks, body in fixtures:
            path = base / (name + '.yaml')
            self.assertTrue(path.is_file())
            with self.subTest(fixture=name):
                case = {'case_id': name, 'phase': 4 if name.startswith('phase4') else 2, 'request': {}}
                row = {'original_catalog_case': case, 'original_contract': {'runner_case': str(path.relative_to(framework))}}
                value = self.plan.canonical_fixture(row, {name: case}, framework, 'SecRuleEngine On')
                self.assertEqual(value['request']['method'], method)
                self.assertEqual(value['request']['uri'], uri)
                side = value['backend' if name.startswith('phase4') else 'request']
                self.assertEqual(bytes.fromhex(side['body_hex']), body)
                self.assertEqual(side['chunk_lengths'], chunks)
                if method == 'POST':
                    self.assertIn(['Content-Type', 'text/plain'], side['headers'])
        content = base / 'phase4_content_type.yaml'
        self.assertTrue(content.is_file())
        for variant, expected in [('out_of_scope', 'image/png'), ('missing', None)]:
            case = {'case_id': 'content-' + variant, 'phase': 4, 'request': {'content_type_variant': variant}}
            value = self.plan.canonical_fixture({'original_catalog_case': case, 'original_contract': {'runner_case': str(content.relative_to(framework))}}, {case['case_id']: case}, framework, '')
            types = [v for k, v in value['backend']['headers'] if k.lower() == 'content-type']
            self.assertEqual(types, [] if expected is None else [expected])

    def test_backpressure_wait_releases_only_exact_measured_tuple_or_timeout(self):
        path = self.root / 'syscall-selection.jsonl'
        row = {'schema': 'traefik-own-child-syscall-v1', 'nonce': 'case-nonce',
               'local_address': '127.0.0.1', 'local_port': 8000,
               'peer_address': '127.0.0.1', 'peer_port': 40000,
               'fd_identity_unchanged': True, 'kernel_result': -11, 'errno': 11}
        wrong = [row | {'nonce': 'wrong-case'}, row | {'peer_port': 40001},
                 row | {'fd_identity_unchanged': False}, row | {'kernel_result': 7}]
        path.write_text(''.join(json.dumps(value) + '\n' for value in wrong))
        result = self.client.await_kernel_backpressure(path, 'case-nonce', ['127.0.0.1', 40000], ['127.0.0.1', 8000], timeout=0.03)
        self.assertIsNone(result['observed_eagain'])
        self.assertEqual(result['release_reason'], 'bounded_timeout')
        def emit_fresh_row():
            time.sleep(0.02)
            row['exit_monotonic_ns'] = time.monotonic_ns()
            with path.open('a') as stream:
                stream.write(json.dumps(row) + '\n')
        thread = threading.Thread(target=emit_fresh_row)
        thread.start()
        result = self.client.await_kernel_backpressure(path, 'case-nonce', ['127.0.0.1', 40000], ['127.0.0.1', 8000], timeout=0.2)
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result['observed_eagain'], row)
        self.assertEqual(result['release_reason'], 'actual_target_tuple_eagain')

    def test_retained_packet_requires_header_pid_scope_time_and_sdk_rule_proof(self):
        adapter = load('acceptance_packet')
        root = self.root / 'retained-joined'
        root.mkdir()
        request = root / 'request.raw'
        request.write_bytes(b'POST / HTTP/1.1\r\nContent-Type: text/plain\r\n\r\nabc')
        (root / 'rules.conf').write_text('SecRule REQUEST_BODY "@contains abc" "id:123,phase:2,deny"\n')
        (root / 'debug.log').write_text('[retained-tx] [/] [4] (Rule: 123) Executing operator "Contains" with param "abc" against REQUEST_BODY.\n')
        case = {'id': 'I12::traefik-native-uds::NEED-request-mime-scope-in'}
        rows = [{'pid': 23, 'call': 5, 'function': 'native_append_request_body', 'edge': edge,
                 'invalid': False, 'monotonic_ns': stamp} for edge, stamp in [('enter', 140), ('return', 160)]]
        proof = {'client': {'started_ns': 100, 'completed_ns': 200}, 'before': {'processes': {'engine': {'pid': 23}}},
                 'request_path': request, 'response_path': root / 'absent.response', 'associated': rows,
                 'all_native': rows, 'scopes': {(23, 9)}, 'transaction_id': 'retained-tx'}
        retained = {'operation': 'native_retained_body', 'pid': 24, 'allocation_scope_call': 9,
            'retained_body_bytes': 3, 'native_method': 'append_request_body', 'accessor': 'msc_get_request_body_length',
            'injected': False, 'monotonic_ns': 150}
        faults = root / 'faults.jsonl'
        faults.write_text(json.dumps(retained) + '\n')
        self.assertIsNone(adapter.body_selection_candidate(case, root, proof))
        retained['pid'] = 23
        faults.write_text(json.dumps(retained) + '\n')
        value = adapter.body_selection_candidate(case, root, proof)
        self.assertEqual(value['actual_retained_body_records'], [retained])
        self.assertEqual(value['actual_content_type_headers'], ['text/plain'])
        self.assertEqual(value['selection_interpretation'], 'sdk_rule_operator_execution_observed')
        self.assertEqual(value['root_approval'], 'pending')
        self.assertFalse(value['retained_is_inspected'])
        self.assertFalse(value['inspection_byte_count_claimed'])
        self.assertNotIn('body_bytes_inspected', value)
        retained['monotonic_ns'] = 300
        faults.write_text(json.dumps(retained) + '\n')
        self.assertIsNone(adapter.body_selection_candidate(case, root, proof))
        retained['monotonic_ns'] = 150
        faults.write_text(json.dumps(retained) + '\n')
        request.unlink()
        self.assertIsNone(adapter.body_selection_candidate(case, root, proof))

    def test_generated_packet_join_requires_exact_admission_and_one_physical_allocation(self):
        adapter = load('acceptance_packet')
        case = {'key': '004-b044cc412aca', 'id': 'I12::traefik-native-uds::transaction_id_generated_or_fallback',
                'fixture': {'request': {'omit_transaction_id': True}}}
        admission = {'generated_id_child_environment': {'name': 'I12_NATIVE_GENERATED_CASE',
            'present': True, 'value': case['key'], 'dedicated_host': True}}
        before = {'processes': {'engine': {'pid': 23}}}
        client = {'started_ns': 100, 'completed_ns': 200}
        native = [{'pid': 23, 'monotonic_ns': 150, 'function': 'native_new_with_id', 'edge': 'return',
            'result': 1, 'invalid': False, 'allocation_scope_call': 9, 'transaction_id': 'actual-sdk-id',
            'transaction_id_origin': 'sdk_public_m_id'},
            {'pid': 23, 'invalid': False, 'allocation_scope_call': 9, 'allocation_join_verified': True}]
        raw = b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n'
        result = adapter.generated_join(case, admission, before, client, native, raw)
        self.assertEqual(result['transaction_id'], 'actual-sdk-id')
        self.assertIsNone(result['client_transaction_id'])
        self.assertIsNone(adapter.generated_join(case, {}, before, client, native, raw))
        self.assertIsNone(adapter.generated_join(case | {'key': 'wrong'}, admission, before, client, native, raw))
        self.assertIsNone(adapter.generated_join(case, admission, before, client, native + [native[0]], raw))
        self.assertIsNone(adapter.generated_join(case, admission, {'processes': {'engine': {'pid': 24}}}, client, native, raw))
        self.assertIsNone(adapter.generated_join(case, admission, before, client, native, b'GET / HTTP/1.1\r\nX-Request-Id: injected\r\n\r\n'))

    def test_canonical_reuse_exposes_lossless_source_bound_resolved_request(self):
        parent = {'case_id': 'phase4_body_over_limit', 'runner_case': 'phase4_body_limits.yaml',
                  'request': {'limit_variant': 'over_limit', 'response_body_fixture': 'no-crs-response-body-marker', 'variant_metadata': {'boundary': 16}}}
        child = {'case_id': 'full_lifecycle_event_metadata_bounded', 'phase': 4,
                 'request': {'reuses': parent['case_id'], 'custom_adapter_flag': True}}
        framework = self.root / 'resolved-catalog'
        framework.mkdir()
        result = self.plan.canonical_fixture({'original_catalog_case': child, 'original_contract': {}},
            {parent['case_id']: parent, child['case_id']: child}, framework, 'SecRuleEngine On\n')
        expected = parent['request'] | {'custom_adapter_flag': True}
        self.assertEqual(result['resolved_catalog_request'], expected)
        self.assertEqual(result['resolved_catalog_request_sha256'], self.plan.json_digest(expected))
        sources = result['catalog_request_resolution']['ordered_sources']
        self.assertEqual([row['case_id'] for row in sources], [child['case_id'], parent['case_id']])
        self.assertEqual(sources[1]['catalog_case_sha256'], self.plan.json_digest(parent))
        self.assertEqual(sources[1]['original_request_sha256'], self.plan.json_digest(parent['request']))
        result['resolved_catalog_request']['variant_metadata']['boundary'] = 999
        self.assertEqual(parent['request']['variant_metadata']['boundary'], 16)
        self.assertEqual(sources[1]['original_request']['variant_metadata']['boundary'], 16)

    def test_http_readiness_retries_404_with_unique_ids_and_requires_native_cleanup(self):
        with mock.patch.dict(sys.modules, {'base_driver': SimpleNamespace()}):
            driver = load('acceptance_driver')
        task = self.root / 'http-readiness'
        (task / 'client').mkdir(parents=True)
        trace = task / 'native.jsonl'
        trace.write_text('')
        case = {'key': 'case', 'readiness_ids': ['ready-0', 'ready-1']}
        def write(name, value):
            (task / name).write_text(json.dumps(value))
        def command(label, argv, env, **kwargs):
            self.assertEqual(kwargs['timeout_seconds'], 10)
            index = int(argv[-1].removeprefix('readiness-'))
            key = 'neighbor-readiness-' + str(index) + '-case'
            write('client/' + key + '.receipt.json', {'status': 404 if index == 0 else 200})
            if index:
                with trace.open('a') as stream:
                    for name in ('native_new_with_id', 'native_process_logging', 'native_cleanup'):
                        stream.write(json.dumps({'pid': 50, 'transaction_id': 'ready-1', 'function': name,
                            'edge': 'return', 'result': 1, 'invalid': False}) + '\n')
            return {'actual_unit_command': label}
        driver.TASK = task
        driver.base.write = write
        with mock.patch.object(driver, 'command', side_effect=command):
            result = driver.http_readiness(case, 1234, {}, trace, 99)
        self.assertTrue(result['ready'])
        self.assertFalse(result['qualified_main_control'])
        self.assertEqual([a['actual_status'] for a in result['attempts']], [404, 200])
        self.assertEqual([a['transaction_id'] for a in result['attempts']], ['ready-0', 'ready-1'])
        self.assertEqual(result['attempts'][1]['native_counts']['native_allocations'], 1)
        self.assertEqual(result['attempts'][1]['native_counts']['native_logging_returns'], 1)
        self.assertEqual(result['attempts'][1]['native_counts']['native_logging_successes'], 1)
        self.assertEqual(result['attempts'][1]['native_counts']['native_cleanup_returns'], 1)
        self.assertEqual(len(list((task / 'client').glob('*.receipt.json'))), 2)
        # HTTP200 alone is not native usability. Keep the actual receipt and fail.
        trace.write_text('')
        case = {'key': 'case-missing', 'readiness_ids': ['missing']}
        def no_native(label, argv, env, **kwargs):
            write('client/neighbor-readiness-0-case-missing.receipt.json', {'status': 200})
            return {'actual_unit_command': label}
        with mock.patch.object(driver, 'command', side_effect=no_native), mock.patch.object(driver.time, 'monotonic', side_effect=[0, 0, 0, 30, 30]):
            with self.assertRaisesRegex(RuntimeError, 'readiness deadline'):
                driver.http_readiness(case, 1234, {}, trace, 99)
        self.assertFalse(json.loads((task / 'case-missing-readiness.json').read_text())['ready'])

    def test_readiness_probe_is_limited_by_remaining_global_budget(self):
        with mock.patch.dict(sys.modules, {'base_driver': SimpleNamespace()}):
            driver = load('acceptance_driver')
        task = self.root / 'readiness-last-quarter-second'
        (task / 'client').mkdir(parents=True)
        trace = task / 'native.jsonl'
        trace.write_text('')
        driver.TASK = task
        writes = {}
        driver.base.write = lambda name, value: writes.update({name: value})
        def command(label, argv, env, **kwargs):
            self.assertEqual(kwargs['timeout_seconds'], 0.25)
            (task / 'client/neighbor-readiness-0-budget.receipt.json').write_text(json.dumps({'status': 404}))
            return {'bounded_unit_probe': True}
        with mock.patch.object(driver, 'command', side_effect=command), mock.patch.object(driver.time, 'monotonic', side_effect=[0, 29.75, 30, 30]), mock.patch.object(driver.time, 'sleep') as sleep:
            with self.assertRaisesRegex(RuntimeError, 'readiness deadline'):
                driver.http_readiness({'key': 'budget', 'readiness_ids': ['ready']}, 1234, {}, trace, 99)
        self.assertFalse(writes['budget-readiness.json']['ready'])
        self.assertTrue(all(call.args[0] <= 0 for call in sleep.call_args_list))
        with mock.patch.object(driver, 'command') as exhausted, mock.patch.object(driver.time, 'monotonic', side_effect=[0, 30]):
            with self.assertRaisesRegex(RuntimeError, 'readiness deadline'):
                driver.http_readiness({'key': 'budget', 'readiness_ids': ['ready']}, 1234, {}, trace, 99)
        exhausted.assert_not_called()

    def test_command_accepts_only_finite_positive_fractional_deadlines(self):
        with mock.patch.dict(sys.modules, {'base_driver': SimpleNamespace()}):
            driver = load('acceptance_driver')
        adapter = load('acceptance_packet')
        driver.TASK = self.root
        driver.base.SOURCE = self.root
        driver.base.digest = lambda path: adapter.reference(path, 'unit_source')['sha256']
        driver.base.write = mock.Mock()
        process = SimpleNamespace(pid=12345, returncode=0, wait=mock.Mock(return_value=0))
        with mock.patch.object(driver.subprocess, 'Popen', return_value=process):
            driver.command('fractional-budget', ['/fixture-not-started'], {}, timeout_seconds=0.25)
        process.wait.assert_called_once_with(timeout=0.25)
        process.wait.reset_mock()
        with mock.patch.object(driver.subprocess, 'Popen', return_value=process), mock.patch.object(driver.time, 'monotonic', return_value=29.9):
            driver.command('fractional-after-launch', ['/fixture-not-started'], {}, timeout_seconds=0.25, absolute_deadline=30)
        self.assertAlmostEqual(process.wait.call_args.kwargs['timeout'], 0.1)
        with mock.patch.object(driver.subprocess, 'Popen', return_value=process), mock.patch.object(driver.time, 'monotonic', return_value=30.5), mock.patch.object(driver.os, 'killpg', side_effect=ProcessLookupError):
            with self.assertRaises(subprocess.TimeoutExpired):
                driver.command('deadline-passed-during-launch', ['/fixture-not-started'], {}, timeout_seconds=0.25, absolute_deadline=30)
        self.assertTrue(driver.base.write.call_args.args[1]['timed_out'])
        self.assertEqual(driver.base.write.call_args.args[1]['wait_budget_seconds'], 0)
        for invalid in (0, -0.25, float('inf'), float('nan'), True, 121):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                driver.command('invalid-budget', ['/fixture-not-started'], {}, timeout_seconds=invalid)

    def test_neighbor_observer_rotation_preserves_completed_scopes_and_rejects_exhaustion(self):
        with mock.patch.dict(sys.modules, {'base_driver': SimpleNamespace()}):
            driver = load('acceptance_driver')
        self.assertTrue(callable(getattr(driver, 'prepare_neighbor_batch', None)),
            'Dedicated neighbor reuse must have an explicit bounded observer rotation boundary')
        trace = self.root / 'neighbor-budget.jsonl'
        socket_path = self.root / 'neighbor-budget.sock'
        batch = {'batch_index': 0, 'pid': 50, 'native_log_start': 0}
        rows = [{'pid': 50, 'sequence': 1, 'function': 'observer', 'edge': 'admitted', 'invalid': False}]
        for index, function in enumerate(('native_new_with_id', 'native_process_request_body',
                'native_process_response_body', 'native_process_logging', 'native_cleanup'), 2):
            rows.append({'pid': 50, 'sequence': index, 'function': function, 'edge': 'return',
                'allocation_scope_call': 2, 'result': 1, 'invalid': False})
        def write_rows():
            trace.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        write_rows()
        writes = {}
        driver.base.write = lambda name, value: writes.update({name: value})
        start = mock.Mock(return_value={'batch_index': 1, 'pid': 51, 'native_log_start': trace.stat().st_size})
        def stop():
            rows.append({'pid': 50, 'sequence': 7, 'function': 'observer', 'edge': 'final',
                'invalid': False, 'live_mappings': 0})
            write_rows()
            return {'actual_pid': 50, 'exit_code': 0}
        same = driver.prepare_neighbor_batch(7, batch, trace, socket_path, stop, start)
        self.assertEqual(same, batch)
        start.assert_not_called()

        rotated = driver.prepare_neighbor_batch(8, batch, trace, socket_path, stop, start)
        self.assertEqual(rotated['pid'], 51)
        start.assert_called_once_with(1)
        self.assertTrue(writes['neighbor-batch-0-final.json']['native']['complete'])
        # A missing final record after a real stop cannot establish cleanup.
        start.reset_mock()
        rows.pop()
        write_rows()
        with self.assertRaisesRegex(RuntimeError, 'observer final'):
            driver.prepare_neighbor_batch(8, batch, trace, socket_path, lambda: {'exit_code': 0}, start)
        start.assert_not_called()
        # Actual observer invalid/budget exhaustion blocks reuse, even with HTTP success elsewhere.
        rows[-1]['invalid'] = True
        write_rows()
        with self.assertRaisesRegex(RuntimeError, 'neighbor scopes'):
            driver.prepare_neighbor_batch(7, batch, trace, socket_path, stop, start)
        start.assert_not_called()

    def test_command_timeout_preserves_waited_signal_and_command_receipt(self):
        with mock.patch.dict(sys.modules, {'base_driver': SimpleNamespace()}):
            driver = load('acceptance_driver')
        adapter = load('acceptance_packet')
        driver.TASK = self.root
        driver.base.SOURCE = self.root
        driver.base.digest = lambda path: adapter.reference(path, 'unit_source')['sha256']
        writes = {}
        driver.base.write = lambda name, value: writes.update({name: value})
        process = SimpleNamespace(pid=12345, returncode=-15,
            wait=mock.Mock(side_effect=[subprocess.TimeoutExpired(['fixture-not-started'], 1), -15]))
        with mock.patch.object(driver.subprocess, 'Popen', return_value=process), mock.patch.object(driver.os, 'killpg') as kill:
            with self.assertRaises(subprocess.TimeoutExpired):
                driver.command('bounded-readiness', ['/fixture-not-started'], {}, timeout_seconds=1)
        self.assertEqual(writes['bounded-readiness.command.json']['signal'], 15)
        self.assertTrue(writes['bounded-readiness.command.json']['timed_out'])
        self.assertEqual(writes['bounded-readiness.command.json']['exit_code'], -15)
        kill.assert_called_once_with(12345, driver.signal.SIGTERM)

    def test_http_readiness_rejects_missing_or_duplicate_native_logging(self):
        with mock.patch.dict(sys.modules, {'base_driver': SimpleNamespace()}):
            driver = load('acceptance_driver')
        for logging_returns, logging_result in ((0, 1), (2, 1), (1, 0), (1, -1)):
            with self.subTest(logging_returns=logging_returns, logging_result=logging_result):
                task = self.root / ('http-readiness-logging-' + str(logging_returns) + '-' + str(logging_result))
                (task / 'client').mkdir(parents=True)
                trace = task / 'native.jsonl'
                trace.write_text('')
                case = {'key': 'logging', 'readiness_ids': ['ready-logging']}
                def write(name, value):
                    (task / name).write_text(json.dumps(value))
                def command(label, argv, env, **kwargs):
                    write('client/neighbor-readiness-0-logging.receipt.json', {'status': 200})
                    names = ['native_new_with_id', 'native_cleanup'] + ['native_process_logging'] * logging_returns
                    with trace.open('a') as stream:
                        for name in names:
                            stream.write(json.dumps({'pid': 50, 'transaction_id': 'ready-logging',
                                'function': name, 'edge': 'return', 'result': logging_result if name == 'native_process_logging' else 1, 'invalid': False}) + '\n')
                    return {'actual_unit_command': label}
                driver.TASK = task
                driver.base.write = write
                with mock.patch.object(driver, 'command', side_effect=command), mock.patch.object(driver.time, 'monotonic', side_effect=[0, 0, 0, 30, 30]):
                    with self.assertRaisesRegex(RuntimeError, 'readiness deadline'):
                        driver.http_readiness(case, 1234, {}, trace, 99)
                receipt = json.loads((task / 'logging-readiness.json').read_text())
                self.assertFalse(receipt['ready'])
                self.assertEqual(receipt['attempts'][0]['native_counts']['native_logging_returns'], logging_returns)
                self.assertEqual(receipt['attempts'][0]['native_counts']['native_logging_successes'], logging_returns if logging_result == 1 else 0)

    def test_unreadable_physical_jsonl_is_unknown_not_empty_or_a_crash(self):
        adapter = load('acceptance_packet')
        path = mock.Mock()
        path.is_file.return_value = True
        path.read_bytes.side_effect = PermissionError(13, 'actual reader permission denied')
        rows, errors = adapter.records(path)
        self.assertIsNone(rows)
        self.assertEqual(errors[0]['errno'], 13)
        self.assertEqual(errors[0]['reader_error'], 'PermissionError')
        self.assertIsNone(adapter.reference(path, 'physical_event_sink'))

    def test_candidate_packet_preserves_missing_sources_and_never_promotes(self):
        adapter = load('acceptance_packet')
        attempt = self.root / 'packet-missing'
        (attempt / 'data').mkdir(parents=True)
        case = {'key': 'missing', 'id': self.plan.PREFIX + 'allow',
            'transaction_id': 'missing', 'classification': 'runtime', 'contract_blockers': []}
        packet = adapter.packet(attempt, case)
        self.assertEqual(set(packet['observations']), set(adapter.contracts().ROLES))
        self.assertFalse(packet['full_lifecycle_qualified'])
        self.assertFalse(packet['oracle_evaluated'])
        self.assertIsNone(packet['parent_sha'])
        for name in ('native_transaction_id', 'native_api_returns', 'native_free_calls', 'client_bytes', 'mime_gate'):
            self.assertIsNone(packet['observations'][name]['value'])
        self.assertTrue(packet['physical_source_errors'])

    def test_candidate_packet_rejects_rebinding_a_retaken_fixture_to_old_measurements(self):
        adapter = load('acceptance_packet')
        attempt = self.root / 'packet-rebinding'
        root = attempt / 'data/cases/fixture'
        root.mkdir(parents=True)
        identifier = self.plan.PREFIX + 'allow'
        (root / 'measurement.json').write_text(json.dumps({'id': identifier, 'fixture_sha256': 'old'}))
        with self.assertRaises(ValueError):
            adapter.packet(attempt, {'key': 'fixture', 'id': identifier, 'transaction_id': 'fixture',
                'classification': 'runtime', 'fixture_sha256': 'new'})

    def test_mime_candidate_uses_central_roles_and_keeps_nested_header_rules_sources(self):
        adapter = load('acceptance_packet')
        attempt = self.root / 'packet-mime-roles'
        root = attempt / 'data/cases/mime'
        root.mkdir(parents=True)
        native = attempt / 'data/runtime/logs/native-lifecycle.jsonl'
        native.parent.mkdir(parents=True)
        native.write_text('{}\n')
        for name in ('faults.jsonl', 'debug.log', 'events.jsonl', 'rules.conf'):
            (root / name).write_text('{}\n')
        header = attempt / 'data/client/mime.response.raw'
        header.parent.mkdir()
        header.write_bytes(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody')
        selection = {'header_source': adapter.reference(header, 'client_process'),
            'effective_rule_source': adapter.reference(root / 'rules.conf', 'effective_configuration'),
            'actual_retained_body_records': [{'retained_body_bytes': 4}], 'root_approval': 'pending'}
        case = {'key': 'mime', 'id': self.plan.PREFIX + 'NEED-response-mime-scope-in',
            'transaction_id': 'mime', 'classification': 'runtime', 'contract_blockers': []}
        with mock.patch.object(adapter, 'body_selection_candidate', return_value=selection):
            packet = adapter.packet(attempt, case)
        item = packet['observations']['mime_gate']
        self.assertEqual(item['value'], selection)
        self.assertEqual({proof['role'] for proof in item['evidence']}, adapter.contracts().ROLES['mime_gate'])
        contract = adapter.contracts()
        for field, observation in packet['observations'].items():
            contract.measurement(field, observation, attempt / 'candidate.json')
        measured, complete = contract.measurement('mime_gate', item, attempt / 'candidate.json')
        self.assertTrue(complete)
        self.assertEqual(measured['value']['header_source'], selection['header_source'])
        for forbidden in ('header_source', 'effective_rule_source'):
            invalid = copy.deepcopy(item)
            invalid['evidence'].append(selection[forbidden])
            with self.assertRaisesRegex(ValueError, 'suitable physical producer'):
                contract.measurement('mime_gate', invalid, attempt / 'candidate.json')

    def test_candidate_packet_does_not_silently_drop_corrupt_sink_bytes(self):
        adapter = load('acceptance_packet')
        path = self.root / 'corrupt-physical.jsonl'
        path.write_bytes(b'{"transaction_id":"synthetic"}\n{"broke\n')
        rows, errors = adapter.records(path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]['line'], 1)
        self.assertTrue(errors[0]['raw_sha256'])
        rows, errors = adapter.records(path.with_name('absent.jsonl'))
        self.assertIsNone(rows)
        self.assertEqual(errors[0]['reason'], 'missing physical source')

    def test_generated_id_observer_admits_only_exact_case_child_environment(self):
        compiler = shutil.which('go')
        if compiler is None:
            self.skipTest('Go compiler unavailable')
        prepare = load('acceptance_prepare')
        capture_root = REPO / 'ci/runtime/lifecycle/i12'
        central = load_source(capture_root / 'capture_sources.py')
        registry = central.Registry(capture_root, REPO)
        entry = registry.manifest['profiles']['traefik-native']['source_targets']['connectors/traefik/native_middleware/i12_observer.go']
        original = registry.content(entry['sha256']).decode()
        fixture = self.plan.default_fixture()
        fixture['request']['omit_transaction_id'] = True
        manifest = {'cases': [{'key': prepare.GENERATED_CASE_KEY,
            'id': self.plan.PREFIX + 'transaction_id_generated_or_fallback', 'fixture': fixture,
            'transaction_id': 'controlled', 'neighbor_id': 'neighbor', 'positive_control_id': 'positive',
            'main_before_id': 'before', 'main_after_id': 'after'}]}
        observer, _ = prepare.instrument_host_observer(original, manifest)
        root = self.root / 'go-generated'
        root.mkdir(mode=0o700)
        trace = root / 'trace.jsonl'
        trace.touch(mode=0o600)
        (root / 'observer.go').write_text(observer.replace('package native_middleware', 'package main', 1))
        (root / 'main.go').write_text('''package main
import ("fmt"; "os")
func main() {
 i12ObserverPath = os.Args[1]
 os.Unsetenv("I12_NATIVE_GENERATED_CASE")
 i12Observe("", "unset", nil)
 os.Setenv("I12_NATIVE_GENERATED_CASE", "wrong-case")
 i12Observe("", "wrong-case", nil)
 os.Setenv("I12_NATIVE_GENERATED_CASE", "004-b044cc412aca")
 i12Observe("foreign-id", "foreign-id", nil)
 i12Observe("", "exact-case", nil)
 os.Unsetenv("I12_NATIVE_GENERATED_CASE")
 i12Observe("", "unset-after", nil)
 i12Observe("controlled", "existing-explicit-id", nil)
 fmt.Println("completed")
}
''')
        cache = EXTERNAL / 'go-cache'
        cache.mkdir(exist_ok=True, mode=0o700)
        environment = os.environ | {'GOTOOLCHAIN': 'local', 'GOPROXY': 'off', 'GOSUMDB': 'off',
            'GO111MODULE': 'off', 'GOCACHE': str(cache), 'TMPDIR': str(root)}
        result = subprocess.run(['rtk', 'proxy', compiler, 'run', str(root / 'observer.go'),
            str(root / 'main.go'), str(trace)], cwd=root, env=environment,
            capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [json.loads(line) for line in trace.read_text().splitlines()]
        self.assertEqual([row['operation'] for row in rows], ['exact-case', 'existing-explicit-id'])
        self.assertEqual(rows[0]['transaction_id'], '')
        self.assertEqual(rows[1]['transaction_id'], 'controlled')
        manifest['cases'][0]['key'] = 'unreviewed-case'
        with self.assertRaises(ValueError):
            prepare.instrument_host_observer(original, manifest)

    def test_ack_fault_is_outcome10_not_commit7_and_positive_ack_is_unchanged(self):
        proxy = load('acceptance_proxy')
        for positive in (False, True):
            with self.subTest(positive_control=positive):
                engine_path = self.root / ('ack-engine-' + str(positive) + '.sock')
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                listener.bind(str(engine_path))
                listener.listen(1)
                listener.settimeout(3)
                side, relayed = socket.socketpair()
                side.settimeout(3)
                rows, errors, observed_opcodes = [], [], []
                reply_body = b'\x01\x00healthy-engine-reply'
                def frame(opcode, payload):
                    return b'MSE1' + bytes((1, opcode, 0, 0)) + struct.pack('!I', len(payload)) + payload
                def engine():
                    try:
                        connection, _ = listener.accept()
                        with connection:
                            connection.settimeout(3)
                            for opcode in (1, 7, 10):
                                head, _ = proxy.transport.frame(connection)
                                observed_opcodes.append(head[5])
                                connection.sendall(frame(opcode, reply_body))
                    except Exception as error:
                        errors.append(error)
                case = {'key': 'ack', 'positive_control_id': 'exact-positive-ack',
                    'fixture': {'fault': {'kind': 'commit-ack-applied', 'opcode': 10}}}
                worker = threading.Thread(target=engine)
                relay = threading.Thread(target=proxy.relay, args=(relayed, str(engine_path), case))
                try:
                    with mock.patch.object(proxy.transport, 'record', side_effect=rows.append):
                        worker.start()
                        relay.start()
                        replies = []
                        for opcode in (1, 7, 10):
                            payload = b'exact-positive-ack' if opcode == 1 and positive else b'exact-target'
                            side.sendall(frame(opcode, payload))
                            _, response = proxy.transport.frame(side)
                            replies.append(response)
                        side.close()
                        worker.join(timeout=4)
                        relay.join(timeout=4)
                    self.assertFalse(worker.is_alive())
                    self.assertFalse(relay.is_alive())
                    self.assertEqual(errors, [])
                    self.assertEqual(observed_opcodes, [1, 7, 10])
                    self.assertEqual(replies[1], reply_body)
                    self.assertEqual(replies[2], reply_body if positive else reply_body[:1] + b'\x05' + reply_body[2:])
                    injected = [row for row in rows if row.get('fault')]
                    self.assertEqual([row['opcode'] for row in injected], [] if positive else [10])
                finally:
                    side.close()
                    listener.close()
                    engine_path.unlink()

    def test_no_file_or_mrc1_http_relabelling(self):
        for name in ('NEED-request-file', 'NEED-response-file', 'NEED-mrc1-error'):
            self.assertTrue(self.plan.constraints(name)[1])

    def file_originals(self):
        return [{'id': self.plan.PREFIX + 'NEED-' + direction + '-file', 'key': 'file-' + direction,
                 'transaction_id': 'tf-a-' + direction, 'neighbor_id': 'tf-n-' + direction,
                 'positive_control_id': 'tf-c-' + direction, 'main_before_id': 'tf-b-' + direction,
                 'main_after_id': 'tf-r-' + direction, 'readiness_ids': ['tf-ready-' + direction],
                 'fixture': self.plan.default_fixture(), 'contract_blockers': ['native File API unresolved']}
                for direction in ('request', 'response')]

    def test_file_supplements_preserve_originals_and_never_invent_backend_exclusion(self):
        originals = self.file_originals()
        before = copy.deepcopy(originals)
        supplements = self.plan.file_supplements(originals)
        self.assertEqual(originals, before)
        self.assertEqual(len(supplements), 4)
        self.assertEqual(len({row['key'] for row in supplements}), 4)
        for row in supplements:
            file = row['fixture']['file_supplement']
            self.assertNotEqual(row['transaction_id'], row['key'])
            self.assertEqual(row['fixture']['policy']['phase4_mode'], 'safe')
            self.assertFalse(file['backend_exclusion_expected'])
            self.assertFalse(file['native_file_api'])
            self.assertIsNone(row['expected'])
            self.assertFalse(row['expected_approval'])
            self.assertEqual(row['contract_blockers'], ['native File API unresolved'])
            self.assertEqual(row['fixture_sha256'], self.plan.json_digest(row['fixture']))

    def test_file_http_arguments_bind_distinct_sealed_transaction_identity(self):
        with mock.patch.dict(sys.modules, {'base_driver': SimpleNamespace()}):
            driver = load('acceptance_driver')
        case = self.plan.file_supplements(self.file_originals())[0]
        execution = {'argv': ['python', '-P', '-m', 'i12_file.run'], 'shared': ['--manifest', 'manifest'],
                     'supplement': case['fixture']['file_supplement']}
        for mode in ('client', 'backend'):
            argv = driver.file_process_argv(execution, mode, 12345, case)
            self.assertEqual(argv[argv.index('--key') + 1], case['key'])
            self.assertEqual(argv[argv.index('--transaction-id') + 1], case['transaction_id'])
        for invalid in (None, '', case['key']):
            bad = copy.deepcopy(case)
            bad['transaction_id'] = invalid
            with self.assertRaises(ValueError):
                driver.file_process_argv(execution, 'client', 12345, bad)
        bad = copy.deepcopy(case)
        del bad['transaction_id']
        with self.assertRaises(ValueError):
            driver.file_process_argv(execution, 'backend', 12345, bad)

    def test_file_packet_uses_specialized_client_and_never_shared_backend_zero(self):
        adapter = load('acceptance_packet')
        for direction in ('request', 'response'):
            case = self.plan.file_supplements(self.file_originals())[0 if direction == 'request' else 2]
            case['classification'] = 'runtime'
            attempt = self.root / ('packet-file-' + direction)
            data = attempt / 'data'
            root = data / 'cases' / case['key']
            root.mkdir(parents=True)
            (root / 'file-evidence').mkdir()
            (root / 'measurement.json').write_text(json.dumps({'id': case['id'],
                'fixture_sha256': case['fixture_sha256']}))
            (data / 'backend').mkdir()
            (data / 'backend/receipts.jsonl').write_text('{}\n')
            specialized = {'client': {'status': 403, 'entity_bytes': 6, 'entity_sha256': 'physical'},
                'client_path': root / 'file-evidence/client.json', 'request_path': root / 'request.raw',
                'response_path': root / 'response.raw', 'entity_path': root / 'entity.raw',
                'wait_path': root / 'measurement.json', 'waited': {'returncode': 0},
                'binding_valid': True, 'native_file_api': False, 'native_eos': None,
                'backend': None, 'backend_path': root / 'backend.json'}
            for path in ('client_path', 'request_path', 'response_path', 'entity_path', 'backend_path'):
                specialized[path].write_text('{}')
            if direction == 'response':
                specialized['backend'] = {'independent_backend_accept_count': 1}
            with mock.patch.object(adapter, 'physical_file_candidate', return_value=specialized):
                packet = adapter.packet(attempt, case)
            self.assertFalse(packet['full_lifecycle_qualified'])
            self.assertFalse(packet['physical_file_supplement']['native_file_api'])
            if direction == 'request':
                self.assertEqual(packet['observations']['client_bytes']['value'], 6)
                self.assertEqual(packet['observations']['client_exit']['value'], 0)
            else:
                self.assertEqual(packet['observations']['backend_request_count']['value'], 1)
            specialized['binding_valid'] = False
            with mock.patch.object(adapter, 'physical_file_candidate', return_value=specialized):
                packet = adapter.packet(attempt, case)
            self.assertIsNone(packet['observations']['backend_request_count']['value'])

    def test_file_packet_binding_rejects_changed_pid_hash_clock_and_transport(self):
        adapter = load('acceptance_packet')
        for mode in ('client', 'backend'):
            case = self.plan.file_supplements(self.file_originals())[0 if mode == 'client' else 2]
            root = self.root / ('file-binding-' + mode)
            evidence = root / 'file-evidence'
            evidence.mkdir(parents=True)
            (root / 'file-source').mkdir()
            content = b'physical file'
            sha = hashlib.sha256(content).hexdigest()
            spec = {'relative_path': 'test.txt', 'size': len(content), 'sha256': sha, 'read_size': 24}
            case['fixture']['file_supplement']['file_spec'] = spec
            (root / 'file-source/test.txt').write_bytes(content)
            key, tx = case['key'], case['transaction_id']
            head = ('POST / HTTP/1.1\r\nX-Request-Id: ' + tx +
                '\r\nX-I12-Acceptance-Key: ' + key + '\r\n\r\n').encode()
            source = {'schema': 'traefik-physical-file-source-v1', 'pid': 22, 'native_file_api': False,
                'native_eos': None, 'complete': True, 'relative_path': 'test.txt',
                'bytes': len(content), 'expected_size': len(content), 'expected_sha256': sha, 'sha256': sha,
                'requested_read_size': 24,
                'pre_stat': {'regular_file': True, 'size': len(content)},
                'post_stat': {'regular_file': True, 'size': len(content)},
                'close': {'result': 0, 'completed_ns': 15}, 'root_close': {'result': 0, 'completed_ns': 16},
                'eof_read_result': 0, 'started_ns': 3, 'completed_ns': 17,
                'reads': [{'offset': 0, 'requested': len(content), 'result': len(content), 'sha256': sha, 'started_ns': 5,
                    'completed_ns': 6, 'consumer_returned_ns': 10}]}
            row = {'schema': 'traefik-file-http-' + mode + '-v1', 'key': key, 'transaction_id': tx,
                'pid': 22, 'process': {'pid': 22, 'ppid': 21}, 'native_file_api': False,
                'native_eos': None, 'file_source': source, 'started_ns': 2, 'completed_ns': 30,
                'http_chunks': [{'source_offset': 0, 'entity_bytes': len(content), 'entity_sha256': sha,
                    'wire_bytes': len(content) + 5,
                    'wire_sha256': hashlib.sha256(b'd\r\n' + content + b'\r\n').hexdigest(),
                    'remote_delivery_proven': False, 'started_ns': 7, 'sendall_returned_ns': 9}],
                'http_terminator_send_started_ns': 18, 'http_terminator_sendall_returned_ns': 19,
                'http_terminator_wire_bytes': 5, 'http_terminator_wire_sha256': hashlib.sha256(b'0\r\n\r\n').hexdigest()}
            measurement = {'client': {'wrapper_pid': 21, 'started_ns': 1, 'completed_ns': 31, 'exit_code': 0}}
            before = {'processes': {'file-backend': {'pid': 22, 'proxy_pid': 21}}}
            if mode == 'client':
                row.update(actual_status=200, response_headers_latin1='HTTP/1.1 200 OK\r\nContent-Length: 4',
                    response_http_complete=True, response_http_framing='content-length')
                raw_fields = [('request-head.raw', head, 'request_head_wire'),
                    ('response.raw', b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody', 'client_response_wire'),
                    ('response-entity.raw', b'body', 'client_response_entity')]
            else:
                row.update(independent_backend_accept_count=1, local=['127.0.0.1', 12345], peer=['127.0.0.1', 23456],
                    accepted_ns=2, observed_correlation={'x-request-id': tx, 'x-i12-acceptance-key': key},
                    request_http_framing_valid=True, request_body_bytes=0,
                    request_body_sha256=hashlib.sha256(b'').hexdigest())
                listening = {'pid': 22, 'port': 12345}
                measurement['physical_file'] = {'listening': listening}
                (evidence / (key + '.backend-listening.json')).write_text(json.dumps(listening))
                (evidence / (key + '.backend-accept.json')).write_text(json.dumps(row))
                raw_fields = [('backend-request.raw', head, 'request_wire'),
                    ('backend-response-head.raw', b'HTTP/1.1 200 OK\r\n\r\n', 'response_head_wire')]
            for suffix, raw, prefix in raw_fields:
                (evidence / (key + '.' + suffix)).write_bytes(raw)
                row[prefix + '_bytes'] = len(raw)
                row[prefix + '_sha256'] = hashlib.sha256(raw).hexdigest()
            path = evidence / (key + '.' + mode + '.json')
            path.write_text(json.dumps(row))
            result = adapter.physical_file_candidate(case, root, measurement, before)
            self.assertTrue(result['binding_valid'], result.get('binding_error'))
            self.assertFalse(result['native_file_api'])
            self.assertIsNone(result['native_eos'])
            mutations = [lambda value: value.update(pid=23),
                lambda value: value['file_source'].update(sha256='0' * 64),
                lambda value: value['file_source']['close'].update(result=-1),
                lambda value: value['http_chunks'][0].update(source_offset=1),
                lambda value: value['http_chunks'][0].update(wire_bytes=0),
                lambda value: value['http_chunks'][0].update(wire_sha256='0' * 64),
                lambda value: value['http_chunks'][0].update(remote_delivery_proven=True),
                lambda value: value['file_source'].update(requested_read_size=9999),
                lambda value: value['file_source']['reads'][0].update(requested=9999),
                lambda value: value.update(http_terminator_send_started_ns=4),
                lambda value: value.update(transaction_id='other'),
                lambda value: value.update(native_file_api=True)]
            for mutate in mutations:
                changed = copy.deepcopy(row)
                mutate(changed)
                path.write_text(json.dumps(changed))
                self.assertFalse(adapter.physical_file_candidate(case, root, measurement, before)['binding_valid'])
            path.write_text(json.dumps(row))
            if mode == 'client':
                entity_path = evidence / (key + '.response-entity.raw')
                entity_path.write_bytes(b'fake')
                changed = row | {'client_response_entity_sha256': hashlib.sha256(b'fake').hexdigest()}
                path.write_text(json.dumps(changed))
                self.assertFalse(adapter.physical_file_candidate(case, root, measurement, before)['binding_valid'])
                entity_path.write_bytes(b'body')
            else:
                changed = row | {'request_body_bytes': 4, 'request_body_sha256': hashlib.sha256(b'fake').hexdigest()}
                path.write_text(json.dumps(changed))
                self.assertFalse(adapter.physical_file_candidate(case, root, measurement, before)['binding_valid'])
            path.write_text(json.dumps(row))
            (root / 'file-source/test.txt').write_bytes(b'changed')
            self.assertFalse(adapter.physical_file_candidate(case, root, measurement, before)['binding_valid'])

    def test_strict_negative_requires_one_exact_safe_configuration(self):
        with mock.patch.dict(sys.modules, {'base_driver': SimpleNamespace()}):
            driver = load('acceptance_driver')
        self.assertEqual(driver.strict_configuration('phase4_mode=safe\n'), 'phase4_mode=strict\n')
        for text in ('phase4_mode=off\n', 'phase4_mode=strict\n', 'phase4_mode=safe\nphase4_mode=safe\n'):
            with self.assertRaises(ValueError):
                driver.strict_configuration(text)

    def test_file_target_router_only_matches_literal_target_and_preserves_control_services(self):
        with mock.patch.dict(sys.modules, {'base_driver': SimpleNamespace()}):
            driver = load('acceptance_driver')
        import yaml
        def write_dynamic(path, port, socket_path):
            path.write_text('http:\n  routers:\n    native:\n      rule: "PathPrefix(`/`)"\n'
                '      middlewares: [native]\n      service: upstream\n  middlewares:\n'
                '    native: {}\n  services:\n    upstream:\n      loadBalancer:\n'
                '        servers:\n          - url: http://127.0.0.1:' + str(port) + '\n')
        path = self.root / 'file-routing.yaml'
        driver.dynamic_config(SimpleNamespace(write_dynamic_config=write_dynamic), path, 12345,
            '/main.sock', '/neighbor.sock', '/reuse.sock', ('file-target-key', 12346))
        config = yaml.safe_load(path.read_text())['http']
        self.assertEqual(config['routers']['file-target']['rule'], 'Header(`X-I12-Acceptance-Key`, `file-target-key`)')
        self.assertEqual(config['routers']['file-target']['middlewares'], ['native'])
        for name in ('native', 'reuse', 'neighbor'):
            self.assertEqual(config['routers'][name]['service'], 'upstream')
        self.assertEqual(config['services']['file-target']['loadBalancer']['servers'], [{'url': 'http://127.0.0.1:12346'}])
        base_driver = SimpleNamespace(write_dynamic_config=write_dynamic)
        with self.assertRaises(ValueError):
            driver.dynamic_config(base_driver, path, 12345,
                '/main.sock', '/neighbor.sock', '/reuse.sock', ('bad`) || PathPrefix(`/`)', 12346))

    def test_file_staging_uses_real_sealed_module_and_fresh_private_sources(self):
        import hashlib
        bound = SimpleNamespace(SOURCE=REPO, digest=lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest(),
                               write=lambda *args: None)
        with mock.patch.dict(sys.modules, {'base_driver': bound}):
            driver = load('acceptance_driver')
        root = self.root / 'file-stage'
        root.mkdir(mode=0o700)
        fixture_root = self.root / 'file-fixtures'
        fixture_root.mkdir(mode=0o700)
        harness = NATIVE.parents[1]
        shutil.copytree(harness / 'i12_file', fixture_root / 'i12_file', ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copytree(harness / 'fixtures/i12-file-source', fixture_root / 'i12-file-source')
        case = self.plan.file_supplements(self.file_originals())[0]
        with mock.patch.object(driver, 'TASK', root), mock.patch.object(driver, 'FIXTURES', fixture_root):
            staged = driver.stage_file_execution(case, root, os.environ.copy())
        self.assertEqual(staged['staging']['exit_code'], 0)
        self.assertEqual((root / 'file-source').stat().st_mode & 0o777, 0o700)
        specs = json.loads((fixture_root / 'i12-file-source/manifest.json').read_text())['files']
        for spec in specs:
            path = root / 'file-source' / spec['relative_path']
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(bound.digest(path), spec['sha256'])
        self.assertTrue((root / 'file-evidence/file-staging.json').is_file())
        inherited_environment = os.environ.copy()
        with mock.patch.object(driver, 'TASK', root), mock.patch.object(driver, 'FIXTURES', fixture_root):
            with self.assertRaises(FileExistsError):
                driver.stage_file_execution(case, root, inherited_environment)

    def test_file_backend_readiness_checks_actual_pid_without_tcp_probe(self):
        with mock.patch.dict(sys.modules, {'base_driver': SimpleNamespace(actual_pid=lambda *args: 456)}):
            driver = load('acceptance_driver')
        root = self.root / 'file-ready'
        root.mkdir(mode=0o700)
        (root / 'file-key.backend-listening.json').write_text(json.dumps({'pid': 456, 'port': 12345}))
        process = SimpleNamespace(poll=lambda: None)
        with mock.patch.object(socket, 'create_connection', side_effect=AssertionError('TCP readiness consumes target accept')):
            self.assertEqual(driver.file_backend_ready(process, 'run.py', root, 'file-key', 12345)['pid'], 456)
        (root / 'file-key.backend-listening.json').write_text(json.dumps({'pid': 457, 'port': 12345}))
        with self.assertRaises(ValueError):
            driver.file_backend_ready(process, 'run.py', root, 'file-key', 12345)

    def test_real_file_backend_script_supports_central_pid_snapshot_and_stop(self):
        root = self.root / 'real-file-process'
        root.mkdir(mode=0o700)
        snapshots = {}
        bound = ProcessObservation(root, writer=lambda name, value: snapshots.update({name: value}))
        self.assertTrue(all(callable(getattr(bound, name)) for name in ('actual_pid', 'descendants', 'snapshot')))
        with mock.patch.dict(sys.modules, {'base_driver': bound}):
            driver = load('acceptance_driver')
        fixtures = self.root / 'real-file-process-fixtures'
        fixtures.mkdir(mode=0o700)
        harness = NATIVE.parents[1]
        shutil.copytree(harness / 'i12_file', fixtures / 'i12_file', ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copytree(harness / 'fixtures/i12-file-source', fixtures / 'i12-file-source')
        case = self.plan.file_supplements(self.file_originals())[2]
        with mock.patch.object(driver, 'TASK', root), mock.patch.object(driver, 'FIXTURES', fixtures):
            execution = driver.stage_file_execution(case, root, os.environ.copy())
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        argv = driver.file_process_argv(execution, 'backend', port, case)
        marker = str(fixtures / 'i12_file/run.py')
        self.assertEqual(list(map(str, argv[:3])), ['/usr/local/bin/python3', '-P', marker])
        self.assertEqual(execution['env']['PYTHONPATH'], str(fixtures / 'i12_file'))
        process = subprocess.Popen(['rtk', 'proxy', *map(str, argv)], env=execution['env'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            listening = driver.file_backend_ready(process, marker, execution['evidence_root'], case['key'], port)
            actual_pid = bound.actual_pid(process, marker)
            self.assertEqual(actual_pid, listening['pid'])
            self.assertNotEqual(actual_pid, process.pid)
            bound.snapshot('file-script', {'file-backend': (process, marker)})
            self.assertTrue(any(value.get('processes', {}).get('file-backend', {}).get('pid') == actual_pid
                                for value in snapshots.values()))
            with self.assertRaises(RuntimeError):
                bound.actual_pid(process, marker + '-wrong')
            stopped = driver.stop('file-backend', process, marker)
            self.assertEqual(stopped['actual_pid'], actual_pid)
            self.assertIsNotNone(process.poll())
            with self.assertRaises(RuntimeError):
                bound.actual_pid(process, marker)
        finally:
            if process.poll() is None:
                driver.stop('file-backend', process, marker)

    def test_exact_chunk_framing_and_byte_identity(self):
        fixture = self.plan.default_fixture()
        fixture['request'].update(method='POST', body_hex=b'a\xffbc'.hex(), chunk_lengths=[1, 3])
        key, head, pieces, body = self.client.request_bytes({'key': '000-test', 'fixture': fixture,
            'transaction_id': 'tf-a-000-test', 'neighbor_id': 'tf-n-000-test'})
        self.assertEqual(body, b'a\xffbc')
        self.assertEqual(pieces, [b'1\r\na\r\n', b'3\r\n\xffbc\r\n'])
        self.assertIn(b'Transfer-Encoding: chunked\r\n', head)
        self.assertEqual(key, '000-test')

    def test_entity_framing_preserves_partial_content_length_and_chunked_prefix(self):
        data, framing = self.client.response_entity(b'HTTP/1.1 200 OK\r\nContent-Length: 16384', b'A' * 8192)
        self.assertEqual(len(data), 8192)
        self.assertFalse(framing['complete'])
        self.assertEqual(framing['declared'], 16384)
        head = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked'
        data, framing = self.client.response_entity(head, b'3\r\naff\r\n0\r\n\r\n')
        self.assertEqual(data, b'aff')
        self.assertTrue(framing['complete'])
        data, framing = self.client.response_entity(head, b'4\r\nab')
        self.assertEqual(data, b'ab')
        self.assertFalse(framing['complete'])

    def test_bad_chunk_length_fails_before_network(self):
        fixture = self.plan.default_fixture()
        fixture['request'].update(body_hex='ff', chunk_lengths=[2])
        with self.assertRaises(ValueError):
            self.client.request_bytes({'key': '000-test', 'fixture': fixture,
                'transaction_id': 'tf-a-000-test', 'neighbor_id': 'tf-n-000-test'})

    def test_main_transport_controls_use_explicit_small_body_without_changing_target(self):
        backend = load('acceptance_backend')
        fixture = self.plan.default_fixture()
        fixture['backend']['body_hex'] = (b'A' * (8 * 1024 * 1024) + b'no-crs-response-body-marker').hex()
        fixture['main_control_backend'] = self.plan.default_fixture()['backend']
        case = {'fixture': fixture}
        original = bytes.fromhex(fixture['backend']['body_hex'])
        for prefix in ('main-before-', 'main-after-'):
            value, selection = backend.response_fixture(case, prefix + 'case', False)
            self.assertEqual(len(bytes.fromhex(value['body_hex'])), 33)
            self.assertEqual(selection, 'explicit_main_control_override')
        target, selection = backend.response_fixture(case, 'case', False)
        self.assertEqual(bytes.fromhex(target['body_hex']), original)
        self.assertEqual(selection, 'original_target_fixture')
        del fixture['main_control_backend']
        unchanged, selection = backend.response_fixture(case, 'main-before-case', False)
        self.assertEqual(bytes.fromhex(unchanged['body_hex']), original)
        self.assertEqual(selection, 'original_target_fixture')

    def test_backend_header_arrival_survives_incomplete_request(self):
        backend = load('acceptance_backend')
        root = self.root / 'backend-incomplete'
        root.mkdir(mode=0o700)
        server = backend.Backend(('127.0.0.1', 0), backend.Handler)
        server.root = root
        server.barriers = root
        server.cases = {'case': {'fixture': self.plan.default_fixture()}}
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01})
        thread.start()
        try:
            with socket.create_connection(server.server_address, timeout=2) as connection:
                connection.sendall(b'POST /incomplete HTTP/1.1\r\nHost: example.test\r\n'
                    b'X-I12-Acceptance-Key: case\r\nContent-Length: 4\r\n\r\nab')
                connection.shutdown(socket.SHUT_WR)
            deadline = time.monotonic() + 2
            rows = []
            while time.monotonic() < deadline:
                path = root / 'receipts.jsonl'
                if path.exists():
                    rows = [json.loads(line) for line in path.read_text().splitlines()]
                if any(row['operation'] == 'handler-end' for row in rows):
                    break
                time.sleep(0.01)
            operations = [row['operation'] for row in rows]
            self.assertLess(operations.index('headers-arrived'), operations.index('body-incomplete'))
            self.assertNotIn('body-complete', operations)
            self.assertEqual((root / 'case.request-body.raw').read_bytes(), b'ab')
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()
        self.assertFalse(thread.is_alive())

    def test_current_native_observer_fault_hooks_match_exact_boundaries(self):
        prepare = load('acceptance_prepare')
        observer = (REPO / 'ci/runtime/lifecycle/native-lifecycle-observer.c').read_text()
        instrumented = prepare.instrument_fault_hooks(observer)
        self.assertIn('return i12_acceptance_native_transaction_result(transaction, "append_" #direction "_body", result); ' + chr(92) + chr(10), instrumented)
        self.assertEqual(instrumented.count('i12_acceptance_native_created(transaction);'), 1)
        cleanup = instrumented.split('void __wrap_msc_transaction_cleanup(Transaction *transaction) {', 1)[1].split('\n}', 1)[0]
        self.assertEqual(cleanup.count('__real_msc_transaction_cleanup(transaction);'), 1)
        self.assertLess(cleanup.index('i12_acceptance_retained_body(transaction, "transaction_cleanup_before_free", 0);'), cleanup.index('i12_acceptance_native_released(transaction);'))
        self.assertLess(cleanup.index('i12_acceptance_retained_body(transaction, "transaction_cleanup_before_free", 1);'), cleanup.index('__real_msc_transaction_cleanup(transaction);'))
        service = (REPO / 'connectors/traefik/src/traefik_engine_service.c').read_text()
        changed = prepare.instrument_native_begin(service)
        self.assertIn('selected_request, input.host_request_id', changed)
        self.assertIn('traefik_engine_request_input_free(&input);', changed)
        with self.assertRaises(ValueError):
            prepare.instrument_native_begin(changed)

    def test_retained_accessor_uses_real_sdk_and_never_claims_inspection(self):
        if shutil.which('gcc') is None:
            self.skipTest('strict C compiler unavailable')
        prepare = load('acceptance_prepare')
        observer = prepare.instrument_fault_hooks((REPO / 'ci/runtime/lifecycle/native-lifecycle-observer.c').read_text())
        helper = observer.split('static void i12_acceptance_retained_body(', 1)[1].split('#define NATIVE_WRAPPER', 1)[0]
        helper = 'static void i12_acceptance_retained_body(' + helper
        source = self.root / 'retained-sdk.c'
        source.write_text(r'''#define _POSIX_C_SOURCE 200809L
#include <modsecurity/modsecurity.h>
#include <modsecurity/transaction.h>
#include <modsecurity/rules_set.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
struct mapping { uint64_t allocation_scope_call; };
static struct mapping entry = {123};
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static const void *tracked;
static const struct mapping *lookup(const void *tx, int native) { return tx == tracked && native == 1 ? &entry : NULL; }
static int fail_clock;
static int observed_clock(clockid_t clock, struct timespec *value) {
 if (fail_clock) { errno = EIO; return -1; }
 return clock_gettime(clock, value);
}
#define clock_gettime observed_clock
''' + helper + r'''
int main(void) {
 ModSecurity *engine = msc_init();
 RulesSet *rules = msc_create_rules_set();
 Transaction *tx = msc_new_transaction(engine, rules, NULL);
 if (!tx) return 2;
 tracked = tx;
 if (msc_append_request_body(tx, (const unsigned char *)"abc", 3) < 0) return 3;
 errno = EDOM;
 i12_acceptance_retained_body(tx, "append_request_body", 0);
 if (errno != EDOM) return 4;
 fail_clock = 1; errno = EDOM;
 i12_acceptance_retained_body(tx, "failed_clock_must_not_emit", 0);
 if (errno != EDOM) return 7;
 fail_clock = 0;
 if (msc_append_response_body(tx, (const unsigned char *)"12345", 5) < 0) return 5;
 i12_acceptance_retained_body(tx, "append_response_body", 1);
 i12_acceptance_retained_body(tx, "process_response_body", 1);
 i12_acceptance_retained_body(tx, "transaction_cleanup_before_free", 0);
 i12_acceptance_retained_body(tx, "transaction_cleanup_before_free", 1);
 tracked = NULL;
 msc_transaction_cleanup(tx);
 i12_acceptance_retained_body(tx, "retired_must_not_dereference", 1);
 Transaction *empty = msc_new_transaction(engine, rules, NULL);
 if (!empty) return 6;
 tracked = empty; entry.allocation_scope_call = 124;
 i12_acceptance_retained_body(empty, "transaction_cleanup_before_free", 0);
 i12_acceptance_retained_body(empty, "transaction_cleanup_before_free", 1);
 tracked = NULL; msc_transaction_cleanup(empty);
 msc_rules_cleanup(rules); msc_cleanup(engine); return 0;
}
''')
        binary = self.root / 'retained-sdk'
        compiled = subprocess.run(['rtk', 'proxy', 'gcc', '-std=c17', '-Wall', '-Wextra', '-Werror',
            '-pthread', str(source), '-lmodsecurity', '-o', str(binary)], capture_output=True, text=True)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        with tempfile.TemporaryFile(dir=self.root) as trace:
            env = os.environ | {'I12_ACCEPTANCE_FAULT_FD': str(trace.fileno())}
            result = subprocess.run(['rtk', 'proxy', str(binary)], env=env, pass_fds=(trace.fileno(),), capture_output=True, text=True)
            trace.seek(0)
            rows = [json.loads(line) for line in trace.read().splitlines()]
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([row['retained_body_bytes'] for row in rows], [3, 5, 5, 3, 5, 0, 0])
        self.assertEqual([row['allocation_scope_call'] for row in rows], [123] * 5 + [124] * 2)
        self.assertTrue(all(row['pid'] > 0 and row['injected'] is False for row in rows))
        self.assertTrue(all('body_bytes_inspected' not in row for row in rows))
        self.assertNotIn('i12_acceptance_retained_body(transaction, "process_logging"', observer)

    def native_probe(self, fault, mode='request', uri='/selected', with_receipts=False):
        self.ensure_native_probe()
        if self.binary is None:
            self.skipTest('strict C compiler unavailable')
        env = os.environ | {'I12_ACCEPTANCE_FAULT': fault, 'I12_ACCEPTANCE_FAULT_URI': '/selected'}
        with tempfile.TemporaryFile(dir=self.root) as trace:
            env['I12_ACCEPTANCE_FAULT_FD'] = str(trace.fileno())
            result = subprocess.run(['rtk', 'proxy', str(self.binary), mode, uri], env=env,
                pass_fds=(trace.fileno(),), capture_output=True, text=True, check=False)
            trace.seek(0)
            receipts = [json.loads(line) for line in trace.read().splitlines()]
        self.assertEqual(result.returncode, 0, result.stderr)
        return (json.loads(result.stdout), receipts) if with_receipts else json.loads(result.stdout)

    def test_native_api_null_injection_preserves_original_parse_ownership(self):
        for fault, field in (('mapper-body-null', 'selected_body'), ('mapper-headers-null', 'selected_headers')):
            result, receipts = self.native_probe(fault, with_receipts=True)
            self.assertEqual(result[field], 1)
            self.assertEqual(len(receipts), 1)
            self.assertTrue(receipts[0]['injected'])
            if fault == 'mapper-body-null':
                self.assertEqual(receipts[0]['input_size'], 1)
                self.assertTrue(receipts[0]['body_data_null'])
            else:
                self.assertEqual(receipts[0]['header_count'], 1)
                self.assertTrue(receipts[0]['headers_null'])
            self.assertEqual(result['original_headers'], 0)
            self.assertEqual(result['original_body'], 0)
            neighbor = self.native_probe(fault, uri='/neighbor')
            self.assertEqual(neighbor['selected_headers'], 0)
            self.assertEqual(neighbor['selected_body'], 0)

    def test_native_result_target_is_real_mse1_begin_request(self):
        self.assertEqual(self.native_probe('native-invalid-return')['result'], -7)
        self.assertEqual(self.native_probe('native-invalid-return', uri='/neighbor')['result'], 0)

    def test_response_phase_invalid_return_never_targets_request_or_neighbor(self):
        self.assertEqual(self.native_probe('native-response-invalid-return', mode='response-header')['result'], -7)
        self.assertEqual(self.native_probe('native-response-invalid-return', mode='request')['result'], 0)
        self.assertEqual(self.native_probe('native-response-invalid-return', mode='response-header', uri='/neighbor')['result'], 0)

    def test_second_response_append_tracks_native_transaction_across_threads(self):
        result = self.native_probe('native-response-append', mode='response')
        self.assertEqual(result, {'first': 0, 'second': -7, 'wrong': 0, 'released': 0})
        neighbor = self.native_probe('native-response-append', mode='response', uri='/neighbor')
        self.assertEqual(neighbor, {'first': 0, 'second': 0, 'wrong': 0, 'released': 0})

    def run_sink(self, name, recover=False):
        self.ensure_native_probe()
        if self.binary is None:
            self.skipTest('strict C compiler unavailable')
        root = self.root / (name + ('-recover' if recover else ''))
        root.mkdir(mode=0o700)
        event = root / 'events.jsonl'
        receipt = root / 'faults.jsonl'
        with receipt.open('wb') as stream:
            env = os.environ | {'I12_ACCEPTANCE_FAULT': name, 'I12_ACCEPTANCE_EVENT_PATH': str(event),
                                'I12_ACCEPTANCE_FAULT_FD': str(stream.fileno())}
            if recover:
                env['I12_ACCEPTANCE_VERIFY_RECOVERY'] = '1'
            result = subprocess.run(['rtk', 'proxy', str(self.binary), str(event)], env=env,
                pass_fds=(stream.fileno(),), capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [json.loads(s) for s in receipt.read_text().splitlines()]
        self.last_fault_receipts = rows
        for row in rows:
            if row['operation'] == 'initial-setvbuf':
                self.assertEqual(row['result'], 0)
        return json.loads(result.stdout), event.read_bytes(), [row for row in rows if row['operation'] not in ('initial-setvbuf', 'owned-event-fd-before-close', 'close-owned-event-fd') and not row['operation'].startswith(('recovery-', 'fault-install-', 'shutdown-'))]

    def test_legitimate_sink_writes_full_line(self):
        result, data, receipts = self.run_sink('control')
        self.assertGreaterEqual(result['put'], 0)
        self.assertEqual(result['flush'], 0)
        self.assertTrue(data.endswith(b'\n'))
        self.assertEqual(receipts, [])

    def test_sink_write_is_real_ebadf_on_owned_readonly_descriptor(self):
        result, data, receipts = self.run_sink('sink-write')
        self.assertEqual(result['put'], -1)
        self.assertEqual(result['put_errno'], 9)
        self.assertEqual(data, b'')
        self.assertEqual(receipts[0]['operation'], 'fputs')

    def test_sink_short_write_has_actual_seven_byte_prefix(self):
        result, data, receipts = self.run_sink('sink-short-write')
        self.assertEqual(result['put'], -1)
        self.assertEqual(data, b'abcdefg')
        self.assertEqual(receipts[0]['result'], 7)

    def test_sink_flush_is_real_ebadf_with_pending_bytes(self):
        result, data, receipts = self.run_sink('sink-flush')
        self.assertEqual(result['flush'], -1)
        self.assertEqual(result['flush_errno'], 9)
        self.assertEqual(data, b'')
        self.assertEqual(receipts[-1]['operation'], 'fflush')

    def test_physical_sink_failure_recovery_preserves_failure_and_same_inode(self):
        for name in ('sink-write', 'sink-flush'):
            with self.subTest(fault=name):
                result, data, _ = self.run_sink(name, recover=True)
                self.assertEqual(result['put'] if name == 'sink-write' else result['flush'], -1)
                self.assertGreaterEqual(result['recovered'], 0)
                self.assertTrue(data.endswith(b'RECOVERED\n'))
                rows = self.last_fault_receipts
                retained = next(row for row in rows if row['operation'] == 'recovery-retain-owned-inode')
                restored = next(row for row in rows if row['operation'] == 'recovery-original-owned-fd-restored')
                self.assertEqual((retained['device'], retained['inode']), (restored['device'], restored['inode']))
                self.assertGreater(restored['monotonic_ns'], next(row['monotonic_ns'] for row in rows
                    if row['operation'] in ('fputs', 'fflush')))

    def test_sink_close_is_real_ebadf_and_once(self):
        result, data, receipts = self.run_sink('sink-close')
        self.assertEqual(result['close'], -1)
        self.assertEqual(result['close_errno'], 9)
        self.assertTrue(data.endswith(b'\n'))
        self.assertEqual([r['operation'] for r in receipts], ['fclose'])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
