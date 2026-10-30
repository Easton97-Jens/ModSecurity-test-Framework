"""Reject filesystem and CLI inputs that escape the admitted Apache task."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import ast
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = connector_root()


def load(name):
    source = source_path('ci/runtime/lifecycle/apache-i12', root=ROOT) / (name + '.py')
    module = load_source(source)
    return module


PATHS = load('paths')
CLIENT = load('observed_curl')
PROJECTION = load('public_projection')


class ApacheBoundaryTests(unittest.TestCase):
    def test_input_and_output_reject_traversal_symlinks_and_shared_parents(self):
        with tempfile.TemporaryDirectory(dir=os.environ['CODEX_TEMP_ROOT']) as root:
            base = Path(root)
            physical = base / 'evidence.json'
            physical.write_text('{}')
            link = base / 'alias.json'
            link.symlink_to(physical)
            with patch.dict(os.environ, CODEX_TEMP_ROOT=root):
                self.assertEqual(PATHS.input_path(physical), physical)
                for supplied in (link, Path('/etc/passwd')):
                    with self.subTest(path=supplied), self.assertRaises(ValueError):
                        PATHS.input_path(supplied)
                with self.assertRaises(ValueError):
                    PATHS.new_output(base / '..' / 'escape')
                shared = base / 'shared'
                shared.mkdir(mode=0o777)
                shared.chmod(0o777)
                with self.assertRaises(ValueError):
                    PATHS.new_output(shared / 'result.json')

    def test_storage_rejects_missing_configuration_and_symlink_root(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(KeyError):
                PATHS.storage_root()
        with tempfile.TemporaryDirectory(dir=os.environ['CODEX_TEMP_ROOT']) as root:
            link = Path(root) / 'alias'
            link.symlink_to(Path(root))
            with patch.dict(os.environ, CODEX_TEMP_ROOT=str(link)):
                with self.assertRaises(ValueError):
                    PATHS.storage_root()

    def test_client_rejects_curl_config_external_urls_and_file_injection(self):
        bad = [
            ['--config', '/etc/curlrc'], ['file:///etc/passwd'],
            ['http://example.org:8080/'], ['http://user:pass@127.0.0.1:8080/'],
            ['-H', '@secret', 'http://127.0.0.1:8080/'],
            ['-H', 'X-Test: value\r\nInjected: yes', 'http://127.0.0.1:8080/'],
            ['-o', '/etc/passwd', 'http://127.0.0.1:8080/'],
            ['--data-binary', '@/etc/passwd', 'http://127.0.0.1:8080/'],
            ['http://127.0.0.1:8080/', 'http://127.0.0.1:8080/second'],
        ]
        with patch.dict(os.environ, I12_APACHE_PRIVATE_RUNTIME='/task/runtime'):
            for arguments in bad:
                with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                    CLIENT.checked_arguments(arguments)
            valid = ['-sS', '--http1.1', '-X', 'POST', '-H', 'X-Test: one', '-H', 'Content-Type;',
                     '--data-binary', '@/task/body', '-o', '/task/response',
                     'http://127.0.0.1:18140/fixture']
            self.assertEqual(CLIENT.checked_arguments(valid), valid)

    def test_response_rule_selector_retains_exact_two_line_rule_and_rejects_neighbors(self):
        sources = (
            'ci/runtime/lifecycle/apache-i12/prepare.py',
            'reports/audits/apache-i12-20261015/rule-equivalence-probe.py',
        )
        rule = 'SecRule RESPONSE_BODY "@contains marker" \\\n    "id:1100301,phase:4,deny,status:403"\n'
        neighbors = (
            'SecRule RESPONSE_BODY "@contains 1100301" \\\n    "id:1100302,phase:4,deny"\n',
            'SecRule REQUEST_BODY "@contains marker" \\\n    "id:1100301,phase:2,deny"\n',
            'SecRule RESPONSE_BODY "@contains marker" \\\n    "msg:' + 'a' * 100000 + ',id:1100302"\n',
        )
        for source in sources:
            tree = ast.parse((ROOT / source).read_text())
            expressions = [node for node in ast.walk(tree)
                           if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                           and node.func.attr == 'compile' and node.args
                           and isinstance(node.args[0], ast.Constant)
                           and '1100301' in str(node.args[0].value)]
            self.assertEqual(len(expressions), 1)
            selector = re.compile(expressions[0].args[0].value, re.MULTILINE)
            with self.subTest(source=source):
                for neighbor in neighbors:
                    self.assertIsNone(selector.search(neighbor))
                text = ''.join(neighbors) + rule + ''.join(neighbors)
                self.assertEqual(selector.search(text).group(), rule)
                self.assertEqual(selector.sub('', text, count=1), ''.join(neighbors) * 2)

    def test_client_endpoint_is_discovered_only_in_url_argument_position(self):
        endpoint = 'http://127.0.0.1:18140/fixture?literal=one%20two'
        arguments = ['-H', 'http://header-only', endpoint]
        admitted, parsed = CLIENT.checked_request(arguments)
        self.assertEqual(admitted, arguments)
        self.assertEqual(parsed.path, '/fixture')
        self.assertEqual(parsed.port, 18140)
        with self.assertRaises(ValueError):
            CLIENT.checked_request(['-H', 'http://header-only'])

    def test_client_rejects_normalized_controls_credentials_and_nonprivate_ports(self):
        invalid = (
            'http://127.0.0.1:8080/fi\nxture',
            ' http://127.0.0.1:8080/fixture',
            'http://127.0.0.1:8080/fixture\x00',
            'http://@127.0.0.1:8080/fixture',
            'http://127.0.0.1:1023/fixture',
            'http://127.0.0.1:65536/fixture',
            'https://127.0.0.1:8080/fixture',
        )
        for endpoint in invalid:
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                CLIENT.checked_arguments([endpoint])
        for port in (1024, 65535):
            endpoint = 'http://127.0.0.1:%d/fixture' % port
            self.assertEqual(CLIENT.checked_arguments([endpoint]), [endpoint])

    def test_neighbor_uses_admitted_endpoint_not_http_looking_header(self):
        arguments = ['-H', 'http://header-only', 'http://127.0.0.1:18140/fixture?x=1']
        process = subprocess.CompletedProcess([], 0, stdout=b'200', stderr=b'')
        with tempfile.TemporaryDirectory(dir=os.environ['CODEX_TEMP_ROOT']) as root:
            with patch.object(CLIENT, 'run_raw', return_value=(process, {})) as run:
                CLIENT.capture_neighbor(arguments, Path(root), 'principal')
            followup = run.call_args.args[0]
            self.assertEqual(followup[-1], 'http://127.0.0.1:18140/no-crs/allow')
            self.assertEqual(len(list(Path(root).glob('*.actual-process.json'))), 1)

    def test_public_projection_preserves_source_and_only_renames_numeric_join(self):
        original = {'positive_control': {'clients': [{'actual_process': {
            'client_token': '123456789', 'actual_waited_exit_code': 0}}]}, 'faults': []}
        raw = json.dumps(original).encode()
        result = PROJECTION.project(raw, 'git:immutable:source.json')
        self.assertEqual(json.loads(raw), original)
        self.assertFalse(result['public_projection']['is_physical_capture'])
        process = result['positive_control']['clients'][0]['actual_process']
        self.assertEqual(process, {'client_process_correlation_id': '123456789',
                                   'actual_waited_exit_code': 0})
        original['positive_control']['clients'][0]['actual_process']['client_token'] = 'unexpected'
        invalid = json.dumps(original).encode()
        with self.assertRaises(ValueError):
            PROJECTION.project(invalid, 'git:immutable:source.json')



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
