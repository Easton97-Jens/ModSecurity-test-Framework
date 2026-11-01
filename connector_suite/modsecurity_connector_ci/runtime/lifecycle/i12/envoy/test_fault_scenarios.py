"""Admission and build-identity controls for the interposed EOS test fixture."""
import copy
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.fault_scenarios as F


class ProxyBuildControls(unittest.TestCase):
    def setUp(self):
        self.references = {name: {'path': str(F.H.HERE / name), 'sha256': name, 'bytes': 1}
                           for name in ('fault_proxy.go', 'fault_proxy_test.go', 'fault-proxy', 'go.mod', 'go.sum')}
        self.proof = {'schema': 'i12.envoy.fault-proxy-build.v1',
            'binary': self.references['fault-proxy'], 'source': self.references['fault_proxy.go'],
            'test_source': self.references['fault_proxy_test.go'],
            'actual_go_version': 'go version go1.27.2 linux/amd64',
            'commands': [{'exit_code': 0}],
            'module_inputs': {self.references[name]['path']: name for name in ('go.mod', 'go.sum')}}

    def validate(self, proof, actual=None):
        references = {value['path']: value for value in self.references.values()}
        if actual is not None:
            references[actual['path']] = actual
        with patch.object(F.E, 'read_json', return_value=proof), \
             patch.object(F.E, 'reference', side_effect=lambda path: references[str(path)]):
            return F.proxy_build('synthetic-build-receipt')

    def test_success_requires_all_bound_build_inputs(self):
        self.assertEqual(self.proof, self.validate(self.proof))

    def test_changed_binary_bytes_rejected(self):
        actual = dict(self.references['fault-proxy'], sha256='changed')
        with self.assertRaisesRegex(ValueError, 'physical build input changed'):
            self.validate(self.proof, actual)

    def test_failed_or_missing_build_is_not_accepted(self):
        for commands in ([], [{'exit_code': 1}], [{'exit_code': False}]):
            changed = dict(self.proof, commands=commands)
            with self.subTest(commands=commands), self.assertRaisesRegex(ValueError, 'must be successful'):
                self.validate(changed)

    def test_changed_dependency_and_other_proxy_source_rejected(self):
        changed = copy.deepcopy(self.proof)
        changed['module_inputs'][self.references['go.sum']['path']] = 'changed'
        with self.assertRaisesRegex(ValueError, 'module inputs changed'):
            self.validate(changed)
        changed = dict(self.proof, source=self.references['fault_proxy_test.go'])
        with self.assertRaisesRegex(ValueError, 'selected Envoy test source'):
            self.validate(changed)


class FaultDriverControls(unittest.TestCase):
    def test_fourth_process_is_bound_snapshotted_and_reaped(self):
        inventory = F.H.source_inventory
        manifest = json.loads(inventory.historical_e4_manifest(
            (F.H.HERE.parent / 'manifest.json').read_bytes()))
        metadata = inventory.registry_adapter_metadata(
            manifest, inventory.E4_REVISION, inventory.E4_MANIFEST, inventory.E4_CURRENT)
        content = F.H.capture_content(inventory.E4_REVISION, metadata)
        driver = F.fault_driver(content(F.H.DRIVER_FILE))
        self.assertLess(driver.index("proxy_process=start('fault-proxy'"), driver.index("envoy=start('envoy'"))
        self.assertIn("processes['fault-proxy']=(proxy_process,str(proxy))", driver)
        self.assertIn("for name in ['envoy','fault-proxy','engine','backend']:", driver)
        self.assertIn("'test_proxy_sha256':digest(proxy)", driver)
        self.assertIn("if (os.geteuid(),os.getegid()) != (65534,65534)", driver)
        self.assertIn("if any(final['client_exit_codes'].values()): raise RuntimeError", driver)

    def test_preparation_passes_exact_native_adapter_and_legacy_absence(self):
        for revision, native in (
                (F.H.source_inventory.E4_REVISION, {'envoy_registry_adapter': {'exact': 'native-proof'}}),
                ('a62296fb57263f9be18c6ac879e36e0ab2a9935c', {})):
            args = SimpleNamespace(parent_sha=revision, proxy_build_receipt='proxy-receipt')
            with self.subTest(revision=revision), \
                 patch.object(F.H, 'preparation_inputs', return_value=(None, None, None, native)), \
                 patch.object(F, 'proxy_build'), \
                 patch.object(F.H, 'capture_content', side_effect=ValueError('capture-boundary')) as content:
                with self.assertRaisesRegex(ValueError, 'capture-boundary'):
                    F.prepare(args)
                content.assert_called_once_with(revision, native.get('envoy_registry_adapter'))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
