"""Actual shell wiring with controlled collaborators; no NGINX/build execution."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = connector_root()
STORAGE = Path('/var/tmp/codex/ModSecurity-conector')
LIFECYCLE = source_path('ci/runtime/lifecycle', root=ROOT)
KEYS = ('NO_CRS_SELECTED_CASE_IDS', 'NO_CRS_RUN_ID', 'BUILD_ROOT', 'RESULTS_DIR', 'FRAMEWORK_ROOT',
        'NGINX_PREFIX', 'NGINX_DOCROOT_PROJECTION_PARENT', 'NO_CRS_SELECTED_CASES',
        'FIVE_CONNECTOR_PARENT_COMMIT', 'FIVE_CONNECTOR_FRAMEWORK_COMMIT',
        'NGX_NATIVE_INPUT_FAULT_LIBRARY', 'NGX_NATIVE_BEGIN_FAULT_LIBRARY', 'NGX_NATIVE_WRITE_FAULT_LIBRARY',
        'NGX_NATIVE_FINISH_FAULT_LIBRARY', 'NGX_NATIVE_ENGINE_BUDGET_FAULT_LIBRARY')


class SelectedNativeWiringTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='native-wiring-unit-', dir=STORAGE)
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.parent = self.base / 'parent'
        self.life = self.parent / 'ci/runtime/lifecycle'
        self.life.mkdir(parents=True)
        self.framework = self.base / 'framework'
        runtime = self.framework / 'ci/runtime'
        runtime.mkdir(parents=True)
        common = self.framework / 'ci/lib/common.sh'
        common.parent.mkdir()
        common.write_text('# controlled framework presence\n')
        shutil.copyfile(LIFECYCLE / 'run-nginx-selected-host.sh', self.life / 'run-nginx-selected-host.sh')
        self.trace = self.base / 'trace.jsonl'
        probe = '''import json,os,sys
keys = %r
with open(os.environ['TRACE'], 'a') as output:
    output.write(json.dumps({'name':NAME,'environment':{k:os.environ.get(k) for k in keys}})+'\\n')
sys.exit(int(os.environ.get(NAME.upper()+'_RC','0')))
''' % (KEYS,)
        smoke = runtime / 'run-nginx-smoke.sh'
        smoke.write_text('#!/bin/sh\nexec "$PYTHON" "$FRAMEWORK_ROOT/ci/runtime/smoke-probe.py"\n')
        (runtime / 'smoke-probe.py').write_text("NAME='smoke'\n" + probe)
        for name, filename in [('config', 'run-selected-nginx-configtests.py'), ('native', 'run-selected-nginx-native-operations.py')]:
            (self.life / filename).write_text('NAME=%r\n' % name + probe)
        self.environment = os.environ.copy()
        self.environment.update(dict(CONNECTOR_ROOT=str(self.parent), FRAMEWORK_ROOT=str(self.framework),
            BUILD_ROOT=str(self.base / 'build'), RESULTS_DIR=str(self.base / 'build/results'),
            VERIFIED_RUN_ROOT=str(self.base / 'run'), PYTHON=sys.executable, TRACE=str(self.trace),
            NO_CRS_ARTIFACT_PROFILE='full_lifecycle', FULL_LIFECYCLE_HOST_PROFILE='native-nginx-http-module',
            FULL_LIFECYCLE_EXECUTED_TARGET='full-lifecycle-nginx', NO_CRS_RUN_ID='actual-run',
            NO_CRS_SELECTED_CASE_IDS='invalid_content_length header_count_nonzero_with_null_headers',
            NO_CRS_SELECTED_CASES='allow_without_marker.yaml deny_header_marker_403.yaml',
            NGINX_PREFIX=str(self.base / 'actual-prefix'), NGINX_DOCROOT_PROJECTION_PARENT=str(self.base / 'projection'),
            FIVE_CONNECTOR_PARENT_COMMIT='a' * 40, FIVE_CONNECTOR_FRAMEWORK_COMMIT='b' * 40))
        for key in KEYS:
            if key.endswith('_FAULT_LIBRARY'):
                self.environment[key] = str(self.base / (key + '.so'))
        self.environment.pop('FIVE_CONNECTOR_PROFILE', None)

    def run_host(self, updates=None):
        environment = self.environment | (updates or {})
        return subprocess.run(['sh', str(self.life / 'run-nginx-selected-host.sh')], env=environment,
                              capture_output=True, text=True, timeout=10)

    def records(self):
        return [json.loads(line) for line in self.trace.read_text().splitlines()] if self.trace.exists() else []

    def test_smoke_config_native_order_and_same_real_inputs(self):
        result = self.run_host()
        self.assertEqual(result.returncode, 0, result.stderr)
        records = self.records()
        self.assertEqual([r['name'] for r in records], ['smoke', 'config', 'native'])
        for record in records:
            self.assertEqual(record['environment'], {key:self.environment[key] for key in KEYS})

    def test_actual_exit_priority_and_no_hidden_dispatch_failure(self):
        for smoke, config, native, expected in [(7, 8, 9, 7), (0, 8, 9, 8), (0, 0, 9, 9), (0, 0, 0, 0)]:
            with self.subTest(exits=(smoke,config,native)):
                if self.trace.exists():
                    self.trace.unlink()
                result = self.run_host({'SMOKE_RC':str(smoke), 'CONFIG_RC':str(config), 'NATIVE_RC':str(native)})
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertEqual([r['name'] for r in self.records()], ['smoke', 'config', 'native'])

    def test_missing_dispatcher_fails_not_silent_success(self):
        (self.life / 'run-selected-nginx-native-operations.py').unlink()
        result = self.run_host()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([r['name'] for r in self.records()], ['smoke', 'config'])

    def stage(self, environment=None, unset_prefix=False):
        wrapper = self.parent / 'ci/provisioning/cache/with-runtime-components.sh'
        wrapper.parent.mkdir(parents=True, exist_ok=True)
        wrapper.write_text('#!/bin/sh\nNGINX_PREFIX="$SNAPSHOT_PREFIX"; export NGINX_PREFIX\n'
                           'NO_CRS_RUN_ID=wrong-snapshot; export NO_CRS_RUN_ID\n'
                           'NGX_NATIVE_BEGIN_FAULT_LIBRARY=wrong-snapshot; export NGX_NATIVE_BEGIN_FAULT_LIBRARY\n'
                           'exec "$@"\n')
        wrapper.chmod(0o700)
        env = self.environment | {'SNAPSHOT_PREFIX':str(self.base / 'snapshot-prefix')} | (environment or {})
        if unset_prefix:
            env.pop('NGINX_PREFIX', None)
        return subprocess.run(['sh', str(LIFECYCLE / 'run-connector-stage.sh'), 'nginx', 'no_crs_baseline'],
                              env=env, capture_output=True, text=True, timeout=10)

    def test_stage_reasserts_actual_run_fault_inputs_and_explicit_prefix(self):
        result = self.stage()
        self.assertEqual(result.returncode, 0, result.stderr)
        records = self.records()
        self.assertEqual([r['name'] for r in records], ['smoke', 'config', 'native'])
        for record in records:
            self.assertEqual(record['environment'], {key:self.environment[key] for key in KEYS})

    def test_unset_prefix_keeps_real_component_snapshot_prefix(self):
        result = self.stage(unset_prefix=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        for record in self.records():
            self.assertEqual(record['environment']['NGINX_PREFIX'], str(self.base / 'snapshot-prefix'))

    def test_missing_selected_smoke_fixture_control_stays_strict(self):
        result = self.stage({'NO_CRS_SELECTED_CASES':''})
        self.assertEqual(result.returncode, 1)
        self.assertIn('capability-selected No-CRS runner cases are missing', result.stderr)
        self.assertEqual(self.records(), [])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
