"""Real SDK/MRC1/JSONL telemetry controls; this does not qualify host cases."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from modsecurity_connector_tests.test_engine_response_limits import ROOT, native_compile_command


class TraefikCompanionMetadata(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(os.environ.get('CODEX_RUN_ROOT', '/var/tmp/codex/ModSecurity-conector/runs'))
        cls.root.mkdir(parents=True, exist_ok=True)
        cls.build = tempfile.TemporaryDirectory(prefix='cm-', dir=cls.root)
        cls.addClassCleanup(cls.build.cleanup)
        cls.binary = Path(cls.build.name) / 'probe'
        command = native_compile_command('tests/traefik_i12_companion_metadata_probe.c', cls.binary,
            extra_sources=['common/runtime/response_companion_client.c',
                           'common/runtime/response_companion_transport.c'])
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    def run_probe(self, scenario, mode='safe', binary=None):
        with tempfile.TemporaryDirectory(prefix='c', dir=self.root) as directory:
            result = subprocess.run([str(binary or self.binary), directory, scenario, mode],
                                    cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            path = Path(directory) / 'events'
            return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_real_committed_p4_safe_retains_late_flag_and_actual_mode(self):
        events = self.run_probe('late')
        terminal = [row for row in events if row['message_id'] == 'MSCONN_EVENT_PHASE4_LATE_INTERVENTION']
        self.assertEqual(len(terminal), 1, events)
        row = terminal[0]
        self.assertTrue(row['response_committed'])
        self.assertTrue(row['headers_sent'])
        self.assertEqual(row['http_status'], 403)
        self.assertEqual(row['requested_action'], 'deny')
        self.assertEqual(row['actual_action'], 'log_only')
        self.assertEqual(row['visible_http_status'], 200)
        self.assert_late_metadata(row, 'safe')

    def assert_late_metadata(self, row, mode):
        self.assertTrue(row['late_intervention'], row)
        self.assertEqual(row.get('late_intervention_mode'), mode, row)

    def assert_nonlate_metadata(self, row):
        self.assertFalse(row['late_intervention'], row)
        self.assertNotIn('late_intervention_mode', row)

    def test_ordinary_allow_does_not_acquire_late_metadata(self):
        self.assertEqual(self.run_probe('allow'), [])

    def test_precommit_p3_deny_remains_nonlate(self):
        events = self.run_probe('precommit')
        self.assertTrue(events)
        self.assertTrue(any(row['actual_action'] == 'deny' for row in events))
        for row in events:
            self.assert_nonlate_metadata(row)

    def test_technical_error_after_commit_is_not_a_late_rule_intervention(self):
        events = self.run_probe('technical')
        self.assertTrue(events)
        for row in events:
            self.assert_nonlate_metadata(row)

    def test_supported_off_mode_is_not_relabelled_safe(self):
        events = self.run_probe('late', 'off')
        terminal = [row for row in events if row['actual_action'] == 'log_only']
        self.assertEqual(len(terminal), 1, events)
        self.assert_late_metadata(terminal[0], 'off')

    def test_unsupported_strict_profile_stays_rejected(self):
        self.assertEqual(self.run_probe('late', 'strict'), [])

    def test_independent_mse1_outcome_preserves_committed_p4_only(self):
        binary = Path(self.build.name) / 'mse1'
        command = native_compile_command('tests/traefik_i12_mse1_metadata_probe.c', binary,
            extra_flags=['-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections'])
        compiled = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=90)
        self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
        result = subprocess.run([str(binary)], cwd=ROOT, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_rejected_mrc1_outcomes_do_not_annotate_retained_decision(self):
        binary = Path(self.build.name) / 'invalid-outcome'
        command = native_compile_command('tests/traefik_i12_companion_invalid_outcome_probe.c', binary,
            extra_flags=['-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections'])
        compiled = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=90)
        self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
        result = subprocess.run([str(binary)], cwd=ROOT, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def compile_mutation(self, name, relative, before, after):
        source = (ROOT / relative).read_text()
        self.assertEqual(source.count(before), 1, 'mutation boundary changed')
        path = Path(self.build.name) / (name + '.c')
        path.write_text(source.replace(before, after, 1))
        binary = Path(self.build.name) / name
        command = native_compile_command('tests/traefik_i12_companion_metadata_probe.c', binary,
            extra_flags=['-Icommon/runtime'],
            extra_sources=['common/runtime/response_companion_client.c',
                           'common/runtime/response_companion_transport.c'])
        command[command.index(relative)] = str(path)
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return binary

    def test_missing_late_annotation_mutation_reproduces_the_defect(self):
        binary = self.compile_mutation('lost-late', 'common/runtime/response_companion_transport.c',
            'state->latest_decision.late_intervention = 1;',
            'state->latest_decision.late_intervention = 0;')
        terminal = [row for row in self.run_probe('late', binary=binary)
                    if row['message_id'] == 'MSCONN_EVENT_PHASE4_LATE_INTERVENTION']
        self.assertEqual(len(terminal), 1)
        with self.assertRaises(AssertionError):
            self.assert_late_metadata(terminal[0], 'safe')

    def test_blanket_late_annotation_mutation_breaks_precommit_control(self):
        relative = 'common/runtime/response_companion_transport.c'
        source = (ROOT / relative).read_text()
        start = source.index('        if (state->committed && state->response_eos &&')
        end = source.index('\n        }', start) + len('\n        }')
        binary = self.compile_mutation('blanket-late', relative, source[start:end],
                                       '        state->latest_decision.late_intervention = 1;')
        terminal = [row for row in self.run_probe('precommit', binary=binary) if row['actual_action'] == 'deny']
        self.assertEqual(len(terminal), 1)
        with self.assertRaises(AssertionError):
            self.assert_nonlate_metadata(terminal[0])

    def test_hardcoded_safe_policy_mutation_breaks_off_mode_control(self):
        binary = self.compile_mutation('forced-safe', 'common/runtime/msconnector_runtime.c',
            'event.flags.late_intervention_mode = phase4_mode_name(\n            runtime->config.phase4_mode);',
            'event.flags.late_intervention_mode = phase4_mode_name(MSCONNECTOR_PHASE4_MODE_SAFE);')
        terminal = [row for row in self.run_probe('late', 'off', binary=binary) if row['actual_action'] == 'log_only']
        self.assertEqual(len(terminal), 1)
        with self.assertRaises(AssertionError):
            self.assert_late_metadata(terminal[0], 'off')



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
