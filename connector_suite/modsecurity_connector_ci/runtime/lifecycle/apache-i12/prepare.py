'Seal Apache-only case inputs for the existing private-runtime-v5 controller.\n\nThis prepares expectations and input hashes, never host observations or PASS.\nShared source-v5, artifacts-v3, Framework, and observers remain unchanged.\n'
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import argparse
import hashlib
import json
import os
import sys
import re
from pathlib import Path
import shutil

paths = load_tool('ci/runtime/lifecycle/apache-i12/paths.py')
LAUNCH_FILE = 'launch.py'
RUN = paths.storage_root() / 'runs/e2e/20261014T182400Z-pr410-oracle-lifecycle'
CASES = ['NEED-request-empty', 'NEED-request-single-chunk', 'NEED-request-content-type-present', 'NEED-request-content-type-missing', 'NEED-request-charset-present', 'NEED-request-charset-missing', 'NEED-request-csv', 'phase4_content_type_with_charset', 'phase4_in_scope_content_type', 'phase4_out_of_scope_content_type', 'phase4_missing_content_type', 'phase2_at_limit', 'phase2_over_limit', 'phase2_truncated', 'phase4_body_at_limit', 'phase4_body_over_limit', 'phase4_body_process_partial', 'phase4_body_reject', 'deny_header_marker_403', 'deny_request_body_marker_403', 'phase3_deny_before_commit', 'phase3_redirect_before_commit', 'phase4_end_of_stream_evaluation', 'duplicate_header_names', 'duplicate_header_names_apache_core_merged']

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def supplemental(case, yaml):
    seed = RUN / 'apache-lifecycle/fixtures-v3/tests/cases/connector-specific/apache/NEED-request-eos-once.yaml'
    fixture = yaml.safe_load(seed.read_text())
    fixture['name'] = case
    fixture['title'] = 'Apache native independent case: ' + case
    fixture['metadata']['source_contract'] = 'Apache I12 supplemental host fixture; original oracle remains unchanged'
    request = fixture['request']
    request['body'] = 'apx-eos-request-payload'
    if case == 'NEED-request-empty':
        request['body'] = ''
    if case.endswith('content-type-missing'):
        request['headers'].pop('Content-Type')
    if case.endswith('charset-present'):
        request['headers']['Content-Type'] = 'text/plain; charset=utf-8'
    if case == 'NEED-request-csv':
        request['headers']['Content-Type'] = 'text/csv'
        request['body'] = 'column_a,column_b\nvalue_a,value_b\n'
    if case.startswith('phase2_'):
        fixture['rules'] += '\nSecRequestBodyLimit 64\nSecRequestBodyNoFilesLimit 64\n'
        request['body'] = 'a' * (64 if case == 'phase2_at_limit' else 65)
        if case == 'phase2_truncated':
            fixture['rules'] += 'SecRequestBodyLimitAction ProcessPartial\n'
        else:
            fixture['rules'] += 'SecRequestBodyLimitAction Reject\n'
        if case == 'phase2_over_limit':
            fixture['expect'] = {'status': 403, 'intervention': 'deny'}
    if case in ('phase4_body_process_partial', 'phase4_body_reject'):
        fixture['response']['body'] = 'a' * 65
        action = 'Reject' if case.endswith('reject') else 'ProcessPartial'
        fixture['rules'] += '\nSecResponseBodyLimit 64\nSecResponseBodyLimitAction ' + action + '\n'
        fixture['expect'] = {'status': 200, 'intervention': 'none'}
    return (fixture, {'case_id': case, 'expected_oracle': None, 'origin': 'missing_host_fixture_or_oracle'})

class ApachePreparation:

    def __init__(self, output, case, deduplicate_response_rule):
        self.output = output
        self.case = case
        self.deduplicate_response_rule = deduplicate_response_rule

    def load_inputs(self):
        import yaml
        self.yaml = yaml
        self.output = paths.new_output(self.output)
        self.allowed = RUN / 'apache-i12-20261015'
        if not self.output.is_relative_to(self.allowed) or self.output == self.allowed:
            raise ValueError('output must be a NEW case directory below ' + str(self.allowed))
        self.output.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.fixtures = self.output / 'fixtures'
        self.fixtures.mkdir(mode=0o700)
        self.here = Path(__file__).resolve().parent
        self.original_case = 'duplicate_header_names' if self.case.endswith('_apache_core_merged') else self.case
        self.candidates = list((RUN / 'sealed-common-inputs/framework/tests/cases').rglob(self.original_case + '.yaml'))
        self.original_path = self.candidates[0] if self.candidates else None

    def select_fixture(self):
        if self.original_path:
            self.original = self.yaml.safe_load(self.original_path.read_text())
            self.fixture = self.yaml.safe_load(self.original_path.read_text())
            (self.fixtures / 'original.yaml').write_bytes(self.original_path.read_bytes())
            if self.case == 'duplicate_header_names_apache_core_merged':
                self.fixture['rules'] = self.fixture['rules'].replace('&REQUEST_HEADERS:X-No-Crs-Duplicate "@eq 2"', '&REQUEST_HEADERS:X-No-Crs-Duplicate "@eq 1"')
                self.fixture['rules'] = self.fixture['rules'].replace('"@streq one" "t:none,chain"\nSecRule REQUEST_HEADERS:X-No-Crs-Duplicate "@streq two" "t:none"', '"@streq one, two" "t:none"')
                self.fixture['name'] = self.case
        else:
            self.fixture, self.original = supplemental(self.case, self.yaml)

    def prepare_partial_fixture(self):
        if self.case == 'phase4_body_process_partial':
            self.fixture['response']['body'] = 'a' * 65
            self.fixture['rules'] = re.sub('SecRule RESPONSE_BODY[^\\n]*\\n[^\\n]*\\n', '', self.fixture['rules'])
            self.fixture['rules'] += 'SecRule RESPONSE_BODY "@streq ' + 'a' * 64 + '" "id:91041504,phase:4,pass,log,t:none,msg:apache-i12-native-partial-64"\n'
            self.fixture['expect'] = {'status': 200, 'intervention': 'none', 'audit_log': {'required': True, 'rule_id': 91041504, 'message': 'apache-i12-native-partial-64'}}
            self.fixture.setdefault('metadata', {})['previous_fixture_error'] = 'Previous marker oracle did not match a*65 payload; earlier sealed fixtures and their outcomes remain unchanged'
            self.fixture['metadata']['independent_native_oracle'] = 'libModSecurity3.0.14 src/transaction.cc1195-1206: ProcessPartial append remaining space up to SecResponseBodyLimit64; native inspection buffer64; wire outcome requires independent capture'

    def deduplicate_rule(self):
        if self.deduplicate_response_rule:
            if self.case not in ('phase4_body_at_limit', 'phase4_body_over_limit', 'phase4_body_reject') or not self.original_path:
                raise ValueError('deduplication only supports the three pinned response-limit originals')
            self.proof_path = RUN / 'apache-i12-20261015/native-rule-equivalence/proof.json'
            self.proof = json.loads(self.proof_path.read_text())
            self.record = next((value for value in self.proof['cases'] if value['case'] == self.case))
            self.canonical_path = RUN / 'sealed-common-inputs/framework/tests/rules/no-crs-baseline.conf'
            self.pattern = re.compile('^SecRule RESPONSE_BODY[^\\n]*\\n(?=[^\\n]*1100301)[^\\n]*\\n', re.MULTILINE)
            self.local_match = self.pattern.search(self.fixture['rules'])
            self.canonical_match = self.pattern.search(self.canonical_path.read_text())
            if self.local_match is None or self.canonical_match is None:
                raise ValueError('expected rule1100301 not found')
            self.normalize = lambda text: re.sub('\\s+', ' ', text).strip()
            if not self.proof.get('all_equivalent') or not self.record.get('equivalent_for_exact_fixture') or self.record['comparison']['local'] != self.record['comparison']['canonical'] or (digest(self.original_path) != self.record['source_sha256']) or (digest(self.canonical_path) != self.proof['canonical_sha256']) or (digest(Path(self.proof['sdk_path'])) != self.proof['sdk_sha256']) or (self.local_match.group() != self.record['local_rule']) or (self.canonical_match.group() != self.record['canonical_rule']) or (self.normalize(self.canonical_match.group().replace(',t:none', '')) != self.normalize(self.local_match.group())) or ('SecDefaultAction' in self.canonical_path.read_text() + self.fixture['rules']):
                raise ValueError('scoped native semantic-equivalence proof does not match exact current inputs')
            self.fixture['rules'] = self.pattern.sub('', self.fixture['rules'], count=1)
            self.fixture.setdefault('metadata', {})['apache_duplicate_rule_normalization'] = {'rule_id': 1100301, 'canonical_binding_path': '/mnt/framework/tests/rules/no-crs-baseline.conf', 'canonical_sha256': self.proof['canonical_sha256'], 'native_sdk_sha256': self.proof['sdk_sha256'], 'semantic_proof_sha256': digest(self.proof_path), 'semantic_scope': self.proof['scope'], 'original_duplicate_load_failure_preserved': True, 'reason': 'Native SDK probes show identical exact64/65-byte fixture outcomes for absent t:none and explicit t:none with no SecDefaultAction; preamble supplies canonical rule once'}
            shutil.copyfile(self.proof_path, self.fixtures / 'rule-equivalence-proof.json')
            shutil.copyfile(self.proof_path.with_name('probe.py'), self.fixtures / 'rule-equivalence-probe.py')

    def write_fixture(self):
        self.common = '\nSecRequestBodyAccess On\nSecResponseBodyAccess On\nSecResponseBodyMimeType text/plain application/json\n'
        if 'SecAuditLog ' not in self.fixture['rules']:
            self.common += 'SecAuditEngine On\nSecAuditLogType Serial\nSecAuditLogParts ABHZ\nSecAuditLog "@@AUDIT_LOG@@"\nSecAuditLogStorageDir "@@AUDIT_LOG_DIR@@"\n'
        if 'SecDebugLog ' not in self.fixture['rules']:
            self.common += 'SecDebugLog "@@AUDIT_LOG_DIR@@/native-debug.log"\nSecDebugLogLevel 5\n'
        self.fixture['rules'] += self.common
        self.fixture['connector'] = 'apache'
        self.fixture.pop('nginx', None)
        self.fixture['status'] = 'pending'
        self.relative = 'tests/cases/connector-specific/apache/' + self.case + '.yaml'
        self.destination = self.fixtures / self.relative
        self.destination.parent.mkdir(parents=True)
        self.destination.write_text(self.yaml.safe_dump(self.fixture, sort_keys=False))
        for source, target in [(LAUNCH_FILE, LAUNCH_FILE), ('observed_curl.py', 'observed-curl.py')]:
            shutil.copyfile(self.here / source, self.fixtures / target)
            (self.fixtures / target).chmod(0o500)
        shutil.copyfile(RUN / 'apache-lifecycle/fixtures-v3/curl-raw-client.py', self.fixtures / 'curl-raw-client.py')
        shutil.copyfile(self.here / 'paths.py', self.fixtures / 'paths.py')
        shutil.copyfile(self.here / 'process_capture.py', self.fixtures / 'process_capture.py')
        self.settings = {'storage_root': str(paths.storage_root()), 'runtime_root': str(paths.storage_root() / 'apache-lifecycle'), 'case_id': self.case, 'original_selected_id': 'I12::apache-native::' + self.original_case, 'fixture_relative_path': self.relative, 'selected_uri': self.fixture['request']['path'], 'run_id': '20261015-apache-i12-' + self.case, 'original_source_path': str(self.original_path) if self.original_path else None, 'original_source_sha256': digest(self.original_path) if self.original_path else None, 'original_expectation': self.original.get('expect', self.original.get('expected_oracle')), 'original_nulls_preserved': True, 'observations': None, 'canonical_no_crs_baseline': bool(self.original.get('no_crs_baseline')), 'canonical_rule_preamble_file': '/mnt/framework/tests/rules/no-crs-baseline.conf' if self.original.get('no_crs_baseline') else None, 'supplemental_expectation': self.fixture.get('expect'), 'limitations': ['input preparation is not execution', 'phase2_truncated uses native ProcessPartial and does not prove truncated HTTP framing']}
        (self.fixtures / 'settings.json').write_text(json.dumps(self.settings, indent=2) + '\n')
        (self.fixtures / 'fixture-contract.json').write_text(json.dumps({'original_selected_requirement': self.original, 'supplemental_fixture': self.fixture, 'actual_runtime': None, 'full_lifecycle_qualification': None, 'settings': self.settings}, indent=2) + '\n')

    def seal_inputs(self):
        self.ledger = {'files': {str(p.relative_to(self.fixtures)): digest(p) for p in sorted(self.fixtures.rglob('*')) if p.is_file()}}
        self.ledger_path = self.output / 'fixtures-ledger.json'
        self.ledger_path.write_text(json.dumps(self.ledger, indent=2, sort_keys=True) + '\n')
        self.spec = json.loads((RUN / 'apache-lifecycle/admission-spec-v3.json').read_text())
        self.binding = next((item for item in self.spec['bindings'] if item['target'] == '/mnt/fixtures'))
        self.binding.update(source=str(self.fixtures), ledger=str(self.ledger_path), ledger_sha256=digest(self.ledger_path))
        self.spec_path = self.output / 'admission-spec.json'
        self.spec_path.write_text(json.dumps(self.spec, indent=2, sort_keys=True) + '\n')
        for path in sorted(self.fixtures.rglob('*'), reverse=True):
            path.chmod(0o555 if path.is_dir() or path.name in (LAUNCH_FILE, 'observed-curl.py') else 0o444)
        self.fixtures.chmod(0o555)
        self.ledger_path.chmod(0o444)
        self.spec_path.chmod(0o444)
        self.output.chmod(0o555)
        print(self.spec_path)

def prepare(output, case, deduplicate_response_rule=False):
    work = ApachePreparation(output, case, deduplicate_response_rule)
    work.load_inputs()
    work.select_fixture()
    work.prepare_partial_fixture()
    work.deduplicate_rule()
    work.write_fixture()
    return work.seal_inputs()
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-input-root', type=Path)
    parser.add_argument('--case', choices=CASES)
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--deduplicate-response-rule', action='store_true')
    args = parser.parse_args()
    if args.list:
        print('\n'.join(CASES))
    elif args.output_input_root is None or args.case is None:
        parser.error('--case and --output-input-root are required')
    else:
        prepare(args.output_input_root, args.case, args.deduplicate_response_rule)
