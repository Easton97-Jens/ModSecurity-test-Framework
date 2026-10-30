"""Current report controls: rendering cannot manufacture host qualification."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = connector_root()
REPORT = load_source(source_path('ci/evidence/reports/generate-pr382-i12-current-report.py', root=ROOT))


class CurrentReportTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="i12-current-report-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        authorization = mock.patch.dict(os.environ, {"I12_TEST_ROOT": str(self.root)})
        authorization.start()
        self.addCleanup(authorization.stop)
        self.ledger = {"schema_version": 1, "rows": []}
        for number in range(1484):
            leg = f"route-{number % 13}" if number < 1406 else "diagnostic"
            identity = f"I12::{leg}::control-{number}"
            self.ledger["rows"].append({"run_scoped_case_id": identity, "leg_id": leg,
                "required_leg": number < 1406, "execution_observed": None,
                "selected_requirement": {"run_scoped_case_id": identity,
                    "expected_oracle": {"visible_status": None, "native_result": None}},
                "status": "NOT_EXECUTED_UNQUALIFIED", "qualification_scope": None,
                "historical_status": "NOT_EXECUTED_UNQUALIFIED", "historical_execution_observed": None,
                "qualified_host_lifecycle_pass": False, "current_lifecycle_packet": None,
                "oracle_reconciliation": None})
        ids = [r["run_scoped_case_id"] for r in self.ledger["rows"]]
        contracts = [r["selected_requirement"] for r in self.ledger["rows"]]
        id_sha = hashlib.sha256(("\n".join(ids)+"\n").encode()).hexdigest()
        contract_sha = REPORT.ORACLES.canonical_digest(contracts)
        for name,value in (("ID_SHA256",id_sha),("CONTRACT_SHA256",contract_sha)):
            patch = mock.patch.object(REPORT.ORACLES,name,value)
            patch.start(); self.addCleanup(patch.stop)
        self.reconciliation = {"schema_version": 1,"original_ordered_id_sha256":id_sha,
            "original_selected_contract_sha256":contract_sha,"original_selected_contracts":copy.deepcopy(contracts),
            "oracle_matrix":[],"supplemental_dispositions":[],
            "summary":{"original_open_oracles":596,"resolved_original_oracles":0,
                       "unresolved_original_oracles":596,"actually_retested_original_oracles":0,
                       "baseline_config_parser_pass":0,"baseline_observed_ids":0}}
        self.historical_rows = copy.deepcopy(self.ledger["rows"])
        self.bind_history()
        self.ledger.update(original_ordered_id_sha256=id_sha,original_selected_contract_sha256=contract_sha)
        self.summary()
        self.source = {"i12_status":"I12_PARTIAL","parent_sha":"control-parent",
                       "ci":{"head":"old-control","status":"historical"}}

    def bind_history(self):
        requirements = self.root / 'original-requirements.json'
        selection = self.root / 'original-selection.json'
        requirements.write_text(json.dumps({'rows':self.historical_rows}))
        selection.write_text(json.dumps({'legs':[
            {'leg_id':row['leg_id'],'required_leg':row['required_leg'],
             'required_cases':[row['selected_requirement']]} for row in self.historical_rows]}))
        refs = [REPORT.ORACLES.reference(path) for path in (requirements,selection)]
        for target,name,value in ((REPORT,'HISTORICAL_REQUIREMENTS_SHA256',refs[0]['sha256']),
                                  (REPORT.ORACLES,'SELECTION_SHA256',refs[1]['sha256'])):
            patch=mock.patch.object(target,name,value)
            patch.start();self.addCleanup(patch.stop)
        self.reconciliation['input_evidence']=refs
        self.reconciliation['summary']['baseline_config_parser_pass']=sum(row['status']=='PASS' for row in self.historical_rows)
        self.reconciliation['summary']['baseline_observed_ids']=sum(row['execution_observed'] is True for row in self.historical_rows)

    def summary(self):
        rows = self.ledger["rows"]
        full = [r for r in rows if r["qualification_scope"]=="full_host_lifecycle"]
        self.ledger["summary"] = {
            "original_ids":1484,"actually_executed_ids":sum(r["execution_observed"] is True for r in rows),
            "configuration_only_pass":sum(r["qualification_scope"]=="historical_configuration_only" for r in rows),
            "full_lifecycle_pass":sum(r["status"]=="PASS" for r in full),
            "full_lifecycle_fail":sum(r["status"]=="FAIL" for r in full),
            "required_full_lifecycle_pass":sum(r["required_leg"] and r["status"]=="PASS" for r in full),
            "required_full_lifecycle_fail":sum(r["required_leg"] and r["status"]=="FAIL" for r in full),
            "required_qualified_pass":sum(r["required_leg"] and r["status"]=="PASS" for r in rows),
            "required_qualified_fail":sum(r["required_leg"] and r["status"]=="FAIL" for r in rows),
            "required_routes_with_full_case":len({r["leg_id"] for r in full if r["required_leg"] and r["status"]=="PASS"}),
            "unqualified_ids":sum(r["qualification_scope"] is None for r in rows),
            "oracle_counts":copy.deepcopy(self.reconciliation["summary"])}

    def partial_packet(self):
        row = self.ledger["rows"][0]
        observation_path = self.root/'independent-control-observation.json'
        observation_path.write_text('{"validator_control":1}\n')
        observation_ref = REPORT.ORACLES.reference(observation_path)
        observations = {field:{'value':1,'evidence':[{**observation_ref,'role':role} for role in sorted(roles)]}
                        for field,roles in REPORT.HOST_LEDGER.ROLES.items()}
        observations['native_eos'] = {'value':None,'reason':'Not measured.'}
        path = self.root/"actual-control-packet.json"
        path.write_text(json.dumps({"run_scoped_case_id":row["run_scoped_case_id"],
            "leg_id":row["leg_id"],"reviewed_by":"root","execution_kind":"host_http",
            "execution_observed":True,"run_id":"validator-control","parent_sha":"control-parent",
            "framework_sha":"control-framework","mrts_sha":"control-mrts",
            "effective_config_sha256":"control-config","oracle_evaluated":False,
            "outcome":None,"observations":observations}))
        row.update(status="PARTIAL_HOST_MEASUREMENTS",execution_observed=True,
            current_lifecycle_packet=REPORT.HOST_LEDGER.reviewed_packet(
                REPORT.ORACLES.reference(path),row,row['selected_requirement']['expected_oracle']))
        self.summary()
        return row,path

    def render(self, german=False):
        return REPORT.render(self.ledger,self.reconciliation,self.source,{}, {},german)

    def test_original_order_all_ids_and_null_oracles_preserved_both_languages(self):
        before = copy.deepcopy(self.ledger)
        for german in (False,True):
            host,index = self.render(german)
            actual = [line.split("\t")[0] for line in index.splitlines() if line.startswith("I12::")]
            self.assertEqual(actual,[r["run_scoped_case_id"] for r in before["rows"]])
            self.assertIn('original_oracle={"native_result":null,"visible_status":null}',index)
            self.assertIn('"original_open_oracles": 596',host)
        self.assertEqual(self.ledger,before)

    def test_unknown_eos_remains_partial_without_pass(self):
        row,_ = self.partial_packet()
        host,index = self.render()
        self.assertIn('PARTIAL_HOST_MEASUREMENTS',index)
        self.assertIn('"unknown_fields": [',host)
        self.assertFalse(row["qualified_host_lifecycle_pass"])
        row.update(qualification_scope="full_host_lifecycle",qualified_host_lifecycle_pass=True,status="PASS")
        row["current_lifecycle_packet"]["full_lifecycle_qualified"]=True
        with self.assertRaisesRegex(ValueError,"physical Root packet"):
            self.render()

    def test_configuration_pass_is_separate_from_host_lifecycle(self):
        row = self.ledger["rows"][0]
        row.update(status="PASS",qualification_scope="historical_configuration_only",execution_observed=True)
        row.update(historical_status="PASS",historical_execution_observed=True)
        self.historical_rows[0].update(status="PASS",execution_observed=True)
        self.bind_history()
        self.summary()
        host,_ = self.render()
        self.assertIn('"configuration_only_pass": 1',host)
        self.assertIn('"full_lifecycle_pass": 0',host)
        row["qualified_host_lifecycle_pass"]=True
        with self.assertRaisesRegex(ValueError,"Configuration PASS"):
            self.render()

    def test_unobserved_pass_arbitrary_status_and_fake_configuration_are_rejected(self):
        row = self.ledger['rows'][0]
        original = copy.deepcopy(row)
        for status,scope in (('PASS',None),('FAIL',None),('UNSUPPORTED_FAKE_STATUS',None),
                             ('PASS','historical_configuration_only'),
                             ('NOT_EXECUTED_UNQUALIFIED','invented_scope')):
            with self.subTest(status=status,scope=scope):
                row.update(status=status,qualification_scope=scope)
                self.summary()
                with self.assertRaisesRegex(ValueError,'preserve its historical result and scope'):
                    self.render()
                row.clear();row.update(copy.deepcopy(original))

    def test_packet_execution_and_partial_status_cannot_be_relabelled(self):
        row,_ = self.partial_packet()
        for changes in ({'execution_observed':False},{'execution_observed':None},
                        {'status':'PASS'},{'status':'NOT_EXECUTED_UNQUALIFIED'},
                        {'qualification_scope':'historical_configuration_only'}):
            with self.subTest(changes=changes):
                original = copy.deepcopy(row)
                row.update(changes);self.summary()
                with self.assertRaisesRegex(ValueError,'observed row execution|incomplete packet requires partial'):
                    self.render()
                row.clear();row.update(original)

    def test_historical_result_and_physical_source_cannot_be_rewritten(self):
        row = self.ledger['rows'][0]
        row['historical_status']='PASS'
        with self.assertRaisesRegex(ValueError,'history differs'):
            self.render()
        row['historical_status']='NOT_EXECUTED_UNQUALIFIED'
        row['historical_execution_observed']=True
        with self.assertRaisesRegex(ValueError,'history differs'):
            self.render()
        row['historical_execution_observed']=None
        ref=self.reconciliation['input_evidence'][0]
        Path(ref['path']).write_text('{}')
        with self.assertRaisesRegex(ValueError,'SHA256'):
            self.render()

    def test_sibling_companion_never_inherits_request_packet(self):
        row,_ = self.partial_packet()
        self.ledger["rows"][1]["current_lifecycle_packet"]=copy.deepcopy(row["current_lifecycle_packet"])
        with self.assertRaisesRegex(ValueError,"sibling route or case"):
            self.render()

    def test_ledger_cannot_neutralize_physical_unknown_or_change_measured_value(self):
        row,_ = self.partial_packet()
        original = copy.deepcopy(row['current_lifecycle_packet'])
        row['current_lifecycle_packet']['observations']['native_eos']={'value':1}
        row['current_lifecycle_packet']['unknown_fields']=[]
        with self.assertRaisesRegex(ValueError,'physical Root packet'):
            self.render()
        row['current_lifecycle_packet']=original
        row['current_lifecycle_packet']['observations']['finish_calls']['value']=99
        with self.assertRaisesRegex(ValueError,'physical Root packet'):
            self.render()

    def test_complete_literal_cannot_promote_incomplete_ledger(self):
        for status in ('I12_COMPLETE','I12_HOST_EVIDENCE_COMPLETE_RELEASE_BLOCKED'):
            self.source['i12_status']=status
            with self.assertRaisesRegex(ValueError,'all1406 required PASS and all13 routes'):
                self.render()

    def test_schema_status_and_missing_summary_are_rejected(self):
        self.ledger["schema_version"]=2
        with self.assertRaisesRegex(ValueError,"schema"):
            self.render()
        self.ledger["schema_version"]=1
        self.source.pop("i12_status")
        with self.assertRaisesRegex(ValueError,"explicitly"):
            self.render()

    def test_reordered_or_modified_original_contracts_rejected(self):
        self.ledger["rows"][0],self.ledger["rows"][1]=self.ledger["rows"][1],self.ledger["rows"][0]
        with self.assertRaisesRegex(ValueError,"ordered ID"):
            self.render()
        self.ledger["rows"][0],self.ledger["rows"][1]=self.ledger["rows"][1],self.ledger["rows"][0]
        self.ledger["rows"][0]["selected_requirement"]["expected_oracle"]["visible_status"]=200
        with self.assertRaisesRegex(ValueError,"contracts changed"):
            self.render()

    def test_changed_physical_packet_and_false_summary_rejected(self):
        _,path = self.partial_packet()
        path.write_text('{}')
        with self.assertRaisesRegex(ValueError,"SHA256"):
            self.render()
        row=self.ledger["rows"][0]
        row.update(current_lifecycle_packet=None,status=row['historical_status'],
                   execution_observed=row['historical_execution_observed'],qualification_scope=None)
        self.ledger["summary"]["full_lifecycle_pass"]=99
        with self.assertRaisesRegex(ValueError,"summary differs"):
            self.render()

    def test_cli_preserves_historical_bytes_and_refuses_overwrite(self):
        files = {}
        for name,value in (("ledger",self.ledger),("reconciliation",self.reconciliation),("source-status",self.source)):
            path=self.root/(name+'.json');path.write_text(json.dumps(value));files[name]=path
        for name in ("historical-host-en","historical-host-de","historical-index-en","historical-index-de"):
            path=self.root/(name+'.md');path.write_bytes(b'# Historical\r\nOld strict CI ONLY\r\n');files[name]=path
        output=self.root/'rendered'
        argv=['renderer']+[item for name,path in files.items() for item in ('--'+name,str(path))]+['--output-dir',str(output)]
        with mock.patch('sys.argv',argv): REPORT.main()
        self.assertEqual(len(list(output.glob('*.md'))),4)
        for name,path in files.items():
            if name.startswith('historical'):
                self.assertEqual((output/'history'/path.name).read_bytes(),path.read_bytes())
        with mock.patch('sys.argv',argv),self.assertRaisesRegex(ValueError,'Output already exists'):
            REPORT.main()

    def test_cli_rejects_outside_and_symlinked_output_before_reading_inputs(self):
        """I12-SONAR-REPORT: output admission precedes every physical input."""
        names = ("ledger", "reconciliation", "source-status", "historical-host-en",
                 "historical-host-de", "historical-index-en", "historical-index-de")
        argv = ["renderer"] + [value for name in names for value in ("--" + name, str(self.root / "missing-input"))]
        with tempfile.TemporaryDirectory(prefix="outside-report-", dir=self.root.parent) as outside:
            link = self.root / "redirect"
            link.symlink_to(outside, target_is_directory=True)
            roots = {"CODEX_TEMP_ROOT": str(self.root), "VERIFIED_RUN_ROOT": "", "I12_TEST_ROOT": str(self.root)}
            for target in (Path(outside) / "rendered", link / "rendered"):
                command = argv + ["--output-dir", str(target)]
                with self.subTest(target=target), mock.patch.dict(os.environ, roots), mock.patch("sys.argv", command):
                    with self.assertRaises(ValueError):
                        REPORT.main()
                self.assertFalse((Path(outside) / "rendered").exists())



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
