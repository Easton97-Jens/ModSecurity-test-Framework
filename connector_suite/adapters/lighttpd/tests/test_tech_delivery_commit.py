"""Execute real adapter callbacks for technical response delivery and commit."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = connector_root()

from modsecurity_connector_tests import test_lighttpd_i10_adapter_errors as i10
from modsecurity_connector_tests.c_source_contract import function_definition


MAIN = r'''
int main(int argc,char **argv) {
 assert(argc==2);int operation=atoi(argv[1]);
 msconnector_runtime runtime={0};
 msconnector_runtime_transaction transaction={0};
 handler_ctx ctx={.transaction=&transaction};
 plugin_data p={.runtime=&runtime,.defaults={.enabled=1}};
 request_st r={.plugin_ctx={&ctx}};
 active_tx=&transaction;
 const msconnector_transaction_profile *profile=msconnector_profile_registry_find("lighttpd-patched");
 assert(profile!=NULL);
 assert(msconnector_transaction_contract_init(&transaction.contract,profile,"commit-test","lighttpd","fixture",MSCONNECTOR_TRANSACTION_MODE_SAFE,100U)==0);
 if(operation>=1 && operation<=3) {
   ctx.response_processed=1;
   transaction.contract.completed_phase_mask|=MSCONNECTOR_TRANSACTION_PHASE_MASK_P3;
 }
 if(operation==3) {
   assert(msconnector_transaction_contract_fail(&transaction.contract,MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT,101U)==0);
   fault=4;r.write_queue.bytes_out=1;
   assert(mod_msconnector_handle_request_reset(&r,&p)==HANDLER_ERROR);
   assert(transaction.contract.error_class==MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT);
   assert(native_calls==0 && ctx.api_failed && cleanup_calls==1);
   assert(r.plugin_ctx[0]==NULL && ctx.response_body_finished==0);
   return 0;
 }
 if(operation==5) {
   fault=14;
   assert(mod_msconnector_fail_request(&r,&runtime,&ctx,MSCONNECTOR_ERROR_MODSECURITY_FAILURE)==HANDLER_ERROR);
   assert(ctx.technical_failed && !ctx.failure_response_selected);
   int calls=native_calls;
   assert(mod_msconnector_handle_response_start(&r,&p)==HANDLER_ERROR);
   assert(native_calls==calls && status_calls==1);
   return 0;
 }
 if(operation==0 || operation==4) {
   if(operation==4)ctx.api_failed=1;
   assert(mod_msconnector_fail_request(&r,&runtime,&ctx,MSCONNECTOR_ERROR_MODSECURITY_FAILURE)==HANDLER_FINISHED);
   assert(r.http_status==500 && ctx.technical_failed);
   int calls=native_calls;
   assert(mod_msconnector_handle_response_start(&r,&p)==HANDLER_GO_ON);
   assert(native_calls==calls && status_calls==1);
   assert(mod_msconnector_handle_uri_clean(&r,&p)==HANDLER_ERROR);
   assert(native_calls==calls && status_calls==1);
   assert(mod_msconnector_handle_request_reset(&r,&p)==HANDLER_ERROR);
   assert(cleanup_calls==1 && r.plugin_ctx[0]==NULL);
 } else {
   /* Real host reset occurs after output; this seam supplies its exact counters. */
   r.http_status=200;r.resp_header_len=100;r.write_queue.bytes_out=operation==1?126:1;
   assert(mod_msconnector_handle_request_reset(&r,&p)==HANDLER_GO_ON);
   assert(transaction.contract.response_committed==1);
   assert(cleanup_calls==1 && r.plugin_ctx[0]==NULL);
   assert(ctx.response_body_finished==0);
 }
 return 0;
}
'''


class TechnicalDeliveryCommitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        i10.LighttpdI10AdapterErrors.setUpClass()
        cls.addClassCleanup(i10.LighttpdI10AdapterErrors.doClassCleanups)
        cls.directory = i10.LighttpdI10AdapterErrors.directory
        source = (cls.directory / "current.c").read_text()
        cls.source = source.replace("int main(", "int fixture_legacy_main(", 1) + MAIN
        cls.binary = cls.directory / "technical-delivery"
        path = cls.binary.with_suffix(".c")
        path.write_text(cls.source)
        command = [os.environ.get("CC", "cc"), "-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread",
                   "-I", str(ROOT), "-I", str(source_path('common/include', root=ROOT)), str(path)]
        command += [str(source_path('common/src', root=ROOT) / name) for name in
                    ("decision.c", "decision_action.c", "intervention.c", "block_statuses.c", "error.c", "status.c",
                     "late_intervention.c", "http_status.c", "event.c", "json_escape.c", "transaction_state.c")]
        command += [str(source_path('connectors/profile_registry.c', root=ROOT)), "-o", str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise AssertionError(result.stderr)
        prefix, reset = cls.source.rsplit("REQUEST_FUNC(mod_msconnector_handle_request_reset) {", 1)
        variants = {
            "abort-own-error": cls.source.replace("ctx->failure_response_selected ? HANDLER_GO_ON : HANDLER_ERROR;",
                                                   "ctx->failure_response_selected ? HANDLER_ERROR : HANDLER_ERROR;"),
            "abort-api-error": cls.source.replace("return ctx->technical_failed &&\n            ctx->failure_response_selected",
                                                   "return ctx->technical_failed && !ctx->api_failed &&\n            ctx->failure_response_selected"),
            "omit-real-commit": prefix + "REQUEST_FUNC(mod_msconnector_handle_request_reset) {" +
                reset.replace("ctx->transaction, r->write_queue.bytes_out > 0,", "ctx->transaction, r->write_queue.bytes_out < 0,", 1),
            "ignore-commit-return": prefix + "REQUEST_FUNC(mod_msconnector_handle_request_reset) {" +
                reset.replace("&runtime_error) != 1)", "&runtime_error) == 123)", 1),
        }
        cls.mutations = {}
        for name, text in variants.items():
            if text == cls.source:
                raise AssertionError("Mutation failed to alter productive callback: " + name)
            variant_path = cls.directory / (name + ".c")
            variant_binary = variant_path.with_suffix("")
            variant_path.write_text(text)
            variant_command = [str(variant_path) if item == str(path) else str(variant_binary) if item == str(cls.binary)
                               else item for item in command]
            result = subprocess.run(variant_command, capture_output=True, text=True, timeout=60)
            if result.returncode:
                raise AssertionError(result.stderr)
            cls.mutations[name] = variant_binary
        cls.stock_binary = cls.directory / "technical-delivery-stock"
        stock_path = cls.stock_binary.with_suffix(".c")
        stock_source = cls.source.replace("#define LIGHTTPD_MSCONNECTOR_STREAM_HOOK_ABI_VERSION 2", "")
        stock_source = stock_source.replace(function_definition(stock_source, "mod_msconnector_prepare_request_body"), "")
        stock_path.write_text(stock_source)
        stock_command = [str(stock_path) if item == str(path) else str(cls.stock_binary) if item == str(cls.binary)
                         else item for item in command]
        result = subprocess.run(stock_command, capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise AssertionError(result.stderr)

    def test_selected_technical_500_reaches_response_hook_without_engine_reentry(self):
        for binary in (self.binary, self.stock_binary):
            for operation in (0, 4, 5):
                result = subprocess.run([str(binary), str(operation)], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_reset_records_full_and_partial_header_commit_before_finish(self):
        for binary in (self.binary, self.stock_binary):
            for operation in (1, 2):
                with self.subTest(binary=binary.name, operation=operation):
                    result = subprocess.run([str(binary), str(operation)], capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_commit_update_failure_stops_finish_preserves_first_cause_and_cleans(self):
        for binary in (self.binary, self.stock_binary):
            result = subprocess.run([str(binary), "3"], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_delivery_and_checked_commit_mutations_are_red(self):
        for name, operation in (("abort-own-error", 0), ("abort-api-error", 4), ("omit-real-commit", 1), ("ignore-commit-return", 3)):
            with self.subTest(mutation=name):
                result = subprocess.run([str(self.mutations[name]), str(operation)], capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0, "Mutation escaped the concrete delivery/commit assertion")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
