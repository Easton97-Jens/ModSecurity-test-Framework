"""Real APR bucket/Common validator/SDK controls; no live Apache launch."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = connector_root()
HERE = source_path('ci/runtime/lifecycle/apache-i12/acceptance', root=ROOT)
BUILD = load_source(HERE / 'build_fault_boundary.py')

FIXTURE = r'''
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <httpd.h>
#include <apr_general.h>
#include <apr_buckets.h>
#include <apr_portable.h>
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include "apache-fault-boundary.h"
#include "msconnector/transaction_contract.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
static int original_result=-99,original_errno=-99;
static const char *scenario;
extern int __real_msc_process_request_headers(Transaction *);
extern int __real_msc_process_logging(Transaction *);
extern int __real_msc_append_response_body(Transaction *,const unsigned char *,size_t);
extern int __real_msc_add_request_header(Transaction *,const unsigned char *,const unsigned char *);
int __wrap_msc_append_response_body(Transaction *tx,const unsigned char *body,size_t size) {
    int result=__real_msc_append_response_body(tx,body,size); original_result=result; original_errno=errno; return result;
}
int __wrap_msc_add_request_header(Transaction *tx,const unsigned char *key,const unsigned char *value) {
    int result=__real_msc_add_request_header(tx,key,value); original_result=result; original_errno=errno; return result;
}
int __wrap_msc_process_request_headers(Transaction *tx) {
    int result=__real_msc_process_request_headers(tx); original_result=result; original_errno=errno; return result;
}
int __wrap_msc_process_logging(Transaction *tx) {
    int result=__real_msc_process_logging(tx); original_result=result; original_errno=errno; return result;
}
static void invoke(request_rec *r,apr_pool_t *pool,const char *operation) {
    if(!strcmp(operation,"null-body")) {
        apr_bucket_alloc_t *allocator=apr_bucket_alloc_create(pool);
        apr_bucket *bucket=apr_bucket_heap_create("actual-body",11,NULL,allocator);
        const char *data=NULL;apr_size_t size=0;
        int read_result=apr_bucket_read(bucket,&data,&size,APR_BLOCK_READ);
        if(read_result!=APR_SUCCESS || !data || size!=11)exit(50);
        errno=E2BIG;int changed=i12_apache_fault_after_bucket_read(r,&data,size,read_result);int saved=errno;
        printf("{\"operation\":\"body\",\"actual_read_result\":%d,\"actual_read_size\":%zu,"
            "\"effective_data_present\":%s,\"changed\":%d,\"errno\":%d}\n",
            read_result,(size_t)size,data?"true":"false",changed,saved);
        apr_bucket_destroy(bucket);apr_bucket_alloc_destroy(allocator);
    } else if(!strcmp(operation,"null-headers")) {
        errno=E2BIG;int result=i12_apache_fault_request_metadata(r);int saved=errno;
        printf("{\"operation\":\"headers\",\"result\":%d,\"errno\":%d}\n",result,saved);
    } else {
        ModSecurity *engine=msc_init();RulesSet *rules=msc_create_rules_set(); const char *error=NULL;
        if(!engine || !rules || msc_rules_add(rules,"SecRuleEngine On\n",&error)<0)exit(51);
        Transaction *tx=msc_new_transaction(engine,rules,NULL);if(!tx)exit(52);
        if(msc_process_connection(tx,"127.0.0.1",1234,"127.0.0.1",8080)!=1 ||
            msc_process_uri(tx,"/_fault","POST","1.1")!=1)exit(53);
        static const msconnector_transaction_profile profile={
            .profile_id=1,.profile_name="unit-real-common",.connector_id="apache",.host_adapter_id="fixture",
            .direct_phase_mask=MSCONNECTOR_TRANSACTION_PHASE_MASK_P1|MSCONNECTOR_TRANSACTION_PHASE_MASK_P2|
                MSCONNECTOR_TRANSACTION_PHASE_MASK_P3|MSCONNECTOR_TRANSACTION_PHASE_MASK_P4};
        msconnector_transaction_contract contract;
        const char *id=!strcmp(scenario,"foreign-contract")?"foreign-contract":apr_table_get(r->headers_in,"X-I12-ID");
        if(msconnector_transaction_contract_init(&contract,&profile,id,"apache","unit-real-common",
            MSCONNECTOR_TRANSACTION_MODE_SAFE,1)!=MSCONNECTOR_TRANSACTION_TRANSITION_OK ||
            msconnector_transaction_contract_begin_phase(&contract,MSCONNECTOR_PHASE_REQUEST_HEADERS,2)!=MSCONNECTOR_TRANSACTION_TRANSITION_OK)exit(55);
        int result,first_append=0,committed=0;
        void *opaque=!strcmp(scenario,"null-contract")?NULL:&contract;
        if(!strcmp(scenario,"prior-cause"))
            (void)msconnector_transaction_contract_fail(&contract,MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR,3);
        if(!strcmp(operation,"invalid-native-return") || !strcmp(operation,"technical-precommit") ||
            !strcmp(operation,"timeout-decision-precommit")) {
            errno=E2BIG;result=i12_apache_fault_process_request_headers(r,tx,opaque,0);
        } else if(!strcmp(operation,"mapping-failure")) {
            errno=E2BIG;result=i12_apache_fault_add_request_header(r,tx,
                (const unsigned char *)"X-Actual-Header",(const unsigned char *)"actual-value");
        } else {
            if(msc_process_request_headers(tx)!=1 || msc_process_request_body(tx)!=1 ||
                msc_process_response_headers(tx,200,"HTTP/1.1")!=1)exit(54);
            if(strstr(operation,"postcommit")) {
                for(int phase=MSCONNECTOR_PHASE_REQUEST_HEADERS;phase<MSCONNECTOR_PHASE_RESPONSE_BODY;++phase) {
                    if(msconnector_transaction_contract_complete_phase(&contract,phase,3+phase)!=MSCONNECTOR_TRANSACTION_TRANSITION_OK ||
                        msconnector_transaction_contract_begin_phase(&contract,phase+1,4+phase)!=MSCONNECTOR_TRANSACTION_TRANSITION_OK)exit(56);
                }
                errno=E2BIG;first_append=i12_apache_fault_append_response_body(r,tx,(const unsigned char *)"first",5,opaque,0);
                committed=strcmp(scenario,"uncommitted")!=0;
                if(committed && msconnector_transaction_contract_set_response_committed(&contract,1)!=MSCONNECTOR_TRANSACTION_TRANSITION_OK)exit(57);
                errno=E2BIG;result=i12_apache_fault_append_response_body(r,tx,(const unsigned char *)"second",6,opaque,committed);
            } else {
                if(msc_process_response_body(tx)!=1)exit(58);
                errno=E2BIG;result=i12_apache_fault_process_logging(r,tx);
            }
        }
        int saved=errno,after_error=contract.error_class;
        (void)msconnector_transaction_contract_fail(&contract,MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE,20);
        int preserved=after_error==MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT && (int)contract.error_class==after_error;
        int cleanup=msconnector_transaction_contract_cleanup(&contract,21);
        printf("{\"operation\":\"native\",\"effective_result\":%d,\"original_result\":%d,"
            "\"original_errno\":%d,\"errno\":%d,\"first_append_result\":%d,"
            "\"after_error_class\":%d,\"timeout_first_cause_preserved\":%s,"
            "\"cleanup_result\":%d,\"cleanup_complete\":%s,\"actual_host_committed_flag\":%s}\n",
            result,original_result,original_errno,saved,first_append,after_error,preserved?"true":"false",
            cleanup,contract.cleanup_complete?"true":"false",committed?"true":"false");
        msc_transaction_cleanup(tx);msc_rules_cleanup(rules);msc_cleanup(engine);
    }
    fflush(stdout);
}
int main(int argc,char **argv) {
    if(argc!=3 || apr_initialize()!=APR_SUCCESS)return 2;
    apr_pool_t *pool=NULL;if(apr_pool_create(&pool,NULL)!=APR_SUCCESS)return 3;
    int listener=socket(AF_INET,SOCK_STREAM,0),client=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    if(listener<0 || client<0 || bind(listener,(struct sockaddr *)&address,sizeof(address)) || listen(listener,1))return 4;
    socklen_t length=sizeof(address);if(getsockname(listener,(struct sockaddr *)&address,&length))return 5;
    if(connect(client,(struct sockaddr *)&address,sizeof(address)))return 6;
    int fd=accept(listener,NULL,NULL);if(fd<0)return 7;
    apr_socket_t *stream=NULL;apr_os_sock_t raw=fd;if(apr_os_sock_put(&stream,&raw,pool)!=APR_SUCCESS)return 8;
    conn_rec connection={0};server_rec server={0};request_rec r={0};
    if(apr_socket_addr_get(&connection.client_addr,APR_REMOTE,stream)!=APR_SUCCESS ||
        apr_socket_addr_get(&connection.local_addr,APR_LOCAL,stream)!=APR_SUCCESS)return 9;
    connection.client_ip="127.0.0.1";server.server_hostname="localhost";
    r.pool=pool;r.connection=&connection;r.server=&server;r.method="POST";r.unparsed_uri="/_fault";r.protocol="HTTP/1.1";
    r.headers_in=apr_table_make(pool,4);apr_table_add(r.headers_in,"Host","localhost");
    apr_table_add(r.headers_in,"X-I12-ID","neighbor");
    const char *operation=argv[1],*variant=argv[2];scenario=variant;
    invoke(&r,pool,operation); /* Unselected principal never faults. */
    apr_table_set(r.headers_in,"X-I12-ID","principal-123");
    if(!strcmp(variant,"duplicate"))apr_table_add(r.headers_in,"X-I12-ID","principal-123");
    if(!strcmp(variant,"nonloopback")) {
        if(apr_sockaddr_info_get(&connection.client_addr,"10.1.2.3",APR_INET,1234,0,pool)!=APR_SUCCESS)return 10;
    }
    if(!strcmp(variant,"subrequest"))r.main=&r;
    if(!strcmp(variant,"redirect"))r.prev=&r;
    if(!strcmp(variant,"fork")) {
        pid_t child=fork();if(child<0)return 11;
        if(!child) { invoke(&r,pool,operation);_exit(0); }
        int status;if(waitpid(child,&status,0)!=child || !WIFEXITED(status) || WEXITSTATUS(status))return 12;
    } else invoke(&r,pool,operation);
    invoke(&r,pool,operation); /* Same principal is one-shot. */
    apr_table_set(r.headers_in,"X-I12-ID","followup");r.main=NULL;r.prev=NULL;
    invoke(&r,pool,operation); /* Unselected follow-up is healthy. */
    apr_socket_close(stream);close(client);close(listener);apr_pool_destroy(pool);apr_terminate();return 0;
}
'''

class ApacheFaultBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base = Path(os.environ.get("CODEX_TEST_TMP_ROOT", "/var/tmp/codex/ModSecurity-conector"))
        temporary = tempfile.TemporaryDirectory(prefix="apache-fault-boundary-", dir=base)
        cls.addClassCleanup(temporary.cleanup)
        cls.work = Path(temporary.name)
        include = Path(os.environ.get("MODSECURITY_INCLUDE_DIR", "/usr/include"))
        receipt = BUILD.build(cls.work / "build", include)
        source = cls.work / "fixture.c"
        source.write_text(FIXTURE)
        cls.binary = cls.work / "fixture"
        shared = cls.work / "fixture-shared.so"
        library = os.environ.get("MODSECURITY_LIB_FILE", "/usr/lib/x86_64-linux-gnu/libmodsecurity.so")
        command = ["rtk", "proxy", "cc", "-std=c17", "-Wall", "-Wextra", "-Werror",
                   "-shared", "-fPIC", "-Wl,-Bsymbolic-functions", "-Dmain=fault_fixture_main",
                   "-I", str(include), "-I", BUILD.query("apxs", "-q", "INCLUDEDIR"),
                   "-I", str(source_path('common/include', root=ROOT)), "-I", str(cls.work / "build"),
                   *shlex.split(BUILD.query("apr-1-config", "--includes", "--cppflags", "--cflags")),
                   str(source), str(cls.work / "build/apache-fault-boundary.o"),
                   str(source_path('common/src/request_helpers.c', root=ROOT)), str(source_path('common/src/request_mapper_contract.c', root=ROOT)),
                   str(source_path('common/src/resource_limits.c', root=ROOT)), str(source_path('common/src/headers.c', root=ROOT)),
                   str(source_path('common/src/transaction_state.c', root=ROOT)), str(source_path('common/src/decision_action.c', root=ROOT)),
                   "-Wl,--wrap=msc_process_request_headers", "-Wl,--wrap=msc_process_logging",
                   "-Wl,--wrap=msc_append_response_body", "-Wl,--wrap=msc_add_request_header",
                   library, "-Wl,-rpath," + str(Path(library).parent),
                   *shlex.split(BUILD.query("apr-1-config", "--link-ld", "--libs")), "-laprutil-1", "-o", str(shared)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        loader = cls.work / "loader.c"
        loader.write_text("extern int fault_fixture_main(int,char **);\nint main(int n,char **v){return fault_fixture_main(n,v);}\n")
        loader_command = ["rtk", "proxy", "cc", "-Wall", "-Wextra", "-Werror", str(loader),
                          str(shared), "-Wl,-rpath," + str(cls.work), "-o", str(cls.binary)]
        loader_result = None
        if result.returncode == 0:
            loader_result = subprocess.run(loader_command, capture_output=True, text=True, timeout=60)
        cls.evidence = os.environ.get("I12_APACHE_FAULT_EVIDENCE_DIR")
        if cls.evidence:
            destination = Path(cls.evidence)
            destination.mkdir(parents=True, exist_ok=True)
            (destination / "fixture-build.json").write_text(json.dumps({"command": command, "exit": result.returncode,
                "stdout": result.stdout, "stderr": result.stderr, "helper_build": receipt,
                "loader_command": loader_command, "loader_exit": loader_result.returncode if loader_result else None,
                "loader_stderr": loader_result.stderr if loader_result else None}, indent=2))
            shutil.copy2(source, destination / source.name)
            for name in ("apache-fault-boundary.o", "apache-fault-boundary.h", "fault-boundary-build.json"):
                shutil.copy2(cls.work / "build" / name, destination / name)
            if not result.returncode and loader_result.returncode == 0:
                shutil.copy2(cls.binary, destination / cls.binary.name)
                shutil.copy2(shared, destination / shared.name)
                shutil.copy2(loader, destination / loader.name)
        if result.returncode:
            raise RuntimeError(result.stderr)
        if loader_result.returncode:
            raise RuntimeError(loader_result.stderr)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="case-", dir=self.work)
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.directory.chmod(0o700)
        self.marker = self.directory / "fault-boundary.enable"
        self.marker.write_bytes(b"I12_APACHE_FAULT_BOUNDARY_V1\n")
        self.marker.chmod(0o600)

    def run_case(self, operation, variant="normal", admitted=True):
        env = os.environ.copy()
        env.update(I12_APACHE_FAULT_ROOT=str(self.directory), I12_APACHE_FAULT_ID="principal-123",
                   I12_APACHE_FAULT_MODE=operation)
        if not admitted:
            env.pop("I12_APACHE_FAULT_ROOT")
        command = ["rtk", "proxy", str(self.binary), operation, variant]
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=15)
        if self.evidence:
            destination = Path(self.evidence) / (self._testMethodName + "-" + operation + "-" + variant + "-" + str(admitted))
            destination.mkdir(exist_ok=True)
            (destination / "process.json").write_text(json.dumps({"command": command, "exit": result.returncode,
                "stdout": result.stdout, "stderr": result.stderr}, indent=2))
            output = self.directory / "fault-boundary.jsonl"
            if output.is_file() and not output.is_symlink() and output.stat().st_nlink == 1:
                shutil.copy2(output, destination / output.name)
        self.assertEqual(result.returncode, 0, result.stderr)
        values = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(values), 4)
        self.assertTrue(all(row["errno"] == 7 for row in values))
        return values

    def records(self):
        output = self.directory / "fault-boundary.jsonl"
        if not output.is_file() or output.is_symlink() or output.stat().st_nlink != 1:
            return []
        return [json.loads(line) for line in output.read_text().splitlines()]

    def healthy(self, values, operation):
        if operation == "null-body":
            self.assertTrue(all(row["effective_data_present"] for row in values))
        elif operation == "null-headers":
            self.assertTrue(all(row["result"] == 1 for row in values))
        else:
            self.assertTrue(all(row["effective_result"] == row["original_result"] == 1 for row in values))

    def test_real_apr_bucket_read_then_one_shot_controlled_null_input(self):
        rows = self.run_case("null-body")
        self.assertEqual([row["effective_data_present"] for row in rows], [True, False, True, True])
        self.assertTrue(all(row["actual_read_result"] == 0 and row["actual_read_size"] == 11 for row in rows))
        observed = self.records()
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["original_size"], observed[0]["effective_size"])
        self.assertFalse(observed[0]["return_value_injected"])

    def test_real_common_validator_rejects_controlled_null_headers_nonzero_count(self):
        rows = self.run_case("null-headers")
        self.assertEqual([row["result"] for row in rows], [1, 0, 1, 1])
        observed = self.records()
        self.assertEqual(len(observed), 1)
        self.assertGreater(observed[0]["actual_apr_header_count"], 0)
        self.assertEqual(observed[0]["actual_validator_result"], 0)
        self.assertTrue(observed[0]["actual_validator_reports_missing_headers"])
        self.assertFalse(observed[0]["runtime_mapper_called"])

    def test_real_sdk_original_observation_is_separate_from_controlled_invalid_return(self):
        self.check_native("invalid-native-return", -77)

    def test_real_sdk_original_logging_is_separate_from_controlled_finish_failure(self):
        self.check_native("finish-failure", 0)

    def test_controlled_technical_precommit_keeps_real_sdk_result(self):
        self.check_native("technical-precommit", 0)

    def test_controlled_mapping_failure_uses_real_header_api(self):
        self.check_native("mapping-failure", 0)

    def test_technical_postcommit_requires_second_append_and_committed_flag(self):
        rows = self.check_native("technical-postcommit", -1)
        self.assertTrue(all(row["first_append_result"] == 1 for row in rows))
        controlled = next(row for row in self.records() if row["kind"] == "controlled_return")
        self.assertEqual(controlled["principal_append_ordinal"], 2)
        self.assertTrue(controlled["actual_host_committed_flag"])

    def test_real_common_timeout_precommit_is_not_sdk_result_or_elapsed_budget(self):
        self.check_timeout("timeout-decision-precommit", 0)

    def test_real_common_timeout_postcommit_preserves_first_error_through_cleanup(self):
        self.check_timeout("timeout-decision-postcommit", -1)

    def check_timeout(self, operation, expected):
        rows = self.check_native(operation, expected)
        self.assertEqual([row["timeout_first_cause_preserved"] for row in rows], [False, True, False, False])
        self.assertTrue(all(row["cleanup_complete"] for row in rows))
        actual = next(row for row in self.records() if row["kind"] == "actual_common_timeout_decision")
        self.assertEqual(actual["actual_transition_result"], 0)
        self.assertEqual(actual["before_error_class"], 0)
        self.assertEqual(actual["after_error_class"], rows[1]["after_error_class"])
        self.assertGreater(actual["requested_timestamp_ms"], 0)
        self.assertEqual(actual["actual_error_phase"], actual["before_active_phase"])
        self.assertEqual(actual["phase_value_kind"], "msconnector_phase_enum_not_rule_phase")
        self.assertTrue(actual["real_common_function_called"])
        self.assertFalse(actual["common_return_value_injected"])
        self.assertFalse(actual["elapsed_budget_enforcement_claimed"])
        self.assertEqual(len([row for row in self.records() if row["kind"] == "actual_common_timeout_decision"]), 1)

    def check_native(self, operation, expected):
        rows = self.run_case(operation)
        self.assertEqual([row["effective_result"] for row in rows], [1, expected, 1, 1])
        self.assertTrue(all(row["original_result"] == 1 and row["original_errno"] == row["errno"] for row in rows))
        records = self.records()
        original = next(row for row in records if row["kind"] == "actual_native_original_return")
        controlled = next(row for row in records if row["kind"] == "controlled_return")
        self.assertEqual(original["actual_original_result"], controlled["actual_original_result"])
        self.assertLessEqual(original["monotonic_ns"], controlled["monotonic_ns"])
        self.assertEqual(controlled["effective_result"], expected)
        self.assertFalse(controlled["effective_result_is_sdk_result"])
        self.assertEqual(len([row for row in records if row["kind"] == "controlled_return"]), 1)
        return rows

    def test_uncommitted_second_append_does_not_inject_postcommit_fault(self):
        for operation in ("technical-postcommit", "timeout-decision-postcommit"):
            self.healthy(self.run_case(operation, "uncommitted"), operation)
        self.assertFalse(any(row["kind"] == "controlled_return" for row in self.records()))

    def test_missing_foreign_or_failed_contract_never_becomes_timeout(self):
        for variant in ("null-contract", "foreign-contract", "prior-cause"):
            rows = self.run_case("timeout-decision-precommit", variant)
            self.healthy(rows, "timeout-decision-precommit")
            if variant == "prior-cause":
                self.assertTrue(all(row["after_error_class"] > 0 for row in rows))
                self.assertFalse(any(row["timeout_first_cause_preserved"] for row in rows))
        self.assertFalse(any(row["kind"] == "actual_common_timeout_decision" for row in self.records()))

    def test_fork_shares_the_one_shot_budget(self):
        rows = self.run_case("null-body", "fork")
        self.assertEqual([row["effective_data_present"] for row in rows], [True, False, True, True])
        self.assertEqual(len(self.records()), 1)

    def test_missing_opt_in_never_faults_any_operation(self):
        for operation in ("null-body", "null-headers", "invalid-native-return", "finish-failure",
                          "technical-precommit", "technical-postcommit", "timeout-decision-precommit",
                          "timeout-decision-postcommit", "mapping-failure"):
            self.healthy(self.run_case(operation, admitted=False), operation)
        self.assertEqual(self.records(), [])

    def test_nonloopback_subrequest_redirect_and_duplicate_principal_never_fault(self):
        for variant in ("nonloopback", "subrequest", "redirect", "duplicate"):
            self.healthy(self.run_case("null-body", variant), "null-body")
        self.assertEqual(self.records(), [])

    def test_bad_marker_or_public_directory_never_fault(self):
        self.marker.write_text("wrong\n")
        self.healthy(self.run_case("null-body"), "null-body")
        self.marker.write_bytes(b"I12_APACHE_FAULT_BOUNDARY_V1\n")
        self.directory.chmod(0o755)
        self.healthy(self.run_case("null-body"), "null-body")
        self.assertEqual(self.records(), [])

    def test_output_symlink_and_hardlink_refuse_fault_and_preserve_foreign_file(self):
        foreign = self.work / (self._testMethodName + ".foreign")
        foreign.write_text("retained\n")
        foreign.chmod(0o600)
        output = self.directory / "fault-boundary.jsonl"
        output.symlink_to(foreign)
        self.healthy(self.run_case("null-body"), "null-body")
        output.unlink()
        os.link(foreign, output)
        self.healthy(self.run_case("null-body"), "null-body")
        self.assertEqual(foreign.read_text(), "retained\n")

    def test_public_marker_refuses_fault(self):
        self.marker.chmod(0o644)
        self.healthy(self.run_case("null-body"), "null-body")
        self.assertEqual(self.records(), [])

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
