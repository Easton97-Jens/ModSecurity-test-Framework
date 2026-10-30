"""Test the test-only observer against real Common and a deterministic native ABI.

These controls qualify the measurement seam, not a hosted connector lifecycle.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import json
import hashlib
import os
import re
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = connector_root()
OUTPUT = None


def sdk_helper_command(include, output, mismatch=False):
    """Keep system headers in the compiler's native include-next search order."""
    sdk_headers = [] if include.resolve() == Path("/usr/include") else ["-isystem", str(include)]
    command = ["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", *sdk_headers,
               "-c", str(source_path('ci/runtime/lifecycle/native-lifecycle-sdk.cpp', root=ROOT)), "-o", str(output)]
    if mismatch:
        command.append('-DMSCONNECTOR_LIFECYCLE_SDK_EXPECTED_VERSION="9.9.9"')
    return command


class SdkHelperCommandTests(unittest.TestCase):
    def test_system_sdk_preserves_native_include_next_search_order(self):
        command = sdk_helper_command(Path("/usr/include"), Path("helper.o"))
        self.assertNotIn("-isystem", command)
        self.assertNotIn("/usr/include", command)
        self.assertEqual(command[-2:], ["-o", "helper.o"])

    def test_custom_sdk_retains_explicit_system_header_selection(self):
        include = source_path('tests/fixtures/custom-sdk-headers', root=ROOT)
        command = sdk_helper_command(include, Path("helper.o"))
        index = command.index("-isystem")
        self.assertEqual(command[index + 1], str(include))
        self.assertEqual(command[-2:], ["-o", "helper.o"])


def constructor_id_type(include, output):
    """Ask the selected C header for its constructor signature; retain both probes."""
    probes = []
    for spelling in ("const char", "char"):
        source = (
            '#include <modsecurity/transaction.h>\n'
            'Transaction *(*constructor)(ModSecurity *, RulesSet *, '
            + spelling + ' *, void *) = msc_new_transaction_with_id;\n'
        )
        argv = ["cc", "-std=c17", "-Wall", "-Wextra", "-Werror", "-fsyntax-only",
                "-I", str(include), "-x", "c", "-"]
        result = subprocess.run(argv, input=source, capture_output=True, text=True, check=False)
        probes.append({"id_type": spelling, "source": source, "argv": argv,
                       "returncode": result.returncode, "stderr": result.stderr})
        if result.returncode == 0:
            output.write_text(json.dumps(probes, indent=2) + "\n", encoding="utf-8")
            return spelling
    output.write_text(json.dumps(probes, indent=2) + "\n", encoding="utf-8")
    raise RuntimeError("Selected SDK constructor matches neither supported public C signature")


def companion_runtime_source_copy(output):
    """Add callbacks only at genuine typed boundaries in an external copy."""
    source = (source_path('common/runtime/msconnector_runtime.c', root=ROOT)).read_text(encoding="utf-8")
    source = source.replace('#include "msconnector_runtime.h"',
                            '#include "msconnector_runtime.h"\n#include "native-lifecycle-observer.h"', 1)
    handle = "((msconnector_native_transaction *)transaction->modsecurity.native_transaction)->transaction"
    registration = "    transaction->completion.response_companion_handed_off = 1;\n"
    assert source.count(registration) == 1
    source = source.replace(registration, registration +
        "    (void)msconnector_lifecycle_companion_registered(&registry->entries[free_index],\n"
        "        transaction, &transaction->contract, transaction->modsecurity.native_transaction == NULL\n"
        f"        ? NULL : {handle});\n")
    claim = "    return 1;\n}\n\nint msconnector_runtime_response_companion_session_process_response_headers("
    assert source.count(claim) == 1
    source = source.replace(claim,
        "    {\n"
        "        msconnector_runtime_transaction *transaction = session->entry->transaction;\n"
        "        (void)msconnector_lifecycle_companion_claimed(session, session->entry,\n"
        "            transaction, &transaction->contract, transaction->modsecurity.native_transaction == NULL\n"
        f"            ? NULL : {handle});\n"
        "    }\n" + claim)
    boundary = "    if (entry->transaction != NULL) {\n        if (timeout) {"
    assert source.count(boundary) == 1
    source = source.replace(boundary,
        "    if (entry->transaction != NULL) {\n"
        "        msconnector_runtime_transaction *observed_transaction = entry->transaction;\n"
        "        const msconnector_transaction_contract *observed_common = &entry->transaction->contract;\n"
        "        const msconnector_native_transaction *observed_native = entry->transaction->modsecurity.native_transaction;\n"
        "        const Transaction *observed_native_handle = observed_native == NULL ? NULL : observed_native->transaction;\n"
        "        if (timeout) {")
    destroyed = "        msconnector_runtime_transaction_destroy(&entry->transaction);\n"
    assert source.count(destroyed) == 1
    source = source.replace(destroyed, destroyed +
        "        (void)msconnector_lifecycle_companion_retired(observed_transaction,\n"
        "            observed_common, observed_native_handle);\n")
    output.write_text(source, encoding="utf-8")
    return output
SYMBOLS = (
    "msconnector_transaction_contract_init", "msconnector_transaction_contract_finish",
    "msconnector_transaction_contract_cleanup", "msconnector_transaction_contract_complete_phase",
    "msconnector_transaction_contract_set_response_committed",
    "msconnector_transaction_contract_record_response_metadata", "msc_new_transaction",
    "msc_new_transaction_with_id", "msc_transaction_cleanup", "msc_process_request_body",
    "msc_process_response_body", "msc_process_logging",
    "msc_append_request_body", "msc_append_response_body",
    "msc_process_request_headers", "msc_process_response_headers",
    "msc_intervention",
    "msconnector_runtime_transaction_begin", "msconnector_runtime_transaction_begin_request_stream",
    "msconnector_runtime_transaction_append_request_body_chunk",
    "msconnector_runtime_transaction_finish_request_body",
    "msconnector_runtime_transaction_process_response_headers",
    "msconnector_runtime_transaction_append_response_body_chunk",
    "msconnector_runtime_transaction_finish_response_body",
    "msconnector_runtime_transaction_finish", "msconnector_runtime_transaction_destroy",
    "msconnector_runtime_transaction_finalize_and_snapshot",
    "msconnector_runtime_response_companion_handoff_with_handle",
    "msconnector_runtime_response_companion_claim_handle",
    "msconnector_runtime_response_companion_revoke_handle",
    "msconnector_runtime_response_companion_session_process_response_headers",
    "msconnector_runtime_response_companion_session_append_response_body_chunk",
    "msconnector_runtime_response_companion_session_finish_response_body",
    "msconnector_runtime_response_companion_session_set_response_commit_state",
    "msconnector_runtime_response_companion_session_record_host_action",
    "msconnector_runtime_response_companion_session_fail",
    "msconnector_runtime_response_companion_session_cancel",
    "msconnector_runtime_response_companion_session_release",
)
FIXTURE = r'''
#include "msconnector/transaction_contract.h"
#include "native-lifecycle-observer.h"
#include <modsecurity/transaction.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
extern _Thread_local unsigned int native_calls[8];
static _Thread_local int token;
_Thread_local unsigned int native_calls[8];
Transaction *msc_new_transaction(ModSecurity *m, RulesSet *r, void *d) {
    (void)m;(void)r;(void)d; ++native_calls[5];errno = EDOM; return (Transaction *)&token;
}
Transaction *msc_new_transaction_with_id(ModSecurity *m, RulesSet *r, msconnector_lifecycle_native_id_argument id, void *d) {
    (void)m;(void)r;(void)d; ++native_calls[0];errno = EDOM;
    return strcmp(id,"failure") == 0 ? NULL : (Transaction *)&token;
}
int msc_process_request_body(Transaction *t) {(void)t;++native_calls[2];errno=ERANGE;return -7;}
int msc_process_response_body(Transaction *t) {(void)t;++native_calls[3];errno=ERANGE;return 9;}
int msc_process_logging(Transaction *t) {(void)t;++native_calls[4];errno=ERANGE;return 1;}
void msc_transaction_cleanup(Transaction *t) {(void)t;++native_calls[1];errno=EILSEQ;}
int msc_append_request_body(Transaction *t,const unsigned char *data,size_t size) {
    (void)t;++native_calls[6];errno=ENOBUFS;
    return data!=NULL && size==3U ? 17 : -8;
}
int msc_append_response_body(Transaction *t,const unsigned char *data,size_t size) {
    (void)t;++native_calls[7];errno=ENOBUFS;
    return data==NULL && size==0U ? 19 : -9;
}
int msc_process_request_headers(Transaction *t) {
    (void)t;errno=EHOSTUNREACH;return -11;
}
int msc_process_response_headers(Transaction *t,int status,const char *protocol) {
    (void)t;errno=EPROTO;
    return status==418 && protocol!=NULL && strcmp(protocol,"DO_NOT_CAPTURE_PROTOCOL")==0 ? 23 : -13;
}
int msc_intervention(Transaction *t,ModSecurityIntervention *intervention) {
    (void)t;errno=ENOMSG;
    if(intervention==(ModSecurityIntervention *)(uintptr_t)1)return 0;
    if(intervention==(ModSecurityIntervention *)(uintptr_t)2)return -1;
    if(intervention==(ModSecurityIntervention *)(uintptr_t)3)return 2;
    if(intervention==NULL)return -9;
    intervention->status=451;intervention->disruptive=1;
    intervention->url=(char *)(uintptr_t)1;intervention->log=(char *)(uintptr_t)1;
    return 1;
}
static void *cycle(void *argument) {
    char *id = argument;
    unsigned int before[5];memcpy(before,native_calls,sizeof(before));
    msconnector_transaction_contract c;
    if (msconnector_transaction_contract_init(&c,NULL,id,"test","test",0,1) != 0) abort();
    Transaction *t=msc_new_transaction_with_id(NULL,NULL,id,NULL);
    if (!t || errno != EDOM) abort();
    unsigned int request_appends=native_calls[6],response_appends=native_calls[7];
    const unsigned char data[3]={'a','b','c'};
    if(msc_append_request_body(t,data,3U)!=17 || errno!=ENOBUFS)abort();
    if(msc_append_request_body(t,data,0U)!=-8 || errno!=ENOBUFS)abort();
    if(msc_append_response_body(t,NULL,0U)!=19 || errno!=ENOBUFS)abort();
    if(native_calls[6]!=request_appends+2U || native_calls[7]!=response_appends+1U)abort();
    if (msc_process_request_body(t) != -7 || errno != ERANGE) abort();
    if (msc_process_response_body(t) != 9 || errno != ERANGE) abort();
    if (msc_process_logging(t) != 1 || errno != ERANGE) abort();
    if (msconnector_transaction_contract_record_response_metadata(&c,200,"text/plain",1,10) != 0) abort();
    const enum msconnector_phase phases[]={MSCONNECTOR_PHASE_REQUEST_HEADERS,MSCONNECTOR_PHASE_REQUEST_BODY,MSCONNECTOR_PHASE_RESPONSE_HEADERS};
    for(size_t i=0;i<3U;++i) {
        if(msconnector_transaction_contract_begin_phase(&c,phases[i],2)!=0)abort();
        if(msconnector_transaction_contract_complete_phase(&c,phases[i],2)!=0)abort();
    }
    (void)msconnector_transaction_contract_set_response_committed(&c,0);
    (void)msconnector_transaction_contract_set_response_committed(&c,1);
    (void)msconnector_transaction_contract_set_response_committed(&c,1);
    (void)msconnector_transaction_contract_complete_phase(&c,MSCONNECTOR_PHASE_REQUEST_BODY,2);
    (void)msconnector_transaction_contract_finish(&c,3);
    (void)msconnector_transaction_contract_finish(&c,4);
    (void)msconnector_transaction_contract_cleanup(&c,5);
    msc_transaction_cleanup(t);
    if (errno != EILSEQ) abort();
    for(size_t i=0;i<5U;++i) if(native_calls[i]!=before[i]+1U)abort();
    return NULL;
}
int main(int argc,char **argv) {
    if (argc != 2) return 2;
    if (strncmp(argv[1],"host",4U)==0) {
        static int host,wrong_host;
        msconnector_transaction_contract common,extra;
        if(strcmp(argv[1],"hostoutside")==0)
            return msconnector_lifecycle_host_end(42U,NULL,NULL,NULL,0)!=0;
        uint64_t outer=0U;
        if(strcmp(argv[1],"hostnested")==0)outer=msconnector_lifecycle_host_begin();
        uint64_t call=msconnector_lifecycle_host_begin();if(!call)return 25;
        if(strcmp(argv[1],"hostoverflow")==0) {
            uint64_t calls[8];calls[0]=call;
            for(size_t i=1U;i<8U;++i){calls[i]=msconnector_lifecycle_host_begin();if(!calls[i])return 39;}
            if(msconnector_lifecycle_host_begin()!=0U)return 40;
            for(size_t i=8U;i>0U;--i)
                if(msconnector_lifecycle_host_end(calls[i-1U],NULL,NULL,NULL,0)!=0)return 41;
            return 0;
        }
        if(strcmp(argv[1],"hostfork")==0) {
            pid_t child=fork();if(child<0)return 26;
            if(child==0){if(msconnector_lifecycle_host_end(call,NULL,NULL,NULL,0)!=0)return 27;exit(0);}
            int status;waitpid(child,&status,0);if(status!=0)return 28;
            return msconnector_lifecycle_host_end(call,NULL,NULL,NULL,0)!=0;
        }
        if(strcmp(argv[1],"hostempty")==0)
            return msconnector_lifecycle_host_end(call,&host,NULL,NULL,1)!=0;
        if(msconnector_transaction_contract_init(&common,NULL,"same","test","test",0,1)!=0)return 29;
        int failed=strcmp(argv[1],"hostfailure")==0;
        Transaction *native=msc_new_transaction_with_id(NULL,NULL,failed?"failure":"same",NULL);
        if(strcmp(argv[1],"hostambiguous")==0 &&
            msconnector_transaction_contract_init(&extra,NULL,"same","test","test",0,1)!=0)return 30;
        if(strcmp(argv[1],"hostbadend")==0 &&
            msconnector_lifecycle_host_end(call+1U,&host,&common,native,1)!=0)return 31;
        const msconnector_transaction_contract *provided=strcmp(argv[1],"hostwrongcommon")==0?&extra:&common;
        int expected=!failed && strcmp(argv[1],"hostambiguous")!=0 && strcmp(argv[1],"hostwrongcommon")!=0;
        errno=EBUSY;
        if(msconnector_lifecycle_host_end(call,&host,provided,native,!failed)!=expected || errno!=EBUSY)return 32;
        if(msconnector_lifecycle_host_scope_call(&wrong_host)!=0 || errno!=EBUSY)return 33;
        if(msconnector_lifecycle_host_scope_call(&host)!=(expected?call:0U))return 34;
        if(msconnector_lifecycle_runtime_scope_call((const msconnector_runtime_transaction *)&host)!=0U || errno!=EBUSY)return 39;
        if(msconnector_lifecycle_runtime_scope_call((const msconnector_runtime_transaction *)&common)!=0U || errno!=EBUSY)return 40;
        if(msconnector_lifecycle_runtime_scope_call((const msconnector_runtime_transaction *)native)!=0U || errno!=EBUSY)return 41;
        if(msconnector_lifecycle_host_retire(&host)!=0)return 35;
        if(outer && msconnector_lifecycle_host_end(outer,&wrong_host,NULL,NULL,0)!=0)return 36;
        (void)msconnector_transaction_contract_cleanup(&common,2);
        if(strcmp(argv[1],"hostambiguous")==0)(void)msconnector_transaction_contract_cleanup(&extra,2);
        if(native)msc_transaction_cleanup(native);
        if(msconnector_lifecycle_host_retire(&host)!=expected)return 37;
        if(msconnector_lifecycle_host_scope_call(&host)!=0)return 38;
        return 0;
    }
    if (strcmp(argv[1],"intervention") == 0) {
        Transaction *t=msc_new_transaction_with_id(NULL,NULL,"intervention",NULL);if(!t)return 21;
        ModSecurityIntervention intervention;
        if(msc_intervention(t,&intervention)!=1 || errno!=ENOMSG)return 22;
        if(msc_intervention(t,(ModSecurityIntervention *)(uintptr_t)1)!=0 || errno!=ENOMSG)return 23;
        if(msc_intervention(t,NULL)!=-9 || errno!=ENOMSG)return 24;
        if(msc_intervention(t,(ModSecurityIntervention *)(uintptr_t)2)!=-1 || errno!=ENOMSG)return 25;
        if(msc_intervention(t,(ModSecurityIntervention *)(uintptr_t)3)!=2 || errno!=ENOMSG)return 26;
        msc_transaction_cleanup(t);return 0;
    }
    if (strcmp(argv[1],"headers") == 0) {
        Transaction *t=msc_new_transaction_with_id(NULL,NULL,"headers",NULL);if(!t)return 17;
        if(msc_process_request_headers(t)!=-11 || errno!=EHOSTUNREACH)return 18;
        if(msc_process_response_headers(t,418,"DO_NOT_CAPTURE_PROTOCOL")!=23 || errno!=EPROTO)return 19;
        if(msc_process_response_headers(t,-23,NULL)!=-13 || errno!=EPROTO)return 20;
        msc_transaction_cleanup(t);return errno!=EILSEQ;
    }
    if (strcmp(argv[1],"live") == 0) {
        msconnector_transaction_contract *c=malloc(sizeof(*c));if(!c)return 11;
        if(msconnector_transaction_contract_init(c,NULL,"live","test","test",0,1)!=0)return 12;
        return 0; /* Intentionally retain live object: missing cleanup control. */
    }
    if (strcmp(argv[1],"terminal") == 0) {
        msconnector_transaction_contract c;
        if(msconnector_transaction_contract_init(&c,NULL,"terminal","test","test",0,1)!=0)return 13;
        if(msconnector_transaction_contract_fail(&c,MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR,2)!=0)return 14;
        if(msconnector_transaction_contract_finish(&c,3)!=0)return 15;
        if(msconnector_transaction_contract_finish(&c,4)!=0)return 16;
        (void)msconnector_transaction_contract_cleanup(&c,5);return 0;
    }
    if (strcmp(argv[1],"closed") == 0) close(atoi(getenv("MSCONNECTOR_LIFECYCLE_FD")));
    if (strcmp(argv[1],"partial") == 0) {
        struct stat st;int fd=atoi(getenv("MSCONNECTOR_LIFECYCLE_FD"));
        if(fstat(fd,&st)!=0)return 9;
        struct rlimit limit={(rlim_t)st.st_size+100U,(rlim_t)st.st_size+100U};
        if(signal(SIGXFSZ,SIG_IGN)==SIG_ERR || setrlimit(RLIMIT_FSIZE,&limit)!=0)return 10;
    }
    if (strcmp(argv[1],"overflow") == 0 || strcmp(argv[1],"duplicate") == 0) {
        size_t count = strcmp(argv[1],"duplicate") == 0 ? 1U : 257U;
        msconnector_transaction_contract *c=calloc(count,sizeof(*c));if(!c)return 7;
        for(size_t i=0;i<count;++i)
            if(msconnector_transaction_contract_init(&c[i],NULL,"map","test","test",0,1)!=0)return 8;
        if(count==1U) (void)msconnector_transaction_contract_init(c,NULL,"again","test","test",0,1);
        for(size_t i=0;i<count;++i) (void)msconnector_transaction_contract_cleanup(&c[i],2);
        free(c);return 0;
    }
    if (strcmp(argv[1],"threads") == 0) {
        pthread_t a,b;
        if (pthread_create(&a,NULL,cycle,"one") || pthread_create(&b,NULL,cycle,"two")) return 3;
        pthread_join(a,NULL);pthread_join(b,NULL);
    } else if (strcmp(argv[1],"fork") == 0) {
        pid_t child=fork();if(child<0)return 4;
        if(child==0){cycle("child");exit(0);}int status;waitpid(child,&status,0);
        if(status!=0)return 5;
        cycle("parent");
    } else {
        cycle("quote\"id");cycle("reuse");
        if (msc_new_transaction_with_id(NULL,NULL,"failure",NULL) != NULL || errno != EDOM) return 6;
        Transaction *t=msc_new_transaction(NULL,NULL,NULL);msc_transaction_cleanup(t);
    }
    return 0;
}
'''


class NativeLifecycleObserverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global OUTPUT
        required = ("NATIVE_OBSERVER_TEST_OUT", "MODSECURITY_INCLUDE_DIR", "MODSECURITY_LIB_DIR")
        missing = [name for name in required if not os.environ.get(name)]
        if missing:
            raise unittest.SkipTest("native observer unqualified: explicit configuration missing: " + ", ".join(missing))
        OUTPUT = Path(os.environ["NATIVE_OBSERVER_TEST_OUT"]).resolve()
        cls.include = Path(os.environ["MODSECURITY_INCLUDE_DIR"]).resolve()
        cls.library_directory = Path(os.environ["MODSECURITY_LIB_DIR"]).resolve()
        cls.library = cls.library_directory / "libmodsecurity.so"
        if not (cls.include / "modsecurity/transaction.h").is_file() or not cls.library.is_file():
            raise RuntimeError("explicit selected SDK is missing transaction.h or libmodsecurity.so; no system fallback")
        OUTPUT.mkdir(parents=True, exist_ok=True)
        cls.directory = tempfile.TemporaryDirectory(prefix="observer-", dir=OUTPUT)
        cls.work = Path(cls.directory.name)
        fixture = cls.work / "fixture.c"
        native = cls.work / "native.c"
        declarations, implementation = FIXTURE.split("static _Thread_local int token;", 1)
        native_implementation, main = implementation.split("static void *cycle", 1)
        native.write_text(declarations + "static _Thread_local int token;" + native_implementation, encoding="utf-8")
        fixture.write_text(declarations + "static void *cycle" + main, encoding="utf-8")
        cls.binary = cls.work / "fixture"
        id_type = constructor_id_type(cls.include, OUTPUT / "constructor-signature.json")
        command = ["cc", "-std=c17", "-D_POSIX_C_SOURCE=200809L", "-Wall", "-Wextra", "-Werror",
                   "-DMSCONNECTOR_TEST_ID_CHAR=" + id_type,
                   "-pthread", "-I", str(source_path('common/include', root=ROOT)), "-I", str(source_path('ci/runtime/lifecycle', root=ROOT)), "-I", str(cls.include),
                   str(source_path('ci/runtime/lifecycle/native-lifecycle-observer.c', root=ROOT)), str(fixture), str(native),
                   str(source_path('common/src/transaction_state.c', root=ROOT)),
                   str(source_path('common/src/decision_action.c', root=ROOT)), "-o", str(cls.binary)]
        command.extend(f"-Wl,--wrap={symbol}" for symbol in SYMBOLS)
        cls.compile_command = command
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        (OUTPUT / "compile.json").write_text(json.dumps({"argv": command, "returncode": result.returncode,
                                                         "stdout": result.stdout, "stderr": result.stderr,
                                                         "selected_sdk_include": str(cls.include),
                                                         "selected_sdk_library": str(cls.library.resolve()),
                                                         "selected_sdk_library_sha256": hashlib.sha256(cls.library.read_bytes()).hexdigest()}), encoding="utf-8")
        if result.returncode:
            raise RuntimeError(result.stderr)

    def test_public_constructor_qualification_is_exact_and_unknown_types_fail(self):
        # These are compile-contract variants of the selected public header,
        # not claims to execute a second SDK binary. Keep every other header
        # declaration and the complete observer/native fixture unchanged.
        header = (self.include / "modsecurity/transaction.h").read_text()
        pattern = (r"(Transaction \*msc_new_transaction_with_id\(ModSecurity \*ms,"
                   r"\s*RulesSet \*rules, )(?:const )?char \*id(, void \*logCbData\);)")
        self.assertEqual(len(re.findall(pattern, header)), 1)
        for qualification, accepted in (("char *", True), ("const char *", True),
                                        ("char **", False)):
            with self.subTest(qualification=qualification):
                directory = tempfile.TemporaryDirectory(prefix="constructor-contract-", dir=OUTPUT)
                self.addCleanup(directory.cleanup)
                variant = Path(directory.name)
                include = variant / "modsecurity"
                include.mkdir(parents=True)
                changed = re.sub(pattern, lambda match: match[1] + qualification + "id" + match[2], header)
                (include / "transaction.h").write_text(changed)
                command = list(self.compile_command)
                command[1:1] = ["-I", str(variant)]
                command[command.index("-o") + 1] = str(variant / "fixture")
                result = subprocess.run(command, capture_output=True, text=True, timeout=90)
                (variant / "compile.json").write_text(json.dumps({
                    "argv": command, "exit": result.returncode,
                    "stdout": result.stdout, "stderr": result.stderr,
                    "scope": "synthetic public declaration qualification; selected SDK supporting headers"}))
                if accepted:
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("_Generic", result.stderr)

    @classmethod
    def tearDownClass(cls):
        retained = OUTPUT / "retained-artifacts"
        retained.mkdir(mode=0o700)
        manifest = []
        for source in sorted(cls.work.iterdir()):
            if source.is_symlink() or not source.is_file():
                raise RuntimeError("unexpected control artifact; refuse silent evidence loss")
            raw = source.read_bytes()
            destination = retained / source.name
            destination.write_bytes(raw)
            destination.chmod(0o600)
            manifest.append({"build_path": str(source), "retained_path": str(destination),
                             "sha256": hashlib.sha256(raw).hexdigest(),
                             "build_mode": source.stat().st_mode & 0o7777})
        (OUTPUT / "retained-files.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        cls.directory.cleanup()

    def run_fixture(self, mode="normal", configured=True, permissions=0o600):
        path = self.work / f"{self._testMethodName}-{mode}.jsonl"
        descriptor = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_APPEND | os.O_EXCL, permissions)
        environment = os.environ.copy()
        environment["LD_LIBRARY_PATH"] = str(self.library_directory)
        environment.pop("MSCONNECTOR_LIFECYCLE_FD", None)
        if configured:
            environment.update(MSCONNECTOR_LIFECYCLE_FD=str(descriptor), MSCONNECTOR_LIFECYCLE_RUN="control",
                               MSCONNECTOR_LIFECYCLE_PROFILE="unit", MSCONNECTOR_LIFECYCLE_CASE='escape"case')
        try:
            result = subprocess.run([str(self.binary), mode], env=environment, pass_fds=(descriptor,),
                                    capture_output=True, text=True, check=False)
        finally:
            os.close(descriptor)
        self.assertEqual(result.returncode, 0, result.stderr)
        raw_lines = path.read_text(encoding="utf-8").splitlines()
        if mode == "partial":
            self.assertGreater(len(raw_lines), 1)
            with self.assertRaises(json.JSONDecodeError):
                json.loads(raw_lines[-1])
            raw_lines = raw_lines[:-1]
        events = [json.loads(line) for line in raw_lines]
        (OUTPUT / f"{self._testMethodName}-{mode}.json").write_text(json.dumps({"mode": mode, "events": events,
                                                                       "stderr": result.stderr,
                                                                       "partial_record": path.read_text(encoding="utf-8").splitlines()[-1] if mode == "partial" else None}), encoding="utf-8")
        return events, result.stderr

    def assert_pairs(self, events):
        enters = {(e["pid"], e["call"]): e for e in events if e["edge"] == "enter"}
        returns = {(e["pid"], e["call"]): e for e in events if e["edge"] == "return"}
        self.assertEqual(set(enters), set(returns))
        for key, entry in enters.items():
            self.assertEqual(entry["function"], returns[key]["function"])
        self.assertTrue(all(e["wall_ns"] > 0 and e["wall_sample_end_monotonic_ns"] >= e["monotonic_ns"] for e in events))
        self.assertTrue(all(not e["invalid"] for e in events))
        self.assertTrue(all(e["host_eos"] is None and e["native_mime_selection"] is None for e in events))

    def test_constructor_qualifier_probe_accepts_both_public_header_signatures(self):
        include = self.work / "signature-control"
        headers = include / "modsecurity"
        headers.mkdir(parents=True)
        for spelling in ("const char", "char"):
            (headers / "transaction.h").write_text(
                'typedef struct ModSecurity_t ModSecurity;\n'
                'typedef struct Rules_t RulesSet;\n'
                'typedef struct Transaction_t Transaction;\n'
                'Transaction *msc_new_transaction_with_id(ModSecurity *, RulesSet *, '
                + spelling + ' *, void *);\n', encoding="utf-8")
            selected = constructor_id_type(include, self.work / (spelling.replace(" ", "-") + "-probe.json"))
            self.assertEqual(selected, spelling)
        # Keep retained artifacts flat, as required by the evidence retention guard.
        (headers / "transaction.h").unlink()
        headers.rmdir()
        include.rmdir()

    def test_real_common_failures_attempts_id_reuse_and_native_passthrough(self):
        events, stderr = self.run_fixture()
        self.assertEqual(stderr, "")
        self.assert_pairs(events)
        body = [e for e in events if e["function"] == "native_process_request_body" and e["edge"] == "return"]
        self.assertEqual([e["result"] for e in body], [-7, -7])
        self.assertEqual([e["transaction_id"] for e in body], ['quote"id', "reuse"])
        finishes = [e for e in events if e["function"] == "common_finish" and e["edge"] == "return"]
        self.assertEqual(len(finishes), 4)
        self.assertTrue(any(e["result"] != 0 for e in finishes))
        anonymous = [e for e in events if e["function"] == "native_new" and e["edge"] == "return"]
        self.assertIsNone(anonymous[0]["transaction_id"])
        failure = [e for e in events if e["function"] == "native_new_with_id" and e["edge"] == "return" and e["result"] == 0]
        self.assertEqual(len(failure), 1)

    def test_concurrent_ids(self):
        events, _ = self.run_fixture("threads")
        self.assert_pairs(events)
        ids = {e["transaction_id"] for e in events if e["function"] == "native_process_logging"}
        self.assertEqual(ids, {"one", "two"})

    def test_map_overflow_invalidates_receipt(self):
        events, stderr = self.run_fixture("overflow")
        self.assertTrue(events[-1]["invalid"])
        self.assertIn("evidence invalid", stderr)

    def test_reinitialization_without_cleanup_invalidates_receipt(self):
        events, stderr = self.run_fixture("duplicate")
        self.assertTrue(events[-1]["invalid"])
        self.assertIn("evidence invalid", stderr)

    def test_common_canonical_key_is_not_inferred_from_native_id(self):
        events, _ = self.run_fixture()
        common = [e for e in events if e["function"] == "common_init" and e["edge"] == "return"]
        self.assertTrue(all(e["canonical_transaction_id"] for e in common))
        self.assertNotEqual(common[0]["canonical_transaction_id"], common[1]["canonical_transaction_id"])
        native = [e for e in events if e["function"].startswith("native_")]
        self.assertTrue(all(e["canonical_transaction_id"] is None for e in native))
        # These real Common and native controls intentionally use equal IDs,
        # but have no enclosing runtime allocation. Equality must not join.
        self.assertTrue(all(e["allocation_scope_call"] is None for e in events))
        self.assertFalse(any(e["allocation_join_verified"] for e in events))

    def test_native_append_byte_counts_and_input_kind_never_imply_eos(self):
        events, _ = self.run_fixture()
        appends = [e for e in events if e["function"].startswith("native_append_") and e["edge"] == "return"]
        self.assertEqual([e["input_size"] for e in appends], [3, 0, 0, 3, 0, 0])
        self.assertEqual([e["input_kind"] for e in appends],
                         ["non_null_buffer", "non_null_buffer", "null_buffer"] * 2)
        self.assertEqual([e["result"] for e in appends], [17, -8, 19, 17, -8, 19])
        self.assertTrue(all(e["argument_eos"] is None and e["host_eos"] is None for e in events))

    def test_native_header_phase_failure_and_status_are_forwarded_without_protocol_capture(self):
        events, stderr = self.run_fixture("headers")
        self.assertEqual(stderr, "")
        self.assert_pairs(events)
        request = [e for e in events if e["function"] == "native_process_request_headers"]
        self.assertEqual([e["phase"] for e in request], [1, 1])
        self.assertEqual([e["result"] for e in request], [None, -11])
        self.assertTrue(all(e["argument_response_status"] is None for e in request))
        response = [e for e in events if e["function"] == "native_process_response_headers"]
        self.assertEqual([e["phase"] for e in response], [3, 3, 3, 3])
        self.assertEqual([e["argument_response_status"] for e in response], [418, 418, -23, -23])
        self.assertEqual([e["result"] for e in response], [None, 23, None, -13])
        self.assertNotIn("DO_NOT_CAPTURE_PROTOCOL", json.dumps(events))
        self.assertEqual(events[-1]["live_mappings"], 0)

    def test_native_intervention_outputs_require_success_and_initialized_output(self):
        events, _ = self.run_fixture("intervention")
        self.assert_pairs(events)
        returns = [e for e in events if e["function"] == "native_intervention" and e["edge"] == "return"]
        self.assertEqual([e["result"] for e in returns], [1, 0, -9, -1, 2])
        self.assertEqual([e["intervention_status"] for e in returns], [451, None, None, None, None])
        self.assertEqual([e["intervention_disruptive"] for e in returns], [1, None, None, None, None])
        entries = [e for e in events if e["function"] == "native_intervention" and e["edge"] == "enter"]
        self.assertTrue(all(e["intervention_status"] is None for e in entries))
        self.assertEqual(events[-1]["live_mappings"], 0)

    def test_commit_arguments_and_observed_states_distinguish_attempts(self):
        events, _ = self.run_fixture()
        commits = [e for e in events if e["function"] == "common_set_response_committed"]
        entries = [e for e in commits if e["edge"] == "enter"]
        returns = [e for e in commits if e["edge"] == "return"]
        self.assertEqual([e["argument_committed"] for e in entries], [0, 1, 1, 0, 1, 1])
        self.assertEqual([e["contract_state"]["response_committed"] for e in entries], [0, 0, 1, 0, 0, 1])
        self.assertEqual([e["contract_state"]["response_committed"] for e in returns], [0, 1, 1, 0, 1, 1])

    def test_successful_finish_on_terminal_state_is_not_a_completion_transition(self):
        events, _ = self.run_fixture("terminal")
        finishes = [e for e in events if e["function"] == "common_finish"]
        self.assertEqual(len(finishes), 4)
        self.assertEqual([e["result"] for e in finishes if e["edge"] == "return"], [0, 0])
        statuses = [e["contract_state"]["status"] for e in finishes]
        self.assertTrue(all(status == statuses[0] for status in statuses))

    def test_final_live_mapping_does_not_prove_cleanup(self):
        events, _ = self.run_fixture("live")
        self.assertFalse(events[-1]["invalid"])
        self.assertEqual(events[-1]["live_mappings"], 1)
        self.assertFalse(any(e["function"] == "common_cleanup" for e in events))

    def test_genuine_sdk_constructor_and_physical_cleanup(self):
        source = self.work / "genuine.c"
        source.write_text(r'''
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>
#include <errno.h>
#include <string.h>
extern int msconnector_lifecycle_sdk_transaction_id(void *,const void *,char *,size_t);
int main(int argc,char **argv) {
    ModSecurity *m=msc_init();RulesSet *r=msc_create_rules_set();
    if(!m || !r)return 2;
    if(argc==2 && strcmp(argv[1],"bounds")==0) {
        char long_id[1024];memset(long_id,'a',sizeof(long_id));long_id[sizeof(long_id)-1U]='\0';
        Transaction *oversized=msc_new_transaction_with_id(m,r,long_id,0);if(!oversized)return 8;
        msc_transaction_cleanup(oversized);msc_rules_cleanup(r);msc_cleanup(m);return 0;
    }
    Transaction *t=msc_new_transaction_with_id(m,r,"genuine-sdk",0);
    if(!t)return 3;
    (void)msc_append_request_body(t,(const unsigned char *)"abc",3U);
    (void)msc_append_response_body(t,(const unsigned char *)"xyz",3U);
    char id[256];errno=ERANGE;
    if(msconnector_lifecycle_sdk_transaction_id(m,t,id,1U)!=-1 || errno!=ERANGE)return 4;
    if(msconnector_lifecycle_sdk_transaction_id(m,NULL,id,sizeof(id))!=-1 || errno!=ERANGE)return 5;
    msc_transaction_cleanup(t);
    t=msc_new_transaction(m,r,0);if(!t)return 6;
    if(msconnector_lifecycle_sdk_transaction_id(m,t,id,sizeof(id))!=1 || id[0]=='\0')return 7;
    msc_transaction_cleanup(t);msc_rules_cleanup(r);msc_cleanup(m);return 0;
}
''', encoding="utf-8")
        binary = self.work / "genuine"
        helper = self.compile_sdk_helper("genuine-helper")
        self.compile_genuine_control(source, binary, helper)
        previous = self.binary
        try:
            self.binary = binary
            events, stderr = self.run_fixture()
            bounds_events, bounds_stderr = self.run_fixture("bounds")
        finally:
            self.binary = previous
        self.assertEqual(stderr, "")
        self.assert_pairs(events)
        cleanup = [e for e in events if e["function"] == "native_cleanup" and e["edge"] == "return"]
        self.assertEqual(len(cleanup), 2)
        self.assertEqual(cleanup[0]["transaction_id"], "genuine-sdk")
        self.assertIsNone(cleanup[0]["result"])
        self.assertTrue(cleanup[1]["transaction_id"])
        self.assertNotEqual(cleanup[1]["transaction_id"], "genuine-sdk")
        self.assertTrue(all(e["transaction_id_origin"] == "sdk_public_m_id" for e in cleanup))
        self.assertEqual(cleanup[0]["input_transaction_id"], "genuine-sdk")
        self.assertIsNone(cleanup[1]["input_transaction_id"])
        self.assertTrue(all(e["canonical_transaction_id"] is None for e in cleanup))
        appends = [e for e in events if e["function"].startswith("native_append_") and e["edge"] == "return"]
        self.assertEqual(len(appends), 2)
        self.assertTrue(all(e["input_size"] == 3 and e["input_kind"] == "non_null_buffer" for e in appends))
        self.assertTrue(all(e["argument_eos"] is None for e in appends))
        self.assertTrue(bounds_events[-1]["invalid"])
        self.assertIn("evidence invalid", bounds_stderr)
        oversized = [e for e in bounds_events if e["function"] == "native_new_with_id" and e["edge"] == "return"]
        self.assertEqual(len(oversized), 1)
        self.assertIsNone(oversized[0]["transaction_id"])
        self.assertEqual(oversized[0]["transaction_id_origin"], "unknown")

    def compile_genuine_control(self, source, binary, helper, extra_sources=()):
        command = ["cc", "-std=c17", "-D_POSIX_C_SOURCE=200809L", "-Wall", "-Wextra", "-Werror",
                   "-pthread", "-I", str(source_path('common/include', root=ROOT)), "-I", str(source_path('common/runtime', root=ROOT)),
                   "-I", str(source_path('ci/runtime/lifecycle', root=ROOT)), "-I", str(self.include),
                   str(source_path('ci/runtime/lifecycle/native-lifecycle-observer.c', root=ROOT)), str(source),
                   str(source_path('common/src/transaction_state.c', root=ROOT)), str(source_path('common/src/decision_action.c', root=ROOT)),
                   str(helper), "-lstdc++", str(self.library), f"-Wl,-rpath,{self.library_directory}", "-o", str(binary)]
        command.extend(f"-Wl,--wrap={symbol}" for symbol in SYMBOLS)
        command.extend(str(path) for path in extra_sources)
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def compile_sdk_helper(self, name, mismatch=False):
        output = self.work / (name + ".o")
        command = sdk_helper_command(self.include, output, mismatch)
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        return output

    def test_sdk_version_mismatch_rejected_before_transaction_access(self):
        source = self.work / "mismatch.c"
        source.write_text(r'''
#include <modsecurity/modsecurity.h>
#include <errno.h>
#include <stdint.h>
extern int msconnector_lifecycle_sdk_transaction_id(void *,const void *,char *,size_t);
int main(void) {
    ModSecurity *m=msc_init();if(!m)return 2;
    char id[128];errno=ERANGE;
    int result=msconnector_lifecycle_sdk_transaction_id(m,(const void *)(uintptr_t)1,id,sizeof(id));
    if(result!=-2 || errno!=ERANGE || id[0]!='\0')return 3;
    msc_cleanup(m);return 0;
}
''', encoding="utf-8")
        helper = self.compile_sdk_helper("mismatch-helper", mismatch=True)
        binary = self.work / "mismatch"
        command = ["cc", "-std=c17", "-Wall", "-Wextra", "-Werror", "-I", str(self.include),
                   str(source), str(helper), "-lstdc++", str(self.library),
                   f"-Wl,-rpath,{self.library_directory}", "-o", str(binary)]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run([str(binary)], capture_output=True, text=True, check=False,
                                env=dict(os.environ, LD_LIBRARY_PATH=str(self.library_directory)))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_fake_native_controls_do_not_load_sdk_accessor(self):
        events, _ = self.run_fixture()
        native = [e for e in events if e["function"].startswith("native_")]
        self.assertFalse(any(e["transaction_id_origin"] == "sdk_public_m_id" for e in native))

    def test_legacy_fourteen_symbol_link_needs_no_runtime_implementation(self):
        command = json.loads((OUTPUT / "compile.json").read_text(encoding="utf-8"))["argv"]
        added_headers = {"-Wl,--wrap=msc_process_request_headers", "-Wl,--wrap=msc_process_response_headers",
                         "-Wl,--wrap=msc_intervention"}
        command = [argument for argument in command if not argument.startswith("-Wl,--wrap=msconnector_runtime_")
                   and argument not in added_headers]
        binary = self.work / "legacy-fourteen"
        command[command.index("-o") + 1] = str(binary)
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        previous = self.binary
        try:
            self.binary = binary
            events, stderr = self.run_fixture()
        finally:
            self.binary = previous
        self.assertEqual(stderr, "")
        self.assert_pairs(events)
        self.assertFalse(any(e["function"].startswith("runtime_") for e in events))

    def test_selected_real_sdk_intervention_allow_and_deny(self):
        source = self.work / "intervention-sdk.c"
        source.write_text(r'''
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>
#include <string.h>
#include <stdlib.h>
int main(int argc,char **argv) {
    if(argc!=2)return 2;
    int deny=strcmp(argv[1],"deny")==0;
    ModSecurity *engine=msc_init();RulesSet *rules=msc_create_rules_set();
    if(!engine || !rules)return 3;
    const char *error=NULL;
    if(deny && msc_rules_add(rules,"SecRuleEngine On\nSecAction \"id:1999001,phase:1,deny,status:403\"\n",&error)<0)return 4;
    Transaction *transaction=msc_new_transaction_with_id(engine,rules,deny?"sdk-deny":"sdk-allow",NULL);
    if(!transaction)return 5;
    if(!msc_process_connection(transaction,"127.0.0.1",12345,"127.0.0.1",80))return 6;
    if(!msc_process_uri(transaction,"/observer","GET","HTTP/1.1"))return 7;
    if(!msc_process_request_headers(transaction))return 8;
    ModSecurityIntervention intervention={0};
    int result=msc_intervention(transaction,&intervention);
    if((deny && (!result || intervention.status!=403 || intervention.disruptive!=1)) || (!deny && result!=0))return 9;
    /* Both supported public SDKs transfer strdup-owned URL/log buffers. */
    free(intervention.url);
    free(intervention.log);
    intervention.url = NULL;
    intervention.log = NULL;
    msc_transaction_cleanup(transaction);msc_rules_cleanup(rules);msc_cleanup(engine);return 0;
}
''', encoding="utf-8")
        binary = self.work / "intervention-sdk"
        self.compile_genuine_control(source, binary, self.compile_sdk_helper("intervention-sdk-helper"))
        previous = self.binary
        try:
            self.binary = binary
            allow, _ = self.run_fixture("allow")
            deny, _ = self.run_fixture("deny")
        finally:
            self.binary = previous
        for events, expected in ((allow, 0), (deny, 1)):
            self.assert_pairs(events)
            rows = [e for e in events if e["function"] == "native_intervention" and e["edge"] == "return"]
            self.assertEqual([e["result"] for e in rows], [expected])
            self.assertEqual(rows[0]["intervention_status"], 403 if expected else None)
            self.assertEqual(rows[0]["intervention_disruptive"], 1 if expected else None)
            self.assertEqual(events[-1]["live_mappings"], 0)

    def compile_observed_fixture(self, sources, helper, binary, evidence_name):
        command = ["cc", "-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread",
                   "-I", str(ROOT), "-I", str(source_path('common/include', root=ROOT)),
                   "-I", str(source_path('common/runtime', root=ROOT)), "-I", str(source_path('ci/runtime/lifecycle', root=ROOT)), "-I", str(self.include)]
        command.extend(str(path) for path in sources)
        command.extend((str(helper), "-lstdc++", str(self.library),
                        f"-Wl,-rpath,{self.library_directory}", "-o", str(binary)))
        command.extend(f"-Wl,--wrap={symbol}" for symbol in SYMBOLS)
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        (OUTPUT / evidence_name).write_text(json.dumps({"argv": command,
            "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
            "sources": {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources}}), encoding="utf-8")
        self.assertEqual(result.returncode, 0, result.stderr)

    def runtime_fixture(self, mode):
        """Compile current real runtime sources; do not substitute a fake runtime ABI."""
        binary = self.work / "runtime-fixture"
        config = self.work / "runtime.conf"
        if not binary.exists():
            rules = self.work / "runtime.rules"
            rules.write_text("SecRuleEngine On\nSecRequestBodyAccess On\n"
                             "SecResponseBodyAccess On\nSecResponseBodyMimeType text/plain\n", encoding="utf-8")
            config.write_text("enabled=on\nrequest_body_mode=streaming\nresponse_body_mode=streaming\n"
                              f"rules_file={rules}\n", encoding="utf-8")
            source = self.work / "runtime-fixture.c"
            source.write_text(r'''
#include "msconnector_runtime.h"
#include "connectors/profile_registry.h"
#include "native-lifecycle-observer.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int require(int result,const char *operation,msconnector_error *error) {
    if(result)return 1;
    fprintf(stderr,"runtime control failed: %s code=%d\n",operation,(int)error->code);return 0;
}
int main(int argc,char **argv) {
    if(argc!=2)return 2;
    const char *mode=argv[1];
    msconnector_runtime *runtime=NULL;msconnector_runtime_transaction *transaction=NULL;
    char text[512];msconnector_decision decision;msconnector_error error;
    if(!msconnector_runtime_create("traefik",getenv("OBSERVER_RUNTIME_CONFIG"),&runtime,text,sizeof(text))) {
        fprintf(stderr,"runtime create: %s\n",text);return 3;
    }
    if(!msconnector_runtime_set_transaction_profile(runtime,
        msconnector_profile_registry_find("traefik-native-uds")))return 4;
    msconnector_header request_header={"Content-Type",12U,"text/plain",10U};
    msconnector_request request={0};request.method="POST";request.uri="/observer";
    request.http_version="HTTP/1.1";request.hostname="example.test";
    request.client.address="127.0.0.1";request.client.port=12345;
    request.server.address="127.0.0.1";request.server.port=80;
    request.headers=&request_header;request.header_count=1U;
    if(strcmp(mode,"failure")==0) {
        if(msconnector_runtime_transaction_begin_request_stream(NULL,&request,"same-id",&transaction,&decision,&error)!=0)return 5;
        if(transaction!=NULL)return 6;
        msconnector_runtime_destroy(&runtime);return 0;
    }
    if(!require(msconnector_runtime_transaction_begin_request_stream(runtime,&request,"same-id",&transaction,&decision,&error),"begin",&error))return 7;
    if(strcmp(mode,"snapshot-control")==0) {
        msconnector_lifecycle_observer_state state;
        errno=EDOM;
        if(msconnector_lifecycle_observer_snapshot(NULL)!=0 || errno!=EDOM)return 31;
        if(msconnector_lifecycle_observer_snapshot(&state)!=1 || errno!=EDOM || state.live_mappings!=3U || state.pending_calls!=0U || state.invalid)return 32;
    }
    if(strcmp(mode,"finalize-null-snapshot")==0) {
        if(msconnector_runtime_transaction_finalize_and_snapshot(&transaction,NULL,&error)!=0 || transaction==NULL)return 21;
        if(msconnector_lifecycle_runtime_scope_call(transaction)==0U)return 22;
        msconnector_runtime_transaction_destroy(&transaction);
        msconnector_runtime_destroy(&runtime);return 0;
    }
    if(strcmp(mode,"finalize-absent")==0) {
        msconnector_runtime_transaction_snapshot snapshot;
        if(msconnector_runtime_transaction_finalize_and_snapshot(&transaction,&snapshot,&error)!=0 || transaction==NULL)return 23;
        if(msconnector_lifecycle_runtime_scope_call(transaction)==0U)return 24;
        msconnector_runtime_transaction_destroy(&transaction);
        msconnector_runtime_destroy(&runtime);return 0;
    }
    if(strcmp(mode,"absent")==0) {
        msconnector_runtime_transaction_destroy(&transaction);
        msconnector_runtime_destroy(&runtime);return 0;
    }
    if(!require(msconnector_runtime_transaction_append_request_body_chunk(transaction,(const unsigned char *)"abc",3U,&error),"append request",&error))return 8;
    if(strcmp(mode,"premature")==0) {
        msconnector_response response={0};response.status=200;response.http_version="HTTP/1.1";
        if(msconnector_runtime_transaction_process_response_headers(transaction,&response,&decision,&error)!=0)return 9;
        msconnector_runtime_transaction_destroy(&transaction);
        msconnector_runtime_destroy(&runtime);return 0;
    }
    if(!require(msconnector_runtime_transaction_finish_request_body(transaction,&decision,&error),"request EOS",&error))return 10;
    if(strcmp(mode,"duplicate")==0)
        (void)msconnector_runtime_transaction_finish_request_body(transaction,&decision,&error);
    msconnector_header response_header={"Content-Type",12U,"text/plain",10U};
    msconnector_response response={0};response.status=200;response.http_version="HTTP/1.1";
    response.headers=&response_header;response.header_count=1U;
    if(!require(msconnector_runtime_transaction_process_response_headers(transaction,&response,&decision,&error),"response headers",&error))return 11;
    if(!require(msconnector_runtime_transaction_append_response_body_chunk(transaction,(const unsigned char *)"xyz",3U,&error),"append response",&error))return 12;
    if(!require(msconnector_runtime_transaction_finish_response_body(transaction,&decision,&error),"response EOS",&error))return 13;
    if(strcmp(mode,"duplicate")==0)
        (void)msconnector_runtime_transaction_finish_response_body(transaction,&decision,&error);
    if(!require(msconnector_runtime_transaction_finish(transaction,&error),"finish",&error))return 14;
    if(strcmp(mode,"finalize-complete")==0) {
        msconnector_runtime_transaction_snapshot snapshot;
        msconnector_runtime_transaction *saved=transaction;
        if(!require(msconnector_runtime_transaction_finalize_and_snapshot(&transaction,&snapshot,&error),"checked finalize",&error))return 25;
        if(transaction!=NULL || msconnector_lifecycle_runtime_scope_call(saved)!=0U)return 26;
        if(!snapshot.finished || !snapshot.contract.cleanup_complete || snapshot.contract.status!=MSCONNECTOR_TRANSACTION_STATUS_CLEANED)return 27;
        if(msconnector_runtime_transaction_finalize_and_snapshot(&transaction,&snapshot,&error)!=0)return 28;
    }
    msconnector_runtime_transaction_destroy(&transaction);
    if(strcmp(mode,"snapshot-control")==0) {
        msconnector_lifecycle_observer_state state;
        errno=ERANGE;
        if(msconnector_lifecycle_observer_snapshot(&state)!=1 || errno!=ERANGE || state.live_mappings!=0U || state.pending_calls!=0U || state.invalid)return 33;
    }
    msconnector_runtime_destroy(&runtime);return 0;
}
''', encoding="utf-8")
            sources = sorted((source_path('common/src', root=ROOT)).glob("*.c"))
            sources.extend(sorted((source_path('common/runtime', root=ROOT)).glob("*.c")))
            sources.extend((source_path('connectors/profile_registry.c', root=ROOT), source,
                            source_path('ci/runtime/lifecycle/native-lifecycle-observer.c', root=ROOT)))
            helper = self.compile_sdk_helper("runtime-helper")
            self.compile_observed_fixture(sources, helper, binary, "runtime-compile.json")
        previous = self.binary
        previous_config = os.environ.get("OBSERVER_RUNTIME_CONFIG")
        try:
            self.binary = binary
            os.environ["OBSERVER_RUNTIME_CONFIG"] = str(config)
            return self.run_fixture(mode)
        finally:
            self.binary = previous
            if previous_config is None:
                os.environ.pop("OBSERVER_RUNTIME_CONFIG", None)
            else:
                os.environ["OBSERVER_RUNTIME_CONFIG"] = previous_config

    def test_real_runtime_allocation_join_and_explicit_eos_handoffs(self):
        events, stderr = self.runtime_fixture("complete")
        self.assertEqual(stderr, "")
        self.assert_pairs(events)
        begin = next(e for e in events if e["function"] == "runtime_begin_request_stream" and e["edge"] == "return")
        self.assertEqual(begin["result"], 1)
        self.assertTrue(begin["allocation_join_verified"])
        self.assertEqual(begin["allocation_scope_call"], begin["call"])
        returns = [e for e in events if e["edge"] == "return"]
        for name in ("native_new_with_id", "common_init", "native_append_request_body",
                     "native_append_response_body", "native_process_request_body", "native_process_response_body",
                     "native_process_request_headers", "native_process_response_headers",
                     "runtime_finish_request_body", "runtime_finish_response_body", "native_cleanup", "runtime_destroy"):
            rows = [e for e in returns if e["function"] == name]
            self.assertEqual(len(rows), 1, name)
            self.assertEqual(rows[0]["allocation_scope_call"], begin["call"], name)
        native_headers = [e for e in returns if e["function"] in
                          ("native_process_request_headers", "native_process_response_headers")]
        self.assertEqual([e["phase"] for e in native_headers], [1, 3])
        self.assertEqual([e["result"] for e in native_headers], [1, 1])
        self.assertEqual([e["argument_response_status"] for e in native_headers], [None, 200])
        eos = [e for e in returns if e["runtime_eos_handoff"] is not None]
        self.assertEqual([e["runtime_eos_handoff"] for e in eos], ["request_body_finish", "response_body_finish"])
        self.assertTrue(all(e["argument_eos"] is None for e in events))
        self.assertEqual(events[-1]["live_mappings"], 0)
        self.assertEqual(events[-1]["pending_calls"], 0)

    def test_real_collector_snapshot_measures_live_and_actual_cleanup_counters(self):
        events, stderr = self.runtime_fixture("snapshot-control")
        self.assertEqual(stderr, "")
        self.assert_pairs(events)
        rows = [e for e in events if e["function"] == "observer" and e["edge"] == "snapshot"]
        self.assertEqual([e["live_mappings"] for e in rows], [3, 0])
        self.assertEqual([e["pending_calls"] for e in rows], [0, 0])
        self.assertFalse(any(e["invalid"] for e in rows))
        self.assertTrue(any(e["edge"] == "final" for e in events))

    def test_real_checked_finalize_snapshot_retires_only_successful_consuming_cleanup(self):
        for mode in ("finalize-complete", "finalize-null-snapshot", "finalize-absent"):
            with self.subTest(mode=mode):
                events, stderr = self.runtime_fixture(mode)
                self.assertEqual(stderr, "")
                self.assert_pairs(events)
                rows = [e for e in events if e["function"] == "runtime_finalize_and_snapshot" and e["edge"] == "return"]
                self.assertEqual([e["result"] for e in rows], [1, 0] if mode == "finalize-complete" else [0])
                if mode == "finalize-complete":
                    receipt = rows[0]["runtime_finalize_snapshot"]
                    self.assertEqual(receipt, {"handle_cleared": 1, "finished": 1, "cleanup_started": 1, "cleanup_complete": 1, "status": 6, "association_retired": 1})
                    self.assertTrue(rows[0]["allocation_join_verified"])
                    self.assertIsNone(rows[1]["runtime_finalize_snapshot"])
                else:
                    self.assertIsNone(rows[0]["runtime_finalize_snapshot"])
                    self.assertTrue(rows[0]["allocation_join_verified"])
                frees = [e for e in events if e["function"] == "native_cleanup" and e["edge"] == "return"]
                self.assertEqual(len(frees), 1)
                self.assertEqual(events[-1]["live_mappings"], 0)
                self.assertEqual(events[-1]["pending_calls"], 0)

    def test_real_runtime_absent_eos_is_not_inferred_from_cleanup(self):
        events, _ = self.runtime_fixture("absent")
        self.assert_pairs(events)
        self.assertFalse(any(e["runtime_eos_handoff"] is not None for e in events))
        self.assertFalse(any(e["function"] == "native_process_request_body" for e in events))
        self.assertEqual(events[-1]["live_mappings"], 0)

    def test_real_runtime_duplicate_eos_attempts_keep_native_finish_once(self):
        events, _ = self.runtime_fixture("duplicate")
        self.assert_pairs(events)
        for direction in ("request", "response"):
            attempts = [e for e in events if e["function"] == f"runtime_finish_{direction}_body" and e["edge"] == "return"]
            native = [e for e in events if e["function"] == f"native_process_{direction}_body" and e["edge"] == "return"]
            self.assertEqual(len(attempts), 2)
            self.assertEqual(len(native), 1)
        self.assertEqual(events[-1]["live_mappings"], 0)

    def test_real_runtime_premature_response_and_failed_begin_keep_missing_evidence(self):
        events, _ = self.runtime_fixture("premature")
        self.assert_pairs(events)
        response = [e for e in events if e["function"] == "runtime_process_response_headers" and e["edge"] == "return"]
        self.assertEqual([e["result"] for e in response], [0])
        self.assertFalse(any(e["function"] == "native_process_response_headers" for e in events))
        self.assertFalse(any(e["runtime_eos_handoff"] is not None for e in events))
        failed, _ = self.runtime_fixture("failure")
        self.assert_pairs(failed)
        begin = next(e for e in failed if e["function"] == "runtime_begin_request_stream" and e["edge"] == "return")
        self.assertEqual(begin["result"], 0)
        self.assertFalse(begin["allocation_join_verified"])
        self.assertFalse(any(e["function"].startswith("native_") for e in failed))
        self.assertEqual(failed[-1]["live_mappings"], 0)

    def test_ambiguous_nested_allocations_do_not_certify_a_runtime_join(self):
        # Adversarial runtime ABI, real Common and selected real SDK: two
        # native allocations must not become a guessed single association.
        implementation = self.work / "ambiguous-runtime.c"
        implementation.write_text(r'''
#include "msconnector_runtime.h"
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>
#include <string.h>
static msconnector_transaction_contract contract;
static ModSecurity *engine;
static RulesSet *rules;
static Transaction *first,*second;
static int token;
int msconnector_runtime_transaction_begin_request_stream(msconnector_runtime *runtime,
    const msconnector_request *request,const char *id,msconnector_runtime_transaction **out,
    msconnector_decision *decision,msconnector_error *error) {
    (void)runtime;(void)request;(void)decision;(void)error;
    engine=msc_init();rules=msc_create_rules_set();if(!engine || !rules)return 0;
    if(msconnector_transaction_contract_init(&contract,NULL,id,"test","test",0,1)!=0)return 0;
    char native_id[MSCONNECTOR_MAX_TRANSACTION_ID_LENGTH];
    if(id==NULL || strlen(id)>=sizeof(native_id))return 0;
    memcpy(native_id,id,strlen(id)+1U);
    first=msc_new_transaction_with_id(engine,rules,native_id,NULL);
    second=msc_new_transaction_with_id(engine,rules,native_id,NULL);
    if(!first || !second)return 0;
    *out=(msconnector_runtime_transaction *)&token;return 1;
}
void msconnector_runtime_transaction_destroy(msconnector_runtime_transaction **transaction) {
    msc_transaction_cleanup(first);msc_transaction_cleanup(second);
    (void)msconnector_transaction_contract_cleanup(&contract,2);
    msc_rules_cleanup(rules);msc_cleanup(engine);*transaction=NULL;
}
''', encoding="utf-8")
        source = self.work / "ambiguous-main.c"
        source.write_text(r'''
#include "msconnector_runtime.h"
int main(void) {
    msconnector_runtime_transaction *transaction=NULL;msconnector_request request={0};
    msconnector_decision decision;msconnector_error error;
    if(!msconnector_runtime_transaction_begin_request_stream(NULL,&request,"equal-id",&transaction,&decision,&error))return 2;
    msconnector_runtime_transaction_destroy(&transaction);return transaction!=NULL;
}
''', encoding="utf-8")
        binary = self.work / "ambiguous"
        self.compile_genuine_control(source, binary, self.compile_sdk_helper("ambiguous-helper"), (implementation,))
        previous = self.binary
        try:
            self.binary = binary
            events, stderr = self.run_fixture()
        finally:
            self.binary = previous
        self.assertEqual(stderr, "")
        self.assert_pairs(events)
        begin = next(e for e in events if e["function"] == "runtime_begin_request_stream" and e["edge"] == "return")
        self.assertEqual(begin["result"], 1)
        self.assertEqual(begin["allocation_scope_call"], begin["call"])
        allocations = [e for e in events if e["function"] == "native_new_with_id" and e["edge"] == "return"]
        self.assertEqual(len(allocations), 2)
        self.assertTrue(all(e["allocation_scope_call"] == begin["call"] for e in allocations))
        self.assertFalse(any(e["allocation_join_verified"] for e in events))
        self.assertEqual(events[-1]["live_mappings"], 0)

    def companion_fixture(self, mode):
        binary = self.work / "companion-fixture"
        config = self.work / "companion.conf"
        if not binary.exists():
            rules = self.work / "companion.rules"
            rules.write_text("SecRuleEngine On\nSecRequestBodyAccess On\nSecResponseBodyAccess On\n"
                             "SecResponseBodyMimeType text/plain\n", encoding="utf-8")
            config.write_text("enabled=on\nrequest_body_mode=streaming\nresponse_body_mode=streaming\n"
                              f"rules_file={rules}\n", encoding="utf-8")
            source = self.work / "companion-fixture.c"
            source.write_text(r'''
#include "msconnector_runtime.h"
#include "native-lifecycle-observer.h"
#include "connectors/profile_registry.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
int main(int argc,char **argv) {
    if(argc!=2)return 2;
    const char *mode=argv[1];
    msconnector_runtime *runtime=NULL;msconnector_runtime_transaction *transaction=NULL;
    msconnector_runtime_response_companion_registry registry;
    msconnector_runtime_response_companion_session session={0},second={0};
    msconnector_decision decision;msconnector_error error;char text[512],handle[MSCONNECTOR_RUNTIME_RESPONSE_COMPANION_HANDLE_SIZE];
    msconnector_runtime_response_companion_registry_init(&registry);
    if(!msconnector_runtime_create("traefik",getenv("OBSERVER_RUNTIME_CONFIG"),&runtime,text,sizeof(text)))return 3;
    if(!msconnector_runtime_set_transaction_profile(runtime,msconnector_profile_registry_find("traefik-forwardauth")))return 4;
    msconnector_header header={"Content-Type",12U,"text/plain",10U};
    msconnector_request request={0};request.method="POST";request.uri="/companion-control";
    request.http_version="HTTP/1.1";request.hostname="example.test";
    request.client.address="127.0.0.1";request.client.port=12345;
    request.server.address="127.0.0.1";request.server.port=80;request.headers=&header;request.header_count=1U;
    if(!msconnector_runtime_transaction_begin_request_stream(runtime,&request,"companion-same-id",&transaction,&decision,&error))return 5;
    if(!msconnector_runtime_transaction_append_request_body_chunk(transaction,(const unsigned char *)"abc",3U,&error))return 6;
    if(strcmp(mode,"premature")==0) {
        if(msconnector_runtime_response_companion_handoff_with_handle(&registry,transaction,10000,handle,&error)!=0)return 7;
        msconnector_runtime_transaction_destroy(&transaction);msconnector_runtime_destroy(&runtime);return 0;
    }
    errno=EDOM;
    if(msconnector_lifecycle_runtime_scope_call(transaction)==0U || errno!=EDOM)return 36;
    if(msconnector_lifecycle_runtime_scope_call(NULL)!=0U || errno!=EDOM)return 37;
    if(msconnector_lifecycle_runtime_scope_call((const msconnector_runtime_transaction *)(uintptr_t)1)!=0U || errno!=EDOM)return 38;
    if(msconnector_lifecycle_authorization_request_eos(NULL,3U,3U,0U)!=0 || errno!=EDOM)return 31;
    if(msconnector_lifecycle_authorization_request_eos(transaction,3U,3U,1U)!=0 || errno!=EDOM)return 32;
    if(msconnector_lifecycle_authorization_request_eos(transaction,3U,4U,0U)!=0 || errno!=EDOM)return 33;
    if(msconnector_lifecycle_authorization_request_eos(transaction,3U,3U,0U)!=1 || errno!=EDOM)return 34;
    if(!msconnector_runtime_transaction_finish_request_body(transaction,&decision,&error))return 8;
    errno=ERANGE;
    if(msconnector_lifecycle_companion_registered((void *)1,transaction,(void *)2,(void *)3)!=0 || errno!=ERANGE)return 9;
    if(msconnector_lifecycle_companion_claimed(&session,(void *)1,transaction,(void *)2,(void *)3)!=0 || errno!=ERANGE)return 10;
    if(msconnector_lifecycle_companion_retired(transaction,(void *)2,(void *)3)!=0 || errno!=ERANGE)return 11;
    unsigned long ttl=strcmp(mode,"expired")==0 ? 1UL : 10000UL;
    if(!msconnector_runtime_response_companion_handoff_with_handle(&registry,transaction,ttl,handle,&error))return 12;
    errno=EDOM;
    if(msconnector_lifecycle_authorization_request_eos((const msconnector_runtime_transaction *)&registry.entries[0],3U,3U,0U)!=0 || errno!=EDOM)return 35;
    if(msconnector_lifecycle_runtime_scope_call((const msconnector_runtime_transaction *)&registry.entries[0])!=0U || errno!=EDOM)return 39;
    if(strcmp(mode,"badclaim")==0) {
        if(msconnector_runtime_response_companion_claim_handle(&registry,NULL,&session,&error)!=0)return 13;
        if(!msconnector_runtime_response_companion_revoke_handle(&registry,handle,&error))return 14;
        msconnector_runtime_destroy(&runtime);return 0;
    }
    if(strcmp(mode,"expired")==0) {
        struct timespec delay={0,10000000};if(nanosleep(&delay,NULL)!=0)return 15;
        if(msconnector_runtime_response_companion_claim_handle(&registry,handle,&session,&error)!=0)return 16;
        msconnector_runtime_destroy(&runtime);return 0;
    }
    if(!msconnector_runtime_response_companion_claim_handle(&registry,handle,&session,&error))return 17;
    errno=EDOM;
    if(msconnector_lifecycle_runtime_scope_call((const msconnector_runtime_transaction *)&session)!=0U || errno!=EDOM)return 40;
    if(strcmp(mode,"duplicateclaim")==0 && msconnector_runtime_response_companion_claim_handle(&registry,handle,&second,&error)!=0)return 18;
    if(strcmp(mode,"equalids")==0) {
        msconnector_runtime_response_companion_registry second_registry;
        msconnector_runtime_transaction *other=NULL;
        char other_handle[MSCONNECTOR_RUNTIME_RESPONSE_COMPANION_HANDLE_SIZE];
        msconnector_runtime_response_companion_registry_init(&second_registry);
        if(!msconnector_runtime_transaction_begin_request_stream(runtime,&request,"companion-same-id",&other,&decision,&error))return 25;
        if(!msconnector_runtime_transaction_append_request_body_chunk(other,(const unsigned char *)"def",3U,&error))return 26;
        if(!msconnector_runtime_transaction_finish_request_body(other,&decision,&error))return 27;
        if(!msconnector_runtime_response_companion_handoff_with_handle(&second_registry,other,10000,other_handle,&error))return 28;
        if(!msconnector_runtime_response_companion_claim_handle(&second_registry,other_handle,&second,&error))return 29;
        if(!msconnector_runtime_response_companion_session_cancel(&second,1,&error))return 30;
    }
    if(strcmp(mode,"absent")==0) {
        if(!msconnector_runtime_response_companion_session_cancel(&session,1,&error))return 19;
        msconnector_runtime_destroy(&runtime);return 0;
    }
    msconnector_response response={0};response.status=200;response.http_version="HTTP/1.1";
    response.headers=&header;response.header_count=1U;
    if(!msconnector_runtime_response_companion_session_process_response_headers(&session,&response,&decision,&error))return 20;
    if(!msconnector_runtime_response_companion_session_append_response_body_chunk(&session,(const unsigned char *)"xyz",3U,&error))return 21;
    if(strcmp(mode,"missing_eos")!=0) {
        if(!msconnector_runtime_response_companion_session_finish_response_body(&session,&decision,&error))return 22;
        if(strcmp(mode,"duplicate_eos")==0)(void)msconnector_runtime_response_companion_session_finish_response_body(&session,&decision,&error);
    }
    int released=msconnector_runtime_response_companion_session_release(&session,&error);
    if(strcmp(mode,"missing_eos")==0 ? released!=0 : released!=1)return 23;
    if(msconnector_runtime_response_companion_session_release(&session,&error)!=0)return 24;
    errno=EDOM;
    if(msconnector_lifecycle_runtime_scope_call(transaction)!=0U || errno!=EDOM)return 41;
    msconnector_runtime_destroy(&runtime);return 0;
}
''', encoding="utf-8")
            copied = companion_runtime_source_copy(self.work / "runtime-companion-copy.c")
            sources = sorted((source_path('common/src', root=ROOT)).glob("*.c"))
            sources.extend(path for path in sorted((source_path('common/runtime', root=ROOT)).glob("*.c"))
                           if path.name != "msconnector_runtime.c")
            sources.extend((copied, source_path('connectors/profile_registry.c', root=ROOT), source,
                            source_path('ci/runtime/lifecycle/native-lifecycle-observer.c', root=ROOT)))
            helper = self.compile_sdk_helper("companion-helper")
            self.compile_observed_fixture(sources, helper, binary, "companion-compile.json")
        previous = self.binary
        previous_config = os.environ.get("OBSERVER_RUNTIME_CONFIG")
        try:
            self.binary = binary
            os.environ["OBSERVER_RUNTIME_CONFIG"] = str(config)
            return self.run_fixture(mode)
        finally:
            self.binary = previous
            if previous_config is None:
                os.environ.pop("OBSERVER_RUNTIME_CONFIG", None)
            else:
                os.environ["OBSERVER_RUNTIME_CONFIG"] = previous_config

    def test_actual_companion_typed_joins_eos_and_failed_ownership_controls(self):
        for mode in ("complete", "equalids", "duplicateclaim", "duplicate_eos", "missing_eos", "absent",
                     "premature", "badclaim", "expired"):
            events, stderr = self.companion_fixture(mode)
            self.assertEqual(stderr, "", mode)
            self.assert_pairs(events)
            returns = [event for event in events if event["edge"] == "return"]
            allocations = [event for event in returns if event["function"] == "runtime_begin_request_stream"]
            self.assertTrue(allocations[0]["allocation_join_verified"], mode)
            claims = [event for event in returns if event["function"] == "companion_claimed"]
            successful = [event for event in claims if event["result"] == 1]
            expected = mode not in ("premature", "badclaim", "expired")
            self.assertEqual(len(successful), 2 if mode == "equalids" else int(expected), mode)
            if successful:
                self.assertTrue(successful[0]["allocation_join_verified"], mode)
                self.assertEqual(successful[0]["allocation_scope_call"], allocations[0]["call"], mode)
            if mode == "equalids":
                self.assertNotEqual(successful[0]["allocation_scope_call"], successful[1]["allocation_scope_call"])
                actual_native = [event for event in returns if event["function"] == "native_new_with_id"]
                self.assertEqual(len(actual_native), 2)
                self.assertEqual(actual_native[0]["transaction_id"], actual_native[1]["transaction_id"])
            phase4 = [event for event in returns if event["function"] == "native_process_response_body"]
            self.assertEqual(len(phase4), int(mode in ("complete", "equalids", "duplicateclaim", "duplicate_eos")), mode)
            eos = [event for event in returns if event["runtime_eos_handoff"] == "companion_response_body_finish"]
            self.assertEqual(len(eos), 2 if mode == "duplicate_eos" else int(bool(phase4)), mode)
            self.assertFalse(any(event["function"] == "runtime_finish_response_body" for event in events), mode)
            self.assertEqual(sum(event["function"] == "native_cleanup" for event in returns), 2 if mode == "equalids" else 1, mode)
            host_eos = [event for event in returns if event["function"] == "authorization_request_eos"]
            self.assertEqual([event["result"] for event in host_eos], [] if mode == "premature" else [0,0,0,1,0], mode)
            for event in host_eos:
                enter = next(row for row in events if row["call"] == event["call"] and row["edge"] == "enter")
                self.assertEqual(event["sequence"], enter["sequence"] + 1, mode)
                self.assertIsNone(event["runtime_eos_handoff"], mode)
                self.assertIsNone(event["host_eos"], mode)
            if host_eos:
                self.assertEqual(host_eos[3]["host_framing"], {"content_length":3,"buffered_body_size":3,"remaining":0})
            self.assertFalse(events[-1]["invalid"], mode)
            self.assertEqual(events[-1]["pending_calls"], 0, mode)
            self.assertEqual(events[-1]["live_mappings"], 0, mode)

    def test_host_scopes_are_typed_and_require_actual_nested_exact_allocations(self):
        for mode in ("host", "hostnested", "hostfailure", "hostempty", "hostambiguous", "hostwrongcommon"):
            events, _ = self.run_fixture(mode)
            self.assert_pairs(events)
            allocations = [e for e in events if e["function"] == "host_allocation" and e["edge"] == "return"]
            expected = mode in ("host", "hostnested")
            self.assertEqual(sum(e["allocation_join_verified"] for e in allocations), int(expected))
            if expected:
                joined = next(e for e in allocations if e["allocation_join_verified"])
                self.assertEqual(joined["allocation_scope_call"], joined["call"])
                self.assertEqual(joined["allocation_scope_kind"], "host")
            self.assertEqual(events[-1]["pending_calls"], 0)
            self.assertEqual(events[-1]["live_mappings"], 0)

    def test_invalid_host_end_and_fork_do_not_inherit_a_valid_scope(self):
        for mode in ("hostbadend", "hostfork", "hostoutside", "hostoverflow"):
            events, stderr = self.run_fixture(mode)
            self.assertTrue(events[-1]["invalid"])
            self.assertIn("evidence invalid", stderr)
            self.assertEqual(events[-1]["pending_calls"], 0)
            self.assertEqual(events[-1]["live_mappings"], 0)
            if mode == "hostfork":
                child = [e for e in events if e["edge"] == "fork"][0]
                self.assertIsNone(child["allocation_scope_call"])

    def test_selected_sdk_host_join_and_retirement_after_real_cleanup(self):
        source = self.work / "host-sdk.c"
        source.write_text(r'''
#include "native-lifecycle-observer.h"
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
int main(void) {
    static int host;
    ModSecurity *engine=msc_init();RulesSet *rules=msc_create_rules_set();if(!engine || !rules)return 2;
    uint64_t call=msconnector_lifecycle_host_begin();if(!call)return 3;
    msconnector_transaction_contract common;
    if(msconnector_transaction_contract_init(&common,NULL,"same-id","test","test",0,1)!=0)return 4;
    Transaction *native=msc_new_transaction_with_id(engine,rules,"same-id",NULL);if(!native)return 5;
    if(!msconnector_lifecycle_host_end(call,&host,&common,native,1))return 6;
    if(msconnector_lifecycle_host_scope_call(&host)!=call || msconnector_lifecycle_host_retire(&host)!=0)return 7;
    if(msconnector_transaction_contract_cleanup(&common,2)!=MSCONNECTOR_TRANSACTION_TRANSITION_PREMATURE_CLEANUP)return 8;
    if(msconnector_lifecycle_host_retire(&host)!=0)return 9;
    msc_transaction_cleanup(native);
    if(!msconnector_lifecycle_host_retire(&host) || msconnector_lifecycle_host_scope_call(&host)!=0)return 10;
    msc_rules_cleanup(rules);msc_cleanup(engine);return 0;
}
''', encoding="utf-8")
        binary = self.work / "host-sdk"
        self.compile_genuine_control(source, binary, self.compile_sdk_helper("host-sdk-helper"))
        previous = self.binary
        try:
            self.binary = binary
            events, _ = self.run_fixture()
        finally:
            self.binary = previous
        self.assert_pairs(events)
        joined = next(e for e in events if e["function"] == "host_allocation" and e["edge"] == "return")
        self.assertTrue(joined["allocation_join_verified"])
        self.assertEqual(joined["allocation_scope_kind"], "host")
        retire = [e for e in events if e["function"] == "host_association_retire" and e["edge"] == "return"]
        self.assertEqual([e["result"] for e in retire], [0, 0, 1])
        native = next(e for e in events if e["function"] == "native_new_with_id" and e["edge"] == "return")
        self.assertEqual(native["transaction_id_origin"], "sdk_public_m_id")
        self.assertEqual(native["allocation_scope_call"], joined["call"])
        self.assertEqual(events[-1]["live_mappings"], 0)

    def test_fork_receipts(self):
        events, _ = self.run_fixture("fork")
        self.assert_pairs(events)
        self.assertEqual(len({e["pid"] for e in events if e["edge"] == "final"}), 2)

    def test_write_failure_is_invalid_without_changing_real_results(self):
        events, stderr = self.run_fixture("closed")
        self.assertEqual(len(events), 1)
        self.assertIn("evidence invalid", stderr)

    def test_partial_write_invalidates_evidence_without_changing_real_results(self):
        events, stderr = self.run_fixture("partial")
        self.assertEqual(len(events), 1)
        self.assertIn("evidence invalid", stderr)

    def test_missing_descriptor_produces_no_qualified_evidence(self):
        events, _ = self.run_fixture(configured=False)
        self.assertEqual(events, [])

    def test_public_descriptor_rejected(self):
        events, stderr = self.run_fixture(permissions=0o644)
        self.assertEqual(events, [])
        self.assertIn("admission rejected", stderr)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
