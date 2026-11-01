"""Real APR bucket controls and unchanged real observers in a GNU-wrapped DSO."""
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
import sys
import tempfile
import unittest

ROOT = connector_root()

from modsecurity_connector_ci.runtime.lifecycle.i12.capture_sources import Registry

HERE = source_path('ci/runtime/lifecycle/apache-i12/acceptance', root=ROOT)
BUILD = load_source(HERE / 'build_host_bucket.py')

CALLER = r'''
#include "mod_security3.h"
#include <apr_mmap.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
extern void apache_lifecycle_observe(const char *,msc_t *,request_rec *,const apr_bucket *);
extern unsigned i12_fixture_original_observer_entries(void);
static void observe(const char *label,msc_t *msr,request_rec *r,const apr_bucket *bucket) {
    errno=E2BIG;apache_lifecycle_observe(label,msr,r,bucket);
    if(errno!=E2BIG) {fprintf(stdout,"errno_changed\n");}
}
int bucket_probe(const char *path,int flood) {
    if(apr_initialize()!=APR_SUCCESS)return 2;
    apr_pool_t *pool=NULL;if(apr_pool_create(&pool,NULL)!=APR_SUCCESS)return 3;
    apr_bucket_alloc_t *allocator=apr_bucket_alloc_create(pool);
    apr_file_t *file=NULL;
    if(apr_file_open(&file,path,APR_READ|APR_WRITE|APR_CREATE|APR_TRUNCATE,
        APR_FPROT_UREAD|APR_FPROT_UWRITE,pool)!=APR_SUCCESS)return 4;
    const char bytes[]="SECRET-BUCKET-PAYLOAD";
    if(apr_file_write_full(file,bytes,sizeof(bytes)-1,NULL)!=APR_SUCCESS)return 5;
    msc_t msr={0};request_rec r={0};r.uri="/_actual_bucket";r.method="GET";r.pool=pool;
    msr.r=&r;msr.owner_request=&r;
    apr_bucket *bucket=apr_bucket_file_create(file,0,sizeof(bytes)-1,pool,allocator);
    if(!bucket || !APR_BUCKET_IS_FILE(bucket))return 6;
    if(apr_bucket_file_enable_mmap(bucket,0)!=APR_SUCCESS)return 7;
    observe("before_file_read",&msr,&r,bucket);
    const char *data=NULL;apr_size_t length=0;int result=apr_bucket_read(bucket,&data,&length,APR_BLOCK_READ);
    if(result!=APR_SUCCESS || length!=sizeof(bytes)-1 || !data || memcmp(data,bytes,length))return 8;
    int heap_after=APR_BUCKET_IS_HEAP(bucket);
    observe("after_file_read",&msr,&r,bucket);
    apr_bucket_destroy(bucket);
    apr_mmap_t *mapping=NULL;
    if(apr_mmap_create(&mapping,file,0,sizeof(bytes)-1,APR_MMAP_READ,pool)!=APR_SUCCESS)return 9;
    bucket=apr_bucket_mmap_create(mapping,0,sizeof(bytes)-1,allocator);
    if(!bucket || !APR_BUCKET_IS_MMAP(bucket))return 10;
    observe("actual_mmap",&msr,&r,bucket);apr_bucket_destroy(bucket);
    bucket=apr_bucket_eos_create(allocator);
    if(!bucket || !APR_BUCKET_IS_EOS(bucket))return 11;
    observe("actual_eos",&msr,&r,bucket);apr_bucket_destroy(bucket);
    bucket=apr_bucket_flush_create(allocator);
    observe("actual_flush",&msr,&r,bucket);apr_bucket_destroy(bucket);
    apr_file_t *read_end=NULL,*write_end=NULL;
    if(apr_file_pipe_create(&read_end,&write_end,pool)!=APR_SUCCESS)return 12;
    bucket=apr_bucket_pipe_create(read_end,allocator);
    if(!bucket || bucket->length!=(apr_size_t)-1)return 13;
    observe("actual_unknown_length_pipe",&msr,&r,bucket);apr_bucket_destroy(bucket);
    observe("actual_null_bucket",&msr,&r,NULL);
    if(flood) {
        bucket=apr_bucket_heap_create(bytes,sizeof(bytes)-1,NULL,allocator);
        for(int i=0;i<4100;++i)observe("actual_heap",&msr,&r,bucket);
        apr_bucket_destroy(bucket);
    }
    printf("{\"actual_file_before_read\":true,\"actual_read_result\":%d,\"actual_read_bytes\":%zu,"
        "\"actual_heap_after_read\":%s,\"observer_calls\":%d,\"actual_original_observer_entries\":%u}\n",result,(size_t)length,
        heap_after?"true":"false",flood?4107:7,i12_fixture_original_observer_entries());
    apr_bucket_alloc_destroy(allocator);apr_pool_destroy(pool);apr_terminate();return 0;
}
'''

MAIN = r'''
extern int bucket_probe(const char *,int);
int main(int argc,char **argv) {return argc<2?1:bucket_probe(argv[1],argc>2);}
'''

# Count actual function entries in the unchanged host observer, without
# inventing an allocation association or bypassing its zero-scope admission.
COUNTER = r'''
#include "mod_security3.h"
#ifdef WRAPPED_FIXTURE
extern void __real_apache_lifecycle_observe(const char *,msc_t *,request_rec *,const apr_bucket *);
#define ACTUAL_OBSERVER __real_apache_lifecycle_observe
#else
extern void apache_lifecycle_observe(const char *,msc_t *,request_rec *,const apr_bucket *);
#define ACTUAL_OBSERVER apache_lifecycle_observe
#endif
static unsigned entries;
void __cyg_profile_func_enter(void *function,void *caller) {
    (void)caller;if(function==(void *)ACTUAL_OBSERVER)++entries;
}
void __cyg_profile_func_exit(void *function,void *caller) {(void)function;(void)caller;}
unsigned i12_fixture_original_observer_entries(void) {return entries;}
'''

class ApacheHostBucketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="apache-host-bucket-",
            dir=os.environ.get("CODEX_TEST_TMP_ROOT", "/var/tmp/codex/ModSecurity-conector"))
        cls.addClassCleanup(temporary.cleanup)
        cls.work = Path(temporary.name)
        registry = Registry()
        cls.host_c = cls.work / "apache-host-observer.c"
        cls.host_h = cls.work / "apache-host-observer.h"
        cls.host_c.write_bytes(registry.content("af42bc5500b0c75b2620678648abaf16d7dc674e8bbd444745b0b8f21320af63"))
        cls.host_h.write_bytes(registry.content("c0bde3c4b54fd802084f54665e3fa17f162bcfb29378136c669f5d8f3f46bfc9"))
        cls.evidence = os.environ.get("I12_APACHE_HOST_BUCKET_EVIDENCE_DIR")
        include = Path(os.environ.get("MODSECURITY_INCLUDE_DIR", "/usr/include"))
        receipt = BUILD.build(cls.work / "build", include)
        caller = cls.work / "caller.c"
        caller.write_text(CALLER)
        main = cls.work / "main.c"
        main.write_text(MAIN)
        counter = cls.work / "counter.c"
        counter.write_text(COUNTER)
        common = ["rtk", "proxy", "cc", "-std=c17", "-Wall", "-Wextra", "-Werror", "-fPIC",
                  "-ffunction-sections", "-fdata-sections", "-I", str(include),
                  "-I", str(source_path('connectors/apache/src', root=ROOT)), "-I", str(source_path('common/include', root=ROOT)),
                  "-I", str(cls.work), "-I", BUILD.query("apxs", "-q", "INCLUDEDIR"),
                  *shlex.split(BUILD.query("apr-1-config", "--includes", "--cppflags", "--cflags"))]
        receipts = []
        def run(command):
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            receipts.append({"command": command, "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
            if cls.evidence:
                destination = Path(cls.evidence)
                destination.mkdir(parents=True, exist_ok=True)
                (destination / "build-commands.json").write_text(json.dumps(receipts, indent=2))
            if result.returncode:
                raise RuntimeError(result.stderr)
        native = cls.work / "native-lifecycle-observer.c"
        shutil.copy2(source_path('ci/runtime/lifecycle/native-lifecycle-observer.c', root=ROOT), native)
        shutil.copy2(source_path('ci/runtime/lifecycle/native-lifecycle-observer.h', root=ROOT), cls.work / "native-lifecycle-observer.h")
        for source, target in ((cls.host_c, "host.o"), (native, "native.o")):
            # Hide unused observer entry points in this standalone control so
            # section GC can retain the REAL scope accessor without faking a
            # successful host allocation or linking unrelated runtime owners.
            # The native observer defines _GNU_SOURCE itself before headers;
            # APR's command-line duplicate otherwise triggers -Werror.
            flags = [flag for flag in common if flag not in ("-D_GNU_SOURCE", "-D_GNU_SOURCE=1")] if source == native else common
            instrumentation = ["-finstrument-functions"] if source == cls.host_c else []
            run([*flags, *instrumentation, "-fvisibility=hidden", "-c", str(source), "-o", str(cls.work / target)])
        run([*common, "-c", str(caller), "-o", str(cls.work / "caller.o")])
        links = [*shlex.split(BUILD.query("apr-1-config", "--link-ld", "--libs")), "-laprutil-1", "-pthread"]
        cls.binaries = {}
        for wrapped in (False, True):
            name = "wrapped" if wrapped else "control"
            counter_object = cls.work / (name + "-counter.o")
            run([*common, *(["-DWRAPPED_FIXTURE=1"] if wrapped else []), "-c", str(counter), "-o", str(counter_object)])
            library = cls.work / ("lib" + name + ".so")
            command = ["rtk", "proxy", "cc", "-shared", "-Wl,-Bsymbolic-functions", "-Wl,--gc-sections",
                       "-Wl,--no-undefined", str(cls.work / "caller.o"), str(cls.work / "host.o"),
                       str(cls.work / "native.o"), str(counter_object)]
            if wrapped:
                command += [str(cls.work / "build/apache-host-bucket.o"), "-Wl,--wrap=apache_lifecycle_observe"]
            run([*command, *links, "-o", str(library)])
            binary = cls.work / name
            run(["rtk", "proxy", "cc", "-std=c17", "-Wall", "-Wextra", "-Werror", str(main), str(library),
                 "-Wl,-rpath," + str(cls.work), "-o", str(binary)])
            cls.binaries[wrapped] = binary
        if cls.evidence:
            destination = Path(cls.evidence)
            destination.mkdir(parents=True, exist_ok=True)
            sources = [cls.host_c, cls.host_h, native, caller, main, counter]
            (destination / "builds.json").write_text(json.dumps({"commands": receipts, "helper_build": receipt,
                "source_sha256": {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources},
                "scope_accessor": "actual native-lifecycle-observer.c; no host association created in standalone control"}, indent=2))
            for item in cls.work.iterdir():
                if item.is_file():
                    shutil.copy2(item, destination / item.name)
            for item in (cls.work / "build").iterdir():
                shutil.copy2(item, destination / item.name)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="case-", dir=self.work)
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.directory.chmod(0o700)
        self.marker = self.directory / "host-bucket.enable"
        self.marker.write_bytes(b"I12_APACHE_HOST_BUCKET_V1\n")
        self.marker.chmod(0o600)

    def run_case(self, *, wrapped=True, admitted=True, flood=False):
        environment = os.environ.copy()
        environment.update(I12_APACHE_BUCKET_ROOT=str(self.directory), I12_APACHE_BUCKET_RUN="genuine-apr-control",
            I12_APACHE_BUCKET_CASE=self._testMethodName, MSCONNECTOR_APACHE_HOST_OBSERVER=str(self.directory / "original.jsonl"))
        environment.pop("MSCONNECTOR_LIFECYCLE_FD", None)
        if not admitted:
            environment.pop("I12_APACHE_BUCKET_ROOT")
        command = ["rtk", "proxy", str(self.binaries[wrapped]), str(self.directory / "body.bin")]
        if flood:
            command.append("flood")
        result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=20)
        snapshots = []
        for line in result.stderr.splitlines():
            if line.startswith('{"schema":"apache-host-bucket-v1"'):
                snapshots.append(json.loads(line))
                self.assertLess(len(line.encode()) + 1, 2048)
        if self.evidence:
            destination = Path(self.evidence) / (self._testMethodName + "-" + str(wrapped) + "-" + str(admitted))
            destination.mkdir(exist_ok=True)
            (destination / "process.json").write_text(json.dumps({"command": command, "exit": result.returncode,
                "stdout": result.stdout, "stderr": result.stderr}, indent=2))
            shutil.copy2(self.directory / "original.jsonl", destination / "original.jsonl")
        self.assertEqual(result.returncode, 0, result.stderr[-2048:])
        self.assertNotIn("errno_changed", result.stdout)
        values = json.loads(result.stdout)
        self.assertEqual(values["actual_original_observer_entries"], values["observer_calls"])
        return values, snapshots

    def test_real_file_bucket_changes_type_only_after_actual_apr_read(self):
        result, rows = self.run_case()
        self.assertTrue(result["actual_file_before_read"])
        self.assertTrue(result["actual_heap_after_read"])
        before, after = rows[:2]
        self.assertEqual((before["bucket_type_name"], before["is_file"], before["is_heap"]), ("FILE", True, False))
        self.assertEqual((after["bucket_type_name"], after["is_file"], after["is_heap"]), ("HEAP", False, True))
        self.assertEqual(before["bucket_key"], after["bucket_key"])
        self.assertEqual(before["bucket_length"], result["actual_read_bytes"])
        self.assertEqual(after["bucket_length"], result["actual_read_bytes"])
        self.assertFalse(before["observer_reads_bucket"])
        self.assertFalse(before["payload_captured"])
        self.assertNotIn("SECRET-BUCKET-PAYLOAD", json.dumps(rows))

    def test_genuine_mmap_eos_and_metadata_types(self):
        _, rows = self.run_case()
        by_kind = {row["observer_kind"]: row for row in rows}
        self.assertTrue(by_kind["actual_mmap"]["is_mmap"])
        eos = by_kind["actual_eos"]
        self.assertEqual(eos["bucket_type_name"], "EOS")
        self.assertTrue(eos["is_eos"])
        self.assertTrue(eos["is_metadata"])
        self.assertFalse(eos["is_file"])
        self.assertTrue(by_kind["actual_flush"]["is_metadata"])
        self.assertFalse(by_kind["actual_flush"]["is_eos"])

    def test_actual_unknown_length_sentinel_and_null_bucket_are_not_invented_values(self):
        _, rows = self.run_case()
        pipe, absent = rows[-2:]
        self.assertEqual(pipe["bucket_type_name"], "PIPE")
        self.assertIsNone(pipe["bucket_length"])
        self.assertFalse(absent["actual_bucket_present"])
        self.assertIsNone(absent["bucket_type_name"])
        self.assertIsNone(absent["is_file"])

    def test_real_observer_entries_and_errno_match_unwrapped_control(self):
        result, rows = self.run_case()
        original = [json.loads(line) for line in (self.directory / "original.jsonl").read_text().splitlines()]
        self.assertEqual(len(rows), result["actual_original_observer_entries"])
        self.assertEqual(original, [])  # Genuine accessor returns0: no fabricated host join.
        self.assertTrue(all(row["errno_at_observer_return"] == 7 for row in rows))
        self.assertTrue(all(row["scope_lookup_result"] == 0 and row["allocation_scope_call"] is None for row in rows))
        self.assertTrue(all(row["pid"] > 0 and row["tid"] > 0 for row in rows))
        self.assertTrue(all(row["uid"] == os.geteuid() and row["run_id"] == "genuine-apr-control" for row in rows))
        (self.directory / "original.jsonl").unlink()
        control, extra = self.run_case(wrapped=False)
        self.assertEqual(result, control)
        self.assertEqual(extra, [])
        baseline = [json.loads(line) for line in (self.directory / "original.jsonl").read_text().splitlines()]
        self.assertEqual(original, baseline)

    def test_missing_opt_in_keeps_original_observer_and_no_extension_records(self):
        result, rows = self.run_case(admitted=False)
        self.assertEqual(rows, [])
        self.assertEqual(result["observer_calls"], 7)
        self.assertEqual(result["actual_original_observer_entries"], 7)

    def test_public_directory_or_invalid_marker_refuses_extension(self):
        self.marker.write_text("wrong\n")
        self.assertEqual(self.run_case()[1], [])
        self.marker.write_bytes(b"I12_APACHE_HOST_BUCKET_V1\n")
        self.directory.chmod(0o755)
        self.assertEqual(self.run_case()[1], [])

    def test_public_symlink_and_hardlink_marker_refuse_extension(self):
        self.marker.chmod(0o644)
        self.assertEqual(self.run_case()[1], [])
        self.marker.unlink()
        foreign = self.work / "foreign-marker"
        foreign.write_bytes(b"I12_APACHE_HOST_BUCKET_V1\n")
        foreign.chmod(0o600)
        self.marker.symlink_to(foreign)
        self.assertEqual(self.run_case()[1], [])
        self.marker.unlink()
        os.link(foreign, self.marker)
        self.assertEqual(self.run_case()[1], [])

    def test_record_budget_is_bounded_and_explicit_without_stopping_real_observer(self):
        result, rows = self.run_case(flood=True)
        self.assertEqual(result["observer_calls"], 4107)
        snapshots = [row for row in rows if row["kind"] == "bucket_snapshot"]
        overflow = [row for row in rows if row["kind"] == "record_limit_reached"]
        self.assertEqual(len(snapshots), 4096)
        self.assertEqual(len(overflow), 1)
        self.assertTrue(overflow[0]["invalid"])

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
