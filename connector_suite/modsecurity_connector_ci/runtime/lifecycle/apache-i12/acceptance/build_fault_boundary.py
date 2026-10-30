#!/usr/bin/env python3
"""Build test-only Apache fault callbacks; never modify productive source."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
APACHE_MODULE_SOURCE = "connectors/apache/src/mod_security3.c"
HEADER = '''/* Test-only declarations for external instrumented source copies. */
#include <httpd.h>
#include <modsecurity/transaction.h>
#include <stddef.h>
int i12_apache_fault_after_bucket_read(request_rec *, const char **, apr_size_t, int);
int i12_apache_fault_request_metadata(request_rec *);
int i12_apache_fault_process_request_headers(request_rec *, Transaction *, void *, int);
int i12_apache_fault_append_response_body(request_rec *, Transaction *, const unsigned char *, size_t, void *, int);
int i12_apache_fault_add_request_header(request_rec *, Transaction *, const unsigned char *, const unsigned char *);
int i12_apache_fault_process_logging(request_rec *, Transaction *);
'''

def query(*args):
    return subprocess.run(["rtk", "proxy", *args], check=True, capture_output=True,
                          text=True, timeout=10).stdout.strip()

def build(output: Path, include: Path) -> dict:
    if not (include / "modsecurity/transaction.h").is_file():
        raise ValueError("explicit selected SDK headers required")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = HERE / "fault_boundary.c"
    target = output / "apache-fault-boundary.o"
    command = ["rtk", "proxy", *shlex.split(os.environ.get("CC", "cc")), "-std=c17",
               "-Wall", "-Wextra", "-Werror", "-fPIC", "-fno-lto", "-I", str(include.resolve()),
               "-I", query("apxs", "-q", "INCLUDEDIR"), "-I", str(source_path('common/include', root=ROOT)),
               *shlex.split(query("apr-1-config", "--includes", "--cppflags", "--cflags")),
               "-c", str(source), "-o", str(target)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    receipt = {"command": command, "exit": result.returncode, "stdout": result.stdout,
               "stderr": result.stderr, "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
               "object_sha256": hashlib.sha256(target.read_bytes()).hexdigest() if not result.returncode else None,
               "test_only": True, "runtime_qualified": False,
               "helper_revision": 2,
               "out_of_scope_mechanisms_not_case_dispositions": {
                   "genuine_native_transaction_allocation_failure": "SDK throwing new Transaction has no C boundary catch; no safe NULL cleanup claim",
                   "genuine_native_header_allocation_failure": "SDK std::string/map allocations throw; no bounded safe returning-failure allocator seam",
                   "genuine_apr_mapper_header_allocation_failure": "apr_pcalloc macro is memset(apr_palloc(...),0,size); a NULL allocator result can dereference NULL"},
               "integration": [
                   "Link this object into external instrumented module; retain existing GNU --wrap observer symbols and -Bsymbolic-functions",
                   "Force-include generated apache-fault-boundary.h ONLY in external copies of mod_security3.c and msc_filters.c",
                   "msc_filters.c apache_input_filter_process_bucket: after if (ret != APR_SUCCESS) return ret; insert (void)i12_apache_fault_after_bucket_read(r, &data, len, ret); BEFORE the existing NULL-data guard",
                   "mod_security3.c msc_apache_contract_record_request_metadata: after productive input/config preconditions and before final Common record call, insert if (!i12_apache_fault_request_metadata(r)) return 0;",
                   "mod_security3.c replace msc_process_request_headers(msr->t) with i12_apache_fault_process_request_headers(r, msr->t, &msr->contract, msr->response.committed) only at productive P1 call",
                   "msc_filters.c replace msc_append_response_body(msr->t, (const unsigned char *)data, len) with i12_apache_fault_append_response_body(msr->r, msr->t, (const unsigned char *)data, len, &msr->contract, msr->response.committed) only in apache_phase4_append_bucket",
                   "mod_security3.c replace msc_add_request_header(msr->t, key_bytes, val_bytes) with i12_apache_fault_add_request_header(r, msr->t, key_bytes, val_bytes) only in actual request header ingestion",
                   "mod_security3.c replace msc_process_logging(msr->t) with i12_apache_fault_process_logging(r, msr->t) only at productive finish call",
                   "Never replace names in observer TUs; helper calls native public APIs and records each actual original SDK return before any controlled return",
                   "Set I12_APACHE_FAULT_ROOT/ID/MODE before startup; modes null-body/null-headers/invalid-native-return/finish-failure/technical-precommit/technical-postcommit/timeout-decision-precommit/timeout-decision-postcommit/mapping-failure; root must be canonical private0700; explicit fault-boundary.enable marker private0600 with I12_APACHE_FAULT_BOUNDARY_V1 newline; principal X-I12-ID must match exactly once; both actual connection addresses IPv4 loopback",
                   "Header callback invokes actual Common validator on a controlled bounded view, not unused Apache mapper; report this extra validation seam explicitly",
                   "Timeout modes call REAL Common timeout on actual live contract through opaque void pointer; record actual transition/error/decision/phase/timestamp, never claim elapsed-budget enforcement or fabricate native timeout result",
                   "Postcommit modes require second actual principal response append AND actual source msr->response.committed flag; independent host/client prefix evidence remains mandatory",
                   "Retain the existing native GNU-wrapper list exactly; msc_append_response_body remains independently wrapped, while the helper itself records the real public msc_add_request_header return without claiming a separate wrapper",
               ]}
    receipt["external_source_anchors"] = [
        {"file": APACHE_MODULE_SOURCE, "occurrences_required": 1,
         "original": "msc_process_request_headers(msr->t)",
         "replacement": "i12_apache_fault_process_request_headers(r, msr->t, &msr->contract, msr->response.committed)"},
        {"file": "connectors/apache/src/msc_filters.c", "occurrences_required": 1,
         "original": "msc_append_response_body(msr->t,\n                (const unsigned char *)data, len)",
         "replacement": "i12_apache_fault_append_response_body(msr->r, msr->t, (const unsigned char *)data, len, &msr->contract, msr->response.committed)"},
        {"file": APACHE_MODULE_SOURCE, "occurrences_required": 1,
         "original": "msc_add_request_header(msr->t, key_bytes, val_bytes)",
         "replacement": "i12_apache_fault_add_request_header(r, msr->t, key_bytes, val_bytes)"},
        {"file": APACHE_MODULE_SOURCE, "occurrences_required": 1,
         "original": "msc_process_logging(msr->t)",
         "replacement": "i12_apache_fault_process_logging(r, msr->t)"}]
    for anchor in receipt["external_source_anchors"]:
        content = (ROOT / anchor["file"]).read_bytes()
        anchor["source_sha256"] = hashlib.sha256(content).hexdigest()
        anchor["actual_occurrences"] = content.decode().count(anchor["original"])
        if anchor["actual_occurrences"] != anchor["occurrences_required"]:
            raise ValueError("External instrumentation source anchor is not unique: " + anchor["file"])
    (output / "fault-boundary-build.json").write_text(json.dumps(receipt, indent=2) + "\n")
    (output / "apache-fault-boundary.h").write_text(HEADER)
    if result.returncode:
        raise RuntimeError(result.stderr)
    return receipt

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sdk-include", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.output, args.sdk_include), sort_keys=True))

if __name__ == "__main__":
    main()
