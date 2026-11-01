#!/usr/bin/env python3
"""Add explicitly selected diagnostic faults to a disposable current Runtime.

These are caller/stdio boundary injections, never native SDK decisions. The
unchanged physical source, real SDK observations and selected overlay remain
separately bound by the preparation receipt.
"""
import hashlib
import json
from pathlib import Path


def observer_paths(source, sink_header, name):
    header = sink_header.with_name(name)
    if header.resolve() != header or header.stat().st_nlink != 1:
        raise ValueError("Observer must be a physical single-link input")
    output = source / name
    if output.exists() or output.is_symlink():
        raise ValueError("Observer output must be fresh")
    return header, output


def validated_fault_inputs(source, sink_header):
    source, sink_header = Path(source), Path(sink_header)
    if source.resolve() != source or sink_header.resolve() != sink_header:
        raise ValueError("Fault sources must have physical paths")
    marker_path = source / ".i12-disposable-source-copy.json"
    if marker_path.resolve() != marker_path or marker_path.stat().st_nlink != 1:
        raise ValueError("Fault source marker must be physical and single-link")
    marker = json.loads(marker_path.read_text())
    if marker.get("disposable") is not True or marker.get("path") != str(source):
        raise ValueError("Fault source must be the exact marked disposable copy")
    runtime = source / "common/runtime/msconnector_runtime.c"
    if runtime.resolve() != runtime or runtime.stat().st_nlink != 1 or sink_header.stat().st_nlink != 1:
        raise ValueError("Fault inputs must be physical single-link files")
    destination = source / "patched_faults.h"
    if destination.exists() or destination.is_symlink():
        raise ValueError("Fault helper output must be fresh")
    budget_header, budget_output = observer_paths(source, sink_header, "diagnostic_budget_observer.h")
    finish_header, finish_output = observer_paths(source, sink_header, "diagnostic_finish_observer.h")
    return runtime, destination, budget_header, budget_output, finish_header, finish_output


def extend(source, sink_header):
    source, sink_header = Path(source), Path(sink_header)
    runtime, destination, budget_header, budget_output, finish_header, finish_output = validated_fault_inputs(source, sink_header)
    original = runtime.read_bytes()
    text = original.decode()
    finish_start = text.index("int msconnector_runtime_transaction_finish(\n")
    finish_end = text.index("\n}\n", finish_start) + 3
    finish_original = text[finish_start:finish_end]
    finish_observed = finish_original.replace("int msconnector_runtime_transaction_finish(",
        "static int i12_diagnostic_finish_implementation(", 1) + '''
int msconnector_runtime_transaction_finish(msconnector_runtime_transaction *transaction,
        msconnector_error *error) {
    const char *id = transaction == NULL ? NULL : transaction->metadata.transaction_id;
    i12_diagnostic_finish("enter", id, -999, 0,
        transaction == NULL ? -1 : transaction->completion.finish_attempted);
    const int actual = i12_diagnostic_finish_implementation(transaction, error);
    i12_diagnostic_finish("return", id, actual, error == NULL ? -1 : (int)error->code,
        transaction == NULL ? -1 : transaction->completion.finish_attempted);
    return actual;
}
'''
    begin = ("    return transaction_begin_internal(runtime, request, host_request_id, out,\n"
             "        decision, error, (msconnector_runtime_begin_options){0, NULL});")
    injected = ("    msconnector_request injected_request;\n"
        "    if (request != NULL && (i12_pointer_null(\"headers_null\", request->headers, request->header_count) ||\n"
        "            i12_pointer_null(\"method_null\", request->method, 1U))) {\n"
        "        const char *selected = getenv(\"MSCONNECTOR_LIGHTTPD_POINTER_FAULT\");\n"
        "        injected_request = *request;\n"
        "        if (strcmp(selected, \"headers_null\") == 0) injected_request.headers = NULL;\n"
        "        else injected_request.method = NULL;\n"
        "        request = &injected_request;\n"
        "    }\n" + begin)
    replacements = [(begin, injected), (finish_original, finish_observed),
        ("msconnector_open_private_event_file(path, &fd)", "i12_sink_open(path, &fd)"),
        ("fputs(json, runtime->event_file)", "i12_sink_puts(json, runtime->event_file)"),
        ("fflush(runtime->event_file)", "i12_sink_flush(runtime->event_file)"),
        ("fclose(runtime->event_file)", "i12_sink_close(runtime->event_file)"),
        ("msconnector_event_write_jsonl_line(event, json, json_size, &truncated)",
         "i12_diagnostic_event_serialize(event, json, json_size, &truncated)")]
    for before, after in replacements:
        if text.count(before) != 1:
            raise ValueError("Diagnostic fault anchor missing or ambiguous: " + before)
        text = text.replace(before, after, 1)
    prefix = ('#include "patched_faults.h"\n#include "diagnostic_budget_observer.h"\n'
              '#include "diagnostic_finish_observer.h"\n')
    # _GNU_SOURCE must precede all header inclusions.
    anchor = '#include "diagnostic_faults.h"\n'
    text = text.replace(anchor, anchor + prefix, 1)
    stripped = text.replace(prefix, "", 1)
    for before, after in reversed(replacements):
        stripped = stripped.replace(after, before, 1)
    if stripped.encode() != original:
        raise ValueError("Fault overlay does not strip to its exact input")
    runtime.write_text(text)
    with destination.open("xb") as output:
        output.write(sink_header.read_bytes())
    with budget_output.open("xb") as output:
        output.write(budget_header.read_bytes())
    with finish_output.open("xb") as output:
        output.write(finish_header.read_bytes())
    return {"input_runtime_sha256": hashlib.sha256(original).hexdigest(),
        "fault_runtime_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "sink_header_sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
        "budget_observer_sha256": hashlib.sha256(budget_output.read_bytes()).hexdigest(),
        "finish_observer_sha256": hashlib.sha256(finish_output.read_bytes()).hexdigest(),
        "stripped_input_identity": True, "native_sdk_return_mutated": False,
        "sink_schema_producer_name": "reused lighttpd-patched-injected-sink-boundary-v1; route remains diagnostic"}
