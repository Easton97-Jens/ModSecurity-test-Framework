"""Physical native HTX Common events; controlled host, real Common serializer."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from modsecurity_connector_tests.c_source_contract import function_definition

ROOT = connector_root()
FILTER = source_path('connectors/haproxy/htx-overlay/haproxy_modsecurity_htx_filter.c', root=ROOT)


class NativePhysicalEvents(unittest.TestCase):
    def compile_probe(self, source, sanitizers=False):
        structs = source[source.index("struct haproxy_modsecurity_htx_filter_config {"):
                         source.index("typedef int (*haproxy_modsecurity_htx_append_body_chunk)")]
        names = ["haproxy_modsecurity_htx_report_decision"]
        for name in (
            "haproxy_modsecurity_htx_observed_error_phase",
            "haproxy_modsecurity_htx_event_reason",
            "haproxy_modsecurity_htx_event_eos",
            "haproxy_modsecurity_htx_prepare_event",
            "haproxy_modsecurity_htx_event_sink_failed",
            "haproxy_modsecurity_htx_write_event",
        ):
            if name + "(" in source:
                names.insert(0, name)
        names.sort(key=lambda name: source.index(name + "("))
        bodies = []
        for name in names:
            body = function_definition(source, name)
            start = source.index(body)
            previous = source[source.rfind("\n", 0, start - 1) + 1:start].strip()
            bodies.append(previous + "\n" + body if not body.startswith("static ") else body)
        wired = "FILE *events_file;" in structs
        setup = ('cfg.events_file = sink; cfg.events_path = "configured.jsonl"; '
                 'assert(pthread_mutex_init(&cfg.events_lock, NULL) == 0); '
                 'cfg.events_lock_initialized = 1; ctx.config = &cfg;') if wired else '(void)cfg;'
        program = r'''
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "haproxy_modsecurity_binding.h"
#include "msconnector/event_jsonl.h"
#include "msconnector/event_protocol.h"
#include "msconnector/decision.h"
#include "msconnector/decision_action.h"
#include "response_companion_client.h"
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define HAPROXY_MODSECURITY_HTX_RESPONSE_HANDLE_LENGTH 64U
static void ha_warning(const char *format, ...) { (void)format; }
/* Product technical rendering is covered by existing binding tests. */
int haproxy_modsecurity_error_event_write_checked(const haproxy_modsecurity_decision *d,
 const char *id, char *line, size_t size, msconnector_error *e) {
 (void)d; (void)id; (void)line; (void)size; (void)e; return 0;
}
/* STRUCTS */
/* FUNCTIONS */
static int sink_fault_writes;
static ssize_t native_sink_fault(void *opaque, const char *data, size_t size) {
 (void)opaque; (void)data; (void)size; sink_fault_writes++; errno = EIO; return -1;
}
struct writer_arg { struct haproxy_modsecurity_htx_filter_config *config; unsigned int index; };
static void *write_parallel_event(void *opaque) {
 struct writer_arg *arg = opaque;
 struct haproxy_modsecurity_htx_filter_context ctx = {0};
 haproxy_modsecurity_decision d = {0};
 ctx.config = arg->config;
 snprintf(ctx.lifecycle.transaction_id, sizeof(ctx.lifecycle.transaction_id), "parallel-%u", arg->index);
 d.disruptive = 1; d.phase = 2; d.status = 403; d.rule_id = 1250922;
 strcpy(d.action, "deny");
 haproxy_modsecurity_htx_report_decision("parallel", &ctx, &d);
 assert(!ctx.lifecycle.fail_closed);
 return NULL;
}
int main(void) {
 FILE *sink = fopen("physical-events.jsonl", "w+"); assert(sink != NULL);
 struct haproxy_modsecurity_htx_filter_config cfg = {0};
 struct haproxy_modsecurity_htx_filter_context ctx = {0};
 /* SETUP */
 strcpy(ctx.lifecycle.transaction_id, "native-independent-physical");
 haproxy_modsecurity_decision d = {0};
 d.disruptive = 1; d.phase = 1; d.status = 403; d.rule_id = 1250921;
 strcpy(d.action, "deny"); strcpy(d.log_message, "SECRET-MATCHED-PAYLOAD");
 for (int phase = 1; phase <= 4; ++phase) {
   d.phase = phase;
   ctx.request.finished = phase >= 2;
   ctx.response.headers_committed = phase == 4;
   ctx.response.finished = phase == 4;
   ctx.response.original_status = phase >= 3 ? 206 : 0;
   haproxy_modsecurity_htx_report_decision("request", &ctx, &d);
 }
 assert(fflush(sink) == 0);
 assert(ftell(sink) > 0); /* stderr/audit is not the configured Common sink. */
 rewind(sink); char line[8192]; assert(fgets(line, sizeof(line), sink) != NULL);
 assert(strstr(line, "native-independent-physical") != NULL);
 assert(strstr(line, "1250921") != NULL);
 assert(strstr(line, "SECRET-MATCHED-PAYLOAD") == NULL);
 assert(strstr(line, "\"actual_action\":\"\"") != NULL);
 assert(strstr(line, "engine_decision") != NULL);
 for (int phase = 2; phase <= 4; ++phase) {
   assert(fgets(line, sizeof(line), sink) != NULL);
   assert(strstr(line, "native-independent-physical") != NULL);
   assert(strstr(line, "1250921") != NULL);
   assert(strstr(line, "\"actual_action\":\"\"") != NULL);
 }
 assert(fgets(line, sizeof(line), sink) == NULL);
 assert(fseek(sink, 0, SEEK_END) == 0); long before = ftell(sink);
 d.disruptive = 0; d.rule_id = 0;
 haproxy_modsecurity_htx_report_decision("allow", &ctx, &d);
 assert(ftell(sink) == before); /* Allow does not invent an intervention. */
 d.disruptive = 1; d.rule_id = 1250921;
 d.error_class = MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE;
 haproxy_modsecurity_htx_report_decision("error", &ctx, &d);
 assert(fseek(sink, before, SEEK_SET) == 0);
 assert(fgets(line, sizeof(line), sink) != NULL);
 assert(strstr(line, "invalid_engine_response") != NULL);
 assert(strstr(line, "\"rule_id\":\"\"") != NULL);
 assert(fclose(sink) == 0);
 cookie_io_functions_t ops = {.write = native_sink_fault};
 cfg.events_file = fopencookie(NULL, "w", ops); assert(cfg.events_file != NULL);
 assert(setvbuf(cfg.events_file, NULL, _IONBF, 0) == 0);
 ctx.lifecycle.error.error_class = MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT;
 ctx.lifecycle.error.phase = 4;
 d.error_class = MSCONNECTOR_TRANSACTION_ERROR_NONE;
 haproxy_modsecurity_htx_report_decision("sink-fault", &ctx, &d);
 assert(ctx.lifecycle.fail_closed && cfg.events_error.code == MSCONNECTOR_ERROR_IO);
 assert(ctx.lifecycle.error.error_class == MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT);
 int writes = sink_fault_writes;
 d.disruptive = 0; d.rule_id = 0;
 for (int phase = 1; phase <= 3; phase += 2) {
   struct haproxy_modsecurity_htx_filter_context next = {0}; next.config = &cfg;
   next.request.headers_seen = 1; next.request.finished = phase == 3;
   next.response.headers_seen = phase == 3; d.phase = phase;
   haproxy_modsecurity_htx_report_decision("later-allow", &next, &d);
   assert(next.lifecycle.fail_closed && sink_fault_writes == writes);
   assert(next.lifecycle.error.phase == phase);
 }
 assert(!msconnector_event_file_close(&cfg.events_file, &cfg.events_error));
 for (int phase = 1; phase <= 3; phase += 2) {
   for (int cause = 0; cause < 3; ++cause) {
     msconnector_error_init(&cfg.events_error);
     cfg.events_file = fopencookie(NULL, "w", ops); assert(cfg.events_file != NULL);
     assert(setvbuf(cfg.events_file, NULL, _IONBF, 0) == 0);
     struct haproxy_modsecurity_htx_filter_context failed = {0}; failed.config = &cfg;
     failed.request.headers_seen = 1; failed.request.finished = phase == 3;
     failed.response.headers_seen = phase == 3;
     haproxy_modsecurity_decision denied = {0};
     denied.phase = phase; denied.disruptive = 1; denied.status = 403;
     strcpy(denied.action, "deny");
     if (cause == 1) {
       failed.lifecycle.error.error_class = MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT;
       failed.lifecycle.error.phase = 2; failed.lifecycle.error.status = 504;
     } else if (cause == 2) {
       denied.error_class = MSCONNECTOR_TRANSACTION_ERROR_ENGINE_UNAVAILABLE;
       denied.status = 503;
     }
     haproxy_modsecurity_htx_report_decision("exact-phase-sink-fault", &failed, &denied);
     assert(failed.lifecycle.fail_closed && cfg.events_error.code == MSCONNECTOR_ERROR_IO);
     assert(failed.lifecycle.error.phase == (cause == 1 ? 2 : phase));
     assert(failed.lifecycle.error.error_class == (cause == 1 ?
       MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT : cause == 2 ?
       MSCONNECTOR_TRANSACTION_ERROR_ENGINE_UNAVAILABLE : MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR));
     assert(failed.lifecycle.error.status == (cause == 1 ? 504 : 503));
     assert(!msconnector_event_file_close(&cfg.events_file, &cfg.events_error));
   }
 }
 msconnector_error_init(&cfg.events_error);
 cfg.events_file = fopen("parallel-events.jsonl", "w+"); assert(cfg.events_file != NULL);
 pthread_t threads[32]; struct writer_arg args[32];
 for (unsigned int i = 0; i < 32; ++i) {
   args[i] = (struct writer_arg){&cfg, i};
   assert(pthread_create(&threads[i], NULL, write_parallel_event, &args[i]) == 0);
 }
 for (int i = 0; i < 32; ++i) assert(pthread_join(threads[i], NULL) == 0);
 rewind(cfg.events_file); unsigned int count = 0; unsigned int seen = 0;
 while (fgets(line, sizeof(line), cfg.events_file)) {
   char *id = strstr(line, "parallel-"); unsigned int index = 99;
   assert(id && sscanf(id, "parallel-%u", &index) == 1 && index < 32);
   assert((seen & (1U << index)) == 0); seen |= 1U << index; count++;
 }
 assert(count == 32 && seen == 0xffffffffU);
 assert(msconnector_event_file_close(&cfg.events_file, &cfg.events_error));
 assert(pthread_mutex_destroy(&cfg.events_lock) == 0);
 return 0;
}
'''
        program = program.replace("/* STRUCTS */", structs).replace("/* FUNCTIONS */", "\n".join(bodies)).replace("/* SETUP */", setup)
        temp_root = Path(os.environ.get("TMPDIR", "/var/tmp/codex/ModSecurity-conector/tmp"))
        temp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="haproxy-physical-event-", dir=temp_root) as directory:
            temp = Path(directory)
            c = temp / "physical.c"
            c.write_text(program)
            sources = ["event_jsonl.c", "transaction_state.c", "transaction_id.c", "log_sanitize.c", "rule_id.c", "late_intervention.c", "event.c", "json_escape.c", "status.c", "http_status.c", "decision.c", "decision_action.c", "intervention.c", "error.c", "memory.c", "block_statuses.c"]
            command = ["cc", "-std=c17", "-Wall", "-Wextra", "-Werror", "-ffunction-sections", "-Wl,--gc-sections", "-pthread",
                "-I", str(source_path('common/include', root=ROOT)), "-I", str(source_path('common/runtime', root=ROOT)),
                "-I", str(source_path('connectors/haproxy/src', root=ROOT)), str(c),
                *(str(source_path('common/src', root=ROOT) / name) for name in sources), "-o", str(temp / "physical")]
            if sanitizers:
                command[1:1] = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return subprocess.run([str(temp / "physical")], capture_output=True, text=True, cwd=temp, timeout=30)

    def test_configured_native_common_sink_is_physical(self):
        result = self.compile_probe(FILTER.read_text())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_native_events_under_asan_ubsan(self):
        result = self.compile_probe(FILTER.read_text(), sanitizers=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_sink_phase_guessing_mutation_is_detected(self):
        source = FILTER.read_text()
        guard = "ctx->lifecycle.error.phase = decision->phase;"
        self.assertGreaterEqual(source.count(guard), 1)
        result = self.compile_probe(source.replace(guard,
            "ctx->lifecycle.error.phase = ctx->response.headers_seen ? 4 : 2;"))
        self.assertNotEqual(result.returncode, 0, "guessed sink phase mutation survived")

    def test_omitted_physical_write_mutation_is_detected(self):
        source = FILTER.read_text()
        old = "ok = msconnector_event_write_jsonl_stream(&event, config->events_file,\n        line, sizeof(line), &config->events_error);"
        self.assertIn(old, source)
        replacement = "(void)event; (void)line; ok = 1;"
        result = self.compile_probe(source.replace(old, replacement, 1))
        self.assertNotEqual(result.returncode, 0, "physical writer omission survived")

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
