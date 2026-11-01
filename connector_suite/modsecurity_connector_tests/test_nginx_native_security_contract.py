"""Static contracts for NGINX-native request boundary hardening."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import unittest

from modsecurity_connector_tests.c_source_contract import function_definition


ROOT = connector_root()
ACCESS = (source_path('connectors/nginx/src/ngx_http_modsecurity_access.c', root=ROOT)).read_text(
    encoding="utf-8"
)
MAPPER = (source_path('connectors/nginx/src/ngx_http_modsecurity_mapper.c', root=ROOT)).read_text(
    encoding="utf-8"
)
MODULE = (source_path('connectors/nginx/src/ngx_http_modsecurity_module.c', root=ROOT)).read_text(
    encoding="utf-8"
)
BODY_FILTER = (
    source_path('connectors/nginx/src/ngx_http_modsecurity_body_filter.c', root=ROOT)
).read_text(encoding="utf-8")
COMMON = (source_path('connectors/nginx/src/ngx_http_modsecurity_common.h', root=ROOT)).read_text(
    encoding="utf-8"
)
HARNESS = (source_path('connectors/nginx/harness/run_nginx_smoke.sh', root=ROOT)).read_text(
    encoding="utf-8"
)
EXACT_GATE = (source_path('connectors/nginx/harness/run_exact_head_use_error_log.sh', root=ROOT)).read_text(
    encoding="utf-8"
)


class NginxNativeSecurityContractTest(unittest.TestCase):
    def test_hostname_requires_received_host_and_has_no_server_name_fallback(self) -> None:
        hostname = ACCESS.split(
            "ngx_http_modsecurity_set_request_hostname", 1
        )[1].split("static ngx_int_t", 1)[0]
        self.assertIn("r->headers_in.host != NULL", hostname)
        self.assertIn("NGX_HTTP_BAD_REQUEST", hostname)
        self.assertNotIn("server_name", hostname)
        self.assertNotIn("headers_in.server", hostname)
        self.assertNotIn("server_name", MAPPER)
        self.assertNotIn("headers_in.server", MAPPER)

    def test_request_body_preserves_technical_file_and_overflow_guards(self) -> None:
        self.assertNotIn("common_config.request_body_limit", ACCESS)
        self.assertIn("SIZE_MAX - chunk_size", ACCESS)
        self.assertIn("ngx_fd_info(file->fd, &file_info)", ACCESS)
        self.assertIn("ngx_is_file(&file_info)", ACCESS)
        self.assertIn("ngx_file_size(&file_info) != file_size", ACCESS)
        self.assertIn("ngx_pnalloc(r->pool, 32768U)", ACCESS)
        self.assertIn("ngx_read_file(file, ctx->scratch_buffers.request_file_scratch", ACCESS)

    def test_native_ingestion_failures_remain_fail_closed(self) -> None:
        self.assertIn("ret = msc_append_request_body", ACCESS)
        self.assertNotIn("msc_request_body_from_file", ACCESS)
        self.assertIn("if (!msconnector_native_body_append_can_continue(ret))", ACCESS)
        self.assertIn("ngx_http_modsecurity_capture_request_body_intervention(r)", ACCESS)

    def test_mapper_failure_stops_initialization_before_header_sink(self) -> None:
        mapper = ACCESS.split(
            "ngx_http_modsecurity_validate_common_request_mapper", 1
        )[1].split("static ngx_int_t", 1)[0]
        initialize = ACCESS.split(
            "ngx_http_modsecurity_initialize_request", 1
        )[1].split("static ngx_int_t", 1)[0]

        self.assertIn("validation failed", mapper)
        self.assertIn("ngx_int_t mapper_status = NGX_HTTP_INTERNAL_SERVER_ERROR;", mapper)
        self.assertIn("&mapper_status, mapper_error, sizeof(mapper_error)", mapper)
        self.assertIn("return mapper_status;", mapper)
        self.assertNotIn("return NGX_HTTP_BAD_REQUEST", mapper)
        self.assertNotIn("validation skipped", mapper)
        request_mapper = function_definition(MAPPER, "ngx_http_modsecurity_map_request")
        self.assertIn(
            "if (failure_status != NULL) {\n"
            "        *failure_status = NGX_HTTP_INTERNAL_SERVER_ERROR;\n"
            "    }",
            request_mapper,
        )
        self.assertLess(
            request_mapper.index("*failure_status = NGX_HTTP_INTERNAL_SERVER_ERROR;"),
            request_mapper.index("if (r == NULL || out == NULL || contract == NULL)"),
        )
        self.assertIn(
            "if (contract->max_header_count > 0U &&\n"
            "        ngx_http_modsecurity_count_list_headers(&r->headers_in.headers) >\n"
            "            contract->max_header_count) {\n"
            "        if (failure_status != NULL) {\n"
            "            *failure_status = NGX_HTTP_BAD_REQUEST;\n"
            "        }\n"
            '        ngx_http_modsecurity_mapper_error(error, error_len, "too many headers");\n'
            "        return 0;\n"
            "    }",
            request_mapper,
        )
        self.assertEqual(request_mapper.count("*failure_status = NGX_HTTP_BAD_REQUEST;"), 1)
        self.assertIn(
            "rc = ngx_http_modsecurity_validate_common_request_mapper(r);",
            initialize,
        )
        self.assertIn(
            "if (rc != NGX_OK) {\n        ctx->intervention_triggered = 1;\n        return rc;\n    }",
            initialize,
        )
        self.assertLess(
            initialize.index("ngx_http_modsecurity_validate_common_request_mapper"),
            initialize.index("ngx_http_modsecurity_set_request_hostname"),
        )
        self.assertLess(
            initialize.index("return rc;"),
            initialize.index("ngx_http_modsecurity_process_request_headers"),
        )
        self.assertIn("ngx_http_modsecurity_add_n_request_header", ACCESS)
        request_header_sink = COMMON.split(
            "ngx_http_modsecurity_add_n_request_header", 1
        )[1].split("ngx_http_modsecurity_add_n_response_header", 1)[0]
        self.assertIn("msc_add_n_request_header", request_header_sink)
        self.assertLess(
            request_header_sink.index("ngx_http_modsecurity_validate_header"),
            request_header_sink.index("msc_add_n_request_header"),
        )

    def test_native_event_file_configuration_uses_common_private_descriptor(self) -> None:
        setter = MODULE.split("static char *\nngx_conf_set_phase4_log", 1)[1].split(
            "static ngx_int_t", 1
        )[0]

        self.assertIn('return "is duplicate";', setter)
        self.assertIn("ngx_strlchr", setter)
        self.assertIn("msconnector_open_private_event_file(path, &fd)", setter)
        self.assertNotIn("ngx_conf_open_file(", setter)
        self.assertNotIn("ngx_list_push(", setter)
        self.assertIn("generic reopen routine", setter)
        self.assertIn("event_file->fd = NGX_INVALID_FILE", setter)
        self.assertIn("ngx_pool_cleanup_add(cf->pool, 0)", setter)
        self.assertIn(
            "cleanup->handler = ngx_http_modsecurity_cleanup_phase4_log", setter
        )
        self.assertIn("cleanup->handler = NULL", setter)
        self.assertIn("cleanup->data = NULL", setter)
        self.assertIn("ngx_conf_log_error(NGX_LOG_EMERG", setter)
        self.assertIn("event_file->fd = (ngx_fd_t)fd", setter)
        self.assertIn("event_file->name = value[1]", setter)
        self.assertIn("mcf->phase4_log_path = value[1]", setter)
        self.assertIn("mcf->common_config.phase4_log_path = path", setter)
        self.assertLess(
            setter.index("ngx_pool_cleanup_add(cf->pool, 0)"),
            setter.index("msconnector_open_private_event_file(path, &fd)"),
        )
        self.assertLess(
            setter.index("msconnector_open_private_event_file(path, &fd)"),
            setter.index("event_file->fd = (ngx_fd_t)fd"),
        )

    def test_native_event_file_cleanup_invalidates_before_close(self) -> None:
        cleanup = MODULE.split(
            "static void\nngx_http_modsecurity_cleanup_phase4_log", 1
        )[1].split("\n\n\n/* vi:set", 1)[0]

        self.assertIn("event_file->fd == NGX_INVALID_FILE", cleanup)
        self.assertIn("fd = event_file->fd", cleanup)
        self.assertIn("event_file->fd = NGX_INVALID_FILE", cleanup)
        self.assertIn("(void)ngx_close_file(fd)", cleanup)
        self.assertLess(
            cleanup.index("event_file->fd = NGX_INVALID_FILE"),
            cleanup.index("(void)ngx_close_file(fd)"),
        )

    def test_native_event_file_inheritance_borrows_without_new_cleanup(self) -> None:
        merge = MODULE.split("static char *\nngx_http_modsecurity_merge_conf", 1)[1].split(
            "\n\nstatic void\nngx_http_modsecurity_cleanup_instance", 1
        )[0]

        self.assertIn("if (c->phase4_log_file == NGX_CONF_UNSET_PTR)", merge)
        self.assertIn("c->phase4_log_file = p->phase4_log_file", merge)
        self.assertIn("c->phase4_log_path = p->phase4_log_path", merge)
        self.assertIn("c->phase4_log_file = NULL", merge)
        self.assertNotIn("ngx_conf_merge_ptr_value(c->phase4_log_file", merge)

    def test_phase4_event_uses_the_safe_request_metadata_helper(self) -> None:
        phase4_event = function_definition(
            BODY_FILTER, "ngx_http_modsecurity_phase4_log_event"
        )

        self.assertIn(
            "ngx_http_modsecurity_event_request_metadata_t request_metadata;",
            phase4_event,
        )
        self.assertIn(
            "request_metadata = ngx_http_modsecurity_event_request_metadata(r);",
            phase4_event,
        )
        self.assertIn("event.request.method = request_metadata.method;", phase4_event)
        self.assertIn("event.request.uri = request_metadata.uri;", phase4_event)
        self.assertLess(
            phase4_event.index(
                "request_metadata = ngx_http_modsecurity_event_request_metadata(r);"
            ),
            phase4_event.index("event.request.uri = request_metadata.uri;"),
        )

    def test_hosted_phase4_lifecycle_keeps_generic_reopen_outside_the_sink(self) -> None:
        for target_mode in (
            "unsafe_symlink",
            "unsafe_fifo",
            "unsafe_directory",
            "unsafe_writable_parent",
            "unsafe_wrong_owner",
        ):
            self.assertIn(target_mode, HARNESS)
        self.assertIn('"$NGINX_BINARY" -t -p "$RUNTIME_ROOT" -c "$CONFIG_FILE"', HARNESS)
        self.assertIn("nginx-reload-unsafe-phase4-configtest.log", HARNESS)
        phase4_lifecycle = HARNESS.split("exercise_phase4_log_lifecycle() {", 1)[
            1
        ].split("\n}\n\nsoak_request_matches_case()", 1)[0]
        unsafe_reload = phase4_lifecycle.split(
            'if "$NGINX_BINARY" -t -p "$RUNTIME_ROOT" -c "$CONFIG_FILE"', 1
        )[1].split("phase4_old_before_failed_reload_request=", 1)[0]
        self.assertIn("record_nginx_master_worker_roles >/dev/null", unsafe_reload)
        self.assertIn('/bin/kill -HUP "$NGINX_PID"', unsafe_reload)
        self.assertNotIn(
            '"$NGINX_BINARY" -p "$RUNTIME_ROOT" -c "$CONFIG_FILE" -s reload',
            unsafe_reload,
        )
        self.assertLess(
            unsafe_reload.index("record_nginx_master_worker_roles >/dev/null"),
            unsafe_reload.index('/bin/kill -HUP "$NGINX_PID"'),
        )
        self.assertIn('/bin/kill -USR1 "$NGINX_PID"', HARNESS)
        overlap_client = HARNESS.split("start_phase4_reload_overlap_client() {", 1)[
            1
        ].split("validate_phase4_reload_overlap_server_record()", 1)[0]
        self.assertIn(
            "phase4_reload_overlap_sync_enabled ||",
            overlap_client,
        )
        self.assertIn('while [ "$phase4_overlap_attempt" -lt 100 ]; do', overlap_client)
        self.assertIn('[ -f "$SYNCHRONIZED_PAUSED_FILE" ]', overlap_client)
        self.assertIn('[ ! -L "$SYNCHRONIZED_PAUSED_FILE" ]', overlap_client)
        self.assertIn('[ -s "$phase4_overlap_output" ]', overlap_client)
        self.assertIn('/bin/kill -0 "$PHASE4_RELOAD_OVERLAP_CLIENT_PID"', overlap_client)
        self.assertIn("--no-buffer --max-time 30 -X GET", overlap_client)
        self.assertIn(
            "phase4 reload-overlap client did not reach the paused first-byte barrier",
            overlap_client,
        )
        self.assertNotIn("PHASE4_SLOW_STREAM_PID", overlap_client)
        overlap_stop = HARNESS.split("stop_phase4_reload_overlap_client() {", 1)[
            1
        ].split("observe_phase4_reload_overlap()", 1)[0]
        self.assertIn(': > "$SYNCHRONIZED_RELEASE_FILE"', overlap_stop)
        self.assertIn('wait "$SYNCHRONIZED_UPSTREAM_PID"', overlap_stop)
        self.assertIn("validate_phase4_reload_overlap_server_record", overlap_stop)
        overlap_server_validation = HARNESS.split(
            "validate_phase4_reload_overlap_server_record() {", 1
        )[1].split("stop_phase4_reload_overlap_client()", 1)[0]
        self.assertIn("body_payload_persisted", overlap_server_validation)
        process_snapshot = HARNESS.split("nginx_process_child_snapshot() {", 1)[
            1
        ].split("nginx_process_children()", 1)[0]
        self.assertIn('ps -o pid=,ppid=,stat= --ppid "$nginx_snapshot_parent_pid"', process_snapshot)
        self.assertIn('-v expected_parent="$nginx_snapshot_parent_pid"', process_snapshot)
        self.assertIn('$2 == expected_parent', process_snapshot)
        self.assertIn('$3 !~ /^Z/', process_snapshot)
        process_children = HARNESS.split("nginx_process_children() {", 1)[1].split(
            "nginx_process_record()", 1
        )[0]
        self.assertIn("nginx_children_parent_pid=$1", process_children)
        self.assertIn(
            'nginx_process_child_snapshot "$nginx_children_parent_pid"',
            process_children,
        )
        overlap_observation = HARNESS.split("observe_phase4_reload_overlap() {", 1)[
            1
        ].split("send_expected_phase4_lifecycle_request()", 1)[0]
        self.assertIn('phase4_overlap_snapshot=$(nginx_process_child_snapshot "$NGINX_PID")', overlap_observation)
        self.assertIn('-v expected_old_worker="$phase4_old_worker"', overlap_observation)
        self.assertIn('-v expected_parent="$NGINX_PID"', overlap_observation)
        self.assertIn('phase4_replacement_present=', overlap_observation)
        self.assertIn('last_snapshot=$phase4_overlap_last_snapshot result=not_observed', overlap_observation)
        self.assertNotIn('case " $phase4_overlap_workers "', overlap_observation)
        synchronized_start = HARNESS.split("start_synchronized_upstream() {", 1)[
            1
        ].split("send_synchronized_first_byte_request()", 1)[0]
        self.assertIn('SYNCHRONIZED_UPSTREAM_CONTROL_ROOT', synchronized_start)
        self.assertIn('--control-root "$SYNCHRONIZED_CONTROL_ROOT"', synchronized_start)
        self.assertIn(
            '[ ! -e "$SYNCHRONIZED_DIR" ] && [ ! -L "$SYNCHRONIZED_DIR" ]',
            synchronized_start,
        )
        self.assertNotIn('rm -rf "$SYNCHRONIZED_DIR"', synchronized_start)
        generated_path_authority = HARNESS.split(
            "validate_nginx_generated_path_authority() {", 1
        )[1].split("validate_nginx_external_projection_authority()", 1)[0]
        self.assertIn(
            'if [ "$MSCONNECTOR_FULL_LIFECYCLE_SYNC" = "1" ]; then',
            generated_path_authority,
        )
        self.assertIn(
            'blocked "full-lifecycle synchronized upstream requires SYNCHRONIZED_UPSTREAM_CONTROL_ROOT"',
            generated_path_authority,
        )
        self.assertIn(
            '--directory SYNCHRONIZED_UPSTREAM_CONTROL_ROOT "$SYNCHRONIZED_UPSTREAM_CONTROL_ROOT"',
            generated_path_authority,
        )
        self.assertLess(
            generated_path_authority.index("SYNCHRONIZED_UPSTREAM_CONTROL_ROOT"),
            generated_path_authority.index('if ! "$@"; then'),
        )
        overlap_directives = HARNESS.split(
            "write_phase4_reload_overlap_directives() {", 1
        )[1].split("write_location_handler_directives()", 1)[0]
        self.assertIn('proxy_pass http://127.0.0.1:$PHASE4_RELOAD_OVERLAP_UPSTREAM_PORT;', overlap_directives)
        self.assertIn('echo "proxy_buffering off;"', overlap_directives)
        self.assertIn('echo "proxy_set_header Host \\$host;"', overlap_directives)
        self.assertIn('echo "limit_rate 1024;"', overlap_directives)
        self.assertLess(
            phase4_lifecycle.index("start_phase4_reload_overlap_client"),
            phase4_lifecycle.index(
                '"$NGINX_BINARY" -p "$RUNTIME_ROOT" -c "$CONFIG_FILE" -s reload'
            ),
        )
        self.assertLess(
            phase4_lifecycle.index("observe_phase4_reload_overlap"),
            phase4_lifecycle.rindex("stop_phase4_reload_overlap_client"),
        )
        smoke_template = (
            source_path('connectors/nginx/harness/nginx_smoke.conf', root=ROOT)
        ).read_text(encoding="utf-8")
        self.assertIn("location = /__modsec_slow_stream", smoke_template)
        self.assertIn("modsecurity off;", smoke_template)
        self.assertIn("@@NGINX_PHASE4_RELOAD_OVERLAP_DIRECTIVES@@", smoke_template)
        self.assertIn("phase4_fd_count_for_target()", HARNESS)
        self.assertIn("assert_phase4_fd_absent", HARNESS)
        self.assertIn("start_phase4_reload_overlap_client", HARNESS)
        self.assertIn("phase=phase4_reload_overlap", HARNESS)
        self.assertIn("phase=phase4_fd_shutdown result=closed_after_master_exit", HARNESS)
        self.assertIn("phase4_reload_unsafe result=failed_old_cycle_preserved", EXACT_GATE)
        self.assertIn("phase4_reload_secure result=new_validated_fd", EXACT_GATE)
        self.assertIn("phase=phase4_reload_overlap", EXACT_GATE)
        self.assertIn("phase=phase4_fd_shutdown result=closed_after_master_exit", EXACT_GATE)

    def test_connector_owned_phase4_mime_file_is_not_registered(self) -> None:
        for source in (MODULE, COMMON, BODY_FILTER):
            self.assertNotIn("phase4_content_types", source)
        self.assertNotIn("ngx_http_modsecurity_phase4_load_content_types_file", MODULE)
        self.assertNotIn("ngx_conf_set_phase4_content_types_file", MODULE)
        append = function_definition(
            BODY_FILTER, "ngx_http_modsecurity_append_response_chain_buffer"
        )
        self.assertNotIn("content_type", append)
        self.assertNotIn("phase4_in_scope", append)
        self.assertIn("ngx_http_modsecurity_append_response_body_buffer", append)

    def test_native_event_file_examples_remain_bounded_and_remote_rules_stay_disabled(self) -> None:
        safe = (source_path('examples/nginx/safe/nginx.conf', root=ROOT)).read_text(
            encoding="utf-8"
        )
        strict = (source_path('examples/nginx/strict/nginx.conf', root=ROOT)).read_text(
            encoding="utf-8"
        )
        smoke = (source_path('connectors/nginx/harness/nginx_smoke.conf', root=ROOT)).read_text(
            encoding="utf-8"
        )
        reference = (source_path('examples/nginx/configuration-reference.md', root=ROOT)).read_text(
            encoding="utf-8"
        )
        reference_de = (
            source_path('examples/nginx/configuration-reference.de.md', root=ROOT)
        ).read_text(encoding="utf-8")

        for configuration in (safe, strict):
            self.assertNotIn("modsecurity_phase4_log ", configuration)
        # The pinned Framework fixture supplies the directive through the one
        # location include.  The Parent template must not add a second copy:
        # duplicate directives would open a second owned descriptor.
        self.assertIn('include "@@NGINX_LOCATION_DIRECTIVES@@";', smoke)
        self.assertNotIn("modsecurity_phase4_log", smoke)
        self.assertNotIn("registered but always rejected path", reference)
        self.assertNotIn("registrierter, aber immer abgelehnter Pfad", reference_de)
        self.assertIn("Policy A rejects remote-rule configuration", reference)
        self.assertIn("Policy A weist Remote-Rule-Konfiguration ab", reference_de)
        self.assertNotIn("Passes the key/URL pair to libmodsecurity", reference)
        self.assertNotIn(
            "Übergibt das Schlüssel-/URL-Paar an den Remote-Regel-Loader",
            reference_de,
        )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
