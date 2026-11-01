#!/usr/bin/env python3
"""Contracts for HAProxy request/response validation before libmodsecurity sinks."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import subprocess
import tempfile
import unittest
from modsecurity_connector_tests.c_source_contract import function_definition


ROOT = connector_root()
MAPPER = (source_path('connectors/haproxy/src/haproxy_modsecurity_mapper.c', root=ROOT)).read_text(
    encoding="utf-8"
)
BINDING = (source_path('connectors/haproxy/src/haproxy_modsecurity_binding.c', root=ROOT)).read_text(
    encoding="utf-8"
)
SPOP_RUNTIME = (
    source_path('connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c', root=ROOT)
).read_text(encoding="utf-8")


class HaproxyHeaderValidationContractTests(unittest.TestCase):
    def test_mapper_validation_executes_without_libmodsecurity(self) -> None:
        harness = r'''
#include "haproxy_modsecurity_mapper.h"
#include <stddef.h>
#include <string.h>

static int request_case(const haproxy_modsecurity_header *headers,
        unsigned int count, int expected) {
    haproxy_modsecurity_request source;
    haproxy_modsecurity_mapped_request mapped;
    msconnector_request_mapper_contract contract;
    char error[128];
    memset(&source, 0, sizeof(source));
    source.method = "GET";
    source.http_version = "1.1";
    source.uri = "/";
    source.client_ip = "192.0.2.10";
    source.client_port = 12345;
    source.server_ip = "198.51.100.20";
    source.server_port = 443;
    source.headers = headers;
    source.header_count = count;
    msconnector_request_mapper_contract_init(&contract);
    error[0] = '\0';
    if ((haproxy_modsecurity_map_owned_request(&source, &contract, &mapped,
            error, sizeof(error)) == 1) != expected) {
        return 1;
    }
    if (expected) {
        if (mapped.request.hostname == NULL ||
                strcmp(mapped.request.hostname, "example.test") != 0 ||
                mapped.request.server.address != source.server_ip) {
            haproxy_modsecurity_mapped_request_cleanup(&mapped);
            return 1;
        }
        haproxy_modsecurity_mapped_request_cleanup(&mapped);
    } else if (mapped.owned_headers != NULL || mapped.request.headers != NULL ||
            mapped.request.header_count != 0U) {
        return 1;
    }
    return 0;
}

static int endpoint_case(const char *client_ip, const char *server_ip,
        int expected) {
    haproxy_modsecurity_header headers[] = {{"Host", "example.test"}};
    haproxy_modsecurity_request source;
    haproxy_modsecurity_mapped_request mapped;
    msconnector_request_mapper_contract contract;
    char error[128];

    memset(&source, 0, sizeof(source));
    source.method = "GET";
    source.http_version = "1.1";
    source.uri = "/";
    source.client_ip = client_ip;
    source.client_port = 12345;
    source.server_ip = server_ip;
    source.server_port = 443;
    source.headers = headers;
    source.header_count = 1U;
    msconnector_request_mapper_contract_init(&contract);
    error[0] = '\0';
    if ((haproxy_modsecurity_map_owned_request(&source, &contract, &mapped,
            error, sizeof(error)) == 1) != expected) {
        return 1;
    }
    if (expected) {
        haproxy_modsecurity_mapped_request_cleanup(&mapped);
    }
    return 0;
}

static int response_case(const haproxy_modsecurity_header *headers,
        unsigned int count, int expected) {
    haproxy_modsecurity_response source;
    haproxy_modsecurity_mapped_response mapped;
    msconnector_response_mapper_contract contract;
    char error[128];
    memset(&source, 0, sizeof(source));
    source.status = 200;
    source.protocol = "HTTP/1.1";
    source.headers = headers;
    source.header_count = count;
    msconnector_response_mapper_contract_init(&contract);
    error[0] = '\0';
    if ((haproxy_modsecurity_map_owned_response(&source, &contract, &mapped,
            error, sizeof(error)) == 1) != expected) {
        return 1;
    }
    if (expected) {
        haproxy_modsecurity_mapped_response_cleanup(&mapped);
    }
    return 0;
}

int main(void) {
    char oversize_name[258];
    char oversize_value[8194];
    char aggregate_value[8193];
    haproxy_modsecurity_header positive[] = {{"Host", "example.test"}};
    haproxy_modsecurity_header no_host[] = {{"X-Test", "value"}};
    haproxy_modsecurity_header empty_host[] = {{"Host", ""}};
    haproxy_modsecurity_header duplicate_host[] = {
        {"Host", "example.test"}, {"host", "other.test"}};
    haproxy_modsecurity_header duplicate_cl[] = {
        {"Host", "example.test"}, {"Content-Length", "1"},
        {"content-length", "1"}};
    haproxy_modsecurity_header cl_te[] = {
        {"Host", "example.test"}, {"Content-Length", "1"},
        {"Transfer-Encoding", "chunked"}};
    haproxy_modsecurity_header invalid_name[] = {{"Bad Name", "value"}};
    haproxy_modsecurity_header crlf_value[] = {{"Host", "bad\r\nInjected: yes"}};
    haproxy_modsecurity_header response_positive[] = {{"Content-Type", "text/plain"}};
    haproxy_modsecurity_header response_invalid[] = {{"Bad Name", "value"}};
    haproxy_modsecurity_header oversize_name_header[1];
    haproxy_modsecurity_header oversize_value_header[] = {{"Host", oversize_value}};
    haproxy_modsecurity_header aggregate[9];
    size_t index;

    memset(oversize_name, 'N', sizeof(oversize_name) - 1U);
    oversize_name[sizeof(oversize_name) - 1U] = '\0';
    oversize_name_header[0].name = oversize_name;
    oversize_name_header[0].value = "value";
    memset(oversize_value, 'v', sizeof(oversize_value) - 1U);
    oversize_value[sizeof(oversize_value) - 1U] = '\0';
    memset(aggregate_value, 'a', sizeof(aggregate_value) - 1U);
    aggregate_value[sizeof(aggregate_value) - 1U] = '\0';
    aggregate[0] = positive[0];
    for (index = 1U; index < 9U; ++index) {
        aggregate[index].name = index == 1U ? "X-1" :
            (index == 2U ? "X-2" : (index == 3U ? "X-3" :
            (index == 4U ? "X-4" : (index == 5U ? "X-5" :
            (index == 6U ? "X-6" : (index == 7U ? "X-7" : "X-8"))))));
        aggregate[index].value = aggregate_value;
    }
    if (request_case(NULL, 0U, 0) != 0 ||
            request_case(positive, 1U, 1) != 0 ||
            request_case(no_host, 1U, 0) != 0 ||
            request_case(empty_host, 1U, 0) != 0 ||
            request_case(duplicate_host, 2U, 0) != 0 ||
            request_case(duplicate_cl, 3U, 0) != 0 ||
            request_case(cl_te, 3U, 0) != 0 ||
            request_case(invalid_name, 1U, 0) != 0 ||
            request_case(crlf_value, 1U, 0) != 0 ||
            request_case(oversize_name_header, 1U, 0) != 0 ||
            request_case(oversize_value_header, 1U, 0) != 0 ||
            request_case(aggregate, 9U, 0) != 0 ||
            endpoint_case(NULL, "198.51.100.20", 0) != 0 ||
            endpoint_case("", "198.51.100.20", 0) != 0 ||
            endpoint_case("192.0.2.10", NULL, 0) != 0 ||
            endpoint_case("192.0.2.10", "", 0) != 0 ||
            response_case(response_positive, 1U, 1) != 0 ||
            response_case(response_invalid, 1U, 0) != 0) {
        return 1;
    }
    return 0;
}
'''
        common_sources = (
            source_path('common/src/headers.c', root=ROOT),
            source_path('common/src/request_helpers.c', root=ROOT),
            source_path('common/src/response_helpers.c', root=ROOT),
            source_path('common/src/resource_limits.c', root=ROOT),
            source_path('common/src/http_status.c', root=ROOT),
            source_path('common/src/request_mapper_contract.c', root=ROOT),
            source_path('common/src/response_mapper_contract.c', root=ROOT),
            source_path('connectors/haproxy/src/haproxy_modsecurity_mapper.c', root=ROOT),
        )
        with tempfile.TemporaryDirectory(prefix="haproxy-mapper-contract-") as directory:
            temp = Path(directory)
            harness_path = temp / "mapper_harness.c"
            binary = temp / "mapper_harness"
            harness_path.write_text(harness, encoding="utf-8")
            command = [
                "cc", "-std=c17", "-Wall", "-Wextra", "-Werror",
                "-I", str(source_path('common/include', root=ROOT)),
                "-I", str(source_path('connectors/haproxy/src', root=ROOT)),
                "-o", str(binary), str(harness_path),
                *(str(source) for source in common_sources),
            ]
            compile_result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(run_result.returncode, 0, run_result.stderr)

    def test_source_contract_rejects_framing_and_header_syntax_cases(self) -> None:
        for marker in (
            '"invalid header syntax"',
            '"missing or duplicate Host header"',
            '"duplicate Content-Length"',
            '"multiple Transfer-Encoding headers"',
            '"ambiguous Content-Length and Transfer-Encoding"',
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, MAPPER)
        self.assertIn("haproxy_header_name_valid", MAPPER)
        self.assertIn("haproxy_header_value_valid", MAPPER)
        for marker in (
            "MSCONNECTOR_MAX_HEADER_COUNT",
            "MSCONNECTOR_MAX_HEADER_NAME_LENGTH",
            "MSCONNECTOR_MAX_HEADER_VALUE_LENGTH",
            "MSCONNECTOR_MAX_TOTAL_HEADER_BYTES",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, MAPPER)

    def test_static_fixtures_cover_negative_and_positive_header_shapes(self) -> None:
        fixtures = (
            (("Host", "example.test"),),
            (("Host", "example.test"), ("host", "other.test")),
            (("Host", "example.test"), ("Content-Length", "1"), ("content-length", "1")),
            (("Host", "example.test"), ("Content-Length", "1"), ("Transfer-Encoding", "chunked")),
            (("Bad Name", "value"),),
            (("X-Test", "value\r\nInjected: yes"),),
            (("X" * 257, "value"),),
            (("X-Test", "v" * 8193),),
            tuple((f"X-{index}", "v" * 8192) for index in range(8)),
        )
        self.assertEqual(fixtures[0][0], ("Host", "example.test"))
        self.assertEqual(fixtures[1][0][0].lower(), "host")
        self.assertEqual(fixtures[2][1][0].lower(), "content-length")
        self.assertEqual(fixtures[3][2][0].lower(), "transfer-encoding")
        self.assertIn(" ", fixtures[4][0][0])
        self.assertIn("\r\n", fixtures[5][0][1])
        self.assertGreater(len(fixtures[6][0][0]), 256)
        self.assertGreater(len(fixtures[7][0][1]), 8192)
        self.assertGreater(sum(len(name) + len(value) for name, value in fixtures[8]), 65536)

    def test_legacy_request_validation_precedes_engine_creation(self) -> None:
        eval_start = BINDING.index("static int eval_request_internal(")
        init = BINDING.index("modsec = msc_init();", eval_start)
        validate = BINDING.index(
            "validate_common_mapped_request(0, request, decision)", eval_start
        )
        self.assertLess(validate, init)

    def test_endpoint_metadata_is_rejected_before_connection_processing(self) -> None:
        connection_start = BINDING.index("static int process_request_connection(")
        connection_end = BINDING.index("static int process_request_headers(", connection_start)
        connection = BINDING[connection_start:connection_end]
        self.assertIn('"missing client or server endpoint"', connection)
        self.assertIn("request->client_ip, request->client_port", connection)
        self.assertIn("request->server_ip, request->server_port", connection)
        self.assertNotIn('"127.0.0.1"', connection)
        self.assertNotIn("49152", connection)

    def test_spop_rejects_oversized_endpoint_ports_before_int_conversion(self) -> None:
        parse_start = SPOP_RUNTIME.index("static int parse_notify_uint_argument(")
        parse_end = SPOP_RUNTIME.index(
            "static int parse_notify_response_header_argument(", parse_start
        )
        parse_uint = SPOP_RUNTIME[parse_start:parse_end]
        build_start = SPOP_RUNTIME.index("static void build_modsecurity_request_from_notify(")
        build_end = SPOP_RUNTIME.index("static int process_production_notify(", build_start)
        build_request = SPOP_RUNTIME[build_start:build_end]

        self.assertIn("*arguments[index].value > 65535U", parse_uint)
        self.assertIn('KEY_EQUALS_LITERAL(arg_name, arg_name_len, "client_port")', parse_uint)
        self.assertIn('KEY_EQUALS_LITERAL(arg_name, arg_name_len, "server_port")', parse_uint)
        self.assertIn("(int)request->client_port", build_request)
        self.assertIn("(int)request->server_port", build_request)
        self.assertIn(
            "static int self_test_rejects_oversized_endpoint_port(void)", SPOP_RUNTIME
        )
        self.assertIn("append_typed_uint32(&payload, 65536U)", SPOP_RUNTIME)
        self.assertIn("run_spop_protocol_self_tests()",
            function_definition(SPOP_RUNTIME, "run_self_test"))
        self.assertIn("self_test_rejects_oversized_endpoint_port() != 0",
            function_definition(SPOP_RUNTIME, "run_spop_protocol_self_tests"))

    def test_spop_requires_fin_before_payload_parsing(self) -> None:
        parser_start = SPOP_RUNTIME.index("static int recv_frame(")
        parser_end = SPOP_RUNTIME.index(
            "static int self_test_rejects_fin_unset_frame(", parser_start
        )
        parser = SPOP_RUNTIME[parser_start:parser_end]
        self.assertIn("if ((frame->flags & SPOP_FIN_FLAG) == 0U)", parser)
        self.assertLess(
            parser.index("if ((frame->flags & SPOP_FIN_FLAG) == 0U)"),
            parser.index("read_varint(data, len, &pos, &frame->stream_id)"),
        )
        self.assertIn("static int self_test_rejects_fin_unset_frame(void)", SPOP_RUNTIME)
        self.assertIn("send_frame_with_flags(sockets[0], SPOP_FRM_NOTIFY, 0U", SPOP_RUNTIME)
        self.assertIn("run_spop_protocol_self_tests()",
            function_definition(SPOP_RUNTIME, "run_self_test"))
        self.assertIn("self_test_rejects_fin_unset_frame() != 0",
            function_definition(SPOP_RUNTIME, "run_spop_protocol_self_tests"))

    def test_response_mapper_failure_precedes_raw_response_header_loop(self) -> None:
        mapper_start = BINDING.index("static int map_response_for_transaction(")
        mapper_end = BINDING.index("static int add_response_headers(", mapper_start)
        mapper = BINDING[mapper_start:mapper_end]
        start = BINDING.index("int haproxy_modsecurity_transaction_process_response_headers(")
        end = BINDING.index(
            "int haproxy_modsecurity_transaction_append_response_body_chunk(", start
        )
        function = BINDING[start:end]
        self.assertIn("normalized_response.status", mapper)
        self.assertIn("haproxy_modsecurity_map_owned_response", mapper)
        self.assertIn('"common response mapper validation failed"', mapper)
        self.assertIn("return 0;", mapper)
        self.assertLess(
            function.index("map_response_for_transaction"),
            function.index("add_response_headers"),
        )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
