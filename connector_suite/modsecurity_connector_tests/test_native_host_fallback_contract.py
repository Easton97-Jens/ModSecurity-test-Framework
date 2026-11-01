#!/usr/bin/env python3
"""Regression contracts for native connector authority handling.

Each native boundary must use only received authority metadata.  A server
endpoint or localhost must never silently replace a missing request Host.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import unittest
from pathlib import Path


ROOT = connector_root()
APACHE = (source_path('connectors/apache/src/msc_apache_mapper.c', root=ROOT)).read_text(
    encoding="utf-8"
)
HAPROXY_MAPPER = (
    source_path('connectors/haproxy/src/haproxy_modsecurity_mapper.c', root=ROOT)
).read_text(encoding="utf-8")
HAPROXY_BINDING = (
    source_path('connectors/haproxy/src/haproxy_modsecurity_binding.c', root=ROOT)
).read_text(encoding="utf-8")
HAPROXY_SPOP = (
    source_path('connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c', root=ROOT)
).read_text(encoding="utf-8")
COMMON_RUNTIME = (source_path('common/runtime/msconnector_runtime.c', root=ROOT)).read_text(
    encoding="utf-8"
)
MAPPER_CONTRACT = (source_path('common/src/request_mapper_contract.c', root=ROOT)).read_text(
    encoding="utf-8"
)


def source_between(source: str, start: str, end: str) -> str:
    return source[source.index(start) : source.index(end, source.index(start))]


class NativeHostFallbackContractTests(unittest.TestCase):
    def test_apache_mapper_rejects_missing_or_empty_received_host(self) -> None:
        mapper = source_between(
            APACHE,
            "int msc_apache_map_request(",
            "int msc_apache_map_response(",
        )
        self.assertIn(
            "host_header == NULL || host_header->value == NULL ||\n"
            "        host_header->value_size == 0U",
            mapper,
        )
        self.assertIn('"missing or invalid Host header"', mapper)
        self.assertIn("out->hostname = host_header->value;", mapper)
        self.assertNotIn("r->hostname", mapper)

    def test_haproxy_mapper_rejects_missing_or_empty_received_host(self) -> None:
        mapper = source_between(
            HAPROXY_MAPPER,
            "int haproxy_modsecurity_map_owned_request(",
            "int haproxy_modsecurity_map_owned_response(",
        )
        self.assertIn(
            "host_header == 0 || host_header->value == 0 ||\n"
            "            host_header->value_size == 0U",
            mapper,
        )
        self.assertIn('"missing or invalid Host header"', mapper)
        self.assertIn("haproxy_modsecurity_mapped_request_cleanup(out);", mapper)
        self.assertIn("out->request.hostname = host_header->value;", mapper)
        self.assertNotIn("out->request.hostname = src->server_ip;", mapper)

    def test_haproxy_binding_propagates_mapper_failure_before_transaction_allocation(
        self,
    ) -> None:
        validator = source_between(
            HAPROXY_BINDING,
            "static int validate_common_mapped_request(",
            "static int begin_transaction_protocol(",
        )
        transaction_begin = source_between(
            HAPROXY_BINDING,
            "int haproxy_modsecurity_transaction_begin_request_with_profile(",
            "int haproxy_modsecurity_transaction_begin_request(",
        )
        self.assertIn("return 1;", validator)
        self.assertIn(
            "if (!validate_common_mapped_request(engine, request, decision)) {\n"
            "        return 1;\n"
            "    }",
            transaction_begin,
        )
        self.assertLess(
            transaction_begin.index("validate_common_mapped_request"),
            transaction_begin.index("calloc(1U, sizeof(*created))"),
        )

    def test_haproxy_crs_helper_requires_explicit_host(self) -> None:
        crs = source_between(
            HAPROXY_BINDING,
            "int haproxy_modsecurity_crs_sqli_eval(",
            "int haproxy_modsecurity_crs_sqli_self_test(",
        )
        self.assertIn("if (host == 0 || host[0] == '\\0') {", crs)
        self.assertIn('"missing or invalid Host header"', crs)
        self.assertIn("headers[0].value = host;", crs)
        self.assertNotIn('"localhost"', crs)

    def test_spop_rejects_missing_host_before_any_request_processing(self) -> None:
        handler = source_between(
            HAPROXY_SPOP,
            "static int handle_notify_frame(",
            "static int handle_connection(",
        )
        self.assertIn(
            "if (!request.is_response && (!request.has_host ||\n"
            "            request.host[0] == '\\0'))",
            handler,
        )
        self.assertIn('send_agent_disconnect(fd, 4, "missing request host",', handler)
        self.assertLess(
            handler.index("missing request host"),
            handler.index("process_production_notify"),
        )
        self.assertNotIn('return request->has_host ? request->host : "localhost";', HAPROXY_SPOP)

    def test_endpoint_metadata_never_silently_becomes_a_loopback_connection(self) -> None:
        validator = source_between(
            COMMON_RUNTIME,
            "static int validate_request_input(",
            "static int validate_response_input(",
        )
        connection = source_between(
            COMMON_RUNTIME,
            "static int native_process_connection(",
            "static int native_process_request_headers(",
        )
        binding_connection = source_between(
            HAPROXY_BINDING,
            "static int process_request_connection(",
            "static int process_request_headers(",
        )
        spop_builder = source_between(
            HAPROXY_SPOP,
            "static void build_modsecurity_request_from_notify(",
            "static void finish_or_store_request_transaction(",
        )

        self.assertIn(
            "contract->client_endpoint = MSCONNECTOR_MAPPER_REQUIRED;",
            MAPPER_CONTRACT,
        )
        self.assertIn(
            "contract->server_endpoint = MSCONNECTOR_MAPPER_REQUIRED;",
            MAPPER_CONTRACT,
        )
        self.assertIn(
            "!bounded_c_string(request->client.address, RUNTIME_ADDRESS_SIZE, 1)",
            validator,
        )
        self.assertIn(
            "!bounded_c_string(request->server.address, RUNTIME_ADDRESS_SIZE, 1)",
            validator,
        )
        self.assertIn("request->client.address, request->client.port", connection)
        self.assertIn("request->server.address, request->server.port", connection)
        self.assertNotIn('"127.0.0.1"', connection)
        self.assertIn('"missing client or server endpoint"', binding_connection)
        self.assertNotIn('"127.0.0.1"', binding_connection)
        self.assertNotIn("49152", binding_connection)
        self.assertIn(
            "request->has_client_ip ? request->client_ip : NULL", spop_builder
        )
        self.assertIn(
            "request->has_server_ip ? request->server_ip : NULL", spop_builder
        )
        self.assertNotIn('"127.0.0.1"', spop_builder)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
