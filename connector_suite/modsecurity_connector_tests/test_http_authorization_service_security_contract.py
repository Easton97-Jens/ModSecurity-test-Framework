from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import unittest
from pathlib import Path


ROOT = connector_root()
SOURCE = source_path('common/runtime/http_authorization_service.c', root=ROOT)


class HttpAuthorizationServiceSecurityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE.read_text(encoding="utf-8")

    def test_listener_policy_is_loopback_only(self) -> None:
        listen_parser = self.source.split("static int parse_listen_spec(", 1)[1].split(
            "static void parsed_request_destroy", 1
        )[0]
        self.assertIn('strcmp(host, "127.0.0.1") != 0', listen_parser)
        self.assertNotIn('strcmp(host, "0.0.0.0")', listen_parser)

    def test_security_header_duplicates_are_rejected_before_mapping(self) -> None:
        duplicate_check = self.source.split(
            "static int security_header_duplicates_are_rejected(", 1
        )[1].split("static int request_hostname", 1)[0]
        request_path = self.source.split(
            "static int handle_authorization_request(", 1
        )[1].split("static int create_listener", 1)[0]
        self.assertIn('"host"', duplicate_check)
        self.assertIn("profile->original_uri_headers", duplicate_check)
        self.assertIn("msconnector_headers_count_name", duplicate_check)
        self.assertIn("security_header_duplicates_are_rejected", request_path)
        self.assertLess(
            request_path.index("security_header_duplicates_are_rejected"),
            request_path.index("source.method = parsed.method"),
        )

    def test_missing_or_oversized_host_fails_closed_before_mapping(self) -> None:
        hostname_check = self.source.split("static int request_hostname", 1)[1].split(
            "static int send_all", 1
        )[0]
        request_path = self.source.split(
            "static int handle_authorization_request(", 1
        )[1].split("static int create_listener", 1)[0]
        self.assertIn("msconnector_headers_find_first(", hostname_check)
        self.assertIn("host->value_size > 0U", hostname_check)
        self.assertIn("copy_slice(host->value, host->value_size,", hostname_check)
        self.assertIn("request->hostname, sizeof(request->hostname)", hostname_check)
        self.assertIn('"missing or invalid Host header"', hostname_check)
        self.assertNotIn("return request->server_address", hostname_check)
        self.assertIn("request_hostname(&parsed, error, sizeof(error))", request_path)
        self.assertIn("source.hostname = parsed.hostname", request_path)
        self.assertLess(
            request_path.index("request_hostname(&parsed, error, sizeof(error))"),
            request_path.index("source.method = parsed.method"),
        )

    def test_existing_content_length_and_transfer_encoding_controls_remain(self) -> None:
        self.assertIn("transfer_encoding_supported", self.source)
        self.assertIn("msconnector_headers_parse_content_length", self.source)
        self.assertIn("chunked request bodies are unsupported", self.source)

    def test_client_socket_never_allows_an_unprotected_sigpipe_path(self) -> None:
        socket_setup = self.source.split("static int configure_client_socket(", 1)[1].split(
            "static int authorization_copy_profile", 1
        )[0]
        send_path = self.source.split("static int send_all(", 1)[1].split(
            "static int send_response(", 1
        )[0]
        self.assertIn("MSG_NOSIGNAL", send_path)
        self.assertIn("#if !defined(MSG_NOSIGNAL)", socket_setup)
        self.assertIn("#if defined(SO_NOSIGPIPE)", socket_setup)
        self.assertIn("setsockopt(socket_fd, SOL_SOCKET, SO_NOSIGPIPE", socket_setup)
        self.assertIn("errno = ENOTSUP", socket_setup)
        self.assertIn("return 0;", socket_setup)

    def test_termination_signal_ownership_excludes_workers(self) -> None:
        worker_main = self.source.split(
            "static void *authorization_worker_main(", 1
        )[1].split("static int authorization_start_worker(", 1)[0]
        worker_helpers = "\n".join(
            self.source.split(marker, 1)[1].split(next_marker, 1)[0]
            for marker, next_marker in (
                ("static int wait_for_socket(", "static int recv_more("),
                ("static int recv_more(", "static int parse_request_line("),
                ("static int send_all(", "static int send_response("),
            )
        )
        worker_start = self.source.split(
            "static int authorization_start_worker(", 1
        )[1].split("static void authorization_shutdown_workers(", 1)[0]
        self.assertNotIn("authorization_stop", worker_main)
        self.assertNotIn("authorization_stop", worker_helpers)
        self.assertIn("pthread_sigmask(SIG_BLOCK", self.source)
        self.assertIn("pthread_create(&thread", worker_start)
        self.assertIn("authorization_restore_signal_mask", worker_start)
        self.assertIn("SIGTERM", worker_start)
        self.assertIn("SIGINT", worker_start)

    def test_common_content_length_parser_rejects_any_duplicate_value(self) -> None:
        headers = (source_path('common/src/headers.c', root=ROOT)).read_text(encoding="utf-8")
        parser = headers.split("int msconnector_headers_parse_content_length(", 1)[1].split(
            "size_t msconnector_header_sanitize_value_for_log", 1
        )[0]
        self.assertIn("Reject every duplicate", parser)
        self.assertIn("if (seen) { return -1; }", parser)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
