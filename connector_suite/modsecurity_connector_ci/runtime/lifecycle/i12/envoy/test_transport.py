"""Unary completion controls independent of companion Process cancellation."""
from types import SimpleNamespace
import unittest
import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.host_log_observations as host_logs
import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.transport as transport
import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.review_runs as review


def row(text, connection='0', stream='101'):
    return ('[2026-10-20T17:28:03.249+00:00] [285] [debug] [http] '
            '[Tags: "ConnectionId":"' + connection + '","StreamId":"' + stream + '"] ' + text)


class UnaryTransportControls(unittest.TestCase):
    def setUp(self):
        self.lines = [
            row('source/common/http/conn_manager_impl.cc:1 request headers complete (end_stream=false):', '1', '20'),
            "':path', '/target'",
            row("source/common/router/router.cc:1 cluster 'composite' match for URL '/envoy.service.auth.v3.Authorization/Check'"),
            row('source/common/http/http2/codec_impl.cc:1 Http2Visitor: remaining data payload: 180, stream_id: 1, end_stream: false', '2', '0'),
            row('source/common/http/async_client_impl.cc:230 async http request response trailers:'),
            "'grpc-status', '0'", "'grpc-message', ''", '',
            row('source/common/http/http2/codec_impl.cc:1 stream 1 closed: 0', '2', '0'),
            row("source/common/router/router.cc:1 cluster 'composite' match for URL '/envoy.service.ext_proc.v3.ExternalProcessor/Process'"),
            row('source/common/http/http2/codec_impl.cc:1 stream 3 closed: 0', '2', '0'),
            row('source/common/http/http2/codec_impl.cc:1 sent reset code=2', '2', '0')]

    def observe(self, lines=None, path='/target'):
        return transport.authorization_observation('\n'.join(self.lines if lines is None else lines), path, host_logs)

    def test_explicit_unary_success_survives_process_close_before_sent_reset(self):
        unary = self.observe()
        self.assertTrue(unary['verified'])
        result = transport.terminal({'verified': False}, unary)
        self.assertEqual(result['authorization']['remote_grpc_status'], 0)
        self.assertTrue(result['authorization']['successful_grpc_completion'])
        self.assertIsNone(result['process']['remote_grpc_status'])
        self.assertFalse(result['process']['successful_grpc_completion'])

    def test_missing_and_duplicate_required_rows_fail_closed(self):
        for index in (0, 2, 3, 4, 5, 8):
            with self.subTest(index=index, mutation='missing'):
                self.assertFalse(self.observe(self.lines[:index] + self.lines[index + 1:])['verified'])
            if index not in (0, 3):
                with self.subTest(index=index, mutation='duplicate'):
                    self.assertFalse(self.observe(self.lines[:index] + [self.lines[index]] + self.lines[index:])['verified'])
        self.assertFalse(self.observe(self.lines[:2] + self.lines)['verified'])

    def test_wrong_status_stream_connection_and_order_fail_closed(self):
        mutations = [(5, "'grpc-status', '13'"),
                     (8, self.lines[8].replace('closed: 0', 'closed: 2')),
                     (8, self.lines[8].replace('stream 1', 'stream 5')),
                     (8, self.lines[8].replace('"2"', '"9"')),
                     (4, self.lines[4].replace('"ConnectionId":"0"', '"ConnectionId":"99"')),
                     (4, self.lines[4].replace('"StreamId":"101"', '"StreamId":"999"')),
                     (4, self.lines[4].replace('async http request response trailers:', 'unrelated trailers:'))]
        for index, value in mutations:
            with self.subTest(index=index, value=value):
                lines = list(self.lines)
                lines[index] = value
                self.assertFalse(self.observe(lines)['verified'])
        lines = list(self.lines)
        lines[3], lines[8] = lines[8], lines[3]
        self.assertFalse(self.observe(lines)['verified'])
        self.assertFalse(self.observe(path='/wrong')['verified'])

    def test_next_request_or_method_cannot_supply_missing_evidence(self):
        for boundary in (row('source/common/http/conn_manager_impl.cc:1 request headers complete (end_stream=false):', '4', '40'),
                         row("source/common/router/router.cc:1 cluster 'other' match for URL '/other'")):
            self.assertFalse(self.observe(self.lines[:4] + [boundary] + self.lines[4:])['verified'])

    def test_two_payload_streams_or_statuses_fail_closed(self):
        self.assertFalse(self.observe(self.lines[:4] + [self.lines[3].replace('stream_id: 1', 'stream_id: 5')] + self.lines[4:])['verified'])
        self.assertFalse(self.observe(self.lines[:6] + ["'grpc-status', '13'"] + self.lines[6:])['verified'])

    def test_review_summary_uses_independent_unary_scope(self):
        artifacts = SimpleNamespace(raw=lambda name: '\n'.join(self.lines).encode())
        capture = SimpleNamespace(observe=lambda raw, path: {'verified': False},
                                  authorization_host_logs=host_logs)
        result = review.transport_summary(artifacts, {'target': 'target', 'neighbor': 'missing'}, transport, capture)
        self.assertTrue(result['target']['authorization']['successful_grpc_completion'])
        self.assertFalse(result['target']['process']['successful_grpc_completion'])
        self.assertFalse(result['neighbor']['authorization']['successful_grpc_completion'])

    def test_unrelated_downstream_backend_route_does_not_truncate_unary_close(self):
        other = row("source/common/router/router.cc:1 cluster 'backend' match for URL '/target'", '1', '20')
        self.assertTrue(self.observe(self.lines[:8] + [other] + self.lines[8:])['verified'])

    def test_unterminated_tag_cannot_supply_a_scope(self):
        malformed = ('[2026-10-20T17:28:03.249+00:00] ' + '[Tags:' * 10000 + ' ' * 100000
                     + 'conn_manager_impl.cc:1 request headers complete (end_stream=false):\n'
                     + "':path', '/target'")
        self.assertFalse(host_logs.extract(malformed, '/target')['scope_verified'])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
