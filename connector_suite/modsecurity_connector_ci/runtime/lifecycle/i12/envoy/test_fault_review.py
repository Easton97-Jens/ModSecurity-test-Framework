"""Mutation controls for independently scoped Response-EOS fault evidence."""
import copy
import hashlib
import json
import unittest
from unittest.mock import patch

import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.fault_review as F


class ProxyReviewControls(unittest.TestCase):
    target = 'target-nonce'
    neighbor = 'neighbor-nonce'
    error_hash = 'e' * 64

    @staticmethod
    def message(stream, sequence, identity, direction, digest, **values):
        return {'stream_id': stream, 'sequence': sequence, 'request_id': identity,
            'event': 'message', 'direction': direction, 'message_sha256': digest * 64,
            'message_bytes': values.pop('message_bytes', 4), **values}

    def rows(self):
        target = [
            {'stream_id': 1, 'sequence': 1, 'request_id': '', 'event': 'upstream_attempt_begin'},
            self.message(1, 2, self.target, 'downstream_receive', 'a'),
            self.message(1, 3, self.target, 'upstream_send', 'a'),
            self.message(1, 4, self.target, 'upstream_receive', 'b'),
            self.message(1, 5, self.target, 'downstream_send', 'b'),
            self.message(1, 6, self.target, 'downstream_receive', 'c', message_bytes=6,
                message_type='*ext_procv3.ProcessingRequest_ResponseBody', body_bytes=0,
                body_sha256=hashlib.sha256(b'').hexdigest(), eos=True),
            self.message(1, 7, self.target, 'dropped_before_upstream_send', 'c', message_bytes=6,
                message_type='*ext_procv3.ProcessingRequest_ResponseBody', body_bytes=0,
                body_sha256=hashlib.sha256(b'').hexdigest(), eos=True),
            {'stream_id': 1, 'sequence': 8, 'request_id': self.target,
                'event': 'upstream_close_send_return', 'close_send_error_nil': True,
                'grpc_api_code': None, 'wire_grpc_status': None},
            {'stream_id': 1, 'sequence': 9, 'request_id': self.target,
                'event': 'upstream_attempt_end', 'grpc_api_code': 14, 'recv_eof': False,
                'wire_grpc_status': None, 'error_sha256': self.error_hash},
            {'stream_id': 1, 'sequence': 10, 'request_id': self.target,
                'event': 'upstream_recv_end', 'grpc_api_code': 14, 'recv_eof': False,
                'wire_grpc_status': None, 'error_sha256': self.error_hash, 'trailers': {}},
            {'stream_id': 1, 'sequence': 11, 'request_id': self.target,
                'event': 'downstream_return', 'grpc_api_code': 14, 'recv_eof': False,
                'wire_grpc_status': None, 'error_sha256': self.error_hash,
                'return_source': 'upstream_receive'},
        ]
        neighbor = [
            {'stream_id': 2, 'sequence': 1, 'request_id': '', 'event': 'upstream_attempt_begin'},
            self.message(2, 2, self.neighbor, 'downstream_receive', 'd'),
            self.message(2, 3, self.neighbor, 'upstream_send', 'd'),
            self.message(2, 4, self.neighbor, 'upstream_receive', 'f'),
            self.message(2, 5, self.neighbor, 'downstream_send', 'f'),
            {'stream_id': 2, 'sequence': 6, 'request_id': self.neighbor,
                'event': 'upstream_attempt_end', 'grpc_api_code': 0, 'recv_eof': False,
                'wire_grpc_status': None},
            {'stream_id': 2, 'sequence': 7, 'request_id': self.neighbor,
                'event': 'upstream_recv_end', 'grpc_api_code': 0, 'recv_eof': True,
                'wire_grpc_status': None, 'trailers': {}},
            {'stream_id': 2, 'sequence': 8, 'request_id': self.neighbor,
                'event': 'downstream_return', 'grpc_api_code': 0, 'recv_eof': False,
                'wire_grpc_status': None, 'return_source': 'upstream_receive'},
        ]
        return target + neighbor

    def project(self, rows=None):
        return F.proxy_projection(rows or self.rows(),
            {'target': self.target, 'neighbor': self.neighbor})

    def test_proxy_projection_preserves_order_status_and_nonqualification(self):
        result = self.project()
        self.assertTrue(all(result['source_contract_checks'].values()))
        self.assertEqual(result['target']['upstream_receive_terminal']['grpc_api_code'], 14)
        self.assertEqual(result['neighbor']['upstream_receive_terminal']['grpc_api_code'], 0)
        self.assertFalse(result['host_lifecycle_qualified'])
        self.assertEqual(result['new_lifecycle_pass'], 0)

    def test_changed_message_is_rejected(self):
        rows = self.rows()
        rows[2]['message_sha256'] = '9' * 64
        with self.assertRaisesRegex(ValueError, 'forwarded_messages'):
            self.project(rows)

    def test_two_distinct_messages_forwarded_in_reversed_order_are_rejected(self):
        rows = self.rows()
        target, neighbor = rows[:11], rows[11:]
        receive = self.message(1, 0, self.target, 'downstream_receive', '9')
        send = self.message(1, 0, self.target, 'upstream_send', '9')
        target[1:3] = [target[1], receive, send, target[2]]
        for sequence, row in enumerate(target, 1):
            row['sequence'] = sequence
        with self.assertRaisesRegex(ValueError, 'forwarded_messages'):
            self.project(target + neighbor)

    def test_drop_order_nonempty_drop_and_invented_wire_status_are_rejected(self):
        for mutation in ('order', 'body', 'wire'):
            rows = self.rows()
            if mutation == 'order':
                rows[6]['event'], rows[7]['event'] = rows[7]['event'], rows[6]['event']
                rows[6].pop('direction')
                rows[6].update(close_send_error_nil=True, grpc_api_code=None, wire_grpc_status=None)
                rows[7] = self.message(1, 8, self.target, 'dropped_before_upstream_send', 'c',
                    message_bytes=6, message_type='*ext_procv3.ProcessingRequest_ResponseBody',
                    body_bytes=0, body_sha256=hashlib.sha256(b'').hexdigest(), eos=True)
            elif mutation == 'body':
                for row in rows[5:7]:
                    row.update(body_bytes=1, body_sha256=hashlib.sha256(b'x').hexdigest())
            else:
                rows[-1]['wire_grpc_status'] = 0
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.project(rows)

    def test_duplicate_terminal_and_stream_collision_are_rejected(self):
        rows = self.rows()
        duplicate = dict(rows[9], sequence=12)
        rows.insert(11, duplicate)
        for index, row in enumerate(rows[:12], 1):
            row['sequence'] = index
        with self.assertRaisesRegex(ValueError, 'one actual proxy terminal'):
            self.project(rows)
        rows = self.rows()
        for row in rows:
            if row['stream_id'] == 2:
                row['stream_id'] = 1
        with self.assertRaises(ValueError):
            self.project(rows)


class EnvoyStatusControls(unittest.TestCase):
    identity = 'e-1234'

    def log(self):
        tag = '[Tags: "ConnectionId":"7","StreamId":"99"]'
        prefix = '[time] [5] [debug] '
        return (prefix + tag + ' request headers complete (end_stream=false):\n'
            "':authority', 'example.test'\n"
            f"':path', '/{self.identity}'\n"
            f"'x-request-id', '{self.identity}'\n\n"
            + prefix + 'async http request response trailers:\n'
            "'grpc-status', '14'\n"
            "'grpc-message', 'bounded'\n\n"
            + prefix + 'gRPC stream closed remotely with status 14: bounded\n'
            + prefix + tag + ' Received gRPC error on stream: 14, message bounded\n'
            + prefix + tag + ' unrelated\n'
            + prefix + tag + ' Resetting stream due to '
            'ext_proc_error_gRPC_error_14{bounded}. Prior headers have already been sent\n').encode()

    def test_status_requires_tagged_request_callback_trailer_and_postcommit_reset(self):
        result = F.envoy_status_projection(self.log(), self.identity)
        self.assertEqual(result['grpc_status'], 14)
        self.assertEqual((result['connection_id'], result['stream_id']), (7, 99))
        self.assertFalse(result['successful_grpc_completion'])

    def test_untagged_wrong_stream_wrong_status_and_duplicate_request_are_rejected(self):
        base = self.log()
        mutations = [
            base.replace(b'Received gRPC error on stream: 14,', b'unrelated untagged trailer,'),
            base.replace(b'ConnectionId":"7","StreamId":"99"] Received',
                         b'ConnectionId":"8","StreamId":"99"] Received'),
            base.replace(b"'grpc-status', '14'", b"'grpc-status', '0'"),
            base + base.split(b'prefix async http', 1)[0],
            base.replace(b"'grpc-message', 'bounded'\n\n", b"'grpc-message', 'bounded'\nforeign\n"),
        ]
        for value in mutations:
            with self.subTest(value=value[-80:]), self.assertRaises(ValueError):
                F.envoy_status_projection(value, self.identity)


class ClientPrefixControls(unittest.TestCase):
    expected = b'a' * 64 + b'b' * 32

    def response(self, tail=b''):
        return (b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n40\r\n'
                + self.expected[:64] + b'\r\n20\r\n' + self.expected[64:] + b'\r\n' + tail)

    def test_complete_chunks_form_an_incomplete_exact_prefix(self):
        result = F.fault_client_projection(self.response(), self.expected)
        self.assertFalse(result['framing_complete'])
        self.assertFalse(result['terminal_zero_chunk_observed'])
        self.assertEqual(result['entity_prefix_bytes'], 96)
        self.assertEqual(result['complete_chunk_sizes'], [64, 32])

    def test_partial_malformed_changed_complete_and_trailing_variants_are_rejected(self):
        changed = bytearray(self.response())
        changed[-3] ^= 1
        variants = [self.response()[:-3], self.response().replace(b'20\r\n', b'20\n', 1),
                    bytes(changed), self.response(b'0\r\n\r\n'), self.response(b'garbage'),
                    self.response().replace(b'Transfer-Encoding: chunked',
                        b'Transfer-Encoding: chunked\r\nContent-Length: 96')]
        for value in variants:
            with self.subTest(length=len(value)), self.assertRaises(ValueError):
                F.fault_client_projection(value, self.expected)


class FixtureLedgerControls(unittest.TestCase):
    def proof(self, changed=None):
        payloads = {'shape.json': b'{"shape":true}', 'fault-contract.json': b'{"contract":true}'}
        files = {name: hashlib.sha256(value).hexdigest() for name, value in payloads.items()}
        ledger = json.dumps({'files': files}, sort_keys=True).encode()
        mapping = {'/approved/ledger.json': ledger,
                   '/approved/fixture/shape.json': payloads['shape.json'],
                   '/approved/fixture/fault-contract.json': payloads['fault-contract.json']}
        if changed is not None:
            mapping[changed[0]] = changed[1]
        binding = {'source': '/approved/fixture', 'ledger': '/approved/ledger.json',
                   'ledger_sha256': hashlib.sha256(ledger).hexdigest()}
        with patch.object(F.E, 'read_bytes', side_effect=lambda path: mapping[str(path)]):
            return F.sealed_fixture_files(binding, tuple(payloads))

    def test_each_selected_fixture_file_is_bound_to_the_admission_ledger(self):
        ledger, references, payloads, count = self.proof()
        self.assertEqual(count, 2)
        self.assertEqual(ledger['sha256'], hashlib.sha256(json.dumps({'files': {
            name: hashlib.sha256(value).hexdigest() for name, value in payloads.items()}},
            sort_keys=True).encode()).hexdigest())
        self.assertEqual(set(references), set(payloads))

    def test_changed_selected_file_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'differs from sealed fixture ledger'):
            self.proof(('/approved/fixture/shape.json', b'changed'))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
