"""Keep observed local closure separate from successful remote gRPC status."""
import argparse
import json
import re
from pathlib import Path
import sys

import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.evidence_io as evidence_io
import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.grpc_stream_observations as grpc_stream_observations
import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.host_log_observations as host_log_observations

HERE = Path(__file__).resolve().parent

import modsecurity_connector_ci.lib.i12_path_safety as paths

PARSER_NAMES = ('grpc_stream_observations.py', 'host_log_observations.py')


def historical_helper_hashes(helpers):
    """Authenticate retained source identities as data, never as import roots."""
    if helpers is None:
        return {}
    manifest = evidence_io.read_json(HERE.parent / 'manifest.json')
    expected = manifest['profiles']['envoy']['capture_files']
    hashes = {}
    for name in PARSER_NAMES:
        actual = evidence_io.reference(helpers / name)['sha256']
        if actual != expected[name]['sha256']:
            raise ValueError('unreviewed transport helper: ' + name)
        hashes[name] = actual
    return hashes


def current_parser_hashes():
    """Bind current analysis code separately from retained capture provenance."""
    return {name: evidence_io.reference(HERE / name)['sha256'] for name in PARSER_NAMES}


def authorization_records(lines, start, end, host_logs):
    records = []
    for i in range(start, end):
        if not host_logs.STAMP.match(lines[i]):
            continue
        tag = host_logs.TAGS.search(lines[i])
        try:
            tags = json.loads('{' + tag.group(1) + '}') if tag else {}
        except json.JSONDecodeError:
            return None
        records.append({'original_line': i + 1, 'text': lines[i], 'tags': tags})
    return records


def authorization_payload(rows):
    payload = []
    for row in rows:
        match = re.search(r'Http2Visitor: remaining data payload: [1-9]\d*, stream_id: (\d+), end_stream: false', row['text'])
        if match and 'http2/codec_impl.cc:' in row['text']:
            payload.append((row['tags'].get('ConnectionId'), match.group(1), row))
    return payload


def authorization_trailers(rows, method, lines, boundary, host_logs):
    trailers = []
    for row in rows:
        if 'async_client_impl.cc:' not in row['text'] or not row['text'].endswith('async http request response trailers:'):
            continue
        if row['tags'] != method['tags']:
            return None
        i = row['original_line']
        block = []
        while i < boundary - 1 and not host_logs.STAMP.match(lines[i]):
            block.append(lines[i])
            i += 1
        statuses = [line for line in block if line.startswith("'grpc-status',")]
        if statuses != ["'grpc-status', '0'"]:
            return None
        trailers.append({'original_line': row['original_line'] + 1, 'text': statuses[0]})
    return trailers


def authorization_method_rows(records, end):
    methods = [r for r in records if 'router.cc:' in r['text'] and
               "match for URL '/envoy.service.auth.v3.Authorization/Check'" in r['text']]
    if len(methods) != 1 or not all(methods[0]['tags'].get(k) for k in ('ConnectionId', 'StreamId')):
        return None
    method = methods[0]
    # Stop at the next asynchronous method construction, before Process traffic.
    boundary = next((r['original_line'] for r in records
                     if r['original_line'] > method['original_line'] and
                     r['tags'].get('ConnectionId') == method['tags']['ConnectionId'] and
                     'router.cc:' in r['text'] and 'match for URL ' in r['text']), end + 1)
    rows = [r for r in records if method['original_line'] < r['original_line'] < boundary]
    return method, rows, boundary


def authorization_observation(raw, path, host_logs):
    """Bind one unary completion independently of the companion Process stream."""
    unknown = {'verified': False}
    host = host_logs.extract(raw, path)
    if not host.get('scope_verified'):
        return unknown
    lines = raw.splitlines()
    start = host['decoded_nonce_original_line'] - 1
    end = next((i for i in range(start + 1, len(lines))
                if 'request headers complete (end_stream=' in lines[i]
                and 'conn_manager_impl.cc:' in lines[i]), len(lines))
    records = authorization_records(lines, start, end, host_logs)
    if records is None:
        return unknown
    method_rows = authorization_method_rows(records, end)
    if method_rows is None:
        return unknown
    method, rows, boundary = method_rows
    payload = authorization_payload(rows)
    keys = {(c, s) for c, s, _ in payload}
    if len(keys) != 1 or not payload:
        return unknown
    connection, stream = next(iter(keys))
    if not connection:
        return unknown
    trailers = authorization_trailers(rows, method, lines, boundary, host_logs)
    if trailers is None:
        return unknown
    closes = [r for r in rows if r['tags'].get('ConnectionId') == connection
              and 'http2/codec_impl.cc:' in r['text']
              and re.search(r' stream ' + re.escape(stream) + r' closed: \d+$', r['text'])]
    if (len(trailers) != 1 or len(closes) != 1
            or not closes[0]['text'].endswith(' closed: 0')
            or not payload[-1][2]['original_line'] < trailers[0]['original_line'] < closes[0]['original_line']):
        return unknown
    return {'verified': True, 'method': method, 'http2_connection': connection,
            'http2_stream': stream, 'actual_success_trailer': trailers[0],
            'actual_stream_close': closes[0], 'downstream_actual_tags': host['actual_host_stream_tags']}


def terminal(observation, unary=None):
    """Classify the existing capture's explicit facts without filling unknowns."""
    process = {
        'method': 'ExternalProcessor/Process',
        'scope_verified': observation.get('verified') is True,
        'local_http2_close_code': observation.get('numeric_actual_close_code'),
        'remote_grpc_status': None,
        'successful_grpc_completion': False,
        'classification': 'unknown',
    }
    if (process['scope_verified'] and observation.get('actual_pool_request_reset')
            and observation.get('actual_sent_reset_callback')
            and observation.get('actual_stream_close')):
        process['classification'] = 'observed_local_reset'
    authorization = {'method': 'Authorization/Check', 'remote_grpc_status': None,
                     'successful_grpc_completion': False, 'classification': 'unknown'}
    if unary and unary.get('verified') is True:
        trailer = unary.get('actual_success_trailer', {}).get('text')
        close = unary.get('actual_stream_close', {}).get('text', '')
        if trailer == "'grpc-status', '0'" and close.endswith(' closed: 0'):
            authorization.update(remote_grpc_status=0, successful_grpc_completion=True,
                                 classification='explicit_remote_status_and_close')
    return {'process': process, 'authorization': authorization,
            'source_observation': observation, 'host_lifecycle_qualified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--helpers', type=Path, required=True)
    parser.add_argument('--raw', type=Path, required=True)
    parser.add_argument('--path', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    hashes = historical_helper_hashes(args.helpers)
    raw = evidence_io.read_bytes(args.raw).decode('utf-8')
    result = terminal(grpc_stream_observations.observe(raw, args.path),
                      authorization_observation(raw, args.path, host_log_observations))
    result['helper_sha256'] = hashes
    result['current_parser_sha256'] = current_parser_hashes()
    with paths.new_text(args.output) as output:
        json.dump(result, output, indent=2)
        output.write('\n')


if __name__ == '__main__':
    main()
