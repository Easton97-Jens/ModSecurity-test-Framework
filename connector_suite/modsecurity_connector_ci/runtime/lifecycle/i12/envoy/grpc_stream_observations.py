"""Maintained HTTP/2 stream-close extraction with unique method construction."""
import re

import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.host_log_observations as authorization_host_logs

STAMP = authorization_host_logs.STAMP
TAGS = authorization_host_logs.TAGS
interval = authorization_host_logs.interval
extract = authorization_host_logs.extract
CODEC = 'http2/codec_impl.cc:'
ROUTER = 'router.cc:'
PROCESS_METHOD = "match for URL '/envoy.service.ext_proc.v3.ExternalProcessor/Process'"
AUTHORIZATION_METHOD = "match for URL '/envoy.service.auth.v3.Authorization/Check'"
PAYLOAD = re.compile(r'Http2Visitor: remaining data payload: \d+, stream_id: (\d+), end_stream: (true|false)')
UNARY_PAYLOAD = re.compile(r'Http2Visitor: remaining data payload: \d+, stream_id: (\d+),')


def unknown(reason):
    return {'verified': False, 'reason': reason, 'actual_stream_close': None}


def request_records(lines, start, end):
    result = []
    for index in range(start, end):
        stamp = STAMP.match(lines[index])
        if stamp:
            result.append({'original_line': index + 1, 'text': lines[index],
                           'tags': authorization_host_logs.tags(lines[index]),
                           'clock_interval': interval(stamp.group(1))})
    return result


def payload_rows(records, first_line, pattern=PAYLOAD, source=CODEC):
    result = []
    for row in records:
        match = pattern.search(row['text'])
        if match and row['original_line'] > first_line and source in row['text']:
            result.append((row['tags'].get('ConnectionId'), match.group(1), row))
    return result


def process_identity(records, target):
    openings = [row for row in records if row['tags'] == target and 'ext_proc.cc:' in row['text']
                and 'Opening gRPC stream to external processor' in row['text']]
    methods = [row for row in records if ROUTER in row['text'] and PROCESS_METHOD in row['text']]
    if (len(openings) != 1 or len(methods) != 1
            or methods[0]['original_line'] <= openings[0]['original_line']):
        return None
    return openings[0], methods[0]


def process_closure(records, method, payload, connection, stream):
    last_payload = payload[-1][2]['original_line']
    resets = [row for row in records if row['tags'] == method['tags']
              and 'upstream_request.cc:' in row['text'] and 'resetting pool request' in row['text']
              and row['original_line'] > last_payload]
    closes = [row for row in records if row['tags'].get('ConnectionId') == connection
              and CODEC in row['text'] and row['original_line'] > last_payload
              and re.search(r' stream ' + re.escape(stream) + r' closed: \d+$', row['text'])]
    if (len(resets) != 1 or len(closes) != 1
            or resets[0]['original_line'] >= closes[0]['original_line']):
        return 'missing or ambiguous actual request reset/HTTP2 onStreamClose'
    close = closes[0]
    sent = [row for row in records if row['tags'].get('ConnectionId') == connection
            and CODEC in row['text'] and 'sent reset code=' in row['text']
            and resets[0]['original_line'] < row['original_line'] < close['original_line']]
    if len(sent) != 1:
        return 'missing or ambiguous actual sent-reset callback'
    return resets[0], sent[0], close


def unary_completion(records, lines, opening, process_method):
    methods = [row for row in records if ROUTER in row['text'] and AUTHORIZATION_METHOD in row['text']
               and row['original_line'] < opening['original_line']]
    if len(methods) != 1:
        return None
    method = methods[0]
    selected = [row for row in records
                if method['original_line'] < row['original_line'] < opening['original_line']]
    payload = payload_rows(selected, method['original_line'], UNARY_PAYLOAD, source='')
    keys = {(connection, stream) for connection, stream, _ in payload}
    if len(keys) != 1:
        return None
    connection, stream = next(iter(keys))
    closes = [row for row in records
              if method['original_line'] < row['original_line'] < process_method['original_line']
              and row['tags'].get('ConnectionId') == connection
              and re.search(r' stream ' + re.escape(stream) + r' closed: 0$', row['text'])]
    trailers = [{'original_line': index + 1, 'text': lines[index]}
                for index in range(method['original_line'], opening['original_line'] - 1)
                if lines[index] == "'grpc-status', '0'"]
    if len(closes) != 1 or len(trailers) != 1:
        return None
    return {'method': method, 'http2_connection': connection, 'http2_stream': stream,
            'actual_success_trailer': trailers[0], 'actual_stream_close': closes[0]}


def observe(raw, path):
    host = extract(raw, path)
    if not host['scope_verified']:
        return unknown('unknown downstream nonce stream')
    lines = raw.splitlines()
    start = host['decoded_nonce_original_line'] - 1
    end = next((index for index in range(start + 1, len(lines))
                if 'request headers complete (end_stream=' in lines[index]
                and 'conn_manager_impl.cc:' in lines[index]), len(lines))
    records = request_records(lines, start, end)
    identity = process_identity(records, host['actual_host_stream_tags'])
    if identity is None:
        return unknown('missing or ambiguous actual gRPC Process construction')
    opening, method = identity
    payload = payload_rows(records, method['original_line'])
    keys = {(connection, stream) for connection, stream, _ in payload}
    if len(keys) != 1 or not payload:
        return unknown('missing or ambiguous actual HTTP2 connection/stream')
    connection, stream = next(iter(keys))
    closure = process_closure(records, method, payload, connection, stream)
    if isinstance(closure, str):
        return unknown(closure)
    reset, sent, close = closure
    return {'verified': True, 'downstream_actual_tags': host['actual_host_stream_tags'],
            'opening': opening, 'actual_method_construction': method,
            'actual_http2_connection': connection, 'actual_http2_stream': stream,
            'actual_received_payload_callbacks': [row for _, _, row in payload],
            'actual_pool_request_reset': reset, 'actual_sent_reset_callback': sent,
            'actual_stream_close': close,
            'numeric_actual_close_code': int(close['text'].rsplit(': ', 1)[1]),
            'unary_authorization_grpc_end': unary_completion(records, lines, opening, method),
            'scope_contract': 'one selected request then separately waited neighbor; unique actual method construction and HTTP2 payload stream in that request interval, own async request reset and codec onStreamClose. No ID equality runtime join. Actual local reset closure; no remote grpc-status/EOF inferred.'}
