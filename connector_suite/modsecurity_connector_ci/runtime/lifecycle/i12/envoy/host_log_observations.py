"""Maintained extraction of actual Envoy logger rows, without oracle inference."""
import datetime
import json
import re

STAMP = re.compile(r'^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}(?:[+-]\d{2}:?\d{2}|Z))\]')
# Whitespace belongs to the JSON fragment. A tag cannot consume the start of
# another tag, so repeated unterminated prefixes cannot rescan the same suffix.
TAGS = re.compile(r'\[Tags:([^\[\]\r\n]*)\]')
CONNECTION_MANAGER = 'conn_manager_impl.cc:'
EXTERNAL_PROCESSOR = 'ext_proc.cc:'


def interval(stamp):
    value = datetime.datetime.fromisoformat(stamp)
    if value.tzinfo is None:
        return None
    delta = value - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    nanoseconds = (delta.days * 86400 + delta.seconds) * 1000000000 + delta.microseconds * 1000
    return {'lower_wall_ns': nanoseconds, 'upper_exclusive_wall_ns': nanoseconds + 1000000,
            'quantization_ns': 1000000}


def tags(line):
    match = TAGS.search(line)
    try:
        return json.loads('{' + match.group(1) + '}') if match else {}
    except json.JSONDecodeError:
        return {}


def blocks(raw):
    result = []
    for number, line in enumerate(raw.splitlines(), 1):
        stamp = STAMP.match(line)
        if stamp:
            scope = tags(line)
            result.append({'line': number, 'text': line,
                           'scope': (scope.get('ConnectionId'), scope.get('StreamId')),
                           'clock': interval(stamp.group(1))})
        elif result:
            result[-1]['text'] += '\n' + line
    return result


def decoded_request(block, path):
    text = block['text']
    return (CONNECTION_MANAGER in text and 'request headers complete (end_stream=' in text
            and ':path' in text and (repr(path) in text or json.dumps(path) in text)
            and all(block['scope']))


def event_rows(selected, marker, source):
    return [{'original_line': block['line'], 'clock_interval': block['clock'],
             'original_first_line': block['text'].splitlines()[0]}
            for block in selected if marker in block['text'] and source in block['text']]


def extract(raw, path):
    parsed = blocks(raw)
    matches = [block for block in parsed if decoded_request(block, path)]
    scopes = {block['scope'] for block in matches}
    if len(scopes) != 1 or len(matches) != 1:
        return {'scope_verified': False, 'reason': 'missing_or_ambiguous_actual_decoded_nonce',
                'codec_headers': [], 'codec_body': [], 'grpc_remote_close': [], 'filter_destroy': []}
    scope = next(iter(scopes))
    selected = [block for block in parsed if block['scope'] == scope]
    return {'scope_verified': True,
            'actual_host_stream_tags': {'ConnectionId': scope[0], 'StreamId': scope[1]},
            'decoded_nonce_original_line': matches[0]['line'],
            'codec_headers': event_rows(selected, 'encoding headers via codec (end_stream=', CONNECTION_MANAGER),
            'codec_body': event_rows(selected, 'encoding data via codec (size=', CONNECTION_MANAGER),
            'grpc_remote_close': event_rows(selected, 'Received gRPC stream close', EXTERNAL_PROCESSOR),
            'grpc_close_attempt': event_rows(selected, 'Calling close on stream', EXTERNAL_PROCESSOR),
            'filter_destroy': event_rows(selected, 'onDestroy', EXTERNAL_PROCESSOR),
            'claim': 'actual existing host callbacks only; no kernel send/allocator free/status/commit inferred from protocol send'}
