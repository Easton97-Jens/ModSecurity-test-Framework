"""Publish a clearly labeled projection while retaining the physical source hash."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import argparse
import copy
import hashlib
import json
from pathlib import Path


def project(source_bytes, original_reference):
    """Rename a noncredential process join field; never rewrite physical evidence."""
    original = json.loads(source_bytes)
    result = copy.deepcopy(original)
    renamed = []
    groups = [result['positive_control'], *result['faults']]
    for group_index, group in enumerate(groups):
        for client_index, client in enumerate(group['clients']):
            process = client['actual_process']
            old_key = 'client_token'
            correlation = process.pop(old_key)
            if not isinstance(correlation, str) or not correlation.isdecimal():
                raise ValueError('Expected the timestamp-derived process correlation identifier')
            process['client_process_correlation_id'] = correlation
            renamed.append({'group_index': group_index, 'client_index': client_index,
                            'old_field': old_key, 'new_field': 'client_process_correlation_id'})
    result['public_projection'] = {
        'schema': 'apache-i12-public-readback-v1', 'is_physical_capture': False,
        'source_sha256': hashlib.sha256(source_bytes).hexdigest(),
        'source_reference': original_reference, 'renamed_fields': renamed,
        'reason': 'Numeric timestamp joins identify test client processes and carry no authentication authority. '
                  'The public name expresses that meaning. Physical originals and referenced hashes remain unchanged.'}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--original-reference', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    paths = load_tool('ci/runtime/lifecycle/apache-i12/paths.py')
    source = paths.input_path(args.source).read_bytes()
    output = paths.new_output(args.output)
    with output.open('x') as stream:
        json.dump(project(source, args.original_reference), stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    main()
