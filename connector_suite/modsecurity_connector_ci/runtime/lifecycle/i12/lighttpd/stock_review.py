#!/usr/bin/env python3
"""Hash physical stock supplements and map their limited scope to original IDs."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

# Load the maintained Parent filesystem boundary from this checkout.
import sys as _i12_sys

import modsecurity_connector_ci.lib.i12_path_safety as i12_paths


def binding(path):
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'bytes': path.stat().st_size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-root', required=True, type=Path)
    parser.add_argument('--inherited', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    checkout = args.inherited.resolve().parents[3]
    head = subprocess.run(['rtk', 'proxy', 'git', '-C', str(checkout), 'rev-parse', 'HEAD'],
                          check=True, capture_output=True, text=True).stdout.strip()
    stock = args.run_root / 'stock'
    nonroot = args.run_root / 'isolation/attempt-1792072435775631502'
    controller = json.loads((nonroot / 'controller-result.json').read_text())
    captures = []
    for root, uid, action in (
        (stock / 'capture-04', 0, 'Reject'),
        (stock / 'capture-05-partial', 0, 'ProcessPartial'),
        (nonroot / 'data/capture', 65534, 'Reject'),
        (nonroot / 'data/partial', 65534, 'ProcessPartial')):
        for profile in ('off', 'safe', 'strict', 'all'):
            folder = root / profile
            row = json.loads((folder / 'observations.json').read_text())
            captures.append({'uid': uid, 'profile': profile, 'native_limit_action': action,
                'execution_status': row['execution_status'], 'observation': binding(folder / 'observations.json'),
                'physical_files': [binding(p) for p in folder.iterdir() if p.is_file()],
                'backend': binding(root / 'backend.jsonl'), 'host_access': binding(root / 'host-access.log'),
                'host_cleanup': binding(root / 'host-cleanup.json'),
                'backend_cleanup': binding(root / 'backend-cleanup.json'),
                'full_lifecycle_qualified': False})
    related = {
        'request-empty': 'Fresh empty POST; inherited exact oracle remains separate.',
        'request-single-chunk': 'Small POST reached native observer; not the original selected fixture.',
        'request-file': 'Actual unlinked private request spool FD observed, not native file-body API coverage.',
        'request-streaming': 'Held 3000-byte upload; actual append records and zero backend before completion.',
        'request-content-type-present': 'Explicit text/plain and multipart/form-data requests.',
        'request-charset-missing': 'Explicit text/plain without charset; no charset-present fixture.',
        'request-eos-once': 'Physical host/native EOS and finish/free captured; selected-ID verifier not rerun.',
        'response-empty': 'Real backend Content-Length0 response and physical native finalization captured.',
        'response-single-chunk': 'Small real backend text/plain response; selected fixture differs.',
        'response-streaming': '5000-byte backend response spans body chunks; Reject/ProcessPartial observed.',
        'response-charset-missing': 'Backend text/plain without charset; MIME-in and octet-stream-out captured.',
        'response-marker-at-payload-end': 'Response marker is the complete15-byte response; original large-tail fixture not executed.',
        'abort-reset-observation': 'Immediate RST/control and strict P4 host action have separate physical records.',
        'first-byte-before-late-error': 'Committed200 and physical P4 action captured; no client timestamp for exact first-byte ordering.',
        'neighbor-connection-stream': 'Separate healthy HTTP/1.1 neighbor after RST and P4/limit requests.',
        'private-spool-ready': 'Actual host/sidecar readiness; spool0700 and bounded held request.',
        'nonroot-uid': 'Trusted unchanged controller admitted actual65534 with zero capabilities; no control weakening.',
        'spool-ownership-0600-private0700': 'Live /proc native FD stat: unlinked nlink0 file0600 in private0700 directory.',
        'readmission-after-release': 'Sequential requests and final neighbor healthy; capacity-contention readmission remains separate.',
        'replay-only-after-native-p2-allow': 'Independent backend count0 while body incomplete; backend bytes after completed held upload.',
        'rst-disconnect': 'Fresh immediate reset has no predetermined event count; original failure separate.',
    }
    for profile in ('all', 'off', 'safe', 'strict'):
        related['profile-' + profile] = 'Delivered exact profile template relocated only for rules/event paths; root/nonroot and both limit actions.'
    not_executed = {
        'request-content-type-missing': 'Every new request deliberately has Content-Type; absent-header fixture not run.',
        'request-charset-present': 'No explicit request charset fixture.',
        'request-mime-scope-in': 'Request MIME processor behavior is not equivalent to response MIME scope.',
        'request-mime-scope-out': 'No independent request MIME-out oracle.',
        'request-csv': 'No request CSV fixture.',
        'request-above-former-connector-limit': 'Largest new body4097; no former-cap crossing fixture.',
        'request-marker-at-payload-end': 'P2 marker exists, but original tail placement fixture not executed.',
        'response-file': 'Backend socket entity route; no response-file/zero-copy claim.',
        'response-csv': 'No response CSV fixture.',
        'response-above-former-connector-limit': 'Largest response5000; no former-cap crossing fixture.',
        'invalid-native-return': 'No native return fault injection in this real-host supplement.',
        'missing-eos': 'No missing-EOS malformed-host injection.',
        'invalid-metadata': 'No invalid-metadata host fixture.',
        'physical-event-sink-open': 'Real event files observed; no sink-open failure injected here.',
        'physical-event-sink-write': 'No sink-write failure injection here.',
        'physical-event-sink-short-write': 'No sink-short-write failure injection here.',
        'physical-event-sink-flush': 'No sink-flush failure injection here.',
        'physical-event-sink-close': 'No sink-close failure injection here.',
        'timeout': 'No host timeout fault fixture in this supplement.',
        'cancel': 'Immediate RST is distinct from an independently specified cancel fixture.',
        'client-exit-signal': 'Python socket client is in the waited controller driver, not an independent signal-exit client.',
        'incomplete-framing': 'Held request completes; malformed finite-framing fixture not run.',
        'capacity-256m-reserve64m': 'Supplement explicitly uses smaller65536-byte capacity and1048576-byte reserve; default contract not inferred.',
        'resource-exhaustion-technical': 'No shared-capacity/free-reserve exhaustion in this host supplement; separate component regression required.',
    }
    inherited = json.loads(args.inherited.read_text())
    rows = []
    for item in inherited['rows']:
        selected = item['run_scoped_case_id']
        name = selected.split('::')[-1]
        if name == 'FU-STOCK-RST-DELIVERY':
            relation = 'historical_failure_reproduced'
            reason = 'Unchanged original immediate-RST test and product snapshot5e3b9586 failed with empty physical event file; exact Sept19 head unavailable.'
        elif name == 'HIST-STOCK06-ACTUAL-ACTION-ENUM':
            relation = 'historical_preserved'
            reason = 'Fresh enum values do not rewrite the source-bound historical Stock06 record.'
        else:
            key = name.removeprefix('NEED-')
            if key in related:
                relation, reason = 'related_supplement_not_original_fixture', related[key]
            else:
                relation, reason = 'not_executed_by_supplement', not_executed[key]
        rows.append({'run_scoped_case_id': selected, 'inherited_category': item['category'],
            'inherited_resolved': item['resolved'], 'new_relation': relation,
            'reason': reason, 'effective_oracle_changes': None, 'qualification_changes': None})
    assert len(rows) == 51
    document = {'schema': 'lighttpd-stock-i12-supplement-review-v1',
        'capture_contract_seed_sha': '8cc32dceb06121f589150a9794f28878c5e4ba2a',
        'actual_checkout_head_sha_at_review': head,
        'seed_is_not_checkout_revision': True,
        'inherited_oracles': binding(args.inherited), 'reviewed_original_oracles': rows,
        'captures': captures, 'controller': binding(nonroot / 'controller-result.json'),
        'controller_cleanup': {k: controller[k] for k in ('exitcode', 'controller_exitcode', 'errors',
            'resource_violation', 'surviving_namespace_pids', 'outside_mount_leaks', 'peak_aggregate_rss_bytes')},
        'source_build_bindings': [binding(stock / name / 'build-binding.json') for name in ('capture-04', 'capture-05-partial')],
        'nonroot_provenance': binding(stock / 'nonroot-input/provenance.json'),
        'nonroot_spec': binding(stock / 'nonroot-v2/admission-spec.json'),
        'historical_reproduction': binding(stock / 'historical-rst/receipt.json'),
        'historical_log': binding(stock / 'historical-rst/unittest.log'),
        'new_full_lifecycle_passes': 0, 'inherited_statuses_changed': False,
        'original_null_oracles_preserved': True,
        'limits': ['No oracle is derived from the same observed client status.',
                  'Capture has native/host/backend logs; selected-ID independent complete verifier remains outstanding.',
                  'Full response bytes may already be visible before strict P4 connection close; physical action is not an alternate HTTP status.',
                  'Shared-capacity/free-reserve/sink fault regressions are separate evidence.']}
    i12_paths.create_text(args.output, json.dumps(document, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
