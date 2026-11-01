"""Parse effective host YAML before starting the real host; no qualification."""
import json
from pathlib import Path
import sys
import re
import os
import stat
from urllib.parse import urlsplit



RUN_ID = 'traefik-acceptance-20261015'
LITERAL_CASE_ID = r'[A-Za-z0-9_.:-]{1,128}'
RESERVATION = 'X-Msconnector-Trusted-Reservation'
HANDLE = 'X-Msconnector-Response-Handle'
PROVENANCE_SOCKET_CONTRACT = {'socket_mode': 0o600, 'parent_mode': 0o700,
    'socket_uid': 65534, 'socket_gid': 65534, 'parent_uid': 65534, 'parent_gid': 65534,
    'parent_lstat_directory_required': True, 'parent_symlink_forbidden': True}
HOST_BOUNDARY_CASES = frozenset(('NEED-complete-sample', 'NEED-incomplete-sample',
    'NEED-host-request-buffer-bound', 'NEED-host-auth-response-32768-bound',
    'NEED-32768-auth-response-not-application-response', 'NEED-request-above-former-connector-limit'))


def provenance_mode(case):
    # Built-in ForwardAuth rejection must be measured without an outer writer
    # requiring service attestation. Otherwise a host401 can become observer503.
    # Handle lookup/expiry controls likewise retain ordinary MRC1 semantics.
    physical = case['fixture'].get('physical_file_supplement', {})
    return (case['case_id'] not in HOST_BOUNDARY_CASES and
            not physical.get('host_capacity_control', False) and
            not bool(case['fixture'].get('relay', {}).get('handle')))


def read_case_input(path, expected_name, case_root):
    """Read only one owned regular file below the exact private case root."""
    path = Path(path)
    case_root = Path(case_root)
    if (not path.is_absolute() or '..' in path.parts or
            path.resolve(strict=True) != path or
            case_root.resolve(strict=True) != case_root or
            not path.is_relative_to(case_root) or path.name != expected_name):
        raise ValueError('exact canonical private case input required')
    state = case_root.stat()
    if (not stat.S_ISDIR(state.st_mode) or state.st_uid != os.geteuid() or
            state.st_mode & 0o077):
        raise ValueError('private owned case directory required')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        state = os.fstat(descriptor)
        if (not stat.S_ISREG(state.st_mode) or state.st_uid != os.geteuid() or
                state.st_mode & 0o022 or state.st_size > 16 * 1024 * 1024):
            raise ValueError('bounded owned regular case input required')
        with os.fdopen(descriptor, 'r', closefd=False) as stream:
            return stream.read()
    finally:
        os.close(descriptor)


def physical_backend_port(server):
    """The isolated fixture supports only a literal loopback HTTP endpoint."""
    parsed = urlsplit(server.get('url', ''))
    if (parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or
            parsed.username is not None or parsed.password is not None or
            parsed.path or parsed.query or parsed.fragment or
            not re.fullmatch(r'127\.0\.0\.1:\d{1,5}', parsed.netloc, re.ASCII)):
        raise ValueError('one literal loopback physical file backend required')
    port = parsed.port
    if port is None or not 1 <= port <= 65535:
        raise ValueError('separate bounded physical file backend port required')
    return port


def validate_file_router(config, routers, case):
    physical = case['fixture'].get('physical_file_supplement') if case else None
    if not physical or physical.get('direction') != 'response':
        if 'physical-file-target' in routers or 'physical-file-backend' in config['services']:
            raise ValueError('file target router requires an explicit response-file binding')
        return
    key = case['probe_id']
    if not re.fullmatch(LITERAL_CASE_ID, key):
        raise ValueError('literal physical file target key required')
    target = routers.get('physical-file-target', {})
    expected_rule = 'Header(`X-I12-Probe`, `' + key + '`) && !Header(`X-I12-Neighbor`, `1`)'
    if (target.get('rule') != expected_rule or target.get('priority') != 200 or
            target.get('entryPoints') != ['web'] or target.get('service') != 'physical-file-backend' or
            target.get('middlewares') != routers['smoke']['middlewares']):
        raise ValueError('exclusive physical file target router required')
    servers = config['services'].get('physical-file-backend', {}).get('loadBalancer', {}).get('servers', [])
    if len(servers) != 1:
        raise ValueError('one literal loopback physical file backend required')
    file_port = physical_backend_port(servers[0])
    if not 1 <= file_port <= 65535 or servers == config['services']['upstream']['loadBalancer']['servers']:
        raise ValueError('separate bounded physical file backend port required')


def validate_observers(path, case, mode, routers, middlewares):
    for name, observer in [('smoke', 'modsecurity-response-observer'),
                           ('healthy-neighbor', 'healthy-response-observer')]:
        validate_observer(path, case, mode, routers, middlewares, name, observer)


def validate_provenance_settings(middlewares, observer, outer, expected_outer, name):
    if outer != expected_outer or not re.fullmatch(LITERAL_CASE_ID, outer['transportCaseID']):
        raise ValueError('atomic outer provenance settings differ: ' + name)
    inner = middlewares[observer + '-confirm']['plugin']['modsecurityResponseObserver']
    if inner != {'socketPath': expected_outer['socketPath'], 'confirmProvenance': True, 'timeoutMillis': expected_outer['timeoutMillis']}:
        raise ValueError('atomic inner provenance settings differ: ' + name)


def validate_observer(path, case, mode, routers, middlewares, name, observer):
    fault = bool(name == 'smoke' and case and case['fixture'].get('relay', {}).get('companion_fault'))
    expected = [observer, 'modsecurity-forwardauth', observer + '-confirm'] if mode else ['modsecurity-forwardauth', observer]
    if routers[name]['middlewares'] != expected:
        raise ValueError('ordered host middleware contract differs: ' + name)
    outer = middlewares[observer]['plugin']['modsecurityResponseObserver']
    socket_root = path.parent.parent.parent / 'sockets'
    companion = socket_root / ('observer.sock' if fault else 'companion.sock')
    if outer.get('socketPath') != str(companion):
        raise ValueError('wrong companion socket: ' + name)
    if mode:
        expected_outer = {'socketPath': str(companion), 'provenanceSocketPath': str(socket_root / 'provenance.sock'),
                          'runID': RUN_ID, 'transportCaseID': case['id'] if case else outer.get('transportCaseID'),
                          'timeoutMillis': 1000 if fault else 5000}
        validate_provenance_settings(middlewares, observer, outer, expected_outer, name)
    elif any(key in outer for key in ('provenanceSocketPath', 'runID', 'transportCaseID', 'confirmProvenance')):
        raise ValueError('default MRC1 control must not enable provenance')


def validate(path, case=None):
    import yaml
    if path.parts[-3:] != ('runtime', 'effective-config', 'traefik-dynamic.yaml'):
        raise ValueError('exact generated dynamic configuration path required')
    config = yaml.safe_load(read_case_input(path, 'traefik-dynamic.yaml', path.parent.parent.parent))['http']
    middlewares = config['middlewares']
    auth = middlewares['modsecurity-forwardauth']['forwardAuth']
    required = {'preserveRequestMethod': True, 'trustForwardHeader': False,
                'forwardBody': True, 'maxBodySize': 4096,
                'maxResponseBodySize': 32768}
    for key, value in required.items():
        if type(auth.get(key)) is not type(value) or auth[key] != value:
            raise ValueError('effective host contract differs: ' + key)
    routers = config['routers']
    validate_file_router(config, routers, case)
    mode = provenance_mode(case) if case is not None else any(
        'provenanceSocketPath' in value.get('plugin', {}).get('modsecurityResponseObserver', {})
        for value in middlewares.values())
    validate_observers(path, case, mode, routers, middlewares)
    request_names = [name.lower() for name in auth['authRequestHeaders']]
    if HANDLE.lower() in request_names:
        raise ValueError('response handle forbidden in authorization request headers')
    if request_names.count(RESERVATION.lower()) != int(mode):
        raise ValueError('reservation forwarding contract differs')
    if auth['authResponseHeaders'] != [HANDLE]:
        raise ValueError('response handle forwarding contract differs')
    return {'parsed_by': yaml.__file__, 'yaml_version': yaml.__version__,
            'effective_auth_contract': required, 'routers': list(routers),
            'observer_mode': 'trusted-provenance' if mode else 'default-mrc1',
            'qualification': None}


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise ValueError('exact config and admitted case arguments required')
    requested_config = Path(sys.argv[1])
    probe = requested_config.parent.parent.parent.name
    if not re.fullmatch(LITERAL_CASE_ID, probe):
        raise ValueError('fixed runtime case root required')
    root = Path('/task/cases') / probe
    config_path = root / 'runtime/effective-config/traefik-dynamic.yaml'
    if requested_config != config_path:
        raise ValueError('fixed runtime configuration path required')
    case_path = root / 'case.json'
    if Path(sys.argv[2]) != case_path:
        raise ValueError('exact admitted case receipt required')
    case = json.loads(read_case_input(case_path, 'case.json', root))
    if case.get('probe_id') != root.name:
        raise ValueError('case receipt identity differs')
    print(json.dumps(validate(config_path, case)))
