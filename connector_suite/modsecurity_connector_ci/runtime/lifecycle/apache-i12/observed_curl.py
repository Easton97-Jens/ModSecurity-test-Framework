#!/usr/local/bin/python3
"""Observe one admitted loopback client and a separate healthy request."""
import json
import os
from pathlib import Path
import subprocess
import string
import sys
import time
from urllib.parse import urlsplit, urlunsplit


def private_output(value):
    path = Path(value)
    roots = (Path('/task'), Path(os.environ['I12_APACHE_PRIVATE_RUNTIME']))
    if not path.is_absolute() or path.resolve() != path or not any(path.is_relative_to(root) for root in roots):
        raise ValueError('Client file must stay in the admitted private runtime')
    return str(path)


def checked_endpoint(value):
    # urlsplit strips some control characters. Reject them before parsing so
    # admission applies to the literal URL that will reach the native client.
    if any(character.isspace() or ord(character) < 32 or ord(character) == 127
           for character in value):
        raise ValueError('Whitespace and controls are not admitted in a client URL')
    url = urlsplit(value)
    if (url.scheme != 'http' or url.hostname != '127.0.0.1'
            or url.username is not None or url.password is not None
            or url.fragment or url.port is None or not 1024 <= url.port <= 65535):
        raise ValueError('Only an uncredentialed admitted loopback HTTP endpoint is allowed')
    return url


def checked_url(value):
    checked_endpoint(value)
    return value


def checked_header(value):
    """Permit literal fields and curl's explicit empty-field semicolon syntax."""
    name, separator, _ = value.partition(':')
    if not separator and value.endswith(';'):
        name = value[:-1]
    elif not separator:
        raise ValueError('A literal single HTTP header is required')
    allowed = string.ascii_letters + string.digits + "!#$%&'*+-.^_`|~"
    if not name or any(character not in allowed for character in name) or '\r' in value or '\n' in value:
        raise ValueError('Invalid literal HTTP header')
    return value


def checked_value(flag, value):
    if flag in ('-D', '-o'):
        return value if value == '/dev/null' else private_output(value)
    if flag == '--data-binary':
        if not value.startswith('@'):
            raise ValueError('Body must name an admitted private input file')
        return '@' + private_output(value[1:])
    if flag == '-X' and value not in ('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'):
        raise ValueError('Unsupported test method')
    if flag == '-w' and value not in ('%{http_code}', '%{http_code}\t%{http_version}\n'):
        raise ValueError('Unsupported output format')
    if flag == '-H':
        checked_header(value)
    return value


def checked_request(arguments):
    """Reject curl config files, alternate protocols, and argument/file injection."""
    if arguments == ['--version']:
        return arguments, None
    switches = {'-sS', '-k', '--http1.1', '--no-buffer'}
    values = {'-D', '-o', '--data-binary', '-X', '-w', '-H'}
    result = []
    endpoint = None
    pending = iter(arguments)
    for value in pending:
        if value in switches:
            result.append(value)
        elif value in values:
            supplied = next(pending, None)
            if supplied is None:
                raise ValueError('Missing client option value')
            result.extend((value, checked_value(value, supplied)))
        else:
            candidate = checked_endpoint(value)
            if endpoint is not None:
                raise ValueError('Exactly one admitted URL is required')
            endpoint = candidate
            result.append(value)
    if endpoint is None:
        raise ValueError('Exactly one admitted URL is required')
    return result, endpoint


def checked_arguments(arguments):
    return checked_request(arguments)[0]


def run_raw(arguments, correlation_id):
    command = ['rtk', 'proxy', sys.executable, str(Path(__file__).with_name('curl-raw-client.py'))]
    command.extend(checked_arguments(arguments))
    process = subprocess.run(command, env=dict(os.environ, I12_APACHE_CLIENT_TOKEN=correlation_id),
                             capture_output=True, timeout=25, check=False)
    receipt = {'argv': command, 'actual_waited_exit_code': process.returncode,
               'actual_signal': -process.returncode if process.returncode < 0 else None,
               'stdout_bytes': len(process.stdout), 'stderr_bytes': len(process.stderr)}
    return process, receipt


def capture_main(arguments):
    output = Path('/task/client')
    output.mkdir(mode=0o700, exist_ok=True)
    main_id = str(time.time_ns())
    delayed = os.environ.get('I12_APACHE_CAPTURE_DELAY') == '1'
    if delayed:
        time.sleep(0.2)
    process, receipt = run_raw(arguments, main_id)
    receipt['client_completed_before_wrapper_exit'] = True
    (output / (main_id + '.actual-process.json')).write_text(json.dumps(receipt, indent=2) + '\n')
    if os.environ.get('I12_APACHE_FOLLOWUP') == '1':
        capture_neighbor(arguments, output, main_id)
    if delayed:
        time.sleep(0.2)
    return process


def capture_neighbor(arguments, output, main_id):
    _, endpoint = checked_request(arguments)
    if endpoint is None:
        raise ValueError('A followup requires an admitted request endpoint')
    neighbor_id = str(time.time_ns())
    process, receipt = run_raw([
        '-sS', '--http1.1', '-D', str(output / 'neighbor.headers'), '-X', 'GET',
        '-o', str(output / 'neighbor.body'), '-w', '%{http_code}', '-H', 'X-Modsec-Smoke: allow',
        urlunsplit((endpoint.scheme, endpoint.netloc, '/no-crs/allow', '', ''))], neighbor_id)
    receipt.update(actual_stdout=process.stdout.decode('ascii', errors='replace'),
                   role='separate_original_allow_neighbor', main_client_token=main_id,
                   does_not_replace_main_outcome=True)
    (output / (neighbor_id + '.actual-process.json')).write_text(json.dumps(receipt, indent=2) + '\n')


def main():
    arguments, endpoint = checked_request(sys.argv[1:])
    selected = os.environ.get('I12_APACHE_SELECTED_URI')
    selected_request = selected and endpoint is not None and endpoint.path == selected
    if selected_request:
        process = capture_main(arguments)
    else:
        process = subprocess.run(['rtk', 'proxy', '/usr/bin/curl', '--disable', *arguments],
                                 capture_output=True, timeout=25, check=False)
    sys.stdout.buffer.write(process.stdout)
    sys.stderr.buffer.write(process.stderr)
    return process.returncode


if __name__ == '__main__':
    raise SystemExit(main())
