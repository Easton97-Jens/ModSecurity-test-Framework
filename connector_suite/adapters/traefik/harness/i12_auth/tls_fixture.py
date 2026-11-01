"""Create a fresh private synthetic CA and IP-SAN leaf for the fixture relay."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

TLS_ROOT = Path('/task/authorization-tls')
CONFIG_FILE = Path('/task/runtime/effective-config/traefik-forwardauth-dynamic.yaml')
LEAF_EXTENSIONS = 'leaf.ext'
CA_PRIVATE_KEY = 'ca.key'
CA_CERTIFICATE = 'ca.crt'
SERVER_REQUEST = 'server.csr'
SERVER_CERTIFICATE = 'server.crt'


def validate_tls_ancestor(parent, anchor):
    if parent.is_symlink():
        raise ValueError('TLS symlink ancestry forbidden')
    metadata = parent.stat()
    if metadata.st_uid != os.getuid() or metadata.st_mode & 0o022:
        raise ValueError('TLS directory ancestry must be task-owned and private')
    if parent != anchor and ((parent / '.git').exists() or (parent / '.git').is_symlink()):
        raise ValueError('TLS material must remain outside Git metadata')


def validate_directory(directory):
    directory = Path(directory)
    configured = os.environ.get('CODEX_TEMP_ROOT')
    anchors = [Path('/task')]
    if configured:
        storage = Path(configured)
        if not storage.is_absolute() or storage.resolve() != storage or not storage.is_dir():
            raise ValueError('physical configured TLS storage root required')
        anchors.append(storage)
    anchor = next((root for root in anchors if root in directory.parents), None)
    if (not directory.is_absolute() or directory.resolve() != directory or anchor is None
            or directory.exists() or directory.is_symlink() or not directory.parent.is_dir()):
        raise ValueError('fresh physical private TLS directory required')
    for parent in directory.parents:
        validate_tls_ancestor(parent, anchor)
        if parent == anchor:
            break
    return directory


def openssl(directory, *arguments):
    result = subprocess.run(['rtk', 'proxy', '/usr/bin/openssl', *arguments], cwd=directory,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    if result.returncode:
        raise RuntimeError('synthetic TLS fixture OpenSSL operation failed')
    return result.stdout.decode('utf-8')


def generate(directory=TLS_ROOT):
    directory = validate_directory(directory)
    directory.mkdir(mode=0o700)
    extensions = directory / LEAF_EXTENSIONS
    extensions.write_text('basicConstraints=critical,CA:FALSE\n'
                          'keyUsage=critical,digitalSignature,keyEncipherment\n'
                          'extendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n')
    try:
        openssl(directory, 'req', '-config', '/dev/null', '-x509', '-newkey', 'rsa:2048', '-noenc', '-sha256', '-days', '1',
                '-subj', '/CN=Traefik I12 synthetic fixture CA', '-keyout', CA_PRIVATE_KEY, '-out', CA_CERTIFICATE,
                '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
                '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
        openssl(directory, 'req', '-config', '/dev/null', '-new', '-newkey', 'rsa:2048', '-noenc',
                '-subj', '/CN=127.0.0.1', '-keyout', 'server.key', '-out', SERVER_REQUEST)
        openssl(directory, 'x509', '-req', '-in', SERVER_REQUEST, '-CA', CA_CERTIFICATE, '-CAkey', CA_PRIVATE_KEY,
                '-CAcreateserial', '-out', SERVER_CERTIFICATE, '-days', '1', '-sha256', '-extfile', LEAF_EXTENSIONS)
        (directory / 'server.key').chmod(0o600)
        openssl(directory, 'verify', '-CAfile', CA_CERTIFICATE, '-verify_ip', '127.0.0.1',
                '-purpose', 'sslserver', SERVER_CERTIFICATE)
        receipt = {'synthetic_fixture_only': True, 'openssl': openssl(directory, 'version').strip(),
                   'san': {'type': 'IP', 'value': '127.0.0.1'}, 'validity_days': 1,
                   'private_key_mode': '0600', 'ca_private_key_retained': False,
                   'public_certificates': {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
                                           for name in (CA_CERTIFICATE, SERVER_CERTIFICATE)}}
        (directory / 'tls-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        return receipt
    finally:
        for name in (CA_PRIVATE_KEY, 'ca.srl', SERVER_REQUEST, LEAF_EXTENSIONS):
            (directory / name).unlink(missing_ok=True)


def configure_forwardauth(text, auth_port):
    if type(auth_port) is not int or not 1 <= auth_port <= 65535:
        raise ValueError('invalid bounded relay TLS port')
    before = f'        address: http://127.0.0.1:{auth_port}/authorize\n'
    after = (f'        address: https://127.0.0.1:{auth_port}/authorize\n'
             '        tls:\n          ca: /task/authorization-tls/ca.crt\n'
             '          insecureSkipVerify: false\n')
    if (text.count(before) != 1 or text.count('maxResponseBodySize: 32768') != 1
            or '\n        tls:' in text or 'insecureSkipVerify:' in text):
        raise ValueError('exact bounded forwardAuth TLS relocation boundary required')
    return text.replace(before, after, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config', type=Path, choices=(CONFIG_FILE,))
    parser.add_argument('port', type=int)
    args = parser.parse_args()
    if (any(path.is_symlink() for path in (args.config, *args.config.parents))
            or not args.config.is_file() or args.config.stat().st_size > 65536
            or args.config.stat().st_uid != os.getuid()):
        raise ValueError('actual private task configuration required')
    configured = configure_forwardauth(args.config.read_text(), args.port)
    generate()
    args.config.write_text(configured)


if __name__ == '__main__':
    main()
