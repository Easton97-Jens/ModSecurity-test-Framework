# Retained Lighttpd client source SHA256: 373baa042edc32be73a04b1ca045761322181da1183c9a3ac743c868e04f8675
# Extension: parse received HTTP after transport error; preserve error and actual exit.
"""Bounded raw HTTP/1 client for the exact test-fixture curl argv contract.

Retain received bytes and actual TCP FIN/RST/timeout separately from HTTP status.
No expected backend bytes or status are used to construct observations.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import signal
import struct
import sys
import time
from urllib.parse import urlsplit
from lighttpd_capture_response import response_decode

TASK_ROOT = Path('/task')


def observe_receive(receipt, chunks, received, chunk, started_ns, completed_ns):
    """Record the actual recv boundary before appending its wire bytes."""
    if not chunks:
        receipt.update(first_response_recv_started_ns=started_ns,
                       first_response_recv_completed_ns=completed_ns)
    chunks.append({'started_ns': started_ns, 'completed_ns': completed_ns,
                   'bytes': len(chunk), 'prior_received_bytes': len(received)})
    received.extend(chunk)
    delimiter = received.find(b'\r\n\r\n')
    if delimiter < 0:
        return False
    header_bytes = delimiter + 4
    if 'headers_complete_recv_ns' not in receipt:
        receipt.update(headers_complete_recv_ns=completed_ns,
                       observed_header_bytes=header_bytes)
    if len(received) == header_bytes or 'first_encoded_entity_recv_ns' in receipt:
        return False
    receipt['first_encoded_entity_recv_ns'] = completed_ns
    return True


def record_local_abort(connection, receipt, mode, received):
    if mode == 'reset':
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
    receipt['local_abort'] = {'mode': mode, 'monotonic_ns': time.monotonic_ns(),
        'actual_received_entity_bytes': len(received) - receipt['observed_header_bytes'],
        'peer_reset_claimed': False}


def create_receipt(arguments, method, path, body):
    receipt = {'pid': os.getpid(), 'argv': arguments, 'method': method, 'path': path,
               'request_bytes': len(body),
               'request_sha256': hashlib.sha256(body).hexdigest(),
               'started_ns': time.monotonic_ns()}
    receipt.update(tcp_eof_observed=False, tcp_reset_observed=False,
                   timeout_observed=False, error=None)
    return receipt


def send_request(connection, request, receipt):
    """Record send completion only after the complete request reaches the socket."""
    connection.settimeout(15)
    connection.sendall(request)
    receipt['request_sent_ns'] = time.monotonic_ns()


def task_file(value):
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts or not path.is_relative_to(TASK_ROOT):
        raise ValueError('fixture file must remain inside its private task directory')
    if any(part.is_symlink() for part in (*path.parents, path)):
        raise ValueError('fixture file aliases forbidden')
    # Resolve before the I/O boundary and compare whole directory components.
    # The lexical and alias checks above remain stricter than canonicalization.
    canonical = os.path.realpath(value)
    boundary = os.path.realpath(TASK_ROOT) + os.sep
    if not canonical.startswith(boundary):
        raise ValueError('fixture file must remain inside its private task directory')
    return Path(canonical)


arguments=sys.argv[1:]
method='GET';headers=[];body=b'';header_file=None;body_file=None;writeout=None;url=None;abort_mode=None;framing_case=None;header_boundary=None
index=0
while index<len(arguments):
    argument=arguments[index]
    if argument in ('-sS','--http1.1'):
        index+=1;continue
    if argument in ('-D','-X','-o','-w','-H','--data-binary','--i12-abort-after-first-entity','--i12-framing-case','--i12-header-byte-boundary'):
        if index+1>=len(arguments):raise SystemExit('incomplete fixture curl argument')
        value=arguments[index+1];index+=2
        if argument=='--i12-header-byte-boundary':
            if value not in ('512','513'):raise SystemExit('unsupported finite header-byte boundary')
            header_boundary=int(value)
        elif argument=='--i12-framing-case':
            if value not in ('invalid_content_length','conflicting_content_length','duplicate_transfer_encoding','content_length_overflow'):raise SystemExit('unsupported finite framing probe')
            framing_case=value
        elif argument=='--i12-abort-after-first-entity':
            if value not in ('reset','close','signal'):raise SystemExit('unknown explicit fixture abort mode')
            abort_mode=value
        elif argument=='-D':header_file=task_file(value)
        elif argument=='-X':method=value
        elif argument=='-o':body_file=task_file(value)
        elif argument=='-w':writeout=value
        elif argument=='-H':
            name,separator,content=value.partition(':')
            if separator:headers.append((name,content.lstrip(' ')))
            elif value.endswith(';'):headers.append((value[:-1],''))
            else:raise SystemExit('unsupported fixture header form')
        else:
            if not value.startswith('@'):raise SystemExit('fixture requires materialized body file')
            body=task_file(value[1:]).read_bytes()
        continue
    if argument.startswith('http://') and url is None:
        url=argument;index+=1;continue
    raise SystemExit('unsupported fixture curl argument: '+argument)
if url is None or header_file is None or body_file is None or writeout!='%{http_code}':
    raise SystemExit('incomplete exact fixture curl contract')
parsed=urlsplit(url)
if parsed.hostname!='127.0.0.1' or parsed.username is not None or parsed.port is None:
    raise SystemExit('fixture client only supports its private loopback target')
if len(body)>2097152 or method not in ('GET','POST'):
    raise SystemExit('unsupported bounded fixture request')
path=parsed.path+('?' +parsed.query if parsed.query else '')
if header_boundary:
    actual_base=len('Host')+len(f'127.0.0.1:{parsed.port}')+len('Connection')+len('close')
    actual_base+=sum(len(name)+len(value) for name,value in headers)
    if body or method=='POST':actual_base+=len('Content-Length')+len(str(len(body)))
    padding=header_boundary-actual_base-len('X-I12-Padding')
    if padding<1:raise SystemExit('header boundary too small')
    headers.append(('X-I12-Padding','x'*padding))
request=(f'{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{parsed.port}\r\n').encode('ascii')
for name,value in headers:
    if '\r' in name+value or '\n' in name+value or name.lower() in ('host','connection','content-length','transfer-encoding'):
        raise SystemExit('fixture client framing/header contract mismatch')
    request+=(name+': '+value+'\r\n').encode('ascii')
if body or method=='POST':request+=f'Content-Length: {len(body)}\r\n'.encode('ascii')
request+=b'Connection: close\r\n\r\n'+body
if framing_case:
    original_length=f'Content-Length: {len(body)}\r\n'.encode()
    replacement={
        'invalid_content_length':b'Content-Length: not-a-number\r\n',
        'conflicting_content_length':original_length+f'Content-Length: {len(body)+1}\r\n'.encode(),
        'duplicate_transfer_encoding':original_length+b'Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n',
        'content_length_overflow':b'Content-Length: 999999999999999999999999999999999999999\r\n',
    }[framing_case]
    if request.count(original_length)!=1:raise SystemExit('framing probe requires one generated Content-Length')
    request=request.replace(original_length,replacement)
root=Path('/task/client');root.mkdir(mode=0o700,exist_ok=True)
token=os.environ['I12_APACHE_CLIENT_TOKEN']
if not token or any(character not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for character in token):
    raise ValueError('fixture client token must be one safe filename component')
received=bytearray()
recv_chunks=[]
receipt=create_receipt(arguments, method, path, body)
status='000';exit_code=1
try:
    with socket.create_connection(('127.0.0.1',parsed.port),timeout=15) as connection:
        send_request(connection, request, receipt)
        while True:
            recv_started_ns=time.monotonic_ns()
            chunk=connection.recv(4096)
            recv_completed_ns=time.monotonic_ns()
            if not chunk:
                receipt['tcp_eof_observed']=True;receipt['eof_ns']=time.monotonic_ns();break
            first_entity = observe_receive(receipt, recv_chunks, received, chunk,
                                           recv_started_ns, recv_completed_ns)
            if first_entity and abort_mode:
                record_local_abort(connection, receipt, abort_mode, received)
                break
            if len(received)>3145728:raise RuntimeError('bounded response exceeded3MiB')

except ConnectionResetError as error:
    receipt['tcp_reset_observed']=True;receipt['error']={'type':type(error).__name__,'message':str(error)}
except TimeoutError as error:
    receipt['timeout_observed']=True;receipt['error']={'type':type(error).__name__,'message':str(error)}
except Exception as error:
    receipt['error']={'type':type(error).__name__,'message':str(error)}
finally:
    if received:
        try:
            observed,header,decoded=response_decode(bytes(received))
            status=str(observed["status"])
            header_file.write_bytes(header);body_file.write_bytes(decoded)
            receipt.update(observed)
            if not observed["framing"]["complete"]:
                receipt["http_parse_error"]={"type":"IncompleteFraming","message":"Declared Content-Length differs from actual received entity"}
                if receipt["error"] is None:receipt["error"]=receipt["http_parse_error"]
            elif receipt["error"] is None:exit_code=0
        except Exception as parse_error:
            receipt['http_parse_error']={'type':type(parse_error).__name__,'message':str(parse_error)}
    (root/(token+'.request.raw')).write_bytes(request)
    (root/(token+'.response.raw')).write_bytes(received)
    receipt.update(completed_ns=time.monotonic_ns(),proposed_process_exit=exit_code,actual_socket_recv_chunks=recv_chunks)
    (root/(token+'.receipt.json')).write_text(json.dumps(receipt,indent=2)+'\n')
sys.stdout.write(status)
sys.stdout.flush()
if abort_mode=='signal':os.kill(os.getpid(),signal.SIGTERM)
raise SystemExit(exit_code)
