"""Explicit same-UID MRC1 fault peer; never impersonates a native engine result."""
import json
import os
from pathlib import Path
import signal
import socket
import sys
import time

path = '/task/sockets/fault.sock'
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path);os.chmod(path,0o600);server.listen(8)
def stop(*_):raise SystemExit(0)
signal.signal(signal.SIGTERM,stop)
try:
    while True:
        connection, _ = server.accept()
        with connection:
            connection.settimeout(5)
            header = bytearray()
            while len(header) < 12:
                data = connection.recv(12-len(header))
                if not data:break
                header.extend(data)
            result = b'BAD!' + bytes(8)
            connection.sendall(result)
            record = {'fixture':'explicit-malformed-mrc1-peer','pid':os.getpid(),
                'received_header_hex':header.hex(),'sent_header_hex':result.hex(),
                'monotonic_ns':time.monotonic_ns(),'native_engine_result':False}
            with Path('/task/fault-peer.jsonl').open('a') as stream:stream.write(json.dumps(record)+'\n')
finally:
    server.close();Path(path).unlink(missing_ok=True)
