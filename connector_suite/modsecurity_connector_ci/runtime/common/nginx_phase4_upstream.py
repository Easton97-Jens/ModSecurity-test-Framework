"""Bounded loopback-only native Phase-4 chunk trigger.

Observations describe bytes actually sent by this upstream, never Engine or
connector facts. In particular sending two chunks is not proof that a proxy
delivered two buffers to ModSecurity. Native EOS/rule/counter observations
must be retained separately and deterministically joined by the host driver.
"""
import socket
import threading


class BoundedPhase4Upstream:
    def __init__(self, chunks, *, pause=False, barrier_timeout=5):
        if (not isinstance(chunks, (list, tuple)) or not 1 <= len(chunks) <= 8
                or any(not isinstance(chunk, bytes) or not 1 <= len(chunk) <= 4096 for chunk in chunks)
                or sum(map(len, chunks)) > 8192):
            raise ValueError("chunks must be one to eight bounded nonempty byte strings")
        if not isinstance(pause, bool) or not 0 < barrier_timeout <= 10:
            raise ValueError("pause must be Boolean and barrier timeout bounded")
        self.chunks = tuple(chunks)
        self.pause = pause
        self.barrier_timeout = barrier_timeout
        self.release = threading.Event()
        self.paused = threading.Event()
        self.finished = threading.Event()
        self.eos_sent = threading.Event()
        self._sizes = []
        self._error = "none"
        self._socket = None
        self._client = None
        self._thread = None

    def __enter__(self):
        self._socket = socket.socket()
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen(1)
        self._socket.settimeout(5)
        self.port = self._socket.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=False)
        self._thread.start()
        return self

    def _read_request(self, client):
        request = b""
        while b"\r\n\r\n" not in request:
            packet = client.recv(min(1024, 8193 - len(request)))
            if not packet or len(request) + len(packet) > 8192:
                raise ValueError("request header incomplete or beyond bound")
            request += packet
        if not request.startswith(b"GET "):
            raise ValueError("fixture accepts only GET")

    def _write_response(self, client):
        client.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
        for index, chunk in enumerate(self.chunks):
            client.sendall(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
            self._sizes.append(len(chunk))
            if index == 0 and self.pause and len(self.chunks) > 1:
                self.paused.set()
                if not self.release.wait(self.barrier_timeout):
                    self._error = "barrier_timeout"
                    return
        client.sendall(b"0\r\n\r\n")
        self.eos_sent.set()

    def _serve(self):
        try:
            client, _ = self._socket.accept()
            self._client = client
            with client:
                client.settimeout(5)
                self._read_request(client)
                self._write_response(client)
        except (OSError, ValueError):
            self._error = "socket_or_request_error"
        finally:
            self.finished.set()

    def observations(self):
        if not self.finished.is_set():
            raise ValueError("upstream observations require completed operation")
        return {"chunk_sizes_sent": list(self._sizes), "eos_sent": self.eos_sent.is_set(),
                "error_class": self._error, "body_payload_persisted": False}

    def __exit__(self, *args):
        self.release.set()
        if self._client is not None:
            try:
                self._client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self._socket.close()
        self._thread.join(timeout=6)
        if self._thread.is_alive():
            raise RuntimeError("bounded fixture thread did not retire")
