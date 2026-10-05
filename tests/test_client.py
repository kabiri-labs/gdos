"""Transport-level tests for :class:`gdos.client.GraphQLClient`.

The rest of the suite stubs the client out, but a read cap and a transfer
deadline are properties of the socket handling itself — a stub cannot show
that a 50 MB answer is never buffered, or that a server trickling bytes does
not hold the scanner open. These tests therefore run a throwaway HTTP server
bound to 127.0.0.1 on an ephemeral port. Nothing leaves the loopback
interface and no external service is involved.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from gdos.client import DEFAULT_MAX_RESPONSE_BYTES, GraphQLClient

# Set by each test before it starts the server.
_BEHAVIOUR: dict[str, object] = {}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        mode = _BEHAVIOUR["mode"]

        if mode == "small":
            body = json.dumps({"data": {"__typename": "Query"}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if mode == "huge":
            # Far more than the cap under test, streamed so the client has to
            # decide to stop rather than being handed a bounded body.
            chunk = b"x" * 65536
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            try:
                for _ in range(int(_BEHAVIOUR.get("chunks", 400))):
                    self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                self.wfile.write(b"0\r\n\r\n")
            except (BrokenPipeError, ConnectionResetError, OSError):
                # Expected: the client stopped reading at the cap.
                pass
            return

        if mode == "trickle":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            try:
                while True:
                    self.wfile.write(b"1\r\n.\r\n")
                    self.wfile.flush()
                    time.sleep(0.2)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            return


class _QuietServer(ThreadingHTTPServer):
    """Disconnects are the point of these tests, not failures to report."""

    daemon_threads = True

    def handle_error(self, request, client_address) -> None:
        pass


@pytest.fixture
def server():
    srv = _QuietServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/graphql"
    srv.shutdown()
    srv.server_close()


def test_small_response_is_read_whole(server):
    _BEHAVIOUR.update(mode="small")
    with GraphQLClient(server, timeout=5) as client:
        resp = client.query("query GdosControl { __typename }")
    assert resp.ok
    assert resp.truncated is False
    assert resp.has_data
    assert resp.bytes_read > 0


def test_oversized_response_stops_at_the_cap(server):
    """The scanner must not buffer an amplified answer in full."""
    _BEHAVIOUR.update(mode="huge", chunks=400)  # ~26 MB offered
    cap = 1 * 1024 * 1024
    with GraphQLClient(server, timeout=20, max_response_bytes=cap) as client:
        resp = client.query("query GdosDeepIntrospection { __typename }")

    assert resp.truncated is True
    assert resp.bytes_read == cap
    assert len(resp.text) <= 2000
    # The body is not valid JSON once cut, and that is fine: the checks read
    # `truncated`, not the parsed payload.
    assert resp.json is None


def test_trickled_response_hits_the_deadline(server):
    """`timeout` bounds the whole transfer, not just the gap between chunks.

    A server dribbling one byte at a time resets a per-read timeout forever,
    so without a wall-clock deadline the scanner would never let go.
    """
    _BEHAVIOUR.update(mode="trickle")
    with GraphQLClient(server, timeout=1.0, max_response_bytes=10 * 1024 * 1024) as c:
        start = time.perf_counter()
        resp = c.query("query GdosDepthProbe { __typename }")
        elapsed = time.perf_counter() - start

    assert resp.timed_out is True
    assert elapsed < 10, "the client kept reading well past its own timeout"


def test_default_cap_is_applied():
    client = GraphQLClient("http://127.0.0.1:1/graphql")
    assert client.max_response_bytes == DEFAULT_MAX_RESPONSE_BYTES
    client.close()


def test_cap_cannot_be_zero_or_negative():
    client = GraphQLClient("http://127.0.0.1:1/graphql", max_response_bytes=0)
    assert client.max_response_bytes >= 1
    client.close()
