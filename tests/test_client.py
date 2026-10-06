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

    def _redirect(self) -> None:
        self.send_response(308)
        self.send_header("Location", "/graphql/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _ok(self) -> None:
        body = json.dumps({"data": {"__typename": "Query"}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        _BEHAVIOUR.setdefault("seen_accept", []).append(
            self.headers.get("Accept", "")
        )
        if _BEHAVIOUR["mode"] == "redirect" and self.path.startswith("/graphql?"):
            self._redirect()
            return
        self._ok()

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        _BEHAVIOUR.setdefault("seen_accept", []).append(
            self.headers.get("Accept", "")
        )
        mode = _BEHAVIOUR["mode"]

        if mode == "redirect":
            # A canonical trailing-slash redirect, which is an ordinary
            # deployment rather than a fault.
            if self.path == "/graphql":
                self._redirect()
            else:
                self._ok()
            return

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

        if mode == "exact":
            body = _BEHAVIOUR["body"]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if mode == "trickle_content_length":
            # Declares a length and then dribbles pieces far smaller than the
            # client's read chunk, so the read blocks mid-chunk instead of
            # yielding. This is the shape that defeated an in-loop deadline.
            total = int(_BEHAVIOUR.get("total", 1_000_000))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(total))
            self.end_headers()
            try:
                sent = 0
                while sent < total:
                    self.wfile.write(b"." * 100)
                    self.wfile.flush()
                    sent += 100
                    time.sleep(0.2)
            except (BrokenPipeError, ConnectionResetError, OSError):
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


def test_trickled_content_length_response_hits_the_deadline(server):
    """Regression: the deadline must interrupt a blocked read, not just follow it.

    With `Content-Length` set, the socket read blocks until the full chunk is
    available, so a server dribbling pieces smaller than the read chunk never
    lets an in-loop clock check run. Each arriving byte also resets the
    per-read socket timeout, so the scanner was held open indefinitely — this
    case ran past 60s against a 1s timeout before the watchdog was added. The
    chunked test above passed throughout, which is why the gap was missed.
    """
    _BEHAVIOUR.update(mode="trickle_content_length", total=1_000_000)
    with GraphQLClient(server, timeout=1.0, max_response_bytes=10 * 1024 * 1024) as c:
        start = time.perf_counter()
        resp = c.query("query GdosDepthProbe { __typename }")
        elapsed = time.perf_counter() - start

    assert resp.timed_out is True
    assert elapsed < 10, f"the client held on for {elapsed:.1f}s despite a 1s timeout"


def test_body_exactly_at_the_cap_is_not_truncated(server):
    """Regression: a complete body the size of the cap is not an amplification.

    `truncated` drives a VULNERABLE verdict, so flagging it without having
    seen a single byte beyond the cap invents a finding — and the body here
    parses perfectly well.
    """
    cap = 200_000
    pad = cap - len('{"data":{"__typename":"Query","pad":""}}')
    body = ('{"data":{"__typename":"Query","pad":"%s"}}' % ("x" * pad)).encode()
    body = body[:cap]
    assert len(body) == cap
    _BEHAVIOUR.update(mode="exact", body=body)

    with GraphQLClient(server, timeout=10, max_response_bytes=cap) as client:
        resp = client.query("query GdosDeepIntrospection { __typename }")

    assert resp.bytes_read == cap
    assert resp.truncated is False
    assert resp.has_data, "the whole body arrived and should have parsed"


def test_one_byte_over_the_cap_is_truncated(server):
    """The boundary in the other direction: cap + 1 byte really is truncated."""
    cap = 200_000
    _BEHAVIOUR.update(mode="exact", body=b"x" * (cap + 1))

    with GraphQLClient(server, timeout=10, max_response_bytes=cap) as client:
        resp = client.query("query GdosDeepIntrospection { __typename }")

    assert resp.truncated is True
    assert resp.bytes_read == cap


def test_post_follows_a_canonical_redirect(server):
    """Regression: refusing redirects on POST abandoned the whole scan.

    An endpoint published behind an http-to-https or trailing-slash redirect is
    ordinary. With redirects off, the baseline saw a 308 with no GraphQL data,
    every sample was discarded and the scan reported the endpoint unscannable.
    """
    _BEHAVIOUR.clear()
    _BEHAVIOUR.update(mode="redirect")
    with GraphQLClient(server, timeout=10) as client:
        resp = client.query("query GdosBaseline { __typename }")

    assert resp.status_code == 200
    assert resp.has_data, "the redirect should have been followed"


def test_get_does_not_follow_a_redirect(server):
    """The GET probe wants the endpoint's own answer, not the target's.

    Following it would test the policy at some other path or origin.
    """
    _BEHAVIOUR.clear()
    _BEHAVIOUR.update(mode="redirect")
    with GraphQLClient(server, timeout=10) as client:
        resp = client.get("query GdosGetProbe { __typename }")

    assert resp.status_code == 308
    assert resp.has_data is False


def test_accept_header_can_be_overridden_per_request(server):
    """Incremental delivery is content-negotiated and must be asked for."""
    _BEHAVIOUR.clear()
    _BEHAVIOUR.update(mode="small")
    wanted = "multipart/mixed; deferSpec=20220824, application/json"
    with GraphQLClient(server, timeout=10) as client:
        client.query("query GdosBaseline { __typename }")
        client.query("query GdosDeferProbe { __typename }", accept=wanted)

    seen = _BEHAVIOUR["seen_accept"]
    assert seen[0] == "application/json", "the default must stay unchanged"
    assert seen[1] == wanted


def test_content_type_is_recorded(server):
    _BEHAVIOUR.clear()
    _BEHAVIOUR.update(mode="small")
    with GraphQLClient(server, timeout=10) as client:
        resp = client.query("query GdosBaseline { __typename }")
    assert resp.content_type.startswith("application/json")
    assert resp.is_multipart is False


def test_default_cap_is_applied():
    client = GraphQLClient("http://127.0.0.1:1/graphql")
    assert client.max_response_bytes == DEFAULT_MAX_RESPONSE_BYTES
    client.close()


def test_cap_cannot_be_zero_or_negative():
    client = GraphQLClient("http://127.0.0.1:1/graphql", max_response_bytes=0)
    assert client.max_response_bytes >= 1
    client.close()
