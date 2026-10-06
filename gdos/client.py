"""HTTP client for talking to a GraphQL endpoint.

The client is intentionally conservative: every request has a hard timeout and a
single retry is *not* performed automatically, because the scanner needs to
observe the raw behaviour of the server (including slow/failed responses) to
judge resilience.

Responses are read under a byte cap and a wall-clock deadline. The probes are
amplification payloads, so the answer to one can be orders of magnitude larger
than the request that caused it; buffering that whole answer would exhaust the
scanner rather than reveal anything about the target. Hitting the cap is not an
error — it is evidence, and the checks treat it as such.
"""

from __future__ import annotations

import json as jsonlib
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any

import requests

DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024
"""Generous enough for a full introspection of a very large schema, small
enough that a runaway amplification cannot exhaust the scanner."""

_READ_CHUNK = 64 * 1024


def _force_disconnect(resp: "requests.Response") -> None:
    """Break a connection hard enough to interrupt a blocked read.

    ``Response.close()`` only releases the connection back to the pool, so a
    thread sitting in ``recv`` keeps waiting on it. Shutting the socket down is
    what actually wakes that thread, which is the whole point of the deadline
    watchdog. The attribute paths differ between urllib3 versions, so every
    step is attempted and none is required to succeed.
    """
    raw = getattr(resp, "raw", None)
    candidates = []
    for attr in ("_connection", "connection"):
        candidates.append(getattr(getattr(raw, attr, None), "sock", None))
    fp = getattr(getattr(raw, "_fp", None), "fp", None)
    candidates.append(getattr(getattr(fp, "raw", None), "_sock", None))
    candidates.append(getattr(fp, "_sock", None))
    for sock in candidates:
        if sock is None:
            continue
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    for closer in (getattr(raw, "close", None), getattr(resp, "close", None)):
        if closer is None:
            continue
        try:
            closer()
        except Exception:  # noqa: BLE001 - nothing useful to do on the way out
            pass


@dataclass
class GraphQLResponse:
    """Normalised view of a single GraphQL HTTP response."""

    status_code: int | None
    elapsed: float
    """Wall-clock seconds spent on the request (including a timeout)."""
    text: str = ""
    json: dict[str, Any] | list[Any] | None = None
    timed_out: bool = False
    error: str | None = None
    """Set when the request never produced an HTTP response (network error)."""
    content_type: str = ""
    """The response's ``Content-Type`` header, lower-cased."""
    truncated: bool = False
    """The body hit the read cap. The server sent at least ``bytes_read``
    bytes, so the payload was answered at scale even though the body could not
    be parsed."""
    bytes_read: int = 0

    @property
    def is_multipart(self) -> bool:
        """True for an incremental-delivery response (``multipart/mixed``).

        Such a body is a stream of payloads rather than one JSON document, so
        it will not parse — the stream itself is the observation.
        """
        return "multipart/" in self.content_type

    @property
    def ok(self) -> bool:
        return self.status_code is not None and 200 <= self.status_code < 300

    @property
    def graphql_errors(self) -> list[dict[str, Any]]:
        """The ``errors`` array from a GraphQL response body, if any."""
        if isinstance(self.json, dict):
            errors = self.json.get("errors")
            if isinstance(errors, list):
                return [e for e in errors if isinstance(e, dict)]
        return []

    @property
    def data(self) -> dict[str, Any] | None:
        """The ``data`` object from a GraphQL response body, if any."""
        if isinstance(self.json, dict):
            payload = self.json.get("data")
            if isinstance(payload, dict):
                return payload
        return None

    @property
    def has_data(self) -> bool:
        return isinstance(self.json, dict) and self.json.get("data") not in (None, {})

    def error_messages(self) -> str:
        """All GraphQL error messages joined, lower-cased, for keyword matching."""
        parts = [str(e.get("message", "")) for e in self.graphql_errors]
        if not parts and self.text:
            parts = [self.text]
        return " ".join(parts).lower()


class GraphQLClient:
    """Thin wrapper around :mod:`requests` for GraphQL POST requests."""

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 15.0,
        verify_tls: bool = True,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        self.url = url
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.max_response_bytes = max(1, max_response_bytes)
        self._session = requests.Session()
        default_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "gdos-scanner/2.3 (+graphql-dos-resilience-scanner)",
        }
        if headers:
            default_headers.update(headers)
        self._session.headers.update(default_headers)

    def _read_body(self, resp: "requests.Response", start: float) -> tuple[bytes, bool]:
        """Read at most ``max_response_bytes``, and never past the deadline.

        Returns the bytes read and whether the cap stopped the read. The
        deadline matters as much as the cap: ``timeout`` governs the wait for
        each socket read, not the transfer as a whole, so a server trickling
        bytes indefinitely would otherwise hold the scanner open forever.

        Checking the clock between chunks is not enough to enforce that. On a
        response carrying ``Content-Length`` the read blocks until the chunk is
        *full*, so a server dribbling pieces smaller than ``_READ_CHUNK`` never
        yields and the check never runs. The deadline therefore also arms a
        watchdog that closes the response out from under the blocked read,
        which is what makes the bound hold regardless of transfer encoding.
        """
        deadline = start + self.timeout
        expired = threading.Event()

        def give_up() -> None:
            expired.set()
            _force_disconnect(resp)

        watchdog = threading.Timer(max(0.0, deadline - time.perf_counter()), give_up)
        watchdog.daemon = True
        watchdog.start()

        chunks: list[bytes] = []
        total = 0
        try:
            for chunk in resp.iter_content(chunk_size=_READ_CHUNK):
                if expired.is_set() or time.perf_counter() > deadline:
                    raise requests.exceptions.Timeout(
                        "response body still arriving after the timeout"
                    )
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                # Strictly greater: a body that is exactly the cap was read in
                # full, and calling that truncated would report an amplified
                # response where there was none.
                if total > self.max_response_bytes:
                    return b"".join(chunks)[: self.max_response_bytes], True
            return b"".join(chunks), False
        except Exception as exc:
            # The watchdog closes the socket mid-read, which surfaces as
            # whatever the stack beneath requests happens to raise. If the
            # deadline is what stopped us, report it as the timeout it is.
            if expired.is_set() or time.perf_counter() > deadline:
                raise requests.exceptions.Timeout(
                    "response body still arriving after the timeout"
                ) from exc
            raise
        finally:
            watchdog.cancel()

    def _send(
        self,
        method: str,
        json_payload: dict[str, Any] | list[Any] | None = None,
        params: dict[str, str] | None = None,
    ) -> GraphQLResponse:
        """Issue one request and normalise whatever comes back.

        Never raises for HTTP/network errors — failures are captured in the
        returned :class:`GraphQLResponse` so the scanner can reason about them.
        """
        start = time.perf_counter()
        try:
            resp = self._session.request(
                method,
                self.url,
                json=json_payload,
                params=params,
                timeout=self.timeout,
                verify=self.verify_tls,
                stream=True,
                allow_redirects=False,
            )
        except requests.exceptions.Timeout:
            return GraphQLResponse(
                status_code=None,
                elapsed=time.perf_counter() - start,
                timed_out=True,
                error=f"request timed out after {self.timeout}s",
            )
        except requests.exceptions.RequestException as exc:
            return GraphQLResponse(
                status_code=None,
                elapsed=time.perf_counter() - start,
                error=str(exc),
            )

        content_type = resp.headers.get("Content-Type", "").lower()
        try:
            body, truncated = self._read_body(resp, start)
        except requests.exceptions.Timeout:
            return GraphQLResponse(
                status_code=resp.status_code,
                elapsed=time.perf_counter() - start,
                timed_out=True,
                content_type=content_type,
                error=f"response body did not finish within {self.timeout}s",
            )
        except requests.exceptions.RequestException as exc:
            return GraphQLResponse(
                status_code=resp.status_code,
                elapsed=time.perf_counter() - start,
                content_type=content_type,
                error=str(exc),
            )
        finally:
            resp.close()

        elapsed = time.perf_counter() - start
        text = body.decode(resp.encoding or "utf-8", errors="replace")
        parsed: dict[str, Any] | list[Any] | None
        try:
            parsed = jsonlib.loads(text)
        except ValueError:
            parsed = None
        return GraphQLResponse(
            status_code=resp.status_code,
            elapsed=elapsed,
            text=text[:2000],
            json=parsed,
            content_type=content_type,
            truncated=truncated,
            bytes_read=len(body),
        )

    def post(self, payload: dict[str, Any] | list[Any]) -> GraphQLResponse:
        """Send a JSON GraphQL payload over POST."""
        return self._send("POST", json_payload=payload)

    def get(
        self, query: str, variables: dict[str, Any] | None = None
    ) -> GraphQLResponse:
        """Send a query in the URL query string instead of a JSON body.

        Used to find out whether limits and filters that a deployment applies
        to POST also cover GET. Callers keep these payloads small: the point is
        the endpoint's policy, not the size of a URL.
        """
        params = {"query": query}
        if variables:
            params["variables"] = jsonlib.dumps(variables)
        return self._send("GET", params=params)

    def query(
        self, query: str, variables: dict[str, Any] | None = None
    ) -> GraphQLResponse:
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables
        return self.post(payload)

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "GraphQLClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
