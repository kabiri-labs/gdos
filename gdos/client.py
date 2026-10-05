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
import time
from dataclasses import dataclass, field
from typing import Any

import requests

DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024
"""Generous enough for a full introspection of a very large schema, small
enough that a runaway amplification cannot exhaust the scanner."""

_READ_CHUNK = 64 * 1024


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
    truncated: bool = False
    """The body hit the read cap. The server sent at least ``bytes_read``
    bytes, so the payload was answered at scale even though the body could not
    be parsed."""
    bytes_read: int = 0

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
            "User-Agent": "gdos-scanner/2.2 (+graphql-dos-resilience-scanner)",
        }
        if headers:
            default_headers.update(headers)
        self._session.headers.update(default_headers)

    def _read_body(self, resp: "requests.Response", start: float) -> tuple[bytes, bool]:
        """Read at most ``max_response_bytes``, and never past the deadline.

        Returns the bytes read and whether the cap stopped the read. The
        deadline matters as much as the cap: ``timeout`` governs the wait
        between chunks, not the transfer as a whole, so a server trickling
        bytes indefinitely would otherwise hold the scanner open forever.
        """
        chunks: list[bytes] = []
        total = 0
        for chunk in resp.iter_content(chunk_size=_READ_CHUNK):
            if time.perf_counter() - start > self.timeout:
                raise requests.exceptions.Timeout(
                    "response body still arriving after the timeout"
                )
            if not chunk:
                continue
            chunks.append(chunk)
            total += len(chunk)
            if total >= self.max_response_bytes:
                return b"".join(chunks)[: self.max_response_bytes], True
        return b"".join(chunks), False

    def post(self, payload: dict[str, Any] | list[Any]) -> GraphQLResponse:
        """Send a JSON GraphQL payload and return a normalised response.

        Never raises for HTTP/network errors — failures are captured in the
        returned :class:`GraphQLResponse` so the scanner can reason about them.
        """
        start = time.perf_counter()
        try:
            resp = self._session.post(
                self.url,
                json=payload,
                timeout=self.timeout,
                verify=self.verify_tls,
                stream=True,
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

        try:
            body, truncated = self._read_body(resp, start)
        except requests.exceptions.Timeout:
            return GraphQLResponse(
                status_code=resp.status_code,
                elapsed=time.perf_counter() - start,
                timed_out=True,
                error=f"response body did not finish within {self.timeout}s",
            )
        except requests.exceptions.RequestException as exc:
            return GraphQLResponse(
                status_code=resp.status_code,
                elapsed=time.perf_counter() - start,
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
            truncated=truncated,
            bytes_read=len(body),
        )

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
