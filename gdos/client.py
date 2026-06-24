"""HTTP client for talking to a GraphQL endpoint.

The client is intentionally conservative: every request has a hard timeout and a
single retry is *not* performed automatically, because the scanner needs to
observe the raw behaviour of the server (including slow/failed responses) to
judge resilience.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import requests


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
    ) -> None:
        self.url = url
        self.timeout = timeout
        self.verify_tls = verify_tls
        self._session = requests.Session()
        default_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "gdos-scanner/2.0 (+graphql-dos-resilience-scanner)",
        }
        if headers:
            default_headers.update(headers)
        self._session.headers.update(default_headers)

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

        elapsed = time.perf_counter() - start
        parsed: dict[str, Any] | list[Any] | None
        try:
            parsed = resp.json()
        except ValueError:
            parsed = None
        return GraphQLResponse(
            status_code=resp.status_code,
            elapsed=elapsed,
            text=resp.text[:2000],
            json=parsed,
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
