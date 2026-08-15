"""Explicit authentication policy for privileged HTTP operations.

The radio daemon may be useful on a trusted LAN for read-only observation while
privileged mutation remains disabled.  Supplying this policy is therefore a
separate, mandatory composition step: possession of a firmware/setup helper is
not by itself authorization to expose that helper through HTTP.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterable
from ipaddress import ip_address
from urllib.parse import urlsplit


class AdminPolicyError(RuntimeError):
    """An administrative HTTP request failed the authorization policy."""


class AdminPolicyUnavailableError(AdminPolicyError):
    """Privileged HTTP authorization was not explicitly configured."""


class AdminAuthenticationError(AdminPolicyError):
    """The administrative credential or browser origin was rejected."""


class AdminSecureTransportRequiredError(AdminPolicyError):
    """A bearer credential would cross a non-loopback plaintext connection."""


def admin_transport_is_secure(
    *, scheme: str, client_host: str | None, server_host: str | None
) -> bool:
    """Accept HTTPS, a local socket/test transport, or a loopback TCP peer."""

    if scheme == "https":
        return True
    if scheme != "http":
        return False
    if client_host is None:
        return bool(server_host and server_host.startswith("/"))
    if client_host == "testclient":
        return True
    try:
        return ip_address(client_host).is_loopback
    except ValueError:
        return client_host.startswith("/")


class AdminMutationPolicy:
    """Constant-time bearer authentication plus a strict browser-origin allowlist.

    The plaintext token is reduced to a SHA-256 digest during construction and
    is never retained.  Non-browser API clients may omit ``Origin`` but still
    require the bearer credential.  Browser-like requests must provide an exact
    configured origin, preventing a credential-bearing browser session from
    being driven cross-site.
    """

    __slots__ = ("_allowed_origins", "_token_digest")

    def __init__(self, *, token: str, allowed_origins: Iterable[str] = ()) -> None:
        if len(token) < 32 or any(character.isspace() for character in token):
            raise ValueError("admin bearer token must contain at least 32 non-space characters")
        self._token_digest = hashlib.sha256(token.encode("utf-8")).digest()
        self._allowed_origins = frozenset(
            self._validate_origin(origin) for origin in allowed_origins
        )

    @property
    def allowed_origins(self) -> frozenset[str]:
        """Return the non-secret exact browser-origin allowlist."""

        return self._allowed_origins

    def authorize(
        self,
        *,
        authorization: str | None,
        origin: str | None,
        browser_request: bool,
    ) -> None:
        """Authorize one admin request or raise a stable typed error."""

        scheme, separator, presented = (authorization or "").partition(" ")
        valid_scheme = separator == " " and scheme == "Bearer"
        valid_token = (
            valid_scheme
            and bool(presented)
            and hmac.compare_digest(
                hashlib.sha256(presented.encode("utf-8")).digest(),
                self._token_digest,
            )
        )
        if not valid_token:
            raise AdminAuthenticationError("valid admin bearer authentication is required")

        if origin is None:
            if browser_request:
                raise AdminAuthenticationError(
                    "browser admin requests must provide an allowed Origin"
                )
            return
        if origin not in self._allowed_origins:
            raise AdminAuthenticationError("request Origin is not allowed for admin operations")

    @staticmethod
    def _validate_origin(origin: str) -> str:
        parsed = urlsplit(origin)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(f"admin allowed origin is not an exact HTTP origin: {origin!r}")
        return f"{parsed.scheme}://{parsed.netloc}"
