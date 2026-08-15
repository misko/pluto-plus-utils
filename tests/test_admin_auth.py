from __future__ import annotations

import pytest

from pluto_plus.admin import AdminAuthenticationError, AdminMutationPolicy

TOKEN = "correct-horse-battery-staple-admin"


def test_admin_policy_requires_exact_bearer_and_never_retains_plaintext() -> None:
    policy = AdminMutationPolicy(token=TOKEN)

    with pytest.raises(AdminAuthenticationError, match="bearer"):
        policy.authorize(authorization=None, origin=None, browser_request=False)
    with pytest.raises(AdminAuthenticationError, match="bearer"):
        policy.authorize(authorization=f"Basic {TOKEN}", origin=None, browser_request=False)
    with pytest.raises(AdminAuthenticationError, match="bearer"):
        policy.authorize(
            authorization="Bearer wrong-token-with-enough-characters",
            origin=None,
            browser_request=False,
        )

    policy.authorize(authorization=f"Bearer {TOKEN}", origin=None, browser_request=False)
    assert TOKEN not in repr(policy)
    assert not hasattr(policy, "token")


def test_browser_admin_request_requires_an_exact_allowed_origin() -> None:
    policy = AdminMutationPolicy(
        token=TOKEN,
        allowed_origins={"http://192.168.1.142:8765", "https://radio.example/"},
    )
    authorization = f"Bearer {TOKEN}"

    with pytest.raises(AdminAuthenticationError, match="Origin"):
        policy.authorize(authorization=authorization, origin=None, browser_request=True)
    with pytest.raises(AdminAuthenticationError, match="Origin"):
        policy.authorize(
            authorization=authorization,
            origin="http://evil.example",
            browser_request=True,
        )

    policy.authorize(
        authorization=authorization,
        origin="http://192.168.1.142:8765",
        browser_request=True,
    )
    assert policy.allowed_origins == frozenset(
        {"http://192.168.1.142:8765", "https://radio.example"}
    )


@pytest.mark.parametrize(
    "origin",
    [
        "ftp://radio.example",
        "http://user@radio.example",
        "http://radio.example/path",
        "http://radio.example?query=yes",
        "null",
    ],
)
def test_allowed_origins_reject_non_origin_urls(origin: str) -> None:
    with pytest.raises(ValueError, match="exact HTTP origin"):
        AdminMutationPolicy(token=TOKEN, allowed_origins={origin})


def test_token_must_be_strong_and_header_safe() -> None:
    with pytest.raises(ValueError, match="at least 32"):
        AdminMutationPolicy(token="short")
    with pytest.raises(ValueError, match="non-space"):
        AdminMutationPolicy(token="x" * 31 + " ")
